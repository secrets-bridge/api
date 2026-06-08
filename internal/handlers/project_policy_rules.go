// EPIC R (api#108) Slice R2 — project-anchored scoped policy rule
// authoring endpoints. Wires the LOCKED §3 gate chains from R1 into
// HTTP, with stable {error_code, message, ...} envelopes per §4 and
// four Prometheus counters per §6.
//
// Routing:
//
//   POST   /projects/:projectID/policy-rules
//   GET    /projects/:projectID/policy-rules
//   GET    /projects/:projectID/policy-rules/:ruleID
//   PUT    /projects/:projectID/policy-rules/:ruleID
//   DELETE /projects/:projectID/policy-rules/:ruleID
//
// Auth path-pinned: every route uses policy.author scoped to projectID
// via the team-aware resolver. The existing admin routes on /policies
// stay on policy.edit unchanged. URL hierarchy expresses the permission
// split at the route level so a future PR can't accidentally loosen
// one path while reviewing the other.
//
// §4 correction 1: inherited platform rules returned via the GET list
// MUST be sanitized — selector VALUES omitted, only selector_keys
// preserved. Scoped users can see WHICH keys platform constrained but
// never the concrete values (secret_ref_prefix, paths, etc.).
//
// §4 correction 2: routes live under the authenticated session
// middleware (v1Middlewares group). Service runs the gate chain inline
// through *ForScopedAuthor methods — handler does NOT add auth.Require
// per-route, but the upstream middleware guarantees an identity is in
// context before the gate chain runs.
//
// §5 correction 1: error code mapping lives in this file as
// mapPolicyServiceErr — NOT folded into provider_connections.go's
// mapServiceErr. Policy and provider-connection domains are separate;
// mixing them invites cross-domain leakage during future code review.

package handlers

import (
	"encoding/json"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ---- Prometheus counters (§6 lock) -------------------------------

var (
	policyRulesCreatedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "policy_rules_created_total",
			Help: "Successful policy rule creations, by the actor's permission path and scope.",
		},
		// LOW-CARDINALITY LOCK: NEVER include actor_id, project_id,
		// policy_rule_id, or workflow_id labels. The audit log is the
		// place operators look those up.
		[]string{"permission_used", "scope"},
	)
	policyRulesUpdatedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "policy_rules_updated_total",
			Help: "Successful policy rule updates, by the actor's permission path and scope.",
		},
		[]string{"permission_used", "scope"},
	)
	policyRulesDeletedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "policy_rules_deleted_total",
			Help: "Successful policy rule deletions, by the actor's permission path and scope.",
		},
		[]string{"permission_used", "scope"},
	)
	policyRulesDeniedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "policy_rules_denied_total",
			Help: "Policy rule mutation attempts denied, by reason. Fixed reason set per §6 — never carries IDs.",
		},
		[]string{"reason"},
	)
)

// Fixed reason set §6 locked. Anything outside this table is bucketed
// to "other" to keep cardinality bounded.
const (
	policyDenialOutOfScope         = "out_of_scope"
	policyDenialPlatformOwned      = "platform_owned"
	policyDenialProdBlocked        = "prod_blocked"
	policyDenialScopeTooBroad      = "scope_too_broad"
	policyDenialPriorityReserved   = "priority_reserved"
	policyDenialSelectorMismatch   = "selector_mismatch"
	policyDenialEnvNotInProject    = "env_not_in_project"
	policyDenialNotFound           = "not_found"
	// R-follow-up #1 (api#118) — 9th value in the fixed reason set.
	// The LOW-CARDINALITY LOCK stays intact; no workflow_id label is
	// ever attached to the counter.
	policyDenialWorkflowNotAuthorable = "workflow_not_authorable"
)

const scopeProject = "project"

// policyEnvelopeCapKey is a Fiber Locals key the handlers set BEFORE
// calling mapPolicyServiceErr so the envelope can carry the live cap
// without re-reading the settings cache. The pre-call lookup is one
// in-memory map read; doing it inside mapPolicyServiceErr would mean
// every code path that returns the mapper also has to plumb settings.
const policyEnvelopeCapKey = "sb:policy:cap"

// policyDenialReasonFor maps a service-layer sentinel to its
// low-cardinality counter reason. Returns empty string when the error
// doesn't map (caller skips the counter increment).
func policyDenialReasonFor(err error) string {
	if errors.Is(err, services.ErrPolicyScopeTooBroad) {
		return policyDenialScopeTooBroad
	}
	switch {
	case errors.Is(err, services.ErrOutOfScopePolicy):
		return policyDenialOutOfScope
	case errors.Is(err, services.ErrPlatformPolicyNotEditable):
		return policyDenialPlatformOwned
	case errors.Is(err, services.ErrProdPolicyNotAllowedForScope):
		return policyDenialProdBlocked
	case errors.Is(err, services.ErrPolicyPriorityReserved):
		return policyDenialPriorityReserved
	case errors.Is(err, services.ErrPolicySelectorMismatch):
		return policyDenialSelectorMismatch
	case errors.Is(err, services.ErrPolicyEnvironmentNotInProject):
		return policyDenialEnvNotInProject
	case errors.Is(err, services.ErrPolicyNotFound):
		return policyDenialNotFound
	case errors.Is(err, services.ErrWorkflowNotAuthorable):
		return policyDenialWorkflowNotAuthorable
	}
	return ""
}

// mapPolicyServiceErr translates EPIC R sentinels into the
// {error_code, message, ...extra} envelope. Kept in this file per §5
// correction 1 — policy errors live separately from EPIC P/Q's
// mapServiceErr.
func mapPolicyServiceErr(c fiber.Ctx, err error) error {
	// PolicyScopeTooBroadDetail carries the reason variant — check
	// before the bare ErrPolicyScopeTooBroad so the envelope carries
	// the variant.
	var stb *services.PolicyScopeTooBroadDetail
	if errors.As(err, &stb) {
		return stableErr(c, fiber.StatusBadRequest,
			"policy_scope_too_broad",
			"scoped policy rules must constrain to a non-prod environment",
			map[string]any{"reason": stb.Reason})
	}
	// WorkflowNotAuthorableDetail carries the workflow_id the actor
	// selected (R-follow-up #1). Surfaced in the envelope for the SPA
	// toast; NOT attached as a Prometheus label.
	var wfn *services.WorkflowNotAuthorableDetail
	if errors.As(err, &wfn) {
		return stableErr(c, fiber.StatusForbidden,
			"workflow_not_authorable_for_scope",
			"the selected workflow is not enabled for scoped policy authoring",
			map[string]any{"workflow_id": wfn.WorkflowID.String()})
	}

	switch {
	case errors.Is(err, services.ErrPolicyNotFound):
		return stableErr(c, fiber.StatusNotFound,
			"policy_not_found",
			"policy rule not found", nil)
	case errors.Is(err, services.ErrPlatformPolicyNotEditable):
		return stableErr(c, fiber.StatusForbidden,
			"platform_policy_not_editable",
			"platform global policy rules are administered via /admin/policies", nil)
	case errors.Is(err, services.ErrOutOfScopePolicy):
		return stableErr(c, fiber.StatusForbidden,
			"out_of_scope_policy",
			"you don't have policy.author on this project", nil)
	case errors.Is(err, services.ErrPolicySelectorMismatch):
		return stableErr(c, fiber.StatusBadRequest,
			"policy_selector_mismatch",
			"the selector's project must match this project", nil)
	case errors.Is(err, services.ErrProdPolicyNotAllowedForScope):
		return stableErr(c, fiber.StatusForbidden,
			"prod_policy_not_allowed_for_scope",
			"scoped policy authors cannot create rules that match production environments",
			map[string]any{"env_kind": "prod"})
	case errors.Is(err, services.ErrPolicyPriorityReserved):
		// R-follow-up #2 (api#121) — cap reads the LIVE admin-set
		// value, not the EPIC R hardcode. Falls back to the test
		// constant only when settings isn't wired (which production
		// main never allows).
		cap := services.PlatformReservedPriority
		if mp, ok := c.Locals(policyEnvelopeCapKey).(int); ok {
			cap = mp
		}
		return stableErr(c, fiber.StatusBadRequest,
			"policy_priority_reserved",
			"priority is reserved for platform policy rules. Use a value below the cap.",
			map[string]any{"cap": cap})
	case errors.Is(err, services.ErrPlatformSettingUnavailable):
		return stableErr(c, fiber.StatusServiceUnavailable,
			"platform_setting_unavailable",
			"the platform setting required to evaluate this request is currently unavailable", nil)
	case errors.Is(err, services.ErrPolicyEnvironmentNotInProject):
		return stableErr(c, fiber.StatusBadRequest,
			"policy_environment_not_in_project",
			"the selector's environment does not belong to this project", nil)
	case errors.Is(err, storage.ErrSystemRow):
		// Scoped path cannot delete/edit a system row. Mirrors
		// ErrPlatformPolicyNotEditable semantically for the scoped
		// surface.
		return stableErr(c, fiber.StatusForbidden,
			"platform_policy_not_editable",
			"system policy rules are administered via /admin/policies", nil)
	}

	// Unknown — caller bubbles as 500.
	return fiber.NewError(fiber.StatusInternalServerError, err.Error())
}

// ---- handler type --------------------------------------------------

// ProjectPolicyRules owns the project-anchored scoped policy.author
// surface. Held on a dedicated struct (separate from the EPIC N Admin
// handler) so the §3 mental model "scoped authoring is project-ownership
// work, not platform policy administration" is visible at the codebase
// level.
type ProjectPolicyRules struct {
	engine   *services.PolicyEngine
	policies storage.PolicyRepository
	// R-follow-up #2 (api#121) — settings is consulted so the
	// policy_priority_reserved envelope's `cap` field reflects the
	// live admin-set value, NOT the EPIC R hardcode.
	settings *services.SettingsService
}

// NewProjectPolicyRules constructs the handler. The PolicyEngine must
// already have WithAuthorScope + WithEnvironments + WithSettings wired
// (main does this after rbacResolver, environmentRepo, and settingsSvc
// are available). settings may be nil — the envelope falls back to the
// EPIC R hardcode constant. Production main always wires this.
func NewProjectPolicyRules(engine *services.PolicyEngine, policies storage.PolicyRepository, settings *services.SettingsService) *ProjectPolicyRules {
	return &ProjectPolicyRules{engine: engine, policies: policies, settings: settings}
}

// ---- request / response shapes ------------------------------------

// scopedPolicyCreateBody is the wire shape for POST. Mirrors
// services.CreateScopedPolicyInput minus the URL-derived projectID and
// service-injected actorID.
type scopedPolicyCreateBody struct {
	Name       string         `json:"name"`
	Selector   map[string]any `json:"selector"`
	Priority   int            `json:"priority"`
	WorkflowID string         `json:"workflow_id"`
	Enabled    bool           `json:"enabled"`
}

// scopedPolicyUpdateBody uses pointer fields so nil = preserve.
// Explicit empty {} selector is the §3 Q9 lock — service rejects it.
type scopedPolicyUpdateBody struct {
	Name       *string         `json:"name,omitempty"`
	Selector   *map[string]any `json:"selector,omitempty"`
	Priority   *int            `json:"priority,omitempty"`
	WorkflowID *string         `json:"workflow_id,omitempty"`
	Enabled    *bool           `json:"enabled,omitempty"`
}

// policyRuleProjection is the wire shape for GET responses. Carries
// the §4 lock: inherited platform rules omit selector VALUES (only
// selector_keys) and stamp is_platform_inherited=true.
type policyRuleProjection struct {
	ID                    uuid.UUID      `json:"id"`
	Name                  string         `json:"name"`
	ProjectID             *string        `json:"project_id"`
	IsPlatformInherited   bool           `json:"is_platform_inherited"`
	SelectorKeys          []string       `json:"selector_keys"`
	Selector              map[string]any `json:"selector,omitempty"`
	Priority              int            `json:"priority"`
	WorkflowID            uuid.UUID      `json:"workflow_id"`
	Enabled               bool           `json:"enabled"`
	IsSystem              bool           `json:"is_system"`
	CreatedAt             string         `json:"created_at,omitempty"`
	UpdatedAt             string         `json:"updated_at,omitempty"`
}

// toScopedProjection emits the FULL projection (with selector values)
// for rules the actor owns through the scoped route — i.e. the row's
// project_id matches the URL projectID.
func toScopedProjection(p *storage.PolicyRule) policyRuleProjection {
	var projectIDPtr *string
	if p.ProjectID != nil {
		s := p.ProjectID.String()
		projectIDPtr = &s
	}
	return policyRuleProjection{
		ID:                  p.ID,
		Name:                p.Name,
		ProjectID:           projectIDPtr,
		IsPlatformInherited: false,
		SelectorKeys:        selectorKeysOf(p.Selector),
		Selector:            p.Selector,
		Priority:            p.Priority,
		WorkflowID:          p.WorkflowID,
		Enabled:             p.Enabled,
		IsSystem:            p.IsSystem,
		CreatedAt:           p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:           p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

// toInheritedProjection emits the SANITIZED projection (no selector
// values) for platform-owned rules surfaced via the scoped GET. §4
// correction 1: scoped users see structure (which keys constrain the
// platform rule), not values (the concrete prefix / path / env_id).
func toInheritedProjection(p *storage.PolicyRule) policyRuleProjection {
	return policyRuleProjection{
		ID:                  p.ID,
		Name:                p.Name,
		ProjectID:           nil,
		IsPlatformInherited: true,
		SelectorKeys:        selectorKeysOf(p.Selector),
		// Selector deliberately omitted.
		Priority:   p.Priority,
		WorkflowID: p.WorkflowID,
		Enabled:    p.Enabled,
		IsSystem:   p.IsSystem,
		CreatedAt:  p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:  p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

func selectorKeysOf(sel map[string]any) []string {
	if len(sel) == 0 {
		return []string{}
	}
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	return keys
}

// ---- handlers ------------------------------------------------------

// Create handles POST /projects/:projectID/policy-rules. The scoped
// (gate-chain) path. Auth is policy.author scoped to projectID via the
// team-aware resolver.
func (h *ProjectPolicyRules) Create(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("projectID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"projectID is malformed", nil)
	}
	var body scopedPolicyCreateBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"request body is not valid JSON", nil)
	}
	if body.Name == "" {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"name is required", nil)
	}
	workflowID, err := uuid.Parse(body.WorkflowID)
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"workflow_id is malformed", nil)
	}

	rule, err := h.engine.CreateForScopedAuthor(c.Context(), services.CreateScopedPolicyInput{
		ProjectID:     projectID,
		Name:          body.Name,
		Selector:      body.Selector,
		Priority:      body.Priority,
		WorkflowID:    workflowID,
		Enabled:       body.Enabled,
		ActorID:       identityFromCtx(c),
		CorrelationID: uuid.New(),
	})
	if err != nil {
		if reason := policyDenialReasonFor(err); reason != "" {
			policyRulesDeniedTotal.WithLabelValues(reason).Inc()
		}
		h.stashLiveCap(c)
		return mapPolicyServiceErr(c, err)
	}

	policyRulesCreatedTotal.WithLabelValues(
		string(auth.PermPolicyAuthor),
		scopeProject,
	).Inc()
	return c.Status(fiber.StatusCreated).JSON(toScopedProjection(rule))
}

// List handles GET /projects/:projectID/policy-rules. Returns scoped
// (project-owned) rules with full selector + inherited platform rules
// with the sanitized projection (selector VALUES omitted).
//
// §4 correction 1: sanitization is route-pinned, not perm-pinned.
// Admins acting via this URL still get the sanitized projection for
// inherited platform rules. They use /admin/policies for full
// platform-rule data.
func (h *ProjectPolicyRules) List(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("projectID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"projectID is malformed", nil)
	}
	rules, err := h.policies.ListForProject(c.Context(), projectID)
	if err != nil {
		return mapPolicyServiceErr(c, err)
	}
	out := make([]policyRuleProjection, 0, len(rules))
	for _, r := range rules {
		if r.ProjectID == nil {
			out = append(out, toInheritedProjection(r))
		} else if *r.ProjectID == projectID {
			out = append(out, toScopedProjection(r))
		}
		// Defense-in-depth: rules with project_id != projectID should
		// never come back from ListForProject (its WHERE clause filters
		// to NULL OR == projectID), but skip them just in case.
	}
	return c.JSON(out)
}

// Get handles GET /projects/:projectID/policy-rules/:ruleID. Returns
// the scoped projection for owned rules, the sanitized projection for
// inherited platform rules. PUT/DELETE on a platform rule via this
// route returns platform_policy_not_editable.
func (h *ProjectPolicyRules) Get(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("projectID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"projectID is malformed", nil)
	}
	ruleID, err := uuid.Parse(c.Params("ruleID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"ruleID is malformed", nil)
	}
	rule, err := h.policies.Get(c.Context(), ruleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return stableErr(c, fiber.StatusNotFound,
				"policy_not_found",
				"policy rule not found", nil)
		}
		return mapPolicyServiceErr(c, err)
	}
	// Sanitized projection for platform rules; full for scoped.
	if rule.ProjectID == nil {
		return c.JSON(toInheritedProjection(rule))
	}
	// Scoped rule must belong to URL projectID; mismatch → not_found
	// (§4 lock: never leak existence under another project).
	if *rule.ProjectID != projectID {
		return stableErr(c, fiber.StatusNotFound,
			"policy_not_found",
			"policy rule not found", nil)
	}
	return c.JSON(toScopedProjection(rule))
}

// Update handles PUT /projects/:projectID/policy-rules/:ruleID. The
// scoped (gate-chain) path. §3 Q9 lock: explicit empty {} selector
// REJECTED. §4 lock: project mismatch returns policy_not_found, NOT
// out_of_scope_policy.
func (h *ProjectPolicyRules) Update(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("projectID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"projectID is malformed", nil)
	}
	ruleID, err := uuid.Parse(c.Params("ruleID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"ruleID is malformed", nil)
	}
	var body scopedPolicyUpdateBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"request body is not valid JSON", nil)
	}

	in := services.UpdateScopedPolicyInput{
		RuleID:        ruleID,
		ProjectID:     projectID,
		Name:          body.Name,
		Selector:      body.Selector,
		Priority:      body.Priority,
		Enabled:       body.Enabled,
		ActorID:       identityFromCtx(c),
		CorrelationID: uuid.New(),
	}
	if body.WorkflowID != nil {
		wid, err := uuid.Parse(*body.WorkflowID)
		if err != nil {
			return stableErr(c, fiber.StatusBadRequest, "bad_request",
				"workflow_id is malformed", nil)
		}
		in.WorkflowID = &wid
	}

	rule, err := h.engine.UpdateForScopedAuthor(c.Context(), in)
	if err != nil {
		if reason := policyDenialReasonFor(err); reason != "" {
			policyRulesDeniedTotal.WithLabelValues(reason).Inc()
		}
		h.stashLiveCap(c)
		return mapPolicyServiceErr(c, err)
	}

	policyRulesUpdatedTotal.WithLabelValues(
		string(auth.PermPolicyAuthor),
		scopeProject,
	).Inc()
	return c.JSON(toScopedProjection(rule))
}

// Delete handles DELETE /projects/:projectID/policy-rules/:ruleID.
// §4 lock: project mismatch returns policy_not_found, NOT
// out_of_scope_policy.
func (h *ProjectPolicyRules) Delete(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("projectID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"projectID is malformed", nil)
	}
	ruleID, err := uuid.Parse(c.Params("ruleID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"ruleID is malformed", nil)
	}

	if err := h.engine.DeleteForScopedAuthor(c.Context(), services.DeleteScopedPolicyInput{
		RuleID:        ruleID,
		ProjectID:     projectID,
		ActorID:       identityFromCtx(c),
		CorrelationID: uuid.New(),
	}); err != nil {
		if reason := policyDenialReasonFor(err); reason != "" {
			policyRulesDeniedTotal.WithLabelValues(reason).Inc()
		}
		h.stashLiveCap(c)
		return mapPolicyServiceErr(c, err)
	}

	policyRulesDeletedTotal.WithLabelValues(
		string(auth.PermPolicyAuthor),
		scopeProject,
	).Inc()
	return c.SendStatus(fiber.StatusNoContent)
}


// stashLiveCap pre-reads the live PlatformReservedPriority and stashes
// it in Fiber Locals so mapPolicyServiceErr can populate the
// policy_priority_reserved envelope without re-reading the settings
// cache. Best-effort — if the read fails, the envelope falls back to
// the EPIC R hardcode constant.
func (h *ProjectPolicyRules) stashLiveCap(c fiber.Ctx) {
	if h.settings == nil {
		return
	}
	cap, err := h.settings.GetInt(c.Context(), services.KeyPlatformReservedPriority)
	if err != nil {
		return
	}
	c.Locals(policyEnvelopeCapKey, cap)
}
