// R-follow-up #3 (api#126) slice 1c — team-anchored scoped policy rule
// authoring endpoints. Wires the slice 1b gate chains into HTTP with
// stable {error_code, message, ...} envelopes per §4.
//
// Routing:
//
//   POST   /teams/:teamID/policy-rules
//   GET    /teams/:teamID/policy-rules
//   GET    /teams/:teamID/policy-rules/:ruleID
//   PUT    /teams/:teamID/policy-rules/:ruleID
//   DELETE /teams/:teamID/policy-rules/:ruleID
//
// Auth path-pinned per §4 C1: every route requires policy.author scoped
// to teamID via the team-aware resolver. requireTeamPolicyScope runs as
// the FIRST handler line (NOT middleware per §3 C3) so the denial path
// emits the same audit + counter signal the rest of the gate chain
// emits — middleware would lose that.
//
// §4 C2 audit normalization: success events use the normalized
// policy.create / policy.update / policy.delete action names with
// scope: "team" + team_id in metadata. Denied path reuses the existing
// policy.denied_out_of_scope action name with attempted_team_id +
// scope: "team".
//
// §4 C4 workflow collapse: workflow not-found / disabled /
// not-authorable all surface as 403 workflow_not_authorable_for_scope
// with the envelope {workflow_id}.
//
// §5 C4 — admin's policy.edit does NOT auto-allow on /teams/:id. The
// route is policy.author only. Platform admins use /admin/policies for
// team rules (slice 1d).

package handlers

import (
	"encoding/json"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// scopeTeam is the counter label value for the team-anchored surface.
const scopeTeam = "team"

// R-follow-up #3 — two new denial-reason values added to the fixed
// low-cardinality set defined in project_policy_rules.go. Cardinality
// grows from 9 to 11; LOW-CARDINALITY LOCK preserved (no IDs as labels).
const (
	policyDenialOutOfTeamScope = "out_of_team_scope"
	policyDenialTeamNotFound   = "team_not_found"
)

// teamPolicyDenialReasonFor extends the project-side denial classifier
// with the team-specific sentinels. Returns "" when no team-specific
// reason matches; caller falls through to the shared classifier.
func teamPolicyDenialReasonFor(err error) string {
	switch {
	case errors.Is(err, services.ErrOutOfScopeTeamPolicy):
		return policyDenialOutOfTeamScope
	case errors.Is(err, services.ErrTeamNotFound):
		return policyDenialTeamNotFound
	}
	return ""
}

// mapTeamPolicyServiceErr translates the team-scoped service sentinels
// into the {error_code, message, ...} envelope. Falls through to
// mapPolicyServiceErr for codes shared with the project-anchored path
// (policy_not_found, policy_priority_reserved, policy_scope_too_broad,
// workflow_not_authorable_for_scope, platform_setting_unavailable,
// platform_policy_not_editable).
func mapTeamPolicyServiceErr(c fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, services.ErrTeamNotFound):
		return stableErr(c, fiber.StatusNotFound,
			"team_not_found",
			"team not found", nil)
	case errors.Is(err, services.ErrOutOfScopeTeamPolicy):
		return stableErr(c, fiber.StatusForbidden,
			"out_of_scope_team_policy",
			"you don't have policy.author on this team", nil)
	}
	// Shared codes routed by the project mapper. Shape stays
	// identical across both surfaces (single envelope contract).
	return mapPolicyServiceErr(c, err)
}

// ---- handler type ------------------------------------------------

// TeamPolicyRules owns the team-anchored scoped policy.author surface.
// Mirrors ProjectPolicyRules. Settings is consulted so the
// policy_priority_reserved envelope's `cap` field reflects the live
// admin-set value.
type TeamPolicyRules struct {
	engine   *services.PolicyEngine
	policies storage.PolicyRepository
	settings *services.SettingsService
	// R-follow-up #5 slice 1c (api#135) — history service + audit
	// repo. nil-safe: when not wired, History returns 503; production
	// main always wires both via WithHistory.
	history *services.PolicyHistoryService
	audit   storage.AuditEventRepository
}

// NewTeamPolicyRules constructs the handler. PolicyEngine must already
// have WithAuthorScope + WithTeams wired (main does this after
// rbacResolver + teamsRepo + settingsSvc are available).
func NewTeamPolicyRules(engine *services.PolicyEngine, policies storage.PolicyRepository, settings *services.SettingsService) *TeamPolicyRules {
	return &TeamPolicyRules{engine: engine, policies: policies, settings: settings}
}

// WithHistory wires the policy rule history service + audit repo for
// the R-follow-up #5 History endpoint. main calls this after the
// service is constructed; tests may leave it unwired.
func (h *TeamPolicyRules) WithHistory(history *services.PolicyHistoryService, audit storage.AuditEventRepository) *TeamPolicyRules {
	h.history = history
	h.audit = audit
	return h
}

// ---- request / response shapes -----------------------------------

// teamPolicyCreateBody is the wire shape for POST. No team_id field —
// the URL is the source of truth per §4 / R-follow-up #2 URL-key-wins.
type teamPolicyCreateBody struct {
	Name       string         `json:"name"`
	Selector   map[string]any `json:"selector"`
	Priority   int            `json:"priority"`
	WorkflowID string         `json:"workflow_id"`
	Enabled    bool           `json:"enabled"`
}

// teamPolicyUpdateBody uses pointer fields so nil = preserve. Explicit
// empty {} selector is rejected by the service-layer (mirrors EPIC R
// §3 Q9).
type teamPolicyUpdateBody struct {
	Name       *string         `json:"name,omitempty"`
	Selector   *map[string]any `json:"selector,omitempty"`
	Priority   *int            `json:"priority,omitempty"`
	WorkflowID *string         `json:"workflow_id,omitempty"`
	Enabled    *bool           `json:"enabled,omitempty"`
}

// teamPolicyRuleProjection is the wire shape for GET responses.
// Carries §4 C2 + §5 envelope:
//   - is_platform_inherited      → row.project_id IS NULL AND row.team_id IS NULL
//   - is_ancestor_inherited      → row.team_id IS NOT NULL AND != URL teamID
//   - own row (team_id == URL)   → full selector exposed
//   - inherited rows             → selector OMITTED; selector_keys only
type teamPolicyRuleProjection struct {
	ID                  uuid.UUID      `json:"id"`
	Name                string         `json:"name"`
	TeamID              *string        `json:"team_id"`
	TeamName            string         `json:"team_name,omitempty"`
	WorkflowID          uuid.UUID      `json:"workflow_id"`
	WorkflowName        string         `json:"workflow_name,omitempty"`
	IsPlatformInherited bool           `json:"is_platform_inherited"`
	IsAncestorInherited bool           `json:"is_ancestor_inherited"`
	SelectorKeys        []string       `json:"selector_keys"`
	Selector            map[string]any `json:"selector,omitempty"`
	Priority            int            `json:"priority"`
	Enabled             bool           `json:"enabled"`
	IsSystem            bool           `json:"is_system"`
	CreatedAt           string         `json:"created_at,omitempty"`
	UpdatedAt           string         `json:"updated_at,omitempty"`
}

// teamPolicyRulesListResponse envelopes the team list. Carries the
// live priority_cap from SettingsService (R-follow-up #2 §3 — SPA
// drawer reads from envelope so a stale fallback never happens).
type teamPolicyRulesListResponse struct {
	Rules       []teamPolicyRuleProjection `json:"rules"`
	PriorityCap int                        `json:"priority_cap"`
}

// teamPolicyRuleResponse envelopes the single-rule response with the
// live priority_cap.
type teamPolicyRuleResponse struct {
	Rule        teamPolicyRuleProjection `json:"rule"`
	PriorityCap int                      `json:"priority_cap"`
}

// toTeamOwnProjection emits the FULL projection (selector exposed) for
// rules owned by the URL team (team_id matches URL teamID).
func toTeamOwnProjection(p *storage.PolicyRule) teamPolicyRuleProjection {
	var teamIDPtr *string
	if p.TeamID != nil {
		s := p.TeamID.String()
		teamIDPtr = &s
	}
	return teamPolicyRuleProjection{
		ID:                  p.ID,
		Name:                p.Name,
		TeamID:              teamIDPtr,
		TeamName:            p.TeamName,
		WorkflowID:          p.WorkflowID,
		WorkflowName:        p.WorkflowName,
		IsPlatformInherited: false,
		IsAncestorInherited: false,
		SelectorKeys:        selectorKeysOf(p.Selector),
		Selector:            p.Selector,
		Priority:            p.Priority,
		Enabled:             p.Enabled,
		IsSystem:            p.IsSystem,
		CreatedAt:           p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:           p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

// toTeamInheritedProjection emits the SANITIZED projection for
// platform-inherited or ancestor-team-inherited rules surfaced via the
// team GET. Scoped users see WHICH keys constrain the inherited rule,
// never the values (defense against selector leakage across siblings
// that share a parent team).
func toTeamInheritedProjection(p *storage.PolicyRule, isPlatform, isAncestor bool) teamPolicyRuleProjection {
	var teamIDPtr *string
	if p.TeamID != nil {
		s := p.TeamID.String()
		teamIDPtr = &s
	}
	return teamPolicyRuleProjection{
		ID:                  p.ID,
		Name:                p.Name,
		TeamID:              teamIDPtr,
		TeamName:            p.TeamName,
		WorkflowID:          p.WorkflowID,
		WorkflowName:        p.WorkflowName,
		IsPlatformInherited: isPlatform,
		IsAncestorInherited: isAncestor,
		SelectorKeys:        selectorKeysOf(p.Selector),
		// Selector deliberately omitted.
		Priority:  p.Priority,
		Enabled:   p.Enabled,
		IsSystem:  p.IsSystem,
		CreatedAt: p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

// ---- coverage gate (handler helper, not middleware) ---------------

// requireTeamPolicyScope runs gate 1 (coverage) as the first line of
// every handler. Per §3 C3 / §4 C3 — kept in the handler so the denial
// path emits the same envelope + audit + counter as the rest of the
// gate chain. Returns nil to proceed; non-nil to terminate.
//
// On denial, the audit event + counter are emitted by the service-
// layer engine's auditPolicyDeniedOutOfTeamScope. The handler then
// surfaces ErrOutOfScopeTeamPolicy via mapTeamPolicyServiceErr.
func (h *TeamPolicyRules) requireTeamPolicyScope(c fiber.Ctx, teamID uuid.UUID, actor string) error {
	// Coverage runs via a dry-run Create with synthetic body. We don't
	// invoke the engine directly here because the gate's audit + counter
	// emission is centralised in the service-layer's gate 1 helper.
	// Instead we use the same EffectiveTeamAccess primitive and emit
	// the audit + counter inline. Service-layer Create runs its own
	// coverage gate too — defense in depth.
	access, err := auth.EffectiveTeamAccess(c.Context(), actor, auth.PermPolicyAuthor,
		h.engine.AuthorResolver(), h.engine.AuthorTeamScope())
	if err != nil {
		return stableErr(c, fiber.StatusInternalServerError, "internal_error",
			"could not resolve team access", nil)
	}
	if access.IsGlobal {
		return nil
	}
	for _, id := range access.TeamIDs {
		if id == teamID {
			return nil
		}
	}
	// Denied — emit audit + counter via the engine's helper (keeps
	// denial-emission centralised on the service layer where
	// auditPolicyDeniedOutOfTeamScope is defined).
	h.engine.EmitPolicyDeniedOutOfTeamScope(c.Context(), actor, teamID, uuid.New())
	policyRulesDeniedTotal.WithLabelValues(policyDenialOutOfTeamScope).Inc()
	return stableErr(c, fiber.StatusForbidden,
		"out_of_scope_team_policy",
		"you don't have policy.author on this team", nil)
}

// ---- handlers ---------------------------------------------------

// Create handles POST /teams/:teamID/policy-rules.
func (h *TeamPolicyRules) Create(c fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("teamID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"teamID is malformed", nil)
	}
	actor := identityFromCtx(c)

	if termErr := h.requireTeamPolicyScope(c, teamID, actor); termErr != nil {
		return termErr
	}

	var body teamPolicyCreateBody
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

	rule, err := h.engine.CreateForTeamScopedAuthor(c.Context(), services.CreateTeamScopedPolicyInput{
		TeamID:        teamID,
		Name:          body.Name,
		Selector:      body.Selector,
		Priority:      body.Priority,
		WorkflowID:    workflowID,
		Enabled:       body.Enabled,
		ActorID:       actor,
		CorrelationID: uuid.New(),
	})
	if err != nil {
		if reason := teamPolicyDenialReasonFor(err); reason != "" {
			policyRulesDeniedTotal.WithLabelValues(reason).Inc()
		} else if reason := policyDenialReasonFor(err); reason != "" {
			policyRulesDeniedTotal.WithLabelValues(reason).Inc()
		}
		h.stashLiveCap(c)
		return mapTeamPolicyServiceErr(c, err)
	}

	policyRulesCreatedTotal.WithLabelValues(string(auth.PermPolicyAuthor), scopeTeam).Inc()
	cap := h.readLiveCapOrZero(c)
	return c.Status(fiber.StatusCreated).JSON(teamPolicyRuleResponse{
		Rule:        toTeamOwnProjection(rule),
		PriorityCap: cap,
	})
}

// List handles GET /teams/:teamID/policy-rules. Sanitization on
// inherited rows lives in the SQL filter from slice 1a's ListForTeam;
// the handler classifies each row as own / ancestor-inherited /
// platform-inherited based on the row's anchor.
func (h *TeamPolicyRules) List(c fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("teamID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"teamID is malformed", nil)
	}
	actor := identityFromCtx(c)
	if termErr := h.requireTeamPolicyScope(c, teamID, actor); termErr != nil {
		return termErr
	}

	rules, err := h.policies.ListForTeam(c.Context(), teamID)
	if err != nil {
		return mapTeamPolicyServiceErr(c, err)
	}
	out := make([]teamPolicyRuleProjection, 0, len(rules))
	for _, r := range rules {
		switch {
		case r.TeamID == nil && r.ProjectID == nil:
			out = append(out, toTeamInheritedProjection(r, true, false))
		case r.TeamID != nil && *r.TeamID == teamID:
			out = append(out, toTeamOwnProjection(r))
		case r.TeamID != nil && *r.TeamID != teamID:
			out = append(out, toTeamInheritedProjection(r, false, true))
		}
	}
	return c.JSON(teamPolicyRulesListResponse{
		Rules:       out,
		PriorityCap: h.readLiveCapOrZero(c),
	})
}

// Get handles GET /teams/:teamID/policy-rules/:ruleID.
func (h *TeamPolicyRules) Get(c fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("teamID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"teamID is malformed", nil)
	}
	ruleID, err := uuid.Parse(c.Params("ruleID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"ruleID is malformed", nil)
	}
	actor := identityFromCtx(c)
	if termErr := h.requireTeamPolicyScope(c, teamID, actor); termErr != nil {
		return termErr
	}
	rule, err := h.policies.Get(c.Context(), ruleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return stableErr(c, fiber.StatusNotFound,
				"policy_not_found",
				"policy rule not found", nil)
		}
		return mapTeamPolicyServiceErr(c, err)
	}
	// Anchor-based classification matching the List filter.
	cap := h.readLiveCapOrZero(c)
	switch {
	case rule.TeamID == nil && rule.ProjectID == nil:
		return c.JSON(teamPolicyRuleResponse{
			Rule:        toTeamInheritedProjection(rule, true, false),
			PriorityCap: cap,
		})
	case rule.TeamID != nil && *rule.TeamID == teamID:
		return c.JSON(teamPolicyRuleResponse{
			Rule:        toTeamOwnProjection(rule),
			PriorityCap: cap,
		})
	case rule.TeamID != nil && *rule.TeamID != teamID:
		return c.JSON(teamPolicyRuleResponse{
			Rule:        toTeamInheritedProjection(rule, false, true),
			PriorityCap: cap,
		})
	}
	// Project-anchored row reached via team URL — wrong family.
	return stableErr(c, fiber.StatusNotFound,
		"policy_not_found",
		"policy rule not found", nil)
}

// Update handles PUT /teams/:teamID/policy-rules/:ruleID.
func (h *TeamPolicyRules) Update(c fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("teamID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"teamID is malformed", nil)
	}
	ruleID, err := uuid.Parse(c.Params("ruleID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"ruleID is malformed", nil)
	}
	actor := identityFromCtx(c)
	if termErr := h.requireTeamPolicyScope(c, teamID, actor); termErr != nil {
		return termErr
	}

	var body teamPolicyUpdateBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"request body is not valid JSON", nil)
	}

	in := services.UpdateTeamScopedPolicyInput{
		RuleID:        ruleID,
		TeamID:        teamID,
		Name:          body.Name,
		Selector:      body.Selector,
		Priority:      body.Priority,
		Enabled:       body.Enabled,
		ActorID:       actor,
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

	rule, err := h.engine.UpdateForTeamScopedAuthor(c.Context(), in)
	if err != nil {
		if reason := teamPolicyDenialReasonFor(err); reason != "" {
			policyRulesDeniedTotal.WithLabelValues(reason).Inc()
		} else if reason := policyDenialReasonFor(err); reason != "" {
			policyRulesDeniedTotal.WithLabelValues(reason).Inc()
		}
		h.stashLiveCap(c)
		return mapTeamPolicyServiceErr(c, err)
	}

	policyRulesUpdatedTotal.WithLabelValues(string(auth.PermPolicyAuthor), scopeTeam).Inc()
	return c.JSON(teamPolicyRuleResponse{
		Rule:        toTeamOwnProjection(rule),
		PriorityCap: h.readLiveCapOrZero(c),
	})
}

// Delete handles DELETE /teams/:teamID/policy-rules/:ruleID.
func (h *TeamPolicyRules) Delete(c fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("teamID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"teamID is malformed", nil)
	}
	ruleID, err := uuid.Parse(c.Params("ruleID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"ruleID is malformed", nil)
	}
	actor := identityFromCtx(c)
	if termErr := h.requireTeamPolicyScope(c, teamID, actor); termErr != nil {
		return termErr
	}

	if err := h.engine.DeleteForTeamScopedAuthor(c.Context(), services.DeleteTeamScopedPolicyInput{
		RuleID:        ruleID,
		TeamID:        teamID,
		ActorID:       actor,
		CorrelationID: uuid.New(),
	}); err != nil {
		if reason := teamPolicyDenialReasonFor(err); reason != "" {
			policyRulesDeniedTotal.WithLabelValues(reason).Inc()
		} else if reason := policyDenialReasonFor(err); reason != "" {
			policyRulesDeniedTotal.WithLabelValues(reason).Inc()
		}
		h.stashLiveCap(c)
		return mapTeamPolicyServiceErr(c, err)
	}

	policyRulesDeletedTotal.WithLabelValues(string(auth.PermPolicyAuthor), scopeTeam).Inc()
	return c.SendStatus(fiber.StatusNoContent)
}

// stashLiveCap pre-reads the live PlatformReservedPriority and stashes
// it in Fiber Locals so mapTeamPolicyServiceErr (via mapPolicyServiceErr)
// can populate the policy_priority_reserved envelope without re-reading
// the settings cache.
func (h *TeamPolicyRules) stashLiveCap(c fiber.Ctx) {
	if h.settings == nil {
		return
	}
	cap, err := h.settings.GetInt(c.Context(), services.KeyPlatformReservedPriority)
	if err != nil {
		return
	}
	c.Locals(policyEnvelopeCapKey, cap)
}

// readLiveCapOrZero pulls the live cap for inclusion in success-path
// envelopes (TeamPolicyRuleResponse + TeamPolicyRulesListResponse).
// Returns 0 when settings isn't wired or unavailable — the SPA's
// Author drawer treats a 0/missing cap as a fail-closed signal.
func (h *TeamPolicyRules) readLiveCapOrZero(c fiber.Ctx) int {
	if h.settings == nil {
		return 0
	}
	cap, err := h.settings.GetInt(c.Context(), services.KeyPlatformReservedPriority)
	if err != nil {
		return 0
	}
	return cap
}

// History handles GET /teams/:teamID/policy-rules/:ruleID/history.
// R-follow-up #5 slice 1c (api#135) — team-anchored history view.
//
// Gate chain per §4 D3:
//
//  1. Parse URL params
//  2. Coverage — requireTeamPolicyScope (handler helper, NOT middleware,
//     per R-follow-up #3 §3 C3 — denial emits its own audit + counter)
//  3. Resource load — policyRepo.Get(ruleID); 404 on missing OR deleted
//     (scoped post-delete behavior per C4: scoped paths lose access at
//     delete time; admin /policies/:id/history retains forensic visibility)
//  4. Anchor routing — rule.TeamID nil OR != URL teamID → silent
//     404 policy_not_found (§4 OQ4-1; gate-order enumeration protection)
//  5. Service call — policyHistorySvc.ListForRule
//  6. Counter + audit — policy_rule_history_views_total{scope="team"}
//     + audit.read.policy_history event
func (h *TeamPolicyRules) History(c fiber.Ctx) error {
	if h.history == nil {
		return stableErr(c, fiber.StatusServiceUnavailable,
			"history_unavailable",
			"policy history service not configured", nil)
	}

	teamID, err := uuid.Parse(c.Params("teamID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"teamID is malformed", nil)
	}
	ruleID, err := uuid.Parse(c.Params("ruleID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"ruleID is malformed", nil)
	}

	limit, err := parseHistoryLimit(c)
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			err.Error(), nil)
	}

	actor := identityFromCtx(c)
	if termErr := h.requireTeamPolicyScope(c, teamID, actor); termErr != nil {
		return termErr
	}

	rule, err := h.policies.Get(c.Context(), ruleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return stableErr(c, fiber.StatusNotFound,
				"policy_not_found",
				"policy rule not found", nil)
		}
		return mapTeamPolicyServiceErr(c, err)
	}

	// §4 anchor routing — wrong-anchor (or non-team) → silent 404.
	// Mirrors the team Get handler's enumeration protection.
	if rule.TeamID == nil || *rule.TeamID != teamID {
		return stableErr(c, fiber.StatusNotFound,
			"policy_not_found",
			"policy rule not found", nil)
	}

	entries, hasMore, err := h.history.ListForRule(c.Context(), ruleID, rule, limit)
	if err != nil {
		return stableErr(c, fiber.StatusInternalServerError,
			"history_internal_error",
			err.Error(), nil)
	}

	policyRuleHistoryViewsTotal.WithLabelValues(scopeTeam).Inc()
	auditReadPolicyHistory(c, h.audit, ruleID, scopeTeam, len(entries))

	return c.JSON(policyRuleHistoryResponse{
		RuleID:  ruleID.String(),
		Scope:   scopeTeam,
		Entries: toHistoryEntryWires(entries),
		HasMore: hasMore,
		Limit:   limit,
	})
}
