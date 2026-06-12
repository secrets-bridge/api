// R-follow-up #3 (api#125) slice 1b — team-scoped policy authoring service.
//
// CreateForTeamScopedAuthor + UpdateForTeamScopedAuthor +
// DeleteForTeamScopedAuthor are the policy.author surface for the
// `/teams/:teamID/policy-rules` URL family. They mirror the project-
// scoped variants (policy_scoped.go) but anchor on team_id instead of
// project_id and cascade subtree-down at resolution time.
//
//   Create (6 gates, §4 C5-reordered):
//     1. actor covers in.TeamID via EffectiveTeamAccess
//     2. team exists + status='active'   (race-only path)
//     3. in.Priority < live cap from SettingsService
//     4. validateTeamSelector             (§1 C1 — strict)
//     5. workflow exists + ScopedPolicyAuthorable
//     6. INSERT + emit policy.create with scope: "team"
//
//   Update (8 gates):
//     1. coverage
//     2. rule exists (repo.Get)
//     3. URL teamID mismatch / project rule / platform inherited routing
//     4. is_system protection
//     5. priority revalidation against live cap (§3 critical pin)
//     6. selector consistency on body change
//     7. workflow re-validation when workflow_id changes (R-follow-up #1 grandfather)
//     8. UPDATE + emit policy.update with changed_keys + scope: "team"
//
//   Delete (5 gates):
//     1. coverage
//     2. rule exists
//     3. teamID mismatch / inherited routing
//     4. is_system protection
//     5. DELETE + emit policy.delete with scope: "team"
//
// Gate ordering matches the enumeration-leak-safe posture EPIC R + EPIC Q
// established: coverage runs BEFORE resource load. Out-of-scope callers
// get out_of_scope_team_policy; coverage holders trying to act on a
// non-matching team get team_not_found (race window only — coverage
// passed but the team disappeared between gate 1 and gate 2).
//
// Selector validation (§1 C1 strict for team rules):
//   - selector.environment_kind MUST equal "non_prod"
//   - selector.project_id        MUST be absent
//   - selector.environment_id    MUST be absent
//   - selector.team_id           MUST be absent (v1 lock)
//   - safe-list optional keys: secret_ref_prefix, provider_type, operation
//     (no semantic validation in v1; selector enum design is deferred)

package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ---- sentinels mapped to stable HTTP codes in slice 1c -------------

var (
	// ErrOutOfScopeTeamPolicy fires when the actor's EffectiveTeamAccess
	// doesn't cover the URL teamID. Handler maps to 403
	// out_of_scope_team_policy.
	ErrOutOfScopeTeamPolicy = errors.New("services: actor does not cover the target team for policy authoring")

	// ErrTeamNotFound fires when the team does not exist or has been
	// archived. Handler maps to 404 team_not_found. Race-only path —
	// coverage already passed at gate 1.
	ErrTeamNotFound = errors.New("services: team not found")
)

// ---- new policy_scope_too_broad reason variants for team rules ----

const (
	// PolicyScopeTooBroadTeamSelectorPinsProject fires when a team
	// rule's selector includes a `project_id` key. Team rules cascade
	// to descendant projects; pinning a specific project_id collapses
	// them into a project-scoped rule.
	PolicyScopeTooBroadTeamSelectorPinsProject = "team_selector_pins_project"

	// PolicyScopeTooBroadTeamSelectorPinsEnvironmentID fires when a
	// team rule's selector includes an `environment_id` key.
	// environment_id resolves to one project's env; team rules MUST
	// stay subtree-applicable.
	PolicyScopeTooBroadTeamSelectorPinsEnvironmentID = "team_selector_pins_environment_id"

	// PolicyScopeTooBroadTeamSelectorPinsTeamID fires when a team
	// rule's selector includes a `team_id` key (forbidden in v1).
	// The row column `team_id` is the anchor; allowing the selector
	// key creates a second source of truth.
	PolicyScopeTooBroadTeamSelectorPinsTeamID = "team_selector_pins_team_id"
)

// ---- service wiring -----------------------------------------------

// WithTeams binds the TeamRepository the team-scoped path needs for
// gate 2 (team exists + active). Pass nil to disable the team scope
// path. main always wires this in production.
func (e *PolicyEngine) WithTeams(t storage.TeamRepository) *PolicyEngine {
	e.teams = t
	return e
}

// ---- input shapes -------------------------------------------------

// CreateTeamScopedPolicyInput is the shape the slice 1c handler will
// hand the service. TeamID comes from the URL.
type CreateTeamScopedPolicyInput struct {
	TeamID        uuid.UUID
	Name          string
	Selector      map[string]any
	Priority      int
	WorkflowID    uuid.UUID
	Enabled       bool
	ActorID       string
	CorrelationID uuid.UUID
}

// UpdateTeamScopedPolicyInput uses pointer fields so nil means "don't
// touch." Selector pointing to an empty map = REJECT with
// PolicyScopeTooBroadSelectorEmpty (mirrors EPIC R §3 Q9).
type UpdateTeamScopedPolicyInput struct {
	RuleID     uuid.UUID
	TeamID     uuid.UUID
	Name       *string
	Selector   *map[string]any
	Priority   *int
	WorkflowID *uuid.UUID
	Enabled    *bool

	ActorID       string
	CorrelationID uuid.UUID
}

// DeleteTeamScopedPolicyInput carries the URL teamID so the §4
// mismatch protection runs (mismatch → ErrPolicyNotFound, never
// ErrOutOfScopeTeamPolicy).
type DeleteTeamScopedPolicyInput struct {
	RuleID        uuid.UUID
	TeamID        uuid.UUID
	ActorID       string
	CorrelationID uuid.UUID
}

// ---- gate chains --------------------------------------------------

// CreateForTeamScopedAuthor runs the 6-gate chain locked at §4 C5.
func (e *PolicyEngine) CreateForTeamScopedAuthor(ctx context.Context, in CreateTeamScopedPolicyInput) (*storage.PolicyRule, error) {
	if e.authorResolver == nil || e.teams == nil {
		return nil, errors.New("services: team-scoped policy path requires WithAuthorScope + WithTeams wiring")
	}

	// Gate 1 — actor covers team.
	access, err := auth.EffectiveTeamAccess(ctx, in.ActorID, auth.PermPolicyAuthor, e.authorResolver, e.authorTeamScope)
	if err != nil {
		return nil, fmt.Errorf("services: resolve scoped author team access: %w", err)
	}
	if !teamAccessCoversPolicy(access, in.TeamID) {
		e.auditPolicyDeniedOutOfTeamScope(ctx, in.ActorID, in.TeamID, in.CorrelationID)
		return nil, ErrOutOfScopeTeamPolicy
	}

	// Gate 2 — team exists + active. Race-only path; coverage passed
	// above so a deleted-meanwhile team yields team_not_found (not
	// out_of_scope, which would be misleading).
	team, err := e.teams.Get(ctx, in.TeamID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrTeamNotFound
		}
		return nil, fmt.Errorf("services: load team: %w", err)
	}
	if team.Status != storage.TeamStatusActive {
		return nil, ErrTeamNotFound
	}

	// Gate 3 — priority < live cap. R-follow-up #2 §3 critical pin —
	// gate must read the LIVE value, not a hardcode. Fail-closed on
	// settings unavailability.
	cap, err := e.reservedPriorityCap(ctx)
	if err != nil {
		return nil, err
	}
	if in.Priority >= cap {
		return nil, ErrPolicyPriorityReserved
	}

	// Gate 4 — selector consistency (§1 C1 strict).
	if err := validateTeamSelector(in.Selector); err != nil {
		return nil, err
	}

	// Gate 5 — workflow exists + scoped_policy_authorable. Per §4 C4
	// the three failure modes (not-found / disabled / not-authorable)
	// all collapse to the same envelope.
	wf, err := e.workflows.Get(ctx, in.WorkflowID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			e.auditPolicyDeniedWorkflowNotAuthorableForTeam(ctx, in.ActorID, in.TeamID, in.WorkflowID, in.CorrelationID)
			return nil, &WorkflowNotAuthorableDetail{WorkflowID: in.WorkflowID}
		}
		return nil, fmt.Errorf("services: workflow %s: %w", in.WorkflowID, err)
	}
	if !wf.Enabled || !wf.ScopedPolicyAuthorable {
		e.auditPolicyDeniedWorkflowNotAuthorableForTeam(ctx, in.ActorID, in.TeamID, in.WorkflowID, in.CorrelationID)
		return nil, &WorkflowNotAuthorableDetail{WorkflowID: in.WorkflowID}
	}

	// Gate 6 — INSERT + audit.
	teamID := in.TeamID
	rule := &storage.PolicyRule{
		Name:       in.Name,
		Selector:   in.Selector,
		WorkflowID: in.WorkflowID,
		Priority:   in.Priority,
		Enabled:    in.Enabled,
		TeamID:     &teamID,
	}
	if err := e.policies.Create(ctx, rule); err != nil {
		return nil, fmt.Errorf("services: create team-scoped policy: %w", err)
	}
	e.auditTeamPolicySuccess(ctx, "policy.create", rule, in.ActorID, in.CorrelationID,
		auth.PermPolicyAuthor, nil)
	return rule, nil
}

// UpdateForTeamScopedAuthor runs the 8-gate chain.
func (e *PolicyEngine) UpdateForTeamScopedAuthor(ctx context.Context, in UpdateTeamScopedPolicyInput) (*storage.PolicyRule, error) {
	if e.authorResolver == nil || e.teams == nil {
		return nil, errors.New("services: team-scoped policy path requires WithAuthorScope + WithTeams wiring")
	}

	// Gate 1 — actor covers team.
	access, err := auth.EffectiveTeamAccess(ctx, in.ActorID, auth.PermPolicyAuthor, e.authorResolver, e.authorTeamScope)
	if err != nil {
		return nil, fmt.Errorf("services: resolve scoped author team access: %w", err)
	}
	if !teamAccessCoversPolicy(access, in.TeamID) {
		e.auditPolicyDeniedOutOfTeamScope(ctx, in.ActorID, in.TeamID, in.CorrelationID)
		return nil, ErrOutOfScopeTeamPolicy
	}

	// Gate 2 — rule exists.
	rule, err := e.policies.Get(ctx, in.RuleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrPolicyNotFound
		}
		return nil, fmt.Errorf("services: load policy: %w", err)
	}

	// Gate 3 — URL teamID / anchor routing. §4 lock: mismatches return
	// not_found (never out_of_scope, which would leak existence).
	switch {
	case rule.TeamID == nil && rule.ProjectID == nil:
		// Platform inherited via team URL — explicit
		// platform_policy_not_editable.
		return nil, ErrPlatformPolicyNotEditable
	case rule.ProjectID != nil:
		// Project rule via team URL — wrong URL family.
		return nil, ErrPolicyNotFound
	case rule.TeamID != nil && *rule.TeamID != in.TeamID:
		// Ancestor / sibling team rule via the wrong team URL.
		return nil, ErrPolicyNotFound
	}

	// Gate 4 — is_system protection. System rows are NOT editable via
	// scoped URLs even when an admin holds the permission.
	if rule.IsSystem {
		return nil, storage.ErrSystemRow
	}

	// Build the patched rule, then re-validate.
	patched := *rule
	changedKeys := []string{}
	if in.Name != nil && *in.Name != patched.Name {
		patched.Name = *in.Name
		changedKeys = append(changedKeys, "name")
	}
	if in.Priority != nil && *in.Priority != patched.Priority {
		patched.Priority = *in.Priority
		changedKeys = append(changedKeys, "priority")
	}
	if in.WorkflowID != nil && *in.WorkflowID != patched.WorkflowID {
		patched.WorkflowID = *in.WorkflowID
		changedKeys = append(changedKeys, "workflow_id")
	}
	if in.Enabled != nil && *in.Enabled != patched.Enabled {
		patched.Enabled = *in.Enabled
		changedKeys = append(changedKeys, "enabled")
	}
	if in.Selector != nil {
		// Explicit {} REJECTED (mirrors EPIC R §3 Q9). nil pointer =
		// preserve (we don't enter this branch).
		patched.Selector = *in.Selector
		changedKeys = append(changedKeys, "selector")
	}

	// Gate 5 — priority < live cap. R-follow-up #2 §3 critical pin —
	// EVERY Update re-validates against the live cap, NOT only when
	// priority is the field changing. Admin may have lowered the cap
	// since the rule was authored; bumping any other field shouldn't
	// keep a now-out-of-band priority alive.
	cap, err := e.reservedPriorityCap(ctx)
	if err != nil {
		return nil, err
	}
	if patched.Priority >= cap {
		return nil, ErrPolicyPriorityReserved
	}

	// Gate 6 — selector consistency on body change. nil-Selector
	// preserves the existing row's selector (already validated when
	// it was created — no re-validation needed for unchanged data).
	if in.Selector != nil {
		if err := validateTeamSelector(patched.Selector); err != nil {
			return nil, err
		}
	}

	// Gate 7 — workflow re-validation when workflow_id changes.
	// Workflow lookup runs unconditionally so the typed sentinels
	// stay consistent, but the grandfather rule (§1 Q4 from
	// R-follow-up #1) only enforces the authorable-flag check when
	// the workflow attachment is actually changing.
	wf, err := e.workflows.Get(ctx, patched.WorkflowID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			e.auditPolicyDeniedWorkflowNotAuthorableForTeam(ctx, in.ActorID, in.TeamID, patched.WorkflowID, in.CorrelationID)
			return nil, &WorkflowNotAuthorableDetail{WorkflowID: patched.WorkflowID}
		}
		return nil, fmt.Errorf("services: workflow %s: %w", patched.WorkflowID, err)
	}
	workflowChanged := in.WorkflowID != nil && *in.WorkflowID != rule.WorkflowID
	if workflowChanged && (!wf.Enabled || !wf.ScopedPolicyAuthorable) {
		e.auditPolicyDeniedWorkflowNotAuthorableForTeam(ctx, in.ActorID, in.TeamID, patched.WorkflowID, in.CorrelationID)
		return nil, &WorkflowNotAuthorableDetail{WorkflowID: patched.WorkflowID}
	}

	// Gate 8 — UPDATE + audit. Storage-level ErrAnchorImmutable is a
	// defense-in-depth backstop; the patched row carries the same
	// TeamID we loaded so the check should pass.
	if err := e.policies.Update(ctx, &patched); err != nil {
		return nil, fmt.Errorf("services: update team-scoped policy: %w", err)
	}
	e.auditTeamPolicySuccess(ctx, "policy.update", &patched, in.ActorID, in.CorrelationID,
		auth.PermPolicyAuthor, changedKeys)
	return &patched, nil
}

// DeleteForTeamScopedAuthor runs the 5-gate chain.
func (e *PolicyEngine) DeleteForTeamScopedAuthor(ctx context.Context, in DeleteTeamScopedPolicyInput) error {
	if e.authorResolver == nil || e.teams == nil {
		return errors.New("services: team-scoped policy path requires WithAuthorScope + WithTeams wiring")
	}

	// Gate 1 — actor covers team.
	access, err := auth.EffectiveTeamAccess(ctx, in.ActorID, auth.PermPolicyAuthor, e.authorResolver, e.authorTeamScope)
	if err != nil {
		return fmt.Errorf("services: resolve scoped author team access: %w", err)
	}
	if !teamAccessCoversPolicy(access, in.TeamID) {
		e.auditPolicyDeniedOutOfTeamScope(ctx, in.ActorID, in.TeamID, in.CorrelationID)
		return ErrOutOfScopeTeamPolicy
	}

	// Gate 2 — rule exists.
	rule, err := e.policies.Get(ctx, in.RuleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrPolicyNotFound
		}
		return fmt.Errorf("services: load policy: %w", err)
	}

	// Gate 3 — URL teamID / anchor routing (mirrors Update gate 3).
	switch {
	case rule.TeamID == nil && rule.ProjectID == nil:
		return ErrPlatformPolicyNotEditable
	case rule.ProjectID != nil:
		return ErrPolicyNotFound
	case rule.TeamID != nil && *rule.TeamID != in.TeamID:
		return ErrPolicyNotFound
	}

	// Gate 4 — is_system protection.
	if rule.IsSystem {
		return storage.ErrSystemRow
	}

	// Gate 5 — DELETE + audit.
	if err := e.policies.Delete(ctx, in.RuleID); err != nil {
		return fmt.Errorf("services: delete team-scoped policy: %w", err)
	}
	e.auditTeamPolicySuccess(ctx, "policy.delete", rule, in.ActorID, in.CorrelationID,
		auth.PermPolicyAuthor, nil)
	return nil
}

// ---- handler accessors --------------------------------------------

// AuthorResolver returns the resolver the team-scoped handler needs
// for its gate-1 coverage check. Slice 1c's requireTeamPolicyScope
// helper calls it inline so the denial path stays in the handler
// (preserves audit + counter emission alongside the rest of the gate
// chain — middleware would lose that).
func (e *PolicyEngine) AuthorResolver() auth.Resolver { return e.authorResolver }

// AuthorTeamScope returns the team-scope resolver wired alongside
// AuthorResolver. Used by handler's gate-1 helper.
func (e *PolicyEngine) AuthorTeamScope() auth.TeamScopeResolver { return e.authorTeamScope }

// EmitPolicyDeniedOutOfTeamScope exposes the centralised denial
// audit emission to the handler so requireTeamPolicyScope doesn't
// duplicate the audit shape. Safe no-op when audit is nil.
func (e *PolicyEngine) EmitPolicyDeniedOutOfTeamScope(ctx context.Context, actorID string, teamID uuid.UUID, correlationID uuid.UUID) {
	e.auditPolicyDeniedOutOfTeamScope(ctx, actorID, teamID, correlationID)
}

// ---- helpers ------------------------------------------------------

// teamAccessCoversPolicy returns whether the resolved TeamAccess
// covers the target teamID. Global access wins.
func teamAccessCoversPolicy(access auth.TeamAccess, target uuid.UUID) bool {
	if access.IsGlobal {
		return true
	}
	for _, id := range access.TeamIDs {
		if id == target {
			return true
		}
	}
	return false
}

// validateTeamSelector enforces the §1 C1 strict selector rules for
// team rules:
//
//	1. selector empty {}                         → scope_too_broad / selector_empty
//	2. selector.project_id present               → scope_too_broad / team_selector_pins_project
//	3. selector.environment_id present           → scope_too_broad / team_selector_pins_environment_id
//	4. selector.team_id present                  → scope_too_broad / team_selector_pins_team_id (v1 lock)
//	5. selector.environment_kind != "non_prod"   → scope_too_broad / env_kind_invalid
//	6. selector.environment_kind == "prod"       → prod_policy_not_allowed_for_scope
//	7. selector.environment_kind absent          → scope_too_broad / env_constraint_missing
//
// The DB CHECK constraints from migration 0037 also catch (1)–(4) and
// (7), but the service-layer catches them earlier with typed sentinels
// that map to friendly error envelopes at the handler.
func validateTeamSelector(selector map[string]any) error {
	if len(selector) == 0 {
		return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadSelectorEmpty}
	}

	// Forbidden pin keys first — these are stricter than the
	// environment_kind branch and should surface before the kind
	// check.
	if _, ok := selector["project_id"]; ok {
		return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadTeamSelectorPinsProject}
	}
	if _, ok := selector["environment_id"]; ok {
		return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadTeamSelectorPinsEnvironmentID}
	}
	if _, ok := selector["team_id"]; ok {
		return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadTeamSelectorPinsTeamID}
	}

	// Selector enum v1 lock (api#139) — provider_type, when present,
	// MUST be a member of the locked backend enum. Absent = wildcard.
	if d := ValidateProviderTypeSelector(selector); d != nil {
		return d
	}
	// Operation dimension (api#141) — same posture.
	if d := ValidateOperationSelector(selector); d != nil {
		return d
	}

	// Required environment_kind = "non_prod".
	kindRaw, hasKind := selector["environment_kind"]
	if !hasKind {
		return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadEnvConstraintMissing}
	}
	kindStr, ok := kindRaw.(string)
	if !ok {
		return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadEnvKindInvalid}
	}
	switch storage.EnvironmentKind(kindStr) {
	case storage.EnvironmentKindNonProd:
		return nil
	case storage.EnvironmentKindProd:
		return ErrProdPolicyNotAllowedForScope
	default:
		return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadEnvKindInvalid}
	}
}

// ---- audit emission -----------------------------------------------

// auditTeamPolicySuccess is the team-scope counterpart of
// auditPolicySuccess. Same action names (policy.create / .update /
// .delete) per §4 C2 normalization, with `scope: "team"` and
// `team_id` in metadata instead of `project_id`.
func (e *PolicyEngine) auditTeamPolicySuccess(
	ctx context.Context,
	action string,
	rule *storage.PolicyRule,
	actorID string,
	correlationID uuid.UUID,
	permUsed auth.Permission,
	changedKeys []string,
) {
	if e.audit == nil {
		return
	}
	teamIDMeta := ""
	if rule.TeamID != nil {
		teamIDMeta = rule.TeamID.String()
	}
	// §6 lock: selector KEYS only, NEVER values.
	keys := make([]string, 0, len(rule.Selector))
	for k := range rule.Selector {
		keys = append(keys, k)
	}
	// R-follow-up #5 slice 1b (api#134) — snapshot extension: add
	// `name` + `enabled` so PolicyHistoryService can diff them
	// without re-reading the rule row from the DB.
	meta := map[string]any{
		"policy_rule_id":        rule.ID.String(),
		"team_id":               teamIDMeta,
		"project_id":            nil,
		"scope":                 "team",
		"name":                  rule.Name,
		"enabled":               rule.Enabled,
		"priority":              rule.Priority,
		"selector_keys":         keys,
		"workflow_id":           rule.WorkflowID.String(),
		"actor_permission_used": string(permUsed),
	}
	if len(changedKeys) > 0 {
		meta["changed_keys"] = changedKeys
	}
	_ = e.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actorOrAdmin(actorID),
		Action:        action,
		Resource:      "policy_rule:" + rule.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: correlationID,
		Metadata:      meta,
	})
}

// auditPolicyDeniedOutOfTeamScope is the team-scope security signal.
// Per §6 lock: NO policy_rule_id field — the actor failed coverage
// BEFORE the rule was loaded, and including the id would defeat the
// gate-order enumeration-leak protection (mirrors EPIC Q's
// binding.denied_out_of_scope + EPIC R's project variant).
//
// Action name is `policy.denied_out_of_scope` per §4 C2 normalization
// — same action both URL families emit; the `scope` metadata key
// distinguishes them.
func (e *PolicyEngine) auditPolicyDeniedOutOfTeamScope(
	ctx context.Context,
	actorID string,
	teamID uuid.UUID,
	correlationID uuid.UUID,
) {
	if e.audit == nil {
		return
	}
	_ = e.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actorOrAdmin(actorID),
		Action:        "policy.denied_out_of_scope",
		Resource:      "team:" + teamID.String(),
		Status:        storage.AuditStatusFailure,
		CorrelationID: correlationID,
		Metadata: map[string]any{
			"attempted_team_id":          teamID.String(),
			"actor_permission_attempted": string(auth.PermPolicyAuthor),
			"scope":                      "team",
		},
	})
}

// auditPolicyDeniedWorkflowNotAuthorableForTeam mirrors the project
// variant but carries attempted_team_id. The attempted_workflow_id
// IS included — actor picked it from the dropdown they were just
// shown, so logging it isn't a leak.
func (e *PolicyEngine) auditPolicyDeniedWorkflowNotAuthorableForTeam(
	ctx context.Context,
	actorID string,
	teamID uuid.UUID,
	workflowID uuid.UUID,
	correlationID uuid.UUID,
) {
	if e.audit == nil {
		return
	}
	_ = e.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actorOrAdmin(actorID),
		Action:        "policy.denied_workflow_not_authorable",
		Resource:      "workflow:" + workflowID.String(),
		Status:        storage.AuditStatusFailure,
		CorrelationID: correlationID,
		Metadata: map[string]any{
			"attempted_workflow_id":      workflowID.String(),
			"attempted_team_id":          teamID.String(),
			"actor_permission_attempted": string(auth.PermPolicyAuthor),
			"scope":                      "team",
		},
	})
}
