// EPIC R (api#108) Slice R1 — scoped policy authoring service.
//
// CreateForScopedAuthor + UpdateForScopedAuthor + DeleteForScopedAuthor
// are the policy.author surface. They run the LOCKED gate chains from
// the §3 sign-off:
//
//   Create (6 gates, §3-locked order):
//     1. actor covers in.ProjectID via EffectiveProjectAccess
//     2. in.Priority < PlatformReservedPriority
//     3. selector.project_id consistency (absent OR equals in.ProjectID)
//     4. validateScopedEnv (4 sub-checks — see below)
//     5. workflow exists
//     6. INSERT + emit policy.create
//
//   Update (8 gates):
//     1. actor covers in.ProjectID via EffectiveProjectAccess
//     2. rule exists (repo.Get)
//     3. rule.ProjectID == in.ProjectID  (mismatch → not_found, §4 lock)
//     4. rule.ProjectID IS NULL → platform_policy_not_editable
//     5. rule.IsSystem → ErrSystemRow
//     6. (if Priority being changed) *in.Priority < PlatformReservedPriority
//     7. (if Selector being changed) validateScopedEnv + project consistency
//     8. UPDATE + emit policy.update with changed_keys
//
//   Delete (5 gates):
//     1. actor covers in.ProjectID
//     2. rule exists
//     3. rule.ProjectID == in.ProjectID (mismatch → not_found)
//     4. rule.ProjectID IS NULL → platform_policy_not_editable
//     5. rule.IsSystem → ErrSystemRow
//     6. DELETE + emit policy.delete
//
// The ORDER is enumeration-leak-safe: a scoped probe of any rule id
// without coverage of the target project gets out_of_scope_policy at
// step 1 — rule state never leaks. The denied audit row omits
// policy_rule_id per §6 (same lesson EPIC Q's binding.denied_out_of_scope
// learned).

package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// PlatformReservedPriority is the floor of the priority range reserved
// for platform (policy.edit) rules. Scoped policy.author rules MUST
// have priority < PlatformReservedPriority so platform's policy always
// outranks scoped overrides for the same selector.
//
// Hardcoded for v1 per EPIC R §1 sign-off. R-follow-up #2 tracks
// making this admin-configurable when real demand surfaces.
const PlatformReservedPriority = 9000

// ---- sentinels mapped to stable HTTP codes in R2 -------------------

var (
	ErrOutOfScopePolicy             = errors.New("services: actor does not cover the target project for policy authoring")
	ErrPlatformPolicyNotEditable    = errors.New("services: platform global policy rules are administered via /admin/policies")
	ErrPolicySelectorMismatch       = errors.New("services: selector.project_id must equal the rule's project")
	ErrProdPolicyNotAllowedForScope = errors.New("services: scoped policy authors cannot create rules that match production environments")
	ErrPolicyScopeTooBroad          = errors.New("services: scoped policy rules must constrain to a non-prod environment")
	ErrPolicyPriorityReserved       = errors.New("services: priority is reserved for platform policy rules")
	ErrPolicyEnvironmentNotInProject = errors.New("services: the selector's environment does not belong to this project")
	ErrPolicyNotFound               = errors.New("services: policy rule not found")
)

// PolicyScopeTooBroadDetail wraps ErrPolicyScopeTooBroad with the
// variant kind. Handlers in R2 surface this via the {error_code:
// policy_scope_too_broad, reason: "..."} envelope.
type PolicyScopeTooBroadDetail struct {
	Reason string
}

func (d *PolicyScopeTooBroadDetail) Error() string { return ErrPolicyScopeTooBroad.Error() }
func (d *PolicyScopeTooBroadDetail) Unwrap() error { return ErrPolicyScopeTooBroad }

// Reason variants exposed to handlers + tests so they're literal in
// the codebase, not magic strings.
const (
	PolicyScopeTooBroadEnvConstraintMissing = "env_constraint_missing"
	PolicyScopeTooBroadEnvKindInvalid       = "env_kind_invalid"
	PolicyScopeTooBroadSelectorEmpty        = "selector_empty"
	PolicyScopeTooBroadEnvKindIdInconsistent = "env_kind_id_inconsistent"
)

// ---- scoped service wiring ----------------------------------------

// WithAuthorScope binds the resolver pair the EPIC R scoped path uses
// to compute project coverage for policy.author callers. Pass nil to
// disable the scoped path. main always wires both in production.
func (e *PolicyEngine) WithAuthorScope(r auth.Resolver, tr auth.TeamScopeResolver) *PolicyEngine {
	e.authorResolver = r
	e.authorTeamScope = tr
	return e
}

// WithEnvironments lets the scoped path validate selector.environment_id
// against the project + non-prod constraint without dragging the env
// repo into NewPolicyEngine.
func (e *PolicyEngine) WithEnvironments(r storage.EnvironmentRepository) *PolicyEngine {
	e.environments = r
	return e
}

// ---- input shapes --------------------------------------------------

// CreateScopedPolicyInput is the shape the R2 handler hands the
// service. ProjectID comes from the URL.
type CreateScopedPolicyInput struct {
	ProjectID     uuid.UUID
	Name          string
	Selector      map[string]any
	Priority      int
	WorkflowID    uuid.UUID
	Enabled       bool
	ActorID       string
	CorrelationID uuid.UUID
}

// UpdateScopedPolicyInput uses pointer fields so nil means
// "don't touch." Per §3 Q9: Selector nil = preserve; Selector pointing
// to an empty map = REJECT with ErrPolicyScopeTooBroad
// (PolicyScopeTooBroadSelectorEmpty).
type UpdateScopedPolicyInput struct {
	RuleID     uuid.UUID
	ProjectID  uuid.UUID
	Name       *string
	Selector   *map[string]any
	Priority   *int
	WorkflowID *uuid.UUID
	Enabled    *bool

	ActorID       string
	CorrelationID uuid.UUID
}

// DeleteScopedPolicyInput carries the URL projectID so the §4 mismatch
// protection runs (mismatch → ErrPolicyNotFound, never
// ErrOutOfScopePolicy).
type DeleteScopedPolicyInput struct {
	RuleID        uuid.UUID
	ProjectID     uuid.UUID
	ActorID       string
	CorrelationID uuid.UUID
}

// ---- gate chains ---------------------------------------------------

// CreateForScopedAuthor runs the 6-gate chain locked at §3.
func (e *PolicyEngine) CreateForScopedAuthor(ctx context.Context, in CreateScopedPolicyInput) (*storage.PolicyRule, error) {
	if e.authorResolver == nil || e.environments == nil {
		return nil, errors.New("services: scoped policy path requires WithAuthorScope + WithEnvironments wiring")
	}

	// Gate 1 — actor covers project.
	access, err := auth.EffectiveProjectAccess(ctx, in.ActorID, auth.PermPolicyAuthor, e.authorResolver, e.authorTeamScope)
	if err != nil {
		return nil, fmt.Errorf("services: resolve scoped author access: %w", err)
	}
	if !projectAccessCoversPolicy(access, in.ProjectID) {
		e.auditPolicyDeniedOutOfScope(ctx, in.ActorID, in.ProjectID, in.CorrelationID)
		return nil, ErrOutOfScopePolicy
	}

	// Gate 2 — priority < 9000.
	if in.Priority >= PlatformReservedPriority {
		return nil, ErrPolicyPriorityReserved
	}

	// Gate 3 — selector project_id consistency.
	if err := validateSelectorProjectMatches(in.Selector, in.ProjectID); err != nil {
		return nil, err
	}

	// Gate 4 — env constraint.
	if err := e.validateScopedEnv(ctx, in.Selector, in.ProjectID); err != nil {
		return nil, err
	}

	// Gate 5 — workflow exists.
	if _, err := e.workflows.Get(ctx, in.WorkflowID); err != nil {
		return nil, fmt.Errorf("services: workflow %s: %w", in.WorkflowID, err)
	}

	// Gate 6 — INSERT + audit.
	projectID := in.ProjectID
	rule := &storage.PolicyRule{
		Name:       in.Name,
		Selector:   in.Selector,
		WorkflowID: in.WorkflowID,
		Priority:   in.Priority,
		Enabled:    in.Enabled,
		ProjectID:  &projectID,
	}
	if err := e.policies.Create(ctx, rule); err != nil {
		return nil, fmt.Errorf("services: create scoped policy: %w", err)
	}
	e.auditPolicySuccess(ctx, "policy.create", rule, in.ActorID, in.CorrelationID,
		auth.PermPolicyAuthor, nil)
	return rule, nil
}

// UpdateForScopedAuthor runs the 8-gate chain.
func (e *PolicyEngine) UpdateForScopedAuthor(ctx context.Context, in UpdateScopedPolicyInput) (*storage.PolicyRule, error) {
	if e.authorResolver == nil || e.environments == nil {
		return nil, errors.New("services: scoped policy path requires WithAuthorScope + WithEnvironments wiring")
	}

	// Gate 1 — actor covers project.
	access, err := auth.EffectiveProjectAccess(ctx, in.ActorID, auth.PermPolicyAuthor, e.authorResolver, e.authorTeamScope)
	if err != nil {
		return nil, fmt.Errorf("services: resolve scoped author access: %w", err)
	}
	if !projectAccessCoversPolicy(access, in.ProjectID) {
		e.auditPolicyDeniedOutOfScope(ctx, in.ActorID, in.ProjectID, in.CorrelationID)
		return nil, ErrOutOfScopePolicy
	}

	// Gate 2 — rule exists.
	rule, err := e.policies.Get(ctx, in.RuleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrPolicyNotFound
		}
		return nil, fmt.Errorf("services: load policy: %w", err)
	}

	// Gate 3 — project_id matches URL. §4 lock: mismatch → not_found
	// (never out_of_scope, which would leak existence).
	if rule.ProjectID == nil || *rule.ProjectID != in.ProjectID {
		// If the rule's project_id doesn't match URL projectID (or the
		// rule is platform-owned), return not_found to the scoped
		// caller. If the row IS platform-owned (project_id IS NULL),
		// the caller is trying to edit a platform rule via the scoped
		// URL — distinguishable from a true mismatch only by inspecting
		// the row, so we surface platform_policy_not_editable to make
		// the message useful when the URL projectID happens to match
		// nothing. But to avoid leaking, prefer not_found on URL
		// mismatch and platform-not-editable only when ProjectID IS NULL.
		if rule.ProjectID == nil {
			return nil, ErrPlatformPolicyNotEditable
		}
		return nil, ErrPolicyNotFound
	}

	// Gate 4 — implicitly: rule.ProjectID is NOT NULL (we checked
	// above). The platform_policy_not_editable path was handled in
	// gate 3's NULL branch.

	// Gate 5 — is_system protection.
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
		// §3 Q9: explicit {} REJECTED for scoped authors (not preserved).
		// nil pointer = preserve (we don't enter this branch).
		patched.Selector = *in.Selector
		changedKeys = append(changedKeys, "selector")
	}

	// Gate 6 — priority < 9000.
	if patched.Priority >= PlatformReservedPriority {
		return nil, ErrPolicyPriorityReserved
	}

	// Gate 7 — selector consistency + env constraint.
	if err := validateSelectorProjectMatches(patched.Selector, in.ProjectID); err != nil {
		return nil, err
	}
	if err := e.validateScopedEnv(ctx, patched.Selector, in.ProjectID); err != nil {
		return nil, err
	}

	// Workflow exists (in case it changed).
	if _, err := e.workflows.Get(ctx, patched.WorkflowID); err != nil {
		return nil, fmt.Errorf("services: workflow %s: %w", patched.WorkflowID, err)
	}

	// Gate 8 — UPDATE + audit.
	if err := e.policies.Update(ctx, &patched); err != nil {
		return nil, fmt.Errorf("services: update scoped policy: %w", err)
	}
	e.auditPolicySuccess(ctx, "policy.update", &patched, in.ActorID, in.CorrelationID,
		auth.PermPolicyAuthor, changedKeys)
	return &patched, nil
}

// DeleteForScopedAuthor runs the 5-gate chain.
func (e *PolicyEngine) DeleteForScopedAuthor(ctx context.Context, in DeleteScopedPolicyInput) error {
	if e.authorResolver == nil || e.environments == nil {
		return errors.New("services: scoped policy path requires WithAuthorScope + WithEnvironments wiring")
	}

	// Gate 1 — actor covers project.
	access, err := auth.EffectiveProjectAccess(ctx, in.ActorID, auth.PermPolicyAuthor, e.authorResolver, e.authorTeamScope)
	if err != nil {
		return fmt.Errorf("services: resolve scoped author access: %w", err)
	}
	if !projectAccessCoversPolicy(access, in.ProjectID) {
		e.auditPolicyDeniedOutOfScope(ctx, in.ActorID, in.ProjectID, in.CorrelationID)
		return ErrOutOfScopePolicy
	}

	// Gate 2 — rule exists.
	rule, err := e.policies.Get(ctx, in.RuleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrPolicyNotFound
		}
		return fmt.Errorf("services: load policy: %w", err)
	}

	// Gate 3 — project_id matches URL.
	if rule.ProjectID == nil {
		return ErrPlatformPolicyNotEditable
	}
	if *rule.ProjectID != in.ProjectID {
		return ErrPolicyNotFound
	}

	// Gate 5 — is_system protection.
	if rule.IsSystem {
		return storage.ErrSystemRow
	}

	// Gate 6 — DELETE + audit.
	if err := e.policies.Delete(ctx, in.RuleID); err != nil {
		return fmt.Errorf("services: delete scoped policy: %w", err)
	}
	e.auditPolicySuccess(ctx, "policy.delete", rule, in.ActorID, in.CorrelationID,
		auth.PermPolicyAuthor, nil)
	return nil
}

// ---- helpers -------------------------------------------------------

// projectAccessCoversPolicy returns whether the resolved ProjectAccess
// covers the target projectID. Global access wins.
func projectAccessCoversPolicy(access auth.ProjectAccess, target uuid.UUID) bool {
	if access.IsGlobal {
		return true
	}
	for _, id := range access.ProjectIDs {
		if id == target {
			return true
		}
	}
	return false
}

// validateSelectorProjectMatches checks that if the selector includes
// a project_id key, it equals in.ProjectID. The DB enforces this too
// via the CHECK constraint, but service-layer catches it earlier with
// a typed sentinel for nicer error responses.
func validateSelectorProjectMatches(selector map[string]any, projectID uuid.UUID) error {
	if selector == nil {
		return nil
	}
	raw, ok := selector["project_id"]
	if !ok {
		return nil
	}
	if s, ok := raw.(string); ok && s == projectID.String() {
		return nil
	}
	return ErrPolicySelectorMismatch
}

// validateScopedEnv enforces "scoped rules non-prod-only by construction"
// per §3 sign-off. The 4 sub-checks:
//
//	1. selector neither has environment_kind NOR environment_id   → scope_too_broad / selector_empty
//	2. selector.environment_kind == "prod"                         → prod_policy_not_allowed_for_scope
//	3. selector.environment_kind not in {non_prod, prod}           → scope_too_broad / env_kind_invalid
//	4. selector.environment_id resolves to a non-prod env in this
//	   project AND agrees with selector.environment_kind (if both)
//
// The DB CHECK from migration 0033 catches (1) and (2) for the bare
// cases; service-layer catches every variant.
func (e *PolicyEngine) validateScopedEnv(ctx context.Context, selector map[string]any, projectID uuid.UUID) error {
	if len(selector) == 0 {
		return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadSelectorEmpty}
	}

	kindRaw, hasKind := selector["environment_kind"]
	envIDRaw, hasEnvID := selector["environment_id"]

	if !hasKind && !hasEnvID {
		return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadEnvConstraintMissing}
	}

	// environment_kind branch.
	var kindStr string
	if hasKind {
		s, ok := kindRaw.(string)
		if !ok {
			return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadEnvKindInvalid}
		}
		kindStr = s
		switch storage.EnvironmentKind(kindStr) {
		case storage.EnvironmentKindNonProd:
			// ok
		case storage.EnvironmentKindProd:
			return ErrProdPolicyNotAllowedForScope
		default:
			return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadEnvKindInvalid}
		}
	}

	// environment_id branch — JOIN to environments to enforce
	// project + non-prod + agreement with environment_kind.
	if hasEnvID {
		envIDStr, ok := envIDRaw.(string)
		if !ok {
			return ErrPolicyEnvironmentNotInProject
		}
		envID, err := uuid.Parse(envIDStr)
		if err != nil {
			return ErrPolicyEnvironmentNotInProject
		}
		env, err := e.environments.Get(ctx, envID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return ErrPolicyEnvironmentNotInProject
			}
			return fmt.Errorf("services: load env: %w", err)
		}
		if env.ProjectID != projectID {
			return ErrPolicyEnvironmentNotInProject
		}
		if env.Kind == storage.EnvironmentKindProd {
			return ErrProdPolicyNotAllowedForScope
		}
		// Agreement with environment_kind when both present.
		if hasKind && string(env.Kind) != kindStr {
			return &PolicyScopeTooBroadDetail{Reason: PolicyScopeTooBroadEnvKindIdInconsistent}
		}
	}

	return nil
}

// ---- audit emission ------------------------------------------------

func (e *PolicyEngine) auditPolicySuccess(
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
	projectIDMeta := ""
	if rule.ProjectID != nil {
		projectIDMeta = rule.ProjectID.String()
	}
	// §6 lock: selector KEYS only, NEVER values.
	keys := make([]string, 0, len(rule.Selector))
	for k := range rule.Selector {
		keys = append(keys, k)
	}
	meta := map[string]any{
		"policy_rule_id":        rule.ID.String(),
		"project_id":            projectIDMeta,
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

// auditPolicyDeniedOutOfScope is the security-signal event. Per §6:
// NO policy_rule_id field — the actor failed coverage BEFORE the rule
// was loaded, and including the id would defeat the gate-order
// enumeration-leak protection (mirrors EPIC Q's
// binding.denied_out_of_scope).
func (e *PolicyEngine) auditPolicyDeniedOutOfScope(
	ctx context.Context,
	actorID string,
	projectID uuid.UUID,
	correlationID uuid.UUID,
) {
	if e.audit == nil {
		return
	}
	_ = e.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actorOrAdmin(actorID),
		Action:        "policy.denied_out_of_scope",
		Resource:      "project:" + projectID.String(),
		Status:        storage.AuditStatusFailure,
		CorrelationID: correlationID,
		Metadata: map[string]any{
			"attempted_project_id":       projectID.String(),
			"actor_permission_attempted": string(auth.PermPolicyAuthor),
		},
	})
}
