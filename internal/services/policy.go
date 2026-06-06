// Package services — policy.go: workflow selection.
//
// PolicyEngine answers: "given the scope of a new secret-update
// request, which WorkflowDefinition governs its approval?"
//
// Resolution algorithm:
//
//  1. Walk policy_rules in priority DESC, created_at ASC order
//     (the repository's ListEnabledOrderedByPriority returns them
//     pre-sorted, so the engine just iterates).
//  2. For each rule, check whether the rule's selector is a SUBSET of
//     the request's scope — every key the rule specifies must match
//     the same key in the scope. Keys the rule omits are wildcards.
//  3. The first rule that fully matches is the winner.
//  4. If no rule matches OR no rules exist, fall back to the workflow
//     with is_default=true. The system seed migration ensures one
//     exists at install time; if an admin deletes it, the engine
//     returns ErrNoDefaultWorkflow and the API surface returns 500
//     loudly so the operator notices.
//
// Hot-path note: today this re-queries the DB on every Resolve call.
// PolicyEngine is designed to be wrappable by an in-memory cache
// later (Step 11 worker territory) when load demands it. The
// repository's resolution index makes the query a single seek.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Scope describes the request that needs a workflow. Fields are
// nullable so the engine can match against partial information.
type Scope struct {
	ProjectID   string
	Environment string
	// EnvironmentKind is the hard safety boundary classification of the
	// environment row (`non_prod` | `prod`). When set to `prod`, the
	// engine refuses to honour `direct_reveal_allowed=true` on the
	// matched rule regardless of policy or permission and emits a
	// `policy.invariant.violated` audit event. Empty means caller did
	// not look up the environment (back-compat) — invariant cannot fire.
	EnvironmentKind storage.EnvironmentKind
	ProviderType    string // "vault" | "aws-sm" | ...
	SecretRefPrefix string
	// Extras carries any additional dimensions the operator might add
	// to a selector. Today only the four fixed dimensions above are
	// used; Extras is reserved.
	Extras map[string]any
}

// PolicyDecision is the full result of PolicyEngine.Resolve.
//
// Slice L2 introduces this shape — previously Resolve returned the
// workflow and the matched rule directly. The decision struct carries
// the access-control fields the rule contributes (DirectReveal /
// RequiresMFA / RevealTTL) AFTER the engine has applied its
// invariants (most importantly: zero direct-reveal when the scope's
// environment.kind is prod).
//
// Workflow is always non-nil on a non-error return (either from the
// matched rule's pointed-at workflow, or from the system default).
// MatchedRule is nil only when the engine fell back to the default
// workflow because no rule matched.
type PolicyDecision struct {
	Workflow            *storage.WorkflowDefinition
	MatchedRule         *storage.PolicyRule
	DirectRevealAllowed bool
	RequiresMFA         bool
	RevealTTLSeconds    int
	// InvariantViolated is set to true when the engine zeroed
	// DirectRevealAllowed because the scope's environment kind was
	// `prod`. The audit event has already been emitted; this flag
	// is here for callers that want to surface a hint to the operator
	// in a response body (without leaking which rule was matched).
	InvariantViolated bool
}

// ErrNoDefaultWorkflow signals a misconfigured deployment — no policy
// matched and the operator has removed the system default. The API
// surface should return a loud 500 so the misconfig gets noticed.
var ErrNoDefaultWorkflow = errors.New("services: no policy matched and no default workflow exists")

// PolicyEngine resolves Scope → PolicyDecision and (EPIC R) hosts the
// scoped policy authoring service.
type PolicyEngine struct {
	policies  storage.PolicyRepository
	workflows storage.WorkflowRepository
	// audit is optional; when nil the engine still applies the PROD
	// invariant but skips the audit emit. Production wiring always
	// supplies audit; tests that don't care can pass nil.
	audit storage.AuditEventRepository

	// EPIC R (api#108) — populated by WithAuthorScope + WithEnvironments
	// so CreateForScopedAuthor / UpdateForScopedAuthor /
	// DeleteForScopedAuthor can compute project coverage + validate
	// selector.environment_id against the project + non-prod constraint.
	authorResolver  auth.Resolver
	authorTeamScope auth.TeamScopeResolver
	environments    storage.EnvironmentRepository
}

// NewPolicyEngine binds an engine to its repositories. audit may be
// nil in tests; production code should supply one so the
// `policy.invariant.violated` event lands when the PROD invariant
// fires.
func NewPolicyEngine(p storage.PolicyRepository, w storage.WorkflowRepository, audit storage.AuditEventRepository) *PolicyEngine {
	return &PolicyEngine{policies: p, workflows: w, audit: audit}
}

// Resolve finds the policy decision governing scope. Returns
// ErrNoDefaultWorkflow only when both the policy walk AND the default
// fallback fail.
//
// PROD invariant: if the matched rule has DirectRevealAllowed=true
// AND scope.EnvironmentKind == EnvironmentKindProd, the engine
// zeroes the flag in the returned decision and emits a
// `policy.invariant.violated` audit event. The matched rule itself
// is unchanged on disk; the violation surfaces as the discrepancy
// between rule.DirectRevealAllowed and decision.DirectRevealAllowed.
func (e *PolicyEngine) Resolve(ctx context.Context, scope Scope) (*PolicyDecision, error) {
	// EPIC R applicability filter — pass scope.ProjectID through to the
	// repository so scoped rules from project A NEVER reach a request
	// against project B. When scope.ProjectID is empty / unparseable,
	// projectUUID stays uuid.Nil and the repo returns platform-owned
	// rules only (per §2 correction 1).
	var projectUUID uuid.UUID
	if scope.ProjectID != "" {
		if parsed, err := uuid.Parse(scope.ProjectID); err == nil {
			projectUUID = parsed
		}
	}
	rules, err := e.policies.ListEnabledOrderedByPriority(ctx, projectUUID)
	if err != nil {
		return nil, fmt.Errorf("services: load policies: %w", err)
	}

	scopeMap := scope.asMap()
	for _, rule := range rules {
		if selectorMatches(rule.Selector, scopeMap) {
			w, err := e.workflows.Get(ctx, rule.WorkflowID)
			if err != nil {
				return nil, fmt.Errorf("services: load workflow %s: %w", rule.WorkflowID, err)
			}
			if !w.Enabled {
				// Operator disabled the workflow but left the policy
				// pointing at it — treat as no match and continue.
				continue
			}
			return e.buildDecision(ctx, w, rule, scope), nil
		}
	}

	// No rule matched. Fall back to the default workflow.
	w, err := e.workflows.GetDefault(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNoDefaultWorkflow
		}
		return nil, fmt.Errorf("services: load default workflow: %w", err)
	}
	if !w.Enabled {
		return nil, ErrNoDefaultWorkflow
	}
	return e.buildDecision(ctx, w, nil, scope), nil
}

// buildDecision applies the engine-level invariants to a (workflow,
// rule) pair and returns the final PolicyDecision. When the matched
// rule wants direct reveal AND the scope is PROD, this is where the
// flag gets zeroed and the audit row gets written.
func (e *PolicyEngine) buildDecision(ctx context.Context, w *storage.WorkflowDefinition, rule *storage.PolicyRule, scope Scope) *PolicyDecision {
	dec := &PolicyDecision{Workflow: w, MatchedRule: rule}
	if rule == nil {
		// Default workflow fallback: no access fields contributed by a
		// rule; treat as strict (request + MFA-fresh) and let the route
		// layer's own defaults take over.
		return dec
	}

	dec.DirectRevealAllowed = rule.DirectRevealAllowed
	dec.RequiresMFA = rule.RequiresMFA
	dec.RevealTTLSeconds = rule.RevealTTLSeconds

	// PROD invariant: direct reveal is impossible by construction.
	// Even if the operator misconfigured the rule, the engine refuses
	// to expose direct-reveal capability on a prod-classified env.
	if dec.DirectRevealAllowed && scope.EnvironmentKind == storage.EnvironmentKindProd {
		dec.DirectRevealAllowed = false
		dec.InvariantViolated = true
		e.emitInvariantViolation(ctx, rule, scope)
	}

	return dec
}

// emitInvariantViolation writes a single `policy.invariant.violated`
// audit row. Best-effort — audit emit failure must not propagate to
// the caller. The metadata carries enough for an operator to find the
// misconfigured rule without leaking it to the user response.
func (e *PolicyEngine) emitInvariantViolation(ctx context.Context, rule *storage.PolicyRule, scope Scope) {
	if e.audit == nil {
		return
	}
	_ = e.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "system:policy-engine",
		Action:   "policy.invariant.violated",
		Resource: "policy_rule:" + rule.ID.String(),
		Metadata: map[string]any{
			"reason":           "direct_reveal_on_prod_env_zeroed",
			"rule_id":          rule.ID.String(),
			"workflow_id":      rule.WorkflowID.String(),
			"environment_name": scope.Environment,
			"environment_kind": string(scope.EnvironmentKind),
			"project_id":       scope.ProjectID,
		},
	})
}

// asMap normalises a Scope into a map shape the selector matcher can
// compare against. Empty fields are excluded so a rule that says
// `environment=prod` correctly fails to match a scope without an
// environment set (rather than treating empty as a wildcard).
func (s Scope) asMap() map[string]any {
	out := make(map[string]any, 6+len(s.Extras))
	for k, v := range s.Extras {
		out[k] = v
	}
	if s.ProjectID != "" {
		out["project_id"] = s.ProjectID
	}
	if s.Environment != "" {
		out["environment"] = s.Environment
	}
	if s.EnvironmentKind != "" {
		out["environment_kind"] = string(s.EnvironmentKind)
	}
	if s.ProviderType != "" {
		out["provider_type"] = s.ProviderType
	}
	if s.SecretRefPrefix != "" {
		out["secret_ref_prefix"] = s.SecretRefPrefix
	}
	return out
}

// selectorMatches returns true iff every key the selector specifies is
// present in scope with the same value. Keys absent from the selector
// are wildcards.
//
// Special case: when the selector key is "secret_ref_prefix", the
// scope's "secret_ref_prefix" value (the full ref) must START with the
// selector's value — that's what makes "myapp/" match
// "myapp/db-password".
func selectorMatches(selector, scope map[string]any) bool {
	for key, want := range selector {
		got, ok := scope[key]
		if !ok {
			return false
		}
		if key == "secret_ref_prefix" {
			wantStr, _ := want.(string)
			gotStr, _ := got.(string)
			if wantStr == "" || gotStr == "" {
				return false
			}
			if !startsWith(gotStr, wantStr) {
				return false
			}
			continue
		}
		// Default: exact equality after JSON-trip-style normalisation.
		// Numbers from JSON come back as float64; strings stay strings;
		// bools stay bools. The selector values come from the DB JSONB
		// column so they follow the same convention.
		if !equalAny(want, got) {
			return false
		}
	}
	return true
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func equalAny(a, b any) bool {
	// Fast path: identical concrete types.
	if a == b {
		return true
	}
	// Strings cover almost all cases for policy selectors today.
	aStr, aOK := a.(string)
	bStr, bOK := b.(string)
	if aOK && bOK {
		return aStr == bStr
	}
	return false
}
