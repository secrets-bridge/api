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

	"github.com/secrets-bridge/api/pkg/storage"
)

// Scope describes the request that needs a workflow. Fields are
// nullable so the engine can match against partial information.
type Scope struct {
	ProjectID       string
	Environment     string
	ProviderType    string // "vault" | "aws-sm" | ...
	SecretRefPrefix string
	// Extras carries any additional dimensions the operator might add
	// to a selector. Today only the four fixed dimensions above are
	// used; Extras is reserved.
	Extras map[string]any
}

// ErrNoDefaultWorkflow signals a misconfigured deployment — no policy
// matched and the operator has removed the system default. The API
// surface should return a loud 500 so the misconfig gets noticed.
var ErrNoDefaultWorkflow = errors.New("services: no policy matched and no default workflow exists")

// PolicyEngine resolves Scope → WorkflowDefinition.
type PolicyEngine struct {
	policies  storage.PolicyRepository
	workflows storage.WorkflowRepository
}

// NewPolicyEngine binds an engine to its repositories.
func NewPolicyEngine(p storage.PolicyRepository, w storage.WorkflowRepository) *PolicyEngine {
	return &PolicyEngine{policies: p, workflows: w}
}

// Resolve finds the workflow governing scope. Returns
// ErrNoDefaultWorkflow only when both the policy walk AND the default
// fallback fail.
func (e *PolicyEngine) Resolve(ctx context.Context, scope Scope) (*storage.WorkflowDefinition, *storage.PolicyRule, error) {
	rules, err := e.policies.ListEnabledOrderedByPriority(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("services: load policies: %w", err)
	}

	scopeMap := scope.asMap()
	for _, rule := range rules {
		if selectorMatches(rule.Selector, scopeMap) {
			w, err := e.workflows.Get(ctx, rule.WorkflowID)
			if err != nil {
				return nil, nil, fmt.Errorf("services: load workflow %s: %w", rule.WorkflowID, err)
			}
			if !w.Enabled {
				// Operator disabled the workflow but left the policy
				// pointing at it — treat as no match and continue.
				continue
			}
			return w, rule, nil
		}
	}

	// No rule matched. Fall back to the default workflow.
	w, err := e.workflows.GetDefault(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil, ErrNoDefaultWorkflow
		}
		return nil, nil, fmt.Errorf("services: load default workflow: %w", err)
	}
	if !w.Enabled {
		return nil, nil, ErrNoDefaultWorkflow
	}
	return w, nil, nil
}

// asMap normalises a Scope into a map shape the selector matcher can
// compare against. Empty fields are excluded so a rule that says
// `environment=prod` correctly fails to match a scope without an
// environment set (rather than treating empty as a wildcard).
func (s Scope) asMap() map[string]any {
	out := make(map[string]any, 5+len(s.Extras))
	for k, v := range s.Extras {
		out[k] = v
	}
	if s.ProjectID != "" {
		out["project_id"] = s.ProjectID
	}
	if s.Environment != "" {
		out["environment"] = s.Environment
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
