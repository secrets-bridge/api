// Selector operation dimension (api#141) tests.
//
// Coverage:
//   - Operation enum membership predicate (IsPolicySelectorOperation)
//   - PolicySelectorOperations() returns a defensive copy
//   - ValidateOperationSelector across all invalid shapes
//     (unknown, empty string, non-string, missing = wildcard)
//   - Scope.asMap() emits "operation" only when non-empty
//   - Resolver behavior: a rule pinning selector.operation matches ONLY
//     when the scope carries the same operation; a rule without
//     operation is a wildcard. This is the load-bearing guard against
//     the "rule silently never matches because a call site forgot to
//     stamp operation" failure mode.

package services

import (
	"testing"
)

func TestIsPolicySelectorOperation(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"read", true},
		{"patch", true},
		{"reveal", true},
		{"cross_team", false}, // §6 D6 — routing flavor, NOT an operation
		{"discover", false},   // a job_type, not a user-request operation
		{"READ", false},       // case-sensitive
		{"", false},
		{"read ", false}, // whitespace not stripped
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := IsPolicySelectorOperation(c.in); got != c.want {
				t.Errorf("IsPolicySelectorOperation(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestPolicySelectorOperations_DefensiveCopy(t *testing.T) {
	a := PolicySelectorOperations()
	if len(a) != 3 {
		t.Fatalf("expected 3 operations, got %d (%v)", len(a), a)
	}
	b := PolicySelectorOperations()
	if &a[0] == &b[0] {
		t.Fatalf("PolicySelectorOperations returned aliased slices; expected defensive copy")
	}
	a[0] = "MUTATED"
	c := PolicySelectorOperations()
	if c[0] == "MUTATED" {
		t.Fatalf("mutation of caller copy leaked into canonical source")
	}
}

func TestValidateOperationSelector(t *testing.T) {
	cases := []struct {
		name     string
		selector map[string]any
		wantNil  bool
	}{
		{"absent_is_wildcard", map[string]any{"environment_kind": "non_prod"}, true},
		{"valid_read", map[string]any{"operation": "read"}, true},
		{"valid_patch", map[string]any{"operation": "patch"}, true},
		{"valid_reveal", map[string]any{"operation": "reveal"}, true},
		{"unknown_rejected", map[string]any{"operation": "delete"}, false},
		{"cross_team_rejected", map[string]any{"operation": "cross_team"}, false},
		{"empty_string_rejected", map[string]any{"operation": ""}, false},
		{"number_rejected", map[string]any{"operation": 7}, false},
		{"bool_rejected", map[string]any{"operation": true}, false},
		{"map_rejected", map[string]any{"operation": map[string]any{"x": "read"}}, false},
		{"case_mismatch_rejected", map[string]any{"operation": "Read"}, false},
		{"whitespace_padding_rejected", map[string]any{"operation": " read"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := ValidateOperationSelector(c.selector)
			if c.wantNil && d != nil {
				t.Errorf("expected nil, got reason=%q", d.Reason)
			}
			if !c.wantNil {
				if d == nil {
					t.Errorf("expected rejection, got nil")
					return
				}
				if d.Reason != PolicyScopeTooBroadOperationInvalid {
					t.Errorf("reason=%q want %q", d.Reason, PolicyScopeTooBroadOperationInvalid)
				}
			}
		})
	}
}

func TestScope_asMap_OperationEmission(t *testing.T) {
	// Non-empty → emitted.
	m := Scope{Operation: "read"}.asMap()
	if m["operation"] != "read" {
		t.Errorf("asMap[operation] = %v, want read", m["operation"])
	}
	// Empty → omitted (wildcard semantics; the key must be absent so a
	// rule pinning operation simply doesn't match rather than matching
	// against "").
	empty := Scope{}.asMap()
	if _, present := empty["operation"]; present {
		t.Errorf("empty Operation should omit the key; got %v", empty["operation"])
	}
}

// TestSelectorMatches_Operation_Resolver pins the resolver behavior that
// makes the operation dimension work — and guards the failure mode the
// EPIC flagged (a rule pinning operation never matches if the scope
// doesn't carry it). selectorMatches is the unexported resolver core.
func TestSelectorMatches_Operation_Resolver(t *testing.T) {
	cases := []struct {
		name     string
		selector map[string]any
		scope    map[string]any
		want     bool
	}{
		{
			name:     "exact_match_read",
			selector: map[string]any{"operation": "read"},
			scope:    map[string]any{"operation": "read"},
			want:     true,
		},
		{
			name:     "mismatch_read_vs_patch",
			selector: map[string]any{"operation": "read"},
			scope:    map[string]any{"operation": "patch"},
			want:     false,
		},
		{
			name:     "absent_from_selector_is_wildcard",
			selector: map[string]any{"environment_kind": "non_prod"},
			scope:    map[string]any{"operation": "reveal", "environment_kind": "non_prod"},
			want:     true,
		},
		{
			name:     "empty_selector_matches_any_operation",
			selector: map[string]any{},
			scope:    map[string]any{"operation": "patch"},
			want:     true,
		},
		{
			// The load-bearing failure mode: a rule pins operation but
			// the scope DOESN'T carry it (a call site forgot to stamp).
			// selectorMatches must return false — the rule does NOT
			// silently match.
			name:     "selector_pins_operation_but_scope_omits_does_not_match",
			selector: map[string]any{"operation": "read"},
			scope:    map[string]any{"environment_kind": "non_prod"},
			want:     false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := selectorMatches(c.selector, c.scope)
			if got != c.want {
				t.Errorf("selectorMatches(%v, %v) = %v, want %v", c.selector, c.scope, got, c.want)
			}
		})
	}
}

// TestScope_CallSiteOperations documents + pins the operation each of
// the five Resolve call sites stamps (D3–D5). The call-site literals
// are inline in requests.go / requests_cross_team.go /
// reveal_sessions.go and compile-checked; this test asserts the enum
// constants those sites reference resolve to the expected wire values,
// so a rename of a constant can't silently change a call site's
// classification.
func TestScope_CallSiteOperations(t *testing.T) {
	if PolicySelectorOperationPatch != "patch" {
		t.Errorf("Submit + cross-team provision must stamp patch; constant = %q", PolicySelectorOperationPatch)
	}
	if PolicySelectorOperationRead != "read" {
		t.Errorf("SubmitRead must stamp read; constant = %q", PolicySelectorOperationRead)
	}
	if PolicySelectorOperationReveal != "reveal" {
		t.Errorf("SubmitDirectReveal + reveal-session TTL must stamp reveal; constant = %q", PolicySelectorOperationReveal)
	}
}
