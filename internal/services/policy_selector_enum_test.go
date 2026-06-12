// Selector enum v1 lock (api#139) tests.
//
// Coverage:
//   - Storage-layer membership predicate (IsPolicySelectorProviderType)
//   - Service-layer ValidateProviderTypeSelector across all 4 invalid
//     shapes (unknown, empty string, non-string, missing entirely)
//   - Resolver behavior (selectorMatches): selector enum is exact match;
//     wildcard when absent; backend rejection happens before storage so
//     the resolver never sees invalid values

package services

import (
	"testing"

	"github.com/secrets-bridge/api/pkg/storage"
)

func TestStorage_IsPolicySelectorProviderType(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"aws-sm", true},
		{"vault", true},
		{"gcp-sm", true},
		{"azure-kv", true},
		{"kubernetes", true},
		{"hashicorp-boundary", false}, // not yet enumerated
		{"AWS-SM", false},             // case-sensitive
		{"", false},
		{"aws-sm ", false}, // whitespace not stripped
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := storage.IsPolicySelectorProviderType(c.in); got != c.want {
				t.Errorf("IsPolicySelectorProviderType(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestStorage_PolicySelectorProviderTypes_DefensiveCopy(t *testing.T) {
	a := storage.PolicySelectorProviderTypes()
	b := storage.PolicySelectorProviderTypes()
	if &a[0] == &b[0] {
		t.Fatalf("PolicySelectorProviderTypes returned aliased slices; expected defensive copy")
	}
	// Caller mutation must not leak into the canonical source.
	a[0] = "MUTATED"
	c := storage.PolicySelectorProviderTypes()
	if c[0] == "MUTATED" {
		t.Fatalf("mutation of caller copy leaked into canonical source")
	}
}

func TestValidateProviderTypeSelector(t *testing.T) {
	cases := []struct {
		name     string
		selector map[string]any
		wantNil  bool
	}{
		{
			name:     "absent_is_wildcard",
			selector: map[string]any{"environment_kind": "non_prod"},
			wantNil:  true,
		},
		{
			name:     "valid_aws_sm",
			selector: map[string]any{"provider_type": "aws-sm"},
			wantNil:  true,
		},
		{
			name:     "valid_vault",
			selector: map[string]any{"provider_type": "vault"},
			wantNil:  true,
		},
		{
			name:     "valid_gcp_sm",
			selector: map[string]any{"provider_type": "gcp-sm"},
			wantNil:  true,
		},
		{
			name:     "valid_azure_kv",
			selector: map[string]any{"provider_type": "azure-kv"},
			wantNil:  true,
		},
		{
			name:     "valid_kubernetes",
			selector: map[string]any{"provider_type": "kubernetes"},
			wantNil:  true,
		},
		{
			name:     "unknown_provider_rejected",
			selector: map[string]any{"provider_type": "hashicorp-boundary"},
			wantNil:  false,
		},
		{
			name:     "empty_string_rejected",
			selector: map[string]any{"provider_type": ""},
			wantNil:  false,
		},
		{
			name:     "number_rejected",
			selector: map[string]any{"provider_type": 42},
			wantNil:  false,
		},
		{
			name:     "bool_rejected",
			selector: map[string]any{"provider_type": true},
			wantNil:  false,
		},
		{
			name:     "map_rejected",
			selector: map[string]any{"provider_type": map[string]any{"nested": "vault"}},
			wantNil:  false,
		},
		{
			name:     "case_mismatch_rejected",
			selector: map[string]any{"provider_type": "Vault"},
			wantNil:  false,
		},
		{
			name:     "whitespace_padding_rejected",
			selector: map[string]any{"provider_type": " vault"},
			wantNil:  false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := ValidateProviderTypeSelector(c.selector)
			if c.wantNil && d != nil {
				t.Errorf("expected nil, got reason=%q", d.Reason)
			}
			if !c.wantNil {
				if d == nil {
					t.Errorf("expected rejection, got nil")
					return
				}
				if d.Reason != PolicyScopeTooBroadProviderTypeInvalid {
					t.Errorf("reason=%q want %q", d.Reason, PolicyScopeTooBroadProviderTypeInvalid)
				}
			}
		})
	}
}

// Resolver behavior — proves the existing selectorMatches honors the
// provider_type field correctly. These tests pin the assumption from
// the design pass: "exact-match still works because the wire value
// matches the storage constant." They guard against a future
// refactor that accidentally inserts provider_type into the
// secret_ref_prefix special-case branch.
func TestSelectorMatches_ProviderType_Resolver(t *testing.T) {
	cases := []struct {
		name     string
		selector map[string]any
		scope    map[string]any
		want     bool
	}{
		{
			name:     "exact_match_vault",
			selector: map[string]any{"provider_type": "vault"},
			scope:    map[string]any{"provider_type": "vault"},
			want:     true,
		},
		{
			name:     "mismatch_vault_vs_aws_sm",
			selector: map[string]any{"provider_type": "vault"},
			scope:    map[string]any{"provider_type": "aws-sm"},
			want:     false,
		},
		{
			name:     "absent_from_selector_is_wildcard",
			selector: map[string]any{"environment_kind": "non_prod"},
			scope:    map[string]any{"provider_type": "vault", "environment_kind": "non_prod"},
			want:     true,
		},
		{
			name:     "absent_from_selector_matches_any_provider",
			selector: map[string]any{},
			scope:    map[string]any{"provider_type": "kubernetes"},
			want:     true,
		},
		{
			name:     "selector_specifies_provider_but_scope_omits_does_not_match",
			selector: map[string]any{"provider_type": "vault"},
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
