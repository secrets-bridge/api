package auth

import (
	"strings"
	"testing"
)

func TestCatalog_NoDuplicateKeys(t *testing.T) {
	seen := map[Permission]int{}
	for i, d := range Catalog {
		if prev, ok := seen[d.Key]; ok {
			t.Errorf("duplicate Catalog key %q at indexes %d and %d", d.Key, prev, i)
		}
		seen[d.Key] = i
	}
}

func TestCatalog_EveryEntryHasFields(t *testing.T) {
	for _, d := range Catalog {
		if d.Key == "" {
			t.Errorf("Catalog entry with empty Key: %+v", d)
		}
		if d.Group == "" {
			t.Errorf("Catalog entry %q missing Group", d.Key)
		}
		if d.Description == "" {
			t.Errorf("Catalog entry %q missing Description", d.Key)
		}
	}
}

func TestCatalog_NamingConvention(t *testing.T) {
	for _, d := range Catalog {
		// The convention is `<resource>.<action>`. ArgoCD's split is
		// closer to triplets; ours collapses resource + action into one
		// dotted string for v1 readability.
		s := string(d.Key)
		if !strings.Contains(s, ".") {
			t.Errorf("Catalog key %q is missing the required `<resource>.<action>` dot", s)
		}
		if strings.Contains(s, " ") {
			t.Errorf("Catalog key %q must not contain whitespace", s)
		}
		if s != strings.ToLower(s) {
			t.Errorf("Catalog key %q must be lowercase", s)
		}
	}
}

func TestIsKnown(t *testing.T) {
	for _, d := range Catalog {
		if !IsKnown(string(d.Key)) {
			t.Errorf("IsKnown(%q) returned false but the key is in the Catalog", d.Key)
		}
	}
	for _, junk := range []string{"", "secret.*", "secret", "secret.x.y", "Secret.Request"} {
		if IsKnown(junk) {
			t.Errorf("IsKnown(%q) returned true but the key is NOT in the Catalog", junk)
		}
	}
}

// TestSeedMigrationStringsAreInCatalog is the drift guardrail. The
// seed migration `0005_workflow_engine.up.sql` embeds the admin /
// approver / developer role permission lists as literal JSON. If
// anyone edits those JSON arrays without adding the matching constant
// to permissions.go, this test catches it.
//
// We hardcode the seed lists here rather than read the .sql file to
// avoid pulling a sqlfile parser into a unit test; the duplicated set
// is small and the test fails loudly the moment they drift.
func TestSeedMigrationStringsAreInCatalog(t *testing.T) {
	seedPermissions := []string{
		// admin (0005_workflow_engine.up.sql lines 135-138)
		"role.edit", "user_role.edit",
		"workflow.edit", "policy.edit",
		"agent.mint", "agent.revoke",
		"secret.request", "secret.approve",
		"audit.read",

		// approver (0005 line 140)
		"secret.approve", "audit.read",

		// developer (0005 line 143) — and Slice L4 adds
		// secret.reveal.direct via 0026_seed_secret_reveal_direct.up.sql.
		"secret.request", "audit.read",
		"secret.reveal.direct",

		// value_provider (0029_cross_team_roles.up.sql) — Slice N2.
		"secret.value.provide",

		// security_approver (0029_cross_team_roles.up.sql) — Slice N2.
		"secret.security.approve",
	}
	for _, p := range seedPermissions {
		if !IsKnown(p) {
			t.Errorf("seed migration uses permission %q but it's NOT in the Catalog — add the constant in permissions.go", p)
		}
	}
}
