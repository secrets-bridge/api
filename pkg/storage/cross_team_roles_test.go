package storage_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Slice N2 — verify the 0029_cross_team_roles seed migration lands
// two is_system=true roles carrying exactly the expected permission
// strings.
//
// The drift test in `internal/auth/permissions_test.go` already
// catches "this migration uses permission X but the Catalog doesn't
// know about it." This test catches the inverse: "the migration
// SHIPS the seed rows we promised" — protecting against an accidental
// migration revert / squash that drops the seeds.

func TestSeedRoles_ValueProviderExists(t *testing.T) {
	pool := freshDB(t)
	role := loadSystemRoleByName(t, pool, "value_provider")
	if role == nil {
		t.Fatal("seed role 'value_provider' missing after migration")
	}
	if !role.IsSystem {
		t.Errorf("value_provider must be is_system=true; got %v", role.IsSystem)
	}
	perms := decodeRolePermissions(t, role.Permissions)
	if len(perms) != 1 || perms[0] != "secret.value.provide" {
		t.Errorf("value_provider permissions = %v want [secret.value.provide]", perms)
	}
}

func TestSeedRoles_SecurityApproverExists(t *testing.T) {
	pool := freshDB(t)
	role := loadSystemRoleByName(t, pool, "security_approver")
	if role == nil {
		t.Fatal("seed role 'security_approver' missing after migration")
	}
	if !role.IsSystem {
		t.Errorf("security_approver must be is_system=true; got %v", role.IsSystem)
	}
	perms := decodeRolePermissions(t, role.Permissions)
	if len(perms) != 1 || perms[0] != "secret.security.approve" {
		t.Errorf("security_approver permissions = %v want [secret.security.approve]", perms)
	}
	// Strict separation: must NOT auto-carry the regular approve perm.
	for _, p := range perms {
		if p == "secret.approve" {
			t.Error("security_approver MUST NOT carry secret.approve — strict separation by design")
		}
	}
}

// TestSeedRoles_NotAddedToExistingSystemRoles verifies the new
// permissions are NOT auto-grafted onto admin / approver / developer.
// Operators must explicitly assign per least-privilege.
func TestSeedRoles_NotAddedToExistingSystemRoles(t *testing.T) {
	pool := freshDB(t)
	for _, name := range []string{"admin", "approver", "developer"} {
		role := loadSystemRoleByName(t, pool, name)
		if role == nil {
			t.Errorf("expected seed role %q to exist", name)
			continue
		}
		perms := decodeRolePermissions(t, role.Permissions)
		for _, p := range perms {
			if p == "secret.value.provide" {
				t.Errorf("seed role %q must NOT carry secret.value.provide; operators explicitly assign", name)
			}
			if p == "secret.security.approve" {
				t.Errorf("seed role %q must NOT carry secret.security.approve; operators explicitly assign", name)
			}
		}
	}
}

// --- helpers ---------------------------------------------------------

type seedRoleRow struct {
	Name        string
	Description string
	Permissions []byte
	IsSystem    bool
}

func loadSystemRoleByName(t *testing.T, pool *storage.Pool, name string) *seedRoleRow {
	t.Helper()
	const q = `
		SELECT name, COALESCE(description, ''), permissions, is_system
		FROM roles
		WHERE name = $1`
	var r seedRoleRow
	err := pool.QueryRow(context.Background(), q, name).Scan(
		&r.Name, &r.Description, &r.Permissions, &r.IsSystem,
	)
	if err != nil {
		return nil
	}
	return &r
}

func decodeRolePermissions(t *testing.T, raw []byte) []string {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode role permissions: %v (raw=%q)", err, raw)
	}
	return out
}
