package storage_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// A user_roles.scope that is not a JSON object (a hand-written jsonb
// null, an array, a scalar) is flagged ScopeMalformed instead of decoding
// to an empty, global-looking scope (null) or failing the whole listing
// (array). The RBAC resolver then ignores the grant (API-N-06).
func TestUserRoles_NonObjectScopeIsFlagged(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `DELETE FROM user_roles`); err != nil {
		t.Fatalf("wipe user_roles: %v", err)
	}
	var roleID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM roles WHERE name = 'developer'`).Scan(&roleID); err != nil {
		t.Fatalf("developer role: %v", err)
	}
	user := "user-" + uuid.NewString()
	for _, scope := range []string{`null`, `[1,2]`, `"global"`, `{}`, `{"project_id":"` + uuid.NewString() + `"}`} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id, scope) VALUES ($1, $2, $3::jsonb)`,
			user, roleID, scope); err != nil {
			t.Fatalf("seed scope %s: %v", scope, err)
		}
	}

	repo := storage.NewUserRoles(pool)
	rows, err := repo.ListByUser(ctx, user)
	if err != nil {
		t.Fatalf("ListByUser must not fail on a malformed row: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("rows = %d, want 5", len(rows))
	}
	malformed := 0
	for _, r := range rows {
		if r.ScopeMalformed {
			malformed++
			if r.Scope != nil {
				t.Errorf("malformed row %s carries scope %v", r.ID, r.Scope)
			}
		} else if r.Scope == nil {
			t.Errorf("object scope row %s decoded to nil", r.ID)
		}
	}
	if malformed != 3 {
		t.Errorf("malformed rows = %d, want 3 (null, array, string)", malformed)
	}

	got, err := repo.Get(ctx, rows[0].ID)
	if err != nil || got.ID != rows[0].ID || got.UserID != user {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if _, err := repo.Get(ctx, uuid.New()); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get missing = %v, want ErrNotFound", err)
	}
}
