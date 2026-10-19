package storage_test

// api#273 follow-up: a role edit and a provider save that picks that
// role as its default can't both pass their checks at once. They share
// a lock on the role row: the provider save holds it FOR SHARE, the role
// edit FOR UPDATE.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

var allowedDefault = []string{"secret.list", "secret.request", "audit.read"}

func newBasicRole(t *testing.T, pool *storage.Pool) uuid.UUID {
	t.Helper()
	// Start without providers, and leave none: a provider with a default
	// role holds the role (ON DELETE RESTRICT) against other tests' wipes.
	wipe := func() { _, _ = pool.Exec(context.Background(), `DELETE FROM sso_providers`) }
	wipe()
	t.Cleanup(wipe)
	id := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles (id, name, permissions) VALUES ($1, $2, '["secret.request"]')`,
		id, "sso-lock-"+id.String()[:8]); err != nil {
		t.Fatal(err)
	}
	return id
}

func waitsThenReturns(t *testing.T, done <-chan error, release func()) error {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("returned before the other transaction let go: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	return <-done
}

// A provider save waits for a role edit in progress, then sees the
// widened role and refuses it.
func TestSSOStore_ProviderSaveWaitsForRoleEdit(t *testing.T) {
	pool := freshDB(t)
	store := storage.NewSSOStore(pool)
	ctx := t.Context()
	role := newBasicRole(t, pool)

	edit, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = edit.Rollback(ctx) }()
	if _, err := edit.Exec(ctx, `SELECT 1 FROM roles WHERE id = $1 FOR UPDATE`, role); err != nil {
		t.Fatal(err)
	}
	if _, err := edit.Exec(ctx, `UPDATE roles SET permissions = '["secret.request", "secret.reveal.direct"]' WHERE id = $1`, role); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- store.CreateProvider(ctx, &storage.SSOProvider{Type: "google", DisplayName: "Google", ClientID: "c",
			AllowedDomains: []string{"example.com"}, DefaultRoleID: &role, CreatedBy: "user:a"}, allowedDefault)
	}()
	err = waitsThenReturns(t, done, func() {
		if err := edit.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	})
	if !errors.Is(err, storage.ErrDefaultRolePrivileged) {
		t.Fatalf("CreateProvider after the role edit = %v; want ErrDefaultRolePrivileged", err)
	}
}

// A widening role edit waits for a provider save in progress that picks
// the role, then sees the provider and refuses.
func TestSSOStore_RoleEditWaitsForProviderSave(t *testing.T) {
	pool := freshDB(t)
	store := storage.NewSSOStore(pool)
	ctx := t.Context()
	role := newBasicRole(t, pool)

	save, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = save.Rollback(ctx) }()
	if _, err := save.Exec(ctx, `SELECT 1 FROM roles WHERE id = $1 FOR SHARE`, role); err != nil {
		t.Fatal(err)
	}
	if _, err := save.Exec(ctx, `INSERT INTO sso_providers (type, display_name, client_id, allowed_domains, require_approval, default_role_id, enabled)
		VALUES ('google', 'Google', 'c', '{example.com}', FALSE, $1, FALSE)`, role); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- store.UpdateRolePermissionsUnlessDefault(ctx, role, []string{"secret.request", "secret.reveal.direct"})
	}()
	err = waitsThenReturns(t, done, func() {
		if err := save.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	})
	if !errors.Is(err, storage.ErrRoleIsSSODefault) {
		t.Fatalf("role edit after the provider save = %v; want ErrRoleIsSSODefault", err)
	}
	var widened bool
	if err := pool.QueryRow(ctx, `SELECT permissions ? 'secret.reveal.direct' FROM roles WHERE id = $1`, role).Scan(&widened); err != nil || widened {
		t.Fatalf("role widened = %v (%v)", widened, err)
	}
}
