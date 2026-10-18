package storage_test

// api#266: accounts waiting for approval. Approve clears the flag and
// grants the role in one transaction; decline only touches a waiting
// account.

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

func newPendingUser(t *testing.T, repo *storage.LocalUsers, email string, pending bool) *storage.LocalUser {
	t.Helper()
	u := &storage.LocalUser{Email: email, PasswordHash: []byte("not-a-real-hash"), DisplayName: email, PendingApproval: pending}
	if err := repo.Create(t.Context(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func newRole(t *testing.T, pool *storage.Pool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO roles (id, name, permissions, is_system) VALUES ($1, $2, '["secret.request"]'::jsonb, false)`,
		id, "pending-test-"+id.String()[:8]); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	return id
}

func TestLocalUsers_PendingApproval(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewLocalUsers(pool)
	ctx := t.Context()
	role := newRole(t, pool)

	waiting := newPendingUser(t, repo, "waiting@example.com", true)
	second := newPendingUser(t, repo, "second@example.com", true)
	active := newPendingUser(t, repo, "active@example.com", false)

	got, err := repo.Get(ctx, waiting.ID)
	if err != nil || !got.PendingApproval {
		t.Fatalf("Get = %+v, %v; want PendingApproval", got, err)
	}

	list, total, err := repo.ListPending(ctx, 0)
	if err != nil || total != 2 || len(list) != 2 || list[0].ID != waiting.ID {
		t.Fatalf("ListPending = %d rows, total %d, %v; want the two waiting accounts, oldest first", len(list), total, err)
	}

	// Approve: flag cleared and role granted together.
	ur := &storage.UserRole{RoleID: role, Scope: map[string]any{}, GrantedBy: "user:admin"}
	if err := repo.ApprovePending(ctx, waiting.ID, ur); err != nil {
		t.Fatalf("ApprovePending: %v", err)
	}
	if got, _ := repo.Get(ctx, waiting.ID); got.PendingApproval {
		t.Fatal("approved account still waiting")
	}
	var grants int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_roles WHERE user_id = $1 AND role_id = $2`,
		waiting.ID.String(), role).Scan(&grants); err != nil || grants != 1 || ur.ID == uuid.Nil {
		t.Fatalf("grants after approve = %d, %v (id %s); want 1", grants, err, ur.ID)
	}

	// A second approve, or approving an active account, is refused.
	if err := repo.ApprovePending(ctx, waiting.ID, &storage.UserRole{RoleID: role}); !errors.Is(err, storage.ErrNotPending) {
		t.Fatalf("approve twice = %v; want ErrNotPending", err)
	}
	if err := repo.ApprovePending(ctx, active.ID, &storage.UserRole{RoleID: role}); !errors.Is(err, storage.ErrNotPending) {
		t.Fatalf("approve an active account = %v; want ErrNotPending", err)
	}

	// An unknown role leaves the account waiting, with no grant.
	if err := repo.ApprovePending(ctx, second.ID, &storage.UserRole{RoleID: uuid.New()}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("approve with an unknown role = %v; want ErrNotFound", err)
	}
	if got, _ := repo.Get(ctx, second.ID); !got.PendingApproval {
		t.Fatal("a failed grant cleared the waiting flag")
	}

	// Decline never touches an active account; it disables a waiting one
	// and keeps it waiting, so re-enabling it still needs an approval.
	if err := repo.DeclinePending(ctx, active.ID); !errors.Is(err, storage.ErrNotPending) {
		t.Fatalf("decline an active account = %v; want ErrNotPending", err)
	}
	if got, _ := repo.Get(ctx, active.ID); got.Disabled {
		t.Fatal("decline disabled an active account")
	}
	if err := repo.DeclinePending(ctx, second.ID); err != nil {
		t.Fatalf("DeclinePending: %v", err)
	}
	if got, _ := repo.Get(ctx, second.ID); !got.Disabled || !got.PendingApproval {
		t.Fatalf("declined account = disabled %v, pending %v; want both", got.Disabled, got.PendingApproval)
	}
	if _, total, _ := repo.ListPending(ctx, 0); total != 0 {
		t.Fatalf("ListPending total after approve and decline = %d; want 0", total)
	}

	if err := repo.ApprovePending(ctx, uuid.New(), &storage.UserRole{RoleID: role}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("approve unknown user = %v; want ErrNotFound", err)
	}
	if err := repo.DeclinePending(ctx, uuid.New()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("decline unknown user = %v; want ErrNotFound", err)
	}
}
