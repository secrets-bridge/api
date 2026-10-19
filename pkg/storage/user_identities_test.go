package storage_test

// api#267 part 2 review: the cap on accounts waiting at once is checked
// inside CreateAccount's transaction, under a lock, so concurrent
// sign-ins can't all see room under it.

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/secrets-bridge/api/pkg/storage"
)

func TestUserIdentities_PendingCapHoldsUnderConcurrency(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewUserIdentities(pool)
	const capacity, attempts = 3, 16

	var wg sync.WaitGroup
	errs := make([]error, attempts)
	start := make(chan struct{})
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			u := &storage.LocalUser{Email: fmt.Sprintf("race%02d@example.com", i), PasswordHash: []byte("x"), DisplayName: "r", PendingApproval: true}
			id := &storage.UserIdentity{ProviderType: "google", Issuer: "https://idp.example.com", Subject: fmt.Sprintf("race-%d", i), EmailAtLink: u.Email}
			errs[i] = repo.CreateAccount(t.Context(), u, id, nil, "system:sso", capacity)
		}()
	}
	close(start)
	wg.Wait()

	created, refused := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, storage.ErrPendingCap):
			refused++
		default:
			t.Fatalf("CreateAccount: %v", err)
		}
	}
	if created != capacity || refused != attempts-capacity {
		t.Fatalf("created %d, refused %d; want %d and %d", created, refused, capacity, attempts-capacity)
	}
}

// The cap check waits for another sign-in holding the lock, then counts
// the account that one committed. Without the lock it would count before
// that commit and go over the cap.
func TestUserIdentities_PendingCapWaitsForTheLock(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewUserIdentities(pool)
	ctx := t.Context()

	other, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback(ctx) }()
	if _, err := other.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('secrets-bridge:sso-pending-cap'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exec(ctx, `INSERT INTO local_users (email, password_hash, display_name, pending_approval)
		VALUES ('first@example.com', '\x00', 'First', TRUE)`); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		u := &storage.LocalUser{Email: "second@example.com", PasswordHash: []byte("x"), DisplayName: "Second", PendingApproval: true}
		done <- repo.CreateAccount(ctx, u, &storage.UserIdentity{ProviderType: "google", Issuer: "https://idp.example.com", Subject: "second", EmailAtLink: u.Email}, nil, "system:sso", 1)
	}()
	select {
	case err := <-done:
		t.Fatalf("CreateAccount didn't wait for the other sign-in: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := other.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, storage.ErrPendingCap) {
		t.Fatalf("CreateAccount after the other sign-in committed = %v; want ErrPendingCap", err)
	}
}

// The identity that created its account can't be removed; one linked to
// an existing account can.
func TestUserIdentities_CreatingIdentityStays(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewUserIdentities(pool)
	ctx := t.Context()
	u := &storage.LocalUser{Email: "gia@example.com", PasswordHash: []byte("x"), DisplayName: "Gia"}
	if err := repo.CreateAccount(ctx, u, &storage.UserIdentity{ProviderType: "google", Issuer: "https://idp.example.com", Subject: "gia", EmailAtLink: u.Email}, nil, "system:sso", 0); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.HasPassword(ctx, u.ID); err != nil || ok {
		t.Fatalf("HasPassword for a created account = %v, %v; want false", ok, err)
	}
	if _, err := repo.Unlink(ctx, u.ID, "google"); !errors.Is(err, storage.ErrIdentityRequired) {
		t.Fatalf("Unlink of the creating identity = %v; want ErrIdentityRequired", err)
	}
	if _, err := repo.Unlink(ctx, u.ID, "other"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Unlink of a missing identity = %v; want ErrNotFound", err)
	}

	local := newPendingUser(t, storage.NewLocalUsers(pool), "lee@example.com", false)
	if err := repo.Link(ctx, &storage.UserIdentity{UserID: local.ID, ProviderType: "google", Issuer: "https://idp.example.com", Subject: "lee", EmailAtLink: local.Email}); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.HasPassword(ctx, local.ID); err != nil || !ok {
		t.Fatalf("HasPassword for a password account = %v, %v; want true", ok, err)
	}
	if _, err := repo.Unlink(ctx, local.ID, "google"); err != nil {
		t.Fatalf("Unlink of a linked identity = %v", err)
	}
}
