package storage_test

// API-S-25: BeginLoginAttempt is the single-statement gate that counts
// a password attempt before bcrypt runs. These tests pin its
// semantics against a live Postgres.

import (
	"sync"
	"testing"
	"time"

	"github.com/secrets-bridge/api/pkg/storage"
)

func newLockoutUser(t *testing.T, repo *storage.LocalUsers, email string) *storage.LocalUser {
	t.Helper()
	u := &storage.LocalUser{Email: email, PasswordHash: []byte("not-a-real-hash"), DisplayName: "Lockout"}
	if err := repo.Create(t.Context(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestBeginLoginAttempt_ConcurrentCallsNeverExceedThreshold(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewLocalUsers(pool)
	u := newLockoutUser(t, repo, "lockout-race@example.com")

	const callers, threshold = 40, 5
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	gate := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			a, err := repo.BeginLoginAttempt(t.Context(), u.ID, threshold, time.Hour, time.Now())
			if err != nil {
				t.Errorf("BeginLoginAttempt: %v", err)
				return
			}
			if a.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	close(gate)
	wg.Wait()

	if allowed != threshold {
		t.Fatalf("%d of %d concurrent attempts allowed, want exactly %d", allowed, callers, threshold)
	}
	got, err := repo.Get(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.FailedLoginCount != threshold || got.LockedUntil == nil || !got.LockedUntil.After(time.Now()) {
		t.Fatalf("count=%d locked_until=%v, want %d and a future lock", got.FailedLoginCount, got.LockedUntil, threshold)
	}
}

func TestBeginLoginAttempt_LockExpiryDisabledAndClear(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewLocalUsers(pool)
	ctx := t.Context()
	u := newLockoutUser(t, repo, "lockout-states@example.com")
	now := time.Now().UTC()

	for i := 1; i <= 3; i++ {
		a, err := repo.BeginLoginAttempt(ctx, u.ID, 3, time.Hour, now)
		if err != nil || !a.Allowed || a.FailedLoginCount != i {
			t.Fatalf("attempt %d: %+v err=%v", i, a, err)
		}
		if (i == 3) != (a.LockedUntil != nil) {
			t.Fatalf("attempt %d: LockedUntil=%v, want set only at the threshold", i, a.LockedUntil)
		}
	}
	a, err := repo.BeginLoginAttempt(ctx, u.ID, 3, time.Hour, now)
	if err != nil || a.Allowed || a.LockedUntil == nil {
		t.Fatalf("while locked: %+v err=%v, want refused with locked_until", a, err)
	}

	// After the lock expires exactly one attempt gets through and the
	// over-threshold counter re-locks in the same statement.
	later := now.Add(2 * time.Hour)
	if a, err := repo.BeginLoginAttempt(ctx, u.ID, 3, time.Hour, later); err != nil || !a.Allowed || a.LockedUntil == nil {
		t.Fatalf("after expiry: %+v err=%v, want one allowed attempt that re-locks", a, err)
	}
	if a, err := repo.BeginLoginAttempt(ctx, u.ID, 3, time.Hour, later); err != nil || a.Allowed {
		t.Fatalf("second attempt after expiry: %+v err=%v, want refused", a, err)
	}

	if err := repo.ClearLockout(ctx, u.ID); err != nil {
		t.Fatalf("ClearLockout: %v", err)
	}
	if a, err := repo.BeginLoginAttempt(ctx, u.ID, 3, time.Hour, later); err != nil || !a.Allowed || a.FailedLoginCount != 1 {
		t.Fatalf("after clear: %+v err=%v, want allowed with count 1", a, err)
	}

	if err := repo.SetDisabled(ctx, u.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	a, err = repo.BeginLoginAttempt(ctx, u.ID, 3, time.Hour, later)
	if err != nil || a.Allowed || !a.Disabled {
		t.Fatalf("disabled: %+v err=%v, want refused with Disabled", a, err)
	}
	got, _ := repo.Get(ctx, u.ID)
	if got.FailedLoginCount != 1 {
		t.Fatalf("refused attempts changed the counter: %d, want 1", got.FailedLoginCount)
	}
}
