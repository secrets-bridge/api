package storage_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Slice M1 — schema + repo round-trip + sweep contract.

func TestRevealSessions_CreateAndGet(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()

	projectID := makeProject(t, pool, "rs-create")
	envRepo := storage.NewEnvironments(pool)
	env := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	if err := envRepo.Create(ctx, env); err != nil {
		t.Fatalf("env Create: %v", err)
	}

	repo := storage.NewRevealSessions(pool)
	wrapIDs := []uuid.UUID{uuid.New(), uuid.New()}
	s := &storage.RevealSession{
		UserID:        "alice@example.com",
		ProjectID:     projectID,
		EnvironmentID: env.ID,
		TTLSeconds:    120,
		ExpiresAt:     time.Now().Add(120 * time.Second),
		WrapIDs:       wrapIDs,
	}
	if err := repo.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.ID == uuid.Nil {
		t.Fatal("Create: ID was not assigned")
	}

	got, err := repo.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UserID != "alice@example.com" {
		t.Errorf("UserID: got %q", got.UserID)
	}
	if got.TTLSeconds != 120 {
		t.Errorf("TTLSeconds: got %d", got.TTLSeconds)
	}
	if got.ExpiredAt != nil {
		t.Errorf("ExpiredAt should be nil for fresh session")
	}
	if got.ExpiredReason != "" {
		t.Errorf("ExpiredReason should be empty for fresh session, got %q", got.ExpiredReason)
	}
	if len(got.WrapIDs) != 2 || got.WrapIDs[0] != wrapIDs[0] || got.WrapIDs[1] != wrapIDs[1] {
		t.Errorf("WrapIDs round-trip lost: %+v", got.WrapIDs)
	}
}

func TestRevealSessions_TTLOutOfRangeRejected(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	projectID := makeProject(t, pool, "rs-ttl-range")
	envRepo := storage.NewEnvironments(pool)
	env := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	_ = envRepo.Create(ctx, env)

	repo := storage.NewRevealSessions(pool)
	cases := []int{5, 600, 9, 301}
	for _, ttl := range cases {
		s := &storage.RevealSession{
			UserID: "alice@example.com", ProjectID: projectID, EnvironmentID: env.ID,
			TTLSeconds: ttl, ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
		}
		if err := repo.Create(ctx, s); err == nil {
			t.Errorf("TTL %d should fail CHECK", ttl)
		}
	}
}

func TestRevealSessions_ExpiredReasonCheckEnforced(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()

	projectID := makeProject(t, pool, "rs-reason-check")
	envRepo := storage.NewEnvironments(pool)
	env := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	_ = envRepo.Create(ctx, env)

	// Direct INSERT with a bogus reason should be rejected by the CHECK.
	_, err := pool.Exec(ctx, `
		INSERT INTO reveal_sessions (
			user_id, project_id, environment_id, ttl_seconds, expires_at,
			expired_at, expired_reason, wrap_ids
		) VALUES ($1, $2, $3, $4, now() + interval '60 seconds',
			now(), 'bogus', $5)`,
		"alice", projectID, env.ID, 60, []uuid.UUID{},
	)
	if err == nil {
		t.Fatal("expected CHECK violation on expired_reason='bogus'")
	}
}

func TestRevealSessions_MarkExpired(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	projectID := makeProject(t, pool, "rs-mark-expired")
	envRepo := storage.NewEnvironments(pool)
	env := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	_ = envRepo.Create(ctx, env)

	repo := storage.NewRevealSessions(pool)
	s := &storage.RevealSession{
		UserID: "alice", ProjectID: projectID, EnvironmentID: env.ID,
		TTLSeconds: 60, ExpiresAt: time.Now().Add(60 * time.Second),
		WrapIDs: []uuid.UUID{},
	}
	if err := repo.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}

	now := time.Now()
	if err := repo.MarkExpired(ctx, s.ID, now, storage.RevealSessionExpiredUserHide); err != nil {
		t.Fatalf("MarkExpired: %v", err)
	}
	got, _ := repo.Get(ctx, s.ID)
	if got.ExpiredAt == nil {
		t.Fatal("ExpiredAt should be set")
	}
	if got.ExpiredReason != string(storage.RevealSessionExpiredUserHide) {
		t.Errorf("ExpiredReason: got %q want user_hide", got.ExpiredReason)
	}

	// Second call → ErrRevealSessionExpired.
	if err := repo.MarkExpired(ctx, s.ID, now.Add(time.Second), storage.RevealSessionExpiredUnmount); !errors.Is(err, storage.ErrRevealSessionExpired) {
		t.Errorf("second MarkExpired: got %v want ErrRevealSessionExpired", err)
	}
}

func TestRevealSessions_ListActiveForUser(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	projectID := makeProject(t, pool, "rs-list-active")
	envRepo := storage.NewEnvironments(pool)
	env := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	_ = envRepo.Create(ctx, env)

	repo := storage.NewRevealSessions(pool)
	// Alice: 2 active + 1 expired
	for i := 0; i < 3; i++ {
		s := &storage.RevealSession{
			UserID: "alice", ProjectID: projectID, EnvironmentID: env.ID,
			TTLSeconds: 60, ExpiresAt: time.Now().Add(60 * time.Second),
			WrapIDs: []uuid.UUID{},
		}
		_ = repo.Create(ctx, s)
		if i == 0 {
			_ = repo.MarkExpired(ctx, s.ID, time.Now(), storage.RevealSessionExpiredUserHide)
		}
	}
	// Bob: 1 active — should not appear in Alice's list.
	bob := &storage.RevealSession{
		UserID: "bob", ProjectID: projectID, EnvironmentID: env.ID,
		TTLSeconds: 60, ExpiresAt: time.Now().Add(60 * time.Second),
		WrapIDs: []uuid.UUID{},
	}
	_ = repo.Create(ctx, bob)

	aliceActive, err := repo.ListActiveForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListActiveForUser: %v", err)
	}
	if len(aliceActive) != 2 {
		t.Errorf("Alice active count: got %d want 2", len(aliceActive))
	}
	for _, s := range aliceActive {
		if s.ExpiredAt != nil {
			t.Errorf("listed session %s should be active", s.ID)
		}
	}
}

func TestRevealSessions_SweepExpired(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	projectID := makeProject(t, pool, "rs-sweep")
	envRepo := storage.NewEnvironments(pool)
	env := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	_ = envRepo.Create(ctx, env)

	repo := storage.NewRevealSessions(pool)
	now := time.Now()

	// 3 sessions: 2 past TTL (with wrap_ids), 1 still active.
	wrapA := []uuid.UUID{uuid.New(), uuid.New()}
	wrapB := []uuid.UUID{uuid.New()}
	// past TTL #1
	pastA := &storage.RevealSession{
		UserID: "alice", ProjectID: projectID, EnvironmentID: env.ID,
		TTLSeconds: 60, ExpiresAt: now.Add(-1 * time.Minute), WrapIDs: wrapA,
	}
	_ = repo.Create(ctx, pastA)
	// past TTL #2
	pastB := &storage.RevealSession{
		UserID: "bob", ProjectID: projectID, EnvironmentID: env.ID,
		TTLSeconds: 60, ExpiresAt: now.Add(-30 * time.Second), WrapIDs: wrapB,
	}
	_ = repo.Create(ctx, pastB)
	// still active
	active := &storage.RevealSession{
		UserID: "carol", ProjectID: projectID, EnvironmentID: env.ID,
		TTLSeconds: 60, ExpiresAt: now.Add(2 * time.Minute), WrapIDs: []uuid.UUID{},
	}
	_ = repo.Create(ctx, active)

	swept, err := repo.SweepExpired(ctx, now)
	if err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	if len(swept) != 2 {
		t.Fatalf("SweepExpired count: got %d want 2", len(swept))
	}

	// Wrap IDs match across the two swept rows (order not guaranteed).
	seenWraps := map[uuid.UUID]bool{}
	for _, s := range swept {
		for _, w := range s.WrapIDs {
			seenWraps[w] = true
		}
	}
	for _, w := range append(wrapA, wrapB...) {
		if !seenWraps[w] {
			t.Errorf("wrap %s missing from sweep return", w)
		}
	}

	// The 2 past sessions are now expired with reason='ttl'.
	for _, id := range []uuid.UUID{pastA.ID, pastB.ID} {
		got, _ := repo.Get(ctx, id)
		if got.ExpiredAt == nil {
			t.Errorf("session %s should be expired", id)
		}
		if got.ExpiredReason != string(storage.RevealSessionExpiredTTL) {
			t.Errorf("session %s reason: got %q want ttl", id, got.ExpiredReason)
		}
	}

	// The active session stays active.
	got, _ := repo.Get(ctx, active.ID)
	if got.ExpiredAt != nil {
		t.Errorf("active session should NOT be expired")
	}

	// Re-running the sweep is a no-op.
	again, err := repo.SweepExpired(ctx, now)
	if err != nil {
		t.Fatalf("re-sweep: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("idempotent sweep returned %d rows", len(again))
	}
}
