package services_test

// Integration tests for the SessionService — server-side session
// table behind the HttpOnly cookie auth scaffold (Slice A2).
//
// Postgres-backed; TEST_DATABASE_URL gates the suite.

import (
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapSessions(t *testing.T) (*services.SessionService, *storage.Pool, *storage.LocalUser) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL is required; skipping")
	}

	ctx := t.Context()
	storageCfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, storageCfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, storageCfg)
	if err != nil {
		t.Fatalf("Open storage: %v", err)
	}
	t.Cleanup(pool.Close)

	const truncate = `
		TRUNCATE TABLE
			audit_events, sessions, user_roles, local_users
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// One seed user — every session test needs an owner.
	hash, err := bcrypt.GenerateFromPassword([]byte("seedpw"), 10)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	users := storage.NewLocalUsers(pool)
	owner := &storage.LocalUser{
		Email:        "session-owner@example.com",
		PasswordHash: hash,
		DisplayName:  "Owner",
	}
	if err := users.Create(ctx, owner); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	svc := services.NewSessionService(
		storage.NewSessions(pool),
		storage.NewAuditEvents(pool),
	)
	return svc, pool, owner
}

func TestSession_IssueValidateRoundtrip(t *testing.T) {
	svc, _, owner := bootstrapSessions(t)
	ctx := t.Context()

	issued, err := svc.Issue(ctx, owner.ID, "10.0.0.1", "Mozilla/5.0 (test)")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.CookieValue == "" {
		t.Fatal("empty cookie value")
	}
	if issued.Session == nil || issued.Session.UserID != owner.ID {
		t.Fatalf("unexpected session: %+v", issued.Session)
	}
	if !issued.AbsoluteExpiry.After(time.Now()) {
		t.Fatalf("absolute expiry not in the future: %v", issued.AbsoluteExpiry)
	}

	session, err := svc.Validate(ctx, issued.CookieValue)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if session.UserID != owner.ID {
		t.Fatalf("validated session user_id = %v, want %v", session.UserID, owner.ID)
	}
}

func TestSession_SubjectFromCookie(t *testing.T) {
	svc, _, owner := bootstrapSessions(t)
	ctx := t.Context()

	issued, err := svc.Issue(ctx, owner.ID, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	sub, err := svc.SubjectFromCookie(ctx, issued.CookieValue)
	if err != nil {
		t.Fatalf("SubjectFromCookie: %v", err)
	}
	if sub != owner.ID.String() {
		t.Fatalf("SubjectFromCookie = %q, want %q", sub, owner.ID.String())
	}
}

func TestSession_ValidateRejectsMalformedCookie(t *testing.T) {
	svc, _, _ := bootstrapSessions(t)
	ctx := t.Context()

	cases := []string{
		"",
		"not-base64-=!@",
		"YWJjZGVm", // valid base64 but wrong length
	}
	for _, in := range cases {
		if _, err := svc.Validate(ctx, in); err == nil {
			t.Fatalf("Validate(%q): expected error, got nil", in)
		}
	}
}

func TestSession_RevokedSessionRejected(t *testing.T) {
	svc, pool, owner := bootstrapSessions(t)
	ctx := t.Context()

	issued, err := svc.Issue(ctx, owner.ID, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := svc.Revoke(ctx, issued.CookieValue); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Validate(ctx, issued.CookieValue); err == nil {
		t.Fatal("Validate after Revoke: expected error, got nil")
	}
	// Revoke is idempotent — re-revoking is a no-op.
	if err := svc.Revoke(ctx, issued.CookieValue); err != nil {
		t.Fatalf("Re-revoke: %v", err)
	}

	var revokeCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'session.revoke'`,
	).Scan(&revokeCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if revokeCount != 1 {
		t.Fatalf("expected 1 session.revoke audit row, got %d", revokeCount)
	}
}

func TestSession_ExpiredAbsoluteRejected(t *testing.T) {
	svc, pool, owner := bootstrapSessions(t)
	svc = svc.WithPolicy(services.SessionPolicy{
		IdleTTL:     30 * time.Minute,
		AbsoluteTTL: 8 * time.Hour,
	})
	ctx := t.Context()

	issued, err := svc.Issue(ctx, owner.ID, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Backdate absolute expiry to a past timestamp via raw SQL.
	if _, err := pool.Exec(ctx,
		`UPDATE sessions SET expires_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(-1*time.Minute), issued.Session.ID,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, err := svc.Validate(ctx, issued.CookieValue); err == nil {
		t.Fatal("expected ErrSessionInvalid on expired absolute TTL")
	}
}

func TestSession_IdleSlidesForwardOnValidate(t *testing.T) {
	svc, _, owner := bootstrapSessions(t)
	svc = svc.WithPolicy(services.SessionPolicy{
		IdleTTL:     30 * time.Minute,
		AbsoluteTTL: 8 * time.Hour,
	})
	ctx := t.Context()

	issued, err := svc.Issue(ctx, owner.ID, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	initialIdle := issued.Session.IdleExpiresAt
	time.Sleep(1100 * time.Millisecond) // long enough that the new idle is measurably later
	session, err := svc.Validate(ctx, issued.CookieValue)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !session.IdleExpiresAt.After(initialIdle) {
		t.Fatalf("idle expiry did not slide forward: before=%v after=%v",
			initialIdle, session.IdleExpiresAt)
	}
}

func TestSession_RevokeAllForUserRevokesActiveOnly(t *testing.T) {
	svc, _, owner := bootstrapSessions(t)
	ctx := t.Context()

	// Issue three sessions; revoke the second one explicitly so we can
	// confirm the bulk revoke only touches sessions that were still
	// active at the time.
	var cookies []string
	for i := 0; i < 3; i++ {
		issued, err := svc.Issue(ctx, owner.ID, "", "")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		cookies = append(cookies, issued.CookieValue)
	}
	if err := svc.Revoke(ctx, cookies[1]); err != nil {
		t.Fatalf("Revoke single: %v", err)
	}

	repo := storage.NewSessions(svcPool(t, svc))
	n, err := repo.RevokeAllForUser(ctx, owner.ID, time.Now().UTC())
	if err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	if n != 2 {
		t.Fatalf("RevokeAllForUser n = %d, want 2 (the third + the first; #2 already revoked)", n)
	}
	for _, c := range cookies {
		if _, err := svc.Validate(ctx, c); err == nil {
			t.Fatal("expected all three sessions invalid after bulk revoke")
		}
	}
}

// svcPool exposes the SessionService's underlying pool via a fresh
// connection so the test can talk to the Sessions repo without
// re-bootstrapping the whole stack. Used only by the bulk-revoke
// test above; the SessionService doesn't expose its repo handle
// publicly because callers shouldn't need it.
func svcPool(t *testing.T, _ *services.SessionService) *storage.Pool {
	t.Helper()
	pool, err := storage.Open(t.Context(), storage.Config{
		DSN:          os.Getenv("TEST_DATABASE_URL"),
		MaxConns:     2,
		ConnLifetime: 1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Open helper pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
