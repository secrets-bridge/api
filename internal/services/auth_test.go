package services_test

// Integration tests for the local-users dev seeder.
// Requires TEST_DATABASE_URL; SKIPs otherwise.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapAuth(t *testing.T) (*services.AuthService, *storage.Pool) {
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

	// Truncate every table that holds user-bound state. We leave the
	// workflow-engine tables (roles, workflow_definitions, policy_rules)
	// alone — they hold the seed `admin`/`approver`/`developer` roles
	// the seeder binds to. local_users belongs in the truncation list
	// so each test starts on an empty users table.
	const truncate = `
		TRUNCATE TABLE
			audit_events, user_roles, local_users
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	svc := services.NewAuthService(
		storage.NewLocalUsers(pool),
		storage.NewRoles(pool),
		storage.NewUserRoles(pool),
		storage.NewAuditEvents(pool),
	)
	return svc, pool
}

func TestBootstrapDevUsers_CreatesAdminApproverRequester(t *testing.T) {
	svc, pool := bootstrapAuth(t)
	ctx := t.Context()

	seeded, err := svc.BootstrapDevUsers(ctx, "shared-uat-password")
	if err != nil {
		t.Fatalf("BootstrapDevUsers: %v", err)
	}
	if len(seeded) != 3 {
		t.Fatalf("expected 3 seeded users, got %d", len(seeded))
	}

	byRole := map[string]services.DevSeededUser{}
	for _, u := range seeded {
		byRole[u.Role] = u
		if u.Password != "shared-uat-password" {
			t.Fatalf("shared-password mode: %s got password %q", u.Email, u.Password)
		}
	}

	for _, want := range []struct{ role, email string }{
		{"admin", "admin@secrets-bridge.dev"},
		{"approver", "approver@secrets-bridge.dev"},
		{"developer", "requester@secrets-bridge.dev"},
	} {
		got, ok := byRole[want.role]
		if !ok {
			t.Fatalf("no seeded user for role %q", want.role)
		}
		if got.Email != want.email {
			t.Fatalf("role %q: email %q, want %q", want.role, got.Email, want.email)
		}
	}

	// Verify every user can be looked up via the same path Login uses
	// and that the password compares cleanly under bcrypt.
	repo := storage.NewLocalUsers(pool)
	for _, u := range seeded {
		row, err := repo.GetByEmail(ctx, u.Email)
		if err != nil {
			t.Fatalf("GetByEmail %s: %v", u.Email, err)
		}
		if err := bcrypt.CompareHashAndPassword(row.PasswordHash, []byte(u.Password)); err != nil {
			t.Fatalf("bcrypt compare for %s: %v", u.Email, err)
		}
	}

	// Each user should hold exactly one role grant.
	userRoles := storage.NewUserRoles(pool)
	for _, u := range seeded {
		row, err := repo.GetByEmail(ctx, u.Email)
		if err != nil {
			t.Fatalf("GetByEmail %s: %v", u.Email, err)
		}
		grants, err := userRoles.ListByUser(ctx, row.ID.String())
		if err != nil {
			t.Fatalf("ListByUser %s: %v", u.Email, err)
		}
		if len(grants) != 1 {
			t.Fatalf("user %s: expected 1 role grant, got %d", u.Email, len(grants))
		}
	}
}

func TestBootstrapDevUsers_RandomPasswordWhenUnset(t *testing.T) {
	svc, _ := bootstrapAuth(t)
	ctx := t.Context()

	seeded, err := svc.BootstrapDevUsers(ctx, "")
	if err != nil {
		t.Fatalf("BootstrapDevUsers: %v", err)
	}
	if len(seeded) != 3 {
		t.Fatalf("expected 3 seeded users, got %d", len(seeded))
	}

	// Each random password should be distinct and non-trivial.
	seen := map[string]bool{}
	for _, u := range seeded {
		if len(u.Password) < 24 {
			t.Fatalf("random password for %s too short: %d chars", u.Email, len(u.Password))
		}
		if seen[u.Password] {
			t.Fatalf("random passwords collided for %s", u.Email)
		}
		seen[u.Password] = true
	}
}

func TestBootstrapDevUsers_IdempotentSecondCall(t *testing.T) {
	svc, _ := bootstrapAuth(t)
	ctx := t.Context()

	first, err := svc.BootstrapDevUsers(ctx, "p1")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(first) != 3 {
		t.Fatalf("first call expected 3 seeded users, got %d", len(first))
	}

	second, err := svc.BootstrapDevUsers(ctx, "p2")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("second call expected 0 seeded users (idempotent), got %d", len(second))
	}
}

func TestBootstrapDevUsers_SkipsWhenAnyUserExists(t *testing.T) {
	svc, pool := bootstrapAuth(t)
	ctx := t.Context()

	// Pre-seed one unrelated user so Count > 0 before the dev seeder runs.
	repo := storage.NewLocalUsers(pool)
	hash, err := bcrypt.GenerateFromPassword([]byte("existing"), 10)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if err := repo.Create(ctx, &storage.LocalUser{
		Email:        "preexisting@example.com",
		PasswordHash: hash,
		DisplayName:  "Preexisting",
	}); err != nil {
		t.Fatalf("Create preexisting: %v", err)
	}

	seeded, err := svc.BootstrapDevUsers(ctx, "p1")
	if err != nil {
		t.Fatalf("BootstrapDevUsers: %v", err)
	}
	if len(seeded) != 0 {
		t.Fatalf("expected 0 seeded users when local_users is non-empty, got %d", len(seeded))
	}
}

// --- Slice A1 — lockout + BREAK_GLASS_LOGIN audit ---------------------

func mustCreateUser(t *testing.T, repo *storage.LocalUsers, email, password string) *storage.LocalUser {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	u := &storage.LocalUser{
		Email:        email,
		PasswordHash: hash,
		DisplayName:  "Test",
	}
	if err := repo.Create(t.Context(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestLogin_LocksAfterFiveWrongPasswordAttempts(t *testing.T) {
	svc, pool := bootstrapAuth(t)
	svc = svc.WithLockoutPolicy(services.LockoutPolicy{Threshold: 5, Duration: 15 * time.Minute})
	ctx := t.Context()

	repo := storage.NewLocalUsers(pool)
	user := mustCreateUser(t, repo, "alice@example.com", "ZZZ-canary-correct-ZZZ")

	for i := 1; i <= 5; i++ {
		if _, err := svc.Login(ctx, "alice@example.com", []byte("YYY-canary-badpw-YYY"), noSession); err == nil {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials", i)
		}
	}

	got, err := repo.Get(ctx, user.ID)
	if err != nil {
		t.Fatalf("Get user: %v", err)
	}
	if got.FailedLoginCount != 5 {
		t.Fatalf("failed_login_count = %d, want 5", got.FailedLoginCount)
	}
	if got.LockedUntil == nil {
		t.Fatal("locked_until is nil; expected the account to be locked")
	}
	if !got.LockedUntil.After(time.Now().UTC()) {
		t.Fatalf("locked_until = %v is in the past; expected future lock", got.LockedUntil)
	}

	// Even the CORRECT password is rejected while locked.
	if _, err := svc.Login(ctx, "alice@example.com", []byte("ZZZ-canary-correct-ZZZ"), noSession); err == nil {
		t.Fatal("expected ErrInvalidCredentials while locked even with correct password")
	}

	// Audit trail: one `auth.lockout.applied` event with metadata
	// carrying the threshold + duration; metadata MUST NOT include
	// the user's password.
	var lockApplied int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'auth.lockout.applied'`,
	).Scan(&lockApplied); err != nil {
		t.Fatalf("count lockout audit: %v", err)
	}
	if lockApplied != 1 {
		t.Fatalf("expected 1 auth.lockout.applied event, got %d", lockApplied)
	}
	var anyMeta string
	if err := pool.QueryRow(ctx,
		`SELECT string_agg(metadata::text, ' ') FROM audit_events`,
	).Scan(&anyMeta); err != nil {
		t.Fatalf("aggregate metadata: %v", err)
	}
	if strings.Contains(anyMeta, "ZZZ-canary-correct-ZZZ") || strings.Contains(anyMeta, "YYY-canary-badpw-YYY") {
		t.Fatal("audit metadata leaked a password fragment")
	}
}

func TestLogin_SuccessClearsCounter(t *testing.T) {
	svc, pool := bootstrapAuth(t)
	svc = svc.WithLockoutPolicy(services.LockoutPolicy{Threshold: 5, Duration: 15 * time.Minute})
	ctx := t.Context()

	repo := storage.NewLocalUsers(pool)
	user := mustCreateUser(t, repo, "bob@example.com", "secret123")

	// Two wrong attempts.
	for i := 0; i < 2; i++ {
		_, _ = svc.Login(ctx, "bob@example.com", []byte("nope"), noSession)
	}
	pre, err := repo.Get(ctx, user.ID)
	if err != nil {
		t.Fatalf("Get pre: %v", err)
	}
	if pre.FailedLoginCount != 2 {
		t.Fatalf("pre failed_login_count = %d, want 2", pre.FailedLoginCount)
	}

	// Correct login.
	res, err := svc.Login(ctx, "bob@example.com", []byte("secret123"), noSession)
	if err != nil {
		t.Fatalf("Login success: %v", err)
	}
	if res.User.ID != user.ID {
		t.Fatalf("login user = %s, want %s", res.User.ID, user.ID)
	}

	got, err := repo.Get(ctx, user.ID)
	if err != nil {
		t.Fatalf("Get post: %v", err)
	}
	if got.FailedLoginCount != 0 {
		t.Fatalf("post failed_login_count = %d, want 0", got.FailedLoginCount)
	}
	if got.LockedUntil != nil {
		t.Fatalf("post locked_until = %v, want nil", got.LockedUntil)
	}
}

func TestLogin_EmitsBreakGlassAuditEvent(t *testing.T) {
	svc, pool := bootstrapAuth(t)
	ctx := t.Context()

	repo := storage.NewLocalUsers(pool)
	mustCreateUser(t, repo, "carol@example.com", "pw-c")

	if _, err := svc.Login(ctx, "carol@example.com", []byte("pw-c"), noSession); err != nil {
		t.Fatalf("Login: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'BREAK_GLASS_LOGIN'`,
	).Scan(&count); err != nil {
		t.Fatalf("count break-glass: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 BREAK_GLASS_LOGIN event, got %d", count)
	}

	var meta string
	if err := pool.QueryRow(ctx,
		`SELECT metadata::text FROM audit_events WHERE action = 'BREAK_GLASS_LOGIN'`,
	).Scan(&meta); err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	if !strings.Contains(meta, `"severity"`) || !strings.Contains(meta, "CRITICAL") {
		t.Fatalf("expected severity=CRITICAL in metadata, got %s", meta)
	}
	if strings.Contains(meta, "pw-c") {
		t.Fatal("audit metadata contained the password")
	}
}

// noSession is a SessionStarter that always succeeds, for tests that
// only care about the credential checks.
func noSession(context.Context, uuid.UUID) error { return nil }

// A login whose session can't be started must not be audited as a
// success: no auth.login success row, no BREAK_GLASS_LOGIN, and one
// auth.login failure row with a generic error_kind and no error text.
func TestLogin_SessionStartFailureIsAuditedAsFailure(t *testing.T) {
	svc, pool := bootstrapAuth(t)
	ctx := t.Context()

	repo := storage.NewLocalUsers(pool)
	user := mustCreateUser(t, repo, "erin@example.com", "pw-e")

	startErr := errors.New("XXX-canary-session-store-down-XXX")
	var startedFor uuid.UUID
	_, err := svc.Login(ctx, "erin@example.com", []byte("pw-e"), func(_ context.Context, id uuid.UUID) error {
		startedFor = id
		return startErr
	})
	if !errors.Is(err, services.ErrSessionStart) || !errors.Is(err, startErr) {
		t.Fatalf("Login err = %v, want ErrSessionStart wrapping the start error", err)
	}
	if errors.Is(err, services.ErrInvalidCredentials) {
		t.Fatal("a session failure must not look like bad credentials")
	}
	if startedFor != user.ID {
		t.Fatalf("start called for %s, want %s", startedFor, user.ID)
	}

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE action = 'auth.login' AND status = 'success'`); n != 0 {
		t.Fatalf("%d auth.login success rows, want 0", n)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE action = 'BREAK_GLASS_LOGIN'`); n != 0 {
		t.Fatalf("%d BREAK_GLASS_LOGIN rows, want 0", n)
	}
	if n := count(`SELECT count(*) FROM audit_events
		WHERE action = 'auth.login' AND status = 'failure' AND resource = $1
		  AND metadata->>'error_kind' = 'session_start_failed'`, "user:"+user.ID.String()); n != 1 {
		t.Fatalf("%d session_start_failed rows, want 1", n)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%canary%' OR metadata::text LIKE '%pw-e%'`); n != 0 {
		t.Fatal("audit metadata carries the start error text or the password")
	}
}

// Without a SessionStarter there is no session, so there is no success.
func TestLogin_NilSessionStarterIsNotASuccess(t *testing.T) {
	svc, pool := bootstrapAuth(t)
	ctx := t.Context()

	repo := storage.NewLocalUsers(pool)
	mustCreateUser(t, repo, "gina@example.com", "pw-g")

	if _, err := svc.Login(ctx, "gina@example.com", []byte("pw-g"), nil); !errors.Is(err, services.ErrSessionStart) {
		t.Fatalf("Login err = %v, want ErrSessionStart", err)
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action IN ('auth.login', 'BREAK_GLASS_LOGIN') AND status = 'success'`,
	).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d success rows, want 0", n)
	}
}

func TestLogin_ExpiredLockoutAllowsNextSuccess(t *testing.T) {
	svc, pool := bootstrapAuth(t)
	svc = svc.WithLockoutPolicy(services.LockoutPolicy{Threshold: 3, Duration: 1 * time.Hour})
	ctx := t.Context()

	repo := storage.NewLocalUsers(pool)
	user := mustCreateUser(t, repo, "dave@example.com", "pw-d")

	// Trip the lock.
	for i := 0; i < 3; i++ {
		_, _ = svc.Login(ctx, "dave@example.com", []byte("nope"), noSession)
	}

	// Backdate the lock by hand to simulate expiry without sleeping.
	past := time.Now().UTC().Add(-1 * time.Minute)
	if err := repo.Lock(ctx, user.ID, past); err != nil {
		t.Fatalf("Lock backdate: %v", err)
	}

	// Lock has expired -> correct password now succeeds and resets state.
	if _, err := svc.Login(ctx, "dave@example.com", []byte("pw-d"), noSession); err != nil {
		t.Fatalf("Login after expiry: %v", err)
	}
	got, err := repo.Get(ctx, user.ID)
	if err != nil {
		t.Fatalf("Get post: %v", err)
	}
	if got.FailedLoginCount != 0 || got.LockedUntil != nil {
		t.Fatalf("expected counter+lock cleared, got count=%d locked=%v",
			got.FailedLoginCount, got.LockedUntil)
	}
}

func TestBootstrapDevUsers_AuditEventsWritten(t *testing.T) {
	svc, pool := bootstrapAuth(t)
	ctx := t.Context()

	_, err := svc.BootstrapDevUsers(ctx, "p1")
	if err != nil {
		t.Fatalf("BootstrapDevUsers: %v", err)
	}

	// Expect exactly three `auth.bootstrap_dev_user` events.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'auth.bootstrap_dev_user'`,
	).Scan(&count); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 bootstrap audit events, got %d", count)
	}

	// And the metadata must NEVER include the password.
	var meta string
	if err := pool.QueryRow(ctx,
		`SELECT string_agg(metadata::text, ' ') FROM audit_events WHERE action = 'auth.bootstrap_dev_user'`,
	).Scan(&meta); err != nil {
		t.Fatalf("aggregate metadata: %v", err)
	}
	// Anti-leak canary: the literal password must not appear in
	// audit metadata even if some future refactor adds a `password`
	// metadata key by accident.
	if strings.Contains(meta, "p1") {
		t.Fatal("audit metadata contained the seed password — must not be logged")
	}

	for _, want := range []string{"admin", "approver", "developer"} {
		if !strings.Contains(meta, want) {
			t.Fatalf("expected metadata to contain role %q; got %s", want, meta)
		}
	}
}

// API-S-25: once a lock expires, one guess is allowed and a wrong one
// re-locks straight away (the counter is still over the threshold).
func TestLogin_ExpiredLockoutAllowsOneGuessThenRelocks(t *testing.T) {
	svc, pool := bootstrapAuth(t)
	svc = svc.WithLockoutPolicy(services.LockoutPolicy{Threshold: 3, Duration: time.Hour})
	ctx := t.Context()

	repo := storage.NewLocalUsers(pool)
	user := mustCreateUser(t, repo, "frank@example.com", "pw-f")
	for i := 0; i < 3; i++ {
		_, _ = svc.Login(ctx, "frank@example.com", []byte("nope"), noSession)
	}
	if err := repo.Lock(ctx, user.ID, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatalf("Lock backdate: %v", err)
	}

	if _, err := svc.Login(ctx, "frank@example.com", []byte("still-wrong"), noSession); err == nil {
		t.Fatal("wrong password after expiry: expected ErrInvalidCredentials")
	}
	got, err := repo.Get(ctx, user.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.FailedLoginCount != 4 || got.LockedUntil == nil || !got.LockedUntil.After(time.Now()) {
		t.Fatalf("count=%d locked_until=%v, want 4 and a fresh lock", got.FailedLoginCount, got.LockedUntil)
	}
	if _, err := svc.Login(ctx, "frank@example.com", []byte("pw-f"), noSession); err == nil {
		t.Fatal("correct password right after re-lock: expected ErrInvalidCredentials")
	}
}
