package handlers_test

// Tests for the POST /auth/login branches that end without a session:
// 503 when no SessionService is wired and 500 when starting the session
// fails. Neither may be audited as a successful login. Requires
// TEST_DATABASE_URL; skips otherwise.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/bcrypt"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// failingSessions is a SessionRepository whose Create always fails, so
// SessionService.Issue fails after the credentials have been verified.
type failingSessions struct {
	storage.SessionRepository
}

func (failingSessions) Create(context.Context, *storage.Session) error {
	return errors.New("XXX-canary-session-store-down-XXX")
}

type loginFixture struct {
	t     *testing.T
	pool  *storage.Pool
	authS *services.AuthService
	audit storage.AuditEventRepository
}

func newLoginFixture(t *testing.T) *loginFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dsn, MaxConns: 4, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE TABLE audit_events, sessions, user_roles, local_users RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	audit := storage.NewAuditEvents(pool)
	authS := services.NewAuthService(storage.NewLocalUsers(pool), storage.NewRoles(pool), storage.NewUserRoles(pool), audit)
	return &loginFixture{t: t, pool: pool, authS: authS, audit: audit}
}

func (f *loginFixture) createUser(email, password string) *storage.LocalUser {
	f.t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		f.t.Fatalf("bcrypt: %v", err)
	}
	u := &storage.LocalUser{Email: email, PasswordHash: hash, DisplayName: "Test"}
	if err := storage.NewLocalUsers(f.pool).Create(f.t.Context(), u); err != nil {
		f.t.Fatalf("create user: %v", err)
	}
	return u
}

func (f *loginFixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(f.t.Context(), q, args...).Scan(&n); err != nil {
		f.t.Fatalf("count: %v", err)
	}
	return n
}

func (f *loginFixture) login(h *handlers.Auth, email, password string) (*http.Response, string) {
	f.t.Helper()
	app := fiber.New()
	app.Post("/api/v1/auth/login", h.Login)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		f.t.Fatalf("app.Test: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

func (f *loginFixture) assertNoSuccessAudit() {
	f.t.Helper()
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action IN ('auth.login', 'BREAK_GLASS_LOGIN') AND status = 'success'`); n != 0 {
		f.t.Fatalf("%d login success audit rows, want 0", n)
	}
}

func hasSessionCookie(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name == middleware.SessionCookieName && c.Value != "" {
			return true
		}
	}
	return false
}

func TestLogin_NoSessionServiceAnswers503(t *testing.T) {
	f := newLoginFixture(t)
	f.createUser("nora@example.com", "nora-pw")

	resp, body := f.login(handlers.NewAuth(f.authS), "nora@example.com", "nora-pw")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", resp.StatusCode, body)
	}
	if !strings.Contains(body, "sign-in is not available") {
		t.Fatalf("body = %s, want the generic 503 message", body)
	}
	if hasSessionCookie(resp) {
		t.Fatal("503 set a session cookie")
	}
	f.assertNoSuccessAudit()
	if n := f.count(`SELECT count(*) FROM sessions`); n != 0 {
		t.Fatalf("%d sessions, want 0", n)
	}
}

func TestLogin_SessionIssueFailureAnswers500AndAuditsFailure(t *testing.T) {
	f := newLoginFixture(t)
	user := f.createUser("omar@example.com", "omar-pw")

	sessions := services.NewSessionService(failingSessions{storage.NewSessions(f.pool)}, f.audit)
	h := handlers.NewAuth(f.authS).WithSessions(sessions, handlers.CookieModeDev)

	resp, body := f.login(h, "omar@example.com", "omar-pw")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %s)", resp.StatusCode, body)
	}
	if !strings.Contains(body, "could not start a session") || strings.Contains(body, "canary") {
		t.Fatalf("body = %s, want the generic 500 message and no error detail", body)
	}
	if hasSessionCookie(resp) {
		t.Fatal("500 set a session cookie")
	}
	f.assertNoSuccessAudit()
	if n := f.count(`SELECT count(*) FROM audit_events
		WHERE action = 'auth.login' AND status = 'failure' AND resource = $1
		  AND metadata->>'error_kind' = 'session_start_failed'`, "user:"+user.ID.String()); n != 1 {
		t.Fatalf("%d session_start_failed audit rows, want 1", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%canary%'`); n != 0 {
		t.Fatal("audit metadata carries the session store error text")
	}
}

// The same fixture with a working session store logs in, so the two
// tests above fail for the reason they name.
func TestLogin_WorkingSessionServiceSucceeds(t *testing.T) {
	f := newLoginFixture(t)
	f.createUser("pia@example.com", "pia-pw")

	sessions := services.NewSessionService(storage.NewSessions(f.pool), f.audit)
	h := handlers.NewAuth(f.authS).WithSessions(sessions, handlers.CookieModeDev)

	resp, body := f.login(h, "pia@example.com", "pia-pw")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, body)
	}
	if !hasSessionCookie(resp) {
		t.Fatal("200 without a session cookie")
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action = 'auth.login' AND status = 'success'`); n != 1 {
		t.Fatalf("%d auth.login success rows, want 1", n)
	}
	if n := f.count(`SELECT count(*) FROM sessions`); n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
}
