package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// loginAuditRows counts the auth.login and BREAK_GLASS_LOGIN rows for
// one user, by status.
type loginAuditRows struct {
	success, breakGlass, denied int
	deniedKinds                 []string
}

func loginTestPool(t *testing.T) (*storage.Pool, storage.Config) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	cfg := storage.Config{DSN: dsn, MaxConns: 4, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(t.Context(), cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, cfg
}

func loginTestUser(t *testing.T, pool *storage.Pool, password string) *storage.LocalUser {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	u := &storage.LocalUser{Email: "login-" + uuid.NewString()[:8] + "@example.com", PasswordHash: hash, DisplayName: "Login Test"}
	if err := storage.NewLocalUsers(pool).Create(t.Context(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func loginAudit(t *testing.T, pool *storage.Pool, userID uuid.UUID) loginAuditRows {
	t.Helper()
	rows, err := pool.Query(t.Context(), `
		SELECT action, status, coalesce(metadata->>'error_kind', '')
		FROM audit_events WHERE resource = $1 AND action IN ('auth.login', 'BREAK_GLASS_LOGIN')`,
		"user:"+userID.String())
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out loginAuditRows
	for rows.Next() {
		var action, status, kind string
		if err := rows.Scan(&action, &status, &kind); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		switch {
		case action == "BREAK_GLASS_LOGIN":
			out.breakGlass++
		case status == string(storage.AuditStatusSuccess):
			out.success++
		default:
			out.denied++
			out.deniedKinds = append(out.deniedKinds, kind)
		}
	}
	return out
}

func postLogin(t *testing.T, app *fiber.App, email, password string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	return resp
}

func loginApp(authH *handlers.Auth) *fiber.App {
	app := fiber.New()
	app.Post("/api/v1/auth/login", authH.Login)
	return app
}

// api#277: a correct password is audited as a successful login only
// once the session exists. Before, Login wrote the success row first,
// so a login that ended in 500 or 503 still showed as a success.
func TestLogin_AuditsSuccessOnlyWithASession(t *testing.T) {
	pool, cfg := loginTestPool(t)
	audit := storage.NewAuditEvents(pool)
	authSvc := services.NewAuthService(storage.NewLocalUsers(pool), storage.NewRoles(pool), storage.NewUserRoles(pool), audit)

	t.Run("no session service: 503", func(t *testing.T) {
		u := loginTestUser(t, pool, "pw-503")
		resp := postLogin(t, loginApp(handlers.NewAuth(authSvc)), u.Email, "pw-503")
		if resp.StatusCode != fiber.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", resp.StatusCode)
		}
		if c := resp.Header.Get("Set-Cookie"); c != "" {
			t.Fatalf("a cookie was set: %q", c)
		}
		got := loginAudit(t, pool, u.ID)
		if got.success != 0 || got.breakGlass != 0 || got.denied != 1 || got.deniedKinds[0] != "session_unavailable" {
			t.Fatalf("audit = %+v, want only a denied session_unavailable row", got)
		}
	})

	t.Run("session start fails: 500", func(t *testing.T) {
		broken, err := storage.Open(t.Context(), cfg)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		broken.Close()
		sessions := services.NewSessionService(storage.NewSessions(broken), audit)
		u := loginTestUser(t, pool, "pw-500")
		resp := postLogin(t, loginApp(handlers.NewAuth(authSvc).WithSessions(sessions, handlers.CookieModeDev)), u.Email, "pw-500")
		if resp.StatusCode != fiber.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", resp.StatusCode)
		}
		if c := resp.Header.Get("Set-Cookie"); c != "" {
			t.Fatalf("a cookie was set: %q", c)
		}
		got := loginAudit(t, pool, u.ID)
		if got.success != 0 || got.breakGlass != 0 || got.denied != 1 || got.deniedKinds[0] != "session_failed" {
			t.Fatalf("audit = %+v, want only a denied session_failed row", got)
		}
	})

	t.Run("session starts: 200", func(t *testing.T) {
		sessions := services.NewSessionService(storage.NewSessions(pool), audit)
		u := loginTestUser(t, pool, "pw-200")
		resp := postLogin(t, loginApp(handlers.NewAuth(authSvc).WithSessions(sessions, handlers.CookieModeDev)), u.Email, "pw-200")
		if resp.StatusCode != fiber.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("Set-Cookie"), "sb_session=") {
			t.Fatalf("no session cookie: %q", resp.Header.Get("Set-Cookie"))
		}
		got := loginAudit(t, pool, u.ID)
		if got.success != 1 || got.breakGlass != 1 || got.denied != 0 {
			t.Fatalf("audit = %+v, want one success and one break-glass row", got)
		}
	})
}
