package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/pkg/storage"
)

// bootstrapMe stands up a fresh pool + the bare repos GetMe needs and
// returns a Fiber app with the route mounted under /api/v1.
func bootstrapMe(t *testing.T) (*fiber.App, *storage.Pool) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 4, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	const wipe = `
		DELETE FROM approvals;
		DELETE FROM access_requests;
		DELETE FROM team_members;
		DELETE FROM teams;
		DELETE FROM user_roles;
		DELETE FROM roles WHERE is_system = false;
		DELETE FROM projects;
		DELETE FROM local_users;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}

	users := storage.NewLocalUsers(pool)
	teams := storage.NewTeams(pool)
	projects := storage.NewProjects(pool)
	roles := storage.NewRoles(pool)
	userRoles := storage.NewUserRoles(pool)

	resolver := auth.NewRepoResolver(userRoles, roles)
	tsr := auth.NewRepoTeamScopeResolver(teams, projects)

	meH := handlers.NewMe(projects, resolver).
		WithTeamScope(tsr).
		WithIdentity(users, teams)

	app := fiber.New()
	app.Use(middleware.Auth(nil)) // legacy X-User-Id path
	app.Get("/api/v1/users/me", meH.GetMe)
	return app, pool
}

func TestGetMe_HappyPath(t *testing.T) {
	app, pool := bootstrapMe(t)
	ctx := t.Context()

	// Seed an admin user + role with secret.list + secret.request.
	uID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO local_users (id, email, password_hash, display_name)
		 VALUES ($1, $2, '\x00', $3)`,
		uID, "alice@example.com", "Alice",
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	roleID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO roles (id, name, permissions, is_system)
		 VALUES ($1, $2, '["secret.list","secret.request"]'::jsonb, false)`,
		roleID, "alpha-developer",
	); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (id, user_id, role_id, scope)
		 VALUES ($1, $2, $3, '{}'::jsonb)`,
		uuid.New(), uID, roleID,
	); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}

	// Seed a team the user belongs to.
	tID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO teams (id, name) VALUES ($1, $2)`,
		tID, "alpha",
	); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO team_members (team_id, user_id) VALUES ($1, $2)`,
		tID, uID,
	); err != nil {
		t.Fatalf("seed team_members: %v", err)
	}

	// Seed a project (global grant means the user sees every project).
	pID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO projects (id, name) VALUES ($1, $2)`,
		pID, "Billing",
	); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("X-User-Id", uID.String())
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	defer func() { _ = resp.Body.Close() }()

	var got handlers.MeResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.ID != uID.String() {
		t.Errorf("ID got %q want %q", got.ID, uID.String())
	}
	if got.Email != "alice@example.com" {
		t.Errorf("Email got %q", got.Email)
	}
	if got.DisplayName != "Alice" {
		t.Errorf("DisplayName got %q", got.DisplayName)
	}
	perms := map[string]bool{}
	for _, p := range got.Permissions {
		perms[p] = true
	}
	if !perms["secret.list"] || !perms["secret.request"] {
		t.Errorf("Permissions missing entries: %v", got.Permissions)
	}
	if len(got.Teams) != 1 || got.Teams[0].Name != "alpha" {
		t.Errorf("Teams unexpected: %+v", got.Teams)
	}
	if len(got.Projects) != 1 || got.Projects[0].ID != pID.String() {
		t.Errorf("Projects unexpected: %+v", got.Projects)
	}
	// MFA lookup wasn't wired in bootstrapMe → safe default `false`.
	if got.MFAEnrolled {
		t.Errorf("MFAEnrolled default got true, want false (no lookup wired)")
	}
}

// fakeMFAEnrollment satisfies handlers.MFAEnrollmentLookup so we can
// drive the mfa_enrolled boolean without booting the verify service.
type fakeMFAEnrollment struct {
	enrolled bool
	err      error
}

func (f fakeMFAEnrollment) AnyEnrolled(_ context.Context, _ uuid.UUID) (bool, error) {
	return f.enrolled, f.err
}

func TestGetMe_MFAEnrolled_RoundTrip(t *testing.T) {
	app, pool := bootstrapMe(t)
	ctx := t.Context()

	// Same seed as HappyPath, minus the role/project plumbing — we
	// only care about the MFA boolean here.
	uID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO local_users (id, email, password_hash, display_name)
		 VALUES ($1, $2, '\x00', $3)`,
		uID, "bob@example.com", "Bob",
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	cases := []struct {
		name string
		lk   fakeMFAEnrollment
		want bool
	}{
		{"enrolled", fakeMFAEnrollment{enrolled: true}, true},
		{"not enrolled", fakeMFAEnrollment{enrolled: false}, false},
		{"lookup errors → false", fakeMFAEnrollment{enrolled: true, err: errors.New("boom")}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Rebuild meH with the lookup attached for this case.
			users := storage.NewLocalUsers(pool)
			teams := storage.NewTeams(pool)
			projects := storage.NewProjects(pool)
			roles := storage.NewRoles(pool)
			userRoles := storage.NewUserRoles(pool)
			resolver := auth.NewRepoResolver(userRoles, roles)
			tsr := auth.NewRepoTeamScopeResolver(teams, projects)
			meH := handlers.NewMe(projects, resolver).
				WithTeamScope(tsr).
				WithIdentity(users, teams).
				WithMFAEnrollment(c.lk)
			caseApp := fiber.New()
			caseApp.Use(middleware.Auth(nil))
			caseApp.Get("/api/v1/users/me", meH.GetMe)

			req := httptest.NewRequest("GET", "/api/v1/users/me", nil)
			req.Header.Set("X-User-Id", uID.String())
			resp, err := caseApp.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			if resp.StatusCode != 200 {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			var got handlers.MeResponse
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.MFAEnrolled != c.want {
				t.Errorf("MFAEnrolled got %v want %v", got.MFAEnrolled, c.want)
			}
		})
	}
	_ = app // silence the bootstrap return — the per-case apps are what we use
}

func TestGetMe_NoUser_404(t *testing.T) {
	app, _ := bootstrapMe(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	// A UUID that doesn't match any local_users row.
	req.Header.Set("X-User-Id", uuid.New().String())
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 404, got %d: %s", resp.StatusCode, body)
	}
}

func TestGetMe_NonUUIDIdentity_422(t *testing.T) {
	app, _ := bootstrapMe(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("X-User-Id", "alice-the-string")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 422, got %d: %s", resp.StatusCode, body)
	}
}

func TestGetMe_NoAuth_401(t *testing.T) {
	app, _ := bootstrapMe(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	// No X-User-Id header → stub leaves actor as "anonymous" → 401
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d: %s", resp.StatusCode, body)
	}
}
