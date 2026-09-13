package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/pkg/storage"
)

// API-04: the project-secret binding WRITE surface (Bind/Update/Unbind)
// must require a scoped integration.bind covering the project. It was
// previously reachable by any authenticated user, which let an attacker
// bind arbitrary catalog secrets to a project — the exact table the
// tenancy gate and reveal allowlists read. DB-backed: SKIP without
// TEST_DATABASE_URL.
type bindAuthzFixture struct {
	app          *fiber.App
	project      uuid.UUID
	otherProject uuid.UUID
	secretID     uuid.UUID
	binder       uuid.UUID // integration.bind scoped to `project`
	otherBinder  uuid.UUID // integration.bind scoped to `otherProject`
	noPerm       uuid.UUID // policy.author only
}

func bootstrapBindAuthz(t *testing.T) *bindAuthzFixture {
	t.Helper()
	enableHeaderIdentityForTest(t)
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
		DELETE FROM reveal_sessions;
		DELETE FROM secret_wraps;
		DELETE FROM approvals;
		DELETE FROM sync_jobs;
		DELETE FROM access_requests;
		DELETE FROM project_secrets;
		DELETE FROM secrets;
		DELETE FROM team_members;
		DELETE FROM teams;
		DELETE FROM user_roles;
		DELETE FROM roles WHERE is_system = false;
		DELETE FROM environments;
		DELETE FROM projects;
		DELETE FROM local_users;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}

	fx := &bindAuthzFixture{project: uuid.New(), otherProject: uuid.New()}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1,'bind-proj'),($2,'other-proj')`,
		fx.project, fx.otherProject); err != nil {
		t.Fatalf("seed projects: %v", err)
	}

	secretsRepo := storage.NewSecrets(pool)
	sec := &storage.Secret{ClusterName: "bind-cluster", ProviderType: "vault", SecretRef: "bind/uat/db", Status: "present"}
	if err := secretsRepo.Upsert(ctx, sec); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	fx.secretID = sec.ID

	fx.binder = seedUserWithGrant(t, pool, "binder",
		`["integration.bind"]`, `{"project_id":"`+fx.project.String()+`"}`)
	fx.otherBinder = seedUserWithGrant(t, pool, "other-binder",
		`["integration.bind"]`, `{"project_id":"`+fx.otherProject.String()+`"}`)
	fx.noPerm = seedUserWithGrant(t, pool, "bind-no-perm", `["policy.author"]`, "{}")

	projectRepo := storage.NewProjects(pool)
	envRepo := storage.NewEnvironments(pool)
	bindings := storage.NewProjectSecrets(pool)
	resolver := auth.NewRepoResolver(storage.NewUserRoles(pool), storage.NewRoles(pool))
	tsr := auth.NewRepoTeamScopeResolver(storage.NewTeams(pool), projectRepo)

	psH := handlers.NewProjectSecrets(bindings, projectRepo, secretsRepo, envRepo).WithScope(resolver, tsr)

	app := fiber.New()
	app.Use(middleware.Auth(nil))
	app.Post("/api/v1/projects/:id/secrets", psH.Bind)
	app.Delete("/api/v1/projects/:id/secrets/:secret_id", psH.Unbind)
	fx.app = app
	return fx
}

func (fx *bindAuthzFixture) bind(t *testing.T, projectID, userID uuid.UUID) (int, string) {
	t.Helper()
	body := `{"secret_id":"` + fx.secretID.String() + `","allowed_ops":["read"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/"+projectID.String()+"/secrets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Id", userID.String())
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestBindWrite_RequiresScopedIntegrationBind(t *testing.T) {
	fx := bootstrapBindAuthz(t)

	// A user without integration.bind is refused.
	if st, body := fx.bind(t, fx.project, fx.noPerm); st != http.StatusForbidden {
		t.Fatalf("no-perm bind = %d body=%s; want 403", st, body)
	}

	// A binder scoped to a DIFFERENT project cannot bind on this project.
	if st, body := fx.bind(t, fx.project, fx.otherBinder); st != http.StatusForbidden {
		t.Fatalf("out-of-scope binder = %d body=%s; want 403", st, body)
	}

	// A binder scoped to THIS project succeeds.
	if st, body := fx.bind(t, fx.project, fx.binder); st != http.StatusCreated {
		t.Fatalf("in-scope binder = %d body=%s; want 201", st, body)
	}
}
