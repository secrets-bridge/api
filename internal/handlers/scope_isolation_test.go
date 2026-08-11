package handlers_test

import (
	"encoding/json"
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
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

// P0 read-path scope isolation (QA §3.6 + direct URL/API isolation).
//
// An authenticated user with NO project/team grants (only policy.author)
// must not be able to enumerate project-scoped metadata through the read
// endpoints. Lists return only in-scope rows (empty when the caller
// covers nothing); detail endpoints 404 an out-of-scope id so existence
// never leaks. A developer WITH project access still sees their project.

type scopeIsoFixture struct {
	app            *fiber.App
	billingProject uuid.UUID
	otherProject   uuid.UUID
	billingEnv     uuid.UUID
	billingSecret  uuid.UUID
	policyAuthor   uuid.UUID // permissions:[policy.author], projects:[]
	billingDev     uuid.UUID // secret.list+request scoped to billingProject
	billingDevReq  uuid.UUID // request owned by billingDev
	otherUserReq   uuid.UUID // request owned by someone else, in billingProject
}

func bootstrapScopeIso(t *testing.T) *scopeIsoFixture {
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
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;
		DELETE FROM environments;
		DELETE FROM projects;
		DELETE FROM local_users;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}

	fx := &scopeIsoFixture{}

	// --- projects + environments ---
	fx.billingProject = uuid.New()
	fx.otherProject = uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1,'billing'),($2,'other')`,
		fx.billingProject, fx.otherProject); err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	envRepo := storage.NewEnvironments(pool)
	billingEnv := &storage.Environment{ProjectID: fx.billingProject, Name: "uat", Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd}
	if err := envRepo.Create(ctx, billingEnv); err != nil {
		t.Fatalf("seed billing env: %v", err)
	}
	fx.billingEnv = billingEnv.ID
	otherEnv := &storage.Environment{ProjectID: fx.otherProject, Name: "uat", Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd}
	if err := envRepo.Create(ctx, otherEnv); err != nil {
		t.Fatalf("seed other env: %v", err)
	}

	// --- catalog secret bound to billing ---
	secretsRepo := storage.NewSecrets(pool)
	sec := &storage.Secret{ClusterName: "iso-cluster", ProviderType: "vault", SecretRef: "billing/uat/db", Status: "present"}
	if err := secretsRepo.Upsert(ctx, sec); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	fx.billingSecret = sec.ID
	bindings := storage.NewProjectSecrets(pool)
	if err := bindings.Bind(ctx, &storage.ProjectSecret{
		ProjectID: fx.billingProject, SecretID: sec.ID,
		AllowedOps: []string{storage.OpRead}, CreatedBy: "iso-test",
	}); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// --- users + role grants ---
	fx.policyAuthor = seedUserWithGrant(t, pool, "policy-author", `["policy.author"]`, "{}")
	fx.billingDev = seedUserWithGrant(t, pool, "billing-dev",
		`["secret.list","secret.request"]`,
		`{"project_id":"`+fx.billingProject.String()+`"}`)

	// --- requests (one per user, both in billing project) ---
	wfRepo := storage.NewWorkflows(pool)
	wf := &storage.WorkflowDefinition{
		Name: "iso-wf", MinApprovers: 1,
		WrapTTLCreated: time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: time.Hour, Enabled: true,
	}
	if err := wfRepo.Create(ctx, wf); err != nil {
		t.Fatalf("seed workflow: %v", err)
	}
	reqRepo := storage.NewAccessRequests(pool)
	fx.billingDevReq = seedReadRequest(t, reqRepo, fx.billingDev.String(), wf.ID, fx.billingProject)
	fx.otherUserReq = seedReadRequest(t, reqRepo, "someone-else", wf.ID, fx.billingProject)

	// --- handlers with scope wired (mirrors cmd/api/main.go) ---
	projectRepo := storage.NewProjects(pool)
	roles := storage.NewRoles(pool)
	userRoles := storage.NewUserRoles(pool)
	teams := storage.NewTeams(pool)
	auditRepo := storage.NewAuditEvents(pool)
	resolver := auth.NewRepoResolver(userRoles, roles)
	tsr := auth.NewRepoTeamScopeResolver(teams, projectRepo)

	tenancyH := handlers.NewTenancy(projectRepo, envRepo).WithScope(resolver, tsr)
	secretsSvc := services.NewSecretsService(secretsRepo, auditRepo)
	secretsH := handlers.NewSecrets(secretsSvc).WithProjectScoping(bindings, resolver).WithTeamScope(tsr)
	projectSecretsH := handlers.NewProjectSecrets(bindings, projectRepo, secretsRepo, envRepo).WithScope(resolver, tsr)

	km, err := keymgmt.NewLocalKMS(make([]byte, 32))
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	wrapSvc := services.NewWrapService(storage.NewSecretWraps(pool), auditRepo, km)
	policyEng := services.NewPolicyEngine(storage.NewPolicies(pool), wfRepo, auditRepo)
	reqSvc := services.NewRequestService(reqRepo, storage.NewApprovals(pool), wrapSvc, wfRepo, policyEng, auditRepo, nil)
	requestsH := handlers.NewRequests(reqSvc).WithTenancyGate(bindings, secretsRepo, resolver).WithTeamScope(tsr)

	app := fiber.New()
	app.Use(middleware.Auth(nil))
	app.Get("/api/v1/projects", tenancyH.ListProjects)
	app.Get("/api/v1/projects/:id/environments", tenancyH.ListEnvironmentsForProject)
	app.Get("/api/v1/projects/:id/secrets", projectSecretsH.List)
	app.Get("/api/v1/projects/:id", tenancyH.GetProject)
	app.Get("/api/v1/environments", tenancyH.ListEnvironments)
	app.Get("/api/v1/environments/:id", tenancyH.GetEnvironment)
	app.Get("/api/v1/secrets/:id", secretsH.Get)
	app.Get("/api/v1/requests", requestsH.List)
	app.Get("/api/v1/requests/:id", requestsH.Get)
	fx.app = app
	return fx
}

func seedUserWithGrant(t *testing.T, pool *storage.Pool, name, permsJSON, scopeJSON string) uuid.UUID {
	t.Helper()
	ctx := t.Context()
	uID := uuid.New()
	roleID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO roles (id, name, permissions, is_system) VALUES ($1,$2,$3::jsonb,false)`,
		roleID, name+"-role", permsJSON); err != nil {
		t.Fatalf("seed role %s: %v", name, err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (id, user_id, role_id, scope) VALUES ($1,$2,$3,$4::jsonb)`,
		uuid.New(), uID, roleID, scopeJSON); err != nil {
		t.Fatalf("seed user_role %s: %v", name, err)
	}
	return uID
}

func seedReadRequest(t *testing.T, repo *storage.AccessRequests, requester string, wfID, projectID uuid.UUID) uuid.UUID {
	t.Helper()
	req := &storage.AccessRequest{
		RequesterID:        requester,
		Type:               storage.AccessRequestTypeRead,
		Justification:      "iso seed",
		Status:             storage.AccessRequestStatusPending,
		WorkflowID:         &wfID,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetScope:        map[string]any{"project_id": projectID.String()},
	}
	if err := repo.Create(t.Context(), req); err != nil {
		t.Fatalf("seed request for %s: %v", requester, err)
	}
	return req.ID
}

// doGet issues an authenticated GET as userID and returns status + body.
func (fx *scopeIsoFixture) doGet(t *testing.T, path string, userID uuid.UUID) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-User-Id", userID.String())
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func jsonLen(t *testing.T, body string) int {
	t.Helper()
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(body), &arr); err != nil {
		t.Fatalf("decode array: %v (body=%s)", err, body)
	}
	return len(arr)
}

func TestScopeIsolation_UnscopedUserSeesNothing(t *testing.T) {
	fx := bootstrapScopeIso(t)
	pa := fx.policyAuthor

	// Case 1 — lists are empty for a user with no project grants.
	for _, path := range []string{"/api/v1/projects", "/api/v1/environments", "/api/v1/requests"} {
		st, body := fx.doGet(t, path, pa)
		if st != http.StatusOK {
			t.Fatalf("GET %s: status %d body=%s", path, st, body)
		}
		if n := jsonLen(t, body); n != 0 {
			t.Errorf("GET %s returned %d rows for an unscoped user; want 0 (leak: %s)", path, n, body)
		}
	}

	// Case 2 — GET billing project detail → 404 (existence hidden).
	if st, _ := fx.doGet(t, "/api/v1/projects/"+fx.billingProject.String(), pa); st != http.StatusNotFound {
		t.Errorf("GET billing project detail = %d; want 404", st)
	}
	// project environments under billing → 404.
	if st, _ := fx.doGet(t, "/api/v1/projects/"+fx.billingProject.String()+"/environments", pa); st != http.StatusNotFound {
		t.Errorf("GET billing project environments = %d; want 404", st)
	}
	// Case 3 — GET billing project secrets (bindings) → 404.
	if st, _ := fx.doGet(t, "/api/v1/projects/"+fx.billingProject.String()+"/secrets", pa); st != http.StatusNotFound {
		t.Errorf("GET billing project secrets = %d; want 404", st)
	}
	// Case 4 — GET secret detail → 404.
	if st, _ := fx.doGet(t, "/api/v1/secrets/"+fx.billingSecret.String(), pa); st != http.StatusNotFound {
		t.Errorf("GET billing secret detail = %d; want 404", st)
	}
	// billing environment detail → 404.
	if st, _ := fx.doGet(t, "/api/v1/environments/"+fx.billingEnv.String(), pa); st != http.StatusNotFound {
		t.Errorf("GET billing environment detail = %d; want 404", st)
	}
	// Case 6 — GET another user's request detail → 404.
	if st, _ := fx.doGet(t, "/api/v1/requests/"+fx.otherUserReq.String(), pa); st != http.StatusNotFound {
		t.Errorf("GET other user's request detail = %d; want 404", st)
	}
}

func TestScopeIsolation_UnscopedUserCannotListOthersRequests(t *testing.T) {
	fx := bootstrapScopeIso(t)
	// Case 5 — even with an explicit requester_id filter for another
	// user, the list is forced to the caller's own (none).
	st, body := fx.doGet(t, "/api/v1/requests?requester_id=someone-else", fx.policyAuthor)
	if st != http.StatusOK {
		t.Fatalf("status %d body=%s", st, body)
	}
	if n := jsonLen(t, body); n != 0 {
		t.Errorf("unscoped user listed %d of another user's requests; want 0 (leak: %s)", n, body)
	}
}

func TestScopeIsolation_ScopedDeveloperSeesTheirProject(t *testing.T) {
	fx := bootstrapScopeIso(t)
	dev := fx.billingDev

	// Case 7 — a developer WITH billing access still sees billing data.
	st, body := fx.doGet(t, "/api/v1/projects", dev)
	if st != http.StatusOK {
		t.Fatalf("projects: status %d body=%s", st, body)
	}
	if n := jsonLen(t, body); n != 1 {
		t.Errorf("billing-dev project list = %d rows; want exactly 1 (billing)", n)
	}
	if st, _ := fx.doGet(t, "/api/v1/projects/"+fx.billingProject.String(), dev); st != http.StatusOK {
		t.Errorf("billing-dev GET billing project = %d; want 200", st)
	}
	if st, _ := fx.doGet(t, "/api/v1/projects/"+fx.otherProject.String(), dev); st != http.StatusNotFound {
		t.Errorf("billing-dev GET other project = %d; want 404 (out of scope)", st)
	}
	if st, _ := fx.doGet(t, "/api/v1/secrets/"+fx.billingSecret.String(), dev); st != http.StatusOK {
		t.Errorf("billing-dev GET billing secret = %d; want 200", st)
	}
	if st, _ := fx.doGet(t, "/api/v1/projects/"+fx.billingProject.String()+"/secrets", dev); st != http.StatusOK {
		t.Errorf("billing-dev GET billing project secrets = %d; want 200", st)
	}
	// The developer sees their OWN request in a list.
	st, body = fx.doGet(t, "/api/v1/requests", dev)
	if st != http.StatusOK {
		t.Fatalf("requests: status %d body=%s", st, body)
	}
	if n := jsonLen(t, body); n != 1 {
		t.Errorf("billing-dev own-request list = %d rows; want exactly 1", n)
	}
	if st, _ := fx.doGet(t, "/api/v1/requests/"+fx.billingDevReq.String(), dev); st != http.StatusOK {
		t.Errorf("billing-dev GET own request = %d; want 200", st)
	}
}
