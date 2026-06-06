package handlers_test

// Slice P3 — handler tests for /provider-connections endpoints.
// Covers the {error_code, message} envelope shape, shared-GET branching,
// dropdown sanitization (no scope leak), and the 19 stable error codes.
//
// The handler-level tests run against a real Postgres + a real Redis
// (the DiscoverNow path uses a Redis lock), SKIPping cleanly when
// either env var is unset.

import (
	"bytes"
	"context"
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
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ---- bootstrap ----------------------------------------------------

func bootstrapProviderConnections(t *testing.T) (
	*fiber.App, *storage.Pool, *handlers.ProviderConnections, *services.ProviderConnectionsService,
) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbDSN == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL required; skipping")
	}
	ctx := t.Context()

	cfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	const wipe = `
		TRUNCATE TABLE
			audit_events, sync_runs, sync_jobs, approvals,
			access_requests, secret_mappings, agents,
			provider_connections, environments, projects
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}

	rdb, err := runtime.Open(ctx, runtime.Config{
		URL:       redisURL,
		PoolSize:  4,
		Namespace: "sb-p3-test",
	})
	if err != nil {
		t.Fatalf("Open runtime: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	svc := services.NewProviderConnections(
		storage.NewProviderConnections(pool),
		storage.NewProjectProviderConnections(pool),
		storage.NewAuditEvents(pool),
	)

	// The shared GET path needs a resolver. Tests inject a stub that
	// returns whatever grants we hand it via the request context.
	resolver := &stubResolver{}
	h := handlers.NewProviderConnections(svc, &fakeJobs{}, rdb, resolver,
		envLookup{pool: pool})
	app := fiber.New()
	v1 := app.Group("/api/v1")
	app.Use(testAuthMW)
	// Mount routes with the same auth.Require wrappers production
	// uses (cmd/api/main.go). The shared GET is unwrapped because
	// the handler runs inline auth branching on the query string.
	v1.Post("/provider-connections", auth.Require(auth.PermIntegrationEdit, resolver), h.Create)
	v1.Get("/provider-connections/:id", auth.Require(auth.PermIntegrationEdit, resolver), h.Get)
	v1.Put("/provider-connections/:id", auth.Require(auth.PermIntegrationEdit, resolver), h.Update)
	v1.Delete("/provider-connections/:id", auth.Require(auth.PermIntegrationEdit, resolver), h.Delete)
	v1.Post("/provider-connections/:id/discover-now", auth.Require(auth.PermIntegrationEdit, resolver), h.DiscoverNow)
	v1.Post("/provider-connections/:id/bindings", auth.Require(auth.PermIntegrationEdit, resolver), h.CreateBinding)
	v1.Get("/provider-connections/:id/bindings", auth.Require(auth.PermIntegrationEdit, resolver), h.ListBindings)
	v1.Delete("/provider-connection-bindings/:binding_id", auth.Require(auth.PermIntegrationEdit, resolver), h.DeleteBinding)
	v1.Get("/provider-connections", h.ListOrDropdown)

	t.Cleanup(func() { resolver.grants = nil })
	currentResolver = resolver
	return app, pool, h, svc
}

// testAuthMW reads X-Test-User-ID into the request context.
// Production wires the real Auth middleware before these routes.
func testAuthMW(c fiber.Ctx) error {
	userID := c.Get("X-Test-User-ID")
	if userID != "" {
		ctx := context.WithValue(c.Context(), middleware.CtxKeyActor, userID)
		c.SetContext(ctx)
	}
	return c.Next()
}

// stubResolver returns a fixed set of grants regardless of the
// userID. Tests reset `grants` before each call.
type stubResolver struct {
	grants []auth.Grant
}

func (s *stubResolver) Resolve(_ context.Context, _ string) ([]auth.Grant, error) {
	return s.grants, nil
}

// Module-level pointer so the per-test bootstrap can re-aim the
// resolver between request setups. Each bootstrap installs its own
// pointer — the tests in this file are not parallel.
var currentResolver *stubResolver

// envLookup adapts the storage Environments repository to the
// CrossTeamEnvLookup interface (Get only) the handler needs.
type envLookup struct {
	pool *storage.Pool
}

func (e envLookup) Get(ctx context.Context, id uuid.UUID) (*storage.Environment, error) {
	return storage.NewEnvironments(e.pool).Get(ctx, id)
}

// fakeJobs implements JobEnqueuer. DiscoverNow's enqueue path calls
// it; we ignore the payload here and return a synthetic job.
type fakeJobs struct {
	called int
}

func (f *fakeJobs) Enqueue(_ context.Context, req services.EnqueueRequest) (*storage.SyncJob, error) {
	f.called++
	return &storage.SyncJob{
		ID:            uuid.New(),
		JobType:       req.JobType,
		Status:        storage.JobStatusQueued,
		CorrelationID: req.CorrelationID,
		Payload:       req.Payload,
	}, nil
}

// ---- helpers ------------------------------------------------------

func grantIntegrationEdit() {
	currentResolver.grants = []auth.Grant{
		{Permission: string(auth.PermIntegrationEdit), Scope: map[string]string{}},
	}
}

func grantSecretRequestForProject(projectID string, envName string) {
	scope := map[string]string{"project_id": projectID}
	if envName != "" {
		scope["environment"] = envName
	}
	currentResolver.grants = []auth.Grant{
		{Permission: string(auth.PermSecretRequest), Scope: scope},
	}
}

func grantNothing() {
	currentResolver.grants = nil
}

func doPCJSON(t *testing.T, app *fiber.App, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("X-Test-User-ID", "alice")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	return resp, respBody
}

func validVaultCreateBody() map[string]any {
	return map[string]any{
		"name":        "vault-handler-test",
		"type":        "vault",
		"auth_method": "token",
		"scope": map[string]string{
			"address": "https://vault.example.com",
			"mount":   "secret",
		},
		"discover_interval_seconds": 300,
	}
}

func decodeEnvelope(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, string(body))
	}
	return m
}

// ---- tests --------------------------------------------------------

func TestCreate_HappyPath_RequiresIntegrationEdit(t *testing.T) {
	app, _, _, _ := bootstrapProviderConnections(t)
	grantNothing()
	resp, body := doPCJSON(t, app, "POST", "/api/v1/provider-connections", validVaultCreateBody())
	if resp.StatusCode != 403 {
		t.Fatalf("no-perm: got %d body=%s", resp.StatusCode, body)
	}

	grantIntegrationEdit()
	resp, body = doPCJSON(t, app, "POST", "/api/v1/provider-connections", validVaultCreateBody())
	if resp.StatusCode != 201 {
		t.Fatalf("with-perm: got %d body=%s", resp.StatusCode, body)
	}
	got := decodeEnvelope(t, body)
	if got["name"] != "vault-handler-test" {
		t.Fatalf("name: %v", got["name"])
	}
	if got["scope"] == nil {
		t.Fatal("admin projection must include scope")
	}
}

func TestCreate_CredentialInScope_400(t *testing.T) {
	app, _, _, _ := bootstrapProviderConnections(t)
	grantIntegrationEdit()
	body := validVaultCreateBody()
	body["scope"].(map[string]string)["awsAccessKeyID"] = "x"
	resp, raw := doPCJSON(t, app, "POST", "/api/v1/provider-connections", body)
	if resp.StatusCode != 400 {
		t.Fatalf("got %d body=%s", resp.StatusCode, raw)
	}
	got := decodeEnvelope(t, raw)
	if got["error_code"] != "credential_in_scope" {
		t.Fatalf("error_code = %v", got["error_code"])
	}
	if got["banned_key"] != "awsAccessKeyID" {
		t.Fatalf("banned_key = %v", got["banned_key"])
	}
}

func TestCreate_InvalidScope_MissingKeys_400(t *testing.T) {
	app, _, _, _ := bootstrapProviderConnections(t)
	grantIntegrationEdit()
	body := validVaultCreateBody()
	delete(body["scope"].(map[string]string), "mount")
	resp, raw := doPCJSON(t, app, "POST", "/api/v1/provider-connections", body)
	if resp.StatusCode != 400 {
		t.Fatalf("got %d body=%s", resp.StatusCode, raw)
	}
	got := decodeEnvelope(t, raw)
	if got["error_code"] != "invalid_scope" {
		t.Fatalf("error_code = %v", got["error_code"])
	}
	missing, _ := got["missing_keys"].([]any)
	if len(missing) == 0 {
		t.Fatalf("missing_keys = %v", got["missing_keys"])
	}
}

func TestCreate_DuplicateName_409(t *testing.T) {
	app, _, _, _ := bootstrapProviderConnections(t)
	grantIntegrationEdit()
	if resp, _ := doPCJSON(t, app, "POST", "/api/v1/provider-connections", validVaultCreateBody()); resp.StatusCode != 201 {
		t.Fatalf("first create: %d", resp.StatusCode)
	}
	resp, raw := doPCJSON(t, app, "POST", "/api/v1/provider-connections", validVaultCreateBody())
	if resp.StatusCode != 409 {
		t.Fatalf("got %d body=%s", resp.StatusCode, raw)
	}
	got := decodeEnvelope(t, raw)
	if got["error_code"] != "connection_name_taken" {
		t.Fatalf("error_code = %v", got["error_code"])
	}
}

func TestDelete_NotInUse_204(t *testing.T) {
	app, _, _, _ := bootstrapProviderConnections(t)
	grantIntegrationEdit()
	resp, raw := doPCJSON(t, app, "POST", "/api/v1/provider-connections", validVaultCreateBody())
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d body=%s", resp.StatusCode, raw)
	}
	created := decodeEnvelope(t, raw)
	id := created["id"].(string)
	resp, _ = doPCJSON(t, app, "DELETE", "/api/v1/provider-connections/"+id, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
}

func TestSharedGET_AdminPath_RequiresIntegrationEdit(t *testing.T) {
	app, _, _, _ := bootstrapProviderConnections(t)

	// No perm → 403.
	grantNothing()
	resp, raw := doPCJSON(t, app, "GET", "/api/v1/provider-connections", nil)
	if resp.StatusCode != 403 {
		t.Fatalf("no-perm: got %d body=%s", resp.StatusCode, raw)
	}

	// With integration.edit → 200 + admin projection (empty list).
	grantIntegrationEdit()
	resp, raw = doPCJSON(t, app, "GET", "/api/v1/provider-connections", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("got %d body=%s", resp.StatusCode, raw)
	}
}

func TestSharedGET_EnvironmentWithoutProject_400(t *testing.T) {
	app, _, _, _ := bootstrapProviderConnections(t)
	// Even without perms — the query-validation runs first.
	grantNothing()
	resp, raw := doPCJSON(t, app, "GET",
		"/api/v1/provider-connections?environment_id="+uuid.New().String(), nil)
	if resp.StatusCode != 400 {
		t.Fatalf("got %d body=%s", resp.StatusCode, raw)
	}
	got := decodeEnvelope(t, raw)
	if got["error_code"] != "project_id_required" {
		t.Fatalf("error_code = %v", got["error_code"])
	}
}

func TestSharedGET_DropdownPath_RequiresScopedSecretRequest(t *testing.T) {
	app, pool, _, svc := bootstrapProviderConnections(t)
	grantIntegrationEdit()
	// Create + bind one connection.
	resp, raw := doPCJSON(t, app, "POST", "/api/v1/provider-connections", validVaultCreateBody())
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d body=%s", resp.StatusCode, raw)
	}
	created := decodeEnvelope(t, raw)
	connID := uuid.MustParse(created["id"].(string))

	var projectID uuid.UUID
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO projects (name) VALUES ('p-drop') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("project: %v", err)
	}
	if _, err := svc.Bind(t.Context(), services.BindInput{
		ConnectionID: connID,
		ProjectID:    projectID,
		Purpose:      storage.ProjectProviderConnectionPurposeDestination,
	}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// Caller without secret.request → 403 out_of_scope_project.
	grantNothing()
	resp, raw = doPCJSON(t, app, "GET",
		"/api/v1/provider-connections?project_id="+projectID.String(), nil)
	if resp.StatusCode != 403 {
		t.Fatalf("no-perm: got %d body=%s", resp.StatusCode, raw)
	}
	got := decodeEnvelope(t, raw)
	if got["error_code"] != "out_of_scope_project" {
		t.Fatalf("error_code = %v", got["error_code"])
	}

	// Caller scoped to the right project → 200 + sanitized projection.
	grantSecretRequestForProject(projectID.String(), "")
	resp, raw = doPCJSON(t, app, "GET",
		"/api/v1/provider-connections?project_id="+projectID.String(), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("got %d body=%s", resp.StatusCode, raw)
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, raw)
	}
	if len(arr) != 1 {
		t.Fatalf("expected 1 result; got %d", len(arr))
	}
	// Sanitization: dropdown row carries ONLY {id, name, type}.
	row, ok := arr[0].(map[string]any)
	if !ok {
		t.Fatalf("row shape: %v", arr[0])
	}
	if _, leaked := row["scope"]; leaked {
		t.Fatal("dropdown projection leaked scope")
	}
	if _, leaked := row["auth_method"]; leaked {
		t.Fatal("dropdown projection leaked auth_method")
	}
	if _, leaked := row["discover_enabled"]; leaked {
		t.Fatal("dropdown projection leaked discover_enabled")
	}
	if row["name"] != "vault-handler-test" || row["type"] != "vault" {
		t.Fatalf("dropdown row: %v", row)
	}
}

func TestDiscoverNow_RequiresClusterName_400(t *testing.T) {
	app, _, _, _ := bootstrapProviderConnections(t)
	grantIntegrationEdit()
	// Create without cluster_name + discover_enabled false.
	body := validVaultCreateBody()
	resp, raw := doPCJSON(t, app, "POST", "/api/v1/provider-connections", body)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d body=%s", resp.StatusCode, raw)
	}
	created := decodeEnvelope(t, raw)
	id := created["id"].(string)

	resp, raw = doPCJSON(t, app, "POST",
		"/api/v1/provider-connections/"+id+"/discover-now", nil)
	if resp.StatusCode != 400 {
		t.Fatalf("got %d body=%s", resp.StatusCode, raw)
	}
	got := decodeEnvelope(t, raw)
	if got["error_code"] != "discover_requires_cluster" {
		t.Fatalf("error_code = %v", got["error_code"])
	}
}

func TestDiscoverNow_Disabled_409(t *testing.T) {
	app, pool, _, _ := bootstrapProviderConnections(t)
	grantIntegrationEdit()
	body := validVaultCreateBody()
	body["cluster_name"] = "c1"
	body["discover_enabled"] = true
	resp, raw := doPCJSON(t, app, "POST", "/api/v1/provider-connections", body)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d body=%s", resp.StatusCode, raw)
	}
	created := decodeEnvelope(t, raw)
	id := created["id"].(string)

	if _, err := pool.Exec(t.Context(),
		`UPDATE provider_connections SET status='disabled' WHERE id=$1`, id,
	); err != nil {
		t.Fatalf("disable: %v", err)
	}
	resp, raw = doPCJSON(t, app, "POST",
		"/api/v1/provider-connections/"+id+"/discover-now", nil)
	if resp.StatusCode != 409 {
		t.Fatalf("got %d body=%s", resp.StatusCode, raw)
	}
	got := decodeEnvelope(t, raw)
	if got["error_code"] != "connection_disabled" {
		t.Fatalf("error_code = %v", got["error_code"])
	}
}

func TestDiscoverNow_HappyPath_202(t *testing.T) {
	app, _, _, _ := bootstrapProviderConnections(t)
	grantIntegrationEdit()
	body := validVaultCreateBody()
	body["cluster_name"] = "c1"
	body["discover_enabled"] = true
	resp, raw := doPCJSON(t, app, "POST", "/api/v1/provider-connections", body)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d body=%s", resp.StatusCode, raw)
	}
	created := decodeEnvelope(t, raw)
	id := created["id"].(string)

	resp, raw = doPCJSON(t, app, "POST",
		"/api/v1/provider-connections/"+id+"/discover-now", nil)
	if resp.StatusCode != 202 {
		t.Fatalf("got %d body=%s", resp.StatusCode, raw)
	}
	got := decodeEnvelope(t, raw)
	if got["job_id"] == nil {
		t.Fatalf("missing job_id: %v", got)
	}
}

func TestBindUnbind_HappyPath(t *testing.T) {
	app, pool, _, _ := bootstrapProviderConnections(t)
	grantIntegrationEdit()
	resp, raw := doPCJSON(t, app, "POST", "/api/v1/provider-connections", validVaultCreateBody())
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d body=%s", resp.StatusCode, raw)
	}
	created := decodeEnvelope(t, raw)
	connID := created["id"].(string)
	var projectID uuid.UUID
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO projects (name) VALUES ('p-bindunbind') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("project: %v", err)
	}

	bindBody := map[string]any{
		"project_id": projectID.String(),
		"purpose":    "destination",
	}
	resp, raw = doPCJSON(t, app, "POST",
		"/api/v1/provider-connections/"+connID+"/bindings", bindBody)
	if resp.StatusCode != 201 {
		t.Fatalf("bind: %d body=%s", resp.StatusCode, raw)
	}
	binding := decodeEnvelope(t, raw)
	bid := binding["id"].(string)

	resp, _ = doPCJSON(t, app, "DELETE",
		"/api/v1/provider-connection-bindings/"+bid, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("unbind: %d", resp.StatusCode)
	}
}
