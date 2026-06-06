// EPIC Q (api#101) Slice Q2 handler tests — project-anchored scoped
// bind / unbind / list + the shared GET for_binding=true branch.
//
// Each test exercises one row of the locked matrix from §4 + asserts
// the {error_code, message, ...} envelope shape. Prometheus counter
// increments are read directly via prometheus.DefaultGatherer so the
// observability lock is pinned at test time.

package handlers_test

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
	"github.com/prometheus/client_golang/prometheus"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// scopedBindHarness owns the test app + DB + seed data the per-test
// cases reuse. The bootstrap parallels bootstrapProviderConnections
// but adds: WithBinderScope + WithEnvironments on the service, the
// project-anchored handler mounted at the same paths production uses,
// and stub resolver / team-scope wired through.
type scopedBindHarness struct {
	app          *fiber.App
	pool         *storage.Pool
	svc          *services.ProviderConnectionsService
	resolver     *stubResolver
	projectID    uuid.UUID
	nonProdEnvID uuid.UUID
	prodEnvID    uuid.UUID
	bindableID   uuid.UUID
	platformID   uuid.UUID
	disabledID   uuid.UUID
}

func bootstrapScopedBindings(t *testing.T) *scopedBindHarness {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
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
			project_provider_connections,
			provider_connections, environments, projects
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}

	// Seed: one project, one non_prod env, one prod env, three connections.
	var projectID, nonProdEnvID, prodEnvID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (name) VALUES ('p-scoped') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
			VALUES ($1, 'dev', 'dev', 'non_prod', 1) RETURNING id`,
		projectID,
	).Scan(&nonProdEnvID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
			VALUES ($1, 'prod', 'prod', 'prod', 4) RETURNING id`,
		projectID,
	).Scan(&prodEnvID); err != nil {
		t.Fatal(err)
	}

	repo := storage.NewProviderConnections(pool)
	envRepo := storage.NewEnvironments(pool)
	bindings := storage.NewProjectProviderConnections(pool)
	audit := storage.NewAuditEvents(pool)

	mustTrue := true
	bindable, err := repo.Create(ctx, storage.ProviderConnectionInput{
		Name:                    "vault-bindable",
		Type:                    storage.ProviderConnectionTypeVault,
		AuthMethod:              "token",
		Scope:                   map[string]string{"address": "https://vault.example.com", "kvMount": "secret"},
		Status:                  storage.ProviderConnectionStatusActive,
		DiscoverIntervalSeconds: 3600,
		SelfServiceBindable:     &mustTrue,
	})
	if err != nil {
		t.Fatal(err)
	}
	mustFalse := false
	platformOnly, err := repo.Create(ctx, storage.ProviderConnectionInput{
		Name:                    "vault-platform-only",
		Type:                    storage.ProviderConnectionTypeVault,
		AuthMethod:              "token",
		Scope:                   map[string]string{"address": "https://vault.example.com", "kvMount": "secret"},
		Status:                  storage.ProviderConnectionStatusActive,
		DiscoverIntervalSeconds: 3600,
		SelfServiceBindable:     &mustFalse,
	})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := repo.Create(ctx, storage.ProviderConnectionInput{
		Name:                    "vault-disabled",
		Type:                    storage.ProviderConnectionTypeVault,
		AuthMethod:              "token",
		Scope:                   map[string]string{"address": "https://vault.example.com", "kvMount": "secret"},
		Status:                  storage.ProviderConnectionStatusDisabled,
		DiscoverIntervalSeconds: 3600,
		SelfServiceBindable:     &mustTrue,
	})
	if err != nil {
		t.Fatal(err)
	}

	resolver := &stubResolver{}
	svc := services.NewProviderConnections(repo, bindings, audit).
		WithBinderScope(resolver, &stubTeamScopeHandler{}).
		WithEnvironments(envRepo)

	app := fiber.New()
	v1 := app.Group("/api/v1")
	app.Use(testAuthMW)

	pcbH := handlers.NewProjectProviderConnectionBindings(svc)
	v1.Post("/projects/:projectID/provider-connection-bindings", pcbH.Create)
	v1.Get("/projects/:projectID/provider-connection-bindings", pcbH.List)
	v1.Delete("/projects/:projectID/provider-connection-bindings/:bindingID", pcbH.Delete)

	// Also mount the shared GET via the EPIC P handler so the
	// for_binding=true branch tests have a path to hit.
	pcH := handlers.NewProviderConnections(svc, &fakeJobs{}, nil, resolver, envLookup{pool: pool})
	v1.Get("/provider-connections", pcH.ListOrDropdown)

	currentResolver = resolver
	return &scopedBindHarness{
		app:          app,
		pool:         pool,
		svc:          svc,
		resolver:     resolver,
		projectID:    projectID,
		nonProdEnvID: nonProdEnvID,
		prodEnvID:    prodEnvID,
		bindableID:   bindable.ID,
		platformID:   platformOnly.ID,
		disabledID:   disabled.ID,
	}
}

// stubTeamScopeHandler implements auth.TeamScopeResolver with empty
// maps. Tests in this file use project_id-scoped grants exclusively;
// the team scope path isn't exercised here.
type stubTeamScopeHandler struct{}

func (stubTeamScopeHandler) DescendantTeamIDs(_ context.Context, root uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (stubTeamScopeHandler) ProjectIDsForTeams(_ context.Context, _ []uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

func grantIntegrationBindForProject(projectID, envName string) {
	scope := map[string]string{"project_id": projectID}
	if envName != "" {
		scope["environment"] = envName
	}
	currentResolver.grants = []auth.Grant{
		{Permission: string(auth.PermIntegrationBind), Scope: scope},
	}
}

// ---- helpers --------------------------------------------------------

func doSBJSON(t *testing.T, app *fiber.App, method, path string, body any) (*http.Response, []byte) {
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
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp, respBody
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode: %v: %s", err, string(b))
	}
	return m
}

// counterValue reads the current value of a counter via the default
// gatherer. The test uses absolute deltas (post - pre) so other
// concurrent tests can't make the assertion flaky.
func counterValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			match := true
			for k, v := range labels {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == k && lp.GetValue() == v {
						found = true
						break
					}
				}
				if !found {
					match = false
					break
				}
			}
			if match && m.Counter != nil {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// ---- POST /projects/:id/provider-connection-bindings ---------------

func TestScopedBind_HappyPath_201_IncrementsCounter(t *testing.T) {
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "")

	pre := counterValue(t, "provider_connection_bindings_created_total",
		map[string]string{"permission_used": "integration.bind", "env_kind": "non_prod"})

	resp, body := doSBJSON(t, h.app, "POST",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings",
		map[string]any{
			"provider_connection_id": h.bindableID.String(),
			"environment_id":         h.nonProdEnvID.String(),
		})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	m := decode(t, body)
	if m["project_id"] != h.projectID.String() {
		t.Fatalf("project_id mismatch: %v", m["project_id"])
	}
	if m["provider_connection_id"] != h.bindableID.String() {
		t.Fatalf("connection_id mismatch: %v", m["provider_connection_id"])
	}
	post := counterValue(t, "provider_connection_bindings_created_total",
		map[string]string{"permission_used": "integration.bind", "env_kind": "non_prod"})
	if post-pre != 1 {
		t.Fatalf("counter delta = %v want 1", post-pre)
	}
}

func TestScopedBind_OutOfScope_403_IncrementsDeniedCounter(t *testing.T) {
	h := bootstrapScopedBindings(t)
	// Grant scoped to a DIFFERENT project — actor doesn't cover h.projectID.
	other := uuid.New()
	grantIntegrationBindForProject(other.String(), "")

	pre := counterValue(t, "provider_connection_bindings_denied_total",
		map[string]string{"reason": "out_of_scope"})

	resp, body := doSBJSON(t, h.app, "POST",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings",
		map[string]any{
			"provider_connection_id": h.bindableID.String(),
			"environment_id":         h.nonProdEnvID.String(),
		})
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	m := decode(t, body)
	if m["error_code"] != "out_of_scope_binding" {
		t.Fatalf("error_code = %v want out_of_scope_binding", m["error_code"])
	}
	post := counterValue(t, "provider_connection_bindings_denied_total",
		map[string]string{"reason": "out_of_scope"})
	if post-pre != 1 {
		t.Fatalf("denied counter delta = %v want 1", post-pre)
	}
}

func TestScopedBind_ProdEnv_403_PromsBlockedReason(t *testing.T) {
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "")
	pre := counterValue(t, "provider_connection_bindings_denied_total",
		map[string]string{"reason": "prod_blocked"})

	resp, body := doSBJSON(t, h.app, "POST",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings",
		map[string]any{
			"provider_connection_id": h.bindableID.String(),
			"environment_id":         h.prodEnvID.String(),
		})
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	m := decode(t, body)
	if m["error_code"] != "prod_binding_not_allowed_for_scope" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
	if m["env_kind"] != "prod" {
		t.Fatalf("env_kind extra missing: %v", m)
	}
	post := counterValue(t, "provider_connection_bindings_denied_total",
		map[string]string{"reason": "prod_blocked"})
	if post-pre != 1 {
		t.Fatalf("denied counter delta = %v want 1", post-pre)
	}
}

func TestScopedBind_MissingEnvironmentID_400(t *testing.T) {
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "")
	resp, body := doSBJSON(t, h.app, "POST",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings",
		map[string]any{
			"provider_connection_id": h.bindableID.String(),
		})
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	m := decode(t, body)
	if m["error_code"] != "environment_id_required" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

func TestScopedBind_NotSelfServiceBindable_403(t *testing.T) {
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "")
	resp, body := doSBJSON(t, h.app, "POST",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings",
		map[string]any{
			"provider_connection_id": h.platformID.String(),
			"environment_id":         h.nonProdEnvID.String(),
		})
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	m := decode(t, body)
	if m["error_code"] != "connection_not_self_service_bindable" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

func TestScopedBind_Disabled_409Code(t *testing.T) {
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "")
	resp, body := doSBJSON(t, h.app, "POST",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings",
		map[string]any{
			"provider_connection_id": h.disabledID.String(),
			"environment_id":         h.nonProdEnvID.String(),
		})
	if resp.StatusCode != fiber.StatusConflict {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	m := decode(t, body)
	if m["error_code"] != "connection_disabled" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

// ---- DELETE /projects/:id/provider-connection-bindings/:bid -------

func TestScopedDelete_HappyPath_204(t *testing.T) {
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "")
	// First create a binding.
	resp, body := doSBJSON(t, h.app, "POST",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings",
		map[string]any{
			"provider_connection_id": h.bindableID.String(),
			"environment_id":         h.nonProdEnvID.String(),
		})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("seed bind status=%d body=%s", resp.StatusCode, string(body))
	}
	bindingID := decode(t, body)["id"].(string)

	pre := counterValue(t, "provider_connection_bindings_deleted_total",
		map[string]string{"permission_used": "integration.bind", "env_kind": "non_prod"})

	resp, body = doSBJSON(t, h.app, "DELETE",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings/"+bindingID, nil)
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	post := counterValue(t, "provider_connection_bindings_deleted_total",
		map[string]string{"permission_used": "integration.bind", "env_kind": "non_prod"})
	if post-pre != 1 {
		t.Fatalf("delete counter delta = %v want 1", post-pre)
	}
}

func TestScopedDelete_ProjectMismatch_ReturnsBindingNotFound_NeverOutOfScope(t *testing.T) {
	// §4 correction pinned at handler layer: a scoped DELETE whose URL
	// projectID doesn't match the stored binding.project_id returns
	// binding_not_found (404), NEVER out_of_scope_binding (403).
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "")
	resp, body := doSBJSON(t, h.app, "POST",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings",
		map[string]any{
			"provider_connection_id": h.bindableID.String(),
			"environment_id":         h.nonProdEnvID.String(),
		})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("seed bind: %s", string(body))
	}
	bindingID := decode(t, body)["id"].(string)

	// Caller has coverage on a DIFFERENT project. Even though they're
	// covered for that other project, they hit the URL with that
	// other project's id — the binding belongs to h.projectID, so the
	// handler returns binding_not_found.
	other := uuid.New()
	grantIntegrationBindForProject(other.String(), "")
	resp, body = doSBJSON(t, h.app, "DELETE",
		"/api/v1/projects/"+other.String()+"/provider-connection-bindings/"+bindingID, nil)
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status = %d (want 404) body=%s", resp.StatusCode, string(body))
	}
	m := decode(t, body)
	if m["error_code"] != "binding_not_found" {
		t.Fatalf("error_code = %v want binding_not_found (NEVER out_of_scope_binding on mismatch)", m["error_code"])
	}
}

// ---- GET /projects/:id/provider-connection-bindings ----------------

func TestScopedList_HappyPath_ReturnsSanitizedJoin(t *testing.T) {
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "")
	// Seed a binding.
	resp, body := doSBJSON(t, h.app, "POST",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings",
		map[string]any{
			"provider_connection_id": h.bindableID.String(),
			"environment_id":         h.nonProdEnvID.String(),
		})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatal(string(body))
	}

	resp, body = doSBJSON(t, h.app, "GET",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings", nil)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d want 1", len(rows))
	}
	row := rows[0]
	if row["connection_name"] != "vault-bindable" || row["connection_type"] != "vault" {
		t.Fatalf("join missing: %+v", row)
	}
	if row["environment_kind"] != "non_prod" {
		t.Fatalf("environment_kind = %v", row["environment_kind"])
	}
	// Sanitization: scope / auth_method / discovery fields MUST NOT
	// appear in the response shape.
	for _, banned := range []string{"scope", "auth_method", "discover_enabled", "last_discover_status"} {
		if _, ok := row[banned]; ok {
			t.Fatalf("sanitized projection leaks field %q: %+v", banned, row)
		}
	}
}

// ---- Shared GET /provider-connections?for_binding=true matrix -----

func TestSharedGET_ForBinding_MissingEnvironmentID_400(t *testing.T) {
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "")
	resp, body := doSBJSON(t, h.app, "GET",
		"/api/v1/provider-connections?for_binding=true&project_id="+h.projectID.String(), nil)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	m := decode(t, body)
	if m["error_code"] != "environment_id_required" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

func TestSharedGET_ForBinding_NoProjectID_400_BeforeAuth(t *testing.T) {
	// for_binding=true without project_id must 400 BEFORE any auth
	// check — caller may be unauthenticated.
	h := bootstrapScopedBindings(t)
	grantNothing()
	resp, body := doSBJSON(t, h.app, "GET",
		"/api/v1/provider-connections?for_binding=true&environment_id="+h.nonProdEnvID.String(), nil)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	m := decode(t, body)
	if m["error_code"] != "project_id_required" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

func TestSharedGET_ForBinding_ProdEnv_403(t *testing.T) {
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "")
	resp, body := doSBJSON(t, h.app, "GET",
		"/api/v1/provider-connections?for_binding=true&project_id="+h.projectID.String()+"&environment_id="+h.prodEnvID.String(), nil)
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	m := decode(t, body)
	if m["error_code"] != "prod_binding_not_allowed_for_scope" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

func TestSharedGET_ForBinding_HappyPath_ReturnsSanitizedAndExcludesBound(t *testing.T) {
	h := bootstrapScopedBindings(t)
	grantIntegrationBindForProject(h.projectID.String(), "dev")

	resp, body := doSBJSON(t, h.app, "GET",
		"/api/v1/provider-connections?for_binding=true&project_id="+h.projectID.String()+"&environment_id="+h.nonProdEnvID.String(), nil)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatal(err)
	}
	// vault-bindable (self_service_bindable=true, active) appears.
	// vault-platform-only (self_service_bindable=false) excluded.
	// vault-disabled (status=disabled) excluded.
	if len(rows) != 1 {
		t.Fatalf("rows = %d want 1 (only the bindable+active conn): %+v", len(rows), rows)
	}
	if rows[0]["name"] != "vault-bindable" || rows[0]["type"] != "vault" {
		t.Fatalf("unexpected row: %+v", rows[0])
	}
	// Sanitization check — no scope / auth_method / discovery fields.
	for _, banned := range []string{"scope", "auth_method", "discover_enabled", "status"} {
		if _, ok := rows[0][banned]; ok {
			t.Fatalf("dropdown projection leaks %q: %+v", banned, rows[0])
		}
	}

	// Now bind it. The next picker call must exclude it (§5 Q13).
	resp, body = doSBJSON(t, h.app, "POST",
		"/api/v1/projects/"+h.projectID.String()+"/provider-connection-bindings",
		map[string]any{
			"provider_connection_id": h.bindableID.String(),
			"environment_id":         h.nonProdEnvID.String(),
		})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("seed bind: %s", string(body))
	}
	resp, body = doSBJSON(t, h.app, "GET",
		"/api/v1/provider-connections?for_binding=true&project_id="+h.projectID.String()+"&environment_id="+h.nonProdEnvID.String(), nil)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("post-bind status = %d body=%s", resp.StatusCode, string(body))
	}
	var rows2 []map[string]any
	if err := json.Unmarshal(body, &rows2); err != nil {
		t.Fatal(err)
	}
	if len(rows2) != 0 {
		t.Fatalf("expected zero rows after bind (picker excludes bound); got %+v", rows2)
	}
}

// Avoid unused-import noise when running -test.run on subsets.
var (
	_ = middleware.CtxKeyActor
	_ = http.StatusOK
)
