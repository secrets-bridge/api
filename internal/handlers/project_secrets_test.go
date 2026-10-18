// Handler tests for the project_secrets environment binding
// Before this slice `environment_id` existed on the table
// and on the storage struct, but no HTTP path could set it — so
// operators could not configure env-scoped project secrets through
// the product at all. These tests pin both write paths plus the
// cross-project guard.

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/pkg/storage"
)

type projectSecretsHarness struct {
	app        *fiber.App
	pool       *storage.Pool
	projectID  uuid.UUID
	otherProj  uuid.UUID
	envID      uuid.UUID // belongs to projectID
	devEnvID   uuid.UUID // second environment of projectID
	otherEnvID uuid.UUID // belongs to otherProj
	secretID   uuid.UUID
}

func bootstrapProjectSecretsHandler(t *testing.T) *projectSecretsHarness {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dsn, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	const wipe = `
		DELETE FROM project_secrets;
		DELETE FROM secrets;
		DELETE FROM environments;
		DELETE FROM projects;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}

	// These are the first tests in this package to leave a
	// project_secrets row carrying a non-null environment_id. Sibling
	// suites wipe `environments` without clearing project_secrets
	// first, so a leaked row would fail their teardown on
	// project_secrets_environment_id_fkey. Clean up after ourselves
	// rather than reordering nine unrelated wipes.
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM project_secrets`); err != nil {
			t.Logf("cleanup project_secrets: %v", err)
		}
	})

	h := &projectSecretsHarness{pool: pool}
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (name) VALUES ('ps-primary') RETURNING id`,
	).Scan(&h.projectID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (name) VALUES ('ps-other') RETURNING id`,
	).Scan(&h.otherProj); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
			VALUES ($1, 'uat', 'uat', 'non_prod', 1) RETURNING id`,
		h.projectID,
	).Scan(&h.envID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
			VALUES ($1, 'dev', 'dev', 'non_prod', 1) RETURNING id`,
		h.projectID,
	).Scan(&h.devEnvID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
			VALUES ($1, 'uat', 'uat', 'non_prod', 1) RETURNING id`,
		h.otherProj,
	).Scan(&h.otherEnvID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO secrets (cluster_name, provider_type, secret_ref, status, last_seen_at)
			VALUES ('eks-tenant-a-uat', 'aws-sm', '/secrets/uat/team-alpha/env', 'present', now())
			RETURNING id`,
	).Scan(&h.secretID); err != nil {
		t.Fatal(err)
	}

	handler := handlers.NewProjectSecrets(
		storage.NewProjectSecrets(pool),
		storage.NewProjects(pool),
		storage.NewSecrets(pool),
		storage.NewEnvironments(pool),
	).WithAudit(storage.NewAuditEvents(pool))
	dev := handlers.NewDevSecrets(
		storage.NewProjects(pool),
		storage.NewEnvironments(pool),
		storage.NewProjectSecrets(pool),
		storage.NewSecrets(pool),
		nil, // ListEnvSecrets does not use the request service
	)
	app := fiber.New()
	// Session identity for the audit actor; the body never supplies it.
	app.Use(func(c fiber.Ctx) error {
		c.SetContext(context.WithValue(c.Context(), middleware.CtxKeyActor, projectSecretsActor))
		return c.Next()
	})
	app.Get("/projects/:id/environments/:env_id/secrets", dev.ListEnvSecrets)
	app.Post("/projects/:id/secrets", handler.Bind)
	app.Get("/projects/:id/secrets", handler.List)
	app.Put("/projects/:id/secrets/:secret_id", handler.Update)
	h.app = app
	return h
}

const projectSecretsActor = "ps-admin"

func (h *projectSecretsHarness) do(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// storedEnvironmentID reads the column directly so the assertion does
// not depend on the response projection being correct.
func (h *projectSecretsHarness) storedEnvironmentID(t *testing.T) *uuid.UUID {
	t.Helper()
	var envID *uuid.UUID
	if err := h.pool.QueryRow(t.Context(),
		`SELECT environment_id FROM project_secrets WHERE project_id=$1 AND secret_id=$2`,
		h.projectID, h.secretID,
	).Scan(&envID); err != nil {
		t.Fatalf("read environment_id: %v", err)
	}
	return envID
}

func TestBindHandler_PersistsEnvironmentID(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)

	status, _ := h.do(t, http.MethodPost,
		fmt.Sprintf("/projects/%s/secrets", h.projectID),
		map[string]any{
			"secret_id":      h.secretID.String(),
			"environment_id": h.envID.String(),
			"allowed_ops":    []string{"read"},
		})
	if status != http.StatusCreated {
		t.Fatalf("status: got %d want 201", status)
	}

	got := h.storedEnvironmentID(t)
	if got == nil || *got != h.envID {
		t.Fatalf("environment_id: got %v want %v", got, h.envID)
	}
}

func TestBindHandler_RejectsCrossProjectEnvironment(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)

	// otherEnvID is a real environment — but it belongs to ps-other.
	status, _ := h.do(t, http.MethodPost,
		fmt.Sprintf("/projects/%s/secrets", h.projectID),
		map[string]any{
			"secret_id":      h.secretID.String(),
			"environment_id": h.otherEnvID.String(),
			"allowed_ops":    []string{"read"},
		})
	if status != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (cross-project environment must be refused)", status)
	}
}

func TestBindHandler_OmittedEnvironmentIDStaysNull(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)

	status, _ := h.do(t, http.MethodPost,
		fmt.Sprintf("/projects/%s/secrets", h.projectID),
		map[string]any{
			"secret_id":   h.secretID.String(),
			"allowed_ops": []string{"read"},
		})
	if status != http.StatusCreated {
		t.Fatalf("status: got %d want 201", status)
	}
	if got := h.storedEnvironmentID(t); got != nil {
		t.Fatalf("environment_id: got %v want nil (back-compat)", got)
	}
}

func TestUpdateHandler_AttachesEnvironmentID(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)

	// Bind first without an environment — the state every existing
	// row in UAT is currently in.
	if status, _ := h.do(t, http.MethodPost,
		fmt.Sprintf("/projects/%s/secrets", h.projectID),
		map[string]any{"secret_id": h.secretID.String(), "allowed_ops": []string{"read"}},
	); status != http.StatusCreated {
		t.Fatalf("seed bind status: got %d want 201", status)
	}

	status, _ := h.do(t, http.MethodPut,
		fmt.Sprintf("/projects/%s/secrets/%s", h.projectID, h.secretID),
		map[string]any{
			"environment_id": h.envID.String(),
			"allowed_keys":   []string{"APP_ENV", "DB_HOST"},
			"allowed_ops":    []string{"read"},
		})
	if status != http.StatusOK {
		t.Fatalf("status: got %d want 200", status)
	}

	got := h.storedEnvironmentID(t)
	if got == nil || *got != h.envID {
		t.Fatalf("environment_id: got %v want %v", got, h.envID)
	}
}

func TestUpdateHandler_RejectsCrossProjectEnvironment(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)

	if status, _ := h.do(t, http.MethodPost,
		fmt.Sprintf("/projects/%s/secrets", h.projectID),
		map[string]any{"secret_id": h.secretID.String(), "allowed_ops": []string{"read"}},
	); status != http.StatusCreated {
		t.Fatalf("seed bind status: got %d want 201", status)
	}

	status, _ := h.do(t, http.MethodPut,
		fmt.Sprintf("/projects/%s/secrets/%s", h.projectID, h.secretID),
		map[string]any{
			"environment_id": h.otherEnvID.String(),
			"allowed_ops":    []string{"read"},
		})
	if status != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (cross-project environment must be refused)", status)
	}
	if got := h.storedEnvironmentID(t); got != nil {
		t.Fatalf("refused update must not write: got %v want nil", got)
	}
}

func TestUpdateHandler_OmittedEnvironmentIDPreservesExisting(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)

	if status, _ := h.do(t, http.MethodPost,
		fmt.Sprintf("/projects/%s/secrets", h.projectID),
		map[string]any{
			"secret_id":      h.secretID.String(),
			"environment_id": h.envID.String(),
			"allowed_ops":    []string{"read"},
		},
	); status != http.StatusCreated {
		t.Fatalf("seed bind status: got %d want 201", status)
	}

	// An allowed_keys-only edit must not detach the environment.
	status, _ := h.do(t, http.MethodPut,
		fmt.Sprintf("/projects/%s/secrets/%s", h.projectID, h.secretID),
		map[string]any{
			"allowed_keys": []string{"APP_ENV"},
			"allowed_ops":  []string{"read"},
		})
	if status != http.StatusOK {
		t.Fatalf("status: got %d want 200", status)
	}

	got := h.storedEnvironmentID(t)
	if got == nil || *got != h.envID {
		t.Fatalf("environment was detached by an unrelated update: got %v want %v", got, h.envID)
	}
}

// QA P2 — an invalid allowed_ops value reached the schema CHECK and
// surfaced as a generic 500 "update failed". Persistence was correctly
// prevented, but the status and envelope were wrong: a client-supplied
// bad enum is a 400, not a server fault.
func TestUpdateHandler_InvalidAllowedOpsIs400(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)

	if status, _ := h.do(t, http.MethodPost,
		fmt.Sprintf("/projects/%s/secrets", h.projectID),
		map[string]any{"secret_id": h.secretID.String(), "allowed_ops": []string{"read"}},
	); status != http.StatusCreated {
		t.Fatalf("seed bind status: got %d want 201", status)
	}

	status, body := h.do(t, http.MethodPut,
		fmt.Sprintf("/projects/%s/secrets/%s", h.projectID, h.secretID),
		map[string]any{"allowed_ops": []string{"delete"}})
	if status != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%v)", status, body)
	}
}

func TestBindHandler_InvalidAllowedOpsIs400(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)

	status, body := h.do(t, http.MethodPost,
		fmt.Sprintf("/projects/%s/secrets", h.projectID),
		map[string]any{
			"secret_id":   h.secretID.String(),
			"allowed_ops": []string{"read", "destroy"},
		})
	if status != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%v)", status, body)
	}
}

// --- api#249: environment_id on update is tri-state -------------------

func (h *projectSecretsHarness) bindIn(t *testing.T, envID *uuid.UUID) {
	t.Helper()
	body := map[string]any{"secret_id": h.secretID.String(), "allowed_ops": []string{"read"}}
	if envID != nil {
		body["environment_id"] = envID.String()
	}
	if status, out := h.do(t, http.MethodPost, fmt.Sprintf("/projects/%s/secrets", h.projectID), body); status != http.StatusCreated {
		t.Fatalf("seed bind status: got %d want 201 (body=%v)", status, out)
	}
}

func (h *projectSecretsHarness) put(t *testing.T, body any) (int, map[string]any) {
	t.Helper()
	return h.do(t, http.MethodPut, fmt.Sprintf("/projects/%s/secrets/%s", h.projectID, h.secretID), body)
}

// The console's edit form sent only allowed_ops/allowed_keys. That
// must never move the binding out of its environment.
func TestUpdateHandler_OpsOnlyKeepsEnvironment(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)
	h.bindIn(t, &h.envID)

	status, body := h.put(t, map[string]any{"allowed_ops": []string{"read", "patch"}})
	if status != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%v)", status, body)
	}
	if got := h.storedEnvironmentID(t); got == nil || *got != h.envID {
		t.Fatalf("environment_id: got %v want %v (omitted field must keep the stored value)", got, h.envID)
	}
	if body["environment_id"] != h.envID.String() {
		t.Fatalf("response environment_id: got %v want %v", body["environment_id"], h.envID)
	}
}

func TestUpdateHandler_ExplicitNullClearsEnvironment(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)
	h.bindIn(t, &h.envID)

	status, body := h.put(t, map[string]any{"environment_id": nil})
	if status != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%v)", status, body)
	}
	if got := h.storedEnvironmentID(t); got != nil {
		t.Fatalf("environment_id: got %v want nil (explicit null = whole project)", got)
	}
	if v, ok := body["environment_id"]; !ok || v != nil {
		t.Fatalf("response environment_id: got %v (present=%v) want null", v, ok)
	}
}

func TestUpdateHandler_MovesBindingToAnotherEnvironment(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)
	h.bindIn(t, &h.envID)

	if status, body := h.put(t, map[string]any{"environment_id": h.devEnvID.String()}); status != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%v)", status, body)
	}
	if got := h.storedEnvironmentID(t); got == nil || *got != h.devEnvID {
		t.Fatalf("environment_id: got %v want %v", got, h.devEnvID)
	}
}

func TestUpdateHandler_InvalidEnvironmentIDIs400AndKeepsValue(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)
	h.bindIn(t, &h.envID)

	for _, v := range []any{"not-a-uuid", uuid.NewString()} {
		status, body := h.put(t, map[string]any{"environment_id": v})
		if status != http.StatusBadRequest && status != http.StatusNotFound {
			t.Fatalf("environment_id=%v: got %d want 400/404 (body=%v)", v, status, body)
		}
	}
	if got := h.storedEnvironmentID(t); got == nil || *got != h.envID {
		t.Fatalf("refused update must not write: got %v want %v", got, h.envID)
	}
}

// A scope change is audited with the session actor, the new
// environment and the one it replaced.
func TestUpdateHandler_EnvironmentChangeIsAudited(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)
	h.bindIn(t, &h.envID)
	since := time.Now().Add(-time.Second)

	if status, body := h.put(t, map[string]any{"environment_id": nil, "created_by": "someone-else"}); status != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%v)", status, body)
	}

	var actor string
	var envID, prevEnvID *string
	resource := fmt.Sprintf("project_secret:%s/%s", h.projectID, h.secretID)
	if err := h.pool.QueryRow(t.Context(),
		`SELECT actor, metadata->>'environment_id', metadata->>'previous_environment_id'
		   FROM audit_events
		  WHERE action = 'project_secret.update' AND resource = $1 AND occurred_at >= $2
		  ORDER BY occurred_at DESC LIMIT 1`,
		resource, since,
	).Scan(&actor, &envID, &prevEnvID); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if actor != "user:"+projectSecretsActor {
		t.Errorf("actor: got %q want user:%s", actor, projectSecretsActor)
	}
	if envID != nil {
		t.Errorf("metadata.environment_id: got %v want null", *envID)
	}
	if prevEnvID == nil || *prevEnvID != h.envID.String() {
		t.Errorf("metadata.previous_environment_id: got %v want %s", prevEnvID, h.envID)
	}
}

// An update that leaves the environment alone records no
// previous_environment_id.
func TestUpdateHandler_NoScopeChangeOmitsPreviousEnvironment(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)
	h.bindIn(t, &h.envID)
	since := time.Now().Add(-time.Second)

	if status, body := h.put(t, map[string]any{"allowed_ops": []string{"read"}}); status != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%v)", status, body)
	}
	var hasPrev bool
	resource := fmt.Sprintf("project_secret:%s/%s", h.projectID, h.secretID)
	if err := h.pool.QueryRow(t.Context(),
		`SELECT metadata ? 'previous_environment_id'
		   FROM audit_events
		  WHERE action = 'project_secret.update' AND resource = $1 AND occurred_at >= $2
		  ORDER BY occurred_at DESC LIMIT 1`,
		resource, since,
	).Scan(&hasPrev); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if hasPrev {
		t.Errorf("previous_environment_id recorded for an update that kept the environment")
	}
}

// --- request listing follows the governing-binding rule ---------------

func (h *projectSecretsHarness) listEnv(t *testing.T, envID uuid.UUID) []map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/projects/%s/environments/%s/secrets", h.projectID, envID), nil)
	resp, err := h.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("list env secrets: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list env secrets status: got %d want 200", resp.StatusCode)
	}
	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestListEnvSecrets_EnvScopedBindingOnlyInItsEnvironment(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)
	h.bindIn(t, &h.envID)

	if got := h.listEnv(t, h.envID); len(got) != 1 || got[0]["secret_id"] != h.secretID.String() {
		t.Fatalf("own environment: got %v want the bound secret", got)
	}
	if got := h.listEnv(t, h.devEnvID); len(got) != 0 {
		t.Fatalf("other environment: got %v want nothing", got)
	}
}

// A whole-project binding governs requests in every environment
// (services.GoverningBinding), so the request listing offers it in each.
func TestListEnvSecrets_WholeProjectBindingInEveryEnvironment(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)
	h.bindIn(t, nil)

	for _, env := range []uuid.UUID{h.envID, h.devEnvID} {
		if got := h.listEnv(t, env); len(got) != 1 || got[0]["secret_id"] != h.secretID.String() {
			t.Fatalf("env %s: got %v want the whole-project binding", env, got)
		}
	}
}

// The same ref discovered on two clusters: one catalog row bound to the
// environment, the other whole-project. Only the governing (env-scoped)
// one is listed in that environment; elsewhere the whole-project one.
func TestListEnvSecrets_ListsOnlyTheGoverningBindingPerRef(t *testing.T) {
	h := bootstrapProjectSecretsHandler(t)
	h.bindIn(t, &h.envID)

	var twin uuid.UUID
	if err := h.pool.QueryRow(t.Context(),
		`INSERT INTO secrets (cluster_name, provider_type, secret_ref, status, last_seen_at)
			VALUES ('eks-tenant-a-dev', 'aws-sm', '/secrets/uat/team-alpha/env', 'present', now())
			RETURNING id`,
	).Scan(&twin); err != nil {
		t.Fatal(err)
	}
	if status, out := h.do(t, http.MethodPost, fmt.Sprintf("/projects/%s/secrets", h.projectID),
		map[string]any{"secret_id": twin.String(), "allowed_ops": []string{"read"}}); status != http.StatusCreated {
		t.Fatalf("bind twin: got %d (body=%v)", status, out)
	}

	if got := h.listEnv(t, h.envID); len(got) != 1 || got[0]["secret_id"] != h.secretID.String() {
		t.Fatalf("scoped environment: got %v want only the env-scoped row %s", got, h.secretID)
	}
	if got := h.listEnv(t, h.devEnvID); len(got) != 1 || got[0]["secret_id"] != twin.String() {
		t.Fatalf("other environment: got %v want only the whole-project row %s", got, twin)
	}
}
