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
	"github.com/secrets-bridge/api/pkg/storage"
)

type projectSecretsHarness struct {
	app        *fiber.App
	pool       *storage.Pool
	projectID  uuid.UUID
	otherProj  uuid.UUID
	envID      uuid.UUID // belongs to projectID
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
	)
	app := fiber.New()
	app.Post("/projects/:id/secrets", handler.Bind)
	app.Get("/projects/:id/secrets", handler.List)
	app.Put("/projects/:id/secrets/:secret_id", handler.Update)
	h.app = app
	return h
}

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
	defer resp.Body.Close()
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
