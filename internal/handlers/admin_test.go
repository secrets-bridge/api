package handlers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

// ---- bootstrap helpers -----------------------------------------------

func bootstrapAdmin(t *testing.T) (*fiber.App, *storage.Pool, *handlers.Admin) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 6, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	const wipe = `
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;
		DELETE FROM user_roles;
		DELETE FROM roles WHERE is_system = false;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit_events: %v", err)
	}

	h := handlers.NewAdmin(
		storage.NewRoles(pool),
		storage.NewUserRoles(pool),
		storage.NewWorkflows(pool),
		storage.NewPolicies(pool),
	)
	app := mountAdmin(h)
	return app, pool, h
}

func mountAdmin(h *handlers.Admin) *fiber.App {
	app := fiber.New()
	v1 := app.Group("/api/v1")
	v1.Post("/roles", h.CreateRole)
	v1.Get("/roles", h.ListRoles)
	v1.Get("/roles/:id", h.GetRole)
	v1.Put("/roles/:id/permissions", h.UpdateRolePermissions)
	v1.Delete("/roles/:id", h.DeleteRole)

	v1.Post("/user-roles", h.GrantUserRole)
	v1.Delete("/user-roles/:id", h.RevokeUserRole)
	v1.Get("/users/:userID/roles", h.ListUserRoles)

	v1.Post("/workflows", h.CreateWorkflow)
	v1.Get("/workflows", h.ListWorkflows)
	v1.Get("/workflows/:id", h.GetWorkflow)
	v1.Put("/workflows/:id", h.UpdateWorkflow)
	v1.Delete("/workflows/:id", h.DeleteWorkflow)

	v1.Post("/policies", h.CreatePolicy)
	v1.Get("/policies", h.ListPolicies)
	v1.Get("/policies/:id", h.GetPolicy)
	v1.Put("/policies/:id", h.UpdatePolicy)
	v1.Delete("/policies/:id", h.DeletePolicy)
	return app
}

func doJSON(t *testing.T, app *fiber.App, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	return resp, respBody
}

// ---- roles ----------------------------------------------------------

func TestRoles_CreateGetUpdateDelete(t *testing.T) {
	app, _, _ := bootstrapAdmin(t)

	// Create
	resp, body := doJSON(t, app, "POST", "/api/v1/roles", handlers.RoleBody{
		Name:        "auditor",
		Description: "Read-only access to audit logs",
		Permissions: []string{"audit.read"},
	})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("create: status %d body %s", resp.StatusCode, body)
	}
	var created handlers.RoleBody
	_ = json.Unmarshal(body, &created)
	if created.ID == uuid.Nil {
		t.Fatal("create did not return ID")
	}

	// Get
	resp, body = doJSON(t, app, "GET", "/api/v1/roles/"+created.ID.String(), nil)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("get: status %d body %s", resp.StatusCode, body)
	}
	var got handlers.RoleBody
	_ = json.Unmarshal(body, &got)
	if got.Name != "auditor" || len(got.Permissions) != 1 {
		t.Fatalf("get: %+v", got)
	}

	// Update permissions
	resp, body = doJSON(t, app, "PUT", "/api/v1/roles/"+created.ID.String()+"/permissions",
		handlers.UpdateRolePermissionsBody{Permissions: []string{"audit.read", "audit.export"}})
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("update: status %d body %s", resp.StatusCode, body)
	}
	resp, body = doJSON(t, app, "GET", "/api/v1/roles/"+created.ID.String(), nil)
	_ = json.Unmarshal(body, &got)
	if len(got.Permissions) != 2 {
		t.Fatalf("update did not persist: %+v", got)
	}

	// Delete
	resp, body = doJSON(t, app, "DELETE", "/api/v1/roles/"+created.ID.String(), nil)
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("delete: status %d body %s", resp.StatusCode, body)
	}
}

func TestRoles_DeleteSystemRoleReturns409(t *testing.T) {
	app, pool, _ := bootstrapAdmin(t)
	// Seed admin role is system; its ID comes from the seed migration.
	var sysID uuid.UUID
	if err := pool.QueryRow(t.Context(),
		`SELECT id FROM roles WHERE name='admin' AND is_system=true`,
	).Scan(&sysID); err != nil {
		t.Fatalf("query seed admin: %v", err)
	}
	resp, body := doJSON(t, app, "DELETE", "/api/v1/roles/"+sysID.String(), nil)
	if resp.StatusCode != fiber.StatusConflict {
		t.Fatalf("expected 409 for system delete, got %d body %s", resp.StatusCode, body)
	}
}

func TestRoles_ListReturnsAllIncludingSystem(t *testing.T) {
	app, _, _ := bootstrapAdmin(t)
	resp, body := doJSON(t, app, "GET", "/api/v1/roles", nil)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("list: status %d body %s", resp.StatusCode, body)
	}
	var roles []handlers.RoleBody
	_ = json.Unmarshal(body, &roles)
	// Seed migration ships 3 system roles (admin/approver/developer).
	if len(roles) < 3 {
		t.Fatalf("expected ≥3 roles (system seeds), got %d", len(roles))
	}
	gotAdmin := false
	for _, r := range roles {
		if r.Name == "admin" && r.IsSystem {
			gotAdmin = true
		}
	}
	if !gotAdmin {
		t.Fatal("seed admin role not in list")
	}
}

// ---- user_roles -----------------------------------------------------

func TestUserRoles_GrantRevoke(t *testing.T) {
	app, pool, _ := bootstrapAdmin(t)
	var approverID uuid.UUID
	_ = pool.QueryRow(t.Context(),
		`SELECT id FROM roles WHERE name='approver'`).Scan(&approverID)

	// Grant
	resp, body := doJSON(t, app, "POST", "/api/v1/user-roles", handlers.GrantUserRoleBody{
		UserID:    "alice@example.com",
		RoleID:    approverID,
		Scope:     map[string]any{"environment": "prod"},
		GrantedBy: "admin@example.com",
	})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("grant: %d body %s", resp.StatusCode, body)
	}
	var granted handlers.UserRoleBody
	_ = json.Unmarshal(body, &granted)
	if granted.Scope["environment"] != "prod" {
		t.Fatalf("scope not preserved: %+v", granted.Scope)
	}

	// List user's roles
	resp, body = doJSON(t, app, "GET", "/api/v1/users/alice@example.com/roles", nil)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("list: %d", resp.StatusCode)
	}
	var listed []handlers.UserRoleBody
	_ = json.Unmarshal(body, &listed)
	if len(listed) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(listed))
	}

	// Revoke
	resp, _ = doJSON(t, app, "DELETE", "/api/v1/user-roles/"+granted.ID.String(), nil)
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}

	// List again — empty.
	_, body = doJSON(t, app, "GET", "/api/v1/users/alice@example.com/roles", nil)
	_ = json.Unmarshal(body, &listed)
	if len(listed) != 0 {
		t.Fatalf("expected 0 after revoke, got %d", len(listed))
	}
}

// ---- workflows ------------------------------------------------------

func sampleWorkflowBody(name string) handlers.WorkflowBody {
	return handlers.WorkflowBody{
		Name:                 name,
		Description:          "test workflow",
		MinApprovers:         2,
		WrapTTLCreatedSec:    int64(7 * 24 * 3600),
		WrapTTLApprovedSec:   3600,
		WrapTTLClaimedSec:    300,
		RequestTTLSec:        int64(14 * 24 * 3600),
		RequireJustification: true,
		AllowSelfApproval:    false,
		NotificationChannels: []string{"slack:#sec-approvals"},
		Enabled:              true,
	}
}

func TestWorkflows_CreateGetUpdateDelete(t *testing.T) {
	app, _, _ := bootstrapAdmin(t)

	// Create
	resp, body := doJSON(t, app, "POST", "/api/v1/workflows", sampleWorkflowBody("strict-prod"))
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("create: %d body %s", resp.StatusCode, body)
	}
	var created handlers.WorkflowBody
	_ = json.Unmarshal(body, &created)

	// Get
	_, body = doJSON(t, app, "GET", "/api/v1/workflows/"+created.ID.String(), nil)
	var got handlers.WorkflowBody
	_ = json.Unmarshal(body, &got)
	if got.MinApprovers != 2 || got.WrapTTLApprovedSec != 3600 {
		t.Fatalf("get: %+v", got)
	}

	// Update
	upd := got
	upd.MinApprovers = 3
	upd.WrapTTLApprovedSec = 7200
	resp, _ = doJSON(t, app, "PUT", "/api/v1/workflows/"+created.ID.String(), upd)
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("update: %d", resp.StatusCode)
	}
	_, body = doJSON(t, app, "GET", "/api/v1/workflows/"+created.ID.String(), nil)
	_ = json.Unmarshal(body, &got)
	if got.MinApprovers != 3 || got.WrapTTLApprovedSec != 7200 {
		t.Fatalf("update did not persist: %+v", got)
	}

	// Delete
	resp, _ = doJSON(t, app, "DELETE", "/api/v1/workflows/"+created.ID.String(), nil)
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
}

func TestWorkflows_RejectsZeroTTL(t *testing.T) {
	app, _, _ := bootstrapAdmin(t)
	bad := sampleWorkflowBody("zero-ttl")
	bad.WrapTTLClaimedSec = 0
	resp, body := doJSON(t, app, "POST", "/api/v1/workflows", bad)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected 400 for zero TTL, got %d body %s", resp.StatusCode, body)
	}
}

func TestWorkflows_DeleteSystemReturns409(t *testing.T) {
	app, pool, _ := bootstrapAdmin(t)
	var sysID uuid.UUID
	_ = pool.QueryRow(t.Context(),
		`SELECT id FROM workflow_definitions WHERE is_system=true`).Scan(&sysID)
	resp, _ := doJSON(t, app, "DELETE", "/api/v1/workflows/"+sysID.String(), nil)
	if resp.StatusCode != fiber.StatusConflict {
		t.Fatalf("expected 409 for system workflow delete, got %d", resp.StatusCode)
	}
}

// ---- policies -------------------------------------------------------

func TestPolicies_CreateListDelete(t *testing.T) {
	app, pool, _ := bootstrapAdmin(t)
	var stdID uuid.UUID
	_ = pool.QueryRow(t.Context(),
		`SELECT id FROM workflow_definitions WHERE name='standard'`).Scan(&stdID)

	// Create a prod-env rule pointing at the standard workflow.
	resp, body := doJSON(t, app, "POST", "/api/v1/policies", handlers.PolicyBody{
		Name:       "prod-only",
		Selector:   map[string]any{"environment": "prod"},
		WorkflowID: stdID,
		Priority:   500,
		Enabled:    true,
	})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("create: %d body %s", resp.StatusCode, body)
	}

	// List should include our rule + the seed match-all.
	_, body = doJSON(t, app, "GET", "/api/v1/policies", nil)
	var listed []handlers.PolicyBody
	_ = json.Unmarshal(body, &listed)
	if len(listed) < 2 {
		t.Fatalf("expected ≥2 policies (ours + seed match-all), got %d", len(listed))
	}
	// List is ordered priority DESC; our 500 should be first.
	if listed[0].Name != "prod-only" {
		t.Fatalf("priority ordering: got first %q", listed[0].Name)
	}
}

func TestPolicies_DeleteSystemReturns409(t *testing.T) {
	app, pool, _ := bootstrapAdmin(t)
	var sysID uuid.UUID
	_ = pool.QueryRow(t.Context(),
		`SELECT id FROM policy_rules WHERE is_system=true`).Scan(&sysID)
	resp, _ := doJSON(t, app, "DELETE", "/api/v1/policies/"+sysID.String(), nil)
	if resp.StatusCode != fiber.StatusConflict {
		t.Fatalf("expected 409 for system policy delete, got %d", resp.StatusCode)
	}
}

// ---- error-handling smoke -------------------------------------------

func TestAdmin_NotFoundReturns404(t *testing.T) {
	app, _, _ := bootstrapAdmin(t)
	for _, ep := range []string{
		"/api/v1/roles/" + uuid.New().String(),
		"/api/v1/workflows/" + uuid.New().String(),
		"/api/v1/policies/" + uuid.New().String(),
	} {
		resp, body := doJSON(t, app, "GET", ep, nil)
		if resp.StatusCode != fiber.StatusNotFound {
			t.Fatalf("%s: expected 404, got %d body %s", ep, resp.StatusCode, body)
		}
	}
}

func TestAdmin_InvalidUUIDReturns400(t *testing.T) {
	app, _, _ := bootstrapAdmin(t)
	resp, body := doJSON(t, app, "GET", "/api/v1/roles/not-a-uuid", nil)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected 400 for non-uuid, got %d body %s", resp.StatusCode, body)
	}
}

func TestAdmin_MalformedJSONBodyReturns400(t *testing.T) {
	app, _, _ := bootstrapAdmin(t)
	req := httptest.NewRequest("POST", "/api/v1/roles",
		bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", resp.StatusCode)
	}
}

// Sanity: large list with system rows present doesn't OOM or
// blow up — uses the existing migrations + small inserts.
func TestRoles_ListAfterManyCreates(t *testing.T) {
	app, _, _ := bootstrapAdmin(t)
	for i := 0; i < 10; i++ {
		body := handlers.RoleBody{
			Name:        fmt.Sprintf("role-%02d", i),
			Permissions: []string{"audit.read"},
		}
		resp, b := doJSON(t, app, "POST", "/api/v1/roles", body)
		if resp.StatusCode != fiber.StatusCreated {
			t.Fatalf("create %d: %d body %s", i, resp.StatusCode, b)
		}
	}
	resp, body := doJSON(t, app, "GET", "/api/v1/roles", nil)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("list: %d", resp.StatusCode)
	}
	var roles []handlers.RoleBody
	_ = json.Unmarshal(body, &roles)
	if len(roles) < 13 { // 10 created + 3 system seeds
		t.Fatalf("expected ≥13 roles, got %d", len(roles))
	}
}
