package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

	// FK-ordered wipe matching bootstrapPolicy in the services tests.
	// Earlier-running tests in other packages may have left
	// access_requests + reveal_sessions rows that reference
	// workflow_definitions; delete them first so the workflow / policy
	// wipe doesn't trip the FK.
	const wipe = `
		DELETE FROM reveal_sessions;
		DELETE FROM secret_wraps;
		DELETE FROM approvals;
		DELETE FROM sync_jobs;
		DELETE FROM access_requests;
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;
		DELETE FROM user_roles;
		DELETE FROM roles WHERE is_system = false;
		DELETE FROM environments;
		DELETE FROM projects;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit_events: %v", err)
	}
	// EPIC R (api#108) — migration 0033 added a FK from policy_rules
	// to projects with ON DELETE CASCADE. Sibling tests that TRUNCATE
	// projects CASCADE silently wipe the seed match-all rule from
	// migration 0005. Re-seed it here so admin tests always see it.
	const reseedSystemPolicy = `
		INSERT INTO policy_rules
			(name, selector, workflow_id, priority, is_system)
		SELECT
			'match-all (system default)',
			'{}'::jsonb,
			(SELECT id FROM workflow_definitions WHERE name = 'standard'),
			0,
			true
		WHERE NOT EXISTS (SELECT 1 FROM policy_rules WHERE name = 'match-all (system default)');
	`
	if _, err := pool.Exec(ctx, reseedSystemPolicy); err != nil {
		t.Fatalf("reseed match-all: %v", err)
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
	_, body = doJSON(t, app, "GET", "/api/v1/roles/"+created.ID.String(), nil)
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

// api#239: a workflow that requests or policy rules reference answers
// 409 workflow_in_use with counts; delete_policy_rules=true deletes the
// rules with it and records a policy.delete for each.
func TestWorkflows_DeleteInUse(t *testing.T) {
	app, pool, h := bootstrapAdmin(t)
	h.WithAudit(storage.NewAuditEvents(pool))
	ctx := t.Context()

	create := func(name string) uuid.UUID {
		resp, body := doJSON(t, app, "POST", "/api/v1/workflows", sampleWorkflowBody(name))
		if resp.StatusCode != fiber.StatusCreated {
			t.Fatalf("create %s: %d %s", name, resp.StatusCode, body)
		}
		var w handlers.WorkflowBody
		_ = json.Unmarshal(body, &w)
		return w.ID
	}
	conflict := func(path string, wantRequests, wantRules float64) string {
		t.Helper()
		resp, body := doJSON(t, app, "DELETE", path, nil)
		var env map[string]any
		_ = json.Unmarshal(body, &env)
		if resp.StatusCode != fiber.StatusConflict || env["error_code"] != "workflow_in_use" ||
			env["requests_count"] != wantRequests || env["policy_rules_count"] != wantRules {
			t.Fatalf("DELETE %s = %d %s; want 409 workflow_in_use with %v requests and %v rules",
				path, resp.StatusCode, body, wantRequests, wantRules)
		}
		return env["message"].(string)
	}

	// Rules route to it: refused, then deleted with them on request.
	ruled := create("wf-ruled")
	resp, body := doJSON(t, app, "POST", "/api/v1/policies", handlers.PolicyBody{
		Name: "uses-wf-ruled", Selector: map[string]any{"environment": "uat"}, WorkflowID: ruled, Priority: 400, Enabled: true,
	})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("create policy: %d %s", resp.StatusCode, body)
	}
	var rule handlers.PolicyBody
	_ = json.Unmarshal(body, &rule)
	if msg := conflict("/api/v1/workflows/"+ruled.String(), 0, 1); !strings.Contains(msg, "delete_policy_rules=true") {
		t.Errorf("message %q doesn't say how to proceed", msg)
	}
	if resp, body := doJSON(t, app, "DELETE", "/api/v1/workflows/"+ruled.String()+"?delete_policy_rules=true", nil); resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("DELETE with delete_policy_rules: %d %s", resp.StatusCode, body)
	}
	if resp, _ := doJSON(t, app, "GET", "/api/v1/policies/"+rule.ID.String(), nil); resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("policy survived its workflow: %d", resp.StatusCode)
	}
	var policyDeletes int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'policy.delete' AND metadata->>'policy_rule_id' = $1`,
		rule.ID.String()).Scan(&policyDeletes); err != nil || policyDeletes != 1 {
		t.Fatalf("policy.delete events for the cascaded rule = %d, %v; want 1", policyDeletes, err)
	}
	var recorded string
	if err := pool.QueryRow(ctx,
		`SELECT metadata->>'deleted_policy_rule_ids' FROM audit_events WHERE action = 'workflow.delete'`).Scan(&recorded); err != nil ||
		!strings.Contains(recorded, rule.ID.String()) {
		t.Fatalf("workflow.delete metadata = %q, %v; want the deleted rule id", recorded, err)
	}

	// A request used it: refused even with delete_policy_rules.
	used := create("wf-used")
	if _, err := pool.Exec(ctx,
		`INSERT INTO access_requests (requester_id, type, status, justification, workflow_id, target_provider_type, target_secret_ref, target_keys)
		 VALUES ('alice', 'patch', 'executed', 'test', $1, 'vault', 'secret/data/x', '["K"]')`, used); err != nil {
		t.Fatalf("seed request: %v", err)
	}
	if msg := conflict("/api/v1/workflows/"+used.String()+"?delete_policy_rules=true", 1, 0); !strings.Contains(msg, "disable it instead") {
		t.Errorf("message %q doesn't point at disabling", msg)
	}
}

// racingWorkflows points one rule at another workflow just before the
// delete runs, as an edit landing between a read of the rules and the
// delete transaction would.
type racingWorkflows struct {
	*storage.Workflows
	pool              *storage.Pool
	ruleID, elsewhere uuid.UUID
}

func (r racingWorkflows) Delete(ctx context.Context, id uuid.UUID, deletePolicyRules bool) (storage.WorkflowUsage, error) {
	if _, err := r.pool.Exec(ctx, `UPDATE policy_rules SET workflow_id = $1 WHERE id = $2`, r.elsewhere, r.ruleID); err != nil {
		return storage.WorkflowUsage{}, err
	}
	return r.Workflows.Delete(ctx, id, deletePolicyRules)
}

// Deleting a workflow with its rules audits the rules the delete
// removed, not a list read before it: a rule pointed elsewhere in
// between survives and gets no policy.delete.
func TestWorkflows_DeleteWithRules_AuditsWhatWasDeleted(t *testing.T) {
	app, pool, _ := bootstrapAdmin(t)
	ctx := t.Context()

	create := func(name string) uuid.UUID {
		resp, body := doJSON(t, app, "POST", "/api/v1/workflows", sampleWorkflowBody(name))
		if resp.StatusCode != fiber.StatusCreated {
			t.Fatalf("create %s: %d %s", name, resp.StatusCode, body)
		}
		var w handlers.WorkflowBody
		_ = json.Unmarshal(body, &w)
		return w.ID
	}
	rule := func(name string, wf uuid.UUID) uuid.UUID {
		resp, body := doJSON(t, app, "POST", "/api/v1/policies", handlers.PolicyBody{
			Name: name, Selector: map[string]any{"environment": "uat"}, WorkflowID: wf, Priority: 400, Enabled: true,
		})
		if resp.StatusCode != fiber.StatusCreated {
			t.Fatalf("create policy %s: %d %s", name, resp.StatusCode, body)
		}
		var p handlers.PolicyBody
		_ = json.Unmarshal(body, &p)
		return p.ID
	}
	going, staying := create("wf-going"), create("wf-staying")
	deletedRule, movedRule := rule("goes-with-it", going), rule("moved-away", going)

	h := handlers.NewAdmin(
		storage.NewRoles(pool),
		storage.NewUserRoles(pool),
		racingWorkflows{Workflows: storage.NewWorkflows(pool), pool: pool, ruleID: movedRule, elsewhere: staying},
		storage.NewPolicies(pool),
	).WithAudit(storage.NewAuditEvents(pool))
	racing := mountAdmin(h)

	if resp, body := doJSON(t, racing, "DELETE", "/api/v1/workflows/"+going.String()+"?delete_policy_rules=true", nil); resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("DELETE with delete_policy_rules: %d %s", resp.StatusCode, body)
	}
	if resp, _ := doJSON(t, app, "GET", "/api/v1/policies/"+movedRule.String(), nil); resp.StatusCode != fiber.StatusOK {
		t.Fatalf("the rule pointed elsewhere was deleted: %d", resp.StatusCode)
	}

	audited := map[string]int{}
	rows, err := pool.Query(ctx, `SELECT metadata->>'policy_rule_id' FROM audit_events WHERE action = 'policy.delete'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		audited[id]++
	}
	rows.Close()
	if audited[deletedRule.String()] != 1 || audited[movedRule.String()] != 0 || len(audited) != 1 {
		t.Fatalf("policy.delete events by rule = %v; want one for %s and none for the moved %s", audited, deletedRule, movedRule)
	}
	var recorded string
	if err := pool.QueryRow(ctx,
		`SELECT metadata->>'deleted_policy_rule_ids' FROM audit_events WHERE action = 'workflow.delete'`).Scan(&recorded); err != nil ||
		!strings.Contains(recorded, deletedRule.String()) || strings.Contains(recorded, movedRule.String()) {
		t.Fatalf("workflow.delete deleted_policy_rule_ids = %q, %v; want only %s", recorded, err, deletedRule)
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

// TestPolicies_SelectorEnumInvalidReturnsStructuredEnvelope pins M5:
// the admin authoring path must reject an unknown provider_type /
// operation selector with the SAME structured envelope the scoped
// paths emit — {error_code: "policy_scope_too_broad", reason: ...} —
// not a plain {error: "<message>"} string. (QA found the admin path
// returning the flat shape, breaking the SPA's reason-variant toast.)
func TestPolicies_SelectorEnumInvalidReturnsStructuredEnvelope(t *testing.T) {
	app, pool, _ := bootstrapAdmin(t)
	var stdID uuid.UUID
	_ = pool.QueryRow(t.Context(),
		`SELECT id FROM workflow_definitions WHERE name='standard'`).Scan(&stdID)

	cases := []struct {
		name     string
		selector map[string]any
		reason   string
	}{
		{"operation", map[string]any{"operation": "bogus"}, "operation_invalid"},
		{"provider_type", map[string]any{"provider_type": "bogus"}, "provider_type_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := doJSON(t, app, "POST", "/api/v1/policies", handlers.PolicyBody{
				Name:       "enum-reject-" + tc.name,
				Selector:   tc.selector,
				WorkflowID: stdID,
				Priority:   500,
				Enabled:    true,
			})
			if resp.StatusCode != fiber.StatusBadRequest {
				t.Fatalf("want 400, got %d body %s", resp.StatusCode, body)
			}
			var env struct {
				ErrorCode string `json:"error_code"`
				Reason    string `json:"reason"`
			}
			if err := json.Unmarshal(body, &env); err != nil {
				t.Fatalf("unmarshal envelope: %v (body %s)", err, body)
			}
			if env.ErrorCode != "policy_scope_too_broad" {
				t.Errorf("error_code = %q, want policy_scope_too_broad (body %s)", env.ErrorCode, body)
			}
			if env.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", env.Reason, tc.reason)
			}
		})
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

// QA P2 — `omitempty` on a bool drops `false` from the JSON, so a
// policy created with requires_mfa=false / direct_reveal_allowed=false
// came back with those keys ABSENT. Indistinguishable from "the field
// is not supported", and it means an operator cannot confirm from the
// API that direct reveal is switched OFF. The values were persisted
// correctly the whole time — this is purely response serialization.
func TestPolicies_FalseBoolsAreVisibleInResponse(t *testing.T) {
	app, pool, _ := bootstrapAdmin(t)
	var stdID uuid.UUID
	_ = pool.QueryRow(t.Context(),
		`SELECT id FROM workflow_definitions WHERE name='standard'`).Scan(&stdID)

	resp, body := doJSON(t, app, "POST", "/api/v1/policies", handlers.PolicyBody{
		Name:                "bools-false",
		Selector:            map[string]any{"environment": "uat"},
		WorkflowID:          stdID,
		Priority:            410,
		Enabled:             true,
		DirectRevealAllowed: false,
		RequiresMFA:         false,
	})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("create: %d body %s", resp.StatusCode, body)
	}

	// Assert on the RAW JSON: the keys must be present, not merely
	// decode to false (which a missing key would also do).
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"direct_reveal_allowed", "requires_mfa"} {
		v, ok := raw[k]
		if !ok {
			t.Errorf("%q absent from create response — an operator cannot tell it is false vs unsupported", k)
			continue
		}
		if v != false {
			t.Errorf("%q: got %v want false", k, v)
		}
	}
}

func TestPolicies_TrueBoolsStillSerialize(t *testing.T) {
	app, pool, _ := bootstrapAdmin(t)
	var stdID uuid.UUID
	_ = pool.QueryRow(t.Context(),
		`SELECT id FROM workflow_definitions WHERE name='standard'`).Scan(&stdID)

	resp, body := doJSON(t, app, "POST", "/api/v1/policies", handlers.PolicyBody{
		Name:                "bools-true",
		Selector:            map[string]any{"environment_kind": "non_prod", "operation": "reveal"},
		WorkflowID:          stdID,
		Priority:            420,
		Enabled:             true,
		DirectRevealAllowed: true,
		RequiresMFA:         true,
		RevealTTLSeconds:    120,
	})
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("create: %d body %s", resp.StatusCode, body)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if raw["direct_reveal_allowed"] != true || raw["requires_mfa"] != true {
		t.Errorf("true bools must still serialize: got %v / %v",
			raw["direct_reveal_allowed"], raw["requires_mfa"])
	}
}
