// EPIC R (api#108) Slice R2 handler tests — project-anchored scoped
// policy.author endpoints. One test per locked gate row + the §4
// mismatch / sanitized-projection / counter-cardinality protections.

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
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

type scopedPolicyHarness struct {
	app          *fiber.App
	pool         *storage.Pool
	engine       *services.PolicyEngine
	resolver     *stubResolver
	projectID    uuid.UUID
	otherProject uuid.UUID
	nonProdEnvID uuid.UUID
	prodEnvID    uuid.UUID
	workflowID   uuid.UUID
	platformRule uuid.UUID
}

func bootstrapScopedPolicies(t *testing.T) *scopedPolicyHarness {
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
		t.Fatalf("truncate audit: %v", err)
	}
	const reseed = `
		INSERT INTO policy_rules
			(name, selector, workflow_id, priority, is_system)
		SELECT 'match-all (system default)', '{}'::jsonb,
		       (SELECT id FROM workflow_definitions WHERE name = 'standard'),
		       0, true
		WHERE NOT EXISTS (SELECT 1 FROM policy_rules WHERE name = 'match-all (system default)');`
	if _, err := pool.Exec(ctx, reseed); err != nil {
		t.Fatalf("reseed: %v", err)
	}

	var projectID, otherProject, nonProdEnvID, prodEnvID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (name) VALUES ('p-scoped-policy') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (name) VALUES ('p-other-covered') RETURNING id`,
	).Scan(&otherProject); err != nil {
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
	var workflowID uuid.UUID
	if err := pool.QueryRow(ctx,
		`SELECT id FROM workflow_definitions WHERE name = 'standard'`,
	).Scan(&workflowID); err != nil {
		t.Fatal(err)
	}
	// Seed a platform-owned rule that pins a sensitive selector value
	// — the sanitization assertion below verifies it's NEVER leaked
	// across the scoped GET projection.
	var platformRule uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO policy_rules (name, selector, workflow_id, priority, project_id)
		 VALUES ('platform-billing-prefix', '{"secret_ref_prefix":"billing/very-secret/"}'::jsonb, $1, 9100, NULL)
		 RETURNING id`,
		workflowID,
	).Scan(&platformRule); err != nil {
		t.Fatal(err)
	}

	resolver := &stubResolver{}
	engine := services.NewPolicyEngine(
		storage.NewPolicies(pool),
		storage.NewWorkflows(pool),
		storage.NewAuditEvents(pool),
	).WithEnvironments(storage.NewEnvironments(pool)).
		WithAuthorScope(resolver, &stubTeamScopeHandler{})

	app := fiber.New()
	v1 := app.Group("/api/v1")
	app.Use(testAuthMW)

	pprH := handlers.NewProjectPolicyRules(engine, storage.NewPolicies(pool))
	v1.Post("/projects/:projectID/policy-rules", pprH.Create)
	v1.Get("/projects/:projectID/policy-rules", pprH.List)
	v1.Get("/projects/:projectID/policy-rules/:ruleID", pprH.Get)
	v1.Put("/projects/:projectID/policy-rules/:ruleID", pprH.Update)
	v1.Delete("/projects/:projectID/policy-rules/:ruleID", pprH.Delete)

	currentResolver = resolver
	return &scopedPolicyHarness{
		app:          app,
		pool:         pool,
		engine:       engine,
		resolver:     resolver,
		projectID:    projectID,
		otherProject: otherProject,
		nonProdEnvID: nonProdEnvID,
		prodEnvID:    prodEnvID,
		workflowID:   workflowID,
		platformRule: platformRule,
	}
}

func grantPolicyAuthorForProject(projectIDs ...string) {
	grants := make([]auth.Grant, 0, len(projectIDs))
	for _, pid := range projectIDs {
		grants = append(grants, auth.Grant{
			Permission: string(auth.PermPolicyAuthor),
			Scope:      map[string]string{"project_id": pid},
		})
	}
	currentResolver.grants = grants
}

func doPolicyJSON(t *testing.T, app *fiber.App, method, path string, body any) (*http.Response, []byte) {
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
	_ = resp.Body.Close()
	return resp, respBody
}

// readPolicyCounter reads a Prometheus counter value by name + labels.
// Returns 0 if not yet observed.
func readPolicyCounter(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if matchLabels(m.GetLabel(), labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func matchLabels(actual []*dto.LabelPair, want map[string]string) bool {
	if len(actual) != len(want) {
		return false
	}
	for _, lp := range actual {
		if want[lp.GetName()] != lp.GetValue() {
			return false
		}
	}
	return true
}

func TestScopedCreate_HappyPath_201_AndCounterDelta(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())

	before := readPolicyCounter(t, "policy_rules_created_total",
		map[string]string{"permission_used": "policy.author", "scope": "project"})

	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name":        "happy-rule",
			"selector":    map[string]any{"environment_kind": "non_prod"},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 201 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	parsed := decode(t, body)
	if parsed["is_platform_inherited"] != false {
		t.Fatalf("created scoped rule should have is_platform_inherited=false; got %v", parsed["is_platform_inherited"])
	}
	after := readPolicyCounter(t, "policy_rules_created_total",
		map[string]string{"permission_used": "policy.author", "scope": "project"})
	if after-before != 1 {
		t.Fatalf("created counter delta = %v, want 1", after-before)
	}
}

func TestScopedCreate_OutOfScope_403_DeniedCounterIncrement_NoRuleIDInAudit(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	// No grants — alice has nothing on this project.
	currentResolver.grants = nil

	before := readPolicyCounter(t, "policy_rules_denied_total",
		map[string]string{"reason": "out_of_scope"})

	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name":        "should-fail",
			"selector":    map[string]any{"environment_kind": "non_prod"},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	if got := decode(t, body)["error_code"]; got != "out_of_scope_policy" {
		t.Fatalf("error_code = %v, want out_of_scope_policy", got)
	}
	after := readPolicyCounter(t, "policy_rules_denied_total",
		map[string]string{"reason": "out_of_scope"})
	if after-before != 1 {
		t.Fatalf("denied counter delta = %v, want 1", after-before)
	}
	// §6 lock: denied audit row must NOT include policy_rule_id.
	var hasRuleID bool
	if err := h.pool.QueryRow(t.Context(),
		`SELECT metadata ? 'policy_rule_id' FROM audit_events
		 WHERE action='policy.denied_out_of_scope' AND actor='alice'
		 ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&hasRuleID); err != nil {
		t.Fatal(err)
	}
	if hasRuleID {
		t.Fatalf("denied audit must NOT include policy_rule_id")
	}
}

func TestScopedCreate_PriorityReserved_400(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name":        "too-high",
			"selector":    map[string]any{"environment_kind": "non_prod"},
			"priority":    services.PlatformReservedPriority,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	parsed := decode(t, body)
	if parsed["error_code"] != "policy_priority_reserved" {
		t.Fatalf("error_code = %v", parsed["error_code"])
	}
	if cap, ok := parsed["cap"].(float64); !ok || int(cap) != services.PlatformReservedPriority {
		t.Fatalf("cap field missing or wrong: %v", parsed["cap"])
	}
}

func TestScopedCreate_ProdEnvKind_403(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name":        "prod-kind",
			"selector":    map[string]any{"environment_kind": "prod"},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	parsed := decode(t, body)
	if parsed["error_code"] != "prod_policy_not_allowed_for_scope" {
		t.Fatalf("error_code = %v", parsed["error_code"])
	}
	if parsed["env_kind"] != "prod" {
		t.Fatalf("env_kind = %v, want prod", parsed["env_kind"])
	}
}

func TestScopedCreate_ProdEnvID_403(t *testing.T) {
	// Service-level §3 Q8 critical test surfaced at the HTTP boundary.
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name":        "prod-env-id",
			"selector":    map[string]any{"environment_id": h.prodEnvID.String()},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	if decode(t, body)["error_code"] != "prod_policy_not_allowed_for_scope" {
		t.Fatalf("error_code mismatch")
	}
}

func TestScopedCreate_EmptySelector_400_SelectorEmpty(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name":        "empty-selector",
			"selector":    map[string]any{},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	parsed := decode(t, body)
	if parsed["error_code"] != "policy_scope_too_broad" {
		t.Fatalf("error_code = %v", parsed["error_code"])
	}
	if parsed["reason"] != "selector_empty" {
		t.Fatalf("reason = %v, want selector_empty", parsed["reason"])
	}
}

func TestScopedCreate_MissingEnvKey_400_EnvConstraintMissing(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name":        "no-env",
			"selector":    map[string]any{"secret_ref_prefix": "billing/"},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	parsed := decode(t, body)
	if parsed["reason"] != "env_constraint_missing" {
		t.Fatalf("reason = %v", parsed["reason"])
	}
}

func TestScopedCreate_SelectorProjectMismatch_400(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	other := uuid.New().String()
	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name": "mismatch",
			"selector": map[string]any{
				"project_id":       other,
				"environment_kind": "non_prod",
			},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	if decode(t, body)["error_code"] != "policy_selector_mismatch" {
		t.Fatalf("error_code mismatch")
	}
}

func TestScopedCreate_EnvIDNotInProject_400(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	// Make a non-prod env in the OTHER project.
	var otherEnvID uuid.UUID
	if err := h.pool.QueryRow(t.Context(),
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
			VALUES ($1, 'dev', 'dev', 'non_prod', 1) RETURNING id`,
		h.otherProject,
	).Scan(&otherEnvID); err != nil {
		t.Fatal(err)
	}
	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name":        "wrong-project-env",
			"selector":    map[string]any{"environment_id": otherEnvID.String()},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if decode(t, body)["error_code"] != "policy_environment_not_in_project" {
		t.Fatalf("error_code mismatch")
	}
}

func TestScopedUpdate_HappyPath_200_AndCounterDelta(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	// Create then update.
	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name": "to-update", "selector": map[string]any{"environment_kind": "non_prod"},
			"priority": 100, "workflow_id": h.workflowID.String(), "enabled": true,
		})
	if resp.StatusCode != 201 {
		t.Fatalf("seed create status = %d, body = %s", resp.StatusCode, string(body))
	}
	id := decode(t, body)["id"].(string)
	before := readPolicyCounter(t, "policy_rules_updated_total",
		map[string]string{"permission_used": "policy.author", "scope": "project"})

	newPriority := 200
	resp2, body2 := doPolicyJSON(t, h.app, "PUT",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules/%s", h.projectID, id),
		map[string]any{"priority": newPriority})
	if resp2.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp2.StatusCode, string(body2))
	}
	after := readPolicyCounter(t, "policy_rules_updated_total",
		map[string]string{"permission_used": "policy.author", "scope": "project"})
	if after-before != 1 {
		t.Fatalf("updated counter delta = %v, want 1", after-before)
	}
}

func TestScopedUpdate_ProjectMismatch_ReturnsNotFound_NeverOutOfScope(t *testing.T) {
	// §4 critical lock pinned at HTTP boundary.
	h := bootstrapScopedPolicies(t)
	// Alice covers BOTH projects.
	grantPolicyAuthorForProject(h.projectID.String(), h.otherProject.String())

	// Create rule under h.projectID.
	_, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name": "rule-on-alice-project", "selector": map[string]any{"environment_kind": "non_prod"},
			"priority": 100, "workflow_id": h.workflowID.String(), "enabled": true,
		})
	id := decode(t, body)["id"].(string)

	newPriority := 200
	resp, body2 := doPolicyJSON(t, h.app, "PUT",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules/%s", h.otherProject, id),
		map[string]any{"priority": newPriority})
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d (want 404 policy_not_found), body = %s", resp.StatusCode, string(body2))
	}
	parsed := decode(t, body2)
	if parsed["error_code"] != "policy_not_found" {
		t.Fatalf("error_code = %v (must NEVER be out_of_scope_policy on project mismatch)", parsed["error_code"])
	}
}

func TestScopedUpdate_PlatformRule_403_PlatformPolicyNotEditable(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	newPriority := 100
	resp, body := doPolicyJSON(t, h.app, "PUT",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules/%s", h.projectID, h.platformRule),
		map[string]any{"priority": newPriority})
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	if decode(t, body)["error_code"] != "platform_policy_not_editable" {
		t.Fatalf("error_code mismatch")
	}
}

func TestScopedUpdate_ExplicitEmptySelector_400(t *testing.T) {
	// §3 Q9 lock pinned at HTTP boundary.
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	_, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name": "to-update", "selector": map[string]any{"environment_kind": "non_prod"},
			"priority": 100, "workflow_id": h.workflowID.String(), "enabled": true,
		})
	id := decode(t, body)["id"].(string)

	emptySelector := map[string]any{}
	resp, body2 := doPolicyJSON(t, h.app, "PUT",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules/%s", h.projectID, id),
		map[string]any{"selector": emptySelector})
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body2))
	}
	parsed := decode(t, body2)
	if parsed["error_code"] != "policy_scope_too_broad" {
		t.Fatalf("error_code mismatch")
	}
	if parsed["reason"] != "selector_empty" {
		t.Fatalf("reason = %v", parsed["reason"])
	}
}

func TestScopedDelete_HappyPath_204_AndCounterDelta(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	_, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name": "to-delete", "selector": map[string]any{"environment_kind": "non_prod"},
			"priority": 100, "workflow_id": h.workflowID.String(), "enabled": true,
		})
	id := decode(t, body)["id"].(string)
	before := readPolicyCounter(t, "policy_rules_deleted_total",
		map[string]string{"permission_used": "policy.author", "scope": "project"})
	resp, _ := doPolicyJSON(t, h.app, "DELETE",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules/%s", h.projectID, id), nil)
	if resp.StatusCode != 204 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	after := readPolicyCounter(t, "policy_rules_deleted_total",
		map[string]string{"permission_used": "policy.author", "scope": "project"})
	if after-before != 1 {
		t.Fatalf("deleted counter delta = %v, want 1", after-before)
	}
}

func TestScopedDelete_ProjectMismatch_ReturnsNotFound(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String(), h.otherProject.String())
	_, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name": "rule", "selector": map[string]any{"environment_kind": "non_prod"},
			"priority": 100, "workflow_id": h.workflowID.String(), "enabled": true,
		})
	id := decode(t, body)["id"].(string)
	resp, body2 := doPolicyJSON(t, h.app, "DELETE",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules/%s", h.otherProject, id), nil)
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body2))
	}
	if decode(t, body2)["error_code"] != "policy_not_found" {
		t.Fatalf("error_code mismatch")
	}
}

func TestScopedList_ReturnsInheritedPlatform_WithSanitizedProjection(t *testing.T) {
	// §4 correction 1 critical test: inherited platform row must
	// expose selector_keys but NOT selector VALUES (no "billing/very-
	// secret/" leaked across the wire).
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	// Also seed one scoped rule so the response carries both kinds.
	_, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name": "scoped", "selector": map[string]any{"environment_kind": "non_prod"},
			"priority": 100, "workflow_id": h.workflowID.String(), "enabled": true,
		})
	_ = body
	resp, body := doPolicyJSON(t, h.app, "GET",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	// CRITICAL canary: response body must NOT contain the platform
	// rule's secret prefix value.
	if strings.Contains(string(body), "billing/very-secret/") {
		t.Fatalf("LEAK: platform selector VALUE present in scoped GET response: %s", string(body))
	}
	var rules []map[string]any
	if err := json.Unmarshal(body, &rules); err != nil {
		t.Fatal(err)
	}
	var (
		foundScoped         bool
		foundPlatformWithKeys bool
		anyPlatform         bool
	)
	for _, r := range rules {
		if r["is_platform_inherited"] == true {
			anyPlatform = true
			// EVERY platform row must omit the selector field.
			if r["selector"] != nil {
				t.Fatalf("platform rule must NOT carry selector field; got %v", r["selector"])
			}
			// At least one platform rule should expose non-empty
			// selector_keys (the seed match-all has empty selector;
			// our test-seeded platform-billing-prefix has 1 key).
			if keys, ok := r["selector_keys"].([]any); ok && len(keys) > 0 {
				foundPlatformWithKeys = true
				// Confirm the key NAME survives sanitization
				// (only the VALUE is stripped).
				if keys[0] != "secret_ref_prefix" {
					t.Fatalf("expected first key to be secret_ref_prefix; got %v", keys[0])
				}
			}
		}
		if r["is_platform_inherited"] == false {
			foundScoped = true
			if r["selector"] == nil {
				t.Fatalf("scoped rule must carry full selector field; got nil")
			}
		}
	}
	if !anyPlatform {
		t.Fatal("expected to see at least one inherited platform rule")
	}
	if !foundPlatformWithKeys {
		t.Fatal("expected the test-seeded platform rule to surface its selector_keys")
	}
	if !foundScoped {
		t.Fatal("expected to see at least one scoped rule")
	}
}

func TestScopedGet_PlatformRule_ReturnsSanitizedProjection(t *testing.T) {
	h := bootstrapScopedPolicies(t)
	grantPolicyAuthorForProject(h.projectID.String())
	resp, body := doPolicyJSON(t, h.app, "GET",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules/%s", h.projectID, h.platformRule), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	if strings.Contains(string(body), "billing/very-secret/") {
		t.Fatalf("LEAK: platform selector VALUE present in scoped GET-by-id: %s", string(body))
	}
	parsed := decode(t, body)
	if parsed["is_platform_inherited"] != true {
		t.Fatalf("is_platform_inherited = %v", parsed["is_platform_inherited"])
	}
	if parsed["selector"] != nil {
		t.Fatalf("selector must be omitted for inherited platform GET; got %v", parsed["selector"])
	}
}

// ---- silence unused imports the package would otherwise drop --------
var _ = context.Background
