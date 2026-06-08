// R-follow-up #1 (api#118) — handler tests for the new
// GET /workflows/scoped-policy-authorable endpoint + the
// preserve-on-omit Update semantic from §3 safety correction +
// the scoped POST denial counter/audit envelope.

package handlers_test

import (
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

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// authorableHarness — minimal app with the workflows admin handlers
// + the new scoped-authorable endpoint mounted in the §2 corrected
// route order.
type authorableHarness struct {
	app      *fiber.App
	pool     *storage.Pool
	resolver *stubResolver
}

func bootstrapAuthorableWorkflows(t *testing.T) *authorableHarness {
	t.Helper()
	dbDSN := requireDB(t)
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

	resolver := &stubResolver{}
	app := fiber.New()
	app.Use(testAuthMW)

	adminH := handlers.NewAdmin(
		storage.NewRoles(pool),
		storage.NewUserRoles(pool),
		storage.NewWorkflows(pool),
		storage.NewPolicies(pool),
	)
	v1 := app.Group("/api/v1")
	v1.Post("/workflows",
		auth.Require(auth.PermWorkflowEdit, resolver),
		adminH.CreateWorkflow)
	v1.Get("/workflows", adminH.ListWorkflows)
	// §2 route-order correction: static BEFORE dynamic.
	v1.Get("/workflows/scoped-policy-authorable",
		auth.RequireAny(auth.PermPolicyAuthor, resolver),
		adminH.ListScopedAuthorableWorkflows)
	v1.Get("/workflows/:id", adminH.GetWorkflow)
	v1.Put("/workflows/:id",
		auth.Require(auth.PermWorkflowEdit, resolver),
		adminH.UpdateWorkflow)

	currentResolver = resolver
	return &authorableHarness{app: app, pool: pool, resolver: resolver}
}

func requireDB(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	return dsn
}

func grantWorkflowEdit() {
	currentResolver.grants = []auth.Grant{
		{Permission: string(auth.PermWorkflowEdit)},
	}
}

func grantPolicyAuthorScoped(projectID string) {
	currentResolver.grants = []auth.Grant{
		{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"project_id": projectID}},
	}
}

func grantNothingAuthorable() {
	currentResolver.grants = nil
}

func doWorkflowsJSON(t *testing.T, app *fiber.App, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = strings.NewReader(string(b))
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

func TestAdminCreateWorkflow_AcceptsScopedAuthorableFlag(t *testing.T) {
	h := bootstrapAuthorableWorkflows(t)
	grantWorkflowEdit()
	tru := true
	resp, body := doWorkflowsJSON(t, h.app, "POST", "/api/v1/workflows", map[string]any{
		"name":                       "create-opted-in",
		"min_approvers":              1,
		"wrap_ttl_created_seconds":   300,
		"wrap_ttl_approved_seconds":  600,
		"wrap_ttl_claimed_seconds":   300,
		"request_ttl_seconds":        86400,
		"require_justification":      true,
		"allow_self_approval":        false,
		"notification_channels":      []string{},
		"enabled":                    true,
		"scoped_policy_authorable":   tru,
	})
	if resp.StatusCode != 201 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	var parsed map[string]any
	_ = json.Unmarshal(body, &parsed)
	if parsed["scoped_policy_authorable"] != true {
		t.Fatalf("returned scoped_policy_authorable = %v, want true", parsed["scoped_policy_authorable"])
	}
}

func TestAdminUpdateWorkflow_PreservesScopedAuthorableWhenOmitted(t *testing.T) {
	// §3 safety correction pinned at the HTTP boundary: PUT body that
	// omits scoped_policy_authorable must NOT silently opt the
	// workflow out. Critical for rolling deploys where the SPA hasn't
	// shipped yet but the api already has migration 0035.
	h := bootstrapAuthorableWorkflows(t)
	grantWorkflowEdit()

	// Seed a workflow with the flag flipped on.
	tru := true
	_, body := doWorkflowsJSON(t, h.app, "POST", "/api/v1/workflows", map[string]any{
		"name":                       "preserve-test",
		"min_approvers":              1,
		"wrap_ttl_created_seconds":   300,
		"wrap_ttl_approved_seconds":  600,
		"wrap_ttl_claimed_seconds":   300,
		"request_ttl_seconds":        86400,
		"require_justification":      true,
		"notification_channels":      []string{},
		"enabled":                    true,
		"scoped_policy_authorable":   tru,
	})
	created := map[string]any{}
	_ = json.Unmarshal(body, &created)
	id, _ := created["id"].(string)

	// PUT a body that OMITS the field. Older SPA / older curl script
	// stand-in.
	resp, _ := doWorkflowsJSON(t, h.app, "PUT", "/api/v1/workflows/"+id, map[string]any{
		"name":                      "preserve-test",
		"min_approvers":             2, // change something else
		"wrap_ttl_created_seconds":  300,
		"wrap_ttl_approved_seconds": 600,
		"wrap_ttl_claimed_seconds":  300,
		"request_ttl_seconds":       86400,
		"require_justification":     true,
		"notification_channels":     []string{},
		"enabled":                   true,
	})
	if resp.StatusCode != 204 {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}

	// Read back — flag must still be true.
	_, body = doWorkflowsJSON(t, h.app, "GET", "/api/v1/workflows/"+id, nil)
	out := map[string]any{}
	_ = json.Unmarshal(body, &out)
	if out["scoped_policy_authorable"] != true {
		t.Fatalf("PRESERVE FAILED — scoped_policy_authorable = %v after omit-on-PUT; want true", out["scoped_policy_authorable"])
	}
	// And min_approvers should have changed to confirm the other
	// fields propagated.
	if out["min_approvers"] != float64(2) {
		t.Fatalf("min_approvers = %v, want 2 (other fields didn't propagate)", out["min_approvers"])
	}
}

func TestAdminUpdateWorkflow_ExplicitFalseFlipsOut(t *testing.T) {
	h := bootstrapAuthorableWorkflows(t)
	grantWorkflowEdit()
	tru := true
	fals := false
	_, body := doWorkflowsJSON(t, h.app, "POST", "/api/v1/workflows", map[string]any{
		"name":                       "flip-out",
		"min_approvers":              1,
		"wrap_ttl_created_seconds":   300,
		"wrap_ttl_approved_seconds":  600,
		"wrap_ttl_claimed_seconds":   300,
		"request_ttl_seconds":        86400,
		"require_justification":      true,
		"notification_channels":      []string{},
		"enabled":                    true,
		"scoped_policy_authorable":   tru,
	})
	created := map[string]any{}
	_ = json.Unmarshal(body, &created)
	id, _ := created["id"].(string)

	// Explicit false flips out.
	_, _ = doWorkflowsJSON(t, h.app, "PUT", "/api/v1/workflows/"+id, map[string]any{
		"name":                      "flip-out",
		"min_approvers":             1,
		"wrap_ttl_created_seconds":  300,
		"wrap_ttl_approved_seconds": 600,
		"wrap_ttl_claimed_seconds":  300,
		"request_ttl_seconds":       86400,
		"require_justification":     true,
		"notification_channels":     []string{},
		"enabled":                   true,
		"scoped_policy_authorable":  fals,
	})

	_, body = doWorkflowsJSON(t, h.app, "GET", "/api/v1/workflows/"+id, nil)
	out := map[string]any{}
	_ = json.Unmarshal(body, &out)
	if out["scoped_policy_authorable"] != false {
		t.Fatalf("explicit false didn't flip the flag; got %v", out["scoped_policy_authorable"])
	}
}

func TestGetScopedAuthorableWorkflows_RequiresPolicyAuthor(t *testing.T) {
	h := bootstrapAuthorableWorkflows(t)
	grantNothingAuthorable()

	resp, body := doWorkflowsJSON(t, h.app, "GET",
		"/api/v1/workflows/scoped-policy-authorable", nil)
	if resp.StatusCode != 403 {
		t.Fatalf("want 403 for no perm, got %d body=%s", resp.StatusCode, string(body))
	}
}

func TestGetScopedAuthorableWorkflows_ReturnsOnlyOptedInEnabled(t *testing.T) {
	h := bootstrapAuthorableWorkflows(t)
	grantWorkflowEdit()

	// Seed three workflows via the api:
	//   1. enabled + authorable        — MUST appear
	//   2. enabled + NOT authorable    — must NOT appear
	//   3. DISABLED + authorable       — must NOT appear
	tru := true
	fals := false
	for _, spec := range []struct {
		name       string
		enabled    bool
		authorable bool
	}{
		{"good", true, true},
		{"opt-out", true, false},
		{"disabled-authorable", false, true},
	} {
		body := map[string]any{
			"name":                       spec.name,
			"min_approvers":              1,
			"wrap_ttl_created_seconds":   300,
			"wrap_ttl_approved_seconds":  600,
			"wrap_ttl_claimed_seconds":   300,
			"request_ttl_seconds":        86400,
			"require_justification":      true,
			"notification_channels":      []string{},
			"enabled":                    spec.enabled,
		}
		if spec.authorable {
			body["scoped_policy_authorable"] = tru
		} else {
			body["scoped_policy_authorable"] = fals
		}
		resp, b := doWorkflowsJSON(t, h.app, "POST", "/api/v1/workflows", body)
		if resp.StatusCode != 201 {
			t.Fatalf("seed %s: %d %s", spec.name, resp.StatusCode, string(b))
		}
	}

	// Switch to a policy.author actor.
	grantPolicyAuthorScoped(uuid.New().String())
	resp, body := doWorkflowsJSON(t, h.app, "GET",
		"/api/v1/workflows/scoped-policy-authorable", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body = %s", resp.StatusCode, string(body))
	}
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}

	// Result must contain "good" and must NOT contain "opt-out" or
	// "disabled-authorable". The seed "standard" workflow may or may
	// not be present depending on migration 0005 default — accept
	// either, just enforce the new rows.
	names := map[string]bool{}
	for _, w := range out {
		if n, ok := w["name"].(string); ok {
			names[n] = true
		}
	}
	if !names["good"] {
		t.Fatal("expected 'good' workflow in result")
	}
	if names["opt-out"] {
		t.Fatal("opt-out workflow leaked into scoped-authorable list")
	}
	if names["disabled-authorable"] {
		t.Fatal("disabled workflow leaked into scoped-authorable list")
	}
}

func TestScopedPolicyCreate_OnOptedOutWorkflow_403_WorkflowNotAuthorableForScope(t *testing.T) {
	// End-to-end pinning of the new envelope + counter + audit at
	// the HTTP boundary. Reuses the scoped policy harness from the
	// EPIC R suite — its bootstrap flips the seed workflow's
	// scoped_policy_authorable=true so most tests work; here we
	// flip it back to false to drive the denial path.
	h := bootstrapScopedPolicies(t)
	if _, err := h.pool.Exec(t.Context(),
		`UPDATE workflow_definitions SET scoped_policy_authorable=false WHERE name='standard'`,
	); err != nil {
		t.Fatal(err)
	}
	grantPolicyAuthorForProject(h.projectID.String())

	before := readPolicyCounter(t, "policy_rules_denied_total",
		map[string]string{"reason": "workflow_not_authorable"})

	resp, body := doPolicyJSON(t, h.app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", h.projectID),
		map[string]any{
			"name":        "should-fail-authorable",
			"selector":    map[string]any{"environment_kind": "non_prod"},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	parsed := decode(t, body)
	if parsed["error_code"] != "workflow_not_authorable_for_scope" {
		t.Fatalf("error_code = %v, want workflow_not_authorable_for_scope", parsed["error_code"])
	}
	if parsed["workflow_id"] != h.workflowID.String() {
		t.Fatalf("workflow_id = %v, want %s", parsed["workflow_id"], h.workflowID)
	}
	after := readPolicyCounter(t, "policy_rules_denied_total",
		map[string]string{"reason": "workflow_not_authorable"})
	if after-before != 1 {
		t.Fatalf("denied counter delta = %v, want 1", after-before)
	}

	// Audit row exists + does NOT carry policy_rule_id + DOES carry
	// attempted_workflow_id.
	var hasRuleID bool
	var attemptedWorkflowID string
	if err := h.pool.QueryRow(t.Context(),
		`SELECT metadata ? 'policy_rule_id',
		        metadata->>'attempted_workflow_id'
		 FROM audit_events
		 WHERE action='policy.denied_workflow_not_authorable'
		 ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&hasRuleID, &attemptedWorkflowID); err != nil {
		t.Fatal(err)
	}
	if hasRuleID {
		t.Fatal("denied_workflow_not_authorable audit must NOT carry policy_rule_id")
	}
	if attemptedWorkflowID != h.workflowID.String() {
		t.Fatalf("attempted_workflow_id = %s, want %s", attemptedWorkflowID, h.workflowID)
	}

}

// Silence services import warning — used implicitly through the
// shared scoped policy harness.
var _ = services.PlatformReservedPriority
