// R-follow-up #3 (api#126) slice 1c handler tests — team-anchored
// scoped policy rules + /me/policy-author-team-coverage endpoint +
// team-lineage transactional audit.

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

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// identityTeamScope expands a team_id-scoped grant to the team itself
// (descendant set = {root}). The handler-package stubTeamScopeHandler
// returns empty descendants and is wrong for team-scoped tests.
type identityTeamScope struct{}

func (identityTeamScope) DescendantTeamIDs(_ context.Context, root uuid.UUID) ([]uuid.UUID, error) {
	return []uuid.UUID{root}, nil
}
func (identityTeamScope) ProjectIDsForTeams(_ context.Context, _ []uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

type teamPolicyHarness struct {
	app        *fiber.App
	pool       *storage.Pool
	resolver   *stubResolver
	teamID     uuid.UUID
	otherTeam  uuid.UUID
	workflowID uuid.UUID
}

func bootstrapTeamPolicies(t *testing.T) *teamPolicyHarness {
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
		DELETE FROM projects;
		DELETE FROM team_members;
		DELETE FROM teams;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}
	const reseed = `
		INSERT INTO policy_rules (name, selector, workflow_id, priority, is_system)
		SELECT 'match-all (system default)', '{}'::jsonb,
		       (SELECT id FROM workflow_definitions WHERE name = 'standard'),
		       0, true
		WHERE NOT EXISTS (SELECT 1 FROM policy_rules WHERE name = 'match-all (system default)');`
	if _, err := pool.Exec(ctx, reseed); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE workflow_definitions SET scoped_policy_authorable=true WHERE name='standard'`,
	); err != nil {
		t.Fatalf("flip authorable: %v", err)
	}

	teamsRepo := storage.NewTeams(pool)
	covered := &storage.Team{Name: "covered"}
	if err := teamsRepo.Create(ctx, covered); err != nil {
		t.Fatalf("teams.Create covered: %v", err)
	}
	other := &storage.Team{Name: "other"}
	if err := teamsRepo.Create(ctx, other); err != nil {
		t.Fatalf("teams.Create other: %v", err)
	}

	var workflowID uuid.UUID
	if err := pool.QueryRow(ctx,
		`SELECT id FROM workflow_definitions WHERE name = 'standard'`,
	).Scan(&workflowID); err != nil {
		t.Fatal(err)
	}

	resolver := &stubResolver{}
	engine := services.NewPolicyEngine(
		storage.NewPolicies(pool),
		storage.NewWorkflows(pool),
		storage.NewAuditEvents(pool),
	).WithAuthorScope(resolver, identityTeamScope{}).
		WithTeams(teamsRepo)

	app := fiber.New()
	v1 := app.Group("/api/v1")
	app.Use(testAuthMW)

	tprH := handlers.NewTeamPolicyRules(engine, storage.NewPolicies(pool), nil)
	v1.Post("/teams/:teamID/policy-rules", tprH.Create)
	v1.Get("/teams/:teamID/policy-rules", tprH.List)
	v1.Get("/teams/:teamID/policy-rules/:ruleID", tprH.Get)
	v1.Put("/teams/:teamID/policy-rules/:ruleID", tprH.Update)
	v1.Delete("/teams/:teamID/policy-rules/:ruleID", tprH.Delete)

	patcH := handlers.NewPolicyAuthorTeamCoverage(resolver, identityTeamScope{})
	v1.Get("/users/me/policy-author-team-coverage", patcH.Get)

	currentResolver = resolver
	return &teamPolicyHarness{
		app: app, pool: pool, resolver: resolver,
		teamID: covered.ID, otherTeam: other.ID, workflowID: workflowID,
	}
}

func grantPolicyAuthorForTeam(teamIDs ...string) {
	grants := make([]auth.Grant, 0, len(teamIDs))
	for _, tid := range teamIDs {
		grants = append(grants, auth.Grant{
			Permission: string(auth.PermPolicyAuthor),
			Scope:      map[string]string{"team_id": tid},
		})
	}
	currentResolver.grants = grants
}

func doTeamPolicyJSON(t *testing.T, app *fiber.App, method, path string, body any) (*http.Response, []byte) {
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

// --- POST /teams/:teamID/policy-rules ---------------------------

func TestTeamPolicyCreate_OutOfScopeReturns403(t *testing.T) {
	h := bootstrapTeamPolicies(t)
	grantPolicyAuthorForTeam(h.otherTeam.String())
	resp, body := doTeamPolicyJSON(t, h.app, "POST",
		"/api/v1/teams/"+h.teamID.String()+"/policy-rules",
		map[string]any{
			"name":        "denied",
			"selector":    map[string]any{"environment_kind": "non_prod"},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	_ = json.Unmarshal(body, &env)
	if env["error_code"] != "out_of_scope_team_policy" {
		t.Errorf("error_code=%v want out_of_scope_team_policy", env["error_code"])
	}
}

func TestTeamPolicyCreate_HappyPath_ReturnsRuleAndCap(t *testing.T) {
	h := bootstrapTeamPolicies(t)
	grantPolicyAuthorForTeam(h.teamID.String())
	resp, body := doTeamPolicyJSON(t, h.app, "POST",
		"/api/v1/teams/"+h.teamID.String()+"/policy-rules",
		map[string]any{
			"name":        "happy",
			"selector":    map[string]any{"environment_kind": "non_prod"},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if _, ok := env["rule"]; !ok {
		t.Fatalf("missing rule field; body=%s", body)
	}
	if _, ok := env["priority_cap"]; !ok {
		t.Fatalf("missing priority_cap field; body=%s", body)
	}
	rule := env["rule"].(map[string]any)
	if rule["team_id"] != h.teamID.String() {
		t.Errorf("rule.team_id mismatch")
	}
	if rule["is_platform_inherited"] != false {
		t.Errorf("is_platform_inherited should be false on own row")
	}
	if rule["is_ancestor_inherited"] != false {
		t.Errorf("is_ancestor_inherited should be false on own row")
	}
}

func TestTeamPolicyCreate_SelectorPinsProject_ReturnsScopeTooBroad(t *testing.T) {
	h := bootstrapTeamPolicies(t)
	grantPolicyAuthorForTeam(h.teamID.String())
	resp, body := doTeamPolicyJSON(t, h.app, "POST",
		"/api/v1/teams/"+h.teamID.String()+"/policy-rules",
		map[string]any{
			"name":        "pins",
			"selector":    map[string]any{"environment_kind": "non_prod", "project_id": uuid.New().String()},
			"priority":    100,
			"workflow_id": h.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	_ = json.Unmarshal(body, &env)
	if env["error_code"] != "policy_scope_too_broad" {
		t.Errorf("error_code=%v want policy_scope_too_broad", env["error_code"])
	}
	if env["reason"] != "team_selector_pins_project" {
		t.Errorf("reason=%v want team_selector_pins_project", env["reason"])
	}
}

// --- GET /teams/:teamID/policy-rules -----------------------------

func TestTeamPolicyList_OutOfScopeReturns403(t *testing.T) {
	h := bootstrapTeamPolicies(t)
	grantPolicyAuthorForTeam(h.otherTeam.String())
	resp, body := doTeamPolicyJSON(t, h.app, "GET",
		"/api/v1/teams/"+h.teamID.String()+"/policy-rules", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}

func TestTeamPolicyList_HappyPath_ReturnsOwnRuleWithCap(t *testing.T) {
	h := bootstrapTeamPolicies(t)
	grantPolicyAuthorForTeam(h.teamID.String())
	// Create a rule first.
	_, _ = doTeamPolicyJSON(t, h.app, "POST",
		"/api/v1/teams/"+h.teamID.String()+"/policy-rules",
		map[string]any{
			"name": "r1", "selector": map[string]any{"environment_kind": "non_prod"},
			"priority": 100, "workflow_id": h.workflowID.String(), "enabled": true,
		})
	resp, body := doTeamPolicyJSON(t, h.app, "GET",
		"/api/v1/teams/"+h.teamID.String()+"/policy-rules", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	_ = json.Unmarshal(body, &env)
	rules := env["rules"].([]any)
	if len(rules) == 0 {
		t.Fatalf("expected at least one rule; body=%s", body)
	}
	if _, ok := env["priority_cap"]; !ok {
		t.Errorf("missing priority_cap")
	}
	// At least one own rule should carry the full selector.
	hasOwn := false
	for _, r := range rules {
		m := r.(map[string]any)
		if m["is_platform_inherited"] == false && m["is_ancestor_inherited"] == false {
			hasOwn = true
			if _, ok := m["selector"]; !ok {
				t.Errorf("own row must expose selector; got %v", m)
			}
		}
	}
	if !hasOwn {
		t.Errorf("expected an own row; got %v", rules)
	}
}

func TestTeamPolicyList_InheritedPlatformRow_OmitsSelector(t *testing.T) {
	h := bootstrapTeamPolicies(t)
	grantPolicyAuthorForTeam(h.teamID.String())
	// Seed a platform row with sensitive selector value.
	_, err := h.pool.Exec(t.Context(),
		`INSERT INTO policy_rules (name, selector, workflow_id, priority)
		 VALUES ('plat', '{"secret_ref_prefix":"VERY-SECRET/"}'::jsonb, $1, 9100)`,
		h.workflowID,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := doTeamPolicyJSON(t, h.app, "GET",
		"/api/v1/teams/"+h.teamID.String()+"/policy-rules", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte("VERY-SECRET")) {
		t.Errorf("selector value leaked in inherited projection: %s", body)
	}
}

// --- DELETE -----------------------------------------------------

func TestTeamPolicyDelete_PlatformRowReturnsNotEditable(t *testing.T) {
	h := bootstrapTeamPolicies(t)
	grantPolicyAuthorForTeam(h.teamID.String())
	var platformID uuid.UUID
	if err := h.pool.QueryRow(t.Context(),
		`SELECT id FROM policy_rules WHERE name='match-all (system default)'`,
	).Scan(&platformID); err != nil {
		t.Fatal(err)
	}
	resp, body := doTeamPolicyJSON(t, h.app, "DELETE",
		"/api/v1/teams/"+h.teamID.String()+"/policy-rules/"+platformID.String(), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	_ = json.Unmarshal(body, &env)
	if env["error_code"] != "platform_policy_not_editable" {
		t.Errorf("error_code=%v want platform_policy_not_editable", env["error_code"])
	}
}

// --- /me/policy-author-team-coverage ----------------------------

func TestPolicyAuthorTeamCoverage_ReturnsActorTeams(t *testing.T) {
	h := bootstrapTeamPolicies(t)
	grantPolicyAuthorForTeam(h.teamID.String())
	resp, body := doTeamPolicyJSON(t, h.app, "GET",
		"/api/v1/users/me/policy-author-team-coverage", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	_ = json.Unmarshal(body, &env)
	if env["global"] != false {
		t.Errorf("global=%v want false", env["global"])
	}
	teamIDs := env["team_ids"].([]any)
	if len(teamIDs) == 0 || teamIDs[0] != h.teamID.String() {
		t.Errorf("team_ids=%v want [%s]", teamIDs, h.teamID.String())
	}
}

func TestPolicyAuthorTeamCoverage_EmptyWhenNoGrant(t *testing.T) {
	h := bootstrapTeamPolicies(t)
	grantPolicyAuthorForTeam() // empty
	resp, body := doTeamPolicyJSON(t, h.app, "GET",
		"/api/v1/users/me/policy-author-team-coverage", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	_ = json.Unmarshal(body, &env)
	teamIDs := env["team_ids"].([]any)
	if len(teamIDs) != 0 {
		t.Errorf("expected empty team_ids; got %v", teamIDs)
	}
}

// --- Team lineage transactional audit ---------------------------

func TestTeamLineageChanged_EmittedInsideTransaction(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	// Clean teams + policy_rules + projects + audit.
	if _, err := pool.Exec(ctx, `
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM projects;
		DELETE FROM team_members;
		DELETE FROM teams;`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE audit_events`); err != nil {
		t.Fatal(err)
	}

	teams := storage.NewTeams(pool)
	audit := storage.NewAuditEvents(pool)

	parent := &storage.Team{Name: "parent"}
	if err := teams.Create(ctx, parent); err != nil {
		t.Fatal(err)
	}
	child := &storage.Team{Name: "child"}
	if err := teams.Create(ctx, child); err != nil {
		t.Fatal(err)
	}
	other := &storage.Team{Name: "other-parent"}
	if err := teams.Create(ctx, other); err != nil {
		t.Fatal(err)
	}

	// Move child under parent.
	if err := teams.UpdateWithLineageAudit(ctx, child.ID, "child", "", &parent.ID,
		"alice", audit,
	); err != nil {
		t.Fatalf("first move: %v", err)
	}
	// Move child to other parent.
	if err := teams.UpdateWithLineageAudit(ctx, child.ID, "child", "", &other.ID,
		"alice", audit,
	); err != nil {
		t.Fatalf("second move: %v", err)
	}

	// Both moves should have emitted audit events (parent changed
	// from NULL → parent → other).
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action='policy.team_lineage_changed'`,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected 2 lineage_changed events, got %d", count)
	}

	// Most recent event metadata carries the new parent.
	var newParent string
	if err := pool.QueryRow(ctx,
		`SELECT metadata->>'new_parent_team_id' FROM audit_events
		   WHERE action='policy.team_lineage_changed'
		   ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&newParent); err != nil {
		t.Fatal(err)
	}
	if newParent != other.ID.String() {
		t.Errorf("new_parent_team_id=%q want %q", newParent, other.ID.String())
	}
}

func TestTeamLineageChanged_NoEventWhenParentUnchanged(t *testing.T) {
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM projects;
		DELETE FROM team_members;
		DELETE FROM teams;`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE audit_events`); err != nil {
		t.Fatal(err)
	}

	teams := storage.NewTeams(pool)
	audit := storage.NewAuditEvents(pool)

	parent := &storage.Team{Name: "parent"}
	if err := teams.Create(ctx, parent); err != nil {
		t.Fatal(err)
	}
	child := &storage.Team{Name: "child", ParentTeamID: &parent.ID}
	if err := teams.Create(ctx, child); err != nil {
		t.Fatal(err)
	}

	// Name change ONLY — parent stays the same.
	if err := teams.UpdateWithLineageAudit(ctx, child.ID, "child-renamed", "", &parent.ID,
		"alice", audit,
	); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE action='policy.team_lineage_changed'`,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 lineage_changed events for unchanged parent, got %d", count)
	}
}
