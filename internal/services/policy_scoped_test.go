// EPIC R (api#108) Slice R1 tests — CreateForScopedAuthor +
// UpdateForScopedAuthor + DeleteForScopedAuthor gate chains, plus the
// resolver applicability filter + the DB CHECK defense-in-depth.
//
// One test per locked gate so a future regression that swaps gates
// fails on a specific test name. Plus the §3 Q9 selector-empty
// rejection, the §4 mismatch protection, and the §6 audit emission
// shapes (no policy_rule_id on the denied audit row).

package services_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

func setupScopedPolicyEnv(t *testing.T) scopedPolicyEnv {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL is required; skipping")
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
	// Re-seed match-all per EPIC R cascade workaround.
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
	// R-follow-up #1 (api#118) — the seed `standard` workflow is
	// default-deny under migration 0035. EPIC R tests use it as the
	// scoped author's workflow; flip the flag so Create gate 5b
	// (workflow_authorable) passes. Real deployments expect platform
	// admin to do this explicitly via /admin/workflows.
	if _, err := pool.Exec(ctx,
		`UPDATE workflow_definitions SET scoped_policy_authorable=true WHERE name='standard'`,
	); err != nil {
		t.Fatalf("flip scoped_policy_authorable on seed: %v", err)
	}

	// Seed: one project, one non_prod env, one prod env, one workflow.
	var projectID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (name) VALUES ('p-scoped-policy') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	var nonProdEnvID, prodEnvID uuid.UUID
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

	engine := services.NewPolicyEngine(
		storage.NewPolicies(pool),
		storage.NewWorkflows(pool),
		storage.NewAuditEvents(pool),
	).WithEnvironments(storage.NewEnvironments(pool))

	return scopedPolicyEnv{
		ctx:          ctx,
		pool:         pool,
		engine:       engine,
		projectID:    projectID,
		nonProdEnvID: nonProdEnvID,
		prodEnvID:    prodEnvID,
		workflowID:   workflowID,
	}
}

type scopedPolicyEnv struct {
	ctx          context.Context
	pool         *storage.Pool
	engine       *services.PolicyEngine
	projectID    uuid.UUID
	nonProdEnvID uuid.UUID
	prodEnvID    uuid.UUID
	workflowID   uuid.UUID
}

func (e *scopedPolicyEnv) withCovers() *services.PolicyEngine {
	return e.engine.WithAuthorScope(
		&stubResolver{grants: []auth.Grant{
			{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"project_id": e.projectID.String()}},
		}},
		&stubTeamScope{},
	)
}

func (e *scopedPolicyEnv) withoutCoverage() *services.PolicyEngine {
	other := uuid.New()
	return e.engine.WithAuthorScope(
		&stubResolver{grants: []auth.Grant{
			{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"project_id": other.String()}},
		}},
		&stubTeamScope{},
	)
}

// ---- BIND chain (6 gates, §3-locked order) ------------------------

func TestCreateForScopedAuthor_Gate1_OutOfScope_EmitsDeniedAudit_NoRuleID(t *testing.T) {
	// §3 + §6: actor coverage check runs FIRST; denied audit has NO
	// policy_rule_id (gate-order enumeration-leak protection).
	e := setupScopedPolicyEnv(t)
	svc := e.withoutCoverage()
	_, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "denied",
		Selector:      map[string]any{"environment_kind": "non_prod"},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "mallory",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrOutOfScopePolicy) {
		t.Fatalf("want ErrOutOfScopePolicy, got %v", err)
	}
	// Audit emit + no policy_rule_id in metadata.
	var hasRuleID bool
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata ? 'policy_rule_id' FROM audit_events
		 WHERE action='policy.denied_out_of_scope' AND actor='mallory'
		 ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&hasRuleID); err != nil {
		t.Fatal(err)
	}
	if hasRuleID {
		t.Fatalf("denied audit must NOT include policy_rule_id")
	}
}

func TestCreateForScopedAuthor_Gate2_PriorityReserved(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "too-high",
		Selector:      map[string]any{"environment_kind": "non_prod"},
		Priority:      services.PlatformReservedPriority, // exactly at the boundary
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPolicyPriorityReserved) {
		t.Fatalf("want ErrPolicyPriorityReserved, got %v", err)
	}
}

func TestCreateForScopedAuthor_Gate3_SelectorProjectMismatch(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	other := uuid.New()
	svc := e.withCovers()
	_, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID: e.projectID,
		Name:      "mismatch",
		Selector: map[string]any{
			"project_id":       other.String(),
			"environment_kind": "non_prod",
		},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPolicySelectorMismatch) {
		t.Fatalf("want ErrPolicySelectorMismatch, got %v", err)
	}
}

func TestCreateForScopedAuthor_Gate4_ScopeTooBroad_SelectorEmpty(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "empty-selector",
		Selector:      map[string]any{},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	var d *services.PolicyScopeTooBroadDetail
	if !errors.As(err, &d) {
		t.Fatalf("want PolicyScopeTooBroadDetail, got %v", err)
	}
	if d.Reason != services.PolicyScopeTooBroadSelectorEmpty {
		t.Fatalf("reason = %s want selector_empty", d.Reason)
	}
}

func TestCreateForScopedAuthor_Gate4_ScopeTooBroad_NoEnvKey(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "no-env",
		Selector:      map[string]any{"secret_ref_prefix": "billing/"},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	var d *services.PolicyScopeTooBroadDetail
	if !errors.As(err, &d) {
		t.Fatalf("want PolicyScopeTooBroadDetail, got %v", err)
	}
	if d.Reason != services.PolicyScopeTooBroadEnvConstraintMissing {
		t.Fatalf("reason = %s want env_constraint_missing", d.Reason)
	}
}

func TestCreateForScopedAuthor_Gate4_ProdEnvKind(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "prod-kind",
		Selector:      map[string]any{"environment_kind": "prod"},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrProdPolicyNotAllowedForScope) {
		t.Fatalf("want ErrProdPolicyNotAllowedForScope, got %v", err)
	}
}

func TestCreateForScopedAuthor_Gate4_ProdEnvID(t *testing.T) {
	// Critical §3 Q8 test: scoped author cannot create a selector with
	// environment_id pointing to a prod environment in their project.
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "prod-env-id",
		Selector:      map[string]any{"environment_id": e.prodEnvID.String()},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrProdPolicyNotAllowedForScope) {
		t.Fatalf("want ErrProdPolicyNotAllowedForScope, got %v", err)
	}
}

func TestCreateForScopedAuthor_Gate4_EnvIDNotInProject(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	// Create a different project with its own env.
	var otherProjectID, otherEnvID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO projects (name) VALUES ('p-other') RETURNING id`,
	).Scan(&otherProjectID); err != nil {
		t.Fatal(err)
	}
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
			VALUES ($1, 'dev', 'dev', 'non_prod', 1) RETURNING id`,
		otherProjectID,
	).Scan(&otherEnvID); err != nil {
		t.Fatal(err)
	}
	svc := e.withCovers()
	_, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "wrong-project-env",
		Selector:      map[string]any{"environment_id": otherEnvID.String()},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPolicyEnvironmentNotInProject) {
		t.Fatalf("want ErrPolicyEnvironmentNotInProject, got %v", err)
	}
}

func TestCreateForScopedAuthor_HappyPath_EmitsCreateAudit_SelectorKeysOnly(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()
	rule, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID: e.projectID,
		Name:      "happy",
		Selector: map[string]any{
			"environment_kind":  "non_prod",
			"secret_ref_prefix": "billing/very-secret-path/",
		},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("CreateForScopedAuthor: %v", err)
	}
	if rule == nil || rule.ProjectID == nil || *rule.ProjectID != e.projectID {
		t.Fatalf("rule project_id mismatch: %+v", rule)
	}
	// Audit: policy.create with selector KEYS only, actor_permission_used
	// = policy.author. Crucially: selector VALUE (the secret prefix)
	// must NOT appear in metadata text.
	var metadataText string
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata::text FROM audit_events
		 WHERE action='policy.create'
		 ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&metadataText); err != nil {
		t.Fatal(err)
	}
	if containsAll(metadataText, "billing/very-secret-path/") {
		t.Fatalf("selector value leaked into audit metadata: %s", metadataText)
	}
	if !containsAll(metadataText, "selector_keys", "policy.author") {
		t.Fatalf("audit metadata missing required keys: %s", metadataText)
	}
}

// ---- UPDATE chain (8 gates) ---------------------------------------

func TestUpdateForScopedAuthor_Gate1_OutOfScope(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	// Pass a bogus rule id — gate 1 should refuse before any rule load.
	svc := e.withoutCoverage()
	bogus := uuid.New()
	priority := 100
	_, err := svc.UpdateForScopedAuthor(e.ctx, services.UpdateScopedPolicyInput{
		RuleID:        bogus,
		ProjectID:     e.projectID,
		Priority:      &priority,
		ActorID:       "mallory",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrOutOfScopePolicy) {
		t.Fatalf("want ErrOutOfScopePolicy (gate-order: coverage before rule load); got %v", err)
	}
}

func TestUpdateForScopedAuthor_Gate3_WrongProject_ReturnsNotFound_NeverOutOfScope(t *testing.T) {
	// §4 correction: scoped DELETE/UPDATE where URL projectID doesn't
	// match the binding's stored project_id returns policy_not_found,
	// NEVER out_of_scope_policy (latter would leak existence).
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()
	rule, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "rule-on-alice-project",
		Selector:      map[string]any{"environment_kind": "non_prod"},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Create another project that alice ALSO covers.
	var otherProjectID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO projects (name) VALUES ('p-other-covered') RETURNING id`,
	).Scan(&otherProjectID); err != nil {
		t.Fatal(err)
	}
	covered := e.engine.WithAuthorScope(
		&stubResolver{grants: []auth.Grant{
			{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"project_id": e.projectID.String()}},
			{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"project_id": otherProjectID.String()}},
		}},
		&stubTeamScope{},
	)
	// URL claims otherProjectID; rule lives under e.projectID. Should
	// return not_found, not out_of_scope.
	priority := 200
	_, err = covered.UpdateForScopedAuthor(e.ctx, services.UpdateScopedPolicyInput{
		RuleID:        rule.ID,
		ProjectID:     otherProjectID,
		Priority:      &priority,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPolicyNotFound) {
		t.Fatalf("want ErrPolicyNotFound on project mismatch, got %v", err)
	}
}

func TestUpdateForScopedAuthor_Gate4_PlatformPolicyNotEditable(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()
	// Seed match-all has project_id IS NULL. Scoped author cannot edit it.
	var seedID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`SELECT id FROM policy_rules WHERE name = 'match-all (system default)'`,
	).Scan(&seedID); err != nil {
		t.Fatal(err)
	}
	priority := 200
	_, err := svc.UpdateForScopedAuthor(e.ctx, services.UpdateScopedPolicyInput{
		RuleID:        seedID,
		ProjectID:     e.projectID,
		Priority:      &priority,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPlatformPolicyNotEditable) {
		t.Fatalf("want ErrPlatformPolicyNotEditable, got %v", err)
	}
}

func TestUpdateForScopedAuthor_Gate7_RejectsExplicitEmptySelector(t *testing.T) {
	// §3 Q9 lock: nil selector preserves; explicit {} REJECTED for
	// scoped authors.
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()
	rule, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "to-update",
		Selector:      map[string]any{"environment_kind": "non_prod"},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	emptySelector := map[string]any{}
	_, err = svc.UpdateForScopedAuthor(e.ctx, services.UpdateScopedPolicyInput{
		RuleID:        rule.ID,
		ProjectID:     e.projectID,
		Selector:      &emptySelector,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	var d *services.PolicyScopeTooBroadDetail
	if !errors.As(err, &d) {
		t.Fatalf("want PolicyScopeTooBroadDetail (selector_empty), got %v", err)
	}
	if d.Reason != services.PolicyScopeTooBroadSelectorEmpty {
		t.Fatalf("reason = %s want selector_empty", d.Reason)
	}
}

// ---- DELETE chain (5 gates) ---------------------------------------

func TestDeleteForScopedAuthor_Gate1_OutOfScope(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	svc := e.withoutCoverage()
	err := svc.DeleteForScopedAuthor(e.ctx, services.DeleteScopedPolicyInput{
		RuleID:        uuid.New(),
		ProjectID:     e.projectID,
		ActorID:       "mallory",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrOutOfScopePolicy) {
		t.Fatalf("want ErrOutOfScopePolicy, got %v", err)
	}
}

func TestDeleteForScopedAuthor_HappyPath_EmitsDeleteAudit(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()
	rule, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "to-delete",
		Selector:      map[string]any{"environment_kind": "non_prod"},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteForScopedAuthor(e.ctx, services.DeleteScopedPolicyInput{
		RuleID:        rule.ID,
		ProjectID:     e.projectID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	}); err != nil {
		t.Fatalf("DeleteForScopedAuthor: %v", err)
	}
	// Audit: policy.delete with actor_permission_used = policy.author.
	var perm string
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata->>'actor_permission_used' FROM audit_events
		 WHERE action='policy.delete' ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&perm); err != nil {
		t.Fatal(err)
	}
	if perm != string(auth.PermPolicyAuthor) {
		t.Fatalf("perm = %s want policy.author", perm)
	}
}

// ---- DB CHECK defense-in-depth ------------------------------------

func TestDB_ScopedRuleWithProdSelector_CannotBeInserted(t *testing.T) {
	// §3 Q8: even if the service layer is bypassed, the DB CHECK from
	// migration 0033 rejects a scoped rule whose selector pins
	// environment_kind=prod.
	e := setupScopedPolicyEnv(t)
	_, err := e.pool.Exec(e.ctx,
		`INSERT INTO policy_rules (name, selector, workflow_id, priority, project_id)
		 VALUES ('db-bypass-prod', '{"environment_kind":"prod"}'::jsonb, $1, 100, $2)`,
		e.workflowID, e.projectID,
	)
	if err == nil {
		t.Fatal("expected DB CHECK to reject scoped rule with env_kind=prod selector")
	}
}

func TestDB_ScopedRuleWithEmptySelector_CannotBeInserted(t *testing.T) {
	// Companion: empty selector on a scoped row also fails the
	// "requires env" CHECK.
	e := setupScopedPolicyEnv(t)
	_, err := e.pool.Exec(e.ctx,
		`INSERT INTO policy_rules (name, selector, workflow_id, priority, project_id)
		 VALUES ('db-bypass-empty', '{}'::jsonb, $1, 100, $2)`,
		e.workflowID, e.projectID,
	)
	if err == nil {
		t.Fatal("expected DB CHECK to reject scoped rule with empty selector")
	}
}

// ---- Resolver applicability (5 tests) -----------------------------

func TestResolve_RequestWithoutProjectID_LoadsOnlyPlatformRules(t *testing.T) {
	// §2 correction: request without project_id must NOT see scoped
	// rules from any project. Resolver passes uuid.Nil → repo filters
	// to project_id IS NULL only.
	e := setupScopedPolicyEnv(t)
	// Insert a scoped rule directly via SQL (bypassing service-layer
	// gates we've already tested).
	if _, err := e.pool.Exec(e.ctx,
		`INSERT INTO policy_rules (name, selector, workflow_id, priority, project_id)
		 VALUES ('scoped-high-pri', '{"environment_kind":"non_prod"}'::jsonb, $1, 8000, $2)`,
		e.workflowID, e.projectID,
	); err != nil {
		t.Fatal(err)
	}
	// Resolve with empty scope (no project_id).
	dec, err := e.engine.Resolve(e.ctx, services.Scope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Should match the seed match-all (priority 0), NOT the scoped rule.
	if dec.MatchedRule == nil || dec.MatchedRule.Name != "match-all (system default)" {
		t.Fatalf("matched rule should be the platform seed, got: %+v", dec.MatchedRule)
	}
}

func TestResolve_ScopedRuleMatchesItsOwnProject(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	// Insert a scoped rule.
	var ruleID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO policy_rules (name, selector, workflow_id, priority, project_id)
		 VALUES ('scoped-non-prod', '{"environment_kind":"non_prod"}'::jsonb, $1, 100, $2)
		 RETURNING id`,
		e.workflowID, e.projectID,
	).Scan(&ruleID); err != nil {
		t.Fatal(err)
	}
	dec, err := e.engine.Resolve(e.ctx, services.Scope{
		ProjectID:       e.projectID.String(),
		EnvironmentKind: storage.EnvironmentKindNonProd,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dec.MatchedRule == nil || dec.MatchedRule.ID != ruleID {
		t.Fatalf("scoped rule should match its own project, got: %+v", dec.MatchedRule)
	}
}

func TestResolve_ScopedRuleA_NeverMatchesProjectB(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	if _, err := e.pool.Exec(e.ctx,
		`INSERT INTO policy_rules (name, selector, workflow_id, priority, project_id)
		 VALUES ('scoped-A', '{"environment_kind":"non_prod"}'::jsonb, $1, 8000, $2)`,
		e.workflowID, e.projectID,
	); err != nil {
		t.Fatal(err)
	}
	// Resolve scope for a different project — must NOT see project A's rule.
	otherProject := uuid.New().String()
	dec, err := e.engine.Resolve(e.ctx, services.Scope{
		ProjectID:       otherProject,
		EnvironmentKind: storage.EnvironmentKindNonProd,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dec.MatchedRule != nil && dec.MatchedRule.Name == "scoped-A" {
		t.Fatal("scoped rule from project A leaked into project B's resolution")
	}
}

func TestResolve_PlatformReservedBandWinsOverScoped(t *testing.T) {
	// Critical: platform rule at priority 9001 (in reserved band) wins
	// over a scoped rule at priority 8999, even though the scoped rule
	// would otherwise resolve.
	e := setupScopedPolicyEnv(t)
	var platformID, scopedID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO policy_rules (name, selector, workflow_id, priority, project_id)
		 VALUES ('platform-override', '{"environment_kind":"non_prod"}'::jsonb, $1, 9001, NULL)
		 RETURNING id`,
		e.workflowID,
	).Scan(&platformID); err != nil {
		t.Fatal(err)
	}
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO policy_rules (name, selector, workflow_id, priority, project_id)
		 VALUES ('scoped-top-band', '{"environment_kind":"non_prod"}'::jsonb, $1, 8999, $2)
		 RETURNING id`,
		e.workflowID, e.projectID,
	).Scan(&scopedID); err != nil {
		t.Fatal(err)
	}
	dec, err := e.engine.Resolve(e.ctx, services.Scope{
		ProjectID:       e.projectID.String(),
		EnvironmentKind: storage.EnvironmentKindNonProd,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dec.MatchedRule == nil || dec.MatchedRule.ID != platformID {
		t.Fatalf("platform reserved band must win, got: %+v", dec.MatchedRule)
	}
}

// containsAll returns true iff every needle appears in s.
func containsAll(s string, needles ...string) bool {
	for _, n := range needles {
		if !strContains(s, n) {
			return false
		}
	}
	return true
}

func strContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
