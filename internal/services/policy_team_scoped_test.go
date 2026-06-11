// R-follow-up #3 (api#125) slice 1b tests — CreateForTeamScopedAuthor
// + UpdateForTeamScopedAuthor + DeleteForTeamScopedAuthor gate chains
// + selector validation + audit emission shapes.
//
// One test per locked gate so a future regression that swaps gates
// fails on a specific test name. Coverage for §4 C5 reordering, §4 C4
// workflow-collapse, R-follow-up #2 §3 critical pin, anchor routing.

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

// ---- env --------------------------------------------------------

type teamPolicyEnv struct {
	ctx        context.Context
	pool       *storage.Pool
	engine     *services.PolicyEngine
	teamID     uuid.UUID
	otherTeam  uuid.UUID
	workflowID uuid.UUID
}

func setupTeamPolicyEnv(t *testing.T) teamPolicyEnv {
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
		DELETE FROM projects;
		DELETE FROM team_members;
		DELETE FROM teams;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}
	// Re-seed the platform default match-all rule per the CASCADE
	// workaround established by EPIC R tests.
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
	// Flip the seed standard workflow's authorable flag so gate 5
	// passes by default in tests. Real deployments expect platform
	// admin to do this explicitly.
	if _, err := pool.Exec(ctx,
		`UPDATE workflow_definitions SET scoped_policy_authorable=true WHERE name='standard'`,
	); err != nil {
		t.Fatalf("flip authorable: %v", err)
	}

	// Two teams: one the actor covers, one they don't.
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

	engine := services.NewPolicyEngine(
		storage.NewPolicies(pool),
		storage.NewWorkflows(pool),
		storage.NewAuditEvents(pool),
	).WithEnvironments(storage.NewEnvironments(pool)).
		WithTeams(teamsRepo)

	return teamPolicyEnv{
		ctx: ctx, pool: pool, engine: engine,
		teamID: covered.ID, otherTeam: other.ID, workflowID: workflowID,
	}
}

func (e *teamPolicyEnv) withCovers() *services.PolicyEngine {
	return e.engine.WithAuthorScope(
		&stubResolver{grants: []auth.Grant{
			{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"team_id": e.teamID.String()}},
		}},
		&stubTeamScope{
			desc: map[uuid.UUID][]uuid.UUID{e.teamID: {e.teamID}},
		},
	)
}

func (e *teamPolicyEnv) withoutCoverage() *services.PolicyEngine {
	return e.engine.WithAuthorScope(
		&stubResolver{grants: []auth.Grant{
			{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"team_id": e.otherTeam.String()}},
		}},
		&stubTeamScope{
			desc: map[uuid.UUID][]uuid.UUID{e.otherTeam: {e.otherTeam}},
		},
	)
}

func nonProdSelectorTeam() map[string]any {
	return map[string]any{"environment_kind": "non_prod"}
}

// ---- Create chain ------------------------------------------------

func TestCreateForTeamScopedAuthor_Gate1_OutOfScope_EmitsDeniedAudit_NoRuleID(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	svc := e.withoutCoverage()
	_, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "denied",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "mallory",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrOutOfScopeTeamPolicy) {
		t.Fatalf("want ErrOutOfScopeTeamPolicy, got %v", err)
	}
	// Audit emitted with attempted_team_id + scope=team + NO policy_rule_id.
	var hasRuleID bool
	var scope, attemptedTeamID string
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata ? 'policy_rule_id',
		        metadata->>'scope',
		        metadata->>'attempted_team_id'
		   FROM audit_events
		  WHERE action='policy.denied_out_of_scope' AND actor='mallory'
		  ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&hasRuleID, &scope, &attemptedTeamID); err != nil {
		t.Fatal(err)
	}
	if hasRuleID {
		t.Error("denied audit must NOT include policy_rule_id")
	}
	if scope != "team" {
		t.Errorf("expected scope=team, got %q", scope)
	}
	if attemptedTeamID != e.teamID.String() {
		t.Errorf("attempted_team_id mismatch: got %q", attemptedTeamID)
	}
}

func TestCreateForTeamScopedAuthor_Gate2_TeamNotFound_RaceWindow(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	// Grant coverage of a team_id that doesn't exist; the resolver
	// will report coverage (via stubs) but gate 2 will fail to load.
	missing := uuid.New()
	svc := e.engine.WithAuthorScope(
		&stubResolver{grants: []auth.Grant{
			{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"team_id": missing.String()}},
		}},
		&stubTeamScope{desc: map[uuid.UUID][]uuid.UUID{missing: {missing}}},
	)
	_, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        missing,
		Name:          "x",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrTeamNotFound) {
		t.Fatalf("want ErrTeamNotFound, got %v", err)
	}
}

func TestCreateForTeamScopedAuthor_Gate2_ArchivedTeamReturnsNotFound(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	// Archive the covered team.
	if _, err := e.pool.Exec(e.ctx,
		`UPDATE teams SET status='archived' WHERE id=$1`, e.teamID,
	); err != nil {
		t.Fatalf("archive: %v", err)
	}
	svc := e.withCovers()
	_, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "x",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrTeamNotFound) {
		t.Fatalf("want ErrTeamNotFound for archived team, got %v", err)
	}
}

func TestCreateForTeamScopedAuthor_Gate3_PriorityReserved(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "too-high",
		Selector:      nonProdSelectorTeam(),
		Priority:      services.PlatformReservedPriority, // exactly at the cap
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPolicyPriorityReserved) {
		t.Fatalf("want ErrPolicyPriorityReserved, got %v", err)
	}
}

func TestCreateForTeamScopedAuthor_Gate4_SelectorPinsProject(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "pins-project",
		Selector:      map[string]any{"environment_kind": "non_prod", "project_id": uuid.New().String()},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	var detail *services.PolicyScopeTooBroadDetail
	if !errors.As(err, &detail) {
		t.Fatalf("want PolicyScopeTooBroadDetail, got %v", err)
	}
	if detail.Reason != services.PolicyScopeTooBroadTeamSelectorPinsProject {
		t.Errorf("reason=%q want %q", detail.Reason, services.PolicyScopeTooBroadTeamSelectorPinsProject)
	}
}

func TestCreateForTeamScopedAuthor_Gate4_SelectorPinsEnvironmentID(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "pins-env-id",
		Selector:      map[string]any{"environment_kind": "non_prod", "environment_id": uuid.New().String()},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	var detail *services.PolicyScopeTooBroadDetail
	if !errors.As(err, &detail) {
		t.Fatalf("want PolicyScopeTooBroadDetail, got %v", err)
	}
	if detail.Reason != services.PolicyScopeTooBroadTeamSelectorPinsEnvironmentID {
		t.Errorf("reason=%q want %q", detail.Reason, services.PolicyScopeTooBroadTeamSelectorPinsEnvironmentID)
	}
}

func TestCreateForTeamScopedAuthor_Gate4_SelectorPinsTeamID(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "pins-team-id",
		Selector:      map[string]any{"environment_kind": "non_prod", "team_id": e.teamID.String()},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	var detail *services.PolicyScopeTooBroadDetail
	if !errors.As(err, &detail) {
		t.Fatalf("want PolicyScopeTooBroadDetail, got %v", err)
	}
	if detail.Reason != services.PolicyScopeTooBroadTeamSelectorPinsTeamID {
		t.Errorf("reason=%q want %q", detail.Reason, services.PolicyScopeTooBroadTeamSelectorPinsTeamID)
	}
}

func TestCreateForTeamScopedAuthor_Gate4_MissingEnvKind(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "no-env",
		Selector:      map[string]any{"secret_ref_prefix": "billing/"},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	var detail *services.PolicyScopeTooBroadDetail
	if !errors.As(err, &detail) {
		t.Fatalf("want PolicyScopeTooBroadDetail, got %v", err)
	}
	if detail.Reason != services.PolicyScopeTooBroadEnvConstraintMissing {
		t.Errorf("reason=%q want %q", detail.Reason, services.PolicyScopeTooBroadEnvConstraintMissing)
	}
}

func TestCreateForTeamScopedAuthor_Gate5_WorkflowCollapse_NotAuthorable(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	// Disable the authorable flag on the seed workflow.
	if _, err := e.pool.Exec(e.ctx,
		`UPDATE workflow_definitions SET scoped_policy_authorable=false WHERE name='standard'`,
	); err != nil {
		t.Fatalf("flip false: %v", err)
	}
	svc := e.withCovers()
	_, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "wf-not-authorable",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	var detail *services.WorkflowNotAuthorableDetail
	if !errors.As(err, &detail) {
		t.Fatalf("want WorkflowNotAuthorableDetail, got %v", err)
	}
	if detail.WorkflowID != e.workflowID {
		t.Errorf("workflow_id mismatch in detail")
	}
}

func TestCreateForTeamScopedAuthor_Gate5_WorkflowCollapse_NotFound(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	svc := e.withCovers()
	_, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "wf-missing",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    uuid.New(),
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	var detail *services.WorkflowNotAuthorableDetail
	if !errors.As(err, &detail) {
		t.Fatalf("want WorkflowNotAuthorableDetail (collapse), got %v", err)
	}
}

func TestCreateForTeamScopedAuthor_HappyPath_EmitsSuccessAuditWithScope(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	svc := e.withCovers()
	rule, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "happy",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rule.TeamID == nil || *rule.TeamID != e.teamID {
		t.Fatalf("rule.TeamID not stamped from URL")
	}
	if rule.ProjectID != nil {
		t.Errorf("rule.ProjectID must be nil for team rule, got %v", rule.ProjectID)
	}
	// Audit event has scope=team + team_id + actor_permission_used=policy.author.
	// R-follow-up #5 slice 1b: also asserts the new name + enabled
	// snapshot fields surface for PolicyHistoryService to diff.
	var scope, teamID, perm, name, enabled string
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata->>'scope',
		        metadata->>'team_id',
		        metadata->>'actor_permission_used',
		        metadata->>'name',
		        metadata->>'enabled'
		   FROM audit_events
		  WHERE action='policy.create' AND actor='alice'
		  ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&scope, &teamID, &perm, &name, &enabled); err != nil {
		t.Fatal(err)
	}
	if scope != "team" {
		t.Errorf("scope=%q want team", scope)
	}
	if teamID != e.teamID.String() {
		t.Errorf("team_id mismatch")
	}
	if perm != string(auth.PermPolicyAuthor) {
		t.Errorf("actor_permission_used=%q", perm)
	}
	if name == "" {
		t.Errorf("R5 slice 1b: name missing from audit metadata")
	}
	if enabled != "true" && enabled != "false" {
		t.Errorf("R5 slice 1b: enabled missing from audit metadata, got %q", enabled)
	}
}

// ---- Update chain ------------------------------------------------

func TestUpdateForTeamScopedAuthor_URLMismatchReturnsPolicyNotFound(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	// Create a rule under teamID, then try to update via otherTeam's URL.
	svc := e.withCovers()
	rule, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "rule",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Actor has coverage of both teams to ensure gate 1 passes.
	svc2 := e.engine.WithAuthorScope(
		&stubResolver{grants: []auth.Grant{
			{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"team_id": e.teamID.String()}},
			{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"team_id": e.otherTeam.String()}},
		}},
		&stubTeamScope{
			desc: map[uuid.UUID][]uuid.UUID{
				e.teamID:    {e.teamID},
				e.otherTeam: {e.otherTeam},
			},
		},
	)
	newPriority := 200
	_, err = svc2.UpdateForTeamScopedAuthor(e.ctx, services.UpdateTeamScopedPolicyInput{
		RuleID:        rule.ID,
		TeamID:        e.otherTeam, // wrong team in URL
		Priority:      &newPriority,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	// MUST return policy_not_found per §4 lock — never out_of_scope.
	if !errors.Is(err, services.ErrPolicyNotFound) {
		t.Fatalf("want ErrPolicyNotFound on URL mismatch, got %v", err)
	}
}

func TestUpdateForTeamScopedAuthor_PriorityRevalidatesAgainstNewCap(t *testing.T) {
	// R-follow-up #2 §3 critical pin: Update revalidates against the
	// live cap on EVERY call, not just when priority is changing.
	// Use a no-op patch that doesn't touch priority — should still
	// re-validate against the cap.
	e := setupTeamPolicyEnv(t)
	svc := e.withCovers()

	// First — Create with priority 100 (below cap).
	rule, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "rule",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Now backdate the row's priority to ABOVE the cap (simulating
	// what would happen if admin lowered the cap after rules were
	// authored at the old higher priority).
	tooHigh := services.PlatformReservedPriority + 100
	if _, err := e.pool.Exec(e.ctx,
		`UPDATE policy_rules SET priority=$1 WHERE id=$2`, tooHigh, rule.ID,
	); err != nil {
		t.Fatalf("backdate priority: %v", err)
	}

	// Try a no-op-ish update (just toggle enabled). The merged final
	// priority is still the backdated tooHigh value — must be
	// rejected.
	enabled := false
	_, err = svc.UpdateForTeamScopedAuthor(e.ctx, services.UpdateTeamScopedPolicyInput{
		RuleID:        rule.ID,
		TeamID:        e.teamID,
		Enabled:       &enabled,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPolicyPriorityReserved) {
		t.Fatalf("want ErrPolicyPriorityReserved on Update revalidation, got %v", err)
	}
}

func TestUpdateForTeamScopedAuthor_ProjectRuleViaTeamURL_ReturnsNotFound(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	// Create a project rule directly (bypass scoped service).
	projID := uuid.New()
	if _, err := e.pool.Exec(e.ctx,
		`INSERT INTO projects (id, name) VALUES ($1, 'p')`, projID,
	); err != nil {
		t.Fatal(err)
	}
	repo := storage.NewPolicies(e.pool)
	projectRule := &storage.PolicyRule{
		Name: "project-rule", Selector: map[string]any{"environment_kind": "non_prod"},
		WorkflowID: e.workflowID, Priority: 100, Enabled: true, ProjectID: &projID,
	}
	if err := repo.Create(e.ctx, projectRule); err != nil {
		t.Fatal(err)
	}

	svc := e.withCovers()
	_, err := svc.UpdateForTeamScopedAuthor(e.ctx, services.UpdateTeamScopedPolicyInput{
		RuleID:        projectRule.ID,
		TeamID:        e.teamID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPolicyNotFound) {
		t.Fatalf("project rule via team URL should be not_found, got %v", err)
	}
}

func TestUpdateForTeamScopedAuthor_PlatformRowReturnsPlatformNotEditable(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	// Find the seed match-all platform rule.
	var ruleID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`SELECT id FROM policy_rules WHERE name='match-all (system default)'`,
	).Scan(&ruleID); err != nil {
		t.Fatal(err)
	}
	svc := e.withCovers()
	_, err := svc.UpdateForTeamScopedAuthor(e.ctx, services.UpdateTeamScopedPolicyInput{
		RuleID:        ruleID,
		TeamID:        e.teamID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPlatformPolicyNotEditable) {
		t.Fatalf("want ErrPlatformPolicyNotEditable, got %v", err)
	}
}

func TestUpdateForTeamScopedAuthor_WorkflowGrandfatherPreserves(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	svc := e.withCovers()

	// Create — workflow authorable at write time.
	rule, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "rule",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Admin opts the workflow out.
	if _, err := e.pool.Exec(e.ctx,
		`UPDATE workflow_definitions SET scoped_policy_authorable=false WHERE id=$1`, e.workflowID,
	); err != nil {
		t.Fatal(err)
	}

	// Pure priority update — workflow attachment unchanged. Should
	// succeed despite the workflow being opted out (grandfather).
	newPriority := 150
	_, err = svc.UpdateForTeamScopedAuthor(e.ctx, services.UpdateTeamScopedPolicyInput{
		RuleID:        rule.ID,
		TeamID:        e.teamID,
		Priority:      &newPriority,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("grandfather rule should preserve untouched workflow, got %v", err)
	}
}

// ---- Delete chain ------------------------------------------------

func TestDeleteForTeamScopedAuthor_HappyPath_EmitsAuditWithScope(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	svc := e.withCovers()
	rule, err := svc.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "to-delete",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteForTeamScopedAuthor(e.ctx, services.DeleteTeamScopedPolicyInput{
		RuleID:        rule.ID,
		TeamID:        e.teamID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var scope, teamID string
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata->>'scope', metadata->>'team_id'
		   FROM audit_events
		  WHERE action='policy.delete' AND actor='alice'
		  ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&scope, &teamID); err != nil {
		t.Fatal(err)
	}
	if scope != "team" {
		t.Errorf("scope=%q want team", scope)
	}
	if teamID != e.teamID.String() {
		t.Errorf("team_id mismatch")
	}
}

func TestDeleteForTeamScopedAuthor_PlatformRowReturnsNotEditable(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	var ruleID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`SELECT id FROM policy_rules WHERE name='match-all (system default)'`,
	).Scan(&ruleID); err != nil {
		t.Fatal(err)
	}
	svc := e.withCovers()
	err := svc.DeleteForTeamScopedAuthor(e.ctx, services.DeleteTeamScopedPolicyInput{
		RuleID:        ruleID,
		TeamID:        e.teamID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPlatformPolicyNotEditable) {
		t.Fatalf("want ErrPlatformPolicyNotEditable, got %v", err)
	}
}

func TestDeleteForTeamScopedAuthor_OutOfScopeReturnsTeamScopeError(t *testing.T) {
	e := setupTeamPolicyEnv(t)
	// Create a rule on the covered team using a "covered" actor, then
	// try to delete with an actor who doesn't cover.
	svcCovered := e.withCovers()
	rule, err := svcCovered.CreateForTeamScopedAuthor(e.ctx, services.CreateTeamScopedPolicyInput{
		TeamID:        e.teamID,
		Name:          "rule",
		Selector:      nonProdSelectorTeam(),
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := e.withoutCoverage()
	err = svc.DeleteForTeamScopedAuthor(e.ctx, services.DeleteTeamScopedPolicyInput{
		RuleID:        rule.ID,
		TeamID:        e.teamID,
		ActorID:       "mallory",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrOutOfScopeTeamPolicy) {
		t.Fatalf("want ErrOutOfScopeTeamPolicy, got %v", err)
	}
}
