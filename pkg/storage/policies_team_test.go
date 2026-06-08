package storage_test

// R-follow-up #3 (api#114) slice 1a — storage tests for the team_id
// extension. Covers:
//
//   - Migration 0037 CHECK constraints reject malformed inserts
//   - Resolver query (ListEnabledOrderedByPriority) returns the
//     deterministic 5-clause tie-break: priority DESC → specificity
//     DESC (project > team > platform) → team distance ASC → created_at
//     ASC → id ASC
//   - ListForProject + ListForTeam apply the C4 filter (own rows any
//     enabled state; inherited rows enabled-only) and surface
//     workflow_name + team_name via the JOINs
//   - ErrAnchorImmutable on Update flipping the anchor

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// --- helpers ---------------------------------------------------------

func makeTeam(t *testing.T, pool *storage.Pool, name string, parent *uuid.UUID) uuid.UUID {
	t.Helper()
	teams := storage.NewTeams(pool)
	team := &storage.Team{Name: name, ParentTeamID: parent}
	if err := teams.Create(t.Context(), team); err != nil {
		t.Fatalf("teams.Create %q: %v", name, err)
	}
	return team.ID
}

func makeProjectWithTeam(t *testing.T, pool *storage.Pool, name string, teamID *uuid.UUID) uuid.UUID {
	t.Helper()
	repo := storage.NewProjects(pool)
	p := &storage.Project{Name: name, OwnerTeamID: "system"}
	if err := repo.Create(t.Context(), p); err != nil {
		t.Fatalf("projects.Create %q: %v", name, err)
	}
	if teamID != nil {
		if _, err := pool.Exec(t.Context(),
			`UPDATE projects SET team_id = $1 WHERE id = $2`, *teamID, p.ID,
		); err != nil {
			t.Fatalf("set team_id on project %q: %v", name, err)
		}
	}
	return p.ID
}

func seedStandardWorkflow(t *testing.T, pool *storage.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(),
		`SELECT id FROM workflow_definitions WHERE name = 'standard'`,
	).Scan(&id)
	if err != nil {
		t.Fatalf("look up seed standard workflow: %v", err)
	}
	return id
}

// nonProdSelector returns the minimal selector that satisfies the team
// rule's CHECK constraints (environment_kind=non_prod).
func nonProdSelector() map[string]any {
	return map[string]any{"environment_kind": "non_prod"}
}

// insertPolicyRow drops a row in directly via SQL so a test can
// construct rules with malformed shapes the Go-side Create wouldn't
// produce. Used for DB-CHECK testing.
func insertPolicyRow(t *testing.T, pool *storage.Pool, projectID, teamID *uuid.UUID, selectorJSON string, workflowID uuid.UUID) error {
	t.Helper()
	_, err := pool.Exec(t.Context(),
		`INSERT INTO policy_rules
		   (name, selector, workflow_id, priority, enabled, is_system, project_id, team_id)
		 VALUES ($1, $2::jsonb, $3, 100, true, false, $4, $5)`,
		"team-test-"+uuid.New().String()[:8], selectorJSON, workflowID, projectID, teamID,
	)
	return err
}

// --- DB-CHECK tests --------------------------------------------------

func TestDBCheck_RejectsMixedAnchor(t *testing.T) {
	pool := freshDB(t)
	teamID := makeTeam(t, pool, "billing", nil)
	projectID := makeProjectWithTeam(t, pool, "billing-app", &teamID)
	wf := seedStandardWorkflow(t, pool)

	err := insertPolicyRow(t, pool, &projectID, &teamID, `{"environment_kind":"non_prod"}`, wf)
	if err == nil {
		t.Fatal("expected mixed-anchor CHECK violation; got nil")
	}
	if !strings.Contains(err.Error(), "policy_rules_one_anchor") {
		t.Fatalf("expected one_anchor CHECK in error, got: %v", err)
	}
}

func TestDBCheck_RejectsTeamRuleWithProjectIDInSelector(t *testing.T) {
	pool := freshDB(t)
	teamID := makeTeam(t, pool, "billing", nil)
	wf := seedStandardWorkflow(t, pool)

	err := insertPolicyRow(t, pool, nil, &teamID,
		`{"environment_kind":"non_prod","project_id":"`+uuid.New().String()+`"}`, wf)
	if err == nil {
		t.Fatal("expected team_no_project_pin CHECK violation; got nil")
	}
	if !strings.Contains(err.Error(), "policy_rules_team_no_project_pin") {
		t.Fatalf("expected team_no_project_pin CHECK, got: %v", err)
	}
}

func TestDBCheck_RejectsTeamRuleWithEnvironmentIDInSelector(t *testing.T) {
	pool := freshDB(t)
	teamID := makeTeam(t, pool, "billing", nil)
	wf := seedStandardWorkflow(t, pool)

	err := insertPolicyRow(t, pool, nil, &teamID,
		`{"environment_kind":"non_prod","environment_id":"`+uuid.New().String()+`"}`, wf)
	if err == nil {
		t.Fatal("expected team_no_env_id_pin CHECK violation; got nil")
	}
	if !strings.Contains(err.Error(), "policy_rules_team_no_env_id_pin") {
		t.Fatalf("expected team_no_env_id_pin CHECK, got: %v", err)
	}
}

func TestDBCheck_RejectsTeamRuleWithTeamIDInSelector(t *testing.T) {
	pool := freshDB(t)
	teamID := makeTeam(t, pool, "billing", nil)
	wf := seedStandardWorkflow(t, pool)

	err := insertPolicyRow(t, pool, nil, &teamID,
		`{"environment_kind":"non_prod","team_id":"`+teamID.String()+`"}`, wf)
	if err == nil {
		t.Fatal("expected team_no_team_id_pin CHECK violation; got nil")
	}
	if !strings.Contains(err.Error(), "policy_rules_team_no_team_id_pin") {
		t.Fatalf("expected team_no_team_id_pin CHECK, got: %v", err)
	}
}

func TestDBCheck_RejectsTeamRuleWithoutNonProdEnvKind(t *testing.T) {
	pool := freshDB(t)
	teamID := makeTeam(t, pool, "billing", nil)
	wf := seedStandardWorkflow(t, pool)

	// Missing environment_kind entirely.
	if err := insertPolicyRow(t, pool, nil, &teamID, `{}`, wf); err == nil {
		t.Fatal("expected requires_non_prod_env_kind CHECK violation on empty selector; got nil")
	} else if !strings.Contains(err.Error(), "policy_rules_team_requires_non_prod_env_kind") {
		t.Fatalf("expected requires_non_prod CHECK, got: %v", err)
	}

	// Present but wrong value.
	if err := insertPolicyRow(t, pool, nil, &teamID, `{"environment_kind":"prod"}`, wf); err == nil {
		t.Fatal("expected requires_non_prod_env_kind CHECK violation on env_kind=prod; got nil")
	} else if !strings.Contains(err.Error(), "policy_rules_team_requires_non_prod_env_kind") {
		t.Fatalf("expected requires_non_prod CHECK, got: %v", err)
	}
}

// --- ListEnabledOrderedByPriority — deterministic ordering ----------

func TestListEnabled_ProjectWithoutTeam_NoTeamRules(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	// Two teams, one project that DOES belong to a team, another that
	// doesn't. A team rule on the first team should NOT appear in the
	// resolver result for the second project.
	teamA := makeTeam(t, pool, "team-alpha", nil)
	noTeamProject := makeProjectWithTeam(t, pool, "team-less-project", nil)

	// Team rule on team-alpha.
	tRule := &storage.PolicyRule{
		Name: "team-alpha rule", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: true, TeamID: &teamA,
	}
	if err := repo.Create(t.Context(), tRule); err != nil {
		t.Fatalf("create team rule: %v", err)
	}

	rules, err := repo.ListEnabledOrderedByPriority(t.Context(), noTeamProject)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, r := range rules {
		if r.TeamID != nil {
			t.Errorf("team rule (id=%s) should not resolve for team-less project", r.ID)
		}
	}
}

func TestListEnabled_ParentTeamRule_AppliesToChildProject(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	parent := makeTeam(t, pool, "parent-team", nil)
	child := makeTeam(t, pool, "child-team", &parent)
	childProject := makeProjectWithTeam(t, pool, "child-project", &child)

	parentRule := &storage.PolicyRule{
		Name: "parent rule", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 200, Enabled: true, TeamID: &parent,
	}
	if err := repo.Create(t.Context(), parentRule); err != nil {
		t.Fatalf("create parent rule: %v", err)
	}

	rules, err := repo.ListEnabledOrderedByPriority(t.Context(), childProject)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.ID == parentRule.ID {
			found = true
		}
	}
	if !found {
		t.Error("parent-team rule did not cascade to child project")
	}
}

func TestListEnabled_ChildTeamRule_DoesNotApplyToSibling(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	parent := makeTeam(t, pool, "parent-team", nil)
	childA := makeTeam(t, pool, "child-a", &parent)
	childB := makeTeam(t, pool, "child-b", &parent)
	siblingProject := makeProjectWithTeam(t, pool, "child-b-project", &childB)

	childARule := &storage.PolicyRule{
		Name: "child-a only", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: true, TeamID: &childA,
	}
	if err := repo.Create(t.Context(), childARule); err != nil {
		t.Fatalf("create child-a rule: %v", err)
	}

	rules, err := repo.ListEnabledOrderedByPriority(t.Context(), siblingProject)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, r := range rules {
		if r.ID == childARule.ID {
			t.Errorf("child-a rule resolved for sibling child-b's project (subtree-down lock violated)")
		}
	}
}

func TestListEnabled_ProjectRule_BeatsTeamRuleAtEqualPriority(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	team := makeTeam(t, pool, "team", nil)
	project := makeProjectWithTeam(t, pool, "project", &team)

	teamRule := &storage.PolicyRule{
		Name: "team rule", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: true, TeamID: &team,
	}
	projectRule := &storage.PolicyRule{
		Name: "project rule", Selector: map[string]any{"environment_kind": "non_prod"},
		WorkflowID: wf, Priority: 100, Enabled: true, ProjectID: &project,
	}
	if err := repo.Create(t.Context(), teamRule); err != nil {
		t.Fatalf("create team rule: %v", err)
	}
	if err := repo.Create(t.Context(), projectRule); err != nil {
		t.Fatalf("create project rule: %v", err)
	}

	rules, err := repo.ListEnabledOrderedByPriority(t.Context(), project)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) < 2 {
		t.Fatalf("expected at least 2 rules in result, got %d", len(rules))
	}
	if rules[0].ID != projectRule.ID {
		t.Errorf("project rule should outrank team rule at same priority; got id=%s first", rules[0].ID)
	}
}

func TestListEnabled_ChildTeamRule_BeatsParentTeamRuleAtEqualPriority(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	parent := makeTeam(t, pool, "parent", nil)
	child := makeTeam(t, pool, "child", &parent)
	project := makeProjectWithTeam(t, pool, "project", &child)

	parentRule := &storage.PolicyRule{
		Name: "parent", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: true, TeamID: &parent,
	}
	childRule := &storage.PolicyRule{
		Name: "child", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: true, TeamID: &child,
	}
	if err := repo.Create(t.Context(), parentRule); err != nil {
		t.Fatalf("create parent rule: %v", err)
	}
	if err := repo.Create(t.Context(), childRule); err != nil {
		t.Fatalf("create child rule: %v", err)
	}

	rules, err := repo.ListEnabledOrderedByPriority(t.Context(), project)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Both team rules must appear; child first per C2 tie-break.
	var posChild, posParent = -1, -1
	for i, r := range rules {
		switch r.ID {
		case childRule.ID:
			posChild = i
		case parentRule.ID:
			posParent = i
		}
	}
	if posChild < 0 || posParent < 0 {
		t.Fatalf("both rules expected in result; child=%d parent=%d", posChild, posParent)
	}
	if posChild >= posParent {
		t.Errorf("child-team rule (pos=%d) should appear before parent-team rule (pos=%d) on same priority", posChild, posParent)
	}
}

func TestListEnabled_IDStabilizesTieBreak(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	team := makeTeam(t, pool, "team", nil)
	project := makeProjectWithTeam(t, pool, "project", &team)

	// Two rules with identical priority + specificity + distance and
	// likely created_at (same millisecond). id ASC must stabilize.
	a := &storage.PolicyRule{
		Name: "rule-a", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: true, TeamID: &team,
	}
	b := &storage.PolicyRule{
		Name: "rule-b", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: true, TeamID: &team,
	}
	if err := repo.Create(t.Context(), a); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if err := repo.Create(t.Context(), b); err != nil {
		t.Fatalf("create b: %v", err)
	}

	// Run the query 5 times — ordering must be stable across runs.
	var lastOrder []uuid.UUID
	for i := 0; i < 5; i++ {
		rules, err := repo.ListEnabledOrderedByPriority(t.Context(), project)
		if err != nil {
			t.Fatalf("list iter %d: %v", i, err)
		}
		ids := []uuid.UUID{}
		for _, r := range rules {
			if r.ID == a.ID || r.ID == b.ID {
				ids = append(ids, r.ID)
			}
		}
		if i > 0 {
			if len(ids) != len(lastOrder) {
				t.Fatalf("iter %d returned a different number of rules (%d vs %d)", i, len(ids), len(lastOrder))
			}
			for j, id := range ids {
				if id != lastOrder[j] {
					t.Fatalf("iter %d order differs from iter 0 at position %d", i, j)
				}
			}
		}
		lastOrder = ids
	}
}

// --- ListForProject / ListForTeam ----------------------------------

func TestListForProject_FiltersDisabledInherited(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	team := makeTeam(t, pool, "team", nil)
	project := makeProjectWithTeam(t, pool, "project", &team)

	// Inherited team rule, DISABLED.
	disabledInherited := &storage.PolicyRule{
		Name: "disabled team rule", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: false, TeamID: &team,
	}
	// Own project rule, DISABLED — must still appear (own rows shown
	// regardless of enabled state).
	disabledOwn := &storage.PolicyRule{
		Name: "disabled project rule", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 50, Enabled: false, ProjectID: &project,
	}
	if err := repo.Create(t.Context(), disabledInherited); err != nil {
		t.Fatalf("create disabled team rule: %v", err)
	}
	if err := repo.Create(t.Context(), disabledOwn); err != nil {
		t.Fatalf("create disabled own rule: %v", err)
	}

	rules, err := repo.ListForProject(t.Context(), project)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	ownSeen, inheritedSeen := false, false
	for _, r := range rules {
		if r.ID == disabledOwn.ID {
			ownSeen = true
		}
		if r.ID == disabledInherited.ID {
			inheritedSeen = true
		}
	}
	if !ownSeen {
		t.Error("disabled own project rule should appear (C4: own rows any-enabled-state)")
	}
	if inheritedSeen {
		t.Error("disabled inherited team rule should NOT appear (C4: inherited enabled-only)")
	}
}

func TestListForProject_PopulatesWorkflowAndTeamName(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	team := makeTeam(t, pool, "billing", nil)
	project := makeProjectWithTeam(t, pool, "billing-app", &team)

	teamRule := &storage.PolicyRule{
		Name: "team rule", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: true, TeamID: &team,
	}
	if err := repo.Create(t.Context(), teamRule); err != nil {
		t.Fatalf("create team rule: %v", err)
	}

	rules, err := repo.ListForProject(t.Context(), project)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var got *storage.PolicyRule
	for _, r := range rules {
		if r.ID == teamRule.ID {
			got = r
			break
		}
	}
	if got == nil {
		t.Fatal("team rule missing from project list")
	}
	if got.WorkflowName != "standard" {
		t.Errorf("expected workflow_name=standard from JOIN, got %q", got.WorkflowName)
	}
	if got.TeamName != "billing" {
		t.Errorf("expected team_name=billing from JOIN, got %q", got.TeamName)
	}
}

func TestListForTeam_ExcludesProjectRules(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	team := makeTeam(t, pool, "team", nil)
	project := makeProjectWithTeam(t, pool, "project", &team)

	projectRule := &storage.PolicyRule{
		Name: "project only", Selector: map[string]any{"environment_kind": "non_prod"},
		WorkflowID: wf, Priority: 100, Enabled: true, ProjectID: &project,
	}
	if err := repo.Create(t.Context(), projectRule); err != nil {
		t.Fatalf("create project rule: %v", err)
	}

	rules, err := repo.ListForTeam(t.Context(), team)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, r := range rules {
		if r.ID == projectRule.ID {
			t.Error("project-scoped rule must not appear on team page (§1 Q3 lock)")
		}
	}
}

func TestListForTeam_IncludesAncestorTeamRules(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	parent := makeTeam(t, pool, "parent", nil)
	child := makeTeam(t, pool, "child", &parent)

	parentRule := &storage.PolicyRule{
		Name: "parent rule", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: true, TeamID: &parent,
	}
	if err := repo.Create(t.Context(), parentRule); err != nil {
		t.Fatalf("create parent rule: %v", err)
	}

	rules, err := repo.ListForTeam(t.Context(), child)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.ID == parentRule.ID {
			found = true
			// Ancestor row should surface the ancestor's team_name via JOIN.
			if r.TeamName != "parent" {
				t.Errorf("expected ancestor team_name=parent via JOIN, got %q", r.TeamName)
			}
		}
	}
	if !found {
		t.Error("ancestor-team rule should appear on child team page")
	}
}

// --- Update: anchor immutability -----------------------------------

func TestUpdate_RejectsAnchorFlip(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewPolicies(pool)
	wf := seedStandardWorkflow(t, pool)

	teamA := makeTeam(t, pool, "team-a", nil)
	teamB := makeTeam(t, pool, "team-b", nil)

	rule := &storage.PolicyRule{
		Name: "rule", Selector: nonProdSelector(),
		WorkflowID: wf, Priority: 100, Enabled: true, TeamID: &teamA,
	}
	if err := repo.Create(t.Context(), rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Try to flip the anchor team.
	mutated := *rule
	mutated.TeamID = &teamB
	if err := repo.Update(t.Context(), &mutated); !errors.Is(err, storage.ErrAnchorImmutable) {
		t.Errorf("expected ErrAnchorImmutable on team_id flip, got: %v", err)
	}

	// Try to drop the anchor entirely.
	mutated = *rule
	mutated.TeamID = nil
	if err := repo.Update(t.Context(), &mutated); !errors.Is(err, storage.ErrAnchorImmutable) {
		t.Errorf("expected ErrAnchorImmutable on team_id drop, got: %v", err)
	}

	// Same-anchor Update is allowed.
	mutated = *rule
	mutated.Priority = 200
	if err := repo.Update(t.Context(), &mutated); err != nil {
		t.Errorf("same-anchor Update should succeed, got: %v", err)
	}
}

// --- Anchor() helper -----------------------------------------------

func TestPolicyRule_Anchor(t *testing.T) {
	pool := freshDB(t)
	teamID := makeTeam(t, pool, "team", nil)
	projectID := makeProjectWithTeam(t, pool, "project", nil)

	platform := &storage.PolicyRule{}
	if platform.Anchor() != storage.AnchorPlatform {
		t.Errorf("expected AnchorPlatform for empty rule, got %d", platform.Anchor())
	}

	team := &storage.PolicyRule{TeamID: &teamID}
	if team.Anchor() != storage.AnchorTeam {
		t.Errorf("expected AnchorTeam for team rule, got %d", team.Anchor())
	}

	project := &storage.PolicyRule{ProjectID: &projectID}
	if project.Anchor() != storage.AnchorProject {
		t.Errorf("expected AnchorProject for project rule, got %d", project.Anchor())
	}
}
