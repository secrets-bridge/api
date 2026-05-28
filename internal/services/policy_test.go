package services_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapPolicy(t *testing.T) (*services.PolicyEngine, *storage.Pool, *storage.Policies, *storage.Workflows) {
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

	// Need to keep the system seed rows from migration 0005 (default
	// workflow + match-all policy) — tests rely on them. So we
	// DELETE only non-system rows from the workflow-engine tables,
	// and TRUNCATE audit_events (which has a no-DELETE trigger).
	const wipeWorkflow = `
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;
		DELETE FROM user_roles;
		DELETE FROM roles WHERE is_system = false;`
	if _, err := pool.Exec(ctx, wipeWorkflow); err != nil {
		t.Fatalf("wipe workflow tables: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit_events: %v", err)
	}

	policies := storage.NewPolicies(pool)
	workflows := storage.NewWorkflows(pool)
	engine := services.NewPolicyEngine(policies, workflows)
	return engine, pool, policies, workflows
}

// The seed rows in migration 0005 give us a working default-only
// configuration. Resolve with an empty scope must return the seed
// workflow ("standard"), via the seed policy ("match-all").
func TestResolve_FallsBackToSystemDefault(t *testing.T) {
	engine, _, _, _ := bootstrapPolicy(t)

	w, rule, err := engine.Resolve(t.Context(), services.Scope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if w == nil || w.Name != "standard" {
		t.Fatalf("default workflow: got %+v", w)
	}
	if rule == nil || rule.Name != "match-all (system default)" {
		t.Fatalf("matched rule: got %+v", rule)
	}
}

func TestResolve_ExactMatchPolicyTakesPrecedence(t *testing.T) {
	engine, _, policies, workflows := bootstrapPolicy(t)
	ctx := t.Context()

	// Create a stricter workflow for prod environments.
	strict := &storage.WorkflowDefinition{
		Name: "strict-prod", Description: "Two approvers, no self-approve",
		MinApprovers: 2, AllowSelfApproval: false,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour,
		RequireJustification: true, Enabled: true,
	}
	if err := workflows.Create(ctx, strict); err != nil {
		t.Fatalf("Create workflow: %v", err)
	}

	rule := &storage.PolicyRule{
		Name:       "prod-only",
		Selector:   map[string]any{"environment": "prod"},
		WorkflowID: strict.ID,
		Priority:   100, // higher than the seed match-all (priority 0)
		Enabled:    true,
	}
	if err := policies.Create(ctx, rule); err != nil {
		t.Fatalf("Create policy: %v", err)
	}

	// prod scope → strict workflow.
	w, matched, err := engine.Resolve(ctx, services.Scope{Environment: "prod"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if w.Name != "strict-prod" {
		t.Fatalf("prod scope: got workflow %q want strict-prod", w.Name)
	}
	if matched.Name != "prod-only" {
		t.Fatalf("matched rule: %+v", matched)
	}

	// dev scope → falls through to system default.
	w2, _, err := engine.Resolve(ctx, services.Scope{Environment: "dev"})
	if err != nil {
		t.Fatalf("Resolve dev: %v", err)
	}
	if w2.Name != "standard" {
		t.Fatalf("dev scope: got %q want standard", w2.Name)
	}
}

func TestResolve_HigherPriorityWins(t *testing.T) {
	engine, _, policies, workflows := bootstrapPolicy(t)
	ctx := t.Context()

	// Two workflows competing for the same scope.
	for _, name := range []string{"low-prio-wf", "high-prio-wf"} {
		if err := workflows.Create(ctx, &storage.WorkflowDefinition{
			Name: name, MinApprovers: 1,
			WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
			WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour,
			Enabled: true,
		}); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}
	lowWF, _ := workflows.GetByName(ctx, "low-prio-wf")
	highWF, _ := workflows.GetByName(ctx, "high-prio-wf")

	// Lower priority added FIRST so created_at ordering won't save it.
	if err := policies.Create(ctx, &storage.PolicyRule{
		Name:     "low-prio-match",
		Selector: map[string]any{"environment": "prod"},
		WorkflowID: lowWF.ID, Priority: 50, Enabled: true,
	}); err != nil {
		t.Fatalf("low rule: %v", err)
	}
	if err := policies.Create(ctx, &storage.PolicyRule{
		Name:     "high-prio-match",
		Selector: map[string]any{"environment": "prod"},
		WorkflowID: highWF.ID, Priority: 500, Enabled: true,
	}); err != nil {
		t.Fatalf("high rule: %v", err)
	}

	w, matched, err := engine.Resolve(ctx, services.Scope{Environment: "prod"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if w.Name != "high-prio-wf" {
		t.Fatalf("priority resolution: got %q want high-prio-wf", w.Name)
	}
	if matched.Name != "high-prio-match" {
		t.Fatalf("matched rule: got %+v", matched)
	}
}

func TestResolve_PartialMatchDoesNotApply(t *testing.T) {
	engine, _, policies, workflows := bootstrapPolicy(t)
	ctx := t.Context()
	wf := &storage.WorkflowDefinition{
		Name: "strict", MinApprovers: 2, AllowSelfApproval: false,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	_ = workflows.Create(ctx, wf)
	_ = policies.Create(ctx, &storage.PolicyRule{
		Name: "needs-both", Selector: map[string]any{
			"environment":   "prod",
			"provider_type": "vault",
		},
		WorkflowID: wf.ID, Priority: 100, Enabled: true,
	})

	// Scope matches only one of the two selector keys → rule doesn't
	// apply. Falls through to default.
	w, _, err := engine.Resolve(ctx, services.Scope{
		Environment:  "prod",
		ProviderType: "aws-sm", // ← mismatched
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if w.Name != "standard" {
		t.Fatalf("partial match should fall through to default, got %q", w.Name)
	}
}

func TestResolve_SecretRefPrefixMatch(t *testing.T) {
	engine, _, policies, workflows := bootstrapPolicy(t)
	ctx := t.Context()
	wf := &storage.WorkflowDefinition{
		Name: "myapp-wf", MinApprovers: 2,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	_ = workflows.Create(ctx, wf)
	_ = policies.Create(ctx, &storage.PolicyRule{
		Name: "myapp-prefix",
		Selector: map[string]any{
			"secret_ref_prefix": "myapp/",
		},
		WorkflowID: wf.ID, Priority: 100, Enabled: true,
	})

	// Matching prefix → custom workflow.
	w1, _, _ := engine.Resolve(ctx, services.Scope{SecretRefPrefix: "myapp/db-password"})
	if w1.Name != "myapp-wf" {
		t.Fatalf("prefix match: got %q", w1.Name)
	}
	// Non-matching prefix → default.
	w2, _, _ := engine.Resolve(ctx, services.Scope{SecretRefPrefix: "otherapp/api-key"})
	if w2.Name != "standard" {
		t.Fatalf("prefix non-match: got %q", w2.Name)
	}
}

func TestResolve_DisabledRuleSkipped(t *testing.T) {
	engine, _, policies, workflows := bootstrapPolicy(t)
	ctx := t.Context()
	wf := &storage.WorkflowDefinition{
		Name: "should-not-resolve", MinApprovers: 2,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	_ = workflows.Create(ctx, wf)
	_ = policies.Create(ctx, &storage.PolicyRule{
		Name: "disabled-rule", Selector: map[string]any{"environment": "prod"},
		WorkflowID: wf.ID, Priority: 999, Enabled: false,
	})

	w, _, _ := engine.Resolve(ctx, services.Scope{Environment: "prod"})
	if w.Name != "standard" {
		t.Fatalf("disabled rule must be skipped, got workflow %q", w.Name)
	}
}

func TestResolve_DisabledWorkflowFalsThrough(t *testing.T) {
	engine, _, policies, workflows := bootstrapPolicy(t)
	ctx := t.Context()
	wf := &storage.WorkflowDefinition{
		Name: "soft-disabled", MinApprovers: 2,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: false,
	}
	_ = workflows.Create(ctx, wf)
	_ = policies.Create(ctx, &storage.PolicyRule{
		Name: "points-at-disabled", Selector: map[string]any{"environment": "prod"},
		WorkflowID: wf.ID, Priority: 999, Enabled: true,
	})

	w, _, _ := engine.Resolve(ctx, services.Scope{Environment: "prod"})
	if w.Name != "standard" {
		t.Fatalf("rule points at disabled workflow; should fall through, got %q", w.Name)
	}
}

func TestRoles_DeleteSystemRowRejected(t *testing.T) {
	_, pool, _, _ := bootstrapPolicy(t)
	ctx := t.Context()
	roles := storage.NewRoles(pool)

	admin, err := roles.GetByName(ctx, "admin")
	if err != nil {
		t.Fatalf("seed admin role missing: %v", err)
	}
	if err := roles.Delete(ctx, admin.ID); !errors.Is(err, storage.ErrSystemRow) {
		t.Fatalf("deleting system role: got %v want ErrSystemRow", err)
	}
}

func TestUserRoles_GrantAndList(t *testing.T) {
	_, pool, _, _ := bootstrapPolicy(t)
	ctx := t.Context()
	roles := storage.NewRoles(pool)
	urs := storage.NewUserRoles(pool)

	approver, _ := roles.GetByName(ctx, "approver")

	ur := &storage.UserRole{
		UserID:    "alice@example.com",
		RoleID:    approver.ID,
		Scope:     map[string]any{"environment": "prod"},
		GrantedBy: "admin@example.com",
	}
	if err := urs.Grant(ctx, ur); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if ur.ID == uuid.Nil {
		t.Fatal("Grant did not populate ID")
	}

	listed, err := urs.ListByUser(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(listed) != 1 || listed[0].RoleID != approver.ID {
		t.Fatalf("ListByUser: %+v", listed)
	}
	if listed[0].Scope["environment"] != "prod" {
		t.Fatalf("scope not preserved: %+v", listed[0].Scope)
	}
}

func TestWorkflows_OnlyOneDefault(t *testing.T) {
	_, _, _, workflows := bootstrapPolicy(t)
	ctx := t.Context()
	// The seed inserted "standard" as default. Trying to create
	// another default must fail (partial unique index).
	dup := &storage.WorkflowDefinition{
		Name: "another-default", MinApprovers: 1, IsDefault: true,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := workflows.Create(ctx, dup); err == nil {
		t.Fatal("schema must reject a second is_default=true row")
	}
}
