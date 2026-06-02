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
	// Wipe in FK-dependency order so workflow_definitions/policy_rules
	// can be deleted even after request-creating tests (L3/L4 wiring)
	// have left access_requests rows around.
	const wipeWorkflow = `
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
	if _, err := pool.Exec(ctx, wipeWorkflow); err != nil {
		t.Fatalf("wipe workflow tables: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit_events: %v", err)
	}

	policies := storage.NewPolicies(pool)
	workflows := storage.NewWorkflows(pool)
	audit := storage.NewAuditEvents(pool)
	engine := services.NewPolicyEngine(policies, workflows, audit)
	return engine, pool, policies, workflows
}

// The seed rows in migration 0005 give us a working default-only
// configuration. Resolve with an empty scope must return the seed
// workflow ("standard"), via the seed policy ("match-all").
func TestResolve_FallsBackToSystemDefault(t *testing.T) {
	engine, _, _, _ := bootstrapPolicy(t)

	dec, err := engine.Resolve(t.Context(), services.Scope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dec.Workflow == nil || dec.Workflow.Name != "standard" {
		t.Fatalf("default workflow: got %+v", dec.Workflow)
	}
	if dec.MatchedRule == nil || dec.MatchedRule.Name != "match-all (system default)" {
		t.Fatalf("matched rule: got %+v", dec.MatchedRule)
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
	dec, err := engine.Resolve(ctx, services.Scope{Environment: "prod"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dec.Workflow.Name != "strict-prod" {
		t.Fatalf("prod scope: got workflow %q want strict-prod", dec.Workflow.Name)
	}
	if dec.MatchedRule.Name != "prod-only" {
		t.Fatalf("matched rule: %+v", dec.MatchedRule)
	}

	// dev scope → falls through to system default.
	dec2, err := engine.Resolve(ctx, services.Scope{Environment: "dev"})
	if err != nil {
		t.Fatalf("Resolve dev: %v", err)
	}
	if dec2.Workflow.Name != "standard" {
		t.Fatalf("dev scope: got %q want standard", dec2.Workflow.Name)
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

	dec, err := engine.Resolve(ctx, services.Scope{Environment: "prod"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dec.Workflow.Name != "high-prio-wf" {
		t.Fatalf("priority resolution: got %q want high-prio-wf", dec.Workflow.Name)
	}
	if dec.MatchedRule.Name != "high-prio-match" {
		t.Fatalf("matched rule: got %+v", dec.MatchedRule)
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
	dec, err := engine.Resolve(ctx, services.Scope{
		Environment:  "prod",
		ProviderType: "aws-sm", // ← mismatched
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dec.Workflow.Name != "standard" {
		t.Fatalf("partial match should fall through to default, got %q", dec.Workflow.Name)
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
	d1, _ := engine.Resolve(ctx, services.Scope{SecretRefPrefix: "myapp/db-password"})
	if d1.Workflow.Name != "myapp-wf" {
		t.Fatalf("prefix match: got %q", d1.Workflow.Name)
	}
	// Non-matching prefix → default.
	d2, _ := engine.Resolve(ctx, services.Scope{SecretRefPrefix: "otherapp/api-key"})
	if d2.Workflow.Name != "standard" {
		t.Fatalf("prefix non-match: got %q", d2.Workflow.Name)
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

	dec, _ := engine.Resolve(ctx, services.Scope{Environment: "prod"})
	if dec.Workflow.Name != "standard" {
		t.Fatalf("disabled rule must be skipped, got workflow %q", dec.Workflow.Name)
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

	dec, _ := engine.Resolve(ctx, services.Scope{Environment: "prod"})
	if dec.Workflow.Name != "standard" {
		t.Fatalf("rule points at disabled workflow; should fall through, got %q", dec.Workflow.Name)
	}
}

// Slice L2 — the PolicyDecision carries the rule's access-control
// fields verbatim when the scope is NOT prod (or kind is unset).
func TestResolve_DecisionCarriesAccessFields(t *testing.T) {
	engine, _, policies, workflows := bootstrapPolicy(t)
	ctx := t.Context()

	wf := &storage.WorkflowDefinition{
		Name: "uat-direct-wf", MinApprovers: 0, AllowSelfApproval: true,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := workflows.Create(ctx, wf); err != nil {
		t.Fatalf("Create workflow: %v", err)
	}
	rule := &storage.PolicyRule{
		Name:     "uat-direct-rule",
		Selector: map[string]any{"environment": "uat"},
		WorkflowID: wf.ID, Priority: 100, Enabled: true,
		DirectRevealAllowed: true,
		RequiresMFA:         false,
		RevealTTLSeconds:    120,
	}
	if err := policies.Create(ctx, rule); err != nil {
		t.Fatalf("Create policy: %v", err)
	}

	dec, err := engine.Resolve(ctx, services.Scope{
		Environment:     "uat",
		EnvironmentKind: storage.EnvironmentKindNonProd,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !dec.DirectRevealAllowed {
		t.Error("DirectRevealAllowed should be true on non_prod kind")
	}
	if dec.RequiresMFA {
		t.Error("RequiresMFA should be false")
	}
	if dec.RevealTTLSeconds != 120 {
		t.Errorf("RevealTTLSeconds: got %d want 120", dec.RevealTTLSeconds)
	}
	if dec.InvariantViolated {
		t.Error("InvariantViolated should be false")
	}
}

// PROD invariant — even when the operator writes
// direct_reveal_allowed=true and the rule matches a prod env, the
// decision flips the flag back to false AND a
// `policy.invariant.violated` audit event is written.
func TestResolve_ProdInvariantZerosDirectReveal(t *testing.T) {
	engine, pool, policies, workflows := bootstrapPolicy(t)
	ctx := t.Context()

	wf := &storage.WorkflowDefinition{
		Name: "lax-wf-on-prod", MinApprovers: 1, AllowSelfApproval: true,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := workflows.Create(ctx, wf); err != nil {
		t.Fatalf("Create workflow: %v", err)
	}

	// Operator misconfigures: a prod-targeted rule with
	// direct_reveal_allowed=true.
	rule := &storage.PolicyRule{
		Name:     "misconfigured-prod-direct",
		Selector: map[string]any{"environment": "prod"},
		WorkflowID: wf.ID, Priority: 200, Enabled: true,
		DirectRevealAllowed: true,
		RequiresMFA:         true,
		RevealTTLSeconds:    60,
	}
	if err := policies.Create(ctx, rule); err != nil {
		t.Fatalf("Create policy: %v", err)
	}

	dec, err := engine.Resolve(ctx, services.Scope{
		Environment:     "prod",
		EnvironmentKind: storage.EnvironmentKindProd,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The rule on disk still says true; the engine zeroes it in
	// the decision because env kind is prod.
	if dec.DirectRevealAllowed {
		t.Error("DirectRevealAllowed should have been zeroed by PROD invariant")
	}
	if !dec.InvariantViolated {
		t.Error("InvariantViolated should be true")
	}
	if !dec.RequiresMFA {
		t.Error("RequiresMFA should still carry through")
	}
	if dec.MatchedRule == nil || dec.MatchedRule.DirectRevealAllowed != true {
		t.Error("rule on disk should still report direct_reveal_allowed=true")
	}

	// Audit event written.
	var actionCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'policy.invariant.violated' AND resource = $1`,
		"policy_rule:"+rule.ID.String(),
	).Scan(&actionCount); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if actionCount != 1 {
		t.Errorf("audit row count: got %d want 1", actionCount)
	}
}

// When scope.EnvironmentKind is unset (caller hasn't looked up the
// env), the invariant cannot fire — the engine can't know it's prod.
// This is the back-compat path for callers that haven't been
// updated to populate Kind. The rule's flags carry through verbatim.
func TestResolve_KindUnsetSkipsInvariant(t *testing.T) {
	engine, _, policies, workflows := bootstrapPolicy(t)
	ctx := t.Context()

	wf := &storage.WorkflowDefinition{
		Name: "kind-unset-wf", MinApprovers: 1, AllowSelfApproval: true,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	_ = workflows.Create(ctx, wf)
	_ = policies.Create(ctx, &storage.PolicyRule{
		Name:     "matches-prod-env",
		Selector: map[string]any{"environment": "prod"},
		WorkflowID: wf.ID, Priority: 50, Enabled: true,
		DirectRevealAllowed: true,
	})

	dec, err := engine.Resolve(ctx, services.Scope{Environment: "prod"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !dec.DirectRevealAllowed {
		t.Error("invariant should NOT have fired without EnvironmentKind set")
	}
	if dec.InvariantViolated {
		t.Error("InvariantViolated should be false when kind unset")
	}
}

// Default workflow fallback path doesn't carry access fields — there
// is no matched rule. Operators relying on the strict default get a
// safe baseline (no direct reveal, no policy-level MFA opt-in).
func TestResolve_FallbackDecisionHasNoAccessFields(t *testing.T) {
	engine, _, _, _ := bootstrapPolicy(t)

	// Empty scope → no rule matches → fall back to default workflow.
	// The seed match-all rule on priority 0 still matches first,
	// though, so we test the *true* fallback by giving an empty
	// scope that the seed rule's selector also matches.
	//
	// The seed rule's selector is empty (matches everything), so
	// it matches our empty scope — meaning we expect a populated
	// MatchedRule pointing at the seed. To exercise the no-rule
	// fallback we'd need to delete the seed, but tests share state.
	// Instead, verify the seed rule's defaults DON'T leak unexpected
	// access fields.
	dec, err := engine.Resolve(t.Context(), services.Scope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dec.MatchedRule == nil {
		t.Fatal("expected seed match-all rule to match")
	}
	if dec.DirectRevealAllowed {
		t.Error("seed rule should default DirectRevealAllowed=false")
	}
	if dec.RequiresMFA {
		t.Error("seed rule should default RequiresMFA=false")
	}
	if dec.RevealTTLSeconds != 60 {
		t.Errorf("seed rule reveal_ttl_seconds: got %d want 60 (schema default)", dec.RevealTTLSeconds)
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
