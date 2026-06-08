// R-follow-up #1 (api#118) — service-layer tests for the
// workflow_authorable gate. Each test exercises one row of the §1 Q4
// locked behaviour matrix: Create rejects opted-out, Create succeeds
// opted-in, Update enforces only when WorkflowID changes (grandfather
// rule), Update bypasses when WorkflowID nil (preserve).

package services_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
)

// flipSeedAuthorable returns the seed `standard` workflow's flag to
// false so individual tests can drive Create against an opted-out
// workflow. The harness's setupScopedPolicyEnv flips it to TRUE by
// default; this helper resets per test where needed.
func flipSeedAuthorable(t *testing.T, e *scopedPolicyEnv, value bool) {
	t.Helper()
	if _, err := e.pool.Exec(e.ctx,
		`UPDATE workflow_definitions SET scoped_policy_authorable=$1 WHERE name='standard'`,
		value,
	); err != nil {
		t.Fatalf("flip seed flag: %v", err)
	}
}

func TestCreateForScopedAuthor_Gate5b_RejectsOptedOutWorkflow(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	flipSeedAuthorable(t, &e, false)
	svc := e.withCovers()

	_, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "denied-opt-out",
		Selector:      map[string]any{"environment_kind": "non_prod"},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	var d *services.WorkflowNotAuthorableDetail
	if !errors.As(err, &d) {
		t.Fatalf("want WorkflowNotAuthorableDetail, got %v", err)
	}
	if d.WorkflowID != e.workflowID {
		t.Fatalf("WorkflowID = %s, want %s", d.WorkflowID, e.workflowID)
	}

	// Audit row must NOT carry policy_rule_id (gate-order protection;
	// the rule was never INSERTed).
	var hasRuleID bool
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata ? 'policy_rule_id' FROM audit_events
		 WHERE action='policy.denied_workflow_not_authorable'
		   AND actor='alice'
		 ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&hasRuleID); err != nil {
		t.Fatalf("query denied audit: %v", err)
	}
	if hasRuleID {
		t.Fatal("denied_workflow_not_authorable audit must NOT carry policy_rule_id")
	}

	// But attempted_workflow_id IS allowed (the actor selected it
	// from the dropdown).
	var attemptedWorkflowID string
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata->>'attempted_workflow_id' FROM audit_events
		 WHERE action='policy.denied_workflow_not_authorable'
		   AND actor='alice'
		 ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&attemptedWorkflowID); err != nil {
		t.Fatalf("query attempted_workflow_id: %v", err)
	}
	if attemptedWorkflowID != e.workflowID.String() {
		t.Fatalf("attempted_workflow_id = %s, want %s", attemptedWorkflowID, e.workflowID)
	}
}

func TestCreateForScopedAuthor_Gate5b_SucceedsOnOptedInWorkflow(t *testing.T) {
	e := setupScopedPolicyEnv(t)
	// Default: setupScopedPolicyEnv flips the seed workflow to true.
	svc := e.withCovers()

	rule, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "opted-in",
		Selector:      map[string]any{"environment_kind": "non_prod"},
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
}

func TestUpdateForScopedAuthor_Gate7b_BypassesWhenWorkflowIDNil(t *testing.T) {
	// §1 Q4 grandfather rule: when the actor only changes priority/
	// selector/name/enabled (workflow_id field omitted), the gate
	// does NOT run. Lets existing rules survive a later platform
	// opt-out of their workflow.
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()

	rule, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "alice-existing-rule",
		Selector:      map[string]any{"environment_kind": "non_prod"},
		Priority:      100,
		WorkflowID:    e.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	// Platform admin opts the workflow out AFTER the rule exists.
	flipSeedAuthorable(t, &e, false)

	newPriority := 200
	patched, err := svc.UpdateForScopedAuthor(e.ctx, services.UpdateScopedPolicyInput{
		RuleID:        rule.ID,
		ProjectID:     e.projectID,
		Priority:      &newPriority,
		// WorkflowID nil — preserve. Should bypass gate 7b.
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("UpdateForScopedAuthor (preserve workflow): %v", err)
	}
	if patched.Priority != newPriority {
		t.Fatalf("priority = %d, want %d", patched.Priority, newPriority)
	}
}

func TestUpdateForScopedAuthor_Gate7b_BypassesWhenWorkflowIDUnchanged(t *testing.T) {
	// Defensive variant: WorkflowID provided but identical to existing.
	// Should still bypass the gate per §1 Q4 lock ("only enforce when
	// new != existing").
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()

	rule, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "alice-rule-same-wf",
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

	flipSeedAuthorable(t, &e, false)

	sameWorkflow := e.workflowID
	newPriority := 200
	if _, err := svc.UpdateForScopedAuthor(e.ctx, services.UpdateScopedPolicyInput{
		RuleID:        rule.ID,
		ProjectID:     e.projectID,
		WorkflowID:    &sameWorkflow,
		Priority:      &newPriority,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	}); err != nil {
		t.Fatalf("UpdateForScopedAuthor (same workflow): %v", err)
	}
}

func TestUpdateForScopedAuthor_Gate7b_EnforcesWhenWorkflowChanges(t *testing.T) {
	// §1 Q4 lock: when WorkflowID differs from existing, run the
	// authorable check against the NEW workflow.
	e := setupScopedPolicyEnv(t)
	svc := e.withCovers()

	// Seed rule with the opted-in workflow.
	rule, err := svc.CreateForScopedAuthor(e.ctx, services.CreateScopedPolicyInput{
		ProjectID:     e.projectID,
		Name:          "alice-rule-changing-wf",
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

	// Create a NEW workflow that's opted out.
	var optedOutWorkflowID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO workflow_definitions
		    (name, description, min_approvers, wrap_ttl_created,
		     wrap_ttl_approved, wrap_ttl_claimed, request_ttl,
		     require_justification, allow_self_approval,
		     notification_channels, is_default, enabled, is_system,
		     scoped_policy_authorable)
		 VALUES ('platform-only-wf', '', 1,
		     '300 seconds'::interval, '600 seconds'::interval,
		     '300 seconds'::interval, '86400 seconds'::interval,
		     true, false,
		     '[]'::jsonb, false, true, false,
		     false)
		 RETURNING id`,
	).Scan(&optedOutWorkflowID); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.UpdateForScopedAuthor(e.ctx, services.UpdateScopedPolicyInput{
		RuleID:        rule.ID,
		ProjectID:     e.projectID,
		WorkflowID:    &optedOutWorkflowID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	}); !errors.Is(err, services.ErrWorkflowNotAuthorable) {
		t.Fatalf("want ErrWorkflowNotAuthorable, got %v", err)
	}
}
