package main

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// TestLive_WorkflowDeleteWithRules_NeedsPolicyEdit: deleting a workflow
// together with the policy rules that route to it deletes those rules,
// so it needs a global policy.edit as well as workflow.edit, like every
// other rule delete. A plain delete still needs workflow.edit only.
func TestLive_WorkflowDeleteWithRules_NeedsPolicyEdit(t *testing.T) {
	l := newLiveApp(t)
	admin := l.grantUser(t, []string{"workflow.edit", "policy.edit"}, `{}`)
	workflowOnly := l.grantUser(t, []string{"workflow.edit"}, `{}`)
	teamPolicy := l.grantUser(t, []string{"workflow.edit"}, `{}`)
	l.addGrant(t, teamPolicy, []string{"policy.edit"}, `{"team_id":"`+uuid.NewString()+`"}`)

	workflow := func(name string) string {
		t.Helper()
		code, body := l.call(t, http.MethodPost, "/api/v1/workflows", admin, map[string]any{
			"name": name, "min_approvers": 1, "enabled": true,
			"wrap_ttl_created_seconds": 3600, "wrap_ttl_approved_seconds": 3600,
			"wrap_ttl_claimed_seconds": 300, "request_ttl_seconds": 3600,
		})
		if code != http.StatusCreated {
			t.Fatalf("create workflow = %d %s", code, body)
		}
		var wf struct{ ID uuid.UUID }
		mustJSON(t, body, &wf)
		return wf.ID.String()
	}
	rule := func(workflowID string) string {
		t.Helper()
		code, body := l.call(t, http.MethodPost, "/api/v1/policies", admin, map[string]any{
			"name": "uses-" + workflowID[:8], "selector": map[string]any{"environment": "uat"},
			"workflow_id": workflowID, "priority": 400, "enabled": true,
		})
		if code != http.StatusCreated {
			t.Fatalf("create policy = %d %s", code, body)
		}
		var p struct{ ID uuid.UUID }
		mustJSON(t, body, &p)
		return p.ID.String()
	}
	exists := func(path string) bool {
		t.Helper()
		code, body := l.call(t, http.MethodGet, path, admin, nil)
		if code != http.StatusOK && code != http.StatusNotFound {
			t.Fatalf("GET %s = %d %s", path, code, body)
		}
		return code == http.StatusOK
	}

	ruled := workflow("wf-ruled")
	ruleID := rule(ruled)
	withRules := "/api/v1/workflows/" + ruled + "?delete_policy_rules=true"

	for who, user := range map[string]string{"workflow.edit only": workflowOnly, "team-scoped policy.edit": teamPolicy} {
		if code, body := l.call(t, http.MethodDelete, withRules, user, nil); code != http.StatusForbidden {
			t.Fatalf("%s: delete with rules = %d %s; want 403", who, code, body)
		}
		if !exists("/api/v1/workflows/"+ruled) || !exists("/api/v1/policies/"+ruleID) {
			t.Fatalf("%s: a refused delete removed the workflow or its rule", who)
		}
	}

	// Without the option nothing changes: in use is still 409, and an
	// unused workflow still deletes with workflow.edit alone.
	if code, body := l.call(t, http.MethodDelete, "/api/v1/workflows/"+ruled, workflowOnly, nil); code != http.StatusConflict {
		t.Fatalf("plain delete of a workflow in use = %d %s; want 409", code, body)
	}
	if code, body := l.call(t, http.MethodDelete, "/api/v1/workflows/"+workflow("wf-free"), workflowOnly, nil); code != http.StatusNoContent {
		t.Fatalf("plain delete of an unused workflow = %d %s; want 204", code, body)
	}

	if code, body := l.call(t, http.MethodDelete, withRules, admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete with rules as workflow.edit + policy.edit = %d %s; want 204", code, body)
	}
	if exists("/api/v1/workflows/"+ruled) || exists("/api/v1/policies/"+ruleID) {
		t.Fatal("the workflow or its rule survived the delete")
	}
	if pd := l.requireOneAudit(t, "policy.delete", admin); pd.Resource == "" {
		t.Errorf("policy.delete row has no resource: %+v", pd)
	}
}
