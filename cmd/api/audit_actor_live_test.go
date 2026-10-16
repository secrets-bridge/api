package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
)

// API-15, whole class: every audit row an HTTP action writes names its
// real actor, "user:<id>" for a session user and "agent:<id>" for an
// agent, never the old literal "admin" or a bare id the audit UI can't
// resolve. Drives the real router against Postgres + Redis.

func (l *liveApp) callAs(t *testing.T, method, path string, headers map[string]string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := l.app.Test(req, fiber.TestConfig{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// actorOf returns the actor of the newest audit row for action.
func (l *liveApp) actorOf(t *testing.T, action string) string {
	t.Helper()
	var actor string
	if err := l.pool.QueryRow(t.Context(),
		`SELECT actor FROM audit_events WHERE action = $1 ORDER BY occurred_at DESC LIMIT 1`, action).Scan(&actor); err != nil {
		t.Fatalf("audit %q: %v", action, err)
	}
	return actor
}

func TestLive_AuditActors_RealActorEverywhere(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()
	op := l.grantUser(t, []string{
		"agent.mint", "agent.revoke", "integration.edit", "integration.bind",
		"policy.edit", "policy.author", "team.edit", "job.enqueue",
	}, `{}`)
	user := "user:" + op
	expect := func(action, want string) {
		t.Helper()
		if got := l.actorOf(t, action); got != want {
			t.Errorf("%s actor = %q, want %q", action, got, want)
		}
	}

	// Provider connection create / update.
	code, body := l.call(t, http.MethodPost, "/api/v1/provider-connections", op, map[string]any{
		"name": "vault-a", "type": "vault", "auth_method": "token",
		"scope":        map[string]string{"address": "https://vault.example.com", "mount": "secret"},
		"cluster_name": "tenant-a-uat", "discover_interval_seconds": 300,
	})
	if code != http.StatusCreated {
		t.Fatalf("create connection = %d %s", code, body)
	}
	var conn struct{ ID uuid.UUID }
	mustJSON(t, body, &conn)
	expect("provider_connection.create", user)
	if code, body := l.call(t, http.MethodPut, "/api/v1/provider-connections/"+conn.ID.String(), op,
		map[string]any{"description": "tenant a"}); code != http.StatusOK {
		t.Fatalf("update connection = %d %s", code, body)
	}
	expect("provider_connection.update", user)

	// Enrollment token create + revoke.
	if code, body := l.call(t, http.MethodPost, "/api/v1/provider-connections/"+conn.ID.String()+"/agent-enrollment-token", op,
		map[string]any{}); code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("enrollment token = %d %s", code, body)
	}
	expect("agent.enrollment_token.created", user)
	var tokenID uuid.UUID
	if err := l.pool.QueryRow(ctx, `SELECT id FROM agent_enrollment_tokens WHERE provider_connection_id = $1`, conn.ID).Scan(&tokenID); err != nil {
		t.Fatalf("token id: %v", err)
	}
	if code, body := l.call(t, http.MethodPost, "/api/v1/agent-enrollment-tokens/"+tokenID.String()+"/revoke", op,
		map[string]any{"reason": "rotated"}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("revoke token = %d %s", code, body)
	}
	expect("agent.enrollment_token.revoked", user)

	// Agent mint, then a discover job the agent claims and completes:
	// the completion hook's audit row is the agent's, not "worker".
	code, body = l.call(t, http.MethodPost, "/api/v1/agents", op, map[string]any{"name": "tenant-a-uat-agent"})
	if code != http.StatusCreated {
		t.Fatalf("mint = %d %s", code, body)
	}
	var minted struct {
		ID          uuid.UUID `json:"id"`
		AgentSecret string    `json:"agent_secret"`
	}
	mustJSON(t, body, &minted)
	if code, body := l.call(t, http.MethodPost, "/api/v1/provider-connections/"+conn.ID.String()+"/discover-now", op, nil); code != http.StatusAccepted {
		t.Fatalf("discover-now = %d %s", code, body)
	}
	expect("job.enqueue", user)
	agentHdr := map[string]string{"X-Agent-Secret": minted.AgentSecret}
	code, body = l.callAs(t, http.MethodPost, "/api/v1/agents/"+minted.ID.String()+"/jobs/claim", agentHdr, nil)
	if code != http.StatusOK {
		t.Fatalf("claim = %d %s", code, body)
	}
	var job struct{ ID uuid.UUID }
	mustJSON(t, body, &job)
	if code, body := l.callAs(t, http.MethodPost, "/api/v1/agents/"+minted.ID.String()+"/jobs/"+job.ID.String()+"/complete",
		agentHdr, map[string]any{"status": "succeeded"}); code != http.StatusNoContent {
		t.Fatalf("complete = %d %s", code, body)
	}
	expect("provider_connection.discover_finished", "agent:"+minted.ID.String())

	// Agent revoke (admin surface).
	if code, body := l.call(t, http.MethodPost, "/api/v1/admin/agents/"+minted.ID.String()+"/revoke", op,
		map[string]any{"reason": "decommissioned"}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("revoke agent = %d %s", code, body)
	}
	expect("agent.revoked", user)

	// Admin policy create + history read.
	var wfID uuid.UUID
	if err := l.pool.QueryRow(ctx, `SELECT id FROM workflow_definitions WHERE is_default LIMIT 1`).Scan(&wfID); err != nil {
		t.Fatalf("default workflow: %v", err)
	}
	code, body = l.call(t, http.MethodPost, "/api/v1/policies", op, map[string]any{
		"name": "uat", "selector": map[string]any{"environment": "uat"}, "workflow_id": wfID, "priority": 200, "enabled": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create policy = %d %s", code, body)
	}
	var pol struct{ ID uuid.UUID }
	mustJSON(t, body, &pol)
	expect("policy.create", user)
	if code, body := l.call(t, http.MethodGet, "/api/v1/policies/"+pol.ID.String()+"/history", op, nil); code != http.StatusOK {
		t.Fatalf("history = %d %s", code, body)
	}
	expect("audit.read.policy_history", user)

	// Project-scoped policy author path: a denial names the caller too.
	projA, projB := uuid.New(), uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1, 'tenant-a'), ($2, 'tenant-b')`, projA, projB); err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	envA := uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO environments (id, project_id, name, type, kind) VALUES ($1, $2, 'uat', 'uat', 'non_prod')`, envA, projA); err != nil {
		t.Fatalf("seed env: %v", err)
	}
	outsider := l.grantUser(t, []string{"policy.author"}, `{"project_id":"`+projB.String()+`"}`)
	if code, _ := l.call(t, http.MethodPost, "/api/v1/projects/"+projA.String()+"/policy-rules", outsider, map[string]any{
		"name": "x", "selector": map[string]any{"environment_kind": "non_prod"}, "workflow_id": wfID.String(), "priority": 10, "enabled": true,
	}); code != http.StatusForbidden {
		t.Errorf("out-of-scope author create = %d, want 403", code)
	}
	expect("policy.denied_out_of_scope", "user:"+outsider)

	// Scoped binding (integration.bind path).
	if _, err := l.pool.Exec(ctx, `UPDATE provider_connections SET self_service_bindable = true WHERE id = $1`, conn.ID); err != nil {
		t.Fatalf("bindable: %v", err)
	}
	if code, body := l.call(t, http.MethodPost, "/api/v1/projects/"+projA.String()+"/provider-connection-bindings", op, map[string]any{
		"provider_connection_id": conn.ID.String(), "environment_id": envA.String(),
	}); code != http.StatusCreated {
		t.Fatalf("scoped bind = %d %s", code, body)
	}
	expect("binding.create", user)

	// Platform setting (re-set the current value so nothing else moves).
	var current struct {
		Value int `json:"value"`
	}
	var raw []byte
	if err := l.pool.QueryRow(ctx, `SELECT value FROM platform_settings WHERE key = 'platform_reserved_priority'`).Scan(&raw); err != nil {
		t.Fatalf("read setting: %v", err)
	}
	_ = json.Unmarshal(raw, &current)
	if code, body := l.call(t, http.MethodPut, "/api/v1/platform-settings/platform_reserved_priority", op,
		map[string]any{"value": current.Value}); code != http.StatusOK {
		t.Fatalf("set setting = %d %s", code, body)
	}
	expect("platform_setting.update", user)

	// Team lineage change.
	teamA, teamB, child := uuid.New(), uuid.New(), uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO teams (id, name) VALUES ($1, 'team-alpha'), ($2, 'team-beta')`, teamA, teamB); err != nil {
		t.Fatalf("seed teams: %v", err)
	}
	if _, err := l.pool.Exec(ctx, `INSERT INTO teams (id, name, parent_team_id) VALUES ($1, 'team-alpha-uat', $2)`, child, teamA); err != nil {
		t.Fatalf("seed child: %v", err)
	}
	if code, body := l.call(t, http.MethodPut, "/api/v1/teams/"+child.String(), op,
		map[string]any{"name": "team-alpha-uat", "parent_team_id": teamB}); code != http.StatusOK {
		t.Fatalf("move team = %d %s", code, body)
	}
	expect("policy.team_lineage_changed", user)

	// Class check over everything this flow wrote.
	ok := regexp.MustCompile(`^((user|agent):[0-9a-f-]{36}|system(:[a-z_-]+)?|anonymous)$`)
	rows, err := l.pool.Query(ctx, `SELECT action, actor FROM audit_events`)
	if err != nil {
		t.Fatalf("scan audit: %v", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var action, actor string
		if err := rows.Scan(&action, &actor); err != nil {
			t.Fatal(err)
		}
		n++
		if !ok.MatchString(actor) {
			t.Errorf("audit %s has actor %q (want user:/agent:<id>, system or anonymous)", action, actor)
		}
	}
	if n < 15 {
		t.Errorf("only %d audit rows; the flow should have written more", n)
	}
}
