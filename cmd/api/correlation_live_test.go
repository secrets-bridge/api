package main

import (
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Hard rule 6: every workflow-changing action emits an audit event with a
// correlation id, and the rows of one access request share the id the
// request was submitted with. A read flow through the real router:
// submit -> approve -> agent claim -> agent wrap -> agent complete ->
// reveal session -> user retrieve -> session hide. Approve and reveal sit
// behind the fresh-MFA gate, so the two users get real cookie sessions
// stamped through SessionService.MarkMFA.

// sessionFor creates a local user and a cookie session with a fresh MFA
// stamp, returning the Cookie header value.
func (l *liveApp) sessionFor(t *testing.T, userID uuid.UUID, email string) string {
	t.Helper()
	ctx := t.Context()
	if _, err := l.pool.Exec(ctx,
		`INSERT INTO local_users (id, email, password_hash, display_name) VALUES ($1, $2, '\x00', $2)`, userID, email); err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	sessions := services.NewSessionService(storage.NewSessions(l.pool), storage.NewAuditEvents(l.pool))
	issued, err := sessions.Issue(ctx, userID, "127.0.0.1", "go-test")
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	if err := sessions.MarkMFA(ctx, issued.Session.ID, time.Now().UTC()); err != nil {
		t.Fatalf("mark mfa: %v", err)
	}
	return middleware.SessionCookieName + "=" + issued.CookieValue
}

func TestLive_ReadFlow_AuditChainSharesCorrelationID(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()

	// Tenancy: project + uat env + a catalog secret bound for read.
	proj, env := uuid.New(), uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1, 'tenant-a')`, proj); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := l.pool.Exec(ctx, `INSERT INTO environments (id, project_id, name, type, kind) VALUES ($1, $2, 'uat', 'uat', 'non_prod')`, env, proj); err != nil {
		t.Fatalf("seed env: %v", err)
	}
	sec := &storage.Secret{ClusterName: "tenant-a-uat", ProviderType: "vault", SecretRef: "team-alpha/uat/db", Status: "present"}
	if err := storage.NewSecrets(l.pool).Upsert(ctx, sec); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	if err := storage.NewProjectSecrets(l.pool).Bind(ctx, &storage.ProjectSecret{
		ProjectID: proj, SecretID: sec.ID, EnvironmentID: &env,
		AllowedKeys: []string{"DB_USER"}, AllowedOps: []string{storage.OpRead}, CreatedBy: "seed",
	}); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	requester, approver := uuid.New(), uuid.New()
	l.addGrant(t, requester.String(), []string{"secret.request", "secret.list"}, `{"project_id":"`+proj.String()+`"}`)
	l.addGrant(t, approver.String(), []string{"secret.approve"}, `{}`)
	reqCookie := l.sessionFor(t, requester, "requester@example.com")
	apprCookie := l.sessionFor(t, approver, "approver@example.com")
	op := l.grantUser(t, []string{"agent.mint"}, `{}`)

	// 1. submit
	code, body := l.callAs(t, http.MethodPost, "/api/v1/requests/read", map[string]string{"Cookie": reqCookie}, map[string]any{
		"requester_id": requester.String(), "project_id": proj.String(), "environment": "uat",
		"target_provider_type": "vault", "target_secret_ref": "team-alpha/uat/db",
		"target_keys": []string{"DB_USER"}, "justification": "debug tenant-a uat login",
	})
	if code != http.StatusCreated {
		t.Fatalf("submit = %d %s", code, body)
	}
	var req struct{ ID uuid.UUID }
	mustJSON(t, body, &req)

	// 2. approve
	if code, body := l.callAs(t, http.MethodPost, "/api/v1/requests/"+req.ID.String()+"/approve",
		map[string]string{"Cookie": apprCookie}, map[string]any{"comment": "ok"}); code != http.StatusOK {
		t.Fatalf("approve = %d %s", code, body)
	}

	// 3. agent claims the read job, posts the wrap, completes.
	code, body = l.call(t, http.MethodPost, "/api/v1/agents", op, map[string]any{"name": "tenant-a-uat-agent"})
	if code != http.StatusCreated {
		t.Fatalf("mint = %d %s", code, body)
	}
	var agent struct {
		ID          uuid.UUID `json:"id"`
		AgentSecret string    `json:"agent_secret"`
	}
	mustJSON(t, body, &agent)
	agentHdr := map[string]string{"X-Agent-Secret": agent.AgentSecret}
	agentBase := "/api/v1/agents/" + agent.ID.String()
	code, body = l.callAs(t, http.MethodPost, agentBase+"/jobs/claim", agentHdr, nil)
	if code != http.StatusOK {
		t.Fatalf("claim = %d %s", code, body)
	}
	var job struct{ ID uuid.UUID }
	mustJSON(t, body, &job)
	const fakeValue = "fake-db-user-value"
	if code, body := l.callAs(t, http.MethodPost, agentBase+"/wraps", agentHdr, map[string]any{
		"request_id": req.ID.String(), "key_name": "DB_USER",
		"value": base64.StdEncoding.EncodeToString([]byte(fakeValue)),
	}); code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("agent wrap = %d %s", code, body)
	}
	if code, body := l.callAs(t, http.MethodPost, agentBase+"/jobs/"+job.ID.String()+"/complete", agentHdr,
		map[string]any{"status": "succeeded"}); code != http.StatusNoContent {
		t.Fatalf("complete = %d %s", code, body)
	}

	// 4. requester opens a reveal session, retrieves the wrap, hides.
	code, body = l.callAs(t, http.MethodPost, "/api/v1/reveal-sessions", map[string]string{"Cookie": reqCookie},
		map[string]any{"access_request_id": req.ID.String()})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("open reveal session = %d %s", code, body)
	}
	var rs struct {
		SessionID string `json:"session_id"`
		Wraps     []struct {
			WrapID string `json:"wrap_id"`
		} `json:"wraps"`
	}
	mustJSON(t, body, &rs)
	if len(rs.Wraps) != 1 {
		t.Fatalf("reveal session wraps = %+v", rs.Wraps)
	}
	if code, body := l.callAs(t, http.MethodGet, "/api/v1/requests/"+req.ID.String()+"/wraps/"+rs.Wraps[0].WrapID,
		map[string]string{"Cookie": reqCookie}, nil); code != http.StatusOK {
		t.Fatalf("retrieve wrap = %d %s", code, body)
	}
	if code, body := l.callAs(t, http.MethodPost, "/api/v1/reveal-sessions/"+rs.SessionID+"/expire",
		map[string]string{"Cookie": reqCookie}, map[string]any{"reason": "user_hide"}); code != http.StatusNoContent {
		t.Fatalf("hide = %d %s", code, body)
	}

	// Every row about this request, its job, its wrap or its reveal
	// session carries the submit's correlation id.
	rows, err := l.pool.Query(ctx, `
		SELECT action, actor, resource, correlation_id FROM audit_events
		WHERE resource IN ($1, $2, $3, $4) ORDER BY occurred_at`,
		"request:"+req.ID.String(), "job:"+job.ID.String(), "wrap:"+rs.Wraps[0].WrapID, "reveal_session:"+rs.SessionID)
	if err != nil {
		t.Fatalf("query chain: %v", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	var submitCorr uuid.UUID
	type link struct {
		action, actor, resource string
		corr                    uuid.UUID
	}
	var chain []link
	for rows.Next() {
		var lk link
		if err := rows.Scan(&lk.action, &lk.actor, &lk.resource, &lk.corr); err != nil {
			t.Fatal(err)
		}
		chain = append(chain, lk)
		seen[lk.action] = true
		if lk.action == "request.submit" {
			submitCorr = lk.corr
		}
	}
	if submitCorr == uuid.Nil {
		t.Fatalf("no request.submit row; chain = %+v", chain)
	}
	for _, want := range []string{
		"request.submit", "request.approve", "job.enqueue", "job.claim", "wrap.create",
		"job.complete", "request.transition", "reveal.session.opened", "wrap.retrieve", "reveal.session.expired",
	} {
		if !seen[want] {
			t.Errorf("chain is missing %s", want)
		}
	}
	for _, lk := range chain {
		if lk.corr != submitCorr {
			t.Errorf("%s on %s has correlation %s, want the submit's %s", lk.action, lk.resource, lk.corr, submitCorr)
		}
	}

	// Actor formats across everything this flow wrote, and no plaintext.
	actorRe := regexp.MustCompile(`^((user|agent):[0-9a-f-]{36}|system:[a-z_-]+|anonymous)$`)
	all, err := l.pool.Query(ctx, `SELECT action, actor, metadata::text FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer all.Close()
	for all.Next() {
		var action, actor, meta string
		if err := all.Scan(&action, &actor, &meta); err != nil {
			t.Fatal(err)
		}
		if !actorRe.MatchString(actor) {
			t.Errorf("%s has actor %q (want user:/agent:<id> or system:<kind>)", action, actor)
		}
		if strings.Contains(meta, fakeValue) {
			t.Errorf("%s metadata carries the secret value", action)
		}
	}
	for _, want := range []struct{ action, actor string }{
		{"request.transition", "system:request-lifecycle"},
		{"session.mfa_stamped", "user:" + requester.String()},
	} {
		var n int
		_ = l.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = $1 AND actor = $2`, want.action, want.actor).Scan(&n)
		if n == 0 {
			t.Errorf("no %s row with actor %s", want.action, want.actor)
		}
	}
}

func TestLive_TeamWrites_AuditedOncePerWrite(t *testing.T) {
	l := newLiveApp(t)
	admin := l.grantUser(t, []string{"team.edit"}, `{}`)

	code, body := l.call(t, http.MethodPost, "/api/v1/teams", admin, map[string]any{"name": "team-alpha"})
	if code != http.StatusCreated {
		t.Fatalf("create team = %d %s", code, body)
	}
	var team struct{ ID uuid.UUID }
	mustJSON(t, body, &team)
	tc := l.requireOneAudit(t, "team.create", admin)
	if tc.Metadata["team_id"] != team.ID.String() {
		t.Errorf("team.create metadata = %v", tc.Metadata)
	}

	// team_members references local_users for both the member and the
	// acting admin (created_by).
	member := uuid.New()
	for _, u := range []string{member.String(), admin} {
		if _, err := l.pool.Exec(t.Context(),
			`INSERT INTO local_users (id, email, password_hash, display_name) VALUES ($1, $2, '\x00', 'x')`,
			u, u+"@example.com"); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	if code, body := l.call(t, http.MethodPost, "/api/v1/teams/"+team.ID.String()+"/members", admin,
		map[string]any{"user_id": member}); code != http.StatusCreated {
		t.Fatalf("add member = %d %s", code, body)
	}
	ma := l.requireOneAudit(t, "team.member.add", admin)
	if ma.Metadata["user_id"] != member.String() || ma.Metadata["team_id"] != team.ID.String() {
		t.Errorf("team.member.add metadata = %v", ma.Metadata)
	}
	if code, body := l.call(t, http.MethodDelete, "/api/v1/teams/"+team.ID.String()+"/members/"+member.String(), admin, nil); code != http.StatusNoContent {
		t.Fatalf("remove member = %d %s", code, body)
	}
	mr := l.requireOneAudit(t, "team.member.remove", admin)
	if mr.Metadata["user_id"] != member.String() {
		t.Errorf("team.member.remove metadata = %v", mr.Metadata)
	}

	if code, body := l.call(t, http.MethodPut, "/api/v1/teams/"+team.ID.String(), admin,
		map[string]any{"name": "team-alpha-renamed"}); code != http.StatusOK {
		t.Fatalf("update team = %d %s", code, body)
	}
	tu := l.requireOneAudit(t, "team.update", admin)
	if keys, _ := tu.Metadata["changed_keys"].([]any); len(keys) != 1 || keys[0] != "name" {
		t.Errorf("team.update changed_keys = %v, want [name]", tu.Metadata["changed_keys"])
	}
	if code, _ := l.call(t, http.MethodPut, "/api/v1/teams/"+team.ID.String()+"/status", admin, map[string]any{"status": "archived"}); code != http.StatusNoContent {
		t.Fatalf("archive team = %d", code)
	}
	l.requireOneAudit(t, "team.status.update", admin)
	if code, _ := l.call(t, http.MethodDelete, "/api/v1/teams/"+team.ID.String(), admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete team = %d", code)
	}
	l.requireOneAudit(t, "team.delete", admin)

	// A refused write (no team.edit) writes nothing.
	if code, _ := l.call(t, http.MethodPost, "/api/v1/teams", uuid.New().String(), map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Errorf("no-perm create = %d, want 403", code)
	}
	if n := len(l.auditRows(t, "team.create")); n != 1 {
		t.Errorf("team.create rows after refused write = %d, want 1", n)
	}
}
