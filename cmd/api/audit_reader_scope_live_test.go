package main

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// TestLive_AuditReaders_SeeOwnEventsAndReadableTrails: what an audit reader sees.
// audit.read alone shows the caller's own events, plus the whole trail
// of a request they can read. A global role.edit, user_role.edit or
// team.edit holder sees every event; the same permission scoped to a
// team does not widen it.
func TestLive_AuditReaders_SeeOwnEventsAndReadableTrails(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()

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

	// The requester is scoped to the project, the approver is global.
	// Both read the audit log the way the seeded developer role does.
	requester, approver := uuid.New(), uuid.New()
	l.addGrant(t, requester.String(), []string{"secret.request", "secret.list"}, `{"project_id":"`+proj.String()+`"}`)
	l.addGrant(t, requester.String(), []string{"audit.read"}, `{}`)
	l.addGrant(t, approver.String(), []string{"secret.approve", "audit.read"}, `{}`)
	reqCookie := l.sessionFor(t, requester, "requester@example.com")
	apprCookie := l.sessionFor(t, approver, "approver@example.com")

	code, body := l.callAs(t, http.MethodPost, "/api/v1/requests/read", map[string]string{"Cookie": reqCookie}, map[string]any{
		"project_id": proj.String(), "environment": "uat",
		"target_provider_type": "vault", "target_secret_ref": "team-alpha/uat/db",
		"target_keys": []string{"DB_USER"}, "justification": "debug tenant-a uat login",
	})
	if code != http.StatusCreated {
		t.Fatalf("submit = %d %s", code, body)
	}
	var req struct{ ID uuid.UUID }
	mustJSON(t, body, &req)
	if code, body := l.callAs(t, http.MethodPost, "/api/v1/requests/"+req.ID.String()+"/approve",
		map[string]string{"Cookie": apprCookie}, map[string]any{"comment": "ok"}); code != http.StatusOK {
		t.Fatalf("approve = %d %s", code, body)
	}

	// An admin's own event, which no one else should see without a
	// global admin permission.
	admin := l.grantUser(t, []string{"team.edit", "audit.read"}, `{}`)
	if code, body := l.call(t, http.MethodPost, "/api/v1/teams", admin, map[string]any{"name": "team-" + uuid.NewString()[:8]}); code != http.StatusCreated {
		t.Fatalf("create team = %d %s", code, body)
	}

	outsider := l.grantUser(t, []string{"audit.read"}, `{}`)
	teamScoped := l.grantUser(t, []string{"audit.read"}, `{}`)
	l.addGrant(t, teamScoped, []string{"role.edit", "user_role.edit", "team.edit"}, `{"team_id":"`+uuid.NewString()+`"}`)

	read := func(t *testing.T, user string, query url.Values) []AuditEventProbe {
		t.Helper()
		code, body := l.call(t, http.MethodGet, "/api/v1/audit-events?"+query.Encode(), user, nil)
		if code != http.StatusOK {
			t.Fatalf("audit as %s (%s) = %d %s", user, query.Encode(), code, body)
		}
		var rows []AuditEventProbe
		mustJSON(t, body, &rows)
		return rows
	}
	actors := func(rows []AuditEventProbe) map[string]bool {
		out := map[string]bool{}
		for _, r := range rows {
			out[r.Actor] = true
		}
		return out
	}
	onlyActor := func(t *testing.T, who string, rows []AuditEventProbe, actor string) {
		t.Helper()
		for _, r := range rows {
			if r.Actor != actor {
				t.Errorf("%s sees %s by %s; want only %s", who, r.Action, r.Actor, actor)
			}
		}
	}
	trail := url.Values{"correlation_id": {req.ID.String()}}
	userActor := func(id string) string { return "user:" + id }

	t.Run("requester sees own events only", func(t *testing.T) {
		rows := read(t, requester.String(), url.Values{})
		if len(rows) == 0 {
			t.Fatal("requester sees none of their own events")
		}
		onlyActor(t, "requester", rows, userActor(requester.String()))
	})

	t.Run("requester sees the whole trail of their request", func(t *testing.T) {
		got := actors(read(t, requester.String(), trail))
		if !got[userActor(requester.String())] || !got[userActor(approver.String())] {
			t.Errorf("trail actors = %v; want the requester and the approver", got)
		}
	})

	t.Run("an actor filter naming someone else returns nothing", func(t *testing.T) {
		rows := read(t, requester.String(), url.Values{"actor": {userActor(admin)}})
		if len(rows) != 0 {
			t.Errorf("requester filtering on the admin got %d rows", len(rows))
		}
	})

	t.Run("approver who can read the request sees its trail", func(t *testing.T) {
		got := actors(read(t, approver.String(), trail))
		if !got[userActor(requester.String())] {
			t.Errorf("approver trail actors = %v; want the requester's submit", got)
		}
	})

	t.Run("approver without the trail sees own events only", func(t *testing.T) {
		onlyActor(t, "approver", read(t, approver.String(), url.Values{}), userActor(approver.String()))
	})

	t.Run("outsider cannot open a trail they cannot read", func(t *testing.T) {
		onlyActor(t, "outsider", read(t, outsider, trail), userActor(outsider))
		onlyActor(t, "outsider", read(t, outsider, url.Values{}), userActor(outsider))
	})

	t.Run("team-scoped admin permissions do not widen it", func(t *testing.T) {
		onlyActor(t, "team-scoped admin", read(t, teamScoped, url.Values{}), userActor(teamScoped))
	})

	t.Run("a global admin permission sees every actor", func(t *testing.T) {
		got := actors(read(t, admin, url.Values{"limit": {"1000"}}))
		for _, want := range []string{userActor(requester.String()), userActor(approver.String()), userActor(admin)} {
			if !got[want] {
				t.Errorf("admin sees actors %v; missing %s", got, want)
			}
		}
	})
}

// AuditEventProbe is the part of an audit row these tests read.
type AuditEventProbe struct {
	Actor         string `json:"actor"`
	Action        string `json:"action"`
	CorrelationID string `json:"correlation_id"`
}
