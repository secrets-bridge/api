package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// api#192: an admin can't widen their own access in one step.
// Every write that changes who can do what needs a fresh second factor
// and records the actor's roles, and a move can't widen a team-scoped
// grant the mover holds. Drives the real router against Postgres + Redis.

// adminWritePerms covers every route in adminWriteRoutes.
var adminWritePerms = []string{
	"role.edit", "user_role.edit", "workflow.edit", "policy.edit", "team.edit", "policy.author",
}

// adminWriteRoutes are the gated writes. Ids don't need to exist: a
// caller who passes the gate gets a 4xx from the handler, and only the
// gate answers 401 step_up_required or 412.
func adminWriteRoutes() []struct{ method, path string } {
	id := uuid.NewString()
	return []struct{ method, path string }{
		{http.MethodPost, "/api/v1/roles"},
		{http.MethodPut, "/api/v1/roles/" + id + "/permissions"},
		{http.MethodDelete, "/api/v1/roles/" + id},
		{http.MethodPost, "/api/v1/user-roles"},
		{http.MethodDelete, "/api/v1/user-roles/" + id},
		{http.MethodPost, "/api/v1/users/" + id + "/approve"},
		{http.MethodPost, "/api/v1/workflows"},
		{http.MethodPut, "/api/v1/workflows/" + id},
		{http.MethodDelete, "/api/v1/workflows/" + id},
		{http.MethodPost, "/api/v1/policies"},
		{http.MethodPut, "/api/v1/policies/" + id},
		{http.MethodDelete, "/api/v1/policies/" + id},
		{http.MethodPut, "/api/v1/platform-settings/" + id},
		{http.MethodPost, "/api/v1/projects/" + id + "/policy-rules"},
		{http.MethodPut, "/api/v1/projects/" + id + "/policy-rules/" + id},
		{http.MethodDelete, "/api/v1/projects/" + id + "/policy-rules/" + id},
		{http.MethodPost, "/api/v1/teams/" + id + "/policy-rules"},
		{http.MethodPut, "/api/v1/teams/" + id + "/policy-rules/" + id},
		{http.MethodDelete, "/api/v1/teams/" + id + "/policy-rules/" + id},
		{http.MethodPut, "/api/v1/projects/" + id + "/team"},
		{http.MethodPost, "/api/v1/teams"},
		{http.MethodPut, "/api/v1/teams/" + id},
	}
}

// staleSession is a session whose second factor is past the step-up window.
func (l *liveApp) staleSession(t *testing.T, uid uuid.UUID) map[string]string {
	t.Helper()
	hdr := map[string]string{"Cookie": l.sessionFor(t, uid, "stale-"+uid.String()[:8]+"@example.com")}
	if _, err := l.pool.Exec(t.Context(), `
		INSERT INTO user_mfa_factors (user_id, kind, label, secret_ciphertext, secret_nonce, data_key_ciphertext, kms_key_id)
		VALUES ($1, 'totp', 'test', '\x00', '\x00', '\x00', 'test')`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := l.pool.Exec(t.Context(), `UPDATE sessions SET last_mfa_at = now() - interval '2 hours' WHERE user_id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	return hdr
}

func TestLive_AdminWrites_NeedFreshSecondFactor(t *testing.T) {
	l := newLiveApp(t)

	stale := uuid.New()
	staleHdr := l.staleSession(t, stale)
	l.addGrant(t, stale.String(), adminWritePerms, `{}`)

	noFactor := uuid.New()
	noFactorHdr := map[string]string{"Cookie": l.noMFASession(t, noFactor, "no-factor@example.com")}
	l.addGrant(t, noFactor.String(), adminWritePerms, `{}`)

	fresh := uuid.New()
	freshHdr := map[string]string{"Cookie": l.sessionFor(t, fresh, "fresh@example.com")}
	l.addGrant(t, fresh.String(), adminWritePerms, `{}`)

	nope := uuid.New()
	nopeHdr := l.staleSession(t, nope)

	for _, r := range adminWriteRoutes() {
		name := r.method + " " + r.path
		if code, raw := l.callAs(t, r.method, r.path, staleHdr, map[string]any{}); code != http.StatusUnauthorized || !strings.Contains(string(raw), "step_up_required") {
			t.Errorf("%s with a stale factor = %d %s; want 401 step_up_required", name, code, raw)
		}
		if code, raw := l.callAs(t, r.method, r.path, noFactorHdr, map[string]any{}); code != http.StatusPreconditionFailed || !strings.Contains(string(raw), "mfa_enrollment_required") {
			t.Errorf("%s with no factor = %d %s; want 412 mfa_enrollment_required", name, code, raw)
		}
		if code, raw := l.callAs(t, r.method, r.path, freshHdr, map[string]any{}); code == http.StatusUnauthorized || code == http.StatusPreconditionFailed {
			t.Errorf("%s with a fresh factor stopped at the gate: %d %s", name, code, raw)
		}
		// The permission comes first: no step-up prompt for a caller who
		// can't make the write anyway.
		if code, raw := l.callAs(t, r.method, r.path, nopeHdr, map[string]any{}); code == http.StatusUnauthorized || code == http.StatusPreconditionFailed {
			t.Errorf("%s without the permission stopped at the gate: %d %s", name, code, raw)
		}
	}

	// An identity with no session has nothing to stamp.
	if code, raw := l.call(t, http.MethodPost, "/api/v1/teams", fresh.String(), map[string]any{"name": "no-session"}); code != http.StatusUnauthorized || !strings.Contains(string(raw), "step_up_required") {
		t.Errorf("write with no session = %d %s; want 401 step_up_required", code, raw)
	}

	// Adding a member stays open: membership grants nothing.
	var team uuid.UUID
	if err := l.pool.QueryRow(t.Context(), `INSERT INTO teams (name) VALUES ('membership') RETURNING id`).Scan(&team); err != nil {
		t.Fatal(err)
	}
	member := uuid.New()
	if _, err := l.pool.Exec(t.Context(), `INSERT INTO local_users (id, email, password_hash, display_name) VALUES ($1, 'member@example.com', '\x00', 'm')`, member); err != nil {
		t.Fatal(err)
	}
	if code, raw := l.callAs(t, http.MethodPost, "/api/v1/teams/"+team.String()+"/members", staleHdr, map[string]any{"user_id": member.String()}); code != http.StatusCreated && code != http.StatusNoContent {
		t.Errorf("adding a member with a stale factor = %d %s", code, raw)
	}
}

// A caller without policy.author reaches the service's scope check,
// which audits the denial, whatever the state of their second factor.
func TestLive_PolicyRuleWrite_DenialStaysAudited(t *testing.T) {
	l := newLiveApp(t)
	nope := uuid.New()
	hdr := l.staleSession(t, nope)
	var team uuid.UUID
	if err := l.pool.QueryRow(t.Context(), `INSERT INTO teams (name) VALUES ('denied') RETURNING id`).Scan(&team); err != nil {
		t.Fatal(err)
	}
	code, raw := l.callAs(t, http.MethodPost, "/api/v1/teams/"+team.String()+"/policy-rules", hdr, map[string]any{})
	if code != http.StatusForbidden {
		t.Fatalf("policy-rule write without policy.author = %d %s; want 403", code, raw)
	}
	if rows := l.auditRows(t, "policy.denied_out_of_scope"); len(rows) != 1 {
		t.Fatalf("denied audit rows = %d; want 1", len(rows))
	}
}

// moveFixture is two sibling trees: parent > x, and z, each with a
// project.
type moveFixture struct {
	l                  *liveApp
	parent, x, z       uuid.UUID
	inX, inZ, unscoped uuid.UUID
}

func newMoveFixture(t *testing.T) *moveFixture {
	t.Helper()
	l := newLiveApp(t)
	f := &moveFixture{l: l, inX: uuid.New(), inZ: uuid.New(), unscoped: uuid.New()}
	team := func(name string, parent any) uuid.UUID {
		var id uuid.UUID
		if err := l.pool.QueryRow(t.Context(), `INSERT INTO teams (name, parent_team_id) VALUES ($1, $2) RETURNING id`, name, parent).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	f.parent = team("parent", nil)
	f.x = team("x", f.parent)
	f.z = team("z", nil)
	for id, tm := range map[uuid.UUID]any{f.inX: f.x, f.inZ: f.z, f.unscoped: nil} {
		if _, err := l.pool.Exec(t.Context(), `INSERT INTO projects (id, name, team_id) VALUES ($1, $2, $3)`, id, "p-"+id.String()[:8], tm); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// mover is a global team.edit holder with one more grant.
func (f *moveFixture) mover(t *testing.T, perms []string, scopeJSON string) map[string]string {
	t.Helper()
	uid := uuid.New()
	hdr := map[string]string{"Cookie": f.l.sessionFor(t, uid, "mover-"+uid.String()[:8]+"@example.com")}
	f.l.addGrant(t, uid.String(), []string{"team.edit"}, `{}`)
	if perms != nil {
		f.l.addGrant(t, uid.String(), perms, scopeJSON)
	}
	return hdr
}

func (f *moveFixture) moveProject(t *testing.T, hdr map[string]string, project uuid.UUID, team any) (int, []byte) {
	t.Helper()
	return f.l.callAs(t, http.MethodPut, "/api/v1/projects/"+project.String()+"/team", hdr, map[string]any{"team_id": team})
}

func (f *moveFixture) reparent(t *testing.T, hdr map[string]string, team uuid.UUID, parent any) (int, []byte) {
	t.Helper()
	var name string
	if err := f.l.pool.QueryRow(t.Context(), `SELECT name FROM teams WHERE id = $1`, team).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return f.l.callAs(t, http.MethodPut, "/api/v1/teams/"+team.String(), hdr, map[string]any{"name": name, "parent_team_id": parent})
}

func wantRefused(t *testing.T, what string, code int, raw []byte) {
	t.Helper()
	if code != http.StatusForbidden || !strings.Contains(string(raw), "self_scope_expansion_not_allowed") {
		t.Fatalf("%s = %d %s; want 403 self_scope_expansion_not_allowed", what, code, raw)
	}
}

func TestLive_StructureCheck_CoversEveryTeamScopedGrant(t *testing.T) {
	scopeOn := func(team uuid.UUID) string { return fmt.Sprintf(`{"team_id":%q}`, team) }

	t.Run("a grant on the destination refuses the move", func(t *testing.T) {
		f := newMoveFixture(t)
		hdr := f.mover(t, []string{"secret.approve"}, scopeOn(f.x))
		code, raw := f.moveProject(t, hdr, f.inZ, f.x)
		wantRefused(t, "project move", code, raw)
		code, raw = f.reparent(t, hdr, f.z, f.x)
		wantRefused(t, "team re-parent", code, raw)
		code, raw = f.moveProject(t, hdr, f.unscoped, f.x)
		wantRefused(t, "unscoped project move", code, raw)
		var team *uuid.UUID
		if err := f.l.pool.QueryRow(t.Context(), `SELECT team_id FROM projects WHERE id = $1`, f.inZ).Scan(&team); err != nil {
			t.Fatal(err)
		}
		if team == nil || *team != f.z {
			t.Fatalf("project team after the refusal = %v; want %s", team, f.z)
		}
	})

	t.Run("a grant reached through a parent team refuses the move", func(t *testing.T) {
		f := newMoveFixture(t)
		hdr := f.mover(t, []string{"secret.reveal.direct"}, scopeOn(f.parent))
		code, raw := f.moveProject(t, hdr, f.inZ, f.x)
		wantRefused(t, "project move", code, raw)
		code, raw = f.reparent(t, hdr, f.z, f.x)
		wantRefused(t, "team re-parent", code, raw)
	})

	t.Run("a narrower team grant still counts", func(t *testing.T) {
		f := newMoveFixture(t)
		hdr := f.mover(t, []string{"secret.approve"}, fmt.Sprintf(`{"team_id":%q,"environment":"prod"}`, f.x))
		code, raw := f.moveProject(t, hdr, f.inZ, f.x)
		wantRefused(t, "project move", code, raw)
	})

	t.Run("a refusal is audited as denied", func(t *testing.T) {
		f := newMoveFixture(t)
		hdr := f.mover(t, []string{"secret.approve"}, scopeOn(f.x))
		f.moveProject(t, hdr, f.inZ, f.x)
		f.reparent(t, hdr, f.z, f.x)
		for _, action := range []string{"project.team.update", "team.update"} {
			var status string
			var meta []byte
			if err := f.l.pool.QueryRow(t.Context(), `SELECT status, metadata FROM audit_events WHERE action = $1`, action).Scan(&status, &meta); err != nil {
				t.Fatalf("%s: %v", action, err)
			}
			if status != "denied" || !strings.Contains(string(meta), "self_scope_expansion_not_allowed") || !strings.Contains(string(meta), f.x.String()) {
				t.Fatalf("%s audit = %s %s", action, status, meta)
			}
		}
	})

	t.Run("no widening goes through", func(t *testing.T) {
		f := newMoveFixture(t)
		// Global grants already cover the destination.
		if code, raw := f.moveProject(t, f.mover(t, nil, ""), f.inZ, f.x); code != http.StatusNoContent {
			t.Fatalf("move by a global-only caller = %d %s", code, raw)
		}
		if code, raw := f.reparent(t, f.mover(t, nil, ""), f.z, f.x); code != http.StatusOK {
			t.Fatalf("re-parent by a global-only caller = %d %s", code, raw)
		}
		// The grant sits on another team.
		f = newMoveFixture(t)
		if code, raw := f.moveProject(t, f.mover(t, []string{"secret.approve"}, scopeOn(f.z)), f.unscoped, f.x); code != http.StatusNoContent {
			t.Fatalf("move elsewhere = %d %s", code, raw)
		}
		// Moving out from under the grant, and inside its subtree.
		f = newMoveFixture(t)
		out := f.mover(t, []string{"secret.approve"}, scopeOn(f.parent))
		if code, raw := f.moveProject(t, out, f.inX, f.parent); code != http.StatusNoContent {
			t.Fatalf("move inside the subtree = %d %s", code, raw)
		}
		if code, raw := f.moveProject(t, out, f.inX, f.z); code != http.StatusNoContent {
			t.Fatalf("move out of the subtree = %d %s", code, raw)
		}
		// The same permission held globally widens nothing.
		f = newMoveFixture(t)
		both := f.mover(t, []string{"secret.approve"}, scopeOn(f.x))
		var uid string
		if err := f.l.pool.QueryRow(t.Context(), `SELECT user_id FROM user_roles ORDER BY granted_at DESC LIMIT 1`).Scan(&uid); err != nil {
			t.Fatal(err)
		}
		f.l.addGrant(t, uid, []string{"secret.approve"}, `{}`)
		if code, raw := f.moveProject(t, both, f.inZ, f.x); code != http.StatusNoContent {
			t.Fatalf("move by a caller with the permission global too = %d %s", code, raw)
		}
		// A new team is empty, so creating one under the grant moves nothing.
		f = newMoveFixture(t)
		create := f.mover(t, []string{"secret.approve"}, scopeOn(f.x))
		if code, raw := f.l.callAs(t, http.MethodPost, "/api/v1/teams", create, map[string]any{"name": "new-child", "parent_team_id": f.x}); code != http.StatusCreated {
			t.Fatalf("new team under the grant = %d %s", code, raw)
		}
	})

	t.Run("a move by someone else is allowed for now", func(t *testing.T) {
		f := newMoveFixture(t)
		f.mover(t, []string{"secret.approve"}, scopeOn(f.x)) // holds X, doesn't move
		if code, raw := f.moveProject(t, f.mover(t, nil, ""), f.inZ, f.x); code != http.StatusNoContent {
			t.Fatalf("move by another admin = %d %s", code, raw)
		}
	})
}

type actorRoleRow struct {
	Status  string
	Meta    map[string]any
	RawMeta string
}

func (l *liveApp) lastAudit(t *testing.T, action string) actorRoleRow {
	t.Helper()
	var r actorRoleRow
	var meta []byte
	if err := l.pool.QueryRow(t.Context(), `SELECT status, metadata FROM audit_events WHERE action = $1 ORDER BY occurred_at DESC LIMIT 1`, action).Scan(&r.Status, &meta); err != nil {
		t.Fatalf("audit %s: %v", action, err)
	}
	r.RawMeta = string(meta)
	mustJSON(t, meta, &r.Meta)
	return r
}

// Every row of these writes names the actor's assignments, by both write
// paths (Append and AppendTx), with the id parts of a scope and no
// free-text scope values.
func TestLive_AdminWrites_RecordActorRoles(t *testing.T) {
	f := newMoveFixture(t)
	l := f.l
	uid := uuid.New()
	hdr := map[string]string{"Cookie": l.sessionFor(t, uid, "actor@example.com")}
	globalRole := l.addGrant(t, uid.String(), adminWritePerms, `{}`)
	scopedRole := l.addGrant(t, uid.String(), []string{"secret.approve"}, fmt.Sprintf(`{"team_id":%q,"secret_ref_prefix":"team-alpha/private"}`, f.z))

	want := func(t *testing.T, action string) {
		t.Helper()
		r := l.lastAudit(t, action)
		for _, bad := range []string{"_dropped_keys", "_rejected_keys", "team-alpha/private"} {
			if strings.Contains(r.RawMeta, bad) {
				t.Errorf("%s audit holds %q: %s", action, bad, r.RawMeta)
			}
		}
		list, _ := r.Meta["actor_roles"].([]any)
		seen := map[string]map[string]any{}
		for _, e := range list {
			m, _ := e.(map[string]any)
			id, _ := m["role_id"].(string)
			seen[id] = m
		}
		if len(seen) != 2 || seen[globalRole.String()] == nil || seen[scopedRole.String()] == nil {
			t.Fatalf("%s actor_roles = %v", action, r.Meta["actor_roles"])
		}
		scoped := seen[scopedRole.String()]
		if scoped["team_id"] != f.z.String() || fmt.Sprint(scoped["scope_keys"]) != "[secret_ref_prefix team_id]" || scoped["user_role_id"] == "" {
			t.Fatalf("%s scoped grant = %v", action, scoped)
		}
	}
	ok := func(code int, raw []byte, wantCode int, what string) {
		t.Helper()
		if code != wantCode {
			t.Fatalf("%s = %d %s; want %d", what, code, raw, wantCode)
		}
	}

	code, raw := l.callAs(t, http.MethodPost, "/api/v1/roles", hdr, map[string]any{"name": "new-role", "permissions": []string{"secret.list"}})
	ok(code, raw, http.StatusCreated, "create role")
	want(t, "role.create")
	var role struct {
		ID string `json:"id"`
	}
	mustJSON(t, raw, &role)

	target := uuid.New()
	code, raw = l.callAs(t, http.MethodPost, "/api/v1/user-roles", hdr, map[string]any{"user_id": target.String(), "role_id": role.ID})
	ok(code, raw, http.StatusCreated, "grant role")
	want(t, "user_role.grant")

	code, raw = l.callAs(t, http.MethodPost, "/api/v1/workflows", hdr, map[string]any{
		"name": "wf", "min_approvers": 1, "enabled": true,
		"wrap_ttl_created_seconds": 3600, "wrap_ttl_approved_seconds": 3600, "wrap_ttl_claimed_seconds": 300, "request_ttl_seconds": 3600,
	})
	ok(code, raw, http.StatusCreated, "create workflow")
	want(t, "workflow.create")
	var wf struct {
		ID string `json:"id"`
	}
	mustJSON(t, raw, &wf)

	code, raw = l.callAs(t, http.MethodPost, "/api/v1/policies", hdr, map[string]any{
		"name": "rule", "selector": map[string]any{"project_id": f.inX.String()}, "workflow_id": wf.ID, "priority": 100, "enabled": true,
	})
	ok(code, raw, http.StatusCreated, "create policy")
	want(t, "policy.create")

	code, raw = f.moveProject(t, hdr, f.inX, f.parent)
	ok(code, raw, http.StatusNoContent, "move project")
	want(t, "project.team.update")

	// A parent change writes team.update and, in its own transaction,
	// policy.team_lineage_changed.
	code, raw = f.reparent(t, hdr, f.x, nil)
	ok(code, raw, http.StatusOK, "re-parent team")
	want(t, "team.update")
	want(t, "policy.team_lineage_changed")

	// The refused move's row names the grants too.
	code, raw = f.moveProject(t, hdr, f.inX, f.z)
	if code != http.StatusForbidden {
		t.Fatalf("widening move = %d %s; want 403", code, raw)
	}
	if r := l.lastAudit(t, "project.team.update"); r.Status != "denied" {
		t.Fatalf("last project.team.update = %s", r.RawMeta)
	}
	want(t, "project.team.update")

	// A write outside the list doesn't carry the key.
	code, raw = l.callAs(t, http.MethodPost, "/api/v1/teams/"+f.x.String()+"/members", hdr, map[string]any{"user_id": uid.String()})
	if code >= 300 {
		t.Fatalf("add member = %d %s", code, raw)
	}
	var rows int
	if err := l.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action LIKE 'team.member%' AND metadata ? 'actor_roles'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("membership rows with actor_roles = %d", rows)
	}
}
