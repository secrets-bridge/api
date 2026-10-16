package main

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// PUT handlers are partial updates: a key the body leaves out keeps the
// stored value, a key it sends is applied (explicit false / 0 / null
// included where valid). Several handlers used to build the row from the
// body alone and wrote every omitted field back as its zero value. These
// tests drive the real router (newApp) against Postgres and read the
// stored row back with SQL.

func TestLive_WorkflowPut_IsPartial(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()
	admin := l.grantUser(t, []string{"workflow.edit"}, `{}`)

	var approverRole uuid.UUID
	if err := l.pool.QueryRow(ctx, `SELECT id FROM roles WHERE name = 'approver'`).Scan(&approverRole); err != nil {
		t.Fatalf("approver role: %v", err)
	}
	code, body := l.call(t, http.MethodPost, "/api/v1/workflows", admin, map[string]any{
		"name": "prod-cross-team", "min_approvers": 2, "approver_role_id": approverRole,
		"wrap_ttl_created_seconds": 3600, "wrap_ttl_approved_seconds": 1800,
		"wrap_ttl_claimed_seconds": 300, "request_ttl_seconds": 7200,
		"require_justification": true, "notification_channels": []string{"ops"}, "enabled": true,
		"requires_security_approval": true, "fill_ttl_seconds": 7200,
	})
	if code != http.StatusCreated {
		t.Fatalf("create workflow = %d %s", code, body)
	}
	var wf struct{ ID uuid.UUID }
	mustJSON(t, body, &wf)
	// Pin the stored state in SQL too, the way a row written before this
	// API exposed the cross-team knobs would look.
	if _, err := l.pool.Exec(ctx,
		`UPDATE workflow_definitions SET requires_security_approval = true, fill_ttl_seconds = 7200, approver_role_id = $2 WHERE id = $1`,
		wf.ID, approverRole); err != nil {
		t.Fatalf("pin workflow: %v", err)
	}

	type row struct {
		minApprovers           int
		approverRole           *uuid.UUID
		createdSec, requestSec float64
		requireJust, selfAppr  bool
		channels               string
		enabled, secApproval   bool
		fillTTL                int
	}
	read := func() row {
		t.Helper()
		var r row
		if err := l.pool.QueryRow(ctx, `
			SELECT min_approvers, approver_role_id,
			       extract(epoch from wrap_ttl_created), extract(epoch from request_ttl),
			       require_justification, allow_self_approval, notification_channels::text,
			       enabled, requires_security_approval, fill_ttl_seconds
			FROM workflow_definitions WHERE id = $1`, wf.ID).Scan(
			&r.minApprovers, &r.approverRole, &r.createdSec, &r.requestSec,
			&r.requireJust, &r.selfAppr, &r.channels, &r.enabled, &r.secApproval, &r.fillTTL); err != nil {
			t.Fatalf("read workflow: %v", err)
		}
		return r
	}
	path := "/api/v1/workflows/" + wf.ID.String()

	// A body that only touches the name changes nothing else.
	if code, body := l.call(t, http.MethodPut, path, admin, map[string]any{"name": "prod-cross-team-renamed"}); code != http.StatusNoContent {
		t.Fatalf("name-only PUT = %d %s", code, body)
	}
	r := read()
	if !r.secApproval || r.fillTTL != 7200 {
		t.Errorf("name-only PUT wiped the cross-team knobs: requires_security_approval=%v fill_ttl_seconds=%d", r.secApproval, r.fillTTL)
	}
	if r.minApprovers != 2 || r.approverRole == nil || *r.approverRole != approverRole ||
		r.createdSec != 3600 || r.requestSec != 7200 || !r.requireJust || !r.enabled || r.channels != `["ops"]` {
		t.Errorf("name-only PUT changed other fields: %+v", r)
	}

	// The old admin form's body (every classic field, none of the new
	// ones, no approver_role_id) also leaves the knobs alone.
	if code, body := l.call(t, http.MethodPut, path, admin, map[string]any{
		"name": "prod-cross-team", "min_approvers": 3,
		"wrap_ttl_created_seconds": 3600, "wrap_ttl_approved_seconds": 1800,
		"wrap_ttl_claimed_seconds": 300, "request_ttl_seconds": 7200,
		"require_justification": true, "allow_self_approval": false,
		"notification_channels": []string{"ops"}, "enabled": true,
	}); code != http.StatusNoContent {
		t.Fatalf("legacy full PUT = %d %s", code, body)
	}
	r = read()
	if r.minApprovers != 3 || !r.secApproval || r.fillTTL != 7200 || r.approverRole == nil {
		t.Errorf("legacy full PUT: %+v (want min_approvers 3, knobs + approver role kept)", r)
	}

	// Explicit false / 0 / null are applied.
	if code, body := l.call(t, http.MethodPut, path, admin, map[string]any{
		"requires_security_approval": false, "enabled": false, "min_approvers": 0,
		"approver_role_id": nil, "fill_ttl_seconds": 600,
	}); code != http.StatusNoContent {
		t.Fatalf("explicit PUT = %d %s", code, body)
	}
	r = read()
	if r.secApproval || r.enabled || r.minApprovers != 0 || r.approverRole != nil || r.fillTTL != 600 {
		t.Errorf("explicit values not applied: %+v", r)
	}
	if r.requestSec != 7200 || !r.requireJust {
		t.Errorf("explicit PUT touched fields it didn't send: %+v", r)
	}

	// GET exposes the knobs.
	code, body = l.call(t, http.MethodGet, path, admin, nil)
	var got map[string]any
	mustJSON(t, body, &got)
	if code != http.StatusOK || got["requires_security_approval"] != false || got["fill_ttl_seconds"] != float64(600) {
		t.Errorf("GET workflow = %d %v", code, got)
	}

	// Invalid explicit values are refused, not stored.
	for _, bad := range []map[string]any{
		{"fill_ttl_seconds": 0},
		{"wrap_ttl_created_seconds": 0},
		{"request_ttl_seconds": -5},
		{"min_approvers": -1},
	} {
		if code, _ := l.call(t, http.MethodPut, path, admin, bad); code != http.StatusBadRequest {
			t.Errorf("PUT %v = %d, want 400", bad, code)
		}
	}
	if r2 := read(); r2 != r {
		t.Errorf("refused PUTs changed the row: %+v -> %+v", r, r2)
	}
}

func TestLive_PolicyPut_IsPartial(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()
	admin := l.grantUser(t, []string{"policy.edit"}, `{}`)
	var wfID uuid.UUID
	if err := l.pool.QueryRow(ctx, `SELECT id FROM workflow_definitions WHERE is_default LIMIT 1`).Scan(&wfID); err != nil {
		t.Fatalf("default workflow: %v", err)
	}
	code, body := l.call(t, http.MethodPost, "/api/v1/policies", admin, map[string]any{
		"name": "uat-direct", "selector": map[string]any{"environment": "uat"}, "workflow_id": wfID,
		"priority": 500, "enabled": true, "direct_reveal_allowed": true, "requires_mfa": true, "reveal_ttl_seconds": 120,
	})
	if code != http.StatusCreated {
		t.Fatalf("create policy = %d %s", code, body)
	}
	var p struct{ ID uuid.UUID }
	mustJSON(t, body, &p)
	path := "/api/v1/policies/" + p.ID.String()

	read := func() (name, selector string, priority int, enabled, direct, mfa bool, ttl int) {
		t.Helper()
		if err := l.pool.QueryRow(ctx,
			`SELECT name, selector::text, priority, enabled, direct_reveal_allowed, requires_mfa, reveal_ttl_seconds FROM policy_rules WHERE id = $1`,
			p.ID).Scan(&name, &selector, &priority, &enabled, &direct, &mfa, &ttl); err != nil {
			t.Fatalf("read policy: %v", err)
		}
		return
	}

	// name + workflow_id only (what a minimal client sends): the old
	// handler reset the selector to {} (match everything) and switched the
	// rule and its reveal flags off.
	if code, body := l.call(t, http.MethodPut, path, admin, map[string]any{"name": "uat-direct-renamed", "workflow_id": wfID}); code != http.StatusNoContent {
		t.Fatalf("name+workflow PUT = %d %s", code, body)
	}
	if _, sel, _, enabled, direct, _, _ := read(); sel != `{"environment": "uat"}` || !enabled || !direct {
		t.Errorf("name+workflow PUT reset fields: selector=%s enabled=%v direct=%v", sel, enabled, direct)
	}
	if code, body := l.call(t, http.MethodPut, path, admin, map[string]any{"name": "uat-direct-renamed"}); code != http.StatusNoContent {
		t.Fatalf("name-only PUT = %d %s", code, body)
	}
	name, sel, prio, enabled, direct, mfa, ttl := read()
	if name != "uat-direct-renamed" {
		t.Errorf("name = %q, want the new name", name)
	}
	if sel != `{"environment": "uat"}` || prio != 500 || !enabled || !direct || !mfa || ttl != 120 {
		t.Errorf("name-only PUT reset fields: selector=%s priority=%d enabled=%v direct=%v mfa=%v ttl=%d", sel, prio, enabled, direct, mfa, ttl)
	}

	if code, body := l.call(t, http.MethodPut, path, admin, map[string]any{"enabled": false, "priority": 0}); code != http.StatusNoContent {
		t.Fatalf("explicit PUT = %d %s", code, body)
	}
	_, sel, prio, enabled, direct, _, _ = read()
	if enabled || prio != 0 || sel != `{"environment": "uat"}` || !direct {
		t.Errorf("explicit false/0 PUT: selector=%s priority=%d enabled=%v direct=%v", sel, prio, enabled, direct)
	}
}

func TestLive_OtherPuts_KeepOmittedFields(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()
	admin := l.grantUser(t, []string{"role.edit", "team.edit", "integration.edit", "integration.bind"}, `{}`)

	// PUT /roles/:id/permissions without the key no longer strips the role.
	code, body := l.call(t, http.MethodPost, "/api/v1/roles", admin, map[string]any{"name": "it-reader", "permissions": []string{"audit.read"}})
	if code != http.StatusCreated {
		t.Fatalf("create role = %d %s", code, body)
	}
	var role struct{ ID uuid.UUID }
	mustJSON(t, body, &role)
	if code, _ := l.call(t, http.MethodPut, "/api/v1/roles/"+role.ID.String()+"/permissions", admin, map[string]any{}); code != http.StatusBadRequest {
		t.Errorf("permissions-less PUT = %d, want 400", code)
	}
	var perms string
	_ = l.pool.QueryRow(ctx, `SELECT permissions::text FROM roles WHERE id = $1`, role.ID).Scan(&perms)
	if perms != `["audit.read"]` {
		t.Errorf("role permissions = %s, want [\"audit.read\"]", perms)
	}
	if code, _ := l.call(t, http.MethodPut, "/api/v1/roles/"+role.ID.String()+"/permissions", admin,
		map[string]any{"permissions": []string{}}); code != http.StatusNoContent {
		t.Errorf("explicit [] PUT = %d, want 204", code)
	}

	// Teams: parent_team_id and description survive a name-only PUT;
	// an explicit null still moves the team to the root.
	parent, child := uuid.New(), uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO teams (id, name) VALUES ($1, 'team-alpha')`, parent); err != nil {
		t.Fatalf("seed parent: %v", err)
	}
	if _, err := l.pool.Exec(ctx, `INSERT INTO teams (id, name, parent_team_id, description) VALUES ($1, 'team-alpha-uat', $2, 'uat squad')`, child, parent); err != nil {
		t.Fatalf("seed child: %v", err)
	}
	if code, body := l.call(t, http.MethodPut, "/api/v1/teams/"+child.String(), admin, map[string]any{"name": "team-alpha-uat2"}); code != http.StatusOK {
		t.Fatalf("team name-only PUT = %d %s", code, body)
	}
	var gotParent *uuid.UUID
	var desc *string
	_ = l.pool.QueryRow(ctx, `SELECT parent_team_id, description FROM teams WHERE id = $1`, child).Scan(&gotParent, &desc)
	if gotParent == nil || *gotParent != parent || desc == nil || *desc != "uat squad" {
		t.Errorf("team name-only PUT: parent=%v description=%v, want both kept", gotParent, desc)
	}
	if code, _ := l.call(t, http.MethodPut, "/api/v1/teams/"+child.String(), admin,
		map[string]any{"name": "team-alpha-uat2", "parent_team_id": nil}); code != http.StatusOK {
		t.Errorf("team explicit-null PUT = %d", code)
	}
	_ = l.pool.QueryRow(ctx, `SELECT parent_team_id FROM teams WHERE id = $1`, child).Scan(&gotParent)
	if gotParent != nil {
		t.Errorf("explicit null parent_team_id not applied: %v", gotParent)
	}

	// PUT /projects/:id/team needs the key; {} used to un-scope the project.
	proj := uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO projects (id, name, team_id) VALUES ($1, 'tenant-a', $2)`, proj, parent); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if code, _ := l.call(t, http.MethodPut, "/api/v1/projects/"+proj.String()+"/team", admin, map[string]any{}); code != http.StatusBadRequest {
		t.Errorf("project team PUT without team_id = %d, want 400", code)
	}
	var projTeam *uuid.UUID
	_ = l.pool.QueryRow(ctx, `SELECT team_id FROM projects WHERE id = $1`, proj).Scan(&projTeam)
	if projTeam == nil || *projTeam != parent {
		t.Errorf("project team = %v, want %s kept", projTeam, parent)
	}

	// Project-secret binding: an edit that leaves out allowed_keys must
	// not widen the allowlist to every key.
	env := uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO environments (id, project_id, name, type, kind) VALUES ($1, $2, 'uat', 'uat', 'non_prod')`, env, proj); err != nil {
		t.Fatalf("seed env: %v", err)
	}
	secID := uuid.New()
	if _, err := l.pool.Exec(ctx,
		`INSERT INTO secrets (id, cluster_name, provider_type, secret_ref, status) VALUES ($1, 'tenant-a-uat', 'vault', 'team-alpha/uat/db', 'present')`, secID); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	bindPath := "/api/v1/projects/" + proj.String() + "/secrets"
	if code, body := l.call(t, http.MethodPost, bindPath, admin, map[string]any{
		"secret_id": secID, "allowed_keys": []string{"DB_USER"}, "allowed_ops": []string{"read"}, "environment_id": env.String(),
	}); code != http.StatusCreated {
		t.Fatalf("bind = %d %s", code, body)
	}
	readKeys := func() (keys *string, ops string) {
		t.Helper()
		_ = l.pool.QueryRow(ctx, `SELECT allowed_keys::text, allowed_ops::text FROM project_secrets WHERE project_id = $1 AND secret_id = $2`,
			proj, secID).Scan(&keys, &ops)
		return
	}
	if code, body := l.call(t, http.MethodPut, bindPath+"/"+secID.String(), admin,
		map[string]any{"allowed_ops": []string{"read", "patch"}}); code != http.StatusOK {
		t.Fatalf("ops-only PUT = %d %s", code, body)
	}
	if keys, ops := readKeys(); keys == nil || *keys != "{DB_USER}" || ops != "{read,patch}" {
		t.Errorf("ops-only PUT: allowed_keys=%v allowed_ops=%s, want {DB_USER} kept", keys, ops)
	}
	if code, body := l.call(t, http.MethodPut, bindPath+"/"+secID.String(), admin,
		map[string]any{"allowed_keys": []string{"DB_USER", "DB_PASSWORD"}}); code != http.StatusOK {
		t.Fatalf("keys-only PUT = %d %s", code, body)
	}
	if keys, ops := readKeys(); keys == nil || *keys != "{DB_USER,DB_PASSWORD}" || ops != "{read,patch}" {
		t.Errorf("keys-only PUT: allowed_keys=%v allowed_ops=%s", keys, ops)
	}
	if code, _ := l.call(t, http.MethodPut, bindPath+"/"+secID.String(), admin, map[string]any{"allowed_keys": nil}); code != http.StatusOK {
		t.Errorf("explicit null allowed_keys PUT = %d", code)
	}
	if keys, _ := readKeys(); keys != nil {
		t.Errorf("explicit null allowed_keys not applied: %v", *keys)
	}

	// Provider connection: a body without discover_enabled / cluster_name
	// / description keeps them.
	code, body = l.call(t, http.MethodPost, "/api/v1/provider-connections", admin, map[string]any{
		"name": "vault-a", "type": "vault", "auth_method": "token",
		"scope":        map[string]string{"address": "https://vault.example.com", "mount": "secret"},
		"cluster_name": "tenant-a-uat", "description": "tenant a vault",
		"discover_enabled": true, "discover_interval_seconds": 300,
	})
	if code != http.StatusCreated {
		t.Fatalf("create connection = %d %s", code, body)
	}
	var conn struct{ ID uuid.UUID }
	mustJSON(t, body, &conn)
	if code, body := l.call(t, http.MethodPut, "/api/v1/provider-connections/"+conn.ID.String(), admin, map[string]any{
		"name": "vault-a", "auth_method": "token",
		"scope":                     map[string]string{"address": "https://vault.example.com", "mount": "secret"},
		"discover_interval_seconds": 600,
	}); code != http.StatusOK {
		t.Fatalf("connection PUT = %d %s", code, body)
	}
	var discover bool
	var cluster, cdesc *string
	var interval int
	_ = l.pool.QueryRow(ctx, `SELECT discover_enabled, cluster_name, description, discover_interval_seconds FROM provider_connections WHERE id = $1`,
		conn.ID).Scan(&discover, &cluster, &cdesc, &interval)
	if !discover || cluster == nil || *cluster != "tenant-a-uat" || cdesc == nil || *cdesc != "tenant a vault" || interval != 600 {
		t.Errorf("connection PUT: discover=%v cluster=%v description=%v interval=%d", discover, cluster, cdesc, interval)
	}
	if code, body := l.call(t, http.MethodPut, "/api/v1/provider-connections/"+conn.ID.String(), admin,
		map[string]any{"discover_enabled": false, "description": ""}); code != http.StatusOK {
		t.Fatalf("connection explicit PUT = %d %s", code, body)
	}
	_ = l.pool.QueryRow(ctx, `SELECT discover_enabled, description FROM provider_connections WHERE id = $1`, conn.ID).Scan(&discover, &cdesc)
	if discover || cdesc != nil {
		t.Errorf("explicit false/\"\" not applied: discover=%v description=%v", discover, cdesc)
	}
}
