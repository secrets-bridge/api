package main

// Binding counts stay inside the caller's teams, and a
// project or team move that uncovers a discovered binding suspends it.
// Through the real router against Postgres and Redis.

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// The AppProject of payments-api maps to X and Y, so both see the target.
func (c *catFixture) shareTeamA(t *testing.T) string {
	t.Helper()
	code, raw := c.putMapping(t, map[string]any{"mappings": []map[string]any{
		{"app_project": "team-a-apps", "team_ids": []string{c.x.team.String(), c.y.team.String()}},
		{"app_project": "team-b-apps", "team_ids": []string{c.y.team.String()}},
	}})
	if code != http.StatusOK {
		t.Fatalf("mapping = %d %s", code, raw)
	}
	return c.byName["team-a-apps/payments-api"].TargetID
}

func (c *catFixture) wantCount(t *testing.T, hdr map[string]string, target string, want int) {
	t.Helper()
	q := url.Values{"app_project": {"team-a-apps"}, "gateway_id": {c.gw.GatewayID}}
	_, p, raw := c.catalog(t, hdr, q)
	found := false
	for _, it := range p.Items {
		if it.TargetID == target {
			found = true
			if it.Bindings != want {
				t.Fatalf("binding_count = %d; want %d: %s", it.Bindings, want, raw)
			}
		}
	}
	if !found {
		t.Fatalf("target missing from the catalog: %s", raw)
	}
	has := func(bound string) bool {
		q.Set("bound", bound)
		_, p, _ := c.catalog(t, hdr, q)
		for _, it := range p.Items {
			if it.TargetID == target {
				return true
			}
		}
		return false
	}
	if has("true") != (want > 0) || has("false") != (want == 0) {
		t.Fatalf("bound filter with %d bindings: true=%v false=%v", want, has("true"), has("false"))
	}
}

// Y binds a target X also sees. X reads no binding on it, through
// binding_count or the bound filter; Y and a platform admin read theirs.
func TestLive_GatewayCatalog_BindingCountStaysInTeam(t *testing.T) {
	c := newCatFixture(t)
	target := c.shareTeamA(t)
	if code, raw := c.bindAs(t, c.y.admin, c.y.uat, c.y.secret, target); code != http.StatusCreated {
		t.Fatalf("bind = %d %s", code, raw)
	}
	c.wantCount(t, c.x.admin, target, 0)
	c.wantCount(t, c.y.admin, target, 1)
	c.wantCount(t, c.admin, target, 1)
	if code, raw := c.bindAs(t, c.x.admin, c.x.uat, c.x.secret, target); code != http.StatusCreated {
		t.Fatalf("second bind = %d %s", code, raw)
	}
	c.wantCount(t, c.x.admin, target, 1)
	c.wantCount(t, c.y.admin, target, 1)
	c.wantCount(t, c.admin, target, 2)
}

func (c *catFixture) moveProject(t *testing.T, project, team uuid.UUID) {
	t.Helper()
	if code, raw := c.l.callAs(t, http.MethodPut, "/api/v1/projects/"+project.String()+"/team", c.admin,
		map[string]any{"team_id": team.String()}); code != http.StatusNoContent {
		t.Fatalf("move project = %d %s", code, raw)
	}
}

func lastMeta(t *testing.T, c *catFixture, action string) map[string]any {
	t.Helper()
	rows := c.l.auditRows(t, action)
	if len(rows) == 0 {
		t.Fatalf("no %s audit", action)
	}
	return rows[len(rows)-1].Metadata
}

// A project move that leaves a binding uncovered suspends it in the same
// write and cancels its leased task, so the Gateway's late result is
// refused. The new team sees why. Moving back resumes nothing.
func TestLive_GatewayBinding_ProjectMoveSuspends(t *testing.T) {
	c := newCatFixture(t)
	c.l.addGrant(t, c.adminID.String(), []string{"team.edit"}, `{}`)
	e := c.byName["team-a-apps/payments-api"]
	id := c.bindID(t, c.x.admin, c.x.uat, c.x.secret, e.TargetID)
	o := c.obsAgent(t)
	reqID, _ := c.execute(t, o.base, o.hdr, c.x.proj, c.x.uat, c.x.secret)
	c.makeClaimable(t, reqID)
	replica := uuid.NewString()
	c.mustHB(t, c.gw, hbV2(replica, testScope(), true, ""))
	code, _, task, raw := c.claimAs(t, c.gw.GatewayID, c.gw.GatewaySecret, replica)
	if code != http.StatusOK {
		t.Fatalf("claim = %d %s", code, raw)
	}

	c.moveProject(t, c.x.proj, c.y.team)

	if got := c.bindingSuspended(t, id); got != "mapping_removed" {
		t.Fatalf("binding after the move = %q; want mapping_removed", got)
	}
	ts := c.taskRows(t, reqID)
	if len(ts) != 1 || ts[0].State != "cancelled" || ts[0].VerdictReason != "binding_suspended" {
		t.Fatalf("task = %+v; want cancelled binding_suspended", ts)
	}
	res := argoResult(task, c.gw.GatewayID, replica)
	res["stages"].([]map[string]any)[0]["resource"].(map[string]any)["name"] = e.Name
	res["stages"].([]map[string]any)[0]["resource"].(map[string]any)["identity_digest"] = e.TargetID
	if code, out := c.postResult(t, c.gw.GatewayID, c.gw.GatewaySecret, task.TaskID, res); code != http.StatusConflict || errCode(t, out) != "task_closed" {
		t.Fatalf("result after the move = %d %s; want 409 task_closed", code, out)
	}
	if ts := c.taskRows(t, reqID); ts[0].State != "cancelled" {
		t.Fatalf("task after the late result = %+v", ts[0])
	}
	if m := lastMeta(t, c, "project.team.update"); m["bindings_suspended"] != float64(1) || m["tasks_cancelled"] != float64(1) {
		t.Fatalf("move audit = %v", m)
	}
	if len(c.l.auditRows(t, "observation.task.cancelled")) != 1 {
		t.Fatal("no audit for the cancelled task")
	}
	p := c.wantBindings(t, c.y.admin, nil, id)
	if p.Items[0].SuspendedReason != "mapping_removed" {
		t.Fatalf("the new team's view = %+v", p.Items[0])
	}

	c.moveProject(t, c.x.proj, c.x.team)
	if got := c.bindingSuspended(t, id); got != "mapping_removed" {
		t.Fatalf("binding after moving back = %q; want still mapping_removed", got)
	}
	req2, _ := c.execute(t, o.base, o.hdr, c.x.proj, c.x.uat, c.x.secret)
	if ts := c.taskRows(t, req2); len(ts) != 0 {
		t.Fatalf("tasks after moving back = %+v; want none", ts)
	}
}

// A move that stays covered changes nothing, and neither does a move of
// another project: one in the child of the mapped team, moved up to it.
func TestLive_GatewayBinding_CoveredMoveKeepsBinding(t *testing.T) {
	c := newCatFixture(t)
	c.l.addGrant(t, c.adminID.String(), []string{"team.edit"}, `{}`)
	child := c.seedTenant(t, "team-c", &c.x.team)
	target := c.byName["team-a-apps/payments-api"].TargetID
	id := c.bindID(t, c.admin, child.uat, child.secret, target)
	other := c.bindID(t, c.x.admin, c.x.uat, c.x.secret, target)

	c.moveProject(t, child.proj, c.x.team)
	if got := c.bindingSuspended(t, id); got != "" {
		t.Fatalf("binding after a covered move = %q; want live", got)
	}
	c.moveProject(t, c.y.proj, c.x.team)
	if got := c.bindingSuspended(t, other); got != "" {
		t.Fatalf("another project's binding = %q; want live", got)
	}
	if m := lastMeta(t, c, "project.team.update"); m["bindings_suspended"] != float64(0) {
		t.Fatalf("move audit = %v", m)
	}
}

// A re-parent that takes a team out of the mapped subtree suspends the
// bindings of its projects and of its child teams' projects, and no
// others.
func TestLive_GatewayBinding_ReparentSuspends(t *testing.T) {
	c := newCatFixture(t)
	c.l.addGrant(t, c.adminID.String(), []string{"team.edit"}, `{}`)
	mid := c.seedTenant(t, "team-m", &c.x.team)
	leaf := c.seedTenant(t, "team-l", &mid.team)
	target := c.byName["team-a-apps/payments-api"].TargetID
	midB := c.bindID(t, c.admin, mid.uat, mid.secret, target)
	leafB := c.bindID(t, c.admin, leaf.uat, leaf.secret, target)
	stay := c.bindID(t, c.x.admin, c.x.uat, c.x.secret, target)
	o := c.obsAgent(t)
	reqID, _ := c.execute(t, o.base, o.hdr, leaf.proj, leaf.uat, leaf.secret)
	if ts := c.taskRows(t, reqID); len(ts) != 1 || !ts[0].State.Open() {
		t.Fatalf("tasks = %+v; want one open task", ts)
	}

	if code, raw := c.l.callAs(t, http.MethodPut, "/api/v1/teams/"+mid.team.String(), c.admin,
		map[string]any{"name": "team-m-moved", "parent_team_id": c.y.team.String()}); code != http.StatusOK {
		t.Fatalf("re-parent = %d %s", code, raw)
	}
	if a, b := c.bindingSuspended(t, midB), c.bindingSuspended(t, leafB); a != "mapping_removed" || b != "mapping_removed" {
		t.Fatalf("after the re-parent: %q and %q; want mapping_removed", a, b)
	}
	if got := c.bindingSuspended(t, stay); got != "" {
		t.Fatalf("a binding outside the moved subtree = %q; want live", got)
	}
	ts := c.taskRows(t, reqID)
	if len(ts) != 1 || ts[0].State != "cancelled" {
		t.Fatalf("task = %+v; want cancelled", ts)
	}
	if m := lastMeta(t, c, "policy.team_lineage_changed"); m["bindings_suspended"] != float64(2) || m["tasks_cancelled"] != float64(1) {
		t.Fatalf("lineage audit = %v", m)
	}
	if len(c.l.auditRows(t, "observation.task.cancelled")) != 1 {
		t.Fatal("no audit for the cancelled task")
	}
	// A rename alone suspends nothing and moving back resumes nothing.
	if code, raw := c.l.callAs(t, http.MethodPut, "/api/v1/teams/"+mid.team.String(), c.admin,
		map[string]any{"name": "team-m-back", "parent_team_id": c.x.team.String()}); code != http.StatusOK {
		t.Fatalf("move back = %d %s", code, raw)
	}
	if got := c.bindingSuspended(t, midB); got != "mapping_removed" {
		t.Fatalf("after moving back = %q", got)
	}
}

// The repository's plain Update suspends too, so no caller can move a
// team past the check.
func TestLive_GatewayBinding_PlainTeamUpdateSuspends(t *testing.T) {
	c := newCatFixture(t)
	child := c.seedTenant(t, "team-c", &c.x.team)
	id := c.bindID(t, c.admin, child.uat, child.secret, c.byName["team-a-apps/payments-api"].TargetID)
	if err := storage.NewTeams(c.l.pool).Update(t.Context(), child.team, "team-c", "", &c.y.team); err != nil {
		t.Fatal(err)
	}
	if got := c.bindingSuspended(t, id); got != "mapping_removed" {
		t.Fatalf("binding after the update = %q; want mapping_removed", got)
	}
}

// Deleting a team leaves its projects with no team, so nothing covers
// their bindings any more.
func TestLive_GatewayBinding_TeamDeleteSuspends(t *testing.T) {
	c := newCatFixture(t)
	c.l.addGrant(t, c.adminID.String(), []string{"team.edit"}, `{}`)
	child := c.seedTenant(t, "team-c", &c.x.team)
	target := c.byName["team-a-apps/payments-api"].TargetID
	id := c.bindID(t, c.admin, child.uat, child.secret, target)
	stay := c.bindID(t, c.x.admin, c.x.uat, c.x.secret, target)
	if code, raw := c.l.callAs(t, http.MethodDelete, "/api/v1/teams/"+child.team.String(), c.admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete team = %d %s", code, raw)
	}
	if got := c.bindingSuspended(t, id); got != "mapping_removed" {
		t.Fatalf("binding after the delete = %q; want mapping_removed", got)
	}
	if got := c.bindingSuspended(t, stay); got != "" {
		t.Fatalf("another team's binding = %q; want live", got)
	}
	if m := lastMeta(t, c, "team.delete"); m["bindings_suspended"] != float64(1) {
		t.Fatalf("delete audit = %v", m)
	}
}

// A failed delete rolls back: the team has a child, so its projects keep
// their team and their bindings stay live.
func TestLive_GatewayBinding_FailedTeamDeleteKeepsBindings(t *testing.T) {
	c := newCatFixture(t)
	c.l.addGrant(t, c.adminID.String(), []string{"team.edit"}, `{}`)
	mid := c.seedTenant(t, "team-m", &c.x.team)
	c.seedTenant(t, "team-l", &mid.team)
	id := c.bindID(t, c.admin, mid.uat, mid.secret, c.byName["team-a-apps/payments-api"].TargetID)
	if code, raw := c.l.callAs(t, http.MethodDelete, "/api/v1/teams/"+mid.team.String(), c.admin, nil); code == http.StatusNoContent {
		t.Fatalf("delete of a team with a child = %d %s; want refused", code, raw)
	}
	if got := c.bindingSuspended(t, id); got != "" {
		t.Fatalf("binding after a refused delete = %q; want live", got)
	}
}

// A team-scoped caller may name only a provider connection bound to the
// environment: unknown and unbound ids answer the same, so the answer
// doesn't say which ids exist. A platform admin keeps the existence check.
func TestLive_GatewayBinding_ProviderConnectionNoOracle(t *testing.T) {
	c := newCatFixture(t)
	target := c.byName["team-a-apps/payments-api"].TargetID
	conn := uuid.New()
	if _, err := c.l.pool.Exec(t.Context(), `INSERT INTO provider_connections (id, name, type, auth_method, scope) VALUES ($1, 'vault-oracle', 'vault', 'token', '{}')`, conn); err != nil {
		t.Fatal(err)
	}
	bind := func(hdr map[string]string, env, id uuid.UUID, ref string) (int, []byte) {
		return c.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", hdr, map[string]any{
			"gateway_id": c.gw.GatewayID, "environment_id": env.String(), "provider_connection_id": id.String(), "secret_ref": ref,
			"argocd_connector_id": c.connID, "argocd_target_id": target,
		})
	}
	if code, raw := bind(c.admin, c.x.uat, conn, "app/platform"); code != http.StatusCreated {
		t.Fatalf("platform bind of an unbound connection = %d %s", code, raw)
	}
	unknownCode, unknown := bind(c.x.admin, c.x.uat, uuid.New(), "app/one")
	boundElsewhere, raw := bind(c.x.admin, c.x.uat, conn, "app/one")
	if unknownCode == http.StatusCreated || unknownCode != boundElsewhere || errCode(t, unknown) != "provider_connection_not_found" || errCode(t, raw) != "provider_connection_not_found" {
		t.Fatalf("unknown = %d %s, unbound = %d %s; want the same answer", unknownCode, unknown, boundElsewhere, raw)
	}
	if _, err := c.l.pool.Exec(t.Context(), `INSERT INTO project_provider_connections (project_id, environment_id, provider_connection_id) VALUES ($1, $2, $3)`, c.x.proj, c.x.dev, conn); err != nil {
		t.Fatal(err)
	}
	if code, raw := bind(c.x.admin, c.x.uat, conn, "app/two"); code != boundElsewhere {
		t.Fatalf("bound to another environment = %d %s; want %d", code, raw, boundElsewhere)
	}
	if code, raw := bind(c.x.admin, c.x.dev, conn, "app/three"); code != http.StatusCreated {
		t.Fatalf("bound to this environment = %d %s", code, raw)
	}
	if _, err := c.l.pool.Exec(t.Context(), `INSERT INTO project_provider_connections (project_id, provider_connection_id) VALUES ($1, $2)`, c.x.proj, conn); err != nil {
		t.Fatal(err)
	}
	if code, raw := bind(c.x.admin, c.x.uat, conn, "app/four"); code != http.StatusCreated {
		t.Fatalf("bound project-wide = %d %s", code, raw)
	}
}
