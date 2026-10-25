package main

// Console catalog read (A1), AppProject to team mapping (A2) and the
// bind rules for discovered targets (A4) (api#308, ADR 0002 S4; gateway
// docs/design/discovery-contract.md section 8), through the real router
// against Postgres and Redis.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// tenant is a team with one project, its environments and a catalog
// secret bound to the project.
type tenant struct {
	team, proj, secret uuid.UUID
	uat, prod, other   uuid.UUID
	stagingProd, dev   uuid.UUID
	adminID            uuid.UUID
	admin              map[string]string // a session holding gateway.bind scoped to team
}

func (f *gwFixture) seedTenant(t *testing.T, name string, parent *uuid.UUID) *tenant {
	t.Helper()
	ctx := t.Context()
	tn := &tenant{team: uuid.New(), proj: uuid.New(), secret: uuid.New()}
	if _, err := f.l.pool.Exec(ctx, `INSERT INTO teams (id, name, parent_team_id) VALUES ($1, $2, $3)`, tn.team, name+"-"+tn.team.String()[:6], parent); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.pool.Exec(ctx, `INSERT INTO projects (id, name, team_id) VALUES ($1, $2, $3)`, tn.proj, "proj-"+tn.proj.String()[:8], tn.team); err != nil {
		t.Fatal(err)
	}
	for _, e := range []struct {
		dst       *uuid.UUID
		name, typ string
		kind      string
	}{{&tn.uat, "uat", "uat", "non_prod"}, {&tn.prod, "prod", "prod", "prod"}, {&tn.other, "other", "other", "non_prod"},
		{&tn.stagingProd, "staging", "staging", "prod"}, {&tn.dev, "dev", "dev", "non_prod"}} {
		*e.dst = uuid.New()
		if _, err := f.l.pool.Exec(ctx, `INSERT INTO environments (id, project_id, name, type, kind, observation_source) VALUES ($1, $2, $3, $4, $5, 'gateway')`,
			*e.dst, tn.proj, e.name, e.typ, e.kind); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.l.pool.Exec(ctx, `INSERT INTO secrets (id, cluster_name, provider_type, secret_ref, status) VALUES ($1, 'tenant-a-uat', 'vault', $2, 'present')`,
		tn.secret, "team-alpha/uat/"+tn.secret.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.pool.Exec(ctx, `INSERT INTO project_secrets (project_id, secret_id) VALUES ($1, $2)`, tn.proj, tn.secret); err != nil {
		t.Fatal(err)
	}
	tn.adminID = uuid.New()
	cookie := f.l.sessionFor(t, tn.adminID, name+"-admin-"+tn.adminID.String()[:6]+"@example.com")
	f.l.addGrant(t, tn.adminID.String(), []string{"gateway.bind"}, `{"team_id":"`+tn.team.String()+`"}`)
	tn.admin = map[string]string{"Cookie": cookie}
	return tn
}

// catFixture is a Gateway whose argocd-main discovered six targets:
// three in team-a-apps (mapped to team X), two in team-b-apps (team Y)
// and "shared" in both, approved for its scope.
type catFixture struct {
	*discFixture
	x, y    *tenant
	entries []discEntry
	byName  map[string]discEntry
}

func newCatFixture(t *testing.T) *catFixture {
	t.Helper()
	gf := newGatewayFixture(t)
	d := newDiscFixture(t, gf, "cat-gw")
	c := &catFixture{discFixture: d, x: gf.seedTenant(t, "team-x", nil), y: gf.seedTenant(t, "team-y", nil), byName: map[string]discEntry{}}
	for i, e := range []struct{ project, name string }{
		{"team-a-apps", "payments-api"}, {"team-a-apps", "billing-api"}, {"team-a-apps", "shared"},
		{"team-b-apps", "orders-api"}, {"team-b-apps", "shared"}, {"team-b-apps", "reports-api"},
	} {
		c.entries = append(c.entries, discEntry{TargetID: discTargetID(100 + i), AppProject: e.project, Namespace: "argocd", Name: e.name})
	}
	slices.SortFunc(c.entries, func(a, b discEntry) int { return strings.Compare(a.TargetID, b.TargetID) })
	for _, e := range c.entries {
		c.byName[e.AppProject+"/"+e.Name] = e
	}
	l := d.lease(t)
	d.mustUpload(t, uploadBody(l, c.entries))
	if code, raw := c.putMapping(t, c.mapping(c.x.team, c.y.team)); code != http.StatusOK {
		t.Fatalf("mapping = %d %s", code, raw)
	}
	if code, raw := d.approveScope(t, d.gw.GatewayID, d.connID, map[string]any{"scope_digest": testScope()}); code != http.StatusOK {
		t.Fatalf("approve = %d %s", code, raw)
	}
	return c
}

func (c *catFixture) mapping(a, b uuid.UUID) map[string]any {
	return map[string]any{"mappings": []map[string]any{
		{"app_project": "team-a-apps", "team_ids": []string{a.String()}},
		{"app_project": "team-b-apps", "team_ids": []string{b.String()}},
	}}
}

func (c *catFixture) putMapping(t *testing.T, body any) (int, []byte) {
	t.Helper()
	return c.l.callAs(t, http.MethodPut, "/api/v1/admin/gateways/"+c.gw.GatewayID+"/connectors/"+c.connID+"/project-teams", c.admin, body)
}

type catItem struct {
	TargetID   string   `json:"target_id"`
	Source     string   `json:"source"`
	Status     string   `json:"status"`
	AppProject string   `json:"app_project"`
	Name       string   `json:"name"`
	LookAlike  bool     `json:"look_alike"`
	IsNew      bool     `json:"is_new"`
	Bindings   int      `json:"binding_count"`
	TeamIDs    []string `json:"team_ids"`
}

type catPage struct {
	Items      []catItem `json:"items"`
	NextCursor string    `json:"next_cursor"`
}

func (c *catFixture) catalog(t *testing.T, hdr map[string]string, query url.Values) (int, catPage, []byte) {
	t.Helper()
	path := "/api/v1/gateway-catalog"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	code, raw := c.l.callAs(t, http.MethodGet, path, hdr, nil)
	var p catPage
	if code == http.StatusOK {
		mustJSON(t, raw, &p)
	}
	return code, p, raw
}

func (c *catFixture) bindAs(t *testing.T, hdr map[string]string, env, secret uuid.UUID, target string) (int, []byte) {
	t.Helper()
	return c.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", hdr, map[string]any{
		"gateway_id": c.gw.GatewayID, "environment_id": env.String(), "secret_id": secret.String(),
		"argocd_connector_id": c.connID, "argocd_target_id": target,
	})
}

func names(items []catItem) []string {
	out := []string{}
	for _, it := range items {
		out = append(out, it.AppProject+"/"+it.Name)
	}
	slices.Sort(out)
	return out
}

// TestLive_GatewayCatalog_TeamScoped: a team X admin sees only team X's
// targets, with team_ids limited to its teams and look_alike computed
// over what it sees; a team Y target answers 404 on bind exactly like
// an unknown one; a binding into another team's project is 404. A
// project_id-scoped grant reads as no grant.
func TestLive_GatewayCatalog_TeamScoped(t *testing.T) {
	c := newCatFixture(t)
	code, all, raw := c.catalog(t, c.admin, nil)
	if code != http.StatusOK || len(all.Items) != 6 {
		t.Fatalf("platform admin catalog = %d %s; want six items", code, raw)
	}
	for _, it := range all.Items {
		if it.Name == "shared" && !it.LookAlike {
			t.Fatalf("platform admin: %s not flagged look_alike", it.AppProject)
		}
		if !it.IsNew || it.Source != "discovered" {
			t.Fatalf("item = %+v", it)
		}
	}
	code, xs, raw := c.catalog(t, c.x.admin, nil)
	if code != http.StatusOK {
		t.Fatalf("team X catalog = %d %s", code, raw)
	}
	if got := names(xs.Items); !slices.Equal(got, []string{"team-a-apps/billing-api", "team-a-apps/payments-api", "team-a-apps/shared"}) {
		t.Fatalf("team X sees %v", got)
	}
	for _, it := range xs.Items {
		if !slices.Equal(it.TeamIDs, []string{c.x.team.String()}) || it.LookAlike {
			t.Fatalf("team X item = %+v; want only its team and no look-alike across teams", it)
		}
	}
	for _, s := range []string{"orders-api", "reports-api", c.y.team.String(), c.byName["team-b-apps/shared"].TargetID} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("team X catalog leaks %q: %s", s, raw)
		}
	}
	if _, ys, _ := c.catalog(t, c.x.admin, url.Values{"team_id": {c.y.team.String()}}); len(ys.Items) != 0 {
		t.Fatalf("team X filtering by team Y = %v; want nothing", names(ys.Items))
	}

	yTarget := c.byName["team-b-apps/orders-api"].TargetID
	code, raw = c.bindAs(t, c.x.admin, c.x.uat, c.x.secret, yTarget)
	if code != http.StatusNotFound || errCode(t, raw) != "target_not_found" {
		t.Fatalf("team X binding a team Y target = %d %s; want 404 target_not_found", code, raw)
	}
	code, unknown := c.bindAs(t, c.x.admin, c.x.uat, c.x.secret, discTargetID(9999))
	if code != http.StatusNotFound || string(unknown) != string(raw) {
		t.Fatalf("unknown target = %d %s; want the same answer as another team's target (%s)", code, unknown, raw)
	}
	xTarget := c.byName["team-a-apps/payments-api"].TargetID
	if code, raw := c.bindAs(t, c.x.admin, c.y.uat, c.y.secret, xTarget); code != http.StatusNotFound || errCode(t, raw) != "environment_not_found" {
		t.Fatalf("team X binding into team Y's project = %d %s; want 404 environment_not_found", code, raw)
	}
	code, raw = c.bindAs(t, c.x.admin, c.x.uat, c.x.secret, xTarget)
	if code != http.StatusCreated {
		t.Fatalf("team X binding its own target = %d %s", code, raw)
	}
	var created struct {
		ID string `json:"id"`
	}
	mustJSON(t, raw, &created)
	allow := c.l.auditRowsWithStatus(t, "gateway.binding.create")
	last := allow[len(allow)-1]
	if last.Status != "success" || last.Metadata["permission_scope"] != "team" || last.Metadata["target_source"] != "discovered" {
		t.Fatalf("allow audit = %+v", last)
	}
	denied := 0
	for _, r := range allow {
		if r.Status == "denied" {
			denied++
			for k := range r.Metadata {
				if k != "error_kind" {
					t.Fatalf("deny audit carries %q: %v", k, r.Metadata)
				}
			}
		}
	}
	if denied != 3 {
		t.Fatalf("denied bind audits = %d; want 3", denied)
	}
	// Team Y cannot delete team X's binding; team X can.
	if code, raw := c.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+created.ID, c.y.admin, nil); code != http.StatusNotFound {
		t.Fatalf("team Y deleting team X's binding = %d %s; want 404", code, raw)
	}
	if code, raw := c.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+created.ID, c.x.admin, nil); code != http.StatusNoContent {
		t.Fatalf("team X deleting its binding = %d %s", code, raw)
	}

	// An AppProject mapped to both teams shows team X only its own team.
	if code, raw := c.putMapping(t, map[string]any{"mappings": []map[string]any{
		{"app_project": "team-a-apps", "team_ids": []string{c.x.team.String(), c.y.team.String()}},
		{"app_project": "team-b-apps", "team_ids": []string{c.y.team.String()}},
	}}); code != http.StatusOK {
		t.Fatalf("shared mapping = %d %s", code, raw)
	}
	_, shared, raw := c.catalog(t, c.x.admin, nil)
	for _, it := range shared.Items {
		if !slices.Equal(it.TeamIDs, []string{c.x.team.String()}) {
			t.Fatalf("team X item with a shared AppProject = %+v; want only team X listed", it)
		}
	}
	if strings.Contains(string(raw), c.y.team.String()) {
		t.Fatalf("team X catalog names team Y: %s", raw)
	}
	// A project_id-scoped gateway.bind is no grant; neither is nothing.
	p := uuid.New()
	pc := c.l.sessionFor(t, p, "proj-scoped-"+p.String()[:6]+"@example.com")
	c.l.addGrant(t, p.String(), []string{"gateway.bind"}, `{"project_id":"`+c.x.proj.String()+`"}`)
	ph := map[string]string{"Cookie": pc}
	if code, _, raw := c.catalog(t, ph, nil); code != http.StatusForbidden {
		t.Fatalf("project-scoped catalog = %d %s; want 403", code, raw)
	}
	if code, raw := c.bindAs(t, ph, c.x.uat, c.x.secret, xTarget); code != http.StatusForbidden {
		t.Fatalf("project-scoped bind = %d %s; want 403", code, raw)
	}
}

// TestLive_GatewayCatalog_ProductionGuardAndTeamRelation: a team-scoped
// bind into type prod or other, or kind prod, is refused; a platform
// admin may bind into prod. The team relation applies to platform
// admins too.
func TestLive_GatewayCatalog_ProductionGuardAndTeamRelation(t *testing.T) {
	c := newCatFixture(t)
	xTarget := c.byName["team-a-apps/payments-api"].TargetID
	for name, env := range map[string]uuid.UUID{"prod": c.x.prod, "other": c.x.other, "staging with kind prod": c.x.stagingProd} {
		if code, raw := c.bindAs(t, c.x.admin, env, c.x.secret, xTarget); code != http.StatusForbidden || errCode(t, raw) != "production_binding_platform_only" {
			t.Fatalf("team-scoped bind into %s = %d %s; want 403 production_binding_platform_only", name, code, raw)
		}
	}
	if code, raw := c.bindAs(t, c.x.admin, c.x.dev, c.x.secret, xTarget); code != http.StatusCreated {
		t.Fatalf("team-scoped bind into dev = %d %s", code, raw)
	}
	if code, raw := c.bindAs(t, c.admin, c.x.prod, c.x.secret, xTarget); code != http.StatusCreated {
		t.Fatalf("platform admin bind into prod = %d %s", code, raw)
	}
	yTarget := c.byName["team-b-apps/orders-api"].TargetID
	if code, raw := c.bindAs(t, c.admin, c.x.uat, c.x.secret, yTarget); code != http.StatusForbidden || errCode(t, raw) != "target_team_mismatch" {
		t.Fatalf("platform admin binding a team Y target into a team X project = %d %s; want 403 target_team_mismatch", code, raw)
	}
	kinds := map[string]int{}
	for _, r := range c.l.auditRowsWithStatus(t, "gateway.binding.create") {
		if r.Status == "denied" {
			kinds[r.Metadata["error_kind"].(string)]++
		}
	}
	if kinds["production_binding_platform_only"] != 3 || kinds["target_team_mismatch"] != 1 {
		t.Fatalf("deny audit kinds = %v", kinds)
	}
}

// TestLive_GatewayCatalog_PagingAndQuery: keyset paging walks every
// item once in sort order; a cursor is bound to its filters; unknown or
// malformed parameters are refused.
func TestLive_GatewayCatalog_PagingAndQuery(t *testing.T) {
	c := newCatFixture(t)
	var seen []string
	q := url.Values{"limit": {"2"}}
	for i := 0; i < 10; i++ {
		code, p, raw := c.catalog(t, c.admin, q)
		if code != http.StatusOK {
			t.Fatalf("page %d = %d %s", i, code, raw)
		}
		for _, it := range p.Items {
			seen = append(seen, it.AppProject+"/"+it.Name+"/"+it.TargetID)
		}
		if p.NextCursor == "" {
			break
		}
		q.Set("cursor", p.NextCursor)
	}
	if len(seen) != 6 || !slices.IsSorted(seen) {
		t.Fatalf("paged items = %v; want all six once, sorted", seen)
	}
	_, first, _ := c.catalog(t, c.admin, url.Values{"limit": {"1"}})
	for _, bad := range []url.Values{
		{"cursor": {first.NextCursor}, "app_project": {"team-a-apps"}},
		{"cursor": {"not-a-cursor"}},
	} {
		if code, _, raw := c.catalog(t, c.admin, bad); code != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_cursor") {
			t.Fatalf("cursor %v = %d %s; want 400 invalid_cursor", bad, code, raw)
		}
	}
	for _, bad := range []url.Values{{"color": {"red"}}, {"limit": {"0"}}, {"limit": {"201"}}, {"status": {"gone"}}, {"q": {"A B"}}, {"gateway_id": {"x"}}} {
		if code, _, raw := c.catalog(t, c.admin, bad); code != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_query") {
			t.Fatalf("query %v = %d %s; want 400 invalid_query", bad, code, raw)
		}
	}
	_, f, _ := c.catalog(t, c.admin, url.Values{"q": {"api"}, "app_project": {"team-b-apps"}})
	if got := names(f.Items); !slices.Equal(got, []string{"team-b-apps/orders-api", "team-b-apps/reports-api"}) {
		t.Fatalf("filtered = %v", got)
	}
	_, fx, _ := c.catalog(t, c.x.admin, url.Values{"limit": {"1"}})
	if len(fx.Items) != 1 || fx.NextCursor == "" {
		t.Fatalf("team X first page = %+v", fx)
	}
}

// TestLive_GatewayCatalog_MappingRemovalSuspends: changing the mapping
// so a binding's project is no longer covered suspends the binding with
// mapping_removed, cancels its open task with binding_suspended and
// stops dispatch. Mapping back does not resume it. The mapping write
// refuses unknown AppProjects and teams and, on an approved connector,
// an incomplete mapping.
func TestLive_GatewayCatalog_MappingRemovalSuspends(t *testing.T) {
	c := newCatFixture(t)
	xTarget := c.byName["team-a-apps/payments-api"].TargetID
	code, raw := c.bindAs(t, c.x.admin, c.x.uat, c.x.secret, xTarget)
	if code != http.StatusCreated {
		t.Fatalf("bind = %d %s", code, raw)
	}
	var b struct {
		ID string `json:"id"`
	}
	mustJSON(t, raw, &b)
	o := c.obsAgent(t)
	reqID, _ := c.execute(t, o.base, o.hdr, c.x.proj, c.x.uat, c.x.secret)
	if ts := c.taskRows(t, reqID); len(ts) != 1 || !ts[0].State.Open() {
		t.Fatalf("tasks = %+v; want one open task", ts)
	}

	bad := []struct {
		body any
		code int
		err  string
	}{
		{map[string]any{"mappings": []map[string]any{{"app_project": "team-z-apps", "team_ids": []string{c.x.team.String()}}}}, 422, "unknown_app_project"},
		{c.mapping(c.x.team, uuid.New()), 404, "team_not_found"},
		{map[string]any{"mappings": []map[string]any{{"app_project": "team-a-apps", "team_ids": []string{c.x.team.String()}}}}, 409, "project_mapping_incomplete"},
		{map[string]any{"mappings": []map[string]any{{"app_project": "team-a-apps", "team_ids": []string{}}}}, 400, "invalid_request"},
	}
	for _, x := range bad {
		code, raw := c.putMapping(t, x.body)
		if code != x.code || !strings.Contains(string(raw), x.err) {
			t.Fatalf("mapping %v = %d %s; want %d %s", x.body, code, raw, x.code, x.err)
		}
	}

	if code, raw := c.putMapping(t, c.mapping(c.y.team, c.y.team)); code != http.StatusOK {
		t.Fatalf("remap = %d %s", code, raw)
	}
	if got := c.bindingSuspended(t, b.ID); got != "mapping_removed" {
		t.Fatalf("binding suspended_reason = %q; want mapping_removed", got)
	}
	ts := c.taskRows(t, reqID)
	if len(ts) != 1 || ts[0].State != "cancelled" || ts[0].VerdictReason != "binding_suspended" {
		t.Fatalf("task = %+v; want cancelled binding_suspended", ts)
	}
	rows := c.l.auditRows(t, "gateway.connector.project_mapping_changed")
	m := rows[len(rows)-1].Metadata
	if m["bindings_suspended"] != float64(1) || m["tasks_cancelled"] != float64(1) || !reflectEqualSanitized("gateway.connector.project_mapping_changed", m) {
		t.Fatalf("mapping audit = %v", m)
	}
	// Mapping back does not resume the binding, and nothing dispatches.
	if code, raw := c.putMapping(t, c.mapping(c.x.team, c.y.team)); code != http.StatusOK {
		t.Fatalf("map back = %d %s", code, raw)
	}
	if got := c.bindingSuspended(t, b.ID); got != "mapping_removed" {
		t.Fatalf("binding after mapping back = %q; want still mapping_removed", got)
	}
	req2, _ := c.execute(t, o.base, o.hdr, c.x.proj, c.x.uat, c.x.secret)
	if ts := c.taskRows(t, req2); len(ts) != 0 {
		t.Fatalf("tasks for a suspended binding = %+v; want none", ts)
	}
	// The claim skips a suspended binding even when its task exists.
	if _, err := c.l.pool.Exec(t.Context(), `UPDATE gateway_connector_bindings SET suspended_reason = NULL, suspended_at = NULL WHERE id = $1`, b.ID); err != nil {
		t.Fatal(err)
	}
	req3, _ := c.execute(t, o.base, o.hdr, c.x.proj, c.x.uat, c.x.secret)
	c.makeClaimable(t, req3)
	if _, err := c.l.pool.Exec(t.Context(), `UPDATE gateway_connector_bindings SET suspended_reason = 'mapping_removed', suspended_at = now() WHERE id = $1`, b.ID); err != nil {
		t.Fatal(err)
	}
	c.mustHB(t, c.gw, hbV2(uuid.NewString(), testScope(), true, ""))
	if code, _, _, raw := c.claimAs(t, c.gw.GatewayID, c.gw.GatewaySecret, uuid.NewString()); code != http.StatusNoContent {
		t.Fatalf("claim of a suspended binding's task = %d %s; want 204", code, raw)
	}
}

type obsAgent struct {
	base string
	hdr  map[string]string
}

func (c *catFixture) obsAgent(t *testing.T) obsAgent {
	t.Helper()
	op := c.l.grantUser(t, []string{"agent.mint"}, `{}`)
	code, body := c.l.call(t, http.MethodPost, "/api/v1/agents", op, agentMintBody("cat-agent-"+uuid.NewString()[:8]))
	if code != http.StatusCreated {
		t.Fatalf("mint agent = %d %s", code, body)
	}
	var a struct {
		ID          uuid.UUID `json:"id"`
		AgentSecret string    `json:"agent_secret"`
	}
	mustJSON(t, body, &a)
	return obsAgent{base: "/api/v1/agents/" + a.ID.String(), hdr: agentHeaders(a.AgentSecret)}
}

// TestLive_GatewayCatalog_DiscoveredEndToEnd: a team-scoped binding of a
// discovered target is dispatched, and its evidence is accepted only for
// the object the catalog names with the target id as its identity
// digest.
func TestLive_GatewayCatalog_DiscoveredEndToEnd(t *testing.T) {
	c := newCatFixture(t)
	e := c.byName["team-a-apps/payments-api"]
	if code, raw := c.bindAs(t, c.x.admin, c.x.uat, c.x.secret, e.TargetID); code != http.StatusCreated {
		t.Fatalf("bind = %d %s", code, raw)
	}
	o := c.obsAgent(t)
	replica := uuid.NewString()
	for _, digest := range []string{discTargetID(5555), e.TargetID} {
		reqID, _ := c.execute(t, o.base, o.hdr, c.x.proj, c.x.uat, c.x.secret)
		c.makeClaimable(t, reqID)
		c.mustHB(t, c.gw, hbV2(replica, testScope(), true, ""))
		code, _, task, raw := c.claimAs(t, c.gw.GatewayID, c.gw.GatewaySecret, replica)
		if code != http.StatusOK || task.ConnectorRefs[0].TargetID != e.TargetID {
			t.Fatalf("claim = %d %s", code, raw)
		}
		res := argoResult(task, c.gw.GatewayID, replica)
		res["stages"].([]map[string]any)[0]["resource"].(map[string]any)["name"] = e.Name
		res["stages"].([]map[string]any)[0]["resource"].(map[string]any)["identity_digest"] = digest
		code, out := c.postResult(t, c.gw.GatewayID, c.gw.GatewaySecret, task.TaskID, res)
		if digest == e.TargetID {
			if code != http.StatusOK {
				t.Fatalf("evidence with the target id as identity = %d %s", code, out)
			}
		} else if code != http.StatusUnprocessableEntity || !strings.Contains(string(out), "identity_digest_mismatch") {
			t.Fatalf("evidence for another object = %d %s; want 422 identity_digest_mismatch", code, out)
		}
	}
}

// TestLive_GatewayCatalog_StructureCheck: a holder of a team-scoped
// gateway.bind (and global team.edit) cannot move a team or a project
// under its team (skills#103 phase 1); a move inside its subtree, and
// the same move by a platform admin, is allowed.
func TestLive_GatewayCatalog_StructureCheck(t *testing.T) {
	f := newGatewayFixture(t)
	x := f.seedTenant(t, "team-x", nil)
	z := f.seedTenant(t, "team-z", nil)
	child := f.seedTenant(t, "team-x-child", &x.team)
	f.l.addGrant(t, x.adminID.String(), []string{"team.edit"}, `{}`)

	reparent := func(hdr map[string]string, team, parent uuid.UUID) (int, []byte) {
		var name string
		if err := f.l.pool.QueryRow(t.Context(), `SELECT name FROM teams WHERE id = $1`, team).Scan(&name); err != nil {
			t.Fatal(err)
		}
		return f.l.callAs(t, http.MethodPut, "/api/v1/teams/"+team.String(), hdr, map[string]any{"name": name, "parent_team_id": parent.String()})
	}
	if code, raw := reparent(x.admin, z.team, x.team); code != http.StatusForbidden || !strings.Contains(string(raw), "self_scope_expansion_not_allowed") {
		t.Fatalf("re-parent of team Z under team X by its scoped admin = %d %s; want 403", code, raw)
	}
	if code, raw := f.l.callAs(t, http.MethodPut, "/api/v1/projects/"+z.proj.String()+"/team", x.admin,
		map[string]any{"team_id": x.team.String()}); code != http.StatusForbidden || !strings.Contains(string(raw), "self_scope_expansion_not_allowed") {
		t.Fatalf("project move into team X by its scoped admin = %d %s; want 403", code, raw)
	}
	if code, raw := f.l.callAs(t, http.MethodPut, "/api/v1/projects/"+child.proj.String()+"/team", x.admin,
		map[string]any{"team_id": x.team.String()}); code != http.StatusNoContent {
		t.Fatalf("project move inside team X's subtree = %d %s; want 204", code, raw)
	}
	f.l.addGrant(t, f.adminID.String(), []string{"team.edit"}, `{}`)
	if code, raw := reparent(f.admin, z.team, x.team); code != http.StatusOK {
		t.Fatalf("re-parent by a platform admin = %d %s; want 200", code, raw)
	}
}

// TestLive_GatewayCatalog_Unapproved: before approval a team-scoped
// admin sees nothing and cannot bind; a platform admin sees everything.
func TestLive_GatewayCatalog_Unapproved(t *testing.T) {
	gf := newGatewayFixture(t)
	d := newDiscFixture(t, gf, "cat-unapproved-gw")
	x := gf.seedTenant(t, "team-x", nil)
	entries := discEntries(2)
	d.mustUpload(t, uploadBody(d.lease(t), entries))
	c := &catFixture{discFixture: d, x: x, y: x}
	if code, raw := c.putMapping(t, c.mapping(x.team, x.team)); code != http.StatusOK {
		t.Fatalf("mapping = %d %s", code, raw)
	}
	if _, p, _ := c.catalog(t, x.admin, nil); len(p.Items) != 0 {
		t.Fatalf("team X before approval sees %v", names(p.Items))
	}
	if code, raw := c.bindAs(t, x.admin, x.uat, x.secret, entries[0].TargetID); code != http.StatusNotFound {
		t.Fatalf("team X bind before approval = %d %s; want 404", code, raw)
	}
	if _, p, _ := c.catalog(t, gf.admin, nil); len(p.Items) != 2 {
		t.Fatalf("platform admin before approval sees %d items; want 2", len(p.Items))
	}
	var resp map[string]any
	_, raw := gf.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+d.gw.GatewayID+"/connectors/"+d.connID+"/project-teams", gf.admin, nil)
	_ = json.Unmarshal(raw, &resp)
	if resp["complete"] != true {
		t.Fatalf("mapping read = %s", raw)
	}
}

// TestLive_GatewayCatalog_BindMissing: a discovered target that left the
// catalog stays visible as missing and cannot be bound (409
// target_missing).
func TestLive_GatewayCatalog_BindMissing(t *testing.T) {
	c := newCatFixture(t)
	gone := c.byName["team-a-apps/billing-api"]
	var keep []discEntry
	for _, e := range c.entries {
		if e.TargetID != gone.TargetID {
			keep = append(keep, e)
		}
	}
	c.mustUpload(t, uploadBody(c.lease(t), keep))
	_, p, _ := c.catalog(t, c.x.admin, url.Values{"status": {"missing"}})
	if len(p.Items) != 1 || p.Items[0].TargetID != gone.TargetID {
		t.Fatalf("team X missing items = %+v", p.Items)
	}
	if code, raw := c.bindAs(t, c.x.admin, c.x.uat, c.x.secret, gone.TargetID); code != http.StatusConflict || errCode(t, raw) != "target_missing" {
		t.Fatalf("bind a missing target = %d %s; want 409 target_missing", code, raw)
	}
}

// TestLive_GatewayCatalog_BoundTargetLimit: a Gateway with 4096 bound
// targets refuses a bind of a new target (409
// gateway_bound_target_limit, decision E-4), so bound_targets never
// passes the Gateway's 4096 cap.
func TestLive_GatewayCatalog_BoundTargetLimit(t *testing.T) {
	c := newCatFixture(t)
	if _, err := c.l.pool.Exec(t.Context(), `INSERT INTO gateway_connector_bindings
		(gateway_id, environment_id, secret_id, expected_stages, argocd_connector_id, argocd_target_id, created_by)
		SELECT $1, $2, $3, '["argocd_context"]', $4, 'bulk-' || i, 'test' FROM generate_series(1, 4096) i`,
		c.gw.GatewayID, c.x.uat, c.x.secret, c.connID); err != nil {
		t.Fatal(err)
	}
	if code, raw := c.bindAs(t, c.x.admin, c.x.uat, c.x.secret, c.byName["team-a-apps/payments-api"].TargetID); code != http.StatusConflict ||
		errCode(t, raw) != "gateway_bound_target_limit" {
		t.Fatalf("bind past 4096 bound targets = %d %s; want 409 gateway_bound_target_limit", code, raw)
	}
}
