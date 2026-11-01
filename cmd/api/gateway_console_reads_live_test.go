package main

// The reads the console needs for S5 (ADR 0002): the team-filtered
// bindings list, the project_id catalog filter and the upload's scope
// digest on the admin read. Through the real router against Postgres and
// Redis.

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type bindingItem struct {
	ID              string `json:"id"`
	ProjectID       string `json:"project_id"`
	SuspendedReason string `json:"suspended_reason"`
	AppProject      string `json:"app_project"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
}

type bindingPage struct {
	Items      []bindingItem `json:"items"`
	NextCursor string        `json:"next_cursor"`
}

func (c *catFixture) bindings(t *testing.T, hdr map[string]string, query url.Values) (int, bindingPage, []byte) {
	t.Helper()
	path := "/api/v1/gateway-bindings"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	code, raw := c.l.callAs(t, http.MethodGet, path, hdr, nil)
	var p bindingPage
	if code == http.StatusOK {
		mustJSON(t, raw, &p)
	}
	return code, p, raw
}

func bindingIDs(items []bindingItem) []string {
	out := []string{}
	for _, it := range items {
		out = append(out, it.ID)
	}
	slices.Sort(out)
	return out
}

func sameIDs(items []bindingItem, want ...string) bool {
	slices.Sort(want)
	return slices.Equal(bindingIDs(items), want)
}

func (c *catFixture) wantBindings(t *testing.T, hdr map[string]string, query url.Values, want ...string) bindingPage {
	t.Helper()
	code, p, raw := c.bindings(t, hdr, query)
	if code != http.StatusOK || !sameIDs(p.Items, want...) {
		t.Fatalf("bindings %v = %d %s; want ids %v", query, code, raw, want)
	}
	return p
}

// A team admin lists its own projects' discovered bindings and nothing
// else: no other team's, and no static binding, even in its own project.
func TestLive_GatewayBindingsRead_TeamFiltered(t *testing.T) {
	c := newCatFixture(t)
	x := c.bindID(t, c.x.admin, c.x.uat, c.x.secret, c.byName["team-a-apps/payments-api"].TargetID)
	y := c.bindID(t, c.y.admin, c.y.uat, c.y.secret, c.byName["team-b-apps/orders-api"].TargetID)
	sgw, scid := c.gatewayReady(t, "bindings-static-gw")
	static := c.bind(t, sgw.GatewayID, scid, c.x.dev, c.x.secret, "payments-api")

	p := c.wantBindings(t, c.x.admin, nil, x)
	if it := p.Items[0]; it.AppProject != "team-a-apps" || it.Namespace != "argocd" || it.Name != "payments-api" || it.ProjectID != c.x.proj.String() {
		t.Fatalf("X's binding = %+v", it)
	}
	c.wantBindings(t, c.y.admin, nil, y)
	c.wantBindings(t, c.x.admin, url.Values{"project_id": {c.y.proj.String()}})
	c.wantBindings(t, c.x.admin, url.Values{"project_id": {c.x.proj.String()}}, x)
	c.wantBindings(t, c.admin, url.Values{"gateway_id": {sgw.GatewayID}}, static)
	c.wantBindings(t, c.admin, url.Values{"gateway_id": {c.gw.GatewayID}}, x, y)

	// Global gateway.list reads everything but binds nothing.
	reader := uuid.New()
	hdr := map[string]string{"Cookie": c.l.sessionFor(t, reader, "bindings-reader-"+reader.String()[:8]+"@example.com")}
	c.l.addGrant(t, reader.String(), []string{"gateway.list"}, `{}`)
	c.wantBindings(t, hdr, url.Values{"project_id": {c.x.proj.String()}}, x, static)

	for name, grant := range map[string]struct{ perm, scope string }{
		"list team-scoped":    {"gateway.list", `{"team_id":"` + c.x.team.String() + `"}`},
		"bind project-scoped": {"gateway.bind", `{"project_id":"` + c.x.proj.String() + `"}`},
		"other permission":    {"secret.list", `{}`},
	} {
		uid := uuid.New()
		h := map[string]string{"Cookie": c.l.sessionFor(t, uid, "bindings-"+uid.String()[:8]+"@example.com")}
		c.l.addGrant(t, uid.String(), []string{grant.perm}, grant.scope)
		if code, _, raw := c.bindings(t, h, nil); code != http.StatusForbidden {
			t.Fatalf("%s: bindings = %d %s; want 403", name, code, raw)
		}
	}
	// The admin route stays global-only (contract section 8.2).
	if code, raw := c.l.callAs(t, http.MethodGet, "/api/v1/admin/gateway-bindings", c.x.admin, nil); code != http.StatusForbidden {
		t.Fatalf("admin bindings as a team admin = %d %s; want 403", code, raw)
	}
	for _, q := range []url.Values{{"team_id": {c.x.team.String()}}, {"project_id": {"nope"}}, {"suspended": {"maybe"}}, {"limit": {"0"}}, {"limit": {"201"}}} {
		if code, _, raw := c.bindings(t, c.x.admin, q); code != http.StatusBadRequest {
			t.Fatalf("bindings %v = %d %s; want 400", q, code, raw)
		}
	}
}

// A mapping change hides the target from the team that owns the binding.
// The binding stays listed with its reason, without the target's fields.
func TestLive_GatewayBindingsRead_MappingRemoved(t *testing.T) {
	c := newCatFixture(t)
	id := c.bindID(t, c.x.admin, c.x.uat, c.x.secret, c.byName["team-a-apps/payments-api"].TargetID)
	live := c.bindID(t, c.x.admin, c.x.dev, c.x.secret, c.byName["team-a-apps/billing-api"].TargetID)
	c.wantBindings(t, c.x.admin, url.Values{"suspended": {"true"}})
	c.wantBindings(t, c.x.admin, url.Values{"suspended": {"false"}}, id, live)

	if code, raw := c.putMapping(t, c.mapping(c.y.team, c.y.team)); code != http.StatusOK {
		t.Fatalf("remap = %d %s", code, raw)
	}
	code, p, raw := c.bindings(t, c.x.admin, url.Values{"suspended": {"true"}})
	if code != http.StatusOK || len(p.Items) != 2 {
		t.Fatalf("suspended = %d %s; want both bindings", code, raw)
	}
	for _, it := range p.Items {
		if it.SuspendedReason != "mapping_removed" || it.AppProject != "" || it.Namespace != "" || it.Name != "" {
			t.Fatalf("suspended item = %+v", it)
		}
	}
	if strings.Contains(string(raw), "payments-api") || strings.Contains(string(raw), "team-a-apps") {
		t.Fatalf("the read leaks a hidden target: %s", raw)
	}
	// Unbinding stays on rules 1 and 3.
	if code, raw := c.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+id, c.x.admin, nil); code != http.StatusNotFound {
		t.Fatalf("X unbinds a hidden target = %d %s; want 404", code, raw)
	}
	// A platform admin still sees the target. The new owner doesn't get
	// another project's binding.
	if _, p, _ := c.bindings(t, c.admin, url.Values{"project_id": {c.x.proj.String()}}); len(p.Items) != 2 || p.Items[0].Name == "" {
		t.Fatalf("platform view = %+v", p.Items)
	}
	c.wantBindings(t, c.y.admin, nil)
}

// A scope change unapproves the connector: same result for the team.
func TestLive_GatewayBindingsRead_ScopeChanged(t *testing.T) {
	c := newCatFixture(t)
	id := c.bindID(t, c.x.admin, c.x.uat, c.x.secret, c.byName["team-a-apps/payments-api"].TargetID)
	c.mustHB(t, c.gw, hbV2(c.uploader, scopeD2, true, ""))
	p := c.wantBindings(t, c.x.admin, url.Values{"suspended": {"true"}}, id)
	if it := p.Items[0]; it.SuspendedReason != "scope_changed" || it.Name != "" {
		t.Fatalf("after a scope change = %+v", it)
	}
}

func TestLive_GatewayBindingsRead_Paging(t *testing.T) {
	c := newCatFixture(t)
	want := []string{
		c.bindID(t, c.x.admin, c.x.uat, c.x.secret, c.byName["team-a-apps/payments-api"].TargetID),
		c.bindID(t, c.x.admin, c.x.dev, c.x.secret, c.byName["team-a-apps/payments-api"].TargetID),
		c.bindID(t, c.x.admin, c.x.uat, c.x.secret, c.byName["team-a-apps/billing-api"].TargetID),
	}
	c.bindID(t, c.y.admin, c.y.uat, c.y.secret, c.byName["team-b-apps/orders-api"].TargetID)
	// The same created_at must not lose a row on a page edge.
	if _, err := c.l.pool.Exec(t.Context(), `UPDATE gateway_connector_bindings SET created_at = now() WHERE gateway_id = $1`, c.gw.GatewayID); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"limit": {"2"}}
	first := c.wantBindingsPage(t, c.x.admin, q, 2)
	if first.NextCursor == "" {
		t.Fatal("first page has no next_cursor")
	}
	q.Set("cursor", first.NextCursor)
	second := c.wantBindingsPage(t, c.x.admin, q, 1)
	if second.NextCursor != "" {
		t.Fatalf("last page has next_cursor %q", second.NextCursor)
	}
	if !sameIDs(append(first.Items, second.Items...), want...) {
		t.Fatalf("pages = %v + %v; want %v", first.Items, second.Items, want)
	}
	if code, _, raw := c.bindings(t, c.x.admin, url.Values{"cursor": {first.NextCursor}, "suspended": {"true"}}); code != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_cursor") {
		t.Fatalf("a cursor under other filters = %d %s; want 400 invalid_cursor", code, raw)
	}
}

func (c *catFixture) wantBindingsPage(t *testing.T, hdr map[string]string, q url.Values, n int) bindingPage {
	t.Helper()
	code, p, raw := c.bindings(t, hdr, q)
	if code != http.StatusOK || len(p.Items) != n {
		t.Fatalf("bindings %v = %d %s; want %d items", q, code, raw, n)
	}
	return p
}

// project_id answers "what can this project bind" with bind rule 5:
// the picker shows every target that would bind and none that answers
// target_team_mismatch. team_id can't, it is an exact match on the mapped
// team.
func TestLive_GatewayCatalog_ProjectIDFilter(t *testing.T) {
	c := newCatFixture(t)
	child := c.seedTenant(t, "team-c", &c.x.team)
	sgw, _ := c.gatewayReady(t, "project-filter-static-gw")
	project := func(id uuid.UUID) url.Values { return url.Values{"project_id": {id.String()}} }
	teamA := []string{"team-a-apps/billing-api", "team-a-apps/payments-api", "team-a-apps/shared"}

	if _, p, _ := c.catalog(t, c.x.admin, url.Values{"team_id": {child.team.String()}}); len(p.Items) != 0 {
		t.Fatalf("team_id of a child team = %v; the exact match finds nothing", names(p.Items))
	}
	code, p, raw := c.catalog(t, c.x.admin, project(child.proj))
	if code != http.StatusOK || !slices.Equal(names(p.Items), teamA) {
		t.Fatalf("X, a child project = %d %s; want %v", code, raw, teamA)
	}
	// A platform admin gets the same discovered rows, plus static targets.
	q := project(child.proj)
	q.Set("gateway_id", c.gw.GatewayID)
	if _, p, raw := c.catalog(t, c.admin, q); !slices.Equal(names(p.Items), teamA) {
		t.Fatalf("platform, a child project = %s; want %v", raw, teamA)
	}
	q.Set("gateway_id", sgw.GatewayID)
	if _, p, raw := c.catalog(t, c.admin, q); len(p.Items) == 0 || p.Items[0].Source != "static" {
		t.Fatalf("platform, static targets = %s; want them kept, rule 5 is for discovered targets", raw)
	}
	// Outside the caller's teams it matches nothing, a project that does
	// not exist reads the same, and a target above the caller stays hidden.
	for name, x := range map[string]struct {
		hdr  map[string]string
		proj uuid.UUID
	}{
		"another team's project":    {c.y.admin, child.proj},
		"its own team, other team":  {c.x.admin, c.y.proj},
		"unknown project":           {c.x.admin, uuid.New()},
		"unknown project, platform": {c.admin, uuid.New()},
		"child admin, target above": {child.admin, child.proj},
	} {
		if code, p, raw := c.catalog(t, x.hdr, project(x.proj)); code != http.StatusOK || len(p.Items) != 0 {
			t.Fatalf("%s = %d %s; want an empty page", name, code, raw)
		}
	}
	if code, _, raw := c.catalog(t, c.x.admin, url.Values{"project_id": {"nope"}}); code != http.StatusBadRequest {
		t.Fatalf("bad project_id = %d %s; want 400", code, raw)
	}
	// The filter agrees with the bind rules, both ways.
	for _, it := range p.Items {
		if code, raw := c.bindAs(t, c.x.admin, child.uat, child.secret, it.TargetID); code != http.StatusCreated {
			t.Fatalf("bind listed %s = %d %s", it.Name, code, raw)
		}
	}
	hidden := c.byName["team-b-apps/orders-api"].TargetID
	if code, raw := c.bindAs(t, c.admin, child.uat, child.secret, hidden); code != http.StatusForbidden || !strings.Contains(string(raw), "target_team_mismatch") {
		t.Fatalf("bind a hidden target = %d %s; want 403 target_team_mismatch", code, raw)
	}
	// A shared AppProject: X sees the target and it covers Y's project, but
	// asking must not tell X what another team's project can bind.
	c.setMapping(t, []uuid.UUID{c.x.team, c.y.team}, []uuid.UUID{c.y.team})
	if code, p, raw := c.catalog(t, c.x.admin, project(c.y.proj)); code != http.StatusOK || len(p.Items) != 0 {
		t.Fatalf("X asks about Y's project = %d %s; want an empty page", code, raw)
	}
	// The filter pages like the others.
	q = project(child.proj)
	q.Set("limit", "2")
	code, first, raw := c.catalog(t, c.x.admin, q)
	if code != http.StatusOK || len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %d %s", code, raw)
	}
	q.Set("cursor", first.NextCursor)
	if code, second, raw := c.catalog(t, c.x.admin, q); code != http.StatusOK || len(second.Items) != 1 {
		t.Fatalf("second page = %d %s", code, raw)
	}
}

// Right after a scope change the upload still holds the old scope. The
// admin read shows both, which is how the console tells "approve now"
// from "waiting for the next catalog".
func TestLive_GatewayConnectorView_UploadDigest(t *testing.T) {
	c := newCatFixture(t)
	type connector struct {
		ID     string `json:"id"`
		Scope  string `json:"scope_digest"`
		Upload string `json:"discovery_scope_digest"`
	}
	read := func() connector {
		t.Helper()
		code, raw := c.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+c.gw.GatewayID, c.admin, nil)
		if code != http.StatusOK {
			t.Fatalf("detail = %d %s", code, raw)
		}
		var d struct {
			Connectors []connector `json:"connectors"`
		}
		mustJSON(t, raw, &d)
		for _, cn := range d.Connectors {
			if cn.ID == c.connID {
				return cn
			}
		}
		t.Fatalf("connector %s not in %s", c.connID, raw)
		return connector{}
	}
	if got := read(); got.Upload != testScope() {
		t.Fatalf("after the upload = %+v; want %s", got, testScope())
	}
	c.mustHB(t, c.gw, hbV2(c.uploader, scopeD2, true, ""))
	if got := read(); got.Scope != scopeD2 || got.Upload != testScope() {
		t.Fatalf("after a scope change = %+v", got)
	}
	if code, raw := c.approveScope(t, c.gw.GatewayID, c.connID, map[string]any{"scope_digest": scopeD2}); code != http.StatusConflict || errCode(t, raw) != "scope_digest_changed" {
		t.Fatalf("approve while the digests differ = %d %s; want 409", code, raw)
	}
}
