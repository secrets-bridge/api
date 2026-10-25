package main

// Authorization guards of the team-filtered discovery catalog and scoped
// binding (api#321, ADR 0002 C4 and C5), live through the real router:
// the team filter holds against forged cursors and every filter, only
// team_id-scoped gateway.bind reads the catalog, the AppProject mapping
// is platform-only, team-scoped binds and deletes stay inside the team
// and off prod, structure moves cannot widen a team-scoped grant, and
// evidence for a suspended binding or a missing target is refused.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// noMFASession is sessionFor without the MFA stamp.
func (l *liveApp) noMFASession(t *testing.T, userID uuid.UUID, email string) string {
	t.Helper()
	if _, err := l.pool.Exec(t.Context(),
		`INSERT INTO local_users (id, email, password_hash, display_name) VALUES ($1, $2, '\x00', $2)`, userID, email); err != nil {
		t.Fatal(err)
	}
	sessions := services.NewSessionService(storage.NewSessions(l.pool), storage.NewAuditEvents(l.pool))
	issued, err := sessions.Issue(t.Context(), userID, "127.0.0.1", "go-test")
	if err != nil {
		t.Fatal(err)
	}
	return middleware.SessionCookieName + "=" + issued.CookieValue
}

// forgeCursor builds a cursor the way services.ListCatalog does (the
// filter hash is unkeyed, so a client can compute it).
func forgeCursor(k storage.CatalogKey, filters map[string]string) string {
	keys := make([]string, 0, len(filters))
	for key := range filters {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key + "=" + filters[key] + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	raw, _ := json.Marshal(map[string]any{"k": k, "h": hex.EncodeToString(sum[:8])})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (c *catFixture) bindID(t *testing.T, hdr map[string]string, env, secret uuid.UUID, target string) string {
	t.Helper()
	code, raw := c.bindAs(t, hdr, env, secret, target)
	if code != http.StatusCreated {
		t.Fatalf("bind %s = %d %s", target, code, raw)
	}
	var b struct {
		ID string `json:"id"`
	}
	mustJSON(t, raw, &b)
	return b.ID
}

func (c *catFixture) setMapping(t *testing.T, a, b []uuid.UUID) {
	t.Helper()
	ids := func(xs []uuid.UUID) []string {
		out := []string{}
		for _, x := range xs {
			out = append(out, x.String())
		}
		return out
	}
	if code, raw := c.putMapping(t, map[string]any{"mappings": []map[string]any{
		{"app_project": "team-a-apps", "team_ids": ids(a)},
		{"app_project": "team-b-apps", "team_ids": ids(b)},
	}}); code != http.StatusOK {
		t.Fatalf("mapping = %d %s", code, raw)
	}
}

func onlyNames(items []catItem, allowed ...string) bool {
	for _, it := range items {
		if !slices.Contains(allowed, it.AppProject) {
			return false
		}
	}
	return true
}

// ---- 1. catalog -----------------------------------------------------------

// Cursor tampering: the filter hash is computable by the client, so the
// cursor is forgeable; the team filter must hold whatever the cursor
// says, and a cursor never pages into other filters' rows.
func TestLive_GatewayCatalogReview_CursorTamperingStaysInTeam(t *testing.T) {
	c := newCatFixture(t)
	// A cursor positioned before every row, valid hash for "no filters".
	start := forgeCursor(storage.CatalogKey{}, map[string]string{})
	code, p, raw := c.catalog(t, c.x.admin, url.Values{"cursor": {start}})
	if code != http.StatusOK || !onlyNames(p.Items, "team-a-apps") || len(p.Items) != 3 {
		t.Fatalf("forged start cursor for team X = %d %s; want only X's three items", code, raw)
	}
	// Forged cursor + team_id=Y with a matching hash: still nothing.
	yq := map[string]string{"team_id": c.y.team.String()}
	code, p, raw = c.catalog(t, c.x.admin, url.Values{"team_id": {c.y.team.String()}, "cursor": {forgeCursor(storage.CatalogKey{}, yq)}})
	if code != http.StatusOK || len(p.Items) != 0 {
		t.Fatalf("forged team_id=Y cursor = %d %s; want empty", code, raw)
	}
	// A platform admin's cursor replayed by team X shows team X rows only.
	_, first, _ := c.catalog(t, c.admin, url.Values{"limit": {"1"}})
	code, p, raw = c.catalog(t, c.x.admin, url.Values{"cursor": {first.NextCursor}})
	if code != http.StatusOK || !onlyNames(p.Items, "team-a-apps") {
		t.Fatalf("platform cursor replayed by team X = %d %s", code, raw)
	}
	// A cursor positioned on a team Y row (last key) leaks nothing past it.
	var gw, conn uuid.UUID
	gw, _ = uuid.Parse(c.gw.GatewayID)
	conn, _ = uuid.Parse(c.connID)
	mid := forgeCursor(storage.CatalogKey{GatewayID: gw, ConnectorID: conn, AppProject: "team-b-apps"}, map[string]string{})
	code, p, raw = c.catalog(t, c.x.admin, url.Values{"cursor": {mid}})
	if code != http.StatusOK || len(p.Items) != 0 {
		t.Fatalf("cursor into team Y's key range = %d %s; want empty", code, raw)
	}
	// A cursor made under one filter set is refused under another, even
	// for a filter that only narrows (limit is excluded from the hash).
	_, f1, _ := c.catalog(t, c.x.admin, url.Values{"limit": {"1"}})
	if code, _, raw := c.catalog(t, c.x.admin, url.Values{"cursor": {f1.NextCursor}, "source": {"discovered"}}); code != http.StatusBadRequest ||
		!strings.Contains(string(raw), "invalid_cursor") {
		t.Fatalf("cursor under other filters = %d %s", code, raw)
	}
	if code, _, raw := c.catalog(t, c.x.admin, url.Values{"cursor": {f1.NextCursor}, "limit": {"5"}}); code != http.StatusOK {
		t.Fatalf("cursor with another limit = %d %s; want 200 (limit is not bound)", code, raw)
	}
	// Garbage cursors.
	for _, bad := range []string{base64.RawURLEncoding.EncodeToString([]byte(`{"k":{"g":"x"},"h":"00"}`)), "%%%", strings.Repeat("A", 600)} {
		if code, _, raw := c.catalog(t, c.x.admin, url.Values{"cursor": {bad}}); code != http.StatusBadRequest {
			t.Fatalf("bad cursor %q = %d %s", bad[:min(len(bad), 20)], code, raw)
		}
	}
}

// Every filter by team X that targets team Y's data comes back empty,
// and the raw body never names a team Y AppProject, name or team.
func TestLive_GatewayCatalogReview_TeamFiltersDoNotLeak(t *testing.T) {
	c := newCatFixture(t)
	for _, q := range []url.Values{
		{"app_project": {"team-b-apps"}}, {"q": {"orders"}}, {"q": {"reports"}}, {"source": {"static"}},
		{"status": {"missing"}}, {"team_id": {c.y.team.String()}}, {"gateway_id": {c.gw.GatewayID}, "app_project": {"team-b-apps"}},
		{"connector_uuid": {c.connID}, "q": {"orders"}}, {"bound": {"true"}}, {"new": {"false"}},
	} {
		code, p, raw := c.catalog(t, c.x.admin, q)
		if code != http.StatusOK || len(p.Items) != 0 && !onlyNames(p.Items, "team-a-apps") {
			t.Fatalf("team X %v = %d %s", q, code, raw)
		}
		for _, s := range []string{"team-b-apps", "orders-api", "reports-api", c.y.team.String()} {
			if strings.Contains(string(raw), s) {
				t.Fatalf("team X %v leaks %q: %s", q, s, raw)
			}
		}
	}
	// Injection-shaped values are refused before SQL, with no echo.
	for _, q := range []url.Values{{"q": {"' OR 1=1--"}}, {"app_project": {"x' OR '1'='1"}}, {"namespace": {"a;b"}}, {"team_id": {"00000000-0000-0000-0000-00000000000g"}}} {
		code, _, raw := c.catalog(t, c.x.admin, q)
		if code != http.StatusBadRequest || string(raw) != `{"error":"invalid_query"}` {
			t.Fatalf("injection %v = %d %s", q, code, raw)
		}
	}
}

// Scope shapes: only global and team_id-only scopes count.
func TestLive_GatewayCatalogReview_ScopeShapes(t *testing.T) {
	c := newCatFixture(t)
	target := c.byName["team-a-apps/payments-api"].TargetID
	for name, grant := range map[string]struct {
		perm, scope string
	}{
		"bind team+environment": {"gateway.bind", `{"team_id":"` + c.x.team.String() + `","environment":"uat"}`},
		"bind team+prefix":      {"gateway.bind", `{"team_id":"` + c.x.team.String() + `","secret_ref_prefix":"team-alpha/"}`},
		"bind bad team id":      {"gateway.bind", `{"team_id":"not-a-uuid"}`},
		"list team-scoped":      {"gateway.list", `{"team_id":"` + c.x.team.String() + `"}`},
		"list project-scoped":   {"gateway.list", `{"project_id":"` + c.x.proj.String() + `"}`},
	} {
		uid := uuid.New()
		hdr := map[string]string{"Cookie": c.l.sessionFor(t, uid, "shape-"+uid.String()[:8]+"@example.com")}
		c.l.addGrant(t, uid.String(), []string{grant.perm}, grant.scope)
		if code, _, raw := c.catalog(t, hdr, nil); code != http.StatusForbidden {
			t.Fatalf("%s: catalog = %d %s; want 403", name, code, raw)
		}
		if code, raw := c.bindAs(t, hdr, c.x.uat, c.x.secret, target); code != http.StatusForbidden {
			t.Fatalf("%s: bind = %d %s; want 403", name, code, raw)
		}
	}
}

// ---- 2. A2 mapping --------------------------------------------------------

func TestLive_GatewayCatalogReview_MappingIsPlatformOnly(t *testing.T) {
	c := newCatFixture(t)
	path := "/api/v1/admin/gateways/" + c.gw.GatewayID + "/connectors/" + c.connID + "/project-teams"
	before := len(c.l.auditRowsWithStatus(t, "gateway.connector.project_mapping_changed"))
	// Team X admin tries to map team-b-apps to itself (self-grant).
	body := map[string]any{"mappings": []map[string]any{
		{"app_project": "team-a-apps", "team_ids": []string{c.x.team.String()}},
		{"app_project": "team-b-apps", "team_ids": []string{c.x.team.String()}},
	}}
	if code, raw := c.l.callAs(t, http.MethodPut, path, c.x.admin, body); code != http.StatusForbidden {
		t.Fatalf("team-scoped mapping write = %d %s; want 403", code, raw)
	}
	if code, raw := c.l.callAs(t, http.MethodGet, path, c.x.admin, nil); code != http.StatusForbidden {
		t.Fatalf("team-scoped mapping read = %d %s; want 403", code, raw)
	}
	rows := c.l.auditRowsWithStatus(t, "gateway.connector.project_mapping_changed")
	if len(rows) != before+1 || rows[len(rows)-1].Status != "denied" || rows[len(rows)-1].Metadata["error_kind"] != "permission_denied" {
		t.Fatalf("mapping deny audit = %+v", rows[len(rows)-1])
	}
	for k := range rows[len(rows)-1].Metadata {
		if k != "error_kind" && k != "gateway_id" && k != "connector_id" {
			t.Fatalf("mapping deny audit carries %q", k)
		}
	}
	// Platform admin without fresh MFA is refused (step-up).
	uid := uuid.New()
	hdr := map[string]string{"Cookie": c.l.noMFASession(t, uid, "nomfa-"+uid.String()[:8]+"@example.com")}
	c.l.addGrant(t, uid.String(), gatewayAdminPerms, `{}`)
	if code, raw := c.l.callAs(t, http.MethodPut, path, hdr, c.mapping(c.x.team, c.y.team)); code != http.StatusUnauthorized && code != http.StatusPreconditionFailed {
		t.Fatalf("mapping write without fresh MFA = %d %s", code, raw)
	}
	// No AppProject name is echoed in an error.
	code, raw := c.putMapping(t, map[string]any{"mappings": []map[string]any{{"app_project": "secret-looking-name", "team_ids": []string{c.x.team.String()}}}})
	if code != http.StatusUnprocessableEntity || strings.Contains(string(raw), "secret-looking-name") {
		t.Fatalf("unknown app project = %d %s", code, raw)
	}
	// The success audit has team ids and counts, no AppProject names.
	c.setMapping(t, []uuid.UUID{c.x.team}, []uuid.UUID{c.y.team})
	ok := c.l.auditRowsWithStatus(t, "gateway.connector.project_mapping_changed")
	m, _ := json.Marshal(ok[len(ok)-1].Metadata)
	if strings.Contains(string(m), "team-a-apps") || strings.Contains(string(m), "team-b-apps") {
		t.Fatalf("mapping audit names an AppProject: %s", m)
	}
}

// ---- 3. A4 bind and delete ------------------------------------------------

func TestLive_GatewayCatalogReview_BindVariants(t *testing.T) {
	c := newCatFixture(t)
	xT := c.byName["team-a-apps/payments-api"].TargetID
	yT := c.byName["team-b-apps/orders-api"].TargetID
	// Team Y's target into team Y's env, by team X: rule 1 first.
	if code, raw := c.bindAs(t, c.x.admin, c.y.uat, c.y.secret, yT); code != http.StatusNotFound || string(raw) != `{"error":"target_not_found"}` {
		t.Fatalf("X binds Y target into Y env = %d %s", code, raw)
	}
	// Team Y's secret in team X's env.
	if code, raw := c.bindAs(t, c.x.admin, c.x.uat, c.y.secret, xT); code == http.StatusCreated {
		t.Fatalf("X binds Y's secret = %d %s", code, raw)
	}
	// project_id of team Y with team X's env.
	code, raw := c.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", c.x.admin, map[string]any{
		"gateway_id": c.gw.GatewayID, "environment_id": c.x.uat.String(), "project_id": c.y.proj.String(), "secret_id": c.x.secret.String(),
		"argocd_connector_id": c.connID, "argocd_target_id": xT,
	})
	if code == http.StatusCreated {
		t.Fatalf("X binds with project_id of Y = %d %s", code, raw)
	}
	// Another Gateway id with this connector: same 404 as an unknown target.
	other := c.enrolled(t, "review-other-gw")
	code, raw = c.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", c.x.admin, map[string]any{
		"gateway_id": other.GatewayID, "environment_id": c.x.uat.String(), "secret_id": c.x.secret.String(),
		"argocd_connector_id": c.connID, "argocd_target_id": xT,
	})
	if code != http.StatusNotFound || errCode(t, raw) != "target_not_found" {
		t.Fatalf("X binds across Gateways = %d %s", code, raw)
	}
	// A static target on an approved connector is invisible to team scope.
	sgw, scid := c.gatewayReady(t, "review-static-gw")
	code, raw = c.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", c.x.admin, map[string]any{
		"gateway_id": sgw.GatewayID, "environment_id": c.x.uat.String(), "secret_id": c.x.secret.String(),
		"argocd_connector_id": scid, "argocd_target_id": "payments-api",
	})
	if code != http.StatusNotFound || errCode(t, raw) != "target_not_found" {
		t.Fatalf("X binds a static target = %d %s", code, raw)
	}
	// Without a fresh second factor.
	uid := uuid.New()
	hdr := map[string]string{"Cookie": c.l.noMFASession(t, uid, "nomfa-x-"+uid.String()[:8]+"@example.com")}
	c.l.addGrant(t, uid.String(), []string{"gateway.bind"}, `{"team_id":"`+c.x.team.String()+`"}`)
	if code, raw := c.bindAs(t, hdr, c.x.uat, c.x.secret, xT); code != http.StatusUnauthorized && code != http.StatusPreconditionFailed {
		t.Fatalf("team-scoped bind without fresh MFA = %d %s", code, raw)
	}
	// Team-scoped admin cannot read the other admin lists.
	for _, p := range []string{"/api/v1/admin/gateway-bindings", "/api/v1/admin/gateways", "/api/v1/admin/gateways/" + c.gw.GatewayID} {
		if code, raw := c.l.callAs(t, http.MethodGet, p, c.x.admin, nil); code != http.StatusForbidden {
			t.Fatalf("team-scoped GET %s = %d %s", p, code, raw)
		}
	}
}

// Rule 5 for a team-scoped caller: the target's AppProject maps only to
// a child team of X; X's admin sees it (child in subtree) but binding it
// into team X's own project must fail (the child does not cover X).
func TestLive_GatewayCatalogReview_TeamRelationForTeamScope(t *testing.T) {
	c := newCatFixture(t)
	child := c.seedTenant(t, "team-x-kid", &c.x.team)
	c.setMapping(t, []uuid.UUID{child.team}, []uuid.UUID{c.y.team})
	xT := c.byName["team-a-apps/payments-api"].TargetID
	if _, p, _ := c.catalog(t, c.x.admin, nil); len(p.Items) != 3 {
		t.Fatalf("X sees %d items; want the child team's 3", len(p.Items))
	}
	if code, raw := c.bindAs(t, c.x.admin, c.x.uat, c.x.secret, xT); code != http.StatusForbidden || errCode(t, raw) != "target_team_mismatch" {
		t.Fatalf("X binds a child-only target into X's project = %d %s; want 403 target_team_mismatch", code, raw)
	}
	if code, raw := c.bindAs(t, c.x.admin, child.uat, child.secret, xT); code != http.StatusCreated {
		t.Fatalf("X binds the child's target into the child's project = %d %s", code, raw)
	}
}

func TestLive_GatewayCatalogReview_DeleteRules(t *testing.T) {
	c := newCatFixture(t)
	// A parent team P maps team-a-apps; X is P's child with a scoped admin.
	p := c.seedTenant(t, "team-p", nil)
	if _, err := c.l.pool.Exec(t.Context(), `UPDATE teams SET parent_team_id = $1 WHERE id = $2`, p.team, c.x.team); err != nil {
		t.Fatal(err)
	}
	c.setMapping(t, []uuid.UUID{p.team}, []uuid.UUID{c.y.team})
	xT := c.byName["team-a-apps/payments-api"].TargetID
	// The platform admin binds it into X's project (P covers X).
	invisible := c.bindID(t, c.admin, c.x.uat, c.x.secret, xT)
	if _, items, _ := c.catalog(t, c.x.admin, nil); len(items.Items) != 0 {
		t.Fatalf("X sees %v; want nothing (P is above X)", names(items.Items))
	}
	if code, raw := c.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+invisible, c.x.admin, nil); code != http.StatusNotFound {
		t.Fatalf("X deletes a binding of a target it cannot see = %d %s; want 404 (rule 1)", code, raw)
	}
	// A static binding in X's project is platform-only.
	sgw, scid := c.gatewayReady(t, "review-static-del-gw")
	static := c.bind(t, sgw.GatewayID, scid, c.x.dev, c.x.secret, "payments-api")
	if code, raw := c.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+static, c.x.admin, nil); code != http.StatusNotFound {
		t.Fatalf("X deletes a static binding = %d %s; want 404", code, raw)
	}
	// Shared AppProject: Y's binding in Y's project is not X's to delete.
	c.setMapping(t, []uuid.UUID{c.x.team, c.y.team}, []uuid.UUID{c.y.team})
	ys := c.bindID(t, c.y.admin, c.y.uat, c.y.secret, xT)
	if code, raw := c.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+ys, c.x.admin, nil); code != http.StatusNotFound || errCode(t, raw) != "binding_not_found" {
		t.Fatalf("X deletes Y's binding on a shared target = %d %s; want 404", code, raw)
	}
	// After the connector leaves approval, X cannot unbind (rule 1).
	xs := c.bindID(t, c.x.admin, c.x.dev, c.x.secret, xT)
	if _, err := c.l.pool.Exec(t.Context(), `UPDATE gateway_connectors SET status = 'advertised', status_reason = 'scope_changed' WHERE id = $1`, c.connID); err != nil {
		t.Fatal(err)
	}
	if code, raw := c.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+xs, c.x.admin, nil); code != http.StatusNotFound {
		t.Fatalf("X unbinds on an unapproved connector = %d %s; want 404", code, raw)
	}
	// Deny audits carry the binding id and the code only.
	for _, r := range c.l.auditRowsWithStatus(t, "gateway.binding.delete") {
		if r.Status != "denied" {
			continue
		}
		for k := range r.Metadata {
			if k != "error_kind" && k != "binding_id" {
				t.Fatalf("delete deny audit carries %q: %v", k, r.Metadata)
			}
		}
	}
}

// ---- 4. structure check ---------------------------------------------------

func TestLive_GatewayCatalogReview_StructureEscalation(t *testing.T) {
	f := newGatewayFixture(t)
	x := f.seedTenant(t, "team-x", nil)
	z := f.seedTenant(t, "team-z", nil)
	kid := f.seedTenant(t, "team-x-kid", &x.team)
	f.l.addGrant(t, x.adminID.String(), []string{"team.edit"}, `{}`)
	put := func(team uuid.UUID, parent any) (int, []byte) {
		var name string
		if err := f.l.pool.QueryRow(t.Context(), `SELECT name FROM teams WHERE id = $1`, team).Scan(&name); err != nil {
			t.Fatal(err)
		}
		return f.l.callAs(t, http.MethodPut, "/api/v1/teams/"+team.String(), x.admin, map[string]any{"name": name, "parent_team_id": parent})
	}
	// Re-parent Z under X's child (inside the subtree, not the root).
	if code, raw := put(z.team, kid.team.String()); code != http.StatusForbidden {
		t.Fatalf("re-parent Z under X's child = %d %s; want 403", code, raw)
	}
	// Two steps: Z under a fresh root W (allowed), then W under X.
	code, raw := f.l.callAs(t, http.MethodPost, "/api/v1/teams", x.admin, map[string]any{"name": "team-w-" + uuid.NewString()[:6]})
	if code != http.StatusCreated {
		t.Fatalf("create W = %d %s", code, raw)
	}
	var w struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, raw, &w)
	if code, raw := put(z.team, w.ID.String()); code != http.StatusOK {
		t.Fatalf("Z under W = %d %s", code, raw)
	}
	if code, raw := put(w.ID, x.team.String()); code != http.StatusForbidden {
		t.Fatalf("W (holding Z) under X = %d %s; want 403", code, raw)
	}
	// A new team created under X, then a foreign project moved into it.
	code, raw = f.l.callAs(t, http.MethodPost, "/api/v1/teams", x.admin, map[string]any{"name": "team-x-new-" + uuid.NewString()[:6], "parent_team_id": x.team.String()})
	if code != http.StatusCreated {
		t.Fatalf("create under X = %d %s", code, raw)
	}
	var nt struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, raw, &nt)
	if code, raw := f.l.callAs(t, http.MethodPut, "/api/v1/projects/"+z.proj.String()+"/team", x.admin, map[string]any{"team_id": nt.ID.String()}); code != http.StatusForbidden {
		t.Fatalf("project of Z into a new child of X = %d %s; want 403", code, raw)
	}
	// Narrowing moves stay allowed: un-scope a project, move X's own team.
	if code, raw := f.l.callAs(t, http.MethodPut, "/api/v1/projects/"+kid.proj.String()+"/team", x.admin, map[string]any{"team_id": nil}); code != http.StatusNoContent {
		t.Fatalf("un-scope a project = %d %s", code, raw)
	}
	if code, raw := put(x.team, z.team.String()); code != http.StatusOK {
		t.Fatalf("X moves its own team under Z = %d %s; want 200 (no widening)", code, raw)
	}
}

// Evidence for an already-leased task is refused once the binding is
// suspended or the target is missing. The control case posts the same
// result with nothing changed and must be accepted, so a refusal can't
// come from the result itself.
func TestLive_GatewayCatalogReview_EvidenceSuspendedOrMissing(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		want      int
	}{
		{"control", `SELECT $1::uuid`, http.StatusOK},
		{"suspended", `UPDATE gateway_connector_bindings SET suspended_reason = 'mapping_removed', suspended_at = now() WHERE id = $1`, http.StatusUnprocessableEntity},
		{"missing", `UPDATE gateway_discovered_targets SET status = 'missing' WHERE target_id = (SELECT argocd_target_id FROM gateway_connector_bindings WHERE id = $1)`, http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCatFixture(t)
			e := c.byName["team-a-apps/payments-api"]
			b := c.bindID(t, c.x.admin, c.x.uat, c.x.secret, e.TargetID)
			o := c.obsAgent(t)
			replica := uuid.NewString()
			req, _ := c.execute(t, o.base, o.hdr, c.x.proj, c.x.uat, c.x.secret)
			c.makeClaimable(t, req)
			c.mustHB(t, c.gw, hbV2(replica, testScope(), true, ""))
			code, _, task, raw := c.claimAs(t, c.gw.GatewayID, c.gw.GatewaySecret, replica)
			if code != http.StatusOK {
				t.Fatalf("claim = %d %s", code, raw)
			}
			if _, err := c.l.pool.Exec(t.Context(), tc.sql, b); err != nil {
				t.Fatal(err)
			}
			res := argoResult(task, c.gw.GatewayID, replica)
			stage0(res)["resource"].(map[string]any)["name"] = e.Name
			stage0(res)["resource"].(map[string]any)["identity_digest"] = e.TargetID
			code, out := c.postResult(t, c.gw.GatewayID, c.gw.GatewaySecret, task.TaskID, res)
			if code != tc.want {
				t.Fatalf("evidence after %s = %d %s; want %d", tc.name, code, out, tc.want)
			}
		})
	}
}
