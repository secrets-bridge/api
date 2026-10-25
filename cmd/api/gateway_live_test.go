package main

// Gateway registry, enrollment, heartbeat and catalog (api#293), driven
// through the REAL router built by newApp against Postgres and Redis.
// The bodies, paths, headers and status codes are the ones the Gateway
// client on gateway main (internal/client) sends and expects.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var gatewayAdminPerms = []string{"gateway.mint", "gateway.revoke", "gateway.list", "gateway.bind"}

type gwFixture struct {
	l       *liveApp
	adminID uuid.UUID
	admin   map[string]string
}

// resetGatewayEnrollLimit clears the per-IP E1 bucket, which every test
// in this package shares (app.Test always comes from one address), and
// the gateway audit rollup slots, so each test sees its own first
// rejection.
func resetGatewayEnrollLimit(t *testing.T) {
	t.Helper()
	opt, err := redis.ParseURL(os.Getenv("TEST_REDIS_URL"))
	if err != nil {
		t.Fatalf("redis url: %v", err)
	}
	rc := redis.NewClient(opt)
	defer func() { _ = rc.Close() }()
	ctx := t.Context()
	iter := rc.Scan(ctx, 0, "*gateway*", 100).Iterator()
	for iter.Next(ctx) {
		_ = rc.Del(ctx, iter.Val()).Err()
	}
}

func newGatewayFixture(t *testing.T, opts ...func(*Config)) *gwFixture {
	t.Helper()
	l := newLiveApp(t, opts...)
	resetGatewayEnrollLimit(t)
	t.Cleanup(func() {
		_, _ = l.pool.Exec(context.Background(), `TRUNCATE observation_evidence, observation_task_attempts, observation_tasks;
			DELETE FROM gateway_connector_bindings; DELETE FROM gateways;`)
	})
	admin := uuid.New()
	cookie := l.sessionFor(t, admin, "gw-admin-"+admin.String()[:8]+"@example.com")
	l.addGrant(t, admin.String(), gatewayAdminPerms, `{}`)
	return &gwFixture{l: l, adminID: admin, admin: map[string]string{"Cookie": cookie}}
}

func (f *gwFixture) createGateway(t *testing.T, name string) string {
	t.Helper()
	code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways", f.admin, map[string]any{
		"name": name, "boundary": "tenant-a-uat",
	})
	if code != http.StatusCreated {
		t.Fatalf("create gateway = %d %s", code, body)
	}
	var g struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	mustJSON(t, body, &g)
	if g.Status != "pending" {
		t.Fatalf("new gateway status = %q; want pending", g.Status)
	}
	return g.ID
}

func (f *gwFixture) mintToken(t *testing.T, gatewayID string, body any) (string, string) {
	t.Helper()
	code, raw := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+gatewayID+"/enrollment-token", f.admin, body)
	if code != http.StatusCreated {
		t.Fatalf("mint token = %d %s", code, raw)
	}
	var tok struct {
		ID              string `json:"id"`
		GatewayID       string `json:"gateway_id"`
		EnrollmentToken string `json:"enrollment_token"`
	}
	mustJSON(t, raw, &tok)
	if tok.EnrollmentToken == "" || tok.GatewayID != gatewayID {
		t.Fatalf("mint token body = %s", raw)
	}
	return tok.ID, tok.EnrollmentToken
}

func (f *gwFixture) enroll(t *testing.T, token string, hdr map[string]string) (int, []byte) {
	t.Helper()
	return f.l.callAs(t, http.MethodPost, "/api/v1/gateways/enroll", hdr, map[string]any{"enrollment_token": token})
}

type gwEnrolled struct {
	GatewayID                string `json:"gateway_id"`
	GatewaySecret            string `json:"gateway_secret"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	ClaimPollSeconds         int    `json:"claim_poll_seconds"`
}

// enrolled creates, mints and enrolls a Gateway.
func (f *gwFixture) enrolled(t *testing.T, name string) gwEnrolled {
	t.Helper()
	id := f.createGateway(t, name)
	_, token := f.mintToken(t, id, map[string]any{})
	code, body := f.enroll(t, token, nil)
	if code != http.StatusCreated {
		t.Fatalf("enroll = %d %s", code, body)
	}
	var e gwEnrolled
	mustJSON(t, body, &e)
	if e.GatewayID != id || e.GatewaySecret == "" {
		t.Fatalf("enroll body = %s", body)
	}
	return e
}

func gwHeartbeatBody(replica string) map[string]any {
	return map[string]any{
		"replica_id": replica, "gateway_version": "0.1.0", "contract_versions": []string{"1"},
		"status": "ok", "in_flight": 0,
		"connectors": []map[string]string{{"connector_id": "argocd-main", "kind": "argocd", "status": "ok"}},
	}
}

func gwCatalogBody() map[string]any {
	return map[string]any{"connectors": []map[string]any{{
		"connector_id": "argocd-main", "kind": "argocd",
		"targets": []map[string]any{{"target_id": "payments-api", "namespace": "argocd", "name": "payments-api"}},
	}}}
}

func (f *gwFixture) heartbeat(t *testing.T, gatewayID, secret, replica string) (int, []byte) {
	t.Helper()
	return f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+gatewayID+"/heartbeat",
		map[string]string{"X-Gateway-Secret": secret}, gwHeartbeatBody(replica))
}

func (f *gwFixture) catalog(t *testing.T, gatewayID, secret string, body any) (int, []byte) {
	t.Helper()
	return f.l.callAs(t, http.MethodPut, "/api/v1/gateways/"+gatewayID+"/catalog",
		map[string]string{"X-Gateway-Secret": secret}, body)
}

func errCode(t *testing.T, body []byte) string {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error
}

// seedScope creates a project, a non-prod environment and a catalog
// secret bound to the project.
func (f *gwFixture) seedScope(t *testing.T) (proj, env, secret uuid.UUID) {
	t.Helper()
	ctx := t.Context()
	proj, env, secret = uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO projects (id, name) VALUES ($1, $2)`, []any{proj, "gw-proj-" + proj.String()[:8]}},
		{`INSERT INTO environments (id, project_id, name, type, kind) VALUES ($1, $2, 'uat', 'uat', 'non_prod')`, []any{env, proj}},
		{`INSERT INTO secrets (id, cluster_name, provider_type, secret_ref, status) VALUES ($1, 'tenant-a-uat', 'vault', $2, 'present')`, []any{secret, "team-alpha/uat/" + secret.String()[:8]}},
		{`INSERT INTO project_secrets (project_id, secret_id) VALUES ($1, $2)`, []any{proj, secret}},
	} {
		if _, err := f.l.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed %q: %v", q.sql, err)
		}
	}
	return proj, env, secret
}

// TestLive_Gateway_EnrollHeartbeatCatalogBind walks the whole R1 registry
// path the way the Gateway client and an admin use it.
func TestLive_Gateway_EnrollHeartbeatCatalogBind(t *testing.T) {
	f := newGatewayFixture(t)
	ctx := t.Context()

	var adminHas bool
	if err := f.l.pool.QueryRow(ctx, `SELECT permissions ?& array['gateway.mint','gateway.revoke','gateway.list','gateway.bind']
		FROM roles WHERE name = 'admin' AND is_system`).Scan(&adminHas); err != nil || !adminHas {
		t.Fatalf("seeded admin role holds the gateway permissions = %v, %v", adminHas, err)
	}

	gw := f.enrolled(t, "tenant-a-uat-gw")
	if gw.HeartbeatIntervalSeconds != 30 || gw.ClaimPollSeconds != 5 {
		t.Errorf("enroll intervals = %+v", gw)
	}
	replica := uuid.NewString()

	// First heartbeat: no catalog yet, so the stored digest is empty and
	// the Gateway uploads its catalog.
	code, body := f.heartbeat(t, gw.GatewayID, gw.GatewaySecret, replica)
	if code != http.StatusOK {
		t.Fatalf("heartbeat = %d %s", code, body)
	}
	var hb struct {
		Status               string    `json:"status"`
		ServerTime           time.Time `json:"server_time"`
		NextHeartbeatSeconds int       `json:"next_heartbeat_seconds"`
		ClaimPollSeconds     int       `json:"claim_poll_seconds"`
		ContractVersion      string    `json:"contract_version"`
		CatalogVersion       string    `json:"catalog_version"`
	}
	mustJSON(t, body, &hb)
	if hb.Status != "ok" || hb.ServerTime.IsZero() || hb.NextHeartbeatSeconds != 30 || hb.ClaimPollSeconds != 5 ||
		hb.ContractVersion != "1" || hb.CatalogVersion != "" {
		t.Fatalf("first heartbeat body = %s", body)
	}

	code, body = f.catalog(t, gw.GatewayID, gw.GatewaySecret, gwCatalogBody())
	if code != http.StatusOK {
		t.Fatalf("catalog = %d %s", code, body)
	}
	var cat struct {
		Accepted       int    `json:"accepted"`
		TargetsStale   int    `json:"targets_stale"`
		CatalogVersion string `json:"catalog_version"`
	}
	mustJSON(t, body, &cat)
	if cat.Accepted != 1 || cat.TargetsStale != 0 || !strings.HasPrefix(cat.CatalogVersion, "sha256:") {
		t.Fatalf("catalog body = %s", body)
	}

	// The same catalog again is idempotent: same digest, one audit row.
	if code, body := f.catalog(t, gw.GatewayID, gw.GatewaySecret, gwCatalogBody()); code != http.StatusOK ||
		!strings.Contains(string(body), cat.CatalogVersion) {
		t.Fatalf("second catalog = %d %s", code, body)
	}
	if n := len(f.l.auditRows(t, "gateway.catalog.updated")); n != 1 {
		t.Errorf("gateway.catalog.updated rows = %d; want 1 for an unchanged catalog", n)
	}

	// The next heartbeat echoes the stored digest.
	hbBody := gwHeartbeatBody(replica)
	hbBody["catalog_version"] = cat.CatalogVersion
	code, body = f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+gw.GatewayID+"/heartbeat",
		map[string]string{"X-Gateway-Secret": gw.GatewaySecret}, hbBody)
	mustJSON(t, body, &hb)
	if code != http.StatusOK || hb.CatalogVersion != cat.CatalogVersion {
		t.Fatalf("heartbeat after catalog = %d %s; want catalog_version %s", code, body, cat.CatalogVersion)
	}

	// Detail: connector advertised, not approved; one replica.
	code, body = f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+gw.GatewayID, f.admin, nil)
	if code != http.StatusOK {
		t.Fatalf("detail = %d %s", code, body)
	}
	var detail struct {
		Gateway struct {
			Status         string `json:"status"`
			LastStatus     string `json:"last_status"`
			GatewayVersion string `json:"gateway_version"`
			CatalogVersion string `json:"catalog_version"`
		} `json:"gateway"`
		Replicas []struct {
			ReplicaID string `json:"replica_id"`
			Status    string `json:"status"`
		} `json:"replicas"`
		Connectors []struct {
			ID          string `json:"id"`
			ConnectorID string `json:"connector_id"`
			Kind        string `json:"kind"`
			Status      string `json:"status"`
			Targets     []struct {
				TargetID string `json:"target_id"`
				Stale    bool   `json:"stale"`
			} `json:"targets"`
		} `json:"connectors"`
		Bindings []any `json:"bindings"`
	}
	mustJSON(t, body, &detail)
	if detail.Gateway.Status != "active" || detail.Gateway.LastStatus != "ok" || detail.Gateway.GatewayVersion != "0.1.0" ||
		detail.Gateway.CatalogVersion != cat.CatalogVersion {
		t.Errorf("gateway detail = %+v", detail.Gateway)
	}
	if len(detail.Replicas) != 1 || detail.Replicas[0].ReplicaID != replica {
		t.Errorf("replicas = %+v", detail.Replicas)
	}
	if len(detail.Connectors) != 1 || detail.Connectors[0].ConnectorID != "argocd-main" || detail.Connectors[0].Status != "advertised" ||
		len(detail.Connectors[0].Targets) != 1 || detail.Connectors[0].Targets[0].TargetID != "payments-api" {
		t.Fatalf("connectors = %+v", detail.Connectors)
	}
	// Advertising never binds: no binding row exists, so nothing can ever
	// turn into a task for this catalog (tasks land in api#294 and are
	// created from bindings only).
	if len(detail.Bindings) != 0 {
		t.Errorf("bindings after catalog = %d; advertising must not bind", len(detail.Bindings))
	}
	var bindings int
	_ = f.l.pool.QueryRow(ctx, `SELECT count(*) FROM gateway_connector_bindings WHERE gateway_id = $1`, gw.GatewayID).Scan(&bindings)
	if bindings != 0 {
		t.Errorf("gateway_connector_bindings rows = %d after catalog only", bindings)
	}
	connID := detail.Connectors[0].ID

	proj, env, secret := f.seedScope(t)
	bind := map[string]any{
		"gateway_id": gw.GatewayID, "project_id": proj, "environment_id": env, "secret_id": secret,
		"argocd_connector_id": connID, "argocd_target_id": "payments-api",
	}
	// Not approved yet.
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, bind); code != http.StatusConflict ||
		errCode(t, body) != "connector_not_approved" {
		t.Fatalf("bind before approval = %d %s; want 409 connector_not_approved", code, body)
	}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+gw.GatewayID+"/connectors/"+connID+"/approve", f.admin, nil); code != http.StatusOK ||
		!strings.Contains(string(body), `"status":"approved"`) {
		t.Fatalf("approve = %d %s", code, body)
	}
	// A target the catalog never advertised.
	other := map[string]any{}
	for k, v := range bind {
		other[k] = v
	}
	other["argocd_target_id"] = "billing-api"
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, other); code != http.StatusBadRequest ||
		errCode(t, body) != "target_not_advertised" {
		t.Fatalf("bind unknown target = %d %s; want 400 target_not_advertised", code, body)
	}
	// Release 1 binds Argo CD only: an eso field is refused, not dropped.
	other["argocd_target_id"] = "payments-api"
	other["eso_connector_id"] = connID
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, other); code != http.StatusBadRequest {
		t.Fatalf("bind with an eso field = %d %s; want 400", code, body)
	}
	code, body = f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, bind)
	if code != http.StatusCreated {
		t.Fatalf("bind = %d %s", code, body)
	}
	var b struct {
		ID             string   `json:"id"`
		ExpectedStages []string `json:"expected_stages"`
		ProjectID      string   `json:"project_id"`
	}
	mustJSON(t, body, &b)
	if len(b.ExpectedStages) != 1 || b.ExpectedStages[0] != "argocd_context" || b.ProjectID != proj.String() {
		t.Errorf("binding = %s", body)
	}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, bind); code != http.StatusConflict ||
		errCode(t, body) != "binding_exists" {
		t.Errorf("duplicate bind = %d %s; want 409 binding_exists", code, body)
	}
	if code, body := f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateway-bindings?gateway_id="+gw.GatewayID, f.admin, nil); code != http.StatusOK ||
		!strings.Contains(string(body), b.ID) {
		t.Errorf("list bindings = %d %s", code, body)
	}

	// A target that leaves the catalog stays, marked stale; it can no
	// longer be bound.
	code, body = f.catalog(t, gw.GatewayID, gw.GatewaySecret, map[string]any{"connectors": []map[string]any{{
		"connector_id": "argocd-main", "kind": "argocd",
		"targets": []map[string]any{{"target_id": "billing-api"}},
	}}})
	mustJSON(t, body, &cat)
	if code != http.StatusOK || cat.TargetsStale != 1 {
		t.Fatalf("catalog without payments-api = %d %s; want targets_stale 1", code, body)
	}
	if code, body := f.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+b.ID, f.admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete binding = %d %s", code, body)
	}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, bind); code != http.StatusConflict ||
		errCode(t, body) != "target_stale" {
		t.Errorf("bind a stale target = %d %s; want 409 target_stale", code, body)
	}

	// Every change is audited with the session actor.
	for _, action := range []string{"gateway.create", "gateway.enrollment_token.create", "gateway.connector.approved",
		"gateway.binding.create", "gateway.binding.delete"} {
		f.l.requireOneSuccessAudit(t, action, f.adminID.String())
	}
	// And every refused bind as denied with its error kind (api#312).
	var kinds []string
	for _, r := range f.l.auditRowsWithStatus(t, "gateway.binding.create") {
		if r.Status == "denied" {
			kinds = append(kinds, r.Metadata["error_kind"].(string))
		}
	}
	if got := strings.Join(kinds, ","); got != "connector_not_approved,target_not_advertised,invalid_request,binding_exists,target_stale" {
		t.Errorf("denied bind error kinds = %s", got)
	}
	if got := f.l.actorOf(t, "gateway.enroll"); got != "gateway:"+gw.GatewayID {
		t.Errorf("gateway.enroll actor = %q", got)
	}
	if got := f.l.actorOf(t, "gateway.catalog.updated"); got != "gateway:"+gw.GatewayID {
		t.Errorf("gateway.catalog.updated actor = %q", got)
	}
}

// TestLive_Gateway_AuthIsolation: an agent credential never works on the
// gateway routes and a gateway credential never works on the agent
// routes, in either header and with either id, even while both hash
// caches are warm.
func TestLive_Gateway_AuthIsolation(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "isolation-gw")

	minter := f.l.grantUser(t, []string{"agent.mint"}, `{}`)
	code, body := f.l.call(t, http.MethodPost, "/api/v1/agents", minter, agentMintBody("isolation-agent"))
	if code != http.StatusCreated {
		t.Fatalf("mint agent = %d %s", code, body)
	}
	var agent struct {
		ID          string `json:"id"`
		AgentSecret string `json:"agent_secret"`
	}
	mustJSON(t, body, &agent)

	// Warm both caches with a good call each.
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/agents/"+agent.ID+"/heartbeat",
		agentHeaders(agent.AgentSecret), nil); code != http.StatusNoContent {
		t.Fatalf("agent heartbeat = %d %s", code, body)
	}
	if code, body := f.heartbeat(t, gw.GatewayID, gw.GatewaySecret, uuid.NewString()); code != http.StatusOK {
		t.Fatalf("gateway heartbeat = %d %s", code, body)
	}

	gwPaths := func(id string) []struct{ method, path string } {
		return []struct{ method, path string }{
			{http.MethodPost, "/api/v1/gateways/" + id + "/heartbeat"},
			{http.MethodPut, "/api/v1/gateways/" + id + "/catalog"},
		}
	}
	for _, id := range []string{agent.ID, gw.GatewayID} {
		for _, hdr := range []map[string]string{
			{"X-Gateway-Secret": agent.AgentSecret},
			agentHeaders(agent.AgentSecret),
			{"X-Agent-Secret": gw.GatewaySecret},
		} {
			for _, p := range gwPaths(id) {
				var body any = gwHeartbeatBody(uuid.NewString())
				if p.method == http.MethodPut {
					body = gwCatalogBody()
				}
				code, raw := f.l.callAs(t, p.method, p.path, hdr, body)
				if code != http.StatusUnauthorized || errCode(t, raw) != "unauthorized" {
					t.Errorf("%s %s with %v = %d %s; want 401 unauthorized", p.method, p.path, keys(hdr), code, raw)
				}
			}
		}
	}
	for _, id := range []string{gw.GatewayID, agent.ID} {
		for _, hdr := range []map[string]string{
			{"X-Agent-Secret": gw.GatewaySecret},
			{"X-Gateway-Secret": gw.GatewaySecret},
		} {
			code, raw := f.l.callAs(t, http.MethodPost, "/api/v1/agents/"+id+"/heartbeat", hdr, nil)
			if code != http.StatusUnauthorized {
				t.Errorf("agent heartbeat %s with %v = %d %s; want 401", id, keys(hdr), code, raw)
			}
			code, raw = f.l.callAs(t, http.MethodPost, "/api/v1/agents/"+id+"/jobs/claim", hdr, nil)
			if code != http.StatusUnauthorized {
				t.Errorf("agent claim %s with %v = %d %s; want 401", id, keys(hdr), code, raw)
			}
		}
	}
	// A session never stands in for X-Gateway-Secret either.
	if code, raw := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+gw.GatewayID+"/heartbeat", f.admin, gwHeartbeatBody(uuid.NewString())); code != http.StatusUnauthorized {
		t.Errorf("gateway heartbeat with an admin session = %d %s; want 401", code, raw)
	}
	// The rejections are audited, ids and reason codes only.
	rows := f.l.auditRows(t, "gateway.auth.rejected")
	if len(rows) == 0 {
		t.Fatal("no gateway.auth.rejected audit row")
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestLive_Gateway_EnrollmentTokenSingleUse: a used token cannot enroll
// again, and the first secret keeps working.
func TestLive_Gateway_EnrollmentTokenSingleUse(t *testing.T) {
	f := newGatewayFixture(t)
	ctx := t.Context()
	id := f.createGateway(t, "replay-gw")
	_, token := f.mintToken(t, id, nil)
	code, body := f.enroll(t, token, nil)
	if code != http.StatusCreated {
		t.Fatalf("enroll = %d %s", code, body)
	}
	var first gwEnrolled
	mustJSON(t, body, &first)
	var hashBefore []byte
	if err := f.l.pool.QueryRow(ctx, `SELECT secret_hash FROM gateways WHERE id = $1`, id).Scan(&hashBefore); err != nil {
		t.Fatal(err)
	}

	code, body = f.enroll(t, token, nil)
	if code != http.StatusConflict || errCode(t, body) != "enrollment_token_already_consumed" {
		t.Fatalf("replayed token = %d %s; want 409 enrollment_token_already_consumed", code, body)
	}
	if strings.Contains(string(body), "gateway_secret") {
		t.Fatalf("replay response carries a secret: %s", body)
	}
	var hashAfter []byte
	if err := f.l.pool.QueryRow(ctx, `SELECT secret_hash FROM gateways WHERE id = $1`, id).Scan(&hashAfter); err != nil {
		t.Fatal(err)
	}
	if string(hashBefore) != string(hashAfter) {
		t.Fatal("a replayed token changed the gateway's secret hash")
	}
	if code, body := f.heartbeat(t, id, first.GatewaySecret, uuid.NewString()); code != http.StatusOK {
		t.Fatalf("first secret after replay = %d %s; want 200", code, body)
	}
	// A second token cannot be minted for an enrolled Gateway.
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+id+"/enrollment-token", f.admin, nil); code != http.StatusConflict {
		t.Errorf("mint for an enrolled gateway = %d %s; want 409", code, body)
	}
	// A revoked unused token is refused with its own code.
	id2 := f.createGateway(t, "replay-gw-2")
	tokID, token2 := f.mintToken(t, id2, nil)
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-enrollment-tokens/"+tokID+"/revoke", f.admin, nil); code != http.StatusNoContent {
		t.Fatalf("revoke token = %d %s", code, body)
	}
	if code, body := f.enroll(t, token2, nil); code != http.StatusForbidden || errCode(t, body) != "enrollment_token_revoked" {
		t.Errorf("revoked token = %d %s; want 403 enrollment_token_revoked", code, body)
	}
	if code, body := f.enroll(t, "not-a-token", nil); code != http.StatusUnauthorized || errCode(t, body) != "enrollment_token_invalid" {
		t.Errorf("unknown token = %d %s; want 401 enrollment_token_invalid", code, body)
	}
	// Scope comes from the gateways row: an unknown field is refused.
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/enroll", nil,
		map[string]any{"enrollment_token": token2, "gateway_id": id}); code != http.StatusBadRequest || errCode(t, body) != "invalid_request" {
		t.Errorf("enroll with a gateway_id field = %d %s; want 400 invalid_request", code, body)
	}
}

// TestLive_Gateway_ExpiredTokenRefused: an expired token is refused and
// the Gateway stays pending with no credential.
func TestLive_Gateway_ExpiredTokenRefused(t *testing.T) {
	f := newGatewayFixture(t)
	ctx := t.Context()
	id := f.createGateway(t, "expired-gw")
	tokID, token := f.mintToken(t, id, map[string]any{"expires_in_seconds": 60})
	if _, err := f.l.pool.Exec(ctx, `UPDATE gateway_enrollment_tokens
		SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1`, tokID); err != nil {
		t.Fatal(err)
	}
	code, body := f.enroll(t, token, nil)
	if code != http.StatusUnauthorized || errCode(t, body) != "enrollment_token_expired" {
		t.Fatalf("expired token = %d %s; want 401 enrollment_token_expired", code, body)
	}
	var status string
	var hash []byte
	if err := f.l.pool.QueryRow(ctx, `SELECT status, secret_hash FROM gateways WHERE id = $1`, id).Scan(&status, &hash); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || hash != nil {
		t.Fatalf("after an expired token: status %q, hash set %v; want pending, none", status, hash != nil)
	}
	var consumed *time.Time
	_ = f.l.pool.QueryRow(ctx, `SELECT consumed_at FROM gateway_enrollment_tokens WHERE id = $1`, tokID).Scan(&consumed)
	if consumed != nil {
		t.Fatal("an expired token was consumed")
	}
	// The rejection is audited with a reason code only.
	found := false
	for _, r := range f.l.auditRows(t, "gateway.enroll") {
		if r.Metadata["reason"] == "expired" {
			found = true
		}
	}
	if !found {
		t.Error("no gateway.enroll audit row with reason expired")
	}
}

// TestLive_Gateway_RevokedGets401: a revoked Gateway is refused on
// heartbeat and catalog at once, with a warm cache.
func TestLive_Gateway_RevokedGets401(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "revoked-gw")
	replica := uuid.NewString()
	if code, body := f.heartbeat(t, gw.GatewayID, gw.GatewaySecret, replica); code != http.StatusOK {
		t.Fatalf("heartbeat = %d %s", code, body)
	}
	if code, body := f.catalog(t, gw.GatewayID, gw.GatewaySecret, gwCatalogBody()); code != http.StatusOK {
		t.Fatalf("catalog = %d %s", code, body)
	}
	code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+gw.GatewayID+"/revoke", f.admin, map[string]any{"reason": "secret_leaked"})
	if code != http.StatusOK || !strings.Contains(string(body), `"status":"revoked"`) {
		t.Fatalf("revoke = %d %s", code, body)
	}
	if code, body := f.heartbeat(t, gw.GatewayID, gw.GatewaySecret, replica); code != http.StatusUnauthorized || errCode(t, body) != "unauthorized" {
		t.Errorf("heartbeat after revoke = %d %s; want 401", code, body)
	}
	if code, body := f.catalog(t, gw.GatewayID, gw.GatewaySecret, gwCatalogBody()); code != http.StatusUnauthorized || errCode(t, body) != "unauthorized" {
		t.Errorf("catalog after revoke = %d %s; want 401", code, body)
	}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+gw.GatewayID+"/revoke", f.admin, nil); code != http.StatusConflict {
		t.Errorf("second revoke = %d %s; want 409", code, body)
	}
	ev := f.l.requireOneAudit(t, "gateway.revoke", f.adminID.String())
	if ev.Metadata["gateway_id"] != gw.GatewayID || ev.Metadata["reason"] != "secret_leaked" {
		t.Errorf("gateway.revoke metadata = %v", ev.Metadata)
	}
}

// TestLive_Gateway_CatalogIDsOnly: the catalog stores ids, kinds and
// display names only, and refuses URL-like or namespace/name-like ids
// and any field outside the contract, storing nothing.
func TestLive_Gateway_CatalogIDsOnly(t *testing.T) {
	f := newGatewayFixture(t)
	ctx := t.Context()
	gw := f.enrolled(t, "catalog-gw")

	conn := func(connector, target string, extra map[string]any) map[string]any {
		tgt := map[string]any{"target_id": target}
		for k, v := range extra {
			tgt[k] = v
		}
		return map[string]any{"connectors": []map[string]any{{
			"connector_id": connector, "kind": "argocd", "targets": []map[string]any{tgt},
		}}}
	}
	bad := map[string]map[string]any{
		"url connector id":         conn("https://argocd.example.com", "payments-api", nil),
		"host:port connector id":   conn("argocd.example.com:443", "payments-api", nil),
		"namespace/name target id": conn("argocd-main", "argocd/payments-api", nil),
		"url target id":            conn("argocd-main", "https://argocd.example.com/applications/payments-api", nil),
		"dotted target id":         conn("argocd-main", "payments.api", nil),
		"upper-case target id":     conn("argocd-main", "Payments-API", nil),
		"path namespace":           conn("argocd-main", "payments-api", map[string]any{"namespace": "argocd/apps"}),
		"url name":                 conn("argocd-main", "payments-api", map[string]any{"name": "https://argocd.example.com"}),
		"credential field":         conn("argocd-main", "payments-api", map[string]any{"token": "eyJhbGciOiJIUzI1NiJ9.e30.x"}),
		"negative interval":        conn("argocd-main", "payments-api", map[string]any{"refresh_interval_seconds": -1}),
		"unknown kind": {"connectors": []map[string]any{{
			"connector_id": "flux-main", "kind": "flux", "targets": []map[string]any{{"target_id": "payments-api"}},
		}}},
		"url on the connector": {"connectors": []map[string]any{{
			"connector_id": "argocd-main", "kind": "argocd", "url": "https://argocd.example.com", "targets": []map[string]any{},
		}}},
		"duplicate connector": {"connectors": []map[string]any{
			{"connector_id": "argocd-main", "kind": "argocd", "targets": []map[string]any{}},
			{"connector_id": "argocd-main", "kind": "argocd", "targets": []map[string]any{}},
		}},
	}
	for name, body := range bad {
		code, raw := f.catalog(t, gw.GatewayID, gw.GatewaySecret, body)
		if code != http.StatusBadRequest || errCode(t, raw) != "invalid_request" {
			t.Errorf("%s: catalog = %d %s; want 400 invalid_request", name, code, raw)
		}
		if strings.Contains(string(raw), "example.com") || strings.Contains(string(raw), "eyJ") {
			t.Errorf("%s: the error echoes request content: %s", name, raw)
		}
	}
	var n int
	var version *string
	_ = f.l.pool.QueryRow(ctx, `SELECT count(*) FROM gateway_connectors WHERE gateway_id = $1`, gw.GatewayID).Scan(&n)
	_ = f.l.pool.QueryRow(ctx, `SELECT catalog_version FROM gateways WHERE id = $1`, gw.GatewayID).Scan(&version)
	if n != 0 || version != nil {
		t.Fatalf("refused catalogs stored %d connectors, catalog_version %v", n, version)
	}

	good := conn("argocd-main", "payments-api", map[string]any{"namespace": "argocd", "name": "payments-api"})
	if code, raw := f.catalog(t, gw.GatewayID, gw.GatewaySecret, good); code != http.StatusOK {
		t.Fatalf("good catalog = %d %s", code, raw)
	}
	var targets []map[string]any
	var rawTargets []byte
	if err := f.l.pool.QueryRow(ctx, `SELECT advertised_targets FROM gateway_connectors WHERE gateway_id = $1`, gw.GatewayID).Scan(&rawTargets); err != nil {
		t.Fatal(err)
	}
	mustJSON(t, rawTargets, &targets)
	allowed := map[string]bool{"target_id": true, "namespace": true, "name": true, "refresh_interval_seconds": true, "progress_deadline_seconds": true, "stale": true}
	for _, tg := range targets {
		for k := range tg {
			if !allowed[k] {
				t.Errorf("stored target carries %q", k)
			}
		}
	}
	// Heartbeat bodies follow the same rules.
	hb := gwHeartbeatBody(uuid.NewString())
	hb["connectors"] = []map[string]string{{"connector_id": "https://argocd.example.com", "kind": "argocd", "status": "ok"}}
	if code, raw := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+gw.GatewayID+"/heartbeat",
		map[string]string{"X-Gateway-Secret": gw.GatewaySecret}, hb); code != http.StatusBadRequest || errCode(t, raw) != "invalid_request" {
		t.Errorf("heartbeat with a URL connector id = %d %s; want 400", code, raw)
	}
	hb = gwHeartbeatBody(uuid.NewString())
	hb["message"] = "dial tcp 10.0.0.1:443: connection refused"
	if code, raw := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+gw.GatewayID+"/heartbeat",
		map[string]string{"X-Gateway-Secret": gw.GatewaySecret}, hb); code != http.StatusBadRequest {
		t.Errorf("heartbeat with free text = %d %s; want 400", code, raw)
	}
	// Body cap: 64 KiB on E3.
	big := map[string]any{"connectors": []map[string]any{{"connector_id": "argocd-main", "kind": "argocd",
		"targets": []map[string]any{{"target_id": "payments-api", "name": strings.Repeat("a", 70<<10)}}}}}
	if code, raw := f.catalog(t, gw.GatewayID, gw.GatewaySecret, big); code != http.StatusRequestEntityTooLarge || errCode(t, raw) != "payload_too_large" {
		t.Errorf("oversized catalog = %d %s; want 413 payload_too_large", code, raw)
	}
}

// TestLive_Gateway_ReplicaLimit: a new replica past max_replicas gets 429
// replica_limit with Retry-After, and known replicas keep working.
func TestLive_Gateway_ReplicaLimit(t *testing.T) {
	f := newGatewayFixture(t)
	code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways", f.admin, map[string]any{
		"name": "small-gw", "boundary": "tenant-a-uat", "max_replicas": 2,
	})
	if code != http.StatusCreated {
		t.Fatalf("create = %d %s", code, body)
	}
	var g struct {
		ID string `json:"id"`
	}
	mustJSON(t, body, &g)
	_, token := f.mintToken(t, g.ID, nil)
	code, body = f.enroll(t, token, nil)
	if code != http.StatusCreated {
		t.Fatalf("enroll = %d %s", code, body)
	}
	var e gwEnrolled
	mustJSON(t, body, &e)
	r1, r2 := uuid.NewString(), uuid.NewString()
	for _, r := range []string{r1, r2} {
		if code, body := f.heartbeat(t, g.ID, e.GatewaySecret, r); code != http.StatusOK {
			t.Fatalf("heartbeat %s = %d %s", r, code, body)
		}
	}
	code, body = f.heartbeat(t, g.ID, e.GatewaySecret, uuid.NewString())
	if code != http.StatusTooManyRequests || errCode(t, body) != "replica_limit" {
		t.Fatalf("third replica = %d %s; want 429 replica_limit", code, body)
	}
	if code, body := f.heartbeat(t, g.ID, e.GatewaySecret, r1); code != http.StatusOK {
		t.Errorf("known replica after the limit = %d %s; want 200", code, body)
	}
	if len(f.l.auditRows(t, "gateway.replica_limit")) != 1 {
		t.Error("want one gateway.replica_limit audit row")
	}
}

// TestLive_Gateway_AdminRoutesNeedPermissionAndFreshMFA: every admin route
// sits behind the session gate and its gateway.* permission, and every
// write also needs a fresh second factor.
func TestLive_Gateway_AdminRoutesNeedPermissionAndFreshMFA(t *testing.T) {
	f := newGatewayFixture(t)
	ctx := t.Context()
	gw := f.createGateway(t, "perm-gw")
	anyID := uuid.NewString()
	_, permEnv, _ := f.seedScope(t)

	type route struct {
		method, path, perm string
		write              bool
	}
	routes := []route{
		{http.MethodPost, "/api/v1/admin/gateways", "gateway.mint", true},
		{http.MethodPost, "/api/v1/admin/gateways/" + gw + "/enrollment-token", "gateway.mint", true},
		{http.MethodPost, "/api/v1/admin/gateway-enrollment-tokens/" + anyID + "/revoke", "gateway.mint", true},
		{http.MethodPost, "/api/v1/admin/gateways/" + gw + "/revoke", "gateway.revoke", true},
		{http.MethodPost, "/api/v1/admin/gateways/" + gw + "/connectors/" + anyID + "/approve", "gateway.bind", true},
		{http.MethodPost, "/api/v1/admin/gateway-bindings", "gateway.bind", true},
		{http.MethodDelete, "/api/v1/admin/gateway-bindings/" + anyID, "gateway.bind", true},
		{http.MethodGet, "/api/v1/admin/gateway-bindings", "gateway.list", false}, // api#298
		{http.MethodGet, "/api/v1/admin/gateways", "gateway.list", false},
		{http.MethodGet, "/api/v1/admin/gateways/" + gw, "gateway.list", false},
		// api#294
		{http.MethodPut, "/api/v1/admin/gateways/" + gw + "/enabled", "gateway.revoke", true},
		{http.MethodGet, "/api/v1/admin/gateways/" + gw + "/tasks", "gateway.list", false},
		{http.MethodPut, "/api/v1/admin/environments/" + anyID + "/observation-source", "gateway.bind", true},
		{http.MethodGet, "/api/v1/admin/environments/" + permEnv.String() + "/observation-source", "gateway.list", false}, // api#298
	}
	body := map[string]any{"name": "x", "boundary": "x"}

	// No session.
	for _, r := range routes {
		if code, raw := f.l.callAs(t, r.method, r.path, nil, body); code != http.StatusUnauthorized {
			t.Errorf("%s %s anonymous = %d %s; want 401", r.method, r.path, code, raw)
		}
	}
	// A session with every other permission, including the agent and
	// integration ones, but not the gateway one.
	others := []string{"agent.mint", "agent.revoke", "agent.list", "integration.edit", "integration.bind", "role.edit"}
	nope := uuid.New()
	nopeHdr := map[string]string{"Cookie": f.l.sessionFor(t, nope, "gw-nope@example.com")}
	f.l.addGrant(t, nope.String(), others, `{}`)
	for _, r := range routes {
		if code, raw := f.l.callAs(t, r.method, r.path, nopeHdr, body); code != http.StatusForbidden {
			t.Errorf("%s %s without %s = %d %s; want 403", r.method, r.path, r.perm, code, raw)
		}
	}
	// The permission at team scope is not enough (global only), except
	// on the bind and unbind routes, which take a team-scoped
	// gateway.bind since api#308 (ADR 0002 C4): there the gate passes and
	// the service's rules answer (here: a body the decoder refuses, and
	// a binding the caller cannot see).
	scoped := uuid.New()
	scopedHdr := map[string]string{"Cookie": f.l.sessionFor(t, scoped, "gw-scoped@example.com")}
	f.l.addGrant(t, scoped.String(), gatewayAdminPerms, `{"team_id":"`+uuid.NewString()+`"}`)
	teamScoped := map[string]int{
		http.MethodPost + " /api/v1/admin/gateway-bindings":            http.StatusBadRequest,
		http.MethodDelete + " /api/v1/admin/gateway-bindings/" + anyID: http.StatusNotFound,
	}
	for _, r := range routes {
		want, ok := teamScoped[r.method+" "+r.path]
		if !ok {
			want = http.StatusForbidden
		}
		if code, raw := f.l.callAs(t, r.method, r.path, scopedHdr, body); code != want {
			t.Errorf("%s %s with a team-scoped grant = %d %s; want %d", r.method, r.path, code, raw, want)
		}
	}
	// The permission with a stale second factor: writes 401 step-up,
	// reads pass.
	stale := uuid.New()
	staleHdr := map[string]string{"Cookie": f.l.sessionFor(t, stale, "gw-stale@example.com")}
	f.l.addGrant(t, stale.String(), gatewayAdminPerms, `{}`)
	if _, err := f.l.pool.Exec(ctx, `
		INSERT INTO user_mfa_factors (user_id, kind, label, secret_ciphertext, secret_nonce, data_key_ciphertext, kms_key_id)
		VALUES ($1, 'totp', 'test', '\x00', '\x00', '\x00', 'test')`, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.pool.Exec(ctx, `UPDATE sessions SET last_mfa_at = now() - interval '2 hours' WHERE user_id = $1`, stale); err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		code, raw := f.l.callAs(t, r.method, r.path, staleHdr, body)
		switch {
		case r.write && (code != http.StatusUnauthorized || !strings.Contains(string(raw), "step_up_required")):
			t.Errorf("%s %s with a stale second factor = %d %s; want 401 step_up_required", r.method, r.path, code, raw)
		case !r.write && code != http.StatusOK:
			t.Errorf("%s %s (read) with a stale second factor = %d %s; want 200", r.method, r.path, code, raw)
		}
	}
	// Nothing was created by the refused calls.
	var n int
	_ = f.l.pool.QueryRow(ctx, `SELECT count(*) FROM gateways`).Scan(&n)
	if n != 1 {
		t.Errorf("gateways = %d after refused calls; want 1", n)
	}
	var tokens int
	_ = f.l.pool.QueryRow(ctx, `SELECT count(*) FROM gateway_enrollment_tokens`).Scan(&tokens)
	if tokens != 0 {
		t.Errorf("enrollment tokens = %d after refused calls; want 0", tokens)
	}
}

// TestLive_Gateway_NoCredentialAfterMint is the canary: once minted and
// enrolled, neither the enrollment token nor the gateway secret nor
// their hashes appear in any later response, in the logs or in
// audit_events.
func TestLive_Gateway_NoCredentialAfterMint(t *testing.T) {
	f := newGatewayFixture(t)
	ctx := t.Context()
	id := f.createGateway(t, "canary-gw")
	_, token := f.mintToken(t, id, map[string]any{"expected_cluster_name": "tenant-a-uat"})
	code, body := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/enroll", nil,
		map[string]any{"enrollment_token": token, "cluster_name": "tenant-a-uat"})
	if code != http.StatusCreated {
		t.Fatalf("enroll = %d %s", code, body)
	}
	var e gwEnrolled
	mustJSON(t, body, &e)

	var responses []string
	record := func(code int, raw []byte) { responses = append(responses, string(raw)) }
	record(f.heartbeat(t, id, e.GatewaySecret, uuid.NewString()))
	record(f.catalog(t, id, e.GatewaySecret, gwCatalogBody()))
	record(f.enroll(t, token, nil))
	record(f.heartbeat(t, id, "wrong-"+e.GatewaySecret, uuid.NewString()))
	record(f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways", f.admin, nil))
	record(f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+id, f.admin, nil))
	record(f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateway-bindings", f.admin, nil))
	record(f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+id+"/revoke", f.admin, nil))
	record(f.heartbeat(t, id, e.GatewaySecret, uuid.NewString()))

	var tokenHash, secretHash []byte
	_ = f.l.pool.QueryRow(ctx, `SELECT token_hash FROM gateway_enrollment_tokens WHERE gateway_id = $1`, id).Scan(&tokenHash)
	_ = f.l.pool.QueryRow(ctx, `SELECT secret_hash FROM gateways WHERE id = $1`, id).Scan(&secretHash)
	if len(tokenHash) != 32 || len(secretHash) != 32 {
		t.Fatalf("hash lengths = %d, %d; want SHA-256", len(tokenHash), len(secretHash))
	}
	canaries := map[string]string{"enrollment token": token, "gateway secret": e.GatewaySecret}
	for _, h := range [][]byte{tokenHash, secretHash} {
		for name, enc := range hashEncodings(h) {
			canaries["hash "+name] = enc
		}
	}

	var auditText strings.Builder
	rows, err := f.l.pool.Query(ctx, `SELECT actor || ' ' || action || ' ' || resource || ' ' || metadata::text FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		auditText.WriteString(s + "\n")
	}
	rows.Close()
	var dbText strings.Builder
	for _, q := range []string{
		`SELECT row_to_json(g)::text FROM (SELECT id, name, boundary, status, last_error, catalog_version FROM gateways) g`,
		`SELECT row_to_json(r)::text FROM gateway_replicas r`,
		`SELECT row_to_json(c)::text FROM gateway_connectors c`,
	} {
		rs, err := f.l.pool.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		for rs.Next() {
			var s string
			_ = rs.Scan(&s)
			dbText.WriteString(s + "\n")
		}
		rs.Close()
	}

	for name, canary := range canaries {
		for i, r := range responses {
			if strings.Contains(r, canary) {
				t.Errorf("%s appears in response %d after mint: %s", name, i, r)
			}
		}
		if strings.Contains(auditText.String(), canary) {
			t.Errorf("%s appears in audit_events", name)
		}
		if strings.Contains(f.l.logs.String(), canary) {
			t.Errorf("%s appears in the logs", name)
		}
		if strings.Contains(dbText.String(), canary) {
			t.Errorf("%s appears in a gateway table outside its hash column", name)
		}
	}
	if !strings.Contains(auditText.String(), "gateway.enroll") || !strings.Contains(auditText.String(), "gateway.revoke") {
		t.Fatalf("expected gateway audit rows, got:\n%s", auditText.String())
	}
}

// TestLive_Gateway_MachineRoutesArePinned pins every route registered
// under the session-exempt /api/v1/gateways/ prefix: E1 is the only one
// without GatewayAuth, and a new route there fails this test until it is
// added here on purpose. Unknown paths under the prefix get 401 from
// GatewayAuth, never a handler.
func TestLive_Gateway_MachineRoutesArePinned(t *testing.T) {
	f := newGatewayFixture(t)
	want := map[string]bool{
		"POST /api/v1/gateways/enroll":        true,
		"POST /api/v1/gateways/:id/heartbeat": true,
		"PUT /api/v1/gateways/:id/catalog":    true,
		// api#294
		"POST /api/v1/gateways/:id/tasks/claim":            true,
		"POST /api/v1/gateways/:id/tasks/:task_id/lease":   true,
		"POST /api/v1/gateways/:id/tasks/:task_id/release": true,
		"POST /api/v1/gateways/:id/tasks/:task_id/result":  true,
		// api#308
		"PUT /api/v1/gateways/:id/connectors/:connector_id/discovery": true,
		"GET /api/v1/gateways/:id/connectors/:connector_id/snapshot":  true,
	}
	got := map[string]bool{}
	for _, r := range f.l.app.GetRoutes(true) {
		if strings.HasPrefix(r.Path, "/api/v1/gateways/") && r.Method != http.MethodHead {
			got[r.Method+" "+r.Path] = true
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("unreviewed route under the session-exempt /api/v1/gateways/ prefix: %s", k)
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing gateway machine route %s", k)
		}
	}
	// Without a credential everything under /gateways/:id is 401.
	for _, p := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/gateways/" + uuid.NewString() + "/heartbeat"},
		{http.MethodPut, "/api/v1/gateways/" + uuid.NewString() + "/catalog"},
		{http.MethodPost, "/api/v1/gateways/" + uuid.NewString() + "/tasks/claim"},
		{http.MethodPost, "/api/v1/gateways/" + uuid.NewString() + "/tasks/" + uuid.NewString() + "/lease"},
		{http.MethodPost, "/api/v1/gateways/" + uuid.NewString() + "/tasks/" + uuid.NewString() + "/release"},
		{http.MethodPost, "/api/v1/gateways/" + uuid.NewString() + "/tasks/" + uuid.NewString() + "/result"},
		{http.MethodGet, "/api/v1/gateways/" + uuid.NewString()},
		{http.MethodPost, "/api/v1/gateways/not-a-uuid/heartbeat"},
	} {
		if code, raw := f.l.callAs(t, p.method, p.path, nil, nil); code != http.StatusUnauthorized {
			t.Errorf("%s %s without a credential = %d %s; want 401", p.method, p.path, code, raw)
		}
	}
	// The admin list is NOT under the exempt prefix.
	if code, _ := f.l.callAs(t, http.MethodGet, "/api/v1/gateways", nil, nil); code != http.StatusUnauthorized && code != http.StatusNotFound {
		t.Errorf("GET /api/v1/gateways anonymous = %d; want 401 or 404", code)
	}
}

// hashEncodings is every text form a hash could take in a log, a JSON
// body or a bytea dump.
func hashEncodings(h []byte) map[string]string {
	return map[string]string{
		"hex":       hex.EncodeToString(h),
		"base64":    base64.StdEncoding.EncodeToString(h),
		"base64url": base64.RawURLEncoding.EncodeToString(h),
		"base64raw": base64.RawStdEncoding.EncodeToString(h),
	}
}

// TestLive_Gateway_EnrollRefusesPlainHTTPInProduction: outside dev, E1
// over plain http is refused before the token is looked at (ADR 0001
// section 11), and the same token still works over https.
func TestLive_Gateway_EnrollRefusesPlainHTTPInProduction(t *testing.T) {
	f := newGatewayFixture(t, func(c *Config) { c.Env = ModeProduction })
	id := f.createGateway(t, "https-gw")
	_, token := f.mintToken(t, id, nil)
	code, body := f.enroll(t, token, nil)
	if code != http.StatusForbidden || errCode(t, body) != "https_required" {
		t.Fatalf("enroll over http in production = %d %s; want 403 https_required", code, body)
	}
	if code, body := f.enroll(t, token, map[string]string{"X-Forwarded-Proto": "http"}); code != http.StatusForbidden {
		t.Fatalf("enroll with X-Forwarded-Proto http = %d %s; want 403", code, body)
	}
	code, body = f.enroll(t, token, map[string]string{"X-Forwarded-Proto": "https"})
	if code != http.StatusCreated {
		t.Fatalf("enroll behind a TLS proxy = %d %s; want 201", code, body)
	}
	found := false
	for _, r := range f.l.auditRows(t, "gateway.enroll") {
		if r.Metadata["reason"] == "insecure_transport" {
			found = true
		}
	}
	if !found {
		t.Error("no gateway.enroll audit row with reason insecure_transport")
	}
}
