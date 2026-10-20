package main

// Gateway admin view fixes found while building the console (api#298):
// the explicit over_privileged flag, the connector summary in the list,
// replicas_seen computed the same in list and detail, task counts over
// every task, and the binding and observation-source reads on
// gateway.list. Driven through the REAL router against Postgres and
// Redis.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type gwListItem struct {
	ID                       string     `json:"id"`
	LastStatus               string     `json:"last_status"`
	ReplicasSeen             int        `json:"replicas_seen"`
	OverPrivileged           bool       `json:"over_privileged"`
	OverPrivilegedReportedAt *time.Time `json:"over_privileged_reported_at"`
	Connectors               []struct {
		ID          string `json:"id"`
		ConnectorID string `json:"connector_id"`
		Kind        string `json:"kind"`
		Status      string `json:"status"`
		TargetCount int    `json:"target_count"`
	} `json:"connectors"`
}

func (f *gwFixture) listItem(t *testing.T, gatewayID string) gwListItem {
	t.Helper()
	code, body := f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways", f.admin, nil)
	if code != http.StatusOK {
		t.Fatalf("list = %d %s", code, body)
	}
	var l struct {
		Items []gwListItem `json:"items"`
	}
	mustJSON(t, body, &l)
	for _, it := range l.Items {
		if it.ID == gatewayID {
			return it
		}
	}
	t.Fatalf("gateway %s not in the list %s", gatewayID, body)
	return gwListItem{}
}

func (f *gwFixture) detailGateway(t *testing.T, gatewayID string) gwListItem {
	t.Helper()
	code, body := f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+gatewayID, f.admin, nil)
	if code != http.StatusOK {
		t.Fatalf("detail = %d %s", code, body)
	}
	var d struct {
		Gateway gwListItem `json:"gateway"`
	}
	mustJSON(t, body, &d)
	return d.Gateway
}

func (f *gwFixture) heartbeatStatus(t *testing.T, gw gwEnrolled, replica, status string) {
	t.Helper()
	hb := gwHeartbeatBody(replica)
	hb["status"] = status
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+gw.GatewayID+"/heartbeat",
		map[string]string{"X-Gateway-Secret": gw.GatewaySecret}, hb); code != http.StatusOK {
		t.Fatalf("heartbeat %s = %d %s", status, code, body)
	}
}

// TestLive_Gateway_OverPrivilegedFlag: an over_privileged heartbeat sets
// over_privileged and its reported time on the list and the detail; a
// later ok heartbeat from the same replica clears both.
func TestLive_Gateway_OverPrivilegedFlag(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "op-gw")
	replica := uuid.NewString()
	f.heartbeatStatus(t, gw, replica, "ok")
	if it := f.listItem(t, gw.GatewayID); it.OverPrivileged || it.OverPrivilegedReportedAt != nil {
		t.Fatalf("after an ok heartbeat: over_privileged %v at %v; want false, none", it.OverPrivileged, it.OverPrivilegedReportedAt)
	}

	start := time.Now().Add(-time.Second)
	f.heartbeatStatus(t, gw, replica, "over_privileged")
	for name, it := range map[string]gwListItem{"list": f.listItem(t, gw.GatewayID), "detail": f.detailGateway(t, gw.GatewayID)} {
		if !it.OverPrivileged || it.OverPrivilegedReportedAt == nil || it.OverPrivilegedReportedAt.Before(start) {
			t.Fatalf("%s after an over_privileged heartbeat: over_privileged %v at %v; want true, reported now", name, it.OverPrivileged, it.OverPrivilegedReportedAt)
		}
	}
	// A second replica reporting ok does not hide the first.
	f.heartbeatStatus(t, gw, uuid.NewString(), "ok")
	if it := f.listItem(t, gw.GatewayID); !it.OverPrivileged || it.LastStatus != "ok" {
		t.Fatalf("another replica ok: over_privileged %v last_status %q; want true, ok", it.OverPrivileged, it.LastStatus)
	}
	f.heartbeatStatus(t, gw, replica, "ok")
	if it := f.detailGateway(t, gw.GatewayID); it.OverPrivileged || it.OverPrivilegedReportedAt != nil {
		t.Fatalf("after the replica recovered: over_privileged %v at %v; want false, none", it.OverPrivileged, it.OverPrivilegedReportedAt)
	}
}

// TestLive_Gateway_ListCarriesConnectorSummary: GET /admin/gateways has
// each Gateway's connectors as kind, status and target count, with no
// target ids or names; a Gateway with none has an empty list.
func TestLive_Gateway_ListCarriesConnectorSummary(t *testing.T) {
	f := newGatewayFixture(t)
	gw, cid := f.gatewayReady(t, "summary-gw")
	bare := f.createGateway(t, "summary-bare-gw")

	it := f.listItem(t, gw.GatewayID)
	if len(it.Connectors) != 1 {
		t.Fatalf("connectors = %+v; want one", it.Connectors)
	}
	c := it.Connectors[0]
	if c.ID != cid || c.ConnectorID != "argocd-main" || c.Kind != "argocd" || c.Status != "approved" || c.TargetCount != 3 {
		t.Fatalf("connector summary = %+v; want %s argocd-main argocd approved 3 targets", c, cid)
	}
	code, body := f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways", f.admin, nil)
	if code != http.StatusOK {
		t.Fatalf("list = %d", code)
	}
	for _, leak := range []string{"payments-api", "orders-api", "billing-api", "\"targets\""} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("list carries target detail %q: %s", leak, body)
		}
	}
	if b := f.listItem(t, bare); b.Connectors == nil || len(b.Connectors) != 0 {
		t.Fatalf("a Gateway with no connector: connectors = %#v; want []", b.Connectors)
	}
}

// TestLive_Gateway_ReplicasSeenSameInListAndDetail: the detail counts
// replicas the way the list does (it returned 0 before api#298).
func TestLive_Gateway_ReplicasSeenSameInListAndDetail(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "replicas-gw")
	for range 2 {
		f.heartbeatStatus(t, gw, uuid.NewString(), "ok")
	}
	// A replica last seen outside the window counts in neither.
	old := uuid.NewString()
	f.heartbeatStatus(t, gw, old, "ok")
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE gateway_replicas SET last_seen_at = now() - interval '1 hour' WHERE replica_id = $1`, old); err != nil {
		t.Fatal(err)
	}
	list, detail := f.listItem(t, gw.GatewayID), f.detailGateway(t, gw.GatewayID)
	if list.ReplicasSeen != 2 || detail.ReplicasSeen != list.ReplicasSeen {
		t.Fatalf("replicas_seen list %d detail %d; want 2 in both", list.ReplicasSeen, detail.ReplicasSeen)
	}
}

// TestLive_Gateway_TaskCountsCoverEveryTask: counts in GET
// /admin/gateways/:id/tasks are over all of the Gateway's tasks per
// state, not the returned page or the state filter.
func TestLive_Gateway_TaskCountsCoverEveryTask(t *testing.T) {
	f := newObsFixture(t)
	// Each later write on the same secret cancels the open task before
	// it (superseded_by_later_write): one queued, two cancelled.
	for range 3 {
		f.executeOn(t, f.env, f.secret)
	}
	for _, q := range []string{"?limit=1", "?state=cancelled&limit=1", "?state=queued"} {
		code, body := f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+f.gw.GatewayID+"/tasks"+q, f.admin, nil)
		if code != http.StatusOK {
			t.Fatalf("tasks%s = %d %s", q, code, body)
		}
		var r struct {
			Items  []map[string]any `json:"items"`
			Counts map[string]int   `json:"counts"`
			Total  int              `json:"total"`
		}
		mustJSON(t, body, &r)
		if len(r.Items) != 1 {
			t.Fatalf("tasks%s items = %d; want 1", q, len(r.Items))
		}
		want := map[string]int{"queued": 1, "leased": 0, "done": 0, "dead": 0, "cancelled": 2}
		if r.Total != 3 || len(r.Counts) != len(want) {
			t.Fatalf("tasks%s counts = %v total %d; want %v total 3", q, r.Counts, r.Total, want)
		}
		for k, v := range want {
			if r.Counts[k] != v {
				t.Fatalf("tasks%s counts = %v; want %v", q, r.Counts, want)
			}
		}
	}
}

// TestLive_Gateway_ListPermissionReadsButNeverWritesBindings: gateway.list
// alone reads the binding list and an environment's observation source,
// and gets 403 on every binding write, the source PUT and the connector
// approve, which stay on gateway.bind. Nothing changes.
func TestLive_Gateway_ListPermissionReadsButNeverWritesBindings(t *testing.T) {
	f := newObsFixture(t)
	reader := uuid.New()
	hdr := map[string]string{"Cookie": f.l.sessionFor(t, reader, "gw-reader-"+reader.String()[:8]+"@example.com")}
	f.l.addGrant(t, reader.String(), []string{"gateway.list"}, `{}`)

	code, body := f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateway-bindings?gateway_id="+f.gw.GatewayID, hdr, nil)
	if code != http.StatusOK || !strings.Contains(string(body), f.bindingID) {
		t.Fatalf("gateway.list GET bindings = %d %s; want 200 with %s", code, body, f.bindingID)
	}
	code, body = f.l.callAs(t, http.MethodGet, "/api/v1/admin/environments/"+f.env.String()+"/observation-source", hdr, nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"observation_source":"gateway"`) {
		t.Fatalf("gateway.list GET observation source = %d %s; want 200 gateway", code, body)
	}

	writes := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/admin/gateway-bindings", map[string]any{
			"gateway_id": f.gw.GatewayID, "environment_id": f.env.String(), "secret_id": f.secret.String(),
			"argocd_connector_id": f.connID, "argocd_target_id": "orders-api",
		}},
		{http.MethodDelete, "/api/v1/admin/gateway-bindings/" + f.bindingID, nil},
		{http.MethodPut, "/api/v1/admin/environments/" + f.env.String() + "/observation-source", map[string]any{"observation_source": "none"}},
		{http.MethodPost, "/api/v1/admin/gateways/" + f.gw.GatewayID + "/connectors/" + f.connID + "/approve", nil},
	}
	for _, w := range writes {
		if code, raw := f.l.callAs(t, w.method, w.path, hdr, w.body); code != http.StatusForbidden {
			t.Errorf("gateway.list %s %s = %d %s; want 403", w.method, w.path, code, raw)
		}
	}
	var bindings int
	var src string
	ctx := t.Context()
	if err := f.l.pool.QueryRow(ctx, `SELECT count(*) FROM gateway_connector_bindings WHERE deleted_at IS NULL`).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := f.l.pool.QueryRow(ctx, `SELECT observation_source FROM environments WHERE id = $1`, f.env).Scan(&src); err != nil {
		t.Fatal(err)
	}
	if bindings != 1 || src != "gateway" {
		t.Fatalf("after refused writes: bindings %d source %q; want 1, gateway", bindings, src)
	}
}
