package main

// E2 heartbeat contract 2 (api#308, ADR 0002 S4; gateway
// docs/design/discovery-contract.md section 2), through the real router
// against Postgres and Redis: version negotiation, the scope digest
// (C6) and the discovery lease (C9).

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

const (
	scopeD1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	scopeD2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// hbV2 is a contract 2 shaped heartbeat for argocd-main.
func hbV2(replica, digest string, discovery bool, boundVersion string) map[string]any {
	conn := map[string]any{"connector_id": "argocd-main", "kind": "argocd", "status": "ok", "scope_digest": digest, "discovery_enabled": discovery}
	if discovery {
		conn["discovery_interval_seconds"] = 60
	}
	return map[string]any{
		"replica_id": replica, "gateway_version": "0.4.0", "contract_versions": []string{"1", "2"},
		"status": "ok", "in_flight": 0, "bound_targets_version": boundVersion,
		"connectors": []map[string]any{conn},
	}
}

type hbResponse struct {
	ContractVersion string `json:"contract_version"`
	DiscoveryLeases []struct {
		ConnectorID string `json:"connector_id"`
		LeaseID     string `json:"lease_id"`
		Generation  int64  `json:"generation"`
		ExpiresAt   string `json:"expires_at"`
	} `json:"discovery_leases"`
	SnapshotGenerations []struct {
		ConnectorID string `json:"connector_id"`
		Generation  int64  `json:"generation"`
	} `json:"snapshot_generations"`
	BoundTargetsVersion *string `json:"bound_targets_version"`
	BoundTargets        *[]struct {
		ConnectorID string   `json:"connector_id"`
		TargetIDs   []string `json:"target_ids"`
	} `json:"bound_targets"`
}

func (f *gwFixture) hb(t *testing.T, gw gwEnrolled, body any) (int, hbResponse, []byte) {
	t.Helper()
	code, raw := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+gw.GatewayID+"/heartbeat",
		map[string]string{"X-Gateway-Secret": gw.GatewaySecret}, body)
	var r hbResponse
	if code == http.StatusOK {
		mustJSON(t, raw, &r)
	}
	return code, r, raw
}

func (f *gwFixture) mustHB(t *testing.T, gw gwEnrolled, body any) hbResponse {
	t.Helper()
	code, r, raw := f.hb(t, gw, body)
	if code != http.StatusOK {
		t.Fatalf("heartbeat = %d %s", code, raw)
	}
	return r
}

type connRow struct {
	Status, Reason, Approved string
}

func (f *gwFixture) connRow(t *testing.T, connID string) connRow {
	t.Helper()
	var c connRow
	if err := f.l.pool.QueryRow(t.Context(), `SELECT status, COALESCE(status_reason, ''), COALESCE(approved_scope_digest, '')
		FROM gateway_connectors WHERE id = $1`, connID).Scan(&c.Status, &c.Reason, &c.Approved); err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *gwFixture) approveScope(t *testing.T, gatewayID, connID string, body any) (int, []byte) {
	t.Helper()
	return f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+gatewayID+"/connectors/"+connID+"/approve", f.admin, body)
}

func (f *gwFixture) bindingSuspended(t *testing.T, bindingID string) string {
	t.Helper()
	var r string
	if err := f.l.pool.QueryRow(t.Context(), `SELECT COALESCE(suspended_reason, '') FROM gateway_connector_bindings WHERE id = $1`, bindingID).Scan(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestLive_GatewayDiscovery_Contract1HeartbeatUnchanged: a heartbeat in
// the old contract 1 shape is answered exactly as before; a Gateway that
// lists "2" gets contract 2 even before it sends the contract 2 fields;
// those fields are refused from a request that does not list "2".
func TestLive_GatewayDiscovery_Contract1HeartbeatUnchanged(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "hb-v1-gw")

	code, raw := f.heartbeat(t, gw.GatewayID, gw.GatewaySecret, uuid.NewString())
	if code != http.StatusOK {
		t.Fatalf("contract 1 heartbeat = %d %s", code, raw)
	}
	var keys map[string]any
	mustJSON(t, raw, &keys)
	want := []string{"catalog_version", "claim_poll_seconds", "contract_version", "next_heartbeat_seconds", "server_time", "status"}
	got := make([]string, 0, len(keys))
	for k := range keys {
		got = append(got, k)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) || keys["contract_version"] != "1" {
		t.Fatalf("contract 1 response = %s; want exactly %v with contract_version 1", raw, want)
	}

	// Lists "2", contract 1 shaped (the first heartbeat after start).
	body := gwHeartbeatBody(uuid.NewString())
	body["contract_versions"] = []string{"1", "2"}
	r := f.mustHB(t, gw, body)
	if r.ContractVersion != "2" || r.BoundTargetsVersion == nil || *r.BoundTargetsVersion != "" || r.DiscoveryLeases != nil || r.BoundTargets != nil {
		t.Fatalf("contract 2 answer to a contract 1 shaped heartbeat = %+v", r)
	}

	// Contract 2 fields without "2" listed: 400.
	bad := hbV2(uuid.NewString(), scopeD1, false, "")
	bad["contract_versions"] = []string{"1"}
	if code, _, raw := f.hb(t, gw, bad); code != http.StatusBadRequest || errCode(t, raw) != "invalid_request" {
		t.Fatalf("contract 2 field without contract 2 = %d %s; want 400 invalid_request", code, raw)
	}
	noBound := hbV2(uuid.NewString(), scopeD1, false, "")
	delete(noBound, "bound_targets_version")
	if code, _, raw := f.hb(t, gw, noBound); code != http.StatusBadRequest {
		t.Fatalf("scope digest in a contract 1 shaped heartbeat = %d %s; want 400", code, raw)
	}
}

// TestLive_GatewayDiscovery_ScopeChangePausesDispatch: the first digest
// of a connector approved before contract 2 is adopted with discovery
// off; a different digest later takes the connector back to pending,
// suspends its bindings, moves a leased task back to queued, pauses
// dispatch and is audited. Approving the old digest or none is refused;
// re-approving the new one resumes the binding and dispatch.
func TestLive_GatewayDiscovery_ScopeChangePausesDispatch(t *testing.T) {
	f := newObsFixture(t)
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)

	f.mustHB(t, f.gw, hbV2(f.replica, scopeD1, false, ""))
	if c := f.connRow(t, f.connID); c.Status != "approved" || c.Approved != scopeD1 || c.Reason != "" {
		t.Fatalf("after the first digest: %+v; want approved with the digest adopted", c)
	}
	adopted := f.l.auditRows(t, "gateway.connector.scope_changed")
	if len(adopted) != 1 || adopted[0].Metadata["adopted"] != true || adopted[0].Metadata["scope_digest_after"] != scopeD1 ||
		adopted[0].Metadata["scope_digest_before"] != nil {
		t.Fatalf("adoption audit = %+v", adopted)
	}

	if code, task := f.claim(t, f.replica); code != http.StatusOK || task == nil {
		t.Fatalf("claim before the change = %d", code)
	}
	f.mustHB(t, f.gw, hbV2(f.replica, scopeD2, false, ""))
	if c := f.connRow(t, f.connID); c.Status != "advertised" || c.Reason != "scope_changed" || c.Approved != scopeD1 {
		t.Fatalf("after the change: %+v; want advertised, scope_changed", c)
	}
	if r := f.bindingSuspended(t, f.bindingID); r != "scope_changed" {
		t.Fatalf("binding suspended_reason = %q; want scope_changed", r)
	}
	if ts := f.taskRows(t, reqID); len(ts) != 1 || ts[0].State != storage.ObservationTaskQueued {
		t.Fatalf("task after the change = %+v; want back to queued", ts)
	}
	if code := f.claimCode(t); code != http.StatusNoContent {
		t.Fatalf("claim after the scope change = %d; want 204", code)
	}
	changed := f.l.auditRows(t, "gateway.connector.scope_changed")
	if len(changed) != 2 {
		t.Fatalf("scope_changed rows = %d; want 2", len(changed))
	}
	m := changed[1].Metadata
	if m["scope_digest_before"] != scopeD1 || m["scope_digest_after"] != scopeD2 || m["bindings_suspended"] != float64(1) ||
		m["tasks_requeued"] != float64(1) || m["adopted"] != false {
		t.Fatalf("scope change audit = %v", m)
	}
	if !reflectEqualSanitized("gateway.connector.scope_changed", m) {
		t.Fatalf("scope change audit carries keys off the allowlist: %v", m)
	}

	// The admin approves the scope they are shown, not an older one.
	for _, body := range []any{nil, map[string]any{"scope_digest": scopeD1}} {
		if code, raw := f.approveScope(t, f.gw.GatewayID, f.connID, body); code != http.StatusConflict || errCode(t, raw) != "scope_digest_changed" {
			t.Fatalf("approve %v = %d %s; want 409 scope_digest_changed", body, code, raw)
		}
	}
	if code, raw := f.approveScope(t, f.gw.GatewayID, f.connID, map[string]any{"scope_digest": scopeD2}); code != http.StatusOK {
		t.Fatalf("re-approve = %d %s", code, raw)
	}
	if c := f.connRow(t, f.connID); c.Status != "approved" || c.Approved != scopeD2 || c.Reason != "" {
		t.Fatalf("after re-approve: %+v", c)
	}
	if r := f.bindingSuspended(t, f.bindingID); r != "" {
		t.Fatalf("binding still suspended after re-approve: %q", r)
	}
	if code, task := f.claim(t, f.replica); code != http.StatusOK || task == nil {
		t.Fatalf("claim after re-approve = %d; want 200", code)
	}
	ap := f.l.auditRows(t, "gateway.connector.approved")
	if last := ap[len(ap)-1].Metadata; last["scope_digest"] != scopeD2 || last["bindings_resumed"] != float64(1) {
		t.Fatalf("approve audit = %v", last)
	}
	denied := 0
	for _, r := range f.l.auditRowsWithStatus(t, "gateway.connector.approved") {
		if r.Status == "denied" && r.Metadata["error_kind"] == "scope_digest_changed" {
			denied++
		}
	}
	if denied != 2 {
		t.Fatalf("denied approve audits = %d; want 2", denied)
	}
}

// reflectEqualSanitized reports whether the audit sanitizer keeps meta
// unchanged.
func reflectEqualSanitized(action string, meta map[string]any) bool {
	a, _ := json.Marshal(storage.SanitizeAuditMetadata(action, meta))
	b, _ := json.Marshal(meta)
	return bytes.Equal(a, b)
}

// TestLive_GatewayDiscovery_ReplicasDisagree: while live replicas report
// different digests the connector is marked
// scope_mismatch_between_replicas, dispatch is paused, no lease is
// granted and approve is refused. Once they agree, all three lift.
func TestLive_GatewayDiscovery_ReplicasDisagree(t *testing.T) {
	f := newObsFixture(t)
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	r1, r2 := f.replica, uuid.NewString()
	f.mustHB(t, f.gw, hbV2(r1, scopeD1, false, ""))
	if res := f.mustHB(t, f.gw, hbV2(r2, scopeD2, true, "")); len(res.DiscoveryLeases) != 0 {
		t.Fatalf("lease granted while replicas disagree: %+v", res.DiscoveryLeases)
	}
	if c := f.connRow(t, f.connID); c.Reason != "scope_mismatch_between_replicas" || c.Status != "approved" {
		t.Fatalf("connector while replicas disagree = %+v", c)
	}
	if code := f.claimCode(t); code != http.StatusNoContent {
		t.Fatalf("claim while replicas disagree = %d; want 204", code)
	}
	code, raw := f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+f.gw.GatewayID, f.admin, nil)
	if code != http.StatusOK || !strings.Contains(string(raw), `"scope_mismatch":true`) {
		t.Fatalf("admin read while replicas disagree = %d %s", code, raw)
	}
	f.mustHB(t, f.gw, hbV2(r2, scopeD1, false, ""))
	if c := f.connRow(t, f.connID); c.Reason != "" || c.Status != "approved" {
		t.Fatalf("connector after the replicas agree = %+v", c)
	}
	if code, task := f.claim(t, r1); code != http.StatusOK || task == nil {
		t.Fatalf("claim after the replicas agree = %d; want 200", code)
	}
}

// TestLive_GatewayDiscovery_BoundTargets: bound_targets is sent when the
// version the replica applied differs, and left out when it is current.
func TestLive_GatewayDiscovery_BoundTargets(t *testing.T) {
	f := newObsFixture(t)
	r := f.mustHB(t, f.gw, hbV2(f.replica, scopeD1, false, ""))
	if r.BoundTargetsVersion == nil || *r.BoundTargetsVersion == "" || r.BoundTargets == nil {
		t.Fatalf("first contract 2 answer = %+v; want the bound list and its version", r)
	}
	if got := *r.BoundTargets; len(got) != 1 || got[0].ConnectorID != "argocd-main" || !slices.Equal(got[0].TargetIDs, []string{"payments-api"}) {
		t.Fatalf("bound_targets = %+v", got)
	}
	r2 := f.mustHB(t, f.gw, hbV2(f.replica, scopeD1, false, *r.BoundTargetsVersion))
	if r2.BoundTargets != nil || r2.BoundTargetsVersion == nil || *r2.BoundTargetsVersion != *r.BoundTargetsVersion {
		t.Fatalf("answer with the current version = %+v; want no list", r2)
	}
	// Deleting the last binding sends an empty full replace.
	if code, raw := f.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+f.bindingID, f.admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete binding = %d %s", code, raw)
	}
	r3 := f.mustHB(t, f.gw, hbV2(f.replica, scopeD1, false, *r.BoundTargetsVersion))
	if r3.BoundTargets == nil || len(*r3.BoundTargets) != 0 || *r3.BoundTargetsVersion != "" {
		t.Fatalf("answer after the last unbind = %+v; want [] and an empty version", r3)
	}
}

// TestLive_GatewayDiscovery_ApproveNeedsMapping: a connector with
// discovery on cannot be approved before an upload and a complete team
// mapping exist.
func TestLive_GatewayDiscovery_ApproveNeedsMapping(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "hb-map-gw")
	if code, raw := f.catalog(t, gw.GatewayID, gw.GatewaySecret, map[string]any{"connectors": []map[string]any{
		{"connector_id": "argocd-main", "kind": "argocd", "targets": []map[string]any{}},
	}}); code != http.StatusOK {
		t.Fatalf("catalog = %d %s", code, raw)
	}
	f.mustHB(t, gw, hbV2(uuid.NewString(), scopeD1, true, ""))
	connID := f.connIDOf(t, gw.GatewayID, "argocd-main")
	if code, raw := f.approveScope(t, gw.GatewayID, connID, map[string]any{"scope_digest": scopeD1}); code != http.StatusConflict ||
		errCode(t, raw) != "project_mapping_incomplete" {
		t.Fatalf("approve without a mapping = %d %s; want 409 project_mapping_incomplete", code, raw)
	}
	if code, raw := f.approveScope(t, gw.GatewayID, connID, map[string]any{"scope_digest": "not-a-digest"}); code != http.StatusBadRequest {
		t.Fatalf("approve with a malformed digest = %d %s; want 400", code, raw)
	}
}

func (f *gwFixture) connIDOf(t *testing.T, gatewayID, name string) string {
	t.Helper()
	var id string
	if err := f.l.pool.QueryRow(t.Context(), `SELECT id FROM gateway_connectors WHERE gateway_id = $1 AND name = $2`, gatewayID, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// secondApp builds another api instance (its own router, services and
// Redis client) on the same database as l, the way a second api replica
// runs. It does not wipe anything.
func (l *liveApp) secondApp(t *testing.T) *liveApp {
	t.Helper()
	ctx := t.Context()
	rdb, err := runtime.Open(ctx, runtime.Config{URL: os.Getenv("TEST_REDIS_URL")})
	if err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	km, err := keymgmt.NewLocalKMS(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	authSvc := services.NewAuthService(storage.NewLocalUsers(l.pool), storage.NewRoles(l.pool), storage.NewUserRoles(l.pool), storage.NewAuditEvents(l.pool))
	logs := &hygLogBuffer{}
	cfg := Config{Env: ModeDev, AllowInsecureHeaderAuth: true, AllowDirectAgentMint: true, AllowInsecureVaultAddr: true}
	return &liveApp{app: newApp(cfg, slog.New(slog.NewTextHandler(logs, nil)), l.pool, rdb, km, authSvc), pool: l.pool, logs: logs}
}

// TestLive_GatewayDiscovery_LeaseSingleAcrossAPIInstances: many
// replicas heartbeating concurrently through two api instances on one
// database get exactly one lease. No second lease while it is live; an
// expired lease is replaced only after the interval floor, with a
// higher generation.
func TestLive_GatewayDiscovery_LeaseSingleAcrossAPIInstances(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "hb-lease-gw")
	if code, raw := f.catalog(t, gw.GatewayID, gw.GatewaySecret, map[string]any{"connectors": []map[string]any{
		{"connector_id": "argocd-main", "kind": "argocd", "targets": []map[string]any{}},
	}}); code != http.StatusOK {
		t.Fatalf("catalog = %d %s", code, raw)
	}
	apps := []*liveApp{f.l, f.l.secondApp(t)}
	hdr := map[string]string{"X-Gateway-Secret": gw.GatewaySecret}

	const n = 12
	var mu sync.Mutex
	var leases []string
	var gens []int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			code, raw := apps[i%2].callAs(t, http.MethodPost, "/api/v1/gateways/"+gw.GatewayID+"/heartbeat", hdr,
				hbV2(uuid.NewString(), scopeD1, true, ""))
			if code != http.StatusOK {
				t.Errorf("heartbeat %d = %d %s", i, code, raw)
				return
			}
			var r hbResponse
			_ = json.Unmarshal(raw, &r)
			mu.Lock()
			defer mu.Unlock()
			for _, l := range r.DiscoveryLeases {
				leases = append(leases, l.LeaseID)
				gens = append(gens, l.Generation)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if len(leases) != 1 || gens[0] != 1 {
		t.Fatalf("leases granted across %d concurrent heartbeats on two api instances = %v (generations %v); want exactly one, generation 1", n, leases, gens)
	}

	// Live lease: no second grant.
	if r := f.mustHB(t, gw, hbV2(uuid.NewString(), scopeD1, true, "")); len(r.DiscoveryLeases) != 0 {
		t.Fatalf("second lease while the first is live: %+v", r.DiscoveryLeases)
	}
	ctx := context.Background()
	connID := f.connIDOf(t, gw.GatewayID, "argocd-main")
	// Live lease past the floor: still no second grant.
	if _, err := f.l.pool.Exec(ctx, `UPDATE gateway_connectors SET last_lease_granted_at = now() - interval '61 seconds' WHERE id = $1`, connID); err != nil {
		t.Fatal(err)
	}
	if r := f.mustHB(t, gw, hbV2(uuid.NewString(), scopeD1, true, "")); len(r.DiscoveryLeases) != 0 {
		t.Fatalf("second lease while the first is live and the floor passed: %+v", r.DiscoveryLeases)
	}
	// Expired, but the previous grant is younger than the floor.
	if _, err := f.l.pool.Exec(ctx, `UPDATE gateway_connectors SET discovery_lease_expires_at = now() - interval '1 second',
		last_lease_granted_at = now() - interval '30 seconds' WHERE id = $1`, connID); err != nil {
		t.Fatal(err)
	}
	if r := f.mustHB(t, gw, hbV2(uuid.NewString(), scopeD1, true, "")); len(r.DiscoveryLeases) != 0 {
		t.Fatalf("lease inside the interval floor: %+v", r.DiscoveryLeases)
	}
	if _, err := f.l.pool.Exec(ctx, `UPDATE gateway_connectors SET last_lease_granted_at = now() - interval '61 seconds' WHERE id = $1`, connID); err != nil {
		t.Fatal(err)
	}
	r := f.mustHB(t, gw, hbV2(uuid.NewString(), scopeD1, true, ""))
	if len(r.DiscoveryLeases) != 1 || r.DiscoveryLeases[0].Generation != 2 || r.DiscoveryLeases[0].LeaseID == leases[0] {
		t.Fatalf("lease after expiry and floor = %+v; want one new lease with generation 2", r.DiscoveryLeases)
	}
	// A replica reporting the connector unreachable never gets one.
	if _, err := f.l.pool.Exec(ctx, `UPDATE gateway_connectors SET discovery_lease_expires_at = now() - interval '1 second',
		last_lease_granted_at = now() - interval '61 seconds' WHERE id = $1`, connID); err != nil {
		t.Fatal(err)
	}
	down := hbV2(uuid.NewString(), scopeD1, true, "")
	down["connectors"].([]map[string]any)[0]["status"] = "unreachable"
	if r := f.mustHB(t, gw, down); len(r.DiscoveryLeases) != 0 {
		t.Fatalf("lease to a replica whose connector is unreachable: %+v", r.DiscoveryLeases)
	}
}

// TestLive_GatewayDiscovery_FirstDigestWithDiscoveryNeedsApproval: a
// connector approved before contract 2 adopts its first digest only with
// discovery off (decision S-3). With discovery on it goes back to
// pending and its bindings are suspended.
func TestLive_GatewayDiscovery_FirstDigestWithDiscoveryNeedsApproval(t *testing.T) {
	f := newObsFixture(t)
	f.mustHB(t, f.gw, hbV2(f.replica, scopeD1, true, ""))
	if c := f.connRow(t, f.connID); c.Status != "advertised" || c.Reason != "scope_changed" || c.Approved != "" {
		t.Fatalf("first digest with discovery on: %+v; want advertised, scope_changed, nothing adopted", c)
	}
	if r := f.bindingSuspended(t, f.bindingID); r != "scope_changed" {
		t.Fatalf("binding suspended_reason = %q; want scope_changed", r)
	}
	rows := f.l.auditRows(t, "gateway.connector.scope_changed")
	if len(rows) != 1 || rows[0].Metadata["adopted"] != false || rows[0].Metadata["scope_digest_before"] != nil {
		t.Fatalf("audit = %+v; want one non-adopted change with no old digest", rows)
	}
}
