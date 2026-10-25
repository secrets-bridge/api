package main

// Fail-closed checks from the security review on #317 (api#308, ADR 0002
// C2 and C6), through the real router against Postgres and Redis.

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func (f *obsFixture) claimFrom(t *testing.T, replica string) int {
	t.Helper()
	code, _, _, _ := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, replica)
	return code
}

// TestLive_GatewayDiscoveryReview_ClaimNeedsOwnApprovedDigest: with an
// approved digest, only a replica whose own live row reports exactly
// that digest claims. A replica's first, contract 1 shaped heartbeat, a
// replica id that never heartbeated, a contract 1 only replica after the
// approved replica left, and a replica at another digest all get 204.
func TestLive_GatewayDiscoveryReview_ClaimNeedsOwnApprovedDigest(t *testing.T) {
	f := newObsFixture(t)
	f.retireReplicas(t, f.gw.GatewayID)
	f.mustHB(t, f.gw, hbV2(f.replica, scopeD1, false, "")) // adopted
	if c := f.connRow(t, f.connID); c.Approved != scopeD1 {
		t.Fatalf("not adopted: %+v", c)
	}
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)

	fresh := uuid.NewString()
	f.heartbeatWith(t, fresh, "ok", "ok") // contract 1 shaped first heartbeat
	if code := f.claimFrom(t, fresh); code != http.StatusNoContent {
		t.Fatalf("claim from a replica that sent no digest = %d; want 204", code)
	}
	if code := f.claimFrom(t, uuid.NewString()); code != http.StatusNoContent {
		t.Fatalf("claim from a replica id that never heartbeated = %d; want 204", code)
	}
	other := uuid.NewString()
	f.mustHB(t, f.gw, hbV2(other, scopeD2, false, ""))
	f.heartbeatWith(t, other, "ok", "ok") // the D2 replica goes contract 1 shaped
	if code := f.claimFrom(t, other); code != http.StatusNoContent {
		t.Fatalf("claim from the D2 replica after a contract 1 shaped heartbeat = %d; want 204", code)
	}
	f.retireReplicas(t, f.gw.GatewayID, fresh)
	if code := f.claimFrom(t, fresh); code != http.StatusNoContent {
		t.Fatalf("claim from a contract 1 only replica after the approved one left = %d; want 204", code)
	}
	f.mustHB(t, f.gw, hbV2(f.replica, scopeD1, false, ""))
	f.retireReplicas(t, f.gw.GatewayID, f.replica)
	if code := f.claimFrom(t, f.replica); code != http.StatusOK {
		t.Fatalf("claim from the replica at the approved digest = %d; want 200", code)
	}
}

// TestLive_GatewayDiscoveryReview_ApproveNeverClearsDigest: once a
// digest was approved, an empty approve body is refused even when no
// live replica reports a digest, and the approved digest is kept.
func TestLive_GatewayDiscoveryReview_ApproveNeverClearsDigest(t *testing.T) {
	f := newObsFixture(t)
	f.retireReplicas(t, f.gw.GatewayID)
	f.mustHB(t, f.gw, hbV2(f.replica, scopeD1, false, ""))
	f.mustHB(t, f.gw, hbV2(f.replica, scopeD2, false, "")) // scope_changed
	f.retireReplicas(t, f.gw.GatewayID)                    // no live digest at all
	if code, raw := f.approveScope(t, f.gw.GatewayID, f.connID, nil); code != http.StatusConflict || errCode(t, raw) != "scope_digest_changed" {
		t.Fatalf("empty approve after a digest was approved = %d %s; want 409 scope_digest_changed", code, raw)
	}
	if c := f.connRow(t, f.connID); c.Approved != scopeD1 || c.Status != "advertised" {
		t.Fatalf("connector = %+v; want the approved digest kept", c)
	}
	if r := f.bindingSuspended(t, f.bindingID); r != "scope_changed" {
		t.Fatalf("binding = %q; want still suspended", r)
	}
}

// TestLive_GatewayDiscoveryReview_ApproveNeedsUploadOfTheScope: with
// discovery on, approve must carry the scope digest of the latest
// accepted upload, so the admin approves the AppProjects the console
// shows. A live replica without a digest also blocks approval.
func TestLive_GatewayDiscoveryReview_ApproveNeedsUploadOfTheScope(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "rev-upload-gw")
	if code, raw := f.catalog(t, gw.GatewayID, gw.GatewaySecret, map[string]any{"connectors": []map[string]any{
		{"connector_id": "argocd-main", "kind": "argocd", "targets": []map[string]any{}},
	}}); code != http.StatusOK {
		t.Fatalf("catalog = %d %s", code, raw)
	}
	connID := f.connIDOf(t, gw.GatewayID, "argocd-main")
	team := uuid.New()
	ctx := t.Context()
	if _, err := f.l.pool.Exec(ctx, `INSERT INTO teams (id, name) VALUES ($1, $2)`, team, "rev-"+team.String()[:8]); err != nil {
		t.Fatal(err)
	}
	// An accepted upload of scope D1 with one AppProject, mapped.
	if _, err := f.l.pool.Exec(ctx, `UPDATE gateway_connectors SET discovery_allowed_projects = '["team-a-apps"]', discovery_scope_digest = $2
		WHERE id = $1`, connID, scopeD1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.pool.Exec(ctx, `INSERT INTO gateway_connector_project_teams (connector_id, app_project, team_id, approved_by, approved_at)
		VALUES ($1, 'team-a-apps', $2, 'test', now())`, connID, team); err != nil {
		t.Fatal(err)
	}
	replica := uuid.NewString()
	f.mustHB(t, gw, hbV2(replica, scopeD2, true, "")) // the replicas now report D2
	if code, raw := f.approveScope(t, gw.GatewayID, connID, map[string]any{"scope_digest": scopeD2}); code != http.StatusConflict ||
		errCode(t, raw) != "scope_digest_changed" {
		t.Fatalf("approve D2 with the console showing D1's upload = %d %s; want 409", code, raw)
	}
	if _, err := f.l.pool.Exec(ctx, `UPDATE gateway_connectors SET discovery_scope_digest = $2 WHERE id = $1`, connID, scopeD2); err != nil {
		t.Fatal(err)
	}
	f.heartbeatWith2(t, gw, uuid.NewString()) // a replica with no digest yet
	if code, raw := f.approveScope(t, gw.GatewayID, connID, map[string]any{"scope_digest": scopeD2}); code != http.StatusConflict {
		t.Fatalf("approve while a live replica sends no digest = %d %s; want 409", code, raw)
	}
	f.retireReplicas(t, gw.GatewayID, replica)
	if code, raw := f.approveScope(t, gw.GatewayID, connID, map[string]any{"scope_digest": scopeD2}); code != http.StatusOK {
		t.Fatalf("approve D2 with a D2 upload = %d %s", code, raw)
	}
}

func (f *gwFixture) heartbeatWith2(t *testing.T, gw gwEnrolled, replica string) {
	t.Helper()
	if code, raw := f.heartbeat(t, gw.GatewayID, gw.GatewaySecret, replica); code != http.StatusOK {
		t.Fatalf("heartbeat = %d %s", code, raw)
	}
}

// TestLive_GatewayDiscoveryReview_LeaseConditions: no lease while
// another live replica reports the connector over_privileged, none to a
// replica that is not ok or degraded, and the floor uses the reported
// interval.
func TestLive_GatewayDiscoveryReview_LeaseConditions(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "rev-lease-gw")
	if code, raw := f.catalog(t, gw.GatewayID, gw.GatewaySecret, map[string]any{"connectors": []map[string]any{
		{"connector_id": "argocd-main", "kind": "argocd", "targets": []map[string]any{}},
	}}); code != http.StatusOK {
		t.Fatalf("catalog = %d %s", code, raw)
	}
	d := struct {
		gw     gwEnrolled
		connID string
	}{gw, f.connIDOf(t, gw.GatewayID, "argocd-main")}
	f.retireReplicas(t, d.gw.GatewayID)
	ctx := t.Context()
	reset := func(since string) {
		t.Helper()
		if _, err := f.l.pool.Exec(ctx, `UPDATE gateway_connectors SET discovery_lease_id = NULL, discovery_lease_replica_id = NULL,
			discovery_lease_generation = NULL, discovery_lease_expires_at = NULL,
			last_lease_granted_at = now() - $2::interval, status_reason = NULL WHERE id = $1`, d.connID, since); err != nil {
			t.Fatal(err)
		}
	}
	// Another live replica reports the connector over_privileged.
	bad := hbV2(uuid.NewString(), scopeD1, true, "")
	bad["connectors"].([]map[string]any)[0]["status"] = "over_privileged"
	f.mustHB(t, d.gw, bad)
	if r := f.mustHB(t, d.gw, hbV2(uuid.NewString(), scopeD1, true, "")); len(r.DiscoveryLeases) != 0 {
		t.Fatalf("lease while a live replica reports over_privileged: %+v", r.DiscoveryLeases)
	}
	f.retireReplicas(t, d.gw.GatewayID)
	reset("1 hour")
	// A replica that is not ready.
	nr := hbV2(uuid.NewString(), scopeD1, true, "")
	nr["status"] = "not_ready"
	if r := f.mustHB(t, d.gw, nr); len(r.DiscoveryLeases) != 0 {
		t.Fatalf("lease to a not_ready replica: %+v", r.DiscoveryLeases)
	}
	f.retireReplicas(t, d.gw.GatewayID)
	// The reported interval (120s) is the floor, not 60s.
	reset("90 seconds")
	slow := hbV2(uuid.NewString(), scopeD1, true, "")
	slow["connectors"].([]map[string]any)[0]["discovery_interval_seconds"] = 120
	if r := f.mustHB(t, d.gw, slow); len(r.DiscoveryLeases) != 0 {
		t.Fatalf("lease 90s after the last grant with a 120s interval: %+v", r.DiscoveryLeases)
	}
	reset("121 seconds")
	if r := f.mustHB(t, d.gw, slow); len(r.DiscoveryLeases) != 1 {
		t.Fatalf("no lease 121s after the last grant with a 120s interval: %+v", r)
	}
}

// TestLive_GatewayDiscoveryReview_MismatchRequeuesAndSuspendedSkips: a
// mismatch between replicas moves a leased task back to queued and is
// audited; a suspended binding on an approved connector is not claimed.
func TestLive_GatewayDiscoveryReview_MismatchRequeuesAndSuspendedSkips(t *testing.T) {
	f := newObsFixture(t)
	f.retireReplicas(t, f.gw.GatewayID)
	f.mustHB(t, f.gw, hbV2(f.replica, scopeD1, false, ""))
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	if code := f.claimFrom(t, f.replica); code != http.StatusOK {
		t.Fatalf("claim = %d", code)
	}
	f.mustHB(t, f.gw, hbV2(uuid.NewString(), scopeD2, false, ""))
	if ts := f.taskRows(t, reqID); len(ts) != 1 || ts[0].State != "queued" {
		t.Fatalf("task after the mismatch = %+v; want queued", ts)
	}
	if rows := f.l.auditRows(t, "gateway.connector.scope_mismatch"); len(rows) != 1 || rows[0].Metadata["tasks_requeued"] != float64(1) {
		t.Fatalf("mismatch audit = %+v", rows)
	}
	f.retireReplicas(t, f.gw.GatewayID, f.replica)
	f.mustHB(t, f.gw, hbV2(f.replica, scopeD1, false, ""))
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE gateway_connector_bindings SET suspended_reason = 'mapping_removed', suspended_at = now() WHERE id = $1`, f.bindingID); err != nil {
		t.Fatal(err)
	}
	if code := f.claimFrom(t, f.replica); code != http.StatusNoContent {
		t.Fatalf("claim of a suspended binding's task on an approved connector = %d; want 204", code)
	}
}

// TestLive_GatewayDiscoveryReview_StaticIDInDiscoveredShape: E3 refuses
// a static target id in the discovered id shape.
func TestLive_GatewayDiscoveryReview_StaticIDInDiscoveredShape(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "rev-e3-gw")
	code, raw := f.catalog(t, gw.GatewayID, gw.GatewaySecret, map[string]any{"connectors": []map[string]any{
		{"connector_id": "argocd-main", "kind": "argocd", "targets": []map[string]any{{"target_id": "d-li3oyoq5xwjxe72ps7qqn5dikf"}}},
	}})
	if code != http.StatusBadRequest || errCode(t, raw) != "invalid_request" {
		t.Fatalf("static target in the discovered shape = %d %s; want 400", code, raw)
	}
}
