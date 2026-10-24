package main

// Dispatch pause on over_privileged (api#312, ADR 0002 C2), through the
// real router against Postgres and Redis.

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func (f *obsFixture) heartbeatWith(t *testing.T, replica, status, connStatus string) {
	t.Helper()
	body := gwHeartbeatBody(replica)
	body["status"] = status
	body["connectors"] = []map[string]string{{"connector_id": "argocd-main", "kind": "argocd", "status": connStatus}}
	if code, raw := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+f.gw.GatewayID+"/heartbeat", f.gwHdr, body); code != http.StatusOK {
		t.Fatalf("heartbeat %s/%s = %d %s", status, connStatus, code, raw)
	}
}

func (f *obsFixture) claimCode(t *testing.T) int {
	t.Helper()
	code, _, _, _ := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, uuid.NewString())
	return code
}

// TestLive_GatewayPause_OverPrivilegedStopsDispatch: one Gateway replica
// reporting its Argo CD connector over_privileged stops every claim of
// that connector's tasks, from any replica. Since api#308 (review on
// #317, ADR 0002 C2) the pause latches: the connector goes back to
// advertised with status_reason over_privileged, a healthy heartbeat
// does not lift it, and a platform admin re-approves only once no live
// replica reports it any more. A replica-level over_privileged does the
// same. degraded is an accepted connector status and does not pause.
func TestLive_GatewayPause_OverPrivilegedStopsDispatch(t *testing.T) {
	f := newObsFixture(t)
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	approve := func() (int, []byte) {
		return f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+f.gw.GatewayID+"/connectors/"+f.connID+"/approve", f.admin, nil)
	}

	reporter := uuid.NewString()
	f.heartbeatWith(t, reporter, "ok", "over_privileged")
	for i := 0; i < 3; i++ { // three other replicas, as many api calls
		if code := f.claimCode(t); code != http.StatusNoContent {
			t.Fatalf("claim %d while argocd-main is over_privileged = %d; want 204", i, code)
		}
	}
	if c := f.connRow(t, f.connID); c.Status != "advertised" || c.Reason != "over_privileged" {
		t.Fatalf("connector after over_privileged = %+v; want advertised, over_privileged", c)
	}
	if code, raw := approve(); code != http.StatusConflict || errCode(t, raw) != "connector_over_privileged" {
		t.Fatalf("approve while a replica reports over_privileged = %d %s; want 409", code, raw)
	}
	// The read probe's degraded is accepted and lifts nothing by itself.
	f.heartbeatWith(t, reporter, "degraded", "degraded")
	if code := f.claimCode(t); code != http.StatusNoContent {
		t.Fatalf("claim after a degraded heartbeat, before re-approval = %d; want 204", code)
	}
	if code, raw := approve(); code != http.StatusOK {
		t.Fatalf("re-approve after a passing probe = %d %s", code, raw)
	}
	if code := f.claimCode(t); code != http.StatusOK {
		t.Fatalf("claim after re-approval = %d; want 200", code)
	}
	if n := len(f.l.auditRows(t, "gateway.connector.approval_reset")); n != 1 {
		t.Fatalf("approval_reset audits = %d; want 1", n)
	}

	// Replica-level over_privileged with the connector itself ok.
	req2, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, req2)
	f.heartbeatWith(t, reporter, "over_privileged", "ok")
	if code := f.claimCode(t); code != http.StatusNoContent {
		t.Fatalf("claim while a replica is over_privileged = %d; want 204", code)
	}
	f.heartbeatWith(t, reporter, "ok", "ok")
	if code := f.claimCode(t); code != http.StatusNoContent {
		t.Fatalf("claim after the healthy heartbeat, before re-approval = %d; want 204", code)
	}
	if code, raw := approve(); code != http.StatusOK {
		t.Fatalf("re-approve = %d %s", code, raw)
	}
	if code := f.claimCode(t); code != http.StatusOK {
		t.Fatalf("claim after re-approval = %d; want 200", code)
	}

	// A replica that left the replica window no longer blocks the
	// re-approval (it is not a live replica); the latch still needs it.
	req3, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, req3)
	gone := uuid.NewString()
	f.heartbeatWith(t, gone, "ok", "over_privileged")
	if code := f.claimCode(t); code != http.StatusNoContent {
		t.Fatalf("claim with a live over_privileged replica = %d; want 204", code)
	}
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE gateway_replicas SET last_seen_at = now() - interval '11 minutes' WHERE replica_id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	if code := f.claimCode(t); code != http.StatusNoContent {
		t.Fatalf("claim after the reporting replica left the window, before re-approval = %d; want 204", code)
	}
	if code, raw := approve(); code != http.StatusOK {
		t.Fatalf("re-approve once the reporter left the window = %d %s", code, raw)
	}
	if code := f.claimCode(t); code != http.StatusOK {
		t.Fatalf("claim after re-approval = %d; want 200", code)
	}
}
