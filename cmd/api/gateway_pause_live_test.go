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
// that connector's tasks, from any replica, until that replica reports
// the connector healthy again. A replica-level over_privileged does the
// same. degraded is an accepted connector status and does not pause.
func TestLive_GatewayPause_OverPrivilegedStopsDispatch(t *testing.T) {
	f := newObsFixture(t)
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)

	reporter := uuid.NewString()
	f.heartbeatWith(t, reporter, "ok", "over_privileged")
	for i := 0; i < 3; i++ { // three other replicas, as many api calls
		if code := f.claimCode(t); code != http.StatusNoContent {
			t.Fatalf("claim %d while argocd-main is over_privileged = %d; want 204", i, code)
		}
	}
	// The read probe's degraded is accepted and is not a pause.
	f.heartbeatWith(t, reporter, "degraded", "degraded")
	if code := f.claimCode(t); code != http.StatusOK {
		t.Fatalf("claim after a degraded heartbeat = %d; want 200", code)
	}

	// Replica-level over_privileged with the connector itself ok.
	req2, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, req2)
	f.heartbeatWith(t, reporter, "over_privileged", "ok")
	if code := f.claimCode(t); code != http.StatusNoContent {
		t.Fatalf("claim while a replica is over_privileged = %d; want 204", code)
	}
	f.heartbeatWith(t, reporter, "ok", "ok")
	if code := f.claimCode(t); code != http.StatusOK {
		t.Fatalf("claim after the healthy heartbeat = %d; want 200", code)
	}

	// A report from a replica that left the replica window no longer
	// pauses (it is not a live replica).
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
	if code := f.claimCode(t); code != http.StatusOK {
		t.Fatalf("claim after the reporting replica left the window = %d; want 200", code)
	}
}
