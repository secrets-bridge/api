package main

// The Gateway-reported identity change (api#314, secrets-bridge/
// gateway#25): an integrator who pins applications[].uid in the Gateway
// settings makes the Gateway compute its catalog identity from that
// uid, so a recreated Application never changes the advertised digest.
// The Gateway refuses the object and posts an error stage with
// error_code target_identity_changed instead, and the CP marks the
// target identity_changed from that stage.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// identityErrorResult is the error stage a Gateway posts when the
// Application's uid is not the settings uid.
func identityErrorResult(task *wireTask, gatewayID, replica string) map[string]any {
	res := argoResult(task, gatewayID, replica)
	st := stage0(res)
	st["outcome"], st["confidence"], st["error_code"] = "error", "none", "target_identity_changed"
	delete(st, "facts")
	delete(st, "resource")
	return res
}

// storedTrigger reads payments-api's stored identity_change_trigger.
func (f *obsFixture) storedTrigger(t *testing.T) string {
	t.Helper()
	var trigger string
	if err := f.l.pool.QueryRow(t.Context(), `
		SELECT COALESCE(e->>'identity_change_trigger', '')
		FROM gateway_connectors c, jsonb_array_elements(c.advertised_targets) e
		WHERE c.id = $1 AND e->>'target_id' = 'payments-api'`, f.connID).Scan(&trigger); err != nil {
		t.Fatalf("stored trigger: %v", err)
	}
	return trigger
}

// TestLive_GatewayIdentity_ReportedChangeSuspendsUntilReconfirmed: an
// accepted target_identity_changed error stage for a pinned target
// suspends its binding and audits once with trigger gateway_reported;
// further results for the target are refused and do not audit again;
// dispatch skips the binding and a new bind is refused; a re-confirm
// with the advertised identity still equal to the pin resumes it.
func TestLive_GatewayIdentity_ReportedChangeSuspendsUntilReconfirmed(t *testing.T) {
	f := newObsFixture(t)
	f.putCatalog(t, identityCatalog(identityA))

	// A second binding on the same target, and one task leased on each
	// binding while the target is still pinned.
	secret2 := f.addSecret(t, f.proj)
	code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, map[string]any{
		"gateway_id": f.gw.GatewayID, "environment_id": f.env.String(), "secret_id": secret2.String(),
		"argocd_connector_id": f.connID, "argocd_target_id": "payments-api",
	})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("second binding = %d %s", code, body)
	}
	code, first := f.claimTask(t)
	if code != http.StatusOK {
		t.Fatalf("first claim = %d; want 200", code)
	}
	req2, _ := f.executeOn(t, f.env, secret2)
	f.makeClaimable(t, req2)
	code, _, second, raw := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, uuid.NewString())
	if code != http.StatusOK {
		t.Fatalf("second claim = %d %s; want 200", code, raw)
	}

	firstResult := identityErrorResult(first, f.gw.GatewayID, f.replica)
	if code, body := f.post(t, first.TaskID, firstResult); code != http.StatusOK {
		t.Fatalf("target_identity_changed error stage = %d %s; want 200", code, body)
	}
	if d, s, a := f.storedTarget(t); d != identityA || s != "identity_changed" || a != identityA {
		t.Fatalf("after the reported change: pin %q status %q advertised %q; want %q identity_changed %q", d, s, a, identityA, identityA)
	}
	if tr := f.storedTrigger(t); tr != "gateway_reported" {
		t.Fatalf("trigger = %q; want gateway_reported", tr)
	}
	if status, suspended := f.adminTargetStatus(t); status != "identity_changed" || suspended != "identity_changed" {
		t.Fatalf("admin read = %q suspended %q; want identity_changed on both", status, suspended)
	}

	// The second leased task's error stage is refused: the target takes
	// no evidence now, and there is no second audit row.
	if code, body := f.post(t, second.TaskID, identityErrorResult(second, f.gw.GatewayID, f.replica)); code != http.StatusUnprocessableEntity ||
		errCode(t, body) != "target_identity_changed" {
		t.Fatalf("second error stage = %d %s; want 422 target_identity_changed", code, body)
	}
	// A replay of the accepted result is a duplicate, not a second report.
	if code, body := f.post(t, first.TaskID, firstResult); code != http.StatusOK || !strings.Contains(string(body), `"duplicate"`) {
		t.Fatalf("replayed error stage = %d %s; want 200 duplicate", code, body)
	}
	// The same catalog identity again changes nothing either.
	f.putCatalog(t, identityCatalog(identityA))
	if _, s, _ := f.storedTarget(t); s != "identity_changed" || f.storedTrigger(t) != "gateway_reported" {
		t.Fatalf("after the pinned identity again: status %q trigger %q; want identity_changed gateway_reported", s, f.storedTrigger(t))
	}

	rows := f.l.auditRows(t, "gateway.target.identity_changed")
	if len(rows) != 1 {
		t.Fatalf("identity_changed audits = %d; want exactly 1", len(rows))
	}
	m := rows[0].Metadata
	want := map[string]any{
		"gateway_id": f.gw.GatewayID, "connector_id": f.connID, "argocd_target_id": "payments-api",
		"identity_digest_before": identityA, "identity_digest_after": identityA, "bindings_suspended": float64(2),
		"trigger": "gateway_reported", "task_id": first.TaskID, "attempt_id": first.AttemptID,
	}
	if len(m) != len(want) {
		t.Fatalf("identity_changed metadata = %v; want exactly %v", m, want)
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("identity_changed metadata[%s] = %v; want %v (all: %v)", k, m[k], v, m)
		}
	}

	// No dispatch while suspended, and no new binding on the target.
	if code, _ := f.claimTask(t); code != http.StatusNoContent {
		t.Fatalf("claim on a suspended binding = %d; want 204", code)
	}
	other := f.addSecret(t, f.proj)
	code, body = f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, map[string]any{
		"gateway_id": f.gw.GatewayID, "environment_id": f.env.String(), "secret_id": other.String(),
		"argocd_connector_id": f.connID, "argocd_target_id": "payments-api",
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "target_identity_changed") {
		t.Fatalf("bind on a suspended target = %d %s; want 409 target_identity_changed", code, body)
	}

	// Re-confirm with the advertised identity still the pin: allowed for
	// a gateway_reported change, and the target is pinned again.
	code, body = f.l.callAs(t, http.MethodPost, f.confirmPath(), f.admin, nil)
	if code != http.StatusOK {
		t.Fatalf("re-confirm = %d %s; want 200", code, body)
	}
	if strings.Contains(string(body), identityA) {
		t.Fatalf("re-confirm response carries a digest: %s", body)
	}
	if d, s, _ := f.storedTarget(t); d != identityA || s != "pinned" || f.storedTrigger(t) != "" {
		t.Fatalf("after re-confirm: pin %q status %q trigger %q; want %q pinned, no trigger", d, s, f.storedTrigger(t), identityA)
	}
	confirmed := f.l.auditRowsWithStatus(t, "gateway.target.identity_confirmed")
	if len(confirmed) != 1 || confirmed[0].Status != "success" ||
		confirmed[0].Metadata["identity_digest_before"] != identityA || confirmed[0].Metadata["identity_digest_after"] != identityA ||
		confirmed[0].Metadata["bindings_resumed"] != float64(2) {
		t.Fatalf("identity_confirmed audits = %+v; want one success row from the pin to the pin", confirmed)
	}

	// Dispatch resumes and the pin is what evidence carries.
	code, _, task, raw := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, uuid.NewString())
	if code != http.StatusOK {
		t.Fatalf("claim after re-confirm = %d %s; want 200", code, raw)
	}
	if code, body := f.post(t, task.TaskID, withIdentity(argoResult(task, f.gw.GatewayID, f.replica), identityA)); code != http.StatusOK {
		t.Fatalf("evidence with the pin after re-confirm = %d %s; want 200", code, body)
	}

	// Re-confirming before the integrator fixed the settings uid: the
	// next error stage marks the target again, with one more audit row.
	code, task = f.claimTask(t)
	if code != http.StatusOK {
		t.Fatalf("claim = %d; want 200", code)
	}
	if code, body := f.post(t, task.TaskID, identityErrorResult(task, f.gw.GatewayID, f.replica)); code != http.StatusOK {
		t.Fatalf("error stage after re-confirm = %d %s; want 200", code, body)
	}
	if _, s, _ := f.storedTarget(t); s != "identity_changed" {
		t.Fatalf("status after a new error stage = %q; want identity_changed", s)
	}
	if rows := f.l.auditRows(t, "gateway.target.identity_changed"); len(rows) != 2 {
		t.Fatalf("identity_changed audits = %d; want 2", len(rows))
	}
}

// TestLive_GatewayIdentity_ReportedThenCatalogChange: the integrator
// fixes the settings uid after a reported change, so the catalog now
// advertises another identity. That is a catalog change (audited with
// trigger catalog) and the re-confirm pins the new identity.
func TestLive_GatewayIdentity_ReportedThenCatalogChange(t *testing.T) {
	f := newObsFixture(t)
	f.putCatalog(t, identityCatalog(identityA))
	_, task := f.claimTask(t)
	if code, body := f.post(t, task.TaskID, identityErrorResult(task, f.gw.GatewayID, f.replica)); code != http.StatusOK {
		t.Fatalf("error stage = %d %s; want 200", code, body)
	}
	f.putCatalog(t, identityCatalog(identityB))
	if d, s, a := f.storedTarget(t); d != identityA || s != "identity_changed" || a != identityB || f.storedTrigger(t) != "" {
		t.Fatalf("after the fixed settings uid: pin %q status %q advertised %q trigger %q; want %q identity_changed %q, no trigger",
			d, s, a, f.storedTrigger(t), identityA, identityB)
	}
	rows := f.l.auditRows(t, "gateway.target.identity_changed")
	if len(rows) != 2 || rows[0].Metadata["trigger"] != "gateway_reported" || rows[1].Metadata["trigger"] != "catalog" ||
		rows[1].Metadata["identity_digest_after"] != identityB {
		t.Fatalf("identity_changed audits = %+v; want gateway_reported then catalog", rows)
	}
	if code, body := f.l.callAs(t, http.MethodPost, f.confirmPath(), f.admin, nil); code != http.StatusOK {
		t.Fatalf("re-confirm = %d %s; want 200", code, body)
	}
	if d, s, _ := f.storedTarget(t); d != identityB || s != "pinned" {
		t.Fatalf("after re-confirm: pin %q status %q; want %q pinned", d, s, identityB)
	}
}

// TestLive_GatewayIdentity_CatalogRevertNotReconfirmable: for a catalog
// change, re-confirm needs an advertised identity other than the pin.
// The Gateway advertising the old pin again leaves nothing to confirm.
func TestLive_GatewayIdentity_CatalogRevertNotReconfirmable(t *testing.T) {
	f := newObsFixture(t)
	f.putCatalog(t, identityCatalog(identityA))
	f.putCatalog(t, identityCatalog(identityB))
	f.putCatalog(t, identityCatalog(identityA))
	if d, s, a := f.storedTarget(t); d != identityA || s != "identity_changed" || a != identityA {
		t.Fatalf("after A, B, A: pin %q status %q advertised %q; want %q identity_changed %q", d, s, a, identityA, identityA)
	}
	if code, body := f.l.callAs(t, http.MethodPost, f.confirmPath(), f.admin, nil); code != http.StatusConflict ||
		!strings.Contains(string(body), "target_identity_not_changed") {
		t.Fatalf("re-confirm of a catalog change back to the pin = %d %s; want 409 target_identity_not_changed", code, body)
	}
	if _, s, _ := f.storedTarget(t); s != "identity_changed" {
		t.Fatalf("status after a refused re-confirm = %q; want identity_changed", s)
	}
}

// TestLive_GatewayIdentity_ReportedOnUnpinnedTargetIsAnError: with no pin
// there is nothing to re-confirm, so the error stage is accepted as an
// error and the target is not marked.
func TestLive_GatewayIdentity_ReportedOnUnpinnedTargetIsAnError(t *testing.T) {
	f := newObsFixture(t)
	f.putCatalog(t, identityCatalog(""))
	_, task := f.claimTask(t)
	if code, body := f.post(t, task.TaskID, identityErrorResult(task, f.gw.GatewayID, f.replica)); code != http.StatusOK {
		t.Fatalf("error stage = %d %s; want 200", code, body)
	}
	if d, s, _ := f.storedTarget(t); d != "" || s != "" {
		t.Fatalf("unpinned target after the error stage: pin %q status %q; want none", d, s)
	}
	if rows := f.l.auditRows(t, "gateway.target.identity_changed"); len(rows) != 0 {
		t.Fatalf("identity_changed audits = %+v; want none", rows)
	}
}

// TestLive_GatewayIdentity_OtherErrorCodeDoesNotSuspend: only
// error_code target_identity_changed marks a pinned target; any other
// error stage is an ordinary error.
func TestLive_GatewayIdentity_OtherErrorCodeDoesNotSuspend(t *testing.T) {
	f := newObsFixture(t)
	f.putCatalog(t, identityCatalog(identityA))
	_, task := f.claimTask(t)
	res := identityErrorResult(task, f.gw.GatewayID, f.replica)
	stage0(res)["error_code"] = "connector_unreachable"
	if code, body := f.post(t, task.TaskID, res); code != http.StatusOK {
		t.Fatalf("error stage = %d %s; want 200", code, body)
	}
	if d, s, _ := f.storedTarget(t); d != identityA || s != "pinned" {
		t.Fatalf("after connector_unreachable: pin %q status %q; want %q pinned", d, s, identityA)
	}
	if rows := f.l.auditRows(t, "gateway.target.identity_changed"); len(rows) != 0 {
		t.Fatalf("identity_changed audits = %+v; want none", rows)
	}
}
