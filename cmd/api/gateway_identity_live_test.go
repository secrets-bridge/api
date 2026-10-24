package main

// The control-plane identity pin of Argo CD targets (api#312, ADR 0002
// C3), driven through the real router against Postgres and Redis: the
// Gateway advertises an optional scoped identity digest per target in
// the E3 catalog, the CP pins the first one, a different one suspends
// the target's bindings (no dispatch, no evidence) until a platform
// admin re-confirms, and evidence for a pinned target must carry the
// pinned digest.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

var (
	identityA = "d-" + strings.Repeat("a", 26)
	identityB = "d-" + strings.Repeat("b", 26)
)

// identityCatalog is obsCatalogBody with an identity on payments-api ("" =
// none sent).
func identityCatalog(identity string) map[string]any {
	body := obsCatalogBody()
	target := body["connectors"].([]map[string]any)[0]["targets"].([]map[string]any)[0]
	if identity != "" {
		target["identity"] = identity
	}
	return body
}

func (f *obsFixture) putCatalog(t *testing.T, body map[string]any) {
	t.Helper()
	if code, raw := f.catalog(t, f.gw.GatewayID, f.gw.GatewaySecret, body); code != http.StatusOK {
		t.Fatalf("catalog = %d %s", code, raw)
	}
}

// storedTarget reads payments-api's stored identity fields.
func (f *obsFixture) storedTarget(t *testing.T) (digest, status, advertised string) {
	t.Helper()
	if err := f.l.pool.QueryRow(t.Context(), `
		SELECT COALESCE(e->>'identity_digest', ''), COALESCE(e->>'identity_status', ''), COALESCE(e->>'identity_advertised', '')
		FROM gateway_connectors c, jsonb_array_elements(c.advertised_targets) e
		WHERE c.id = $1 AND e->>'target_id' = 'payments-api'`, f.connID).Scan(&digest, &status, &advertised); err != nil {
		t.Fatalf("stored target: %v", err)
	}
	return digest, status, advertised
}

// adminTargetStatus reads payments-api's identity_status and the
// binding's suspended_reason from GET /admin/gateways/:id, and checks
// that no digest is in the body.
func (f *obsFixture) adminTargetStatus(t *testing.T) (status, suspended string) {
	t.Helper()
	code, body := f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+f.gw.GatewayID, f.admin, nil)
	if code != http.StatusOK {
		t.Fatalf("detail = %d %s", code, body)
	}
	if strings.Contains(string(body), identityA) || strings.Contains(string(body), identityB) || strings.Contains(string(body), "identity_digest") {
		t.Fatalf("admin read carries an identity digest: %s", body)
	}
	var d struct {
		Connectors []struct {
			Targets []struct {
				TargetID       string `json:"target_id"`
				IdentityStatus string `json:"identity_status"`
			} `json:"targets"`
		} `json:"connectors"`
		Bindings []struct {
			ID              string `json:"id"`
			SuspendedReason string `json:"suspended_reason"`
		} `json:"bindings"`
	}
	mustJSON(t, body, &d)
	for _, tg := range d.Connectors[0].Targets {
		if tg.TargetID == "payments-api" {
			status = tg.IdentityStatus
		}
	}
	for _, b := range d.Bindings {
		if b.ID == f.bindingID {
			suspended = b.SuspendedReason
		}
	}
	return status, suspended
}

func (f *obsFixture) confirmPath() string {
	return "/api/v1/admin/gateways/" + f.gw.GatewayID + "/connectors/" + f.connID + "/targets/payments-api/confirm-identity"
}

// claimTask executes a request on the fixture binding and claims its
// task with a fresh replica. Returns the claim status and the task.
func (f *obsFixture) claimTask(t *testing.T) (int, *wireTask) {
	t.Helper()
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	code, _, w, _ := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, uuid.NewString())
	return code, w
}

func withIdentity(res map[string]any, identity string) map[string]any {
	if identity != "" {
		stage0(res)["resource"].(map[string]any)["identity_digest"] = identity
	}
	return res
}

type statusAuditRow struct {
	Actor    string
	Status   string
	Metadata map[string]any
}

func (l *liveApp) auditRowsWithStatus(t *testing.T, action string) []statusAuditRow {
	t.Helper()
	rows, err := l.pool.Query(t.Context(),
		`SELECT actor, status, metadata FROM audit_events WHERE action = $1 ORDER BY occurred_at`, action)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []statusAuditRow
	for rows.Next() {
		var r statusAuditRow
		var meta []byte
		if err := rows.Scan(&r.Actor, &r.Status, &meta); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		_ = json.Unmarshal(meta, &r.Metadata)
		out = append(out, r)
	}
	return out
}

// requireOneSuccessAudit is requireOneAudit over the success rows only:
// a refused write of the same action is audited as denied (api#312).
func (l *liveApp) requireOneSuccessAudit(t *testing.T, action, actorUserID string) {
	t.Helper()
	var ok []statusAuditRow
	for _, r := range l.auditRowsWithStatus(t, action) {
		if r.Status == "success" {
			ok = append(ok, r)
		}
	}
	if len(ok) != 1 || ok[0].Actor != "user:"+actorUserID {
		t.Fatalf("audit %q success rows = %+v; want exactly 1 by user:%s", action, ok, actorUserID)
	}
}

// TestLive_GatewayIdentity_FirstPinSameAgainAbsentKeeps: the first
// identity is pinned, the same one again changes nothing, and a catalog
// without it (a Gateway that predates the field, or one that has not
// learned the uid) never clears the pin.
func TestLive_GatewayIdentity_FirstPinSameAgainAbsentKeeps(t *testing.T) {
	f := newObsFixture(t)
	if status, _ := f.adminTargetStatus(t); status != "unpinned" {
		t.Fatalf("identity_status before any identity = %q; want unpinned", status)
	}

	f.putCatalog(t, identityCatalog(identityA))
	if d, s, _ := f.storedTarget(t); d != identityA || s != "pinned" {
		t.Fatalf("after the first identity: pin %q status %q; want %q pinned", d, s, identityA)
	}
	if status, suspended := f.adminTargetStatus(t); status != "pinned" || suspended != "" {
		t.Fatalf("admin read = %q suspended %q; want pinned, not suspended", status, suspended)
	}

	f.putCatalog(t, identityCatalog(identityA))
	f.putCatalog(t, identityCatalog(""))
	if d, s, _ := f.storedTarget(t); d != identityA || s != "pinned" {
		t.Fatalf("after the same identity and an absent one: pin %q status %q; want %q pinned", d, s, identityA)
	}
	if rows := f.l.auditRows(t, "gateway.target.identity_changed"); len(rows) != 0 {
		t.Fatalf("identity_changed audits = %+v; want none", rows)
	}
	// Still dispatched and the pinned digest is accepted.
	code, task := f.claimTask(t)
	if code != http.StatusOK {
		t.Fatalf("claim on a pinned target = %d; want 200", code)
	}
	if code, body := f.post(t, task.TaskID, withIdentity(argoResult(task, f.gw.GatewayID, f.replica), identityA)); code != http.StatusOK {
		t.Fatalf("evidence with the pinned digest = %d %s; want 200", code, body)
	}
}

// TestLive_GatewayIdentity_ChangeSuspendsUntilReconfirmed: a different
// identity suspends the binding and audits once with ids and digests
// only; dispatch skips the binding; a re-confirm without a fresh second
// factor is refused; a re-confirm with one resumes it.
func TestLive_GatewayIdentity_ChangeSuspendsUntilReconfirmed(t *testing.T) {
	f := newObsFixture(t)
	f.putCatalog(t, identityCatalog(identityA))
	f.putCatalog(t, identityCatalog(identityB))
	f.putCatalog(t, identityCatalog(identityB)) // same new identity: no second audit
	f.putCatalog(t, identityCatalog(""))        // absent: still suspended

	if d, s, a := f.storedTarget(t); d != identityA || s != "identity_changed" || a != identityB {
		t.Fatalf("after a new identity: pin %q status %q advertised %q; want %q identity_changed %q", d, s, a, identityA, identityB)
	}
	if status, suspended := f.adminTargetStatus(t); status != "identity_changed" || suspended != "identity_changed" {
		t.Fatalf("admin read = %q suspended %q; want identity_changed on both", status, suspended)
	}
	rows := f.l.auditRows(t, "gateway.target.identity_changed")
	if len(rows) != 1 {
		t.Fatalf("identity_changed audits = %d; want exactly 1", len(rows))
	}
	m := rows[0].Metadata
	want := map[string]any{
		"gateway_id": f.gw.GatewayID, "connector_id": f.connID, "argocd_target_id": "payments-api",
		"identity_digest_before": identityA, "identity_digest_after": identityB, "bindings_suspended": float64(1),
		"trigger": "catalog",
	}
	if len(m) != len(want) {
		t.Fatalf("identity_changed metadata = %v; want exactly %v", m, want)
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("identity_changed metadata[%s] = %v; want %v (all: %v)", k, m[k], v, m)
		}
	}

	// No dispatch while suspended.
	if code, _ := f.claimTask(t); code != http.StatusNoContent {
		t.Fatalf("claim on a suspended binding = %d; want 204", code)
	}
	// A new binding on the suspended target is refused.
	other := f.addSecret(t, f.proj)
	code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, map[string]any{
		"gateway_id": f.gw.GatewayID, "environment_id": f.env.String(), "secret_id": other.String(),
		"argocd_connector_id": f.connID, "argocd_target_id": "payments-api",
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "target_identity_changed") {
		t.Fatalf("bind on a suspended target = %d %s; want 409 target_identity_changed", code, body)
	}

	// Re-confirm with a stale second factor: 401 step-up, still suspended.
	stale := uuid.New()
	staleHdr := map[string]string{"Cookie": f.l.sessionFor(t, stale, "gw-stale-"+stale.String()[:8]+"@example.com")}
	f.l.addGrant(t, stale.String(), gatewayAdminPerms, `{}`)
	if _, err := f.l.pool.Exec(t.Context(), `
		INSERT INTO user_mfa_factors (user_id, kind, label, secret_ciphertext, secret_nonce, data_key_ciphertext, kms_key_id)
		VALUES ($1, 'totp', 'test', '\x00', '\x00', '\x00', 'test')`, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE sessions SET last_mfa_at = now() - interval '2 hours' WHERE user_id = $1`, stale); err != nil {
		t.Fatal(err)
	}
	if code, body := f.l.callAs(t, http.MethodPost, f.confirmPath(), staleHdr, nil); code != http.StatusUnauthorized || !strings.Contains(string(body), "step_up_required") {
		t.Fatalf("re-confirm with a stale second factor = %d %s; want 401 step_up_required", code, body)
	}
	// Without gateway.bind: 403.
	nope := uuid.New()
	nopeHdr := map[string]string{"Cookie": f.l.sessionFor(t, nope, "gw-nope-"+nope.String()[:8]+"@example.com")}
	f.l.addGrant(t, nope.String(), []string{"gateway.list"}, `{}`)
	if code, body := f.l.callAs(t, http.MethodPost, f.confirmPath(), nopeHdr, nil); code != http.StatusForbidden {
		t.Fatalf("re-confirm without gateway.bind = %d %s; want 403", code, body)
	}
	if _, s, _ := f.storedTarget(t); s != "identity_changed" {
		t.Fatalf("status after refused re-confirms = %q; want identity_changed", s)
	}
	if rows := f.l.auditRowsWithStatus(t, "gateway.target.identity_confirmed"); len(rows) != 2 ||
		rows[0].Status != "denied" || rows[1].Status != "denied" {
		t.Fatalf("identity_confirmed audits after two refusals = %+v; want two denied rows", rows)
	}

	// Re-confirm by a platform admin with a fresh second factor.
	code, body = f.l.callAs(t, http.MethodPost, f.confirmPath(), f.admin, nil)
	if code != http.StatusOK {
		t.Fatalf("re-confirm = %d %s; want 200", code, body)
	}
	if strings.Contains(string(body), identityA) || strings.Contains(string(body), identityB) {
		t.Fatalf("re-confirm response carries a digest: %s", body)
	}
	if d, s, _ := f.storedTarget(t); d != identityB || s != "pinned" {
		t.Fatalf("after re-confirm: pin %q status %q; want %q pinned", d, s, identityB)
	}
	confirmed := f.l.auditRowsWithStatus(t, "gateway.target.identity_confirmed")
	last := confirmed[len(confirmed)-1]
	if last.Status != "success" || last.Actor != "user:"+f.adminID.String() ||
		last.Metadata["identity_digest_before"] != identityA || last.Metadata["identity_digest_after"] != identityB ||
		last.Metadata["bindings_resumed"] != float64(1) || last.Metadata["argocd_target_id"] != "payments-api" {
		t.Fatalf("identity_confirmed audit = %+v", last)
	}
	// A second re-confirm has nothing to confirm.
	if code, body := f.l.callAs(t, http.MethodPost, f.confirmPath(), f.admin, nil); code != http.StatusConflict ||
		!strings.Contains(string(body), "target_identity_not_changed") {
		t.Fatalf("re-confirm of a pinned target = %d %s; want 409 target_identity_not_changed", code, body)
	}

	// Dispatch resumes (the task queued while suspended is claimable now),
	// and the new pin is what evidence must carry.
	code, _, task, raw := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, uuid.NewString())
	if code != http.StatusOK {
		t.Fatalf("claim after re-confirm = %d %s; want 200", code, raw)
	}
	if code, body := f.post(t, task.TaskID, withIdentity(argoResult(task, f.gw.GatewayID, f.replica), identityA)); code != http.StatusUnprocessableEntity ||
		errCode(t, body) != "identity_digest_mismatch" {
		t.Fatalf("evidence with the old digest after re-confirm = %d %s; want 422 identity_digest_mismatch", code, body)
	}
	if code, body := f.post(t, task.TaskID, withIdentity(argoResult(task, f.gw.GatewayID, f.replica), identityB)); code != http.StatusOK {
		t.Fatalf("evidence with the new pin = %d %s; want 200", code, body)
	}
}

// TestLive_GatewayIdentity_EvidenceMustCarryThePin: for a pinned target,
// evidence with no digest or another digest is refused with a typed
// reason and audited; the pinned digest is accepted. A target that goes
// identity_changed while its task is leased refuses that task's
// evidence.
func TestLive_GatewayIdentity_EvidenceMustCarryThePin(t *testing.T) {
	f := newObsFixture(t)
	f.putCatalog(t, identityCatalog(identityA))
	code, task := f.claimTask(t)
	if code != http.StatusOK {
		t.Fatalf("claim = %d", code)
	}
	if code, body := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusUnprocessableEntity ||
		errCode(t, body) != "identity_digest_missing" {
		t.Fatalf("evidence without a digest = %d %s; want 422 identity_digest_missing", code, body)
	}
	if code, body := f.post(t, task.TaskID, withIdentity(argoResult(task, f.gw.GatewayID, f.replica), identityB)); code != http.StatusUnprocessableEntity ||
		errCode(t, body) != "identity_digest_mismatch" {
		t.Fatalf("evidence with another digest = %d %s; want 422 identity_digest_mismatch", code, body)
	}
	if n := f.evidenceCount(t); n != 0 {
		t.Fatalf("evidence rows after refused results = %d; want 0", n)
	}
	reasons := map[string]int{}
	for _, r := range f.l.auditRows(t, "observation.evidence.rejected") {
		reasons[r.Metadata["reason"].(string)]++
	}
	if reasons["identity_digest_missing"] != 1 || reasons["identity_digest_mismatch"] != 1 {
		t.Fatalf("rejection reasons = %v; want one identity_digest_missing and one identity_digest_mismatch", reasons)
	}

	// The target goes identity_changed while the task is leased: even the
	// pinned digest is refused now.
	f.putCatalog(t, identityCatalog(identityB))
	if code, body := f.post(t, task.TaskID, withIdentity(argoResult(task, f.gw.GatewayID, f.replica), identityA)); code != http.StatusUnprocessableEntity ||
		errCode(t, body) != "target_identity_changed" {
		t.Fatalf("evidence for a suspended target = %d %s; want 422 target_identity_changed", code, body)
	}
	if n := f.evidenceCount(t); n != 0 {
		t.Fatalf("evidence rows = %d; want 0", n)
	}
}

// TestLive_GatewayIdentity_LegacyGatewayStillWorks: a Gateway that sends
// no identity in the catalog and no digest in evidence (one that
// predates api#312) keeps working: no pin, evidence accepted.
func TestLive_GatewayIdentity_LegacyGatewayStillWorks(t *testing.T) {
	f := newObsFixture(t)
	f.putCatalog(t, identityCatalog(""))
	if d, s, _ := f.storedTarget(t); d != "" || s != "" {
		t.Fatalf("pin %q status %q without an identity; want none", d, s)
	}
	code, task := f.claimTask(t)
	if code != http.StatusOK {
		t.Fatalf("claim = %d", code)
	}
	if code, body := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusOK {
		t.Fatalf("evidence without a digest for an unpinned target = %d %s; want 200", code, body)
	}
}

// TestLive_GatewayIdentity_CatalogFieldIsClosed: identity must match the
// digest pattern, is refused on a Kubernetes connector, and an empty
// string is not "absent".
func TestLive_GatewayIdentity_CatalogFieldIsClosed(t *testing.T) {
	f := newObsFixture(t)
	bad := []map[string]any{
		identityCatalog("d-UPPER" + strings.Repeat("a", 21)),
		identityCatalog("d-" + strings.Repeat("a", 25)),
		identityCatalog("0123456789abcdef0123456789ab"),
	}
	empty := identityCatalog("")
	empty["connectors"].([]map[string]any)[0]["targets"].([]map[string]any)[0]["identity"] = ""
	bad = append(bad, empty)
	eso := map[string]any{"connectors": []map[string]any{{
		"connector_id": "eso-main", "kind": "eso",
		"targets": []map[string]any{{"target_id": "db-creds", "namespace": "payments", "name": "db-creds", "identity": identityA}},
	}}}
	bad = append(bad, eso)
	for i, b := range bad {
		if code, raw := f.catalog(t, f.gw.GatewayID, f.gw.GatewaySecret, b); code != http.StatusBadRequest || errCode(t, raw) != "invalid_request" {
			t.Errorf("bad catalog %d = %d %s; want 400 invalid_request", i, code, raw)
		}
	}
	if d, _, _ := f.storedTarget(t); d != "" {
		t.Fatalf("a refused catalog set a pin %q", d)
	}
}
