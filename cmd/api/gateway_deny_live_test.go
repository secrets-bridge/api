package main

// Denied Gateway admin writes are audited (api#312, ADR 0002 section 5),
// through the real router against Postgres and Redis.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestLive_GatewayDeny_RefusedWritesAreAudited: a refused bind, approve,
// delete or re-confirm writes one denied row with an error kind and path
// ids only, never a target id, name or secret reference from the body.
func TestLive_GatewayDeny_RefusedWritesAreAudited(t *testing.T) {
	f := newObsFixture(t)
	nope := uuid.New()
	nopeHdr := map[string]string{"Cookie": f.l.sessionFor(t, nope, "gw-deny-"+nope.String()[:8]+"@example.com")}
	f.l.addGrant(t, nope.String(), []string{"gateway.list"}, `{}`)

	bindBody := map[string]any{
		"gateway_id": f.gw.GatewayID, "environment_id": f.env.String(), "secret_id": f.secret.String(),
		"argocd_connector_id": f.connID, "argocd_target_id": "orders-api",
	}
	calls := []struct {
		action, method, path string
		body                 any
		ids                  map[string]string
	}{
		{"gateway.binding.create", http.MethodPost, "/api/v1/admin/gateway-bindings", bindBody, map[string]string{}},
		{"gateway.connector.approved", http.MethodPost, "/api/v1/admin/gateways/" + f.gw.GatewayID + "/connectors/" + f.connID + "/approve", nil,
			map[string]string{"gateway_id": f.gw.GatewayID, "connector_id": f.connID}},
		{"gateway.binding.delete", http.MethodDelete, "/api/v1/admin/gateway-bindings/" + f.bindingID, nil, map[string]string{"binding_id": f.bindingID}},
		{"gateway.target.identity_confirmed", http.MethodPost, f.confirmPath(), nil,
			map[string]string{"gateway_id": f.gw.GatewayID, "connector_id": f.connID}},
	}
	for _, c := range calls {
		if code, raw := f.l.callAs(t, c.method, c.path, nopeHdr, c.body); code != http.StatusForbidden {
			t.Fatalf("%s without gateway.bind = %d %s; want 403", c.action, code, raw)
		}
		rows := f.l.auditRowsWithStatus(t, c.action)
		var denied []statusAuditRow
		for _, r := range rows {
			if r.Status == "denied" {
				denied = append(denied, r)
			}
		}
		if len(denied) != 1 {
			t.Fatalf("%s denied audits = %+v; want exactly 1", c.action, rows)
		}
		d := denied[0]
		if d.Actor != "user:"+nope.String() || d.Metadata["error_kind"] != "permission_denied" {
			t.Fatalf("%s denied audit = %+v; want the caller and error_kind permission_denied", c.action, d)
		}
		if len(d.Metadata) != len(c.ids)+1 {
			t.Fatalf("%s denied metadata = %v; want error_kind and %v only", c.action, d.Metadata, c.ids)
		}
		for k, v := range c.ids {
			if d.Metadata[k] != v {
				t.Fatalf("%s denied metadata[%s] = %v; want %s", c.action, k, d.Metadata[k], v)
			}
		}
	}

	// A rule refusal from the handler is audited too, with its code: the
	// target id the caller sent stays out of the row.
	bindBody["argocd_target_id"] = "not-advertised"
	if code, raw := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, bindBody); code != http.StatusBadRequest {
		t.Fatalf("bind on an unadvertised target = %d %s; want 400", code, raw)
	}
	rows := f.l.auditRowsWithStatus(t, "gateway.binding.create")
	last := rows[len(rows)-1]
	if last.Status != "denied" || last.Metadata["error_kind"] != "target_not_advertised" || last.Actor != "user:"+f.adminID.String() {
		t.Fatalf("rule refusal audit = %+v; want denied target_not_advertised by the admin", last)
	}
	var raw string
	if err := f.l.pool.QueryRow(t.Context(), `SELECT string_agg(metadata::text, ' ') FROM audit_events WHERE status = 'denied' AND action LIKE 'gateway.%'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"not-advertised", "orders-api", "payments-api", f.secret.String(), f.env.String()} {
		if strings.Contains(raw, leak) {
			t.Fatalf("denied gateway audit metadata carries %q: %s", leak, raw)
		}
	}
	// An allowed write is not audited as denied.
	before := len(f.l.auditRowsWithStatus(t, "gateway.binding.delete"))
	if code, raw := f.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+f.bindingID, f.admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", code, raw)
	}
	del := f.l.auditRowsWithStatus(t, "gateway.binding.delete")
	if len(del) != before+1 || del[len(del)-1].Status != "success" {
		t.Fatalf("delete audits = %+v; want one more, success", del)
	}
}
