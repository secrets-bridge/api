package main

// Guards on the confirm-identity route (api#312) that no other test
// pins: the route takes only a global gateway.bind grant, the connector
// is looked up under the Gateway in the path, and a target the Gateway
// stopped advertising cannot be re-confirmed (api#318).

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// identityChangedFixture is an obsFixture whose payments-api target is
// pinned to identityA and then advertised as identityB, so it is
// identity_changed and confirmable.
func identityChangedFixture(t *testing.T) *obsFixture {
	t.Helper()
	f := newObsFixture(t)
	f.putCatalog(t, identityCatalog(identityA))
	f.putCatalog(t, identityCatalog(identityB))
	if _, s, a := f.storedTarget(t); s != "identity_changed" || a != identityB {
		t.Fatalf("setup: status %q advertised %q; want identity_changed %q", s, a, identityB)
	}
	return f
}

// requireStillChanged fails unless payments-api is still identity_changed
// with the original pin, i.e. the refused re-confirm changed nothing.
func requireStillChanged(t *testing.T, f *obsFixture) {
	t.Helper()
	if d, s, _ := f.storedTarget(t); d != identityA || s != "identity_changed" {
		t.Fatalf("after a refused re-confirm: pin %q status %q; want %q identity_changed", d, s, identityA)
	}
	if rows := f.l.auditRowsWithStatus(t, "gateway.target.identity_confirmed"); len(rows) != 1 || rows[0].Status != "denied" {
		t.Fatalf("identity_confirmed audits = %+v; want one denied row", rows)
	}
}

// TestLive_GatewayIdentity_ConfirmNeedsAGlobalGrant: gateway.bind scoped
// to a team is not enough to re-confirm, even with a fresh second factor
// and an enrolled factor, so nothing but the grant scope stops the call.
func TestLive_GatewayIdentity_ConfirmNeedsAGlobalGrant(t *testing.T) {
	f := identityChangedFixture(t)
	scoped := uuid.New()
	hdr := map[string]string{"Cookie": f.l.sessionFor(t, scoped, "gw-scoped-"+scoped.String()[:8]+"@example.com")}
	f.l.addGrant(t, scoped.String(), gatewayAdminPerms, `{"team_id":"`+uuid.NewString()+`"}`)
	if _, err := f.l.pool.Exec(t.Context(), `
		INSERT INTO user_mfa_factors (user_id, kind, label, secret_ciphertext, secret_nonce, data_key_ciphertext, kms_key_id)
		VALUES ($1, 'totp', 'test', '\x00', '\x00', '\x00', 'test')`, scoped); err != nil {
		t.Fatal(err)
	}
	if code, body := f.l.callAs(t, http.MethodPost, f.confirmPath(), hdr, nil); code != http.StatusForbidden {
		t.Fatalf("re-confirm with a team-scoped gateway.bind = %d %s; want 403", code, body)
	}
	requireStillChanged(t, f)
}

// TestLive_GatewayIdentity_ConfirmIsScopedToThePathGateway: a connector
// id is only found under its own Gateway. Naming another Gateway in the
// path answers 404 and leaves the real target suspended.
func TestLive_GatewayIdentity_ConfirmIsScopedToThePathGateway(t *testing.T) {
	f := identityChangedFixture(t)
	other, _ := f.gatewayReady(t, "obs-gw-other")
	path := "/api/v1/admin/gateways/" + other.GatewayID + "/connectors/" + f.connID + "/targets/payments-api/confirm-identity"
	code, body := f.l.callAs(t, http.MethodPost, path, f.admin, nil)
	if code != http.StatusNotFound || !strings.Contains(string(body), "connector_not_found") {
		t.Fatalf("re-confirm under another Gateway = %d %s; want 404 connector_not_found", code, body)
	}
	requireStillChanged(t, f)
}

// TestLive_GatewayIdentity_ConfirmRefusesAStaleTarget: once the Gateway
// stops advertising the target, there is no current identity to accept,
// so the re-confirm answers 409 target_stale and the pin stays.
func TestLive_GatewayIdentity_ConfirmRefusesAStaleTarget(t *testing.T) {
	f := identityChangedFixture(t)
	body := obsCatalogBody()
	conn := body["connectors"].([]map[string]any)[0]
	conn["targets"] = conn["targets"].([]map[string]any)[1:] // drop payments-api
	f.putCatalog(t, body)
	code, raw := f.l.callAs(t, http.MethodPost, f.confirmPath(), f.admin, nil)
	if code != http.StatusConflict || !strings.Contains(string(raw), "target_stale") {
		t.Fatalf("re-confirm of a stale target = %d %s; want 409 target_stale", code, raw)
	}
	requireStillChanged(t, f)
}
