package main

// The gateway discovery contract examples (vendored from gateway PR #32,
// see internal/handlers/testdata/gateway-contract/SOURCE.txt) against
// the api's request decoders, through the real router (api#308). A valid
// example passes the decoder; an invalid one is refused with the
// contract's code. The response examples are checked against the api's
// response types in internal/handlers.

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const contractExamplesDir = "../../internal/handlers/testdata/gateway-contract/examples"

// contractExamples returns name to raw body for one schema directory.
func contractExamples(t *testing.T, schema string) map[string][]byte {
	t.Helper()
	dir := filepath.Join(contractExamplesDir, schema)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	out := map[string][]byte{}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = raw
	}
	if len(out) == 0 {
		t.Fatalf("no examples in %s", dir)
	}
	return out
}

// TestLive_GatewayContractExamples_Heartbeat: every E2 request example.
// Valid examples are accepted (200); invalid ones get 400
// invalid_request, the code the strict decoder and the validation
// answer.
func TestLive_GatewayContractExamples_Heartbeat(t *testing.T) {
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "contract-hb-gw")
	hdr := map[string]string{"X-Gateway-Secret": gw.GatewaySecret, "Content-Type": "application/json"}
	for name, raw := range contractExamples(t, "gateway-heartbeat") {
		code, _, body := f.l.callRaw(t, http.MethodPost, "/api/v1/gateways/"+gw.GatewayID+"/heartbeat", hdr, raw)
		switch {
		case strings.HasPrefix(name, "valid-"):
			if code != http.StatusOK {
				t.Errorf("%s = %d %s; want 200", name, code, body)
			}
		default:
			if code != http.StatusBadRequest || errCode(t, body) != "invalid_request" {
				t.Errorf("%s = %d %s; want 400 invalid_request", name, code, body)
			}
		}
	}
}

// TestLive_GatewayContractExamples_DiscoveryCatalog: every E8 request
// example. A valid names-mode example passes parse and schema (it then
// stops at the lease check: no lease is held); an invalid one is 422
// schema_violation. valid-opaque.json is valid against the schema but
// refused with 422 until opaque mode ships (decision E-8).
func TestLive_GatewayContractExamples_DiscoveryCatalog(t *testing.T) {
	d := newDiscFixture(t, newGatewayFixture(t), "contract-e8-gw")
	for name, raw := range contractExamples(t, "gateway-discovery-catalog") {
		code, body := d.uploadRaw(t, "argocd-main", raw)
		switch name {
		case "valid-names.json":
			if code != http.StatusConflict || errCode(t, body) != "lease_not_held" {
				t.Errorf("%s = %d %s; want past the schema (409 lease_not_held)", name, code, body)
			}
		case "valid-opaque.json":
			if code != http.StatusUnprocessableEntity || errCode(t, body) != "schema_violation" {
				t.Errorf("%s = %d %s; want 422 until opaque mode ships", name, code, body)
			}
		default:
			if code != http.StatusUnprocessableEntity || errCode(t, body) != "schema_violation" {
				t.Errorf("%s = %d %s; want 422 schema_violation", name, code, body)
			}
		}
	}
}

// TestLive_GatewayContractExamples_ProjectTeamsPut: every A2 body
// example as a PUT. valid-put.json passes the decoder (its team ids do
// not exist here, so it stops at 404 team_not_found); the GET body
// (valid-get.json, with allowed_projects and complete) and every invalid
// example are refused with 400 invalid_request. The GET response type
// is checked in internal/handlers.
func TestLive_GatewayContractExamples_ProjectTeamsPut(t *testing.T) {
	c := newCatFixture(t)
	hdr := map[string]string{"Cookie": c.admin["Cookie"], "Content-Type": "application/json"}
	for name, raw := range contractExamples(t, "gateway-project-teams") {
		code, _, body := c.l.callRaw(t, http.MethodPut, "/api/v1/admin/gateways/"+c.gw.GatewayID+"/connectors/"+c.connID+"/project-teams", hdr, raw)
		switch name {
		case "valid-put.json":
			if code != http.StatusNotFound || !strings.Contains(string(body), "team_not_found") {
				t.Errorf("%s = %d %s; want past the decoder (404 team_not_found)", name, code, body)
			}
		default:
			if code != http.StatusBadRequest {
				t.Errorf("%s = %d %s; want 400", name, code, body)
			}
		}
	}
}
