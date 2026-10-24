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
