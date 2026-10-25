package handlers

// The gateway discovery contract response examples (vendored from
// gateway PR #32, testdata/gateway-contract/SOURCE.txt) against the
// api's response types (api#308). Each example is decoded strictly into
// the type the api encodes, so a field the contract has and the api does
// not (or the reverse) fails, then checked against the contract rules
// the schema states. A valid example also round-trips: re-encoding the
// decoded value gives the same JSON. The request examples run through
// the real router in cmd/api (gateway_contract_examples_live_test.go).

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

const contractExamplesDir = "testdata/gateway-contract/examples"

var (
	exLocalIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	exUUIDRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	exVersionRe = regexp.MustCompile(`^(sha256:[0-9a-f]{64})?$`)
)

func readContractExamples(t *testing.T, schema string) map[string][]byte {
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

// roundTrips reports whether v re-encodes to the same JSON as raw.
func roundTrips(t *testing.T, raw []byte, v any) bool {
	t.Helper()
	enc, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if json.Unmarshal(raw, &a) != nil || json.Unmarshal(enc, &b) != nil {
		return false
	}
	return reflect.DeepEqual(a, b)
}

// runContractExamples decodes every example of schema strictly into a
// fresh value from mk and applies check: valid examples must pass and
// round-trip, invalid ones must fail the decode or the check.
func runContractExamples[T any](t *testing.T, schema string, check func(*T) error) {
	t.Helper()
	for name, raw := range readContractExamples(t, schema) {
		v := new(T)
		err := decodeStrict(raw, v)
		if err == nil {
			err = check(v)
		}
		switch {
		case strings.HasPrefix(name, "valid-") || name == "valid.json":
			if err != nil {
				t.Errorf("%s/%s refused: %v", schema, name, err)
			} else if !roundTrips(t, raw, v) {
				t.Errorf("%s/%s does not round-trip through the api type", schema, name)
			}
		default:
			if err == nil {
				t.Errorf("%s/%s accepted; want it refused", schema, name)
			}
		}
	}
}

func checkHeartbeatResponse(r *gatewayHeartbeatResponse) error {
	if r.Status != "ok" || !exVersionRe.MatchString(r.CatalogVersion) || r.NextHeartbeatSeconds < 1 || r.ClaimPollSeconds < 1 {
		return errors.New("base fields")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.ServerTime); err != nil {
		return errors.New("server_time")
	}
	switch r.ContractVersion {
	case "1":
		if r.BoundTargetsVersion != nil || r.DiscoveryLeases != nil || r.SnapshotGenerations != nil || r.BoundTargets != nil {
			return errors.New("contract 2 field in a contract 1 answer")
		}
		return nil
	case "2":
	default:
		return errors.New("contract_version")
	}
	if r.BoundTargetsVersion == nil || !exVersionRe.MatchString(*r.BoundTargetsVersion) {
		return errors.New("bound_targets_version")
	}
	for _, l := range r.DiscoveryLeases {
		if !exLocalIDRe.MatchString(l.ConnectorID) || !exUUIDRe.MatchString(l.LeaseID) || l.Generation < 1 {
			return errors.New("lease")
		}
		if _, err := time.Parse(time.RFC3339, l.ExpiresAt); err != nil {
			return errors.New("lease expires_at")
		}
	}
	for _, g := range r.SnapshotGenerations {
		if !exLocalIDRe.MatchString(g.ConnectorID) || g.Generation < 1 {
			return errors.New("snapshot generation")
		}
	}
	if r.BoundTargets != nil {
		for _, b := range *r.BoundTargets {
			if !exLocalIDRe.MatchString(b.ConnectorName) {
				return errors.New("bound target connector")
			}
			for _, id := range b.TargetIDs {
				if !exLocalIDRe.MatchString(id) {
					return errors.New("bound target id")
				}
			}
		}
	}
	return nil
}

func TestContractExamples_HeartbeatResponse(t *testing.T) {
	runContractExamples(t, "gateway-heartbeat-response", checkHeartbeatResponse)
}

func TestContractExamples_DiscoveryResult(t *testing.T) {
	runContractExamples(t, "gateway-discovery-result", func(r *storage.DiscoveryResult) error {
		if (r.Status != "accepted" && r.Status != "duplicate") || r.Generation < 1 ||
			r.TargetsPresent < 0 || r.TargetsNew < 0 || r.TargetsMissing < 0 || r.TargetsRenamed < 0 {
			return errors.New("discovery result")
		}
		return nil
	})
}

var exWholeSecondRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
var exNonceRe = regexp.MustCompile(`^[A-Za-z0-9+/]{16}$`)
var exCipherRe = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

func TestContractExamples_DiscoverySnapshot(t *testing.T) {
	runContractExamples(t, "gateway-discovery-snapshot", func(r *gatewaySnapshotResponse) error {
		s := r.Snapshot
		if r.SchemaVersion != services.SnapshotSchemaVersion() || !exLocalIDRe.MatchString(r.ConnectorID) || r.Generation < 1 ||
			!exWholeSecondRe.MatchString(r.DiscoveredAt) || s.Alg != "A256GCM+HKDF-SHA256/v1" || !exNonceRe.MatchString(s.Nonce) ||
			len(s.Ciphertext) < 24 || !exCipherRe.MatchString(s.Ciphertext) {
			return errors.New("snapshot")
		}
		return nil
	})
}

// gatewayDiscoveryErrorCodes are the codes the E8 and E9 handlers send.
var gatewayDiscoveryErrorCodes = []string{
	"invalid_request", "unauthorized", "connector_not_found", "snapshot_not_found", "lease_not_held",
	"discovery_generation_stale", "scope_digest_mismatch", "catalog_too_large", "schema_violation",
}

func TestContractExamples_DiscoveryError(t *testing.T) {
	runContractExamples(t, "gateway-discovery-error", func(r *struct {
		Error string `json:"error"`
	}) error {
		if !slices.Contains(gatewayDiscoveryErrorCodes, r.Error) {
			return errors.New("error code")
		}
		return nil
	})
}
