package main

// E8 discovery upload and E9 snapshot fetch (api#308, ADR 0002 S4;
// gateway docs/design/discovery-contract.md sections 3 and 4), through
// the real router against Postgres and Redis.

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
)

const testEndpointDigest = "sha256:9508006565bb8a9beb9bb68e3984a5350e7e0320f55945cad5aeddbdd71115ce"

var testAllowedProjects = []string{"team-a-apps", "team-b-apps"}

// testScope is the scope digest of testEndpointDigest and
// testAllowedProjects, discovery on, names mode.
func testScope() string {
	return services.GatewayScopeDigest(testEndpointDigest, testAllowedProjects, true, "names")
}

// discTargetID derives a stable d- id for test entry i (not a real
// uid derivation; the CP only checks the pattern).
func discTargetID(i int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("target-%d", i)))
	return "d-" + strings.ToLower(base32.StdEncoding.EncodeToString(sum[:]))[:26]
}

type discEntry struct {
	TargetID   string `json:"target_id"`
	AppProject string `json:"app_project"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

// discEntries returns n entries in team-a-apps, sorted by target id.
func discEntries(n int) []discEntry {
	out := make([]discEntry, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, discEntry{TargetID: discTargetID(i), AppProject: "team-a-apps", Namespace: "argocd", Name: fmt.Sprintf("app-%d", i)})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].TargetID < out[b].TargetID })
	return out
}

type discLease struct {
	replica, lease string
	generation     int64
}

func uploadBody(l discLease, entries []discEntry) map[string]any {
	return map[string]any{
		"schema_version": "gateway.discovery-catalog/v1",
		"replica_id":     l.replica, "lease_id": l.lease, "generation": l.generation,
		"discovered_at": "2026-10-24T12:00:00Z", "scope_digest": testScope(), "endpoint_digest": testEndpointDigest,
		"identity_mode": "names", "allowed_projects": testAllowedProjects, "entries": entries,
		"entries_rejected": 1, "entries_deferred": 0,
		"snapshot": map[string]any{
			"alg": "A256GCM+HKDF-SHA256/v1", "nonce": "oKGio6Slpqeoqaqr",
			"ciphertext": base64.StdEncoding.EncodeToString([]byte("opaque sealed bytes the control plane cannot open " + l.lease)),
		},
	}
}

type discFixture struct {
	*gwFixture
	gw     gwEnrolled
	hdr    map[string]string
	connID string
}

// newDiscFixture is an enrolled Gateway whose E3 catalog has argocd-main
// with no static targets.
func newDiscFixture(t *testing.T, f *gwFixture, name string) *discFixture {
	t.Helper()
	gw := f.enrolled(t, name)
	if code, raw := f.catalog(t, gw.GatewayID, gw.GatewaySecret, map[string]any{"connectors": []map[string]any{
		{"connector_id": "argocd-main", "kind": "argocd", "targets": []map[string]any{}},
	}}); code != http.StatusOK {
		t.Fatalf("catalog = %d %s", code, raw)
	}
	return &discFixture{gwFixture: f, gw: gw, hdr: map[string]string{"X-Gateway-Secret": gw.GatewaySecret},
		connID: f.connIDOf(t, gw.GatewayID, "argocd-main")}
}

// lease heartbeats as a fresh replica with discovery on and returns the
// lease it got. It first lets any previous lease lapse past the floor.
func (d *discFixture) lease(t *testing.T) discLease {
	t.Helper()
	if _, err := d.l.pool.Exec(t.Context(), `UPDATE gateway_connectors SET discovery_lease_id = NULL, discovery_lease_replica_id = NULL,
		discovery_lease_generation = NULL, discovery_lease_expires_at = NULL, last_lease_granted_at = now() - interval '1 hour' WHERE id = $1`, d.connID); err != nil {
		t.Fatal(err)
	}
	replica := uuid.NewString()
	r := d.mustHB(t, d.gw, hbV2(replica, testScope(), true, ""))
	if len(r.DiscoveryLeases) != 1 {
		t.Fatalf("no lease: %+v", r)
	}
	return discLease{replica: replica, lease: r.DiscoveryLeases[0].LeaseID, generation: r.DiscoveryLeases[0].Generation}
}

func (d *discFixture) upload(t *testing.T, connector string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return d.uploadRaw(t, connector, raw)
}

func (d *discFixture) uploadRaw(t *testing.T, connector string, raw []byte) (int, []byte) {
	t.Helper()
	code, _, out := d.l.callRaw(t, http.MethodPut, "/api/v1/gateways/"+d.gw.GatewayID+"/connectors/"+connector+"/discovery", d.hdr, raw)
	return code, out
}

func (d *discFixture) snapshot(t *testing.T, connector string) (int, []byte) {
	t.Helper()
	code, _, out := d.l.callRaw(t, http.MethodGet, "/api/v1/gateways/"+d.gw.GatewayID+"/connectors/"+connector+"/snapshot", d.hdr, nil)
	return code, out
}

type discResult struct {
	Status         string `json:"status"`
	Generation     int64  `json:"generation"`
	TargetsPresent int    `json:"targets_present"`
	TargetsNew     int    `json:"targets_new"`
	TargetsMissing int    `json:"targets_missing"`
	TargetsRenamed int    `json:"targets_renamed"`
}

func (d *discFixture) mustUpload(t *testing.T, body any) discResult {
	t.Helper()
	code, raw := d.upload(t, "argocd-main", body)
	if code != http.StatusOK {
		t.Fatalf("upload = %d %s", code, raw)
	}
	var r discResult
	mustJSON(t, raw, &r)
	return r
}

// TestLive_GatewayDiscoveryUpload_AcceptRetryAndSnapshot: the lease
// holder's upload is accepted; the same bytes again answer duplicate and
// change nothing; E9 returns the sealed snapshot exactly as uploaded;
// the next heartbeat names its generation.
func TestLive_GatewayDiscoveryUpload_AcceptRetryAndSnapshot(t *testing.T) {
	d := newDiscFixture(t, newGatewayFixture(t), "disc-accept-gw")
	if code, raw := d.snapshot(t, "argocd-main"); code != http.StatusNotFound || errCode(t, raw) != "snapshot_not_found" {
		t.Fatalf("snapshot before an upload = %d %s", code, raw)
	}
	l := d.lease(t)
	body := uploadBody(l, discEntries(2))
	raw, _ := json.Marshal(body)
	code, out := d.uploadRaw(t, "argocd-main", raw)
	if code != http.StatusOK {
		t.Fatalf("upload = %d %s", code, out)
	}
	var r discResult
	mustJSON(t, out, &r)
	if r.Status != "accepted" || r.Generation != l.generation || r.TargetsPresent != 2 || r.TargetsNew != 2 || r.TargetsMissing != 0 {
		t.Fatalf("upload result = %+v", r)
	}
	code, again := d.uploadRaw(t, "argocd-main", raw)
	var dup discResult
	mustJSON(t, again, &dup)
	if code != http.StatusOK || dup.Status != "duplicate" || dup.Generation != r.Generation || dup.TargetsNew != 2 {
		t.Fatalf("retry = %d %s; want 200 duplicate with the same counts", code, again)
	}
	if n := len(d.l.auditRows(t, "gateway.discovery.catalog_replaced")); n != 1 {
		t.Fatalf("catalog_replaced audits = %d; want 1 (the retry changes nothing)", n)
	}
	m := d.l.auditRows(t, "gateway.discovery.catalog_replaced")[0].Metadata
	if m["targets_new"] != float64(2) || m["entries_rejected"] != float64(1) || m["generation"] != float64(l.generation) ||
		!reflectEqualSanitized("gateway.discovery.catalog_replaced", m) {
		t.Fatalf("catalog_replaced audit = %v", m)
	}
	for _, e := range discEntries(2) {
		if strings.Contains(fmt.Sprint(m), e.Name) {
			t.Fatalf("audit carries an Application name: %v", m)
		}
	}

	code, snap := d.snapshot(t, "argocd-main")
	if code != http.StatusOK {
		t.Fatalf("snapshot = %d %s", code, snap)
	}
	var s map[string]any
	mustJSON(t, snap, &s)
	want := body["snapshot"].(map[string]any)
	got := s["snapshot"].(map[string]any)
	if s["schema_version"] != "gateway.discovery-snapshot/v1" || s["connector_id"] != "argocd-main" ||
		s["generation"] != float64(l.generation) || s["discovered_at"] != "2026-10-24T12:00:00Z" ||
		got["ciphertext"] != want["ciphertext"] || got["nonce"] != want["nonce"] || got["alg"] != want["alg"] || len(s) != 5 {
		t.Fatalf("snapshot = %s; want the upload exactly", snap)
	}
	// The next heartbeat names the generation, and carries a Date header
	// (the Gateway measures its lease deadline from it).
	hbRaw, _ := json.Marshal(hbV2(l.replica, testScope(), true, ""))
	code, hdr, hbOut := d.l.callRaw(t, http.MethodPost, "/api/v1/gateways/"+d.gw.GatewayID+"/heartbeat", d.hdr, hbRaw)
	var hr hbResponse
	mustJSON(t, hbOut, &hr)
	if code != http.StatusOK || len(hr.SnapshotGenerations) != 1 || hr.SnapshotGenerations[0].Generation != l.generation || hdr.Get("Date") == "" {
		t.Fatalf("heartbeat after the upload = %d %s (Date %q)", code, hbOut, hdr.Get("Date"))
	}
	// A snapshot older than the largest snapshot_max_age shows the
	// connector snapshot_stale in the admin read.
	if _, err := d.l.pool.Exec(t.Context(), `UPDATE gateway_discovery_snapshots SET discovered_at = date_trunc('second', now()) - interval '2 hours' WHERE connector_id = $1`, d.connID); err != nil {
		t.Fatal(err)
	}
	if code, raw := d.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+d.gw.GatewayID, d.admin, nil); code != http.StatusOK ||
		!strings.Contains(string(raw), `"status_reason":"snapshot_stale"`) {
		t.Fatalf("admin read with an old snapshot = %d %s", code, raw)
	}
	// Not one of this Gateway's connectors: the same 404.
	other := newDiscFixture(t, d.gwFixture, "disc-other-gw")
	for _, c := range []struct {
		d    *discFixture
		conn string
	}{{d, "argocd-other"}, {other, "argocd-main"}, {d, "Not_A_Label"}} {
		if code, raw := c.d.snapshot(t, c.conn); code != http.StatusNotFound || errCode(t, raw) != "snapshot_not_found" {
			t.Fatalf("snapshot %s = %d %s; want 404 snapshot_not_found", c.conn, code, raw)
		}
	}
	// Revoking the Gateway deletes its snapshots.
	if code, raw := d.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+d.gw.GatewayID+"/revoke", d.admin, nil); code != http.StatusOK {
		t.Fatalf("revoke = %d %s", code, raw)
	}
	var left int
	if err := d.l.pool.QueryRow(t.Context(), `SELECT count(*) FROM gateway_discovery_snapshots WHERE connector_id = $1`, d.connID).Scan(&left); err != nil || left != 0 {
		t.Fatalf("snapshots after revoke = %d, %v; want 0", left, err)
	}
}

// TestLive_GatewayDiscoveryUpload_Refusals: every typed E8 error.
func TestLive_GatewayDiscoveryUpload_Refusals(t *testing.T) {
	d := newDiscFixture(t, newGatewayFixture(t), "disc-refuse-gw")
	l := d.lease(t)
	expect := func(name string, code int, raw []byte, wantCode int, wantErr string) {
		t.Helper()
		if code != wantCode || errCode(t, raw) != wantErr {
			t.Fatalf("%s = %d %s; want %d %s", name, code, raw, wantCode, wantErr)
		}
	}
	code, raw := d.uploadRaw(t, "argocd-main", []byte(`{"schema_version":`))
	expect("malformed JSON", code, raw, 400, "invalid_request")
	code, raw = d.uploadRaw(t, "argocd-main", []byte(`{} {}`))
	expect("trailing data", code, raw, 400, "invalid_request")

	withField := uploadBody(l, discEntries(1))
	withField["key_id"] = "k1"
	code, raw = d.upload(t, "argocd-main", withField)
	expect("unknown field", code, raw, 422, "schema_violation")
	outside := uploadBody(l, []discEntry{{TargetID: discTargetID(1), AppProject: "team-z-apps", Namespace: "argocd", Name: "x"}})
	code, raw = d.upload(t, "argocd-main", outside)
	expect("AppProject outside the allowlist", code, raw, 422, "schema_violation")
	unsorted := discEntries(2)
	unsorted[0], unsorted[1] = unsorted[1], unsorted[0]
	code, raw = d.upload(t, "argocd-main", uploadBody(l, unsorted))
	expect("unsorted entries", code, raw, 422, "schema_violation")
	opaque := uploadBody(l, []discEntry{})
	opaque["identity_mode"] = "opaque"
	delete(opaque, "allowed_projects")
	opaque["project_aliases"] = []string{"team-a"}
	code, raw = d.upload(t, "argocd-main", opaque)
	expect("opaque mode before it ships", code, raw, 422, "schema_violation")

	code, raw = d.upload(t, "argocd-other", uploadBody(l, discEntries(1)))
	expect("unknown connector", code, raw, 404, "connector_not_found")

	wrongLease := l
	wrongLease.lease = uuid.NewString()
	code, raw = d.upload(t, "argocd-main", uploadBody(wrongLease, discEntries(1)))
	expect("another lease id", code, raw, 409, "lease_not_held")
	wrongReplica := l
	wrongReplica.replica = uuid.NewString()
	code, raw = d.upload(t, "argocd-main", uploadBody(wrongReplica, discEntries(1)))
	expect("not the holder", code, raw, 409, "lease_not_held")

	badScope := uploadBody(l, discEntries(1))
	badScope["endpoint_digest"] = "sha256:" + strings.Repeat("0", 64)
	code, raw = d.upload(t, "argocd-main", badScope)
	expect("scope digest not recomputable", code, raw, 409, "scope_digest_mismatch")

	// Caps: 2 MiB body, the per-connector entry cap, the per-Gateway cap.
	big := uploadBody(l, discEntries(1))
	big["snapshot"].(map[string]any)["ciphertext"] = strings.Repeat("A", 2<<20)
	code, raw = d.upload(t, "argocd-main", big)
	expect("body over 2 MiB", code, raw, 413, "catalog_too_large")
	if _, err := d.l.pool.Exec(t.Context(), `UPDATE gateways SET discovery_max_entries = 2 WHERE id = $1`, d.gw.GatewayID); err != nil {
		t.Fatal(err)
	}
	code, raw = d.upload(t, "argocd-main", uploadBody(l, discEntries(3)))
	expect("entries over the connector cap", code, raw, 413, "catalog_too_large")
	if _, err := d.l.pool.Exec(t.Context(), `UPDATE gateways SET discovery_max_entries = 2000 WHERE id = $1`, d.gw.GatewayID); err != nil {
		t.Fatal(err)
	}
	var otherConn string
	if err := d.l.pool.QueryRow(t.Context(), `INSERT INTO gateway_connectors (gateway_id, name, kind) VALUES ($1, 'argocd-two', 'argocd') RETURNING id`,
		d.gw.GatewayID).Scan(&otherConn); err != nil {
		t.Fatal(err)
	}
	// 9999 targets on another connector: md5 hex with 0, 1, 8 and 9
	// mapped into the base32 alphabet.
	if _, err := d.l.pool.Exec(t.Context(), `INSERT INTO gateway_discovered_targets
		(connector_id, target_id, gateway_id, app_project, namespace, name, generation_first_seen, last_seen_generation, first_seen_at, last_seen_at)
		SELECT $1, 'd-' || translate(substr(md5(i::text) || md5((i+7)::text), 1, 26), '0189', 'wxyz'), $2, 'team-a-apps', 'argocd', 'app-' || i, 1, 1, now(), now()
		FROM generate_series(1, 9999) i`, otherConn, d.gw.GatewayID); err != nil {
		t.Fatalf("seed 9999 targets: %v", err)
	}
	code, raw = d.upload(t, "argocd-main", uploadBody(l, discEntries(2)))
	expect("over 10000 discovered targets on the Gateway", code, raw, 413, "catalog_too_large")
	if _, err := d.l.pool.Exec(t.Context(), `DELETE FROM gateway_connectors WHERE id = $1`, otherConn); err != nil {
		t.Fatal(err)
	}

	// Accepted, then an older or equal generation is stale.
	d.mustUpload(t, uploadBody(l, discEntries(1)))
	again := uploadBody(l, discEntries(2)) // other bytes, same lease and generation
	code, raw = d.upload(t, "argocd-main", again)
	expect("same generation, other body", code, raw, 409, "discovery_generation_stale")
	l2 := d.lease(t)
	if l2.generation <= l.generation {
		t.Fatalf("second lease generation %d not above %d", l2.generation, l.generation)
	}
	old := uploadBody(l2, discEntries(1))
	old["generation"] = l.generation
	code, raw = d.upload(t, "argocd-main", old)
	expect("older generation", code, raw, 409, "discovery_generation_stale")
	// An expired lease is not held.
	if _, err := d.l.pool.Exec(t.Context(), `UPDATE gateway_connectors SET discovery_lease_expires_at = now() - interval '1 second' WHERE id = $1`, d.connID); err != nil {
		t.Fatal(err)
	}
	code, raw = d.upload(t, "argocd-main", uploadBody(l2, discEntries(1)))
	expect("expired lease", code, raw, 409, "lease_not_held")
}

// TestLive_GatewayDiscoveryUpload_MissingTargetSuspendsBinding: a bound
// target that leaves the catalog goes missing, its binding is suspended
// with target_missing and its open task is cancelled with target_missing.
// It stays while bound; an unbound target missing since an earlier
// upload is pruned.
func TestLive_GatewayDiscoveryUpload_MissingTargetSuspendsBinding(t *testing.T) {
	f := newObsFixture(t)
	d := &discFixture{gwFixture: f.gwFixture, gw: f.gw, hdr: f.gwHdr, connID: f.connID}
	l := d.lease(t)
	entries := discEntries(3)
	d.mustUpload(t, uploadBody(l, entries))
	bound, unbound := entries[0].TargetID, entries[1].TargetID
	var bindingID string
	if err := f.l.pool.QueryRow(t.Context(), `INSERT INTO gateway_connector_bindings
		(gateway_id, environment_id, secret_id, expected_stages, argocd_connector_id, argocd_target_id, target_source, created_by)
		VALUES ($1, $2, $3, '["argocd_context"]', $4, $5, 'discovered', 'test') RETURNING id`,
		f.gw.GatewayID, f.env, f.secret, f.connID, bound).Scan(&bindingID); err != nil {
		t.Fatal(err)
	}
	// Map team-a-apps to the project's team, so the binding dispatches.
	team := uuid.New()
	if _, err := f.l.pool.Exec(t.Context(), `INSERT INTO teams (id, name) VALUES ($1, $2)`, team, "team-"+team.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE projects SET team_id = $1 WHERE id = $2`, team, f.proj); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.pool.Exec(t.Context(), `INSERT INTO gateway_connector_project_teams (connector_id, app_project, team_id, approved_by, approved_at)
		VALUES ($1, 'team-a-apps', $2, 'test', now()), ($1, 'team-b-apps', $2, 'test', now())`, f.connID, team); err != nil {
		t.Fatal(err)
	}
	// The discovery heartbeat put the connector back to pending (first
	// digest with discovery on); approve the scope with the mapping done.
	if code, raw := f.approveScope(t, f.gw.GatewayID, f.connID, map[string]any{"scope_digest": testScope()}); code != http.StatusOK {
		t.Fatalf("approve = %d %s", code, raw)
	}
	// Drop the static binding so the request's only task is on the
	// discovered target.
	if code, raw := f.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+f.bindingID, f.admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete static binding = %d %s", code, raw)
	}
	reqID, _ := f.executeOn(t, f.env, f.secret)
	if ts := f.taskRows(t, reqID); len(ts) != 1 || !ts[0].State.Open() {
		t.Fatalf("tasks = %+v; want one open task on the discovered binding", ts)
	}

	l2 := d.lease(t)
	r := d.mustUpload(t, uploadBody(l2, entries[2:]))
	if r.TargetsMissing != 2 {
		t.Fatalf("result = %+v; want 2 missing", r)
	}
	if got := f.bindingSuspended(t, bindingID); got != "target_missing" {
		t.Fatalf("binding suspended_reason = %q; want target_missing", got)
	}
	ts := f.taskRows(t, reqID)
	if len(ts) != 1 || ts[0].State != "cancelled" || ts[0].VerdictReason != "target_missing" {
		t.Fatalf("task = %+v; want cancelled target_missing", ts)
	}
	status := func(id string) string {
		var s string
		if err := f.l.pool.QueryRow(t.Context(), `SELECT status FROM gateway_discovered_targets WHERE connector_id = $1 AND target_id = $2`, f.connID, id).Scan(&s); err != nil {
			return "absent"
		}
		return s
	}
	if status(bound) != "missing" || status(unbound) != "missing" {
		t.Fatalf("statuses = %s, %s; want missing, missing", status(bound), status(unbound))
	}
	// Defense in depth: even with the suspension cleared, a binding
	// whose discovered target is missing gets no task.
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE gateway_connector_bindings SET suspended_reason = NULL, suspended_at = NULL WHERE id = $1`, bindingID); err != nil {
		t.Fatal(err)
	}
	req2, _ := f.executeOn(t, f.env, f.secret)
	if ts := f.taskRows(t, req2); len(ts) != 0 {
		t.Fatalf("tasks for a missing discovered target = %+v; want none", ts)
	}
	l3 := d.lease(t)
	d.mustUpload(t, uploadBody(l3, entries[2:]))
	if status(bound) != "missing" || status(unbound) != "absent" {
		t.Fatalf("after the next upload: bound %s, unbound %s; want missing, pruned", status(bound), status(unbound))
	}
}

// TestLive_GatewayDiscovery_SnapshotStaleRefusalIsNotAFailure: E7 takes
// the new refusal reason target_snapshot_stale (section 7.2). It closes
// the attempt as refused and, unlike the other reasons, does not count
// as a failure of the binding.
func TestLive_GatewayDiscovery_SnapshotStaleRefusalIsNotAFailure(t *testing.T) {
	f := newObsFixture(t)
	for _, c := range []struct {
		reason   string
		failures int
	}{{"target_snapshot_stale", 0}, {"unbound_target", 1}} {
		reqID, _ := f.executeOn(t, f.env, f.secret)
		f.makeClaimable(t, reqID)
		code, task := f.claim(t, f.replica)
		if code != http.StatusOK {
			t.Fatalf("claim = %d", code)
		}
		res := argoResult(task, f.gw.GatewayID, f.replica)
		res["attempt_status"], res["refusal_reason"], res["stages"] = "refused", c.reason, []any{}
		if code, raw := f.post(t, task.TaskID, res); code != http.StatusOK {
			t.Fatalf("refused %s = %d %s", c.reason, code, raw)
		}
		ts := f.taskRows(t, reqID)
		if len(ts) != 1 || ts[0].FailureCount != c.failures {
			t.Fatalf("after a %s refusal: failure_count = %d; want %d", c.reason, ts[0].FailureCount, c.failures)
		}
	}
}
