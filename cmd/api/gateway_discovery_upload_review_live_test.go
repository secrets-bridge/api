package main

// Regression tests for the security review on api#320: the E8 upload
// needs the scope every live replica agrees on and the approved one, a
// full uid churn cannot strand a connector over the Gateway cap, and the
// upload's lock on the Gateway row does not deadlock task creation.

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
)

// reviewEntries is n discovered entries in project, ids from start, sorted
// by target id as E8 requires.
func reviewEntries(start, n int, project string) []discEntry {
	out := make([]discEntry, 0, n)
	for i := start; i < start+n; i++ {
		out = append(out, discEntry{TargetID: discTargetID(i), AppProject: project, Namespace: "argocd", Name: fmt.Sprintf("app-%d", i)})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].TargetID < out[b].TargetID })
	return out
}

// ageOutSetupReplica takes the obsFixture's contract 1 setup replica out
// of the live window: it reports no scope digest, so it blocks a lease.
func ageOutSetupReplica(t *testing.T, f *obsFixture) {
	t.Helper()
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE gateway_replicas SET last_seen_at = now() - interval '11 minutes' WHERE gateway_id = $1`, f.gw.GatewayID); err != nil {
		t.Fatal(err)
	}
}

// approvedDiscoveryFixture is an obsFixture whose argocd-main connector
// uploaded two team-a-apps targets and is approved at testScope(), with
// team-a-apps and team-b-apps mapped to one team.
func approvedDiscoveryFixture(t *testing.T) (*obsFixture, *discFixture, []discEntry) {
	t.Helper()
	f := newObsFixture(t)
	d := &discFixture{gwFixture: f.gwFixture, gw: f.gw, hdr: f.gwHdr, connID: f.connID}
	ageOutSetupReplica(t, f)
	entries := reviewEntries(0, 2, "team-a-apps")
	d.mustUpload(t, uploadBody(d.lease(t), entries))
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
	if code, raw := f.approveScope(t, f.gw.GatewayID, f.connID, map[string]any{"scope_digest": testScope()}); code != http.StatusOK {
		t.Fatalf("approve = %d %s", code, raw)
	}
	return f, d, entries
}

// TestLive_GatewayDiscoveryReview_UploadNeedsTheApprovedAgreedScope: a
// lease holder that switches to a wider scope after its lease cannot
// upload it while the connector is approved at the old one, and nothing
// of the wider scope is stored.
func TestLive_GatewayDiscoveryReview_UploadNeedsTheApprovedAgreedScope(t *testing.T) {
	f, d, _ := approvedDiscoveryFixture(t)
	l2 := d.lease(t)
	wide := []string{"team-a-apps", "team-b-apps", "team-c-apps"}
	s2 := services.GatewayScopeDigest(testEndpointDigest, wide, true, "names")
	d.mustHB(t, d.gw, hbV2(l2.replica, s2, true, ""))

	body := uploadBody(l2, append(reviewEntries(0, 2, "team-a-apps"), reviewEntries(500, 1, "team-c-apps")...))
	es := body["entries"].([]discEntry)
	sort.Slice(es, func(a, b int) bool { return es[a].TargetID < es[b].TargetID })
	body["entries"], body["scope_digest"], body["allowed_projects"] = es, s2, wide
	code, raw := d.upload(t, "argocd-main", body)
	if code != http.StatusConflict || errCode(t, raw) != "scope_digest_mismatch" {
		t.Fatalf("upload of a wider scope on a connector approved at the old one = %d %s; want 409 scope_digest_mismatch", code, raw)
	}
	var allowed string
	var teamC bool
	if err := f.l.pool.QueryRow(t.Context(), `SELECT discovery_allowed_projects::text,
		EXISTS (SELECT 1 FROM gateway_discovered_targets WHERE connector_id = $1 AND app_project = 'team-c-apps')
		FROM gateway_connectors WHERE id = $1`, d.connID).Scan(&allowed, &teamC); err != nil {
		t.Fatal(err)
	}
	if teamC || allowed != `["team-a-apps", "team-b-apps"]` {
		t.Fatalf("after the refused upload: allowed %s, team-c target stored %v; want the approved scope only", allowed, teamC)
	}
	if c := d.connRow(t, d.connID); c.Status != "approved" || c.Approved != testScope() {
		t.Fatalf("connector after the refused upload = %+v; want approved at the old digest", c)
	}
}

// TestLive_GatewayDiscoveryReview_FullChurnStaysUnderTheCap: with a
// connector cap above half the Gateway cap, uploads where every uid
// changed keep being accepted, because unbound targets that went missing
// in the same upload are pruned instead of counted.
func TestLive_GatewayDiscoveryReview_FullChurnStaysUnderTheCap(t *testing.T) {
	d := newDiscFixture(t, newGatewayFixture(t), "review-churn-gw")
	if _, err := d.l.pool.Exec(t.Context(), `UPDATE gateways SET discovery_max_entries = 6000 WHERE id = $1`, d.gw.GatewayID); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 3; round++ {
		if code, raw := d.upload(t, "argocd-main", uploadBody(d.lease(t), reviewEntries(round*100000, 6000, "team-a-apps"))); code != http.StatusOK {
			t.Fatalf("round %d: upload of 6000 fresh targets = %d %s; want 200", round, code, raw)
		}
		var total, missing int
		if err := d.l.pool.QueryRow(t.Context(), `SELECT count(*), count(*) FILTER (WHERE status = 'missing')
			FROM gateway_discovered_targets WHERE gateway_id = $1`, d.gw.GatewayID).Scan(&total, &missing); err != nil {
			t.Fatal(err)
		}
		if total > 10000 {
			t.Fatalf("round %d: %d discovered rows (%d missing); want at most 10000", round, total, missing)
		}
	}
}

// TestLive_GatewayDiscoveryReview_UploadAndCreateTaskLockOrder: a
// transaction in task creation's lock order (the superseded task first,
// then the Gateway row's key share through the new task's foreign key)
// and an upload that holds the Gateway row and then cancels that task
// both complete.
func TestLive_GatewayDiscoveryReview_UploadAndCreateTaskLockOrder(t *testing.T) {
	f, d, entries := approvedDiscoveryFixture(t)
	if _, err := f.l.pool.Exec(t.Context(), `INSERT INTO gateway_connector_bindings
		(gateway_id, environment_id, secret_id, expected_stages, argocd_connector_id, argocd_target_id, target_source, created_by)
		VALUES ($1, $2, $3, '["argocd_context"]', $4, $5, 'discovered', 'test')`,
		f.gw.GatewayID, f.env, f.secret, f.connID, entries[0].TargetID); err != nil {
		t.Fatal(err)
	}
	if code, raw := f.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+f.bindingID, f.admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete static binding = %d %s", code, raw)
	}
	reqID, _ := f.executeOn(t, f.env, f.secret)
	ts := f.taskRows(t, reqID)
	if len(ts) != 1 {
		t.Fatalf("tasks = %d; want 1", len(ts))
	}
	l2 := d.lease(t)
	ctx := t.Context()
	tx, err := f.l.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT id FROM observation_tasks WHERE id = $1 FOR UPDATE`, ts[0].ID); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var upCode int
	var upRaw []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The target the task observes goes missing, so the upload cancels it.
		upCode, upRaw = d.upload(t, "argocd-main", uploadBody(l2, entries[1:]))
	}()
	waiting := false
	for i := 0; i < 250 && !waiting; i++ {
		time.Sleep(20 * time.Millisecond)
		var n int
		_ = f.l.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%observation_tasks%'`).Scan(&n)
		waiting = n > 0
	}
	if !waiting {
		_ = tx.Rollback(ctx)
		wg.Wait()
		t.Fatalf("the upload never waited on the task lock (upload = %d %s), so the lock order was not exercised", upCode, upRaw)
	}
	_, kerr := tx.Exec(ctx, `SELECT 1 FROM gateways WHERE id = $1 FOR KEY SHARE`, f.gw.GatewayID)
	_ = tx.Rollback(ctx)
	wg.Wait()
	if kerr != nil {
		t.Fatalf("task creation's key share on the Gateway row = %v; want it granted while the upload holds the row", kerr)
	}
	if upCode != http.StatusOK {
		t.Fatalf("upload racing task creation = %d %s; want 200", upCode, upRaw)
	}
}
