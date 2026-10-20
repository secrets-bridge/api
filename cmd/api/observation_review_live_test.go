package main

// Follow-ups from the review of api#296: lock order between revoke and
// result, contract negotiation, the object a result describes, exact
// and unique keys, the environment source under concurrency, the
// fail-closed limiter, and the cross-Gateway and in-transaction checks.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// claimedFixture is an obsFixture with one executed request whose task
// is leased.
func claimedFixture(t *testing.T) (*obsFixture, uuid.UUID, *wireTask) {
	t.Helper()
	f := newObsFixture(t)
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	code, task := f.claim(t, f.replica)
	if code != http.StatusOK {
		t.Fatalf("claim = %d", code)
	}
	return f, reqID, task
}

func isDeadlock(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "40P01"
}

// TestLive_Observation_RevokeAndResultDoNotDeadlock: Revoke locks the
// Gateway and then the Gateway's tasks; a result must take the same
// order. A third transaction holds the attempt row so Revoke pauses
// between its two steps while it holds the Gateway row, then the result
// transaction starts. With the result locking the task first, the two
// deadlock (SQLSTATE 40P01); with the Gateway first, the result waits,
// sees the revoke and is refused.
func TestLive_Observation_RevokeAndResultDoNotDeadlock(t *testing.T) {
	f, _, task := claimedFixture(t)
	ctx := t.Context()
	pool := f.l.pool
	gwID := uuid.MustParse(f.gw.GatewayID)
	taskID := uuid.MustParse(task.TaskID)

	hold, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(ctx, `SELECT 1 FROM observation_task_attempts WHERE attempt_id = $1 FOR UPDATE`, task.AttemptID); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var revokeErr, resultErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, revokeErr = storage.NewGateways(pool).Revoke(context.Background(), gwID, "test", time.Now())
	}()
	waitForLockWait(t, pool, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		rt, err := storage.NewObservationTasks(pool).BeginResult(context.Background(), gwID, taskID)
		resultErr = err
		if rt != nil {
			time.Sleep(200 * time.Millisecond)
			rt.Rollback(context.Background())
		}
	}()
	waitForLockWait(t, pool, 2)
	_ = hold.Rollback(ctx)
	wg.Wait()
	if isDeadlock(revokeErr) || isDeadlock(resultErr) {
		t.Fatalf("deadlock: revoke %v, result %v", revokeErr, resultErr)
	}
	if revokeErr != nil {
		t.Fatalf("revoke = %v", revokeErr)
	}
	if !errors.Is(resultErr, storage.ErrGatewayNotLive) {
		t.Fatalf("result after a concurrent revoke = %v; want ErrGatewayNotLive", resultErr)
	}
}

// waitForLockWait waits until n backends of this database wait on a
// lock, so the interleaving does not depend on sleeps.
func waitForLockWait(t *testing.T, pool *storage.Pool, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("fewer than %d backends waiting on a lock", n)
}

// TestLive_Observation_ClaimNeedsNegotiatedContract: a Gateway whose
// contract_versions is empty (no heartbeat accepted yet) is handed no
// task: 204 with Retry-After.
func TestLive_Observation_ClaimNeedsNegotiatedContract(t *testing.T) {
	f := newObsFixture(t)
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE gateways SET contract_versions = '[]' WHERE id = $1`, f.gw.GatewayID); err != nil {
		t.Fatal(err)
	}
	code, hdr, _, body := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, f.replica)
	if code != http.StatusNoContent || hdr.Get("Retry-After") == "" {
		t.Fatalf("claim before contract negotiation = %d %s; want 204 with Retry-After", code, body)
	}
	if tk := f.taskRows(t, reqID)[0]; tk.State != storage.ObservationTaskQueued || tk.AttemptCount != 0 {
		t.Fatalf("task after the refused claim: %s, %d attempts; want queued, 0", tk.State, tk.AttemptCount)
	}
}

// TestLive_Observation_EvidenceMustNameTheBoundObject: the resource a
// stage describes must be the object the target advertises: another
// Application's name, or another namespace than the advertised one, is
// refused even with the right connector and target ids.
func TestLive_Observation_EvidenceMustNameTheBoundObject(t *testing.T) {
	f, _, task := claimedFixture(t)
	for name, mutate := range map[string]func(r map[string]any){
		"another application":   func(r map[string]any) { r["name"] = "orders-api" },
		"another tenant's app":  func(r map[string]any) { r["namespace"] = "tenant-b"; r["name"] = "orders-api" },
		"advertised namespace":  func(r map[string]any) { r["namespace"] = "tenant-b" },
		"unadvertised app name": func(r map[string]any) { r["name"] = "payments-api-canary" },
	} {
		body := argoResult(task, f.gw.GatewayID, f.replica)
		mutate(stage0(body)["resource"].(map[string]any))
		if code, out := f.post(t, task.TaskID, body); code != http.StatusUnprocessableEntity || errCode(t, out) != "schema_violation" {
			t.Errorf("%s = %d %s; want 422 schema_violation", name, code, out)
		}
	}
	if n := f.evidenceCount(t); n != 0 {
		t.Fatalf("evidence rows = %d; want 0", n)
	}
	if code, out := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusOK {
		t.Fatalf("the bound object = %d %s", code, out)
	}
}

// TestLive_Observation_KeysAreExactAndUnique: encoding/json matches keys
// case-insensitively and keeps the last duplicate; the result decoder
// must refuse a case-variant key, a duplicate key and "Stages" for
// "stages", and nothing from such a body is stored.
func TestLive_Observation_KeysAreExactAndUnique(t *testing.T) {
	f, _, task := claimedFixture(t)
	const canary = "CANARY-sb-keys-7c1e"
	good, _ := json.Marshal(argoResult(task, f.gw.GatewayID, f.replica))
	cases := map[string]string{
		"case-variant facts before facts": strings.Replace(string(good), `"facts":{`, `"Facts":"`+canary+`","facts":{`, 1),
		"case-variant top-level key":      strings.Replace(string(good), `"gateway_version":"0.1.0"`, `"gateway_version":"0.1.0","GATEWAY_VERSION":"`+canary+`"`, 1),
		"duplicate key":                   strings.Replace(string(good), `"gateway_version":"0.1.0"`, `"gateway_version":"`+canary+`","gateway_version":"0.1.0"`, 1),
		"duplicate facts":                 strings.Replace(string(good), `"facts":{`, `"facts":{"sync_status":"`+canary+`"},"facts":{`, 1),
		"Stages for stages":               strings.Replace(string(good), `"stages":`, `"Stages":`, 1),
		"case-variant fact key":           strings.Replace(string(good), `"sync_status":"Synced"`, `"sync_status":"Synced","Sync_Status":"OutOfSync"`, 1),
	}
	for name, body := range cases {
		if body == string(good) {
			t.Fatalf("%s: mutation did not apply", name)
		}
		code, _, out := f.l.callRaw(t, http.MethodPost, "/api/v1/gateways/"+f.gw.GatewayID+"/tasks/"+task.TaskID+"/result", f.gwHdr, []byte(body))
		if code != http.StatusUnprocessableEntity || errCode(t, out) != "schema_violation" {
			t.Errorf("%s = %d %s; want 422 schema_violation", name, code, out)
		}
		if bytes.Contains(out, []byte(canary)) {
			t.Errorf("%s: response echoes the body", name)
		}
	}
	var n int
	if err := f.l.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM observation_evidence) +
		(SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%'||$1||'%') +
		(SELECT count(*) FROM observation_task_attempts WHERE result_response::text LIKE '%'||$1||'%')`, canary).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows from refused bodies = %d, %v; want 0", n, err)
	}
}

// TestLive_Observation_TaskNotCreatedOnceSourceLeftGateway: the source is
// read again under a lock inside the task insert, so a switch away from
// gateway that commits between OnJobCompleted's read and the insert
// leaves no task behind.
func TestLive_Observation_TaskNotCreatedOnceSourceLeftGateway(t *testing.T) {
	f := newObsFixture(t)
	ctx := t.Context()
	reqID, _ := f.executeOn(t, f.env, f.secret)
	existing := f.taskRows(t, reqID)[0]
	f.setSource(t, f.env, "control_plane")

	// The same insert the starter makes, for a later request in the same
	// environment, after the switch.
	req2, _ := f.executeOn(t, f.env, f.secret) // control_plane now: no task
	tk := *existing
	tk.ID, tk.RequestID = uuid.Nil, req2
	created, superseded, err := storage.NewObservationTasks(f.l.pool).CreateTask(ctx, &tk, time.Now())
	if !errors.Is(err, storage.ErrObservationSourceNotGateway) || created || len(superseded) != 0 {
		t.Fatalf("CreateTask after the switch = %v, %v, %d; want ErrObservationSourceNotGateway, no task", err, created, len(superseded))
	}
	if n := len(f.taskRows(t, req2)); n != 0 {
		t.Fatalf("tasks for the request = %d; want 0", n)
	}

	// Concurrently: a switch that holds the environment row makes the
	// insert wait and then refuse.
	f.setSource(t, f.env, "gateway")
	tx, err := f.l.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE environments SET observation_source = 'none' WHERE id = $1`, f.env); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := storage.NewObservationTasks(f.l.pool).CreateTask(context.Background(), &tk, time.Now())
		done <- err
	}()
	waitForLockWait(t, f.l.pool, 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, storage.ErrObservationSourceNotGateway) {
		t.Fatalf("CreateTask racing a switch to none = %v; want ErrObservationSourceNotGateway", err)
	}
}

// TestLive_Observation_MachineRateLimitFailsClosedWithoutRedis: with
// Redis unreachable, E4 to E7 answer 503 (the Gateway backs off) instead
// of running unlimited.
func TestLive_Observation_MachineRateLimitFailsClosedWithoutRedis(t *testing.T) {
	f, _, task := claimedFixture(t)
	ctx := t.Context()
	dead, err := runtime.Open(ctx, runtime.Config{URL: os.Getenv("TEST_REDIS_URL")})
	if err != nil {
		t.Fatal(err)
	}
	_ = dead.Close()
	km, err := keymgmt.NewLocalKMS(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	authSvc := services.NewAuthService(storage.NewLocalUsers(f.l.pool), storage.NewRoles(f.l.pool), storage.NewUserRoles(f.l.pool), storage.NewAuditEvents(f.l.pool))
	prev := middleware.AllowInsecureHeaderIdentity
	t.Cleanup(func() { middleware.AllowInsecureHeaderIdentity = prev })
	app := newApp(Config{Env: ModeDev, AllowInsecureHeaderAuth: true}, slog.New(slog.DiscardHandler), f.l.pool, dead, km, authSvc)
	noRedis := &liveApp{app: app, pool: f.l.pool, logs: &hygLogBuffer{}}

	base := "/api/v1/gateways/" + f.gw.GatewayID + "/tasks/"
	for _, c := range []struct {
		path string
		body any
	}{
		{"claim", map[string]any{"replica_id": f.replica, "max_tasks": 1}},
		{task.TaskID + "/lease", map[string]any{"replica_id": f.replica, "attempt_id": task.AttemptID}},
		{task.TaskID + "/release", map[string]any{"replica_id": f.replica, "attempt_id": task.AttemptID, "reason": "shutdown"}},
		{task.TaskID + "/result", argoResult(task, f.gw.GatewayID, f.replica)},
	} {
		if code, body := noRedis.callAs(t, http.MethodPost, base+c.path, f.gwHdr, c.body); code != http.StatusServiceUnavailable {
			t.Errorf("%s without Redis = %d %s; want 503", c.path, code, body)
		}
	}
	if tk := f.taskRows(t, uuid.MustParse(task.RequestID))[0]; tk.State != storage.ObservationTaskLeased || f.evidenceCount(t) != 0 {
		t.Fatalf("a refused call changed the task: %s, evidence %d", tk.State, f.evidenceCount(t))
	}
}

// TestLive_Observation_ClaimNeverCrossesGateways: Gateway B has nothing
// of its own to claim while Gateway A's task is claimable; B gets 204.
// Fails deterministically if the claim drops its gateway_id predicate.
func TestLive_Observation_ClaimNeverCrossesGateways(t *testing.T) {
	f := newObsFixture(t)
	gwB, _ := f.gatewayReady(t, "obs-gw-b")
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	if code, _, w, body := f.claimAs(t, gwB.GatewayID, gwB.GatewaySecret, uuid.NewString()); code != http.StatusNoContent {
		t.Fatalf("gateway B claim with only gateway A's task claimable = %d %s (task %v); want 204", code, body, w != nil)
	}
	if code, _ := f.claim(t, f.replica); code != http.StatusOK {
		t.Fatalf("gateway A claim = %d; want 200", code)
	}
}

// TestLive_Observation_EvidenceThroughUnapprovedConnector: a connector
// that left the catalog (missing) or was disabled while a task was
// leased cannot carry evidence for it.
func TestLive_Observation_EvidenceThroughUnapprovedConnector(t *testing.T) {
	t.Run("missing from the catalog", func(t *testing.T) {
		f, _, task := claimedFixture(t)
		if code, body := f.catalog(t, f.gw.GatewayID, f.gw.GatewaySecret, map[string]any{"connectors": []map[string]any{}}); code != http.StatusOK {
			t.Fatalf("catalog = %d %s", code, body)
		}
		if code, out := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusUnprocessableEntity {
			t.Fatalf("result through a missing connector = %d %s; want 422", code, out)
		}
		if f.evidenceCount(t) != 0 {
			t.Fatal("evidence stored through a missing connector")
		}
	})
	t.Run("disabled", func(t *testing.T) {
		f, _, task := claimedFixture(t)
		if _, err := f.l.pool.Exec(t.Context(), `UPDATE gateway_connectors SET status = 'disabled' WHERE id = $1`, f.connID); err != nil {
			t.Fatal(err)
		}
		if code, out := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusUnprocessableEntity {
			t.Fatalf("result through a disabled connector = %d %s; want 422", code, out)
		}
		if f.evidenceCount(t) != 0 {
			t.Fatal("evidence stored through a disabled connector")
		}
	})
}

// TestLive_Observation_ClaimRechecksGatewayStatusInTransaction: the claim
// re-reads the Gateway's status under its row lock, so a revoke or
// disable that the auth cache has not seen still stops it (storage
// level, past GatewayAuth).
func TestLive_Observation_ClaimRechecksGatewayStatusInTransaction(t *testing.T) {
	f := newObsFixture(t)
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	store := storage.NewObservationTasks(f.l.pool)
	gwID := uuid.MustParse(f.gw.GatewayID)
	for _, status := range []string{"disabled", "revoked"} {
		q := `UPDATE gateways SET status = $2 WHERE id = $1`
		if status == "revoked" {
			q = `UPDATE gateways SET status = $2, revoked_at = now() WHERE id = $1`
		}
		if _, err := f.l.pool.Exec(t.Context(), q, gwID, status); err != nil {
			t.Fatal(err)
		}
		_, err := store.Claim(t.Context(), gwID, uuid.New(), time.Minute, 1, "1")
		if !errors.Is(err, storage.ErrGatewayNotLive) {
			t.Fatalf("storage claim for a %s gateway = %v; want ErrGatewayNotLive", status, err)
		}
	}
	if tk := f.taskRows(t, reqID)[0]; tk.State != storage.ObservationTaskQueued {
		t.Fatalf("task = %s; want queued", tk.State)
	}
}

// TestLive_Observation_EvidenceNeedsTheRequestEnvironment: the binding
// scope read in the result transaction carries the request's
// environment, and a task whose request is no longer in the binding's
// environment refuses evidence.
func TestLive_Observation_EvidenceNeedsTheRequestEnvironment(t *testing.T) {
	f, reqID, task := claimedFixture(t)
	ctx := t.Context()
	_, otherEnv, _ := f.seedScope(t)
	gwID, taskID := uuid.MustParse(f.gw.GatewayID), uuid.MustParse(task.TaskID)

	rt, err := storage.NewObservationTasks(f.l.pool).BeginResult(ctx, gwID, taskID)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := rt.BindingScope(ctx)
	rt.Rollback(ctx)
	if err != nil || scope.RequestEnvironmentID == nil || *scope.RequestEnvironmentID != f.env || scope.BindingEnvironmentID != f.env {
		t.Fatalf("binding scope = %+v, %v; want the request and binding in %s", scope, err, f.env)
	}
	if _, err := f.l.pool.Exec(ctx, `UPDATE access_requests SET environment_id = $2 WHERE id = $1`, reqID, otherEnv); err != nil {
		t.Fatal(err)
	}
	if code, out := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusUnprocessableEntity {
		t.Fatalf("result for a request outside the binding's environment = %d %s; want 422", code, out)
	}
	if f.evidenceCount(t) != 0 {
		t.Fatal("evidence stored for a request outside the binding's environment")
	}
	// Another Gateway's task is not found at the storage level.
	gwB, _ := f.gatewayReady(t, "obs-gw-b")
	if _, err := storage.NewObservationTasks(f.l.pool).BeginResult(ctx, uuid.MustParse(gwB.GatewayID), taskID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("BeginResult for another gateway's task = %v; want ErrNotFound", err)
	}
}

// TestLive_Observation_RequestEvidenceIsNotAnIDOR: the evidence read has
// the GET /requests/:id read check; an outsider gets 404 and its read
// closes nothing.
func TestLive_Observation_RequestEvidenceIsNotAnIDOR(t *testing.T) {
	f, reqID, _ := claimedFixture(t)
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE observation_tasks SET deadline_at = now() - interval '1 second' WHERE request_id = $1`, reqID); err != nil {
		t.Fatal(err)
	}
	u := uuid.New()
	hdr := map[string]string{"Cookie": f.l.sessionFor(t, u, "obs-idor-"+u.String()[:8]+"@example.com")}
	if code, body := f.l.callAs(t, http.MethodGet, "/api/v1/requests/"+reqID.String()+"/observations", hdr, nil); code != http.StatusNotFound {
		t.Fatalf("no-grant reader = %d %s; want 404", code, body)
	}
	u2 := uuid.New()
	hdr2 := map[string]string{"Cookie": f.l.sessionFor(t, u2, "obs-idor2-"+u2.String()[:8]+"@example.com")}
	f.l.addGrant(t, u2.String(), []string{"secret.approve"}, `{"project_id":"`+uuid.NewString()+`"}`)
	if code, body := f.l.callAs(t, http.MethodGet, "/api/v1/requests/"+reqID.String()+"/observations", hdr2, nil); code != http.StatusNotFound {
		t.Fatalf("other-project reader = %d %s; want 404", code, body)
	}
	if n := len(f.l.auditRows(t, "observation.task.timed_out")); n != 0 {
		t.Fatalf("an unauthorized read closed %d tasks", n)
	}
}

// TestLive_Observation_BindingDeletedMidLease: deleting the binding while
// its task is leased fences the result (409 task_closed, nothing stored).
func TestLive_Observation_BindingDeletedMidLease(t *testing.T) {
	f, _, task := claimedFixture(t)
	if code, body := f.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+f.bindingID, f.admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete binding = %d %s", code, body)
	}
	if code, out := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusConflict || errCode(t, out) != "task_closed" {
		t.Fatalf("result after binding delete = %d %s; want 409 task_closed", code, out)
	}
	if f.evidenceCount(t) != 0 {
		t.Fatal("evidence stored after binding delete")
	}
}

// TestLive_Observation_HugeClockOffsetIsNeitherObservedNorWindowWidening:
// a self-reported 24h offset widens the time window only up to the skew
// bound, and could never make a stage observed.
func TestLive_Observation_HugeClockOffsetIsNeitherObservedNorWindowWidening(t *testing.T) {
	f, reqID, task := claimedFixture(t)
	body := argoResult(task, f.gw.GatewayID, f.replica)
	body["clock"] = map[string]any{"cp_offset_ms": 86400000}
	future := time.Now().Add(20 * time.Hour).UTC().Format(time.RFC3339Nano)
	body["finished_at"] = future
	stage0(body)["observed_at"] = future
	if code, out := f.post(t, task.TaskID, body); code != http.StatusUnprocessableEntity || errCode(t, out) != "evidence_out_of_window" {
		t.Fatalf("20h-ahead result with a 24h offset = %d %s; want 422 evidence_out_of_window", code, out)
	}
	// Inside the window, a large offset still bars observed.
	ok := argoResult(task, f.gw.GatewayID, f.replica)
	ok["clock"] = map[string]any{"cp_offset_ms": 86400000}
	if code, out := f.post(t, task.TaskID, ok); code != http.StatusOK {
		t.Fatalf("in-window result with a 24h offset = %d %s", code, out)
	}
	for _, tk := range f.taskRows(t, reqID) {
		if st := tk.Stages["argocd_context"]; st.Outcome == "observed" {
			t.Fatal("observed with a 24h self-reported clock offset")
		}
	}
}
