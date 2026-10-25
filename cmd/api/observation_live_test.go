package main

// Gateway observation tasks, claim, lease, result and evidence (api#294),
// driven through the REAL router built by newApp against Postgres and
// Redis. Paths, bodies, status codes and error codes are the ones the
// Gateway client on gateway main (internal/client, internal/contract,
// internal/loop) sends and expects.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// obsFixture is an enrolled, heartbeating Gateway with an approved
// argocd-main connector advertising payments-api, orders-api and
// billing-api, and one binding of payments-api to a catalog secret in a
// gateway-sourced environment.
type obsFixture struct {
	*gwFixture
	gw        gwEnrolled
	gwHdr     map[string]string
	replica   string
	connID    string
	proj, env uuid.UUID
	secret    uuid.UUID
	secretRef string
	bindingID string
	agentHdr  map[string]string
	agentBase string
}

func obsCatalogBody() map[string]any {
	return map[string]any{"connectors": []map[string]any{{
		"connector_id": "argocd-main", "kind": "argocd",
		"targets": []map[string]any{
			{"target_id": "payments-api", "namespace": "argocd", "name": "payments-api"},
			{"target_id": "orders-api", "namespace": "argocd", "name": "orders-api"},
			{"target_id": "billing-api", "namespace": "argocd", "name": "billing-api"},
		},
	}}}
}

// gatewayReady enrolls a Gateway, heartbeats, uploads the catalog and
// approves argocd-main. Returns the enrolled identity and the connector
// id.
func (f *gwFixture) gatewayReady(t *testing.T, name string) (gwEnrolled, string) {
	t.Helper()
	gw := f.enrolled(t, name)
	if code, body := f.heartbeat(t, gw.GatewayID, gw.GatewaySecret, uuid.NewString()); code != http.StatusOK {
		t.Fatalf("heartbeat = %d %s", code, body)
	}
	if code, body := f.catalog(t, gw.GatewayID, gw.GatewaySecret, obsCatalogBody()); code != http.StatusOK {
		t.Fatalf("catalog = %d %s", code, body)
	}
	code, body := f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+gw.GatewayID, f.admin, nil)
	if code != http.StatusOK {
		t.Fatalf("detail = %d %s", code, body)
	}
	var d struct {
		Connectors []struct {
			ID          string `json:"id"`
			ConnectorID string `json:"connector_id"`
		} `json:"connectors"`
	}
	mustJSON(t, body, &d)
	if len(d.Connectors) != 1 {
		t.Fatalf("connectors = %s", body)
	}
	cid := d.Connectors[0].ID
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+gw.GatewayID+"/connectors/"+cid+"/approve", f.admin, nil); code != http.StatusOK {
		t.Fatalf("approve = %d %s", code, body)
	}
	return gw, cid
}

func (f *gwFixture) bind(t *testing.T, gatewayID, connID string, env, secret uuid.UUID, target string) string {
	t.Helper()
	code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateway-bindings", f.admin, map[string]any{
		"gateway_id": gatewayID, "environment_id": env.String(), "secret_id": secret.String(),
		"argocd_connector_id": connID, "argocd_target_id": target,
	})
	if code != http.StatusCreated {
		t.Fatalf("bind = %d %s", code, body)
	}
	var b struct {
		ID string `json:"id"`
	}
	mustJSON(t, body, &b)
	return b.ID
}

func (f *gwFixture) setSource(t *testing.T, env uuid.UUID, src string) []byte {
	t.Helper()
	code, body := f.l.callAs(t, http.MethodPut, "/api/v1/admin/environments/"+env.String()+"/observation-source", f.admin,
		map[string]any{"observation_source": src})
	if code != http.StatusOK {
		t.Fatalf("set observation source %s = %d %s", src, code, body)
	}
	return body
}

// secretRefOf returns the catalog secret's provider reference.
func (f *gwFixture) secretRefOf(t *testing.T, secret uuid.UUID) string {
	t.Helper()
	var ref string
	if err := f.l.pool.QueryRow(t.Context(), `SELECT secret_ref FROM secrets WHERE id = $1`, secret).Scan(&ref); err != nil {
		t.Fatal(err)
	}
	return ref
}

// addSecret seeds another catalog secret bound to proj.
func (f *gwFixture) addSecret(t *testing.T, proj uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	ctx := t.Context()
	if _, err := f.l.pool.Exec(ctx, `INSERT INTO secrets (id, cluster_name, provider_type, secret_ref, status) VALUES ($1, 'tenant-a-uat', 'vault', $2, 'present')`,
		id, "team-alpha/uat/"+id.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.pool.Exec(ctx, `INSERT INTO project_secrets (project_id, secret_id) VALUES ($1, $2)`, proj, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func newObsFixture(t *testing.T) *obsFixture {
	t.Helper()
	gf := newGatewayFixture(t)
	f := &obsFixture{gwFixture: gf, replica: uuid.NewString()}
	f.gw, f.connID = gf.gatewayReady(t, "obs-gw")
	f.gwHdr = map[string]string{"X-Gateway-Secret": f.gw.GatewaySecret}
	f.proj, f.env, f.secret = gf.seedScope(t)
	f.secretRef = gf.secretRefOf(t, f.secret)
	f.bindingID = gf.bind(t, f.gw.GatewayID, f.connID, f.env, f.secret, "payments-api")
	gf.setSource(t, f.env, "gateway")

	op := f.l.grantUser(t, []string{"agent.mint"}, `{}`)
	code, body := f.l.call(t, http.MethodPost, "/api/v1/agents", op, agentMintBody("obs-agent-"+uuid.NewString()[:8]))
	if code != http.StatusCreated {
		t.Fatalf("mint agent = %d %s", code, body)
	}
	var agent struct {
		ID          uuid.UUID `json:"id"`
		AgentSecret string    `json:"agent_secret"`
	}
	mustJSON(t, body, &agent)
	f.agentHdr = agentHeaders(agent.AgentSecret)
	f.agentBase = "/api/v1/agents/" + agent.ID.String()
	return f
}

// execute drives a patch request on secret in env to executed through
// the real agent job routes: an approved request and its patch job are
// seeded, the agent claims the job and completes it, and
// RequestService.OnJobCompleted runs. Returns the request id and the
// job's correlation id.
func (f *gwFixture) execute(t *testing.T, agentBase string, agentHdr map[string]string, proj, env, secret uuid.UUID) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := t.Context()
	ref := f.secretRefOf(t, secret)
	var wf uuid.UUID
	if err := f.l.pool.QueryRow(ctx, `SELECT id FROM workflow_definitions WHERE is_system ORDER BY created_at LIMIT 1`).Scan(&wf); err != nil {
		t.Fatalf("seed workflow: %v", err)
	}
	req := &storage.AccessRequest{
		WorkflowID:  &wf,
		RequesterID: uuid.NewString(), Type: storage.AccessRequestTypePatch, Justification: "rotate tenant-a uat db",
		Status: storage.AccessRequestStatusApproved, EnvironmentID: &env, TargetProviderType: "vault",
		TargetSecretRef: ref, TargetKeys: []string{"DB_PASSWORD"},
		TargetScope: map[string]any{"project_id": proj.String(), "environment": "uat"},
	}
	if err := storage.NewAccessRequests(f.l.pool).Create(ctx, req); err != nil {
		t.Fatalf("seed request: %v", err)
	}
	job := &storage.SyncJob{JobType: storage.JobTypePatch, RequestID: &req.ID, Payload: map[string]any{"request_id": req.ID.String()}}
	if err := storage.NewSyncJobs(f.l.pool).Create(ctx, job); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	code, body := f.l.callAs(t, http.MethodPost, agentBase+"/jobs/claim", agentHdr, nil)
	if code != http.StatusOK {
		t.Fatalf("agent claim = %d %s", code, body)
	}
	var claimed struct{ ID uuid.UUID }
	mustJSON(t, body, &claimed)
	if claimed.ID != job.ID {
		t.Fatalf("agent claimed %s; want %s", claimed.ID, job.ID)
	}
	if code, body := f.l.callAs(t, http.MethodPost, agentBase+"/jobs/"+job.ID.String()+"/complete", agentHdr,
		map[string]any{"status": "succeeded"}); code != http.StatusNoContent {
		t.Fatalf("agent complete = %d %s", code, body)
	}
	var status string
	if err := f.l.pool.QueryRow(ctx, `SELECT status FROM access_requests WHERE id = $1`, req.ID).Scan(&status); err != nil || status != "executed" {
		t.Fatalf("request status = %q, %v; want executed", status, err)
	}
	return req.ID, job.CorrelationID
}

func (f *obsFixture) executeOn(t *testing.T, env, secret uuid.UUID) (uuid.UUID, uuid.UUID) {
	t.Helper()
	return f.execute(t, f.agentBase, f.agentHdr, f.proj, env, secret)
}

// makeClaimable moves time forward for a request's tasks: claimable now
// and executed a minute ago, so an Argo CD reconcile "now" is after the
// write plus skew.
func (f *gwFixture) makeClaimable(t *testing.T, requestID uuid.UUID) {
	t.Helper()
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE observation_tasks
		SET not_before = now() - interval '1 second', executed_at = now() - interval '1 minute',
		    created_at = now() - interval '1 minute'
		WHERE request_id = $1`, requestID); err != nil {
		t.Fatal(err)
	}
}

func (f *gwFixture) taskRows(t *testing.T, requestID uuid.UUID) []*storage.ObservationTask {
	t.Helper()
	ts, err := storage.NewObservationTasks(f.l.pool).ListForRequest(t.Context(), requestID)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func (l *liveApp) callRaw(t *testing.T, method, path string, headers map[string]string, body []byte) (int, http.Header, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := l.app.Test(req, fiber.TestConfig{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, out
}

type wireTask struct {
	SchemaVersion     string          `json:"schema_version"`
	TaskID            string          `json:"task_id"`
	AttemptID         string          `json:"attempt_id"`
	AttemptCount      int             `json:"attempt_count"`
	LeaseExpiresAt    time.Time       `json:"lease_expires_at"`
	DeadlineAt        time.Time       `json:"deadline_at"`
	RequestID         string          `json:"request_id"`
	CorrelationID     string          `json:"correlation_id"`
	SkewMarginSeconds int             `json:"skew_margin_seconds"`
	GatewayScope      json.RawMessage `json:"gateway_scope"`
	ConnectorRefs     []struct {
		ConnectorID string `json:"connector_id"`
		TargetID    string `json:"target_id"`
		Stage       string `json:"stage"`
	} `json:"connector_refs"`
	ExpectedChange  map[string]any  `json:"expected_change"`
	RolloutBaseline json.RawMessage `json:"rollout_baseline"`
}

func (f *gwFixture) claimAs(t *testing.T, gatewayID, secret, replica string) (int, http.Header, *wireTask, []byte) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"replica_id": replica, "max_tasks": 1})
	code, hdr, body := f.l.callRaw(t, http.MethodPost, "/api/v1/gateways/"+gatewayID+"/tasks/claim",
		map[string]string{"X-Gateway-Secret": secret}, raw)
	if code != http.StatusOK {
		return code, hdr, nil, body
	}
	var w wireTask
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		t.Fatalf("claim body is not an ObservationTask: %v %s", err, body)
	}
	return code, hdr, &w, body
}

func (f *obsFixture) claim(t *testing.T, replica string) (int, *wireTask) {
	t.Helper()
	code, _, w, body := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, replica)
	if code != http.StatusOK && code != http.StatusNoContent && w == nil {
		t.Logf("claim = %d %s", code, body)
	}
	return code, w
}

// argoResult is the EvidenceResult the Gateway's argocd connector sends
// for a Healthy, Synced Application reconciled now.
func argoResult(task *wireTask, gatewayID, replica string) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"schema_version": "gateway.evidence-result/v1",
		"task_id":        task.TaskID, "attempt_id": task.AttemptID, "gateway_id": gatewayID, "replica_id": replica,
		"gateway_version": "0.1.0",
		"started_at":      now.Add(-time.Second).Format(time.RFC3339Nano),
		"finished_at":     now.Format(time.RFC3339Nano),
		"attempt_status":  "completed",
		"stages": []map[string]any{{
			"stage":       "argocd_context",
			"source":      map[string]any{"connector_id": task.ConnectorRefs[0].ConnectorID, "target_id": task.ConnectorRefs[0].TargetID, "api": "argocd"},
			"observed_at": now.Format(time.RFC3339Nano),
			"resource":    map[string]any{"api_version": "argoproj.io/v1alpha1", "kind": "Application", "namespace": "argocd", "name": task.ConnectorRefs[0].TargetID},
			"outcome":     "observed", "confidence": "low", "caveats": []string{"argocd_health_not_proof"}, "linkage": "none",
			"facts": map[string]any{
				"sync_status": "Synced", "health_status": "Healthy", "sync_revision": "4f2a9c1",
				"reconciled_at": now.Format(time.RFC3339),
			},
		}},
		"clock": map[string]any{"cp_offset_ms": 0},
	}
}

func stage0(m map[string]any) map[string]any { return m["stages"].([]map[string]any)[0] }

func (f *gwFixture) postResult(t *testing.T, gatewayID, secret, taskID string, body any) (int, []byte) {
	t.Helper()
	return f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+gatewayID+"/tasks/"+taskID+"/result",
		map[string]string{"X-Gateway-Secret": secret}, body)
}

func (f *obsFixture) post(t *testing.T, taskID string, body any) (int, []byte) {
	t.Helper()
	return f.postResult(t, f.gw.GatewayID, f.gw.GatewaySecret, taskID, body)
}

func (f *gwFixture) evidenceCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.l.pool.QueryRow(t.Context(), `SELECT count(*) FROM observation_evidence`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *gwFixture) gitopsRows(t *testing.T, requestID uuid.UUID) int {
	t.Helper()
	var n int
	if err := f.l.pool.QueryRow(t.Context(), `SELECT count(*) FROM gitops_observations WHERE request_id = $1`, requestID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

type requestEvidence struct {
	ObservationSource string `json:"observation_source"`
	Rollup            string `json:"rollup"`
	Label             string `json:"label"`
	Tasks             []struct {
		TaskID         string `json:"task_id"`
		GatewayName    string `json:"gateway_name"`
		State          string `json:"state"`
		Verdict        string `json:"verdict"`
		VerdictReason  string `json:"verdict_reason"`
		TimedOutAtRead bool   `json:"timed_out_at_read"`
		Stages         []struct {
			Stage       string         `json:"stage"`
			Outcome     string         `json:"outcome"`
			ObservedAt  time.Time      `json:"observed_at"`
			GatewayID   string         `json:"gateway_id"`
			ConnectorID string         `json:"connector_id"`
			TargetID    string         `json:"target_id"`
			Caveats     []string       `json:"caveats"`
			Facts       map[string]any `json:"facts"`
			Label       string         `json:"label"`
		} `json:"stages"`
	} `json:"tasks"`
}

// requestEvidence reads GET /requests/:id/observations as an admin who
// can read every request (secret.approve, global).
func (f *gwFixture) requestEvidence(t *testing.T, requestID uuid.UUID) (requestEvidence, []byte) {
	t.Helper()
	reader := uuid.New()
	hdr := map[string]string{"Cookie": f.l.sessionFor(t, reader, "obs-reader-"+reader.String()[:8]+"@example.com")}
	f.l.addGrant(t, reader.String(), []string{"secret.approve"}, `{}`)
	code, body := f.l.callAs(t, http.MethodGet, "/api/v1/requests/"+requestID.String()+"/observations", hdr, nil)
	if code != http.StatusOK {
		t.Fatalf("request observations = %d %s", code, body)
	}
	var ev requestEvidence
	mustJSON(t, body, &ev)
	return ev, body
}

// TestLive_Observation_ArgoCDEndToEnd walks the R1 path: a request
// reaches executed in a gateway environment, one task is created (and no
// control-plane observation), the Gateway claims it, posts Argo CD
// Healthy and Synced, and the request page shows argocd_context observed
// as operational state with the argocd_health_not_proof caveat and an
// unverified verdict. A replay is idempotent, a conflicting body is 409.
func TestLive_Observation_ArgoCDEndToEnd(t *testing.T) {
	f := newObsFixture(t)
	ctx := t.Context()
	reqID, correlation := f.executeOn(t, f.env, f.secret)

	tasks := f.taskRows(t, reqID)
	if len(tasks) != 1 {
		t.Fatalf("tasks = %d; want 1", len(tasks))
	}
	if n := f.gitopsRows(t, reqID); n != 0 {
		t.Fatalf("gitops_observations rows = %d; a gateway environment must not get the control-plane observer", n)
	}
	created := f.l.auditRows(t, "observation.task.created")
	if len(created) != 1 || created[0].CorrelationID != correlation {
		t.Fatalf("observation.task.created = %+v; want one row with the job correlation id", created)
	}
	if rows := f.l.auditRows(t, "request.gitops_observation_skipped"); len(rows) != 0 {
		t.Fatalf("request.gitops_observation_skipped = %+v; the control-plane observer is gone, want none", rows)
	}

	// Not claimable before not_before (10s after executed).
	if code, _, _, body := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, f.replica); code != http.StatusNoContent {
		t.Fatalf("claim before not_before = %d %s; want 204", code, body)
	}
	f.makeClaimable(t, reqID)
	code, task := f.claim(t, f.replica)
	if code != http.StatusOK {
		t.Fatalf("claim = %d", code)
	}
	if task.SchemaVersion != "gateway.observation-task/v1" || task.AttemptCount != 1 || task.RequestID != reqID.String() ||
		task.CorrelationID != correlation.String() || len(task.ConnectorRefs) != 1 ||
		task.ConnectorRefs[0].ConnectorID != "argocd-main" || task.ConnectorRefs[0].TargetID != "payments-api" ||
		task.ConnectorRefs[0].Stage != "argocd_context" || task.SkewMarginSeconds != 5 ||
		string(task.RolloutBaseline) != "null" {
		t.Fatalf("task = %+v", task)
	}
	ec := task.ExpectedChange
	if ec["provider_type"] != "vault" || ec["version_source"] != "none" || ec["provider_version_id"] != nil ||
		ec["secret_ref"].(map[string]any)["name"] != f.secretRef {
		t.Fatalf("expected_change = %+v", ec)
	}
	if lease := time.Until(task.LeaseExpiresAt); lease < 50*time.Second || lease > 61*time.Second {
		t.Fatalf("lease = %v; want about 60s", lease)
	}
	if dl := time.Until(task.DeadlineAt); dl < 28*time.Minute || dl > 31*time.Minute {
		t.Fatalf("deadline = %v; want about 30m (binding default 1800s)", dl)
	}
	// The same replica is at its in-flight limit (1).
	if code, _, _, body := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, f.replica); code != http.StatusTooManyRequests {
		t.Fatalf("second claim by the same replica = %d %s; want 429", code, body)
	}

	// Renew moves the lease.
	code, body := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+f.gw.GatewayID+"/tasks/"+task.TaskID+"/lease", f.gwHdr,
		map[string]any{"replica_id": f.replica, "attempt_id": task.AttemptID})
	if code != http.StatusOK || !strings.Contains(string(body), "lease_expires_at") {
		t.Fatalf("renew = %d %s", code, body)
	}

	res := argoResult(task, f.gw.GatewayID, f.replica)
	code, body = f.post(t, task.TaskID, res)
	if code != http.StatusOK {
		t.Fatalf("result = %d %s", code, body)
	}
	var resp map[string]string
	mustJSON(t, body, &resp)
	if resp["status"] != "accepted" || resp["task_state"] != "done" || resp["verdict"] != "unverified" || resp["next"] != "none" {
		t.Fatalf("result response = %s; want accepted, done, unverified (Argo CD health is context only), none", body)
	}

	// Replay after a lost 200, keys in another order: 200 duplicate.
	raw, _ := json.Marshal(res)
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)
	reordered := reorderJSON(t, generic)
	code, body = f.post(t, task.TaskID, json.RawMessage(reordered))
	mustJSON(t, body, &resp)
	if code != http.StatusOK || resp["status"] != "duplicate" || resp["task_state"] != "done" || resp["verdict"] != "unverified" {
		t.Fatalf("replay = %d %s; want 200 duplicate with the stored response", code, body)
	}
	// Same attempt, different body: 409 result_conflict.
	stage0(res)["facts"].(map[string]any)["health_status"] = "Degraded"
	if code, body := f.post(t, task.TaskID, res); code != http.StatusConflict || errCode(t, body) != "result_conflict" {
		t.Fatalf("conflicting result = %d %s; want 409 result_conflict", code, body)
	}
	if n := f.evidenceCount(t); n != 1 {
		t.Fatalf("evidence rows = %d; want 1 (replay and conflict store nothing)", n)
	}

	ev, evBody := f.requestEvidence(t, reqID)
	if ev.ObservationSource != "gateway" || ev.Rollup != "unverified" || ev.Label != "observed_operational_state" || len(ev.Tasks) != 1 {
		t.Fatalf("request evidence = %s", evBody)
	}
	tk := ev.Tasks[0]
	if tk.GatewayName != "obs-gw" || tk.State != "done" || tk.Verdict != "unverified" || tk.VerdictReason != "context_only" || len(tk.Stages) != 1 {
		t.Fatalf("task view = %s", evBody)
	}
	st := tk.Stages[0]
	if st.Stage != "argocd_context" || st.Outcome != "observed" || st.ObservedAt.IsZero() || st.GatewayID != f.gw.GatewayID ||
		st.ConnectorID != "argocd-main" || st.TargetID != "payments-api" || st.Label != "observed_operational_state" ||
		!contains(st.Caveats, "argocd_health_not_proof") || st.Facts["health_status"] != "Healthy" || st.Facts["sync_status"] != "Synced" {
		t.Fatalf("stage view = %s", evBody)
	}
	// Namespace and name are admin display only.
	if strings.Contains(string(evBody), `"namespace"`) || strings.Contains(string(evBody), `"resource"`) {
		t.Fatalf("request evidence carries the resource identity: %s", evBody)
	}

	// One transaction wrote evidence, task, verdict and audit; the audit
	// rows carry the job correlation id.
	for _, action := range []string{"observation.task.claimed", "observation.evidence.accepted", "observation.task.verdict"} {
		rows := f.l.auditRows(t, action)
		if len(rows) != 1 || rows[0].CorrelationID != correlation {
			t.Fatalf("%s = %+v; want one row with the job correlation id", action, rows)
		}
	}
	if acc := f.l.auditRows(t, "observation.evidence.accepted")[0]; acc.Metadata["verdict"] != "unverified" ||
		acc.Metadata["attempt_status"] != "completed" {
		t.Fatalf("observation.evidence.accepted metadata = %+v", acc.Metadata)
	}

	// Idle: 204 with Retry-After.
	code, hdr, _, _ := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, f.replica)
	if code != http.StatusNoContent || hdr.Get("Retry-After") == "" {
		t.Fatalf("idle claim = %d Retry-After %q; want 204 with Retry-After", code, hdr.Get("Retry-After"))
	}

	// Evidence is append-only.
	if _, err := f.l.pool.Exec(ctx, `UPDATE observation_evidence SET cp_outcome = 'error'`); err == nil {
		t.Fatal("UPDATE observation_evidence succeeded; want the append-only trigger to raise")
	}
	if _, err := f.l.pool.Exec(ctx, `DELETE FROM observation_evidence`); err == nil {
		t.Fatal("DELETE FROM observation_evidence succeeded; want the append-only trigger to raise")
	}
	// The Gateway admin task view.
	code, body = f.l.callAs(t, http.MethodGet, "/api/v1/admin/gateways/"+f.gw.GatewayID+"/tasks", f.admin, nil)
	if code != http.StatusOK || !strings.Contains(string(body), task.TaskID) || !strings.Contains(string(body), `"done":1`) {
		t.Fatalf("admin tasks = %d %s", code, body)
	}
}

// reorderJSON re-encodes v with object keys in reverse order and extra
// whitespace, the same JSON value in another byte form.
func reorderJSON(t *testing.T, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	var enc func(v any)
	enc = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			for i := 0; i < len(keys); i++ {
				for j := i + 1; j < len(keys); j++ {
					if keys[j] > keys[i] {
						keys[i], keys[j] = keys[j], keys[i]
					}
				}
			}
			b.WriteString("{ ")
			for i, k := range keys {
				if i > 0 {
					b.WriteString(" , ")
				}
				kb, _ := json.Marshal(k)
				b.Write(kb)
				b.WriteString(" : ")
				enc(x[k])
			}
			b.WriteString(" }")
		case []any:
			b.WriteString("[ ")
			for i, e := range x {
				if i > 0 {
					b.WriteString(", ")
				}
				enc(e)
			}
			b.WriteString(" ]")
		default:
			vb, _ := json.Marshal(x)
			b.Write(vb)
		}
	}
	enc(v)
	return b.Bytes()
}

// TestLive_Observation_SourceDecidesTheObserver: gateway creates a
// Gateway task, none creates nothing, and the retired control_plane is
// refused with 400 source_retired and never read back
// (secrets-bridge/gateway#13). No source starts a control-plane
// observer: no request gets a gitops_observations row. The environment
// column is read once per request in OnJobCompleted.
func TestLive_Observation_SourceDecidesTheObserver(t *testing.T) {
	f := newObsFixture(t)

	// gateway (set by the fixture).
	gwReq, _ := f.executeOn(t, f.env, f.secret)
	if n := len(f.taskRows(t, gwReq)); n != 1 {
		t.Fatalf("gateway source: tasks = %d; want 1", n)
	}
	if n := f.gitopsRows(t, gwReq); n != 0 {
		t.Fatalf("gateway source: gitops_observations rows = %d; want 0", n)
	}

	// control_plane is retired: refused, nothing changes.
	code, body := f.l.callAs(t, http.MethodPut, "/api/v1/admin/environments/"+f.env.String()+"/observation-source", f.admin,
		map[string]any{"observation_source": "control_plane"})
	if code != http.StatusBadRequest || errCode(t, body) != "source_retired" {
		t.Fatalf("set control_plane = %d %s; want 400 source_retired", code, body)
	}
	code, body = f.l.callAs(t, http.MethodGet, "/api/v1/admin/environments/"+f.env.String()+"/observation-source", f.admin, nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"observation_source":"gateway"`) {
		t.Fatalf("get after refused control_plane = %d %s; want gateway unchanged", code, body)
	}
	// Even a row written around the api cannot hold it.
	if _, err := f.l.pool.Exec(t.Context(), `UPDATE environments SET observation_source = 'control_plane' WHERE id = $1`, f.env); err == nil {
		t.Fatal("the schema accepted observation_source = control_plane")
	}

	// none.
	f.setSource(t, f.env, "none")
	noneReq, _ := f.executeOn(t, f.env, f.secret)
	if n := len(f.taskRows(t, noneReq)); n != 0 {
		t.Fatalf("none source: tasks = %d; want 0", n)
	}
	if n := f.gitopsRows(t, noneReq); n != 0 {
		t.Fatalf("none source: gitops_observations rows = %d; want 0", n)
	}
	found := false
	for _, r := range f.l.auditRows(t, "request.observation_skipped") {
		found = found || (r.Resource == "request:"+noneReq.String() && r.Metadata["reason"] == "source_none")
	}
	if !found {
		t.Fatal("none source: no request.observation_skipped source_none row")
	}
	if rows := f.l.auditRows(t, "request.gitops_observation_skipped"); len(rows) != 0 {
		t.Fatalf("request.gitops_observation_skipped = %+v; want none", rows)
	}

	// A new environment starts at none.
	var src string
	if err := f.l.pool.QueryRow(t.Context(), `INSERT INTO environments (project_id, name, type, kind)
		VALUES ($1, 'tenant-a-new', 'uat', 'non_prod') RETURNING observation_source`, f.proj).Scan(&src); err != nil || src != "none" {
		t.Fatalf("new environment observation_source = %q, %v; want none", src, err)
	}

	// Gateway with no binding for the secret: no task, audited.
	f.setSource(t, f.env, "gateway")
	other := f.addSecret(t, f.proj)
	unbound, _ := f.executeOn(t, f.env, other)
	if n := len(f.taskRows(t, unbound)); n != 0 {
		t.Fatalf("no binding: tasks = %d; want 0", n)
	}
	found = false
	for _, r := range f.l.auditRows(t, "request.observation_skipped") {
		found = found || (r.Resource == "request:"+unbound.String() && r.Metadata["reason"] == "no_gateway_binding")
	}
	if !found {
		t.Fatal("no binding: no request.observation_skipped no_gateway_binding row")
	}
	ev, _ := f.requestEvidence(t, unbound)
	if ev.Rollup != "none" || len(ev.Tasks) != 0 {
		t.Fatalf("no binding: request evidence rollup %q tasks %d; want none, 0", ev.Rollup, len(ev.Tasks))
	}
}

// TestLive_Observation_ConcurrentClaimsNeverShareATask: one claim holds a
// task row locked from another transaction; the next claim skips it
// (FOR UPDATE SKIP LOCKED) and leases a different task, never the held
// one; and many replicas claiming at once lease each task at most once.
func TestLive_Observation_ConcurrentClaimsNeverShareATask(t *testing.T) {
	f := newObsFixture(t)
	ctx := t.Context()
	secrets := []uuid.UUID{f.secret}
	for range 5 {
		s := f.addSecret(t, f.proj)
		f.bind(t, f.gw.GatewayID, f.connID, f.env, s, "payments-api")
		secrets = append(secrets, s)
	}
	var reqs []uuid.UUID
	for _, s := range secrets {
		r, _ := f.executeOn(t, f.env, s)
		f.makeClaimable(t, r)
		reqs = append(reqs, r)
	}
	all, err := storage.NewObservationTasks(f.l.pool).ListForGateway(ctx, uuid.MustParse(f.gw.GatewayID), "", 100)
	if err != nil || len(all) != 6 {
		t.Fatalf("tasks = %d, %v; want 6", len(all), err)
	}
	// Order the queue so the held task is the one a claim would pick first.
	held := all[len(all)-1].ID
	if _, err := f.l.pool.Exec(ctx, `UPDATE observation_tasks SET not_before = now() - interval '1 hour' WHERE id = $1`, held); err != nil {
		t.Fatal(err)
	}
	tx, err := f.l.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM observation_tasks WHERE id = $1 FOR UPDATE`, held); err != nil {
		t.Fatal(err)
	}
	code, task := f.claim(t, uuid.NewString())
	if code != http.StatusOK || task.TaskID == held.String() {
		_ = tx.Rollback(ctx)
		t.Fatalf("claim with the first task locked = %d %+v; want a different task", code, task)
	}
	_ = tx.Rollback(ctx)

	// Many replicas at once.
	var mu sync.Mutex
	seen := map[string]int{task.TaskID: 1}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, w := f.claim(t, uuid.NewString())
			if c == http.StatusOK {
				mu.Lock()
				seen[w.TaskID]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != 6 {
		t.Fatalf("leased tasks = %d; want all 6", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("task %s leased %d times", id, n)
		}
	}
	// At most one live attempt per task.
	var overlap int
	if err := f.l.pool.QueryRow(ctx, `SELECT count(*) FROM (SELECT task_id FROM observation_task_attempts
		WHERE outcome IS NULL GROUP BY task_id HAVING count(*) > 1) x`).Scan(&overlap); err != nil || overlap != 0 {
		t.Fatalf("tasks with more than one open attempt = %d, %v", overlap, err)
	}
	_ = reqs
}

// TestLive_Observation_LeaseExpiryFencesTheOldAttempt: an expired lease
// refuses its own late result (lease_expired), a re-claim mints a new
// attempt and closes the old one, and the old attempt's result, renew
// and release are refused (attempt_superseded) while the new one is
// accepted.
func TestLive_Observation_LeaseExpiryFencesTheOldAttempt(t *testing.T) {
	f := newObsFixture(t)
	ctx := t.Context()
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	replicaA, replicaB := uuid.NewString(), uuid.NewString()
	_, a := f.claim(t, replicaA)
	resA := argoResult(a, f.gw.GatewayID, replicaA)

	expire := func() {
		if _, err := f.l.pool.Exec(ctx, `UPDATE observation_tasks SET lease_expires_at = now() - interval '1 second',
			leased_at = now() - interval '61 seconds' WHERE request_id = $1`, reqID); err != nil {
			t.Fatal(err)
		}
	}
	expire()
	// Same replica, no re-claim, after expiry: lease_expired.
	if code, body := f.post(t, a.TaskID, resA); code != http.StatusConflict || errCode(t, body) != "lease_expired" {
		t.Fatalf("late result before re-claim = %d %s; want 409 lease_expired", code, body)
	}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+f.gw.GatewayID+"/tasks/"+a.TaskID+"/lease", f.gwHdr,
		map[string]any{"replica_id": replicaA, "attempt_id": a.AttemptID}); code != http.StatusConflict || errCode(t, body) != "lease_expired" {
		t.Fatalf("renew after expiry = %d %s; want 409 lease_expired", code, body)
	}
	// Another replica re-claims: new attempt.
	code, b := f.claim(t, replicaB)
	if code != http.StatusOK || b.TaskID != a.TaskID || b.AttemptID == a.AttemptID || b.AttemptCount != 2 {
		t.Fatalf("re-claim = %d %+v; want the same task, a new attempt, attempt_count 2", code, b)
	}
	var outcome string
	if err := f.l.pool.QueryRow(ctx, `SELECT outcome FROM observation_task_attempts WHERE attempt_id = $1`, a.AttemptID).Scan(&outcome); err != nil || outcome != "lease_expired" {
		t.Fatalf("old attempt outcome = %q, %v; want lease_expired", outcome, err)
	}
	if rows := f.l.auditRows(t, "observation.task.lease_expired"); len(rows) != 1 {
		t.Fatalf("observation.task.lease_expired rows = %d; want 1", len(rows))
	}
	// The old attempt is fenced everywhere.
	if code, body := f.post(t, a.TaskID, resA); code != http.StatusConflict || errCode(t, body) != "attempt_superseded" {
		t.Fatalf("old attempt result after re-claim = %d %s; want 409 attempt_superseded", code, body)
	}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+f.gw.GatewayID+"/tasks/"+a.TaskID+"/lease", f.gwHdr,
		map[string]any{"replica_id": replicaA, "attempt_id": a.AttemptID}); code != http.StatusConflict || errCode(t, body) != "attempt_superseded" {
		t.Fatalf("old attempt renew = %d %s; want 409 attempt_superseded", code, body)
	}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+f.gw.GatewayID+"/tasks/"+a.TaskID+"/release", f.gwHdr,
		map[string]any{"replica_id": replicaA, "attempt_id": a.AttemptID, "reason": "shutdown"}); code != http.StatusConflict || errCode(t, body) != "attempt_superseded" {
		t.Fatalf("old attempt release = %d %s; want 409 attempt_superseded", code, body)
	}
	if n := f.evidenceCount(t); n != 0 {
		t.Fatalf("evidence rows = %d; want 0", n)
	}
	// The new attempt is accepted.
	if code, body := f.post(t, b.TaskID, argoResult(b, f.gw.GatewayID, replicaB)); code != http.StatusOK {
		t.Fatalf("new attempt result = %d %s", code, body)
	}
	// Lease expiry never counts as a failure.
	tk := f.taskRows(t, reqID)[0]
	if tk.FailureCount != 0 {
		t.Fatalf("failure_count = %d; want 0 after a lease expiry", tk.FailureCount)
	}
}

// TestLive_Observation_ReleaseIsNotAFailure: release queues the task,
// a second release of the same attempt is a no-op, after a re-claim it
// is superseded, and failure_count never moves.
func TestLive_Observation_ReleaseIsNotAFailure(t *testing.T) {
	f := newObsFixture(t)
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	for i := range 6 {
		replica := uuid.NewString()
		code, task := f.claim(t, replica)
		if code != http.StatusOK || task.AttemptCount != i+1 {
			t.Fatalf("claim %d = %d %+v", i, code, task)
		}
		rel := map[string]any{"replica_id": replica, "attempt_id": task.AttemptID, "reason": "shutdown"}
		path := "/api/v1/gateways/" + f.gw.GatewayID + "/tasks/" + task.TaskID + "/release"
		for range 2 {
			if code, body := f.l.callAs(t, http.MethodPost, path, f.gwHdr, rel); code != http.StatusNoContent {
				t.Fatalf("release = %d %s; want 204 (twice)", code, body)
			}
		}
	}
	tk := f.taskRows(t, reqID)[0]
	if tk.State != storage.ObservationTaskQueued || tk.FailureCount != 0 || tk.Verdict != storage.ObservationVerdictPending {
		t.Fatalf("after six rolling restarts: state %s failure_count %d verdict %s; want queued, 0, pending", tk.State, tk.FailureCount, tk.Verdict)
	}
	// Bad reason: 400.
	code, task := f.claim(t, uuid.NewString())
	if code != http.StatusOK {
		t.Fatalf("claim = %d", code)
	}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+f.gw.GatewayID+"/tasks/"+task.TaskID+"/release", f.gwHdr,
		map[string]any{"replica_id": f.replica, "attempt_id": task.AttemptID, "reason": "because"}); code != http.StatusBadRequest {
		t.Fatalf("release with a free-text reason = %d %s; want 400", code, body)
	}
}

// TestLive_Observation_EvidenceBinding is the security gate from
// secrets-bridge/gateway#13: a result is accepted only for an attempt
// the CP dispatched to that same Gateway, for the connector and target
// bound in the request's own environment and project.
func TestLive_Observation_EvidenceBinding(t *testing.T) {
	f := newObsFixture(t)
	ctx := t.Context()

	// A second binding in the same environment (orders-api for another
	// secret), and another tenant: a second project and environment with
	// billing-api bound.
	ordersSecret := f.addSecret(t, f.proj)
	f.bind(t, f.gw.GatewayID, f.connID, f.env, ordersSecret, "orders-api")
	proj2, env2, sec2 := f.seedScope(t)
	f.bind(t, f.gw.GatewayID, f.connID, env2, sec2, "billing-api")
	f.setSource(t, env2, "gateway")

	// Another Gateway with the same connector and target names.
	gwB, connB := f.gatewayReady(t, "obs-gw-b")
	f.bind(t, gwB.GatewayID, connB, f.env, f.secret, "payments-api")

	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	// Gateway A claims its task (payments-api).
	var task *wireTask
	for {
		code, w := f.claim(t, uuid.NewString())
		if code != http.StatusOK {
			t.Fatalf("gateway A claim = %d", code)
		}
		if w.ConnectorRefs[0].TargetID == "payments-api" {
			task = w
			break
		}
	}
	good := func() map[string]any { return argoResult(task, f.gw.GatewayID, f.replica) }

	// 1. Another Gateway posting to this task: 404, as if it did not exist.
	foreign := good()
	foreign["gateway_id"] = gwB.GatewayID
	if code, body := f.postResult(t, gwB.GatewayID, gwB.GatewaySecret, task.TaskID, foreign); code != http.StatusNotFound {
		t.Fatalf("another gateway's task = %d %s; want 404", code, body)
	}
	// ... and the body naming gateway A under gateway B's credential is a
	// path/body mismatch.
	if code, body := f.postResult(t, gwB.GatewayID, gwB.GatewaySecret, task.TaskID, good()); code != http.StatusBadRequest {
		t.Fatalf("body gateway_id differs from the path = %d %s; want 400", code, body)
	}
	// 2. Wrong attempt: one the CP never minted.
	wrong := good()
	wrong["attempt_id"] = uuid.NewString()
	if code, body := f.post(t, task.TaskID, wrong); code != http.StatusConflict || errCode(t, body) != "attempt_superseded" {
		t.Fatalf("wrong attempt = %d %s; want 409 attempt_superseded", code, body)
	}
	// 3. A target from another binding in the same environment.
	other := good()
	stage0(other)["source"].(map[string]any)["target_id"] = "orders-api"
	stage0(other)["resource"].(map[string]any)["name"] = "orders-api"
	if code, body := f.post(t, task.TaskID, other); code != http.StatusUnprocessableEntity || errCode(t, body) != "schema_violation" {
		t.Fatalf("target of another binding = %d %s; want 422 schema_violation", code, body)
	}
	// 4. Another tenant's app (bound in another project and environment).
	tenant := good()
	stage0(tenant)["source"].(map[string]any)["target_id"] = "billing-api"
	stage0(tenant)["resource"].(map[string]any)["name"] = "billing-api"
	if code, body := f.post(t, task.TaskID, tenant); code != http.StatusUnprocessableEntity || errCode(t, body) != "schema_violation" {
		t.Fatalf("another tenant's app = %d %s; want 422 schema_violation", code, body)
	}
	// 5. A connector name the Gateway does not have.
	conn := good()
	stage0(conn)["source"].(map[string]any)["connector_id"] = "argocd-other"
	if code, body := f.post(t, task.TaskID, conn); code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown connector = %d %s; want 422", code, body)
	}
	if n := f.evidenceCount(t); n != 0 {
		t.Fatalf("evidence rows after refused results = %d; want 0", n)
	}
	reasons := map[string]int{}
	for _, r := range f.l.auditRows(t, "observation.evidence.rejected") {
		reasons[r.Metadata["reason"].(string)]++
	}
	if reasons["foreign_task"] < 1 || reasons["unknown_attempt"] != 1 || reasons["scope"] != 3 {
		t.Fatalf("rejection audit reasons = %v", reasons)
	}

	// 6. Another tenant's request: a task for the second tenant is never
	// handed out under the first tenant's binding, and its evidence
	// cannot be posted against the first tenant's task.
	req2, _ := f.execute(t, f.agentBase, f.agentHdr, proj2, env2, sec2)
	t2 := f.taskRows(t, req2)
	if len(t2) != 1 || t2[0].EnvironmentID != env2 || t2[0].ConnectorRefs[0].TargetID != "billing-api" {
		t.Fatalf("second tenant's task = %+v", t2)
	}
	// The attempt still accepts the right evidence.
	if code, body := f.post(t, task.TaskID, good()); code != http.StatusOK {
		t.Fatalf("bound evidence = %d %s", code, body)
	}

	// 7. Gateway B cannot claim gateway A's tasks: its claims see only its
	// own task for the same request.
	f.makeClaimable(t, reqID)
	code, _, wb, _ := f.claimAs(t, gwB.GatewayID, gwB.GatewaySecret, uuid.NewString())
	if code != http.StatusOK {
		t.Fatalf("gateway B claim = %d", code)
	}
	var owner string
	if err := f.l.pool.QueryRow(ctx, `SELECT gateway_id::text FROM observation_tasks WHERE id = $1`, wb.TaskID).Scan(&owner); err != nil || owner != gwB.GatewayID {
		t.Fatalf("gateway B leased task of %s; want its own", owner)
	}
}

// TestLive_Observation_ResultSchemaIsClosed: no secret- or value-shaped
// data fits a result. Unknown fields, free text, oversized strings and
// broken conditional rules are 422 with nothing stored and the attempt
// still leased; a fixed body is then accepted.
func TestLive_Observation_ResultSchemaIsClosed(t *testing.T) {
	f := newObsFixture(t)
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	_, task := f.claim(t, f.replica)
	const canary = "hunter2-canary-value"

	cases := map[string]func(m map[string]any){
		"top-level data field": func(m map[string]any) { m["data"] = map[string]any{"DB_PASSWORD": canary} },
		"stage value field":    func(m map[string]any) { stage0(m)["value"] = canary },
		"facts secret field":   func(m map[string]any) { stage0(m)["facts"].(map[string]any)["secret"] = canary },
		"free-text caveat":     func(m map[string]any) { stage0(m)["caveats"] = []string{"argocd_health_not_proof", canary} },
		"free-text message":    func(m map[string]any) { stage0(m)["message"] = "pod restarted with " + canary },
		"oversized revision": func(m map[string]any) {
			stage0(m)["facts"].(map[string]any)["sync_revision"] = strings.Repeat("a", 200)
		},
		"revision with space":    func(m map[string]any) { stage0(m)["facts"].(map[string]any)["sync_revision"] = "rev " + canary },
		"health enum":            func(m map[string]any) { stage0(m)["facts"].(map[string]any)["health_status"] = canary },
		"missing caveat":         func(m map[string]any) { stage0(m)["caveats"] = []string{} },
		"argocd high confidence": func(m map[string]any) { stage0(m)["confidence"] = "high" },
		"argocd linkage":         func(m map[string]any) { stage0(m)["linkage"] = "time_ordered" },
		"error with facts":       func(m map[string]any) { stage0(m)["outcome"] = "error"; stage0(m)["error_code"] = "internal" },
		"wrong kind":             func(m map[string]any) { stage0(m)["resource"].(map[string]any)["kind"] = "Deployment" },
		"url namespace":          func(m map[string]any) { stage0(m)["resource"].(map[string]any)["namespace"] = "https://x" },
		"stage not in task": func(m map[string]any) {
			st := stage0(m)
			st["stage"] = "eso_sync"
			st["source"].(map[string]any)["api"] = "kubernetes"
		},
		"schema version":    func(m map[string]any) { m["schema_version"] = "gateway.evidence-result/v2" },
		"refused and stage": func(m map[string]any) { m["attempt_status"] = "refused"; m["refusal_reason"] = "unknown_connector" },
		"refusal free text": func(m map[string]any) {
			m["attempt_status"] = "refused"
			m["refusal_reason"] = canary
			m["stages"] = []any{}
		},
		"float offset":  func(m map[string]any) { m["clock"] = map[string]any{"cp_offset_ms": 1.5} },
		"missing clock": func(m map[string]any) { delete(m, "clock") },
		"duplicate stage": func(m map[string]any) {
			m["stages"] = []map[string]any{stage0(m), stage0(m)}
		},
	}
	for name, mutate := range cases {
		body := argoResult(task, f.gw.GatewayID, f.replica)
		mutate(body)
		code, raw := f.post(t, task.TaskID, body)
		if code != http.StatusUnprocessableEntity || errCode(t, raw) != "schema_violation" {
			t.Errorf("%s = %d %s; want 422 schema_violation", name, code, raw)
		}
		if strings.Contains(string(raw), canary) {
			t.Errorf("%s: response echoes request content: %s", name, raw)
		}
	}
	// Out of window.
	late := argoResult(task, f.gw.GatewayID, f.replica)
	stage0(late)["observed_at"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if code, raw := f.post(t, task.TaskID, late); code != http.StatusUnprocessableEntity || errCode(t, raw) != "evidence_out_of_window" {
		t.Errorf("observed_at an hour ahead = %d %s; want 422 evidence_out_of_window", code, raw)
	}
	// Over 64 KiB: 413 before decoding.
	big := argoResult(task, f.gw.GatewayID, f.replica)
	big["pad"] = strings.Repeat("x", 70<<10)
	if code, raw := f.post(t, task.TaskID, big); code != http.StatusRequestEntityTooLarge {
		t.Errorf("70 KiB result = %d %s; want 413", code, raw)
	}
	if n := f.evidenceCount(t); n != 0 {
		t.Fatalf("evidence rows = %d; want 0", n)
	}
	tk := f.taskRows(t, reqID)[0]
	if tk.State != storage.ObservationTaskLeased || tk.CurrentAttemptID == nil || tk.CurrentAttemptID.String() != task.AttemptID {
		t.Fatalf("after 422s the attempt must stay leased: %+v", tk)
	}
	// A fixed body within the lease is accepted.
	if code, raw := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusOK {
		t.Fatalf("valid result = %d %s", code, raw)
	}
	// The canary reached no table and no audit row.
	var n int
	if err := f.l.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM observation_evidence WHERE body::text LIKE '%'||$1||'%') +
		(SELECT count(*) FROM observation_task_attempts WHERE result_response::text LIKE '%'||$1||'%') +
		(SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%'||$1||'%')`, canary).Scan(&n); err != nil || n != 0 {
		t.Fatalf("canary rows = %d, %v; want 0", n, err)
	}
}

// TestLive_Observation_OfflineGatewayTimesOut: a Gateway that never
// claims leaves the task pending; at the deadline it is timed_out with
// reason gateway_unavailable, never observed, verified or failed.
func TestLive_Observation_OfflineGatewayTimesOut(t *testing.T) {
	f := newObsFixture(t)
	ctx := t.Context()
	reqID, _ := f.executeOn(t, f.env, f.secret)
	ev, _ := f.requestEvidence(t, reqID)
	if ev.Rollup != "pending" || ev.Tasks[0].Verdict != "pending" || len(ev.Tasks[0].Stages) != 0 {
		t.Fatalf("before the deadline: rollup %q verdict %q stages %d; want pending, pending, 0", ev.Rollup, ev.Tasks[0].Verdict, len(ev.Tasks[0].Stages))
	}
	// The Gateway goes quiet: last seen before the task, then the
	// deadline passes.
	if _, err := f.l.pool.Exec(ctx, `UPDATE gateways SET last_seen_at = now() - interval '2 hours' WHERE id = $1`, f.gw.GatewayID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.pool.Exec(ctx, `UPDATE observation_tasks SET created_at = now() - interval '1 hour',
		deadline_at = now() - interval '1 second' WHERE request_id = $1`, reqID); err != nil {
		t.Fatal(err)
	}
	// The read shows the overdue task as timed out (api#297) but writes
	// nothing: the row stays open and no audit row is added. Closing it
	// is the worker's deadline sweeper.
	before := f.taskRows(t, reqID)[0]
	ev, body := f.requestEvidence(t, reqID)
	if ev.Rollup != "timed_out" || ev.Tasks[0].State != "done" || ev.Tasks[0].Verdict != "timed_out" ||
		ev.Tasks[0].VerdictReason != "gateway_unavailable" || !ev.Tasks[0].TimedOutAtRead || len(ev.Tasks[0].Stages) != 0 {
		t.Fatalf("after the deadline = %s; want timed_out, gateway_unavailable, timed_out_at_read, no stage", body)
	}
	after := f.taskRows(t, reqID)[0]
	if after.State != storage.ObservationTaskQueued || after.Verdict != storage.ObservationVerdictPending ||
		after.VerdictReason != "" || after.TerminalAt != nil || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("task row after the read = %s %s %q terminal %v updated %v (was %v); want unchanged", after.State,
			after.Verdict, after.VerdictReason, after.TerminalAt, after.UpdatedAt, before.UpdatedAt)
	}
	if rows := f.l.auditRows(t, "observation.task.timed_out"); len(rows) != 0 {
		t.Fatalf("observation.task.timed_out rows after a read = %d; want 0", len(rows))
	}
	// The sweeper's storage call closes the row the same way; the read
	// then shows the stored verdict, no longer computed.
	if closed, err := storage.NewObservationTasks(f.l.pool).ExpireDeadlines(ctx, time.Now(), &reqID, 10); err != nil || len(closed) != 1 {
		t.Fatalf("sweep = %d, %v; want 1 closed", len(closed), err)
	}
	ev, body = f.requestEvidence(t, reqID)
	if ev.Rollup != "timed_out" || ev.Tasks[0].State != "done" || ev.Tasks[0].VerdictReason != "gateway_unavailable" || ev.Tasks[0].TimedOutAtRead {
		t.Fatalf("after the sweep = %s; want stored timed_out, gateway_unavailable, not computed", body)
	}
	// A claim never hands out a task past its deadline.
	if code, _ := f.claim(t, uuid.NewString()); code != http.StatusNoContent {
		t.Fatalf("claim after the deadline = %d; want 204", code)
	}

	// A result that arrives after the deadline on a live lease: 409
	// task_closed, and the task is timed_out in the same transaction.
	req2, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, req2)
	_, task := f.claim(t, f.replica)
	if _, err := f.l.pool.Exec(ctx, `UPDATE observation_tasks SET deadline_at = now() - interval '1 second' WHERE request_id = $1`, req2); err != nil {
		t.Fatal(err)
	}
	// A leased task past its deadline on a Gateway seen since: shown as
	// deadline_reached, the lease untouched.
	if code, body := f.heartbeat(t, f.gw.GatewayID, f.gw.GatewaySecret, f.replica); code != http.StatusOK {
		t.Fatalf("heartbeat = %d %s", code, body)
	}
	ev, body = f.requestEvidence(t, req2)
	if ev.Tasks[0].Verdict != "timed_out" || ev.Tasks[0].VerdictReason != "deadline_reached" || !ev.Tasks[0].TimedOutAtRead {
		t.Fatalf("leased past the deadline = %s; want timed_out, deadline_reached, timed_out_at_read", body)
	}
	if tk := f.taskRows(t, req2)[0]; tk.State != storage.ObservationTaskLeased || tk.CurrentAttemptID == nil {
		t.Fatalf("leased row after the read = %s attempt %v; want leased with its attempt", tk.State, tk.CurrentAttemptID)
	}
	if code, raw := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusConflict || errCode(t, raw) != "task_closed" {
		t.Fatalf("result after the deadline = %d %s; want 409 task_closed", code, raw)
	}
	tk := f.taskRows(t, req2)[0]
	if tk.Verdict != storage.ObservationVerdictTimedOut || tk.VerdictReason != "deadline_reached" || f.evidenceCount(t) != 0 {
		t.Fatalf("after a late result: verdict %s reason %s evidence %d; want timed_out, deadline_reached, 0", tk.Verdict, tk.VerdictReason, f.evidenceCount(t))
	}
}

// TestLive_Observation_ProgressingIsNotHealthy: Argo CD Progressing, or
// Healthy reconciled before the write, is not_observed; the task is
// rescheduled and stays pending. Argo CD errors count toward max
// failures and end dead / unverified, never failed.
func TestLive_Observation_ProgressingIsNotHealthy(t *testing.T) {
	f := newObsFixture(t)
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)

	_, task := f.claim(t, f.replica)
	res := argoResult(task, f.gw.GatewayID, f.replica)
	stage0(res)["outcome"] = "not_observed"
	stage0(res)["facts"].(map[string]any)["health_status"] = "Progressing"
	code, body := f.post(t, task.TaskID, res)
	var resp map[string]string
	mustJSON(t, body, &resp)
	if code != http.StatusOK || resp["task_state"] != "queued" || resp["verdict"] != "pending" || resp["next"] != "rescheduled" {
		t.Fatalf("progressing = %d %s; want accepted, queued, pending, rescheduled", code, body)
	}
	tk := f.taskRows(t, reqID)[0]
	if d := time.Until(tk.NotBefore); d < 10*time.Second || d > 16*time.Second {
		t.Fatalf("reschedule backoff = %v; want about 15s", d)
	}

	// Healthy and Synced but reconciled before the write: the Gateway
	// claims observed, the CP keeps not_observed and audits the mismatch.
	f.makeClaimable(t, reqID)
	_, task = f.claim(t, f.replica)
	res = argoResult(task, f.gw.GatewayID, f.replica)
	stage0(res)["facts"].(map[string]any)["reconciled_at"] = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	code, body = f.post(t, task.TaskID, res)
	mustJSON(t, body, &resp)
	if code != http.StatusOK || resp["verdict"] != "pending" {
		t.Fatalf("stale reconcile = %d %s; want pending", code, body)
	}
	if rows := f.l.auditRows(t, "gateway.evidence.outcome_mismatch"); len(rows) != 1 || rows[0].Metadata["cp_outcome"] != "not_observed" {
		t.Fatalf("outcome mismatch audit = %+v", rows)
	}

	// Five Argo CD errors (and refusals) end the task dead, unverified.
	for i := range 5 {
		f.makeClaimable(t, reqID)
		_, task = f.claim(t, f.replica)
		res = argoResult(task, f.gw.GatewayID, f.replica)
		if i%2 == 0 {
			st := stage0(res)
			st["outcome"], st["confidence"], st["error_code"] = "error", "none", "connector_unreachable"
			delete(st, "facts")
			delete(st, "resource")
		} else {
			res["attempt_status"], res["refusal_reason"], res["stages"] = "refused", "unknown_connector", []any{}
		}
		if code, body := f.post(t, task.TaskID, res); code != http.StatusOK {
			t.Fatalf("error pass %d = %d %s", i, code, body)
		}
	}
	tk = f.taskRows(t, reqID)[0]
	if tk.State != storage.ObservationTaskDead || tk.Verdict != storage.ObservationVerdictUnverified || tk.VerdictReason != "gateway_errors" {
		t.Fatalf("after five errors: %s %s %s; want dead, unverified, gateway_errors", tk.State, tk.Verdict, tk.VerdictReason)
	}
}

// TestLive_Observation_RevokeAndDisableRequeueLeasedTasks: disabling or
// revoking a Gateway moves its leased tasks back to queued in the same
// transaction (attempts closed), and its late results are refused.
func TestLive_Observation_RevokeAndDisableRequeueLeasedTasks(t *testing.T) {
	f := newObsFixture(t)
	ctx := t.Context()
	reqID, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, reqID)
	_, task := f.claim(t, f.replica)

	code, body := f.l.callAs(t, http.MethodPut, "/api/v1/admin/gateways/"+f.gw.GatewayID+"/enabled", f.admin, map[string]any{"enabled": false})
	if code != http.StatusOK || !strings.Contains(string(body), `"status":"disabled"`) {
		t.Fatalf("disable = %d %s", code, body)
	}
	tk := f.taskRows(t, reqID)[0]
	if tk.State != storage.ObservationTaskQueued || tk.CurrentAttemptID != nil {
		t.Fatalf("after disable: %s attempt %v; want queued, none", tk.State, tk.CurrentAttemptID)
	}
	var outcome string
	if err := f.l.pool.QueryRow(ctx, `SELECT outcome FROM observation_task_attempts WHERE attempt_id = $1`, task.AttemptID).Scan(&outcome); err != nil || outcome != "cancelled" {
		t.Fatalf("attempt after disable = %q, %v; want cancelled", outcome, err)
	}
	if code, _ := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusUnauthorized {
		t.Fatalf("result from a disabled gateway = %d; want 401", code)
	}
	if code, _ := f.claim(t, f.replica); code != http.StatusUnauthorized {
		t.Fatalf("claim from a disabled gateway = %d; want 401", code)
	}
	if rows := f.l.auditRows(t, "gateway.disable"); len(rows) != 1 || rows[0].Metadata["tasks_requeued"] != float64(1) {
		t.Fatalf("gateway.disable audit = %+v", rows)
	}

	// Enable, claim again (new attempt), then revoke.
	if code, body := f.l.callAs(t, http.MethodPut, "/api/v1/admin/gateways/"+f.gw.GatewayID+"/enabled", f.admin, map[string]any{"enabled": true}); code != http.StatusOK ||
		!strings.Contains(string(body), `"status":"active"`) {
		t.Fatalf("enable = %d %s", code, body)
	}
	f.makeClaimable(t, reqID)
	code, task2 := f.claim(t, f.replica)
	if code != http.StatusOK || task2.AttemptCount != 2 {
		t.Fatalf("claim after enable = %d %+v", code, task2)
	}
	// The disabled attempt stays fenced on the re-enabled Gateway.
	if code, body := f.post(t, task.TaskID, argoResult(task, f.gw.GatewayID, f.replica)); code != http.StatusConflict || errCode(t, body) != "attempt_superseded" {
		t.Fatalf("pre-disable attempt after enable = %d %s; want 409 attempt_superseded", code, body)
	}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/admin/gateways/"+f.gw.GatewayID+"/revoke", f.admin, nil); code != http.StatusOK {
		t.Fatalf("revoke = %d %s", code, body)
	}
	tk = f.taskRows(t, reqID)[0]
	if tk.State != storage.ObservationTaskQueued || tk.CurrentAttemptID != nil {
		t.Fatalf("after revoke: %s; want queued", tk.State)
	}
	if code, _ := f.post(t, task2.TaskID, argoResult(task2, f.gw.GatewayID, f.replica)); code != http.StatusUnauthorized {
		t.Fatalf("result from a revoked gateway = %d; want 401", code)
	}
	if rows := f.l.auditRows(t, "gateway.revoke"); len(rows) != 1 || rows[0].Metadata["tasks_requeued"] != float64(1) {
		t.Fatalf("gateway.revoke audit = %+v", rows)
	}
	// A revoked Gateway cannot be re-enabled.
	if code, _ := f.l.callAs(t, http.MethodPut, "/api/v1/admin/gateways/"+f.gw.GatewayID+"/enabled", f.admin, map[string]any{"enabled": true}); code != http.StatusConflict {
		t.Fatalf("enable a revoked gateway = %d; want 409", code)
	}
	if f.evidenceCount(t) != 0 {
		t.Fatal("evidence stored from a disabled or revoked gateway")
	}
}

// TestLive_Observation_LaterWriteAndSourceSwitchCancel: a second write to
// the same secret cancels the open older task (superseded_by_later_write)
// and its result is refused; switching the environment back to
// none cancels open tasks (source_changed); deleting a binding
// cancels its tasks (binding_removed).
func TestLive_Observation_LaterWriteAndSourceSwitchCancel(t *testing.T) {
	f := newObsFixture(t)
	first, _ := f.executeOn(t, f.env, f.secret)
	f.makeClaimable(t, first)
	_, old := f.claim(t, f.replica)
	second, _ := f.executeOn(t, f.env, f.secret)

	t1 := f.taskRows(t, first)[0]
	if t1.State != storage.ObservationTaskCancelled || t1.Verdict != storage.ObservationVerdictUnverified || t1.VerdictReason != "superseded_by_later_write" {
		t.Fatalf("older task = %s %s %s; want cancelled, unverified, superseded_by_later_write", t1.State, t1.Verdict, t1.VerdictReason)
	}
	if code, body := f.post(t, old.TaskID, argoResult(old, f.gw.GatewayID, f.replica)); code != http.StatusConflict || errCode(t, body) != "task_closed" {
		t.Fatalf("result for a superseded task = %d %s; want 409 task_closed", code, body)
	}
	if rows := f.l.auditRows(t, "observation.task.superseded"); len(rows) != 1 {
		t.Fatalf("observation.task.superseded rows = %d; want 1", len(rows))
	}

	body := f.setSource(t, f.env, "none")
	if !strings.Contains(string(body), `"tasks_cancelled":1`) {
		t.Fatalf("source switch = %s; want one task cancelled", body)
	}
	if t2 := f.taskRows(t, second)[0]; t2.State != storage.ObservationTaskCancelled || t2.VerdictReason != "source_changed" {
		t.Fatalf("after source switch: %s %s; want cancelled, source_changed", t2.State, t2.VerdictReason)
	}
	if code, body := f.l.callAs(t, http.MethodGet, "/api/v1/admin/environments/"+f.env.String()+"/observation-source", f.admin, nil); code != http.StatusOK ||
		!strings.Contains(string(body), `"observation_source":"none"`) {
		t.Fatalf("read observation source = %d %s", code, body)
	}
	noPerm := map[string]string{"Cookie": f.l.sessionFor(t, uuid.New(), "obs-noperm@example.com")}
	if code, _ := f.l.callAs(t, http.MethodGet, "/api/v1/admin/environments/"+f.env.String()+"/observation-source", noPerm, nil); code != http.StatusForbidden {
		t.Fatalf("read observation source without gateway.bind = %d; want 403", code)
	}
	if rows := f.l.auditRows(t, "environment.observation_source.update"); len(rows) < 2 {
		t.Fatalf("environment.observation_source.update rows = %d", len(rows))
	}

	f.setSource(t, f.env, "gateway")
	third, _ := f.executeOn(t, f.env, f.secret)
	if code, body := f.l.callAs(t, http.MethodDelete, "/api/v1/admin/gateway-bindings/"+f.bindingID, f.admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete binding = %d %s", code, body)
	}
	if t3 := f.taskRows(t, third)[0]; t3.State != storage.ObservationTaskCancelled || t3.VerdictReason != "binding_removed" {
		t.Fatalf("after binding delete: %s %s; want cancelled, binding_removed", t3.State, t3.VerdictReason)
	}
	ev, _ := f.requestEvidence(t, third)
	if ev.Rollup != "unverified" {
		t.Fatalf("rollup of a cancelled task = %q; want unverified", ev.Rollup)
	}
}

// TestLive_Observation_ContractVersionUnsupported: a Gateway that lists
// only another contract version gets 409 contract_version_unsupported.
func TestLive_Observation_ContractVersionUnsupported(t *testing.T) {
	f := newObsFixture(t)
	hb := gwHeartbeatBody(uuid.NewString())
	hb["contract_versions"] = []string{"2"}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/gateways/"+f.gw.GatewayID+"/heartbeat", f.gwHdr, hb); code != http.StatusOK {
		t.Fatalf("heartbeat = %d %s", code, body)
	}
	if code, _, _, body := f.claimAs(t, f.gw.GatewayID, f.gw.GatewaySecret, f.replica); code != http.StatusConflict || errCode(t, body) != "contract_version_unsupported" {
		t.Fatalf("claim = %d %s; want 409 contract_version_unsupported", code, body)
	}
	// Bad claim bodies.
	for _, b := range []map[string]any{
		{"replica_id": f.replica, "max_tasks": 2},
		{"replica_id": "not-a-uuid", "max_tasks": 1},
		{"replica_id": f.replica, "max_tasks": 1, "gateway_id": uuid.NewString()},
	} {
		raw, _ := json.Marshal(b)
		if code, _, body := f.l.callRaw(t, http.MethodPost, "/api/v1/gateways/"+f.gw.GatewayID+"/tasks/claim", f.gwHdr, raw); code != http.StatusBadRequest {
			t.Errorf("claim %v = %d %s; want 400", b, code, body)
		}
	}
}
