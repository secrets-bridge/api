package handlers_test

// Regression tests for the agent-facing surface (api#191 H4 + API-18,
// plus API-S-21 / -23 / -24 / -27 and API-N-07 from the 2026-10 audit).
//
// The app below mirrors the /api/v1/agents route chain in cmd/api/main.go:
// Recover at the top, the enroll route, then the AgentAuth-gated
// /agents/:id group with the real Jobs / Wraps / Agents handlers. Every
// service and repository is the production type over a real Postgres +
// Redis, so the tests drive the same code path a running agent hits.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/sealing"
	"github.com/secrets-bridge/api/pkg/storage"
)

type agentSurface struct {
	app      *fiber.App
	pool     *storage.Pool
	rdb      *runtime.Client
	agentSvc *services.AgentService
	reqSvc   *services.RequestService
	jobsR    *storage.SyncJobs
	connID   uuid.UUID
}

type surfaceAgent struct {
	id     uuid.UUID
	secret string
	pub    []byte
	priv   []byte
}

func bootstrapAgentSurface(t *testing.T) *agentSurface {
	return bootstrapAgentSurfaceWith(t, nil)
}

// bootstrapAgentSurfaceWith lets a test wrap the agent repository the
// AgentService reads through (the revocation race test gates Get).
func bootstrapAgentSurfaceWith(t *testing.T, wrap func(*storage.Agents) storage.AgentRepository) *agentSurface {
	t.Helper()
	return bootstrapAgentSurfaceOpts(t, wrap, false)
}

// bootstrapAgentSurfaceOpts also sets the SB_ALLOW_UNSEALED_WRAPS
// break-glass on the wraps handler.
func bootstrapAgentSurfaceOpts(t *testing.T, wrap func(*storage.Agents) storage.AgentRepository, allowUnsealed bool) *agentSurface {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbDSN == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL required; skipping")
	}
	ctx := t.Context()

	cfg := storage.Config{DSN: dbDSN, MaxConns: 16, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	// Keep the system workflow + policy seeds; wipe everything this
	// surface writes. CASCADE also clears the tables that reference
	// these (reveal_sessions, project_provider_connections, ...).
	const wipe = `
		TRUNCATE TABLE
			audit_events, sync_runs, sync_jobs, approvals,
			access_requests, secret_wraps, agents,
			agent_enrollment_tokens, provider_connections, secrets
		RESTART IDENTITY CASCADE;
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}

	rdb, err := runtime.Open(ctx, runtime.Config{
		URL:       redisURL,
		PoolSize:  8,
		Namespace: fmt.Sprintf("sb-agentsurface-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("Open runtime: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	km, err := keymgmt.NewLocalKMS(masterKey)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	agentsR := storage.NewAgents(pool)
	var agentRepo storage.AgentRepository = agentsR
	if wrap != nil {
		agentRepo = wrap(agentsR)
	}
	auditR := storage.NewAuditEvents(pool)
	jobsR := storage.NewSyncJobs(pool)
	workflowsR := storage.NewWorkflows(pool)
	wrapSvc := services.NewWrapService(storage.NewSecretWraps(pool), auditR, km)
	policy := services.NewPolicyEngine(storage.NewPolicies(pool), workflowsR, auditR)
	jobSvc := services.NewJobService(jobsR, auditR)
	reqSvc := services.NewRequestService(storage.NewAccessRequests(pool), storage.NewApprovals(pool),
		wrapSvc, workflowsR, policy, auditR, jobSvc)
	jobSvc.OnCompleted(reqSvc.OnJobCompleted)
	agentSvc := services.NewAgentService(agentRepo, auditR, rdb).
		WithEnrollment(storage.NewAgentEnrollmentTokens(pool), storage.NewProviderConnections(pool))

	var connID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO provider_connections (name, type, auth_method, scope, status)
		VALUES ('tenant-a-uat', 'aws-sm', 'token', '{}'::jsonb, 'active') RETURNING id`).Scan(&connID); err != nil {
		t.Fatalf("seed provider connection: %v", err)
	}

	app := fiber.New()
	app.Use(middleware.Recover(slog.New(slog.NewTextHandler(io.Discard, nil))))
	v1 := app.Group("/api/v1")
	agentsH := handlers.NewAgents(agentSvc)
	jobsH := handlers.NewJobs(jobSvc)
	wrapsH := handlers.NewWraps(reqSvc, wrapSvc, agentsR, km).WithAllowUnsealed(allowUnsealed)
	v1.Post("/agents/enroll", agentsH.Enroll)
	agentRoutes := v1.Group("/agents/:id", middleware.AgentAuth(agentSvc))
	agentRoutes.Post("/jobs/claim", jobsH.Claim)
	agentRoutes.Post("/jobs/:job/complete", jobsH.Complete)
	agentRoutes.Get("/wraps/:wrap_id", wrapsH.Retrieve)
	agentRoutes.Post("/wraps", wrapsH.Create)
	agentRoutes.Post("/dek", wrapsH.IssueDEK)
	secretsH := handlers.NewSecrets(services.NewSecretsService(storage.NewSecrets(pool), auditR).
		WithAgentIdentity(agentsR, storage.NewProviderConnections(pool)))
	agentRoutes.Post("/secrets/bulk", secretsH.BulkUpsert)

	return &agentSurface{
		app: app, pool: pool, rdb: rdb, agentSvc: agentSvc,
		reqSvc: reqSvc, jobsR: jobsR, connID: connID,
	}
}

// mint creates an agent. withKey registers an X25519 public key so
// wrap retrievals come back sealed (the production default).
func (fx *agentSurface) mint(t *testing.T, name string, withKey bool) surfaceAgent {
	t.Helper()
	in := services.MintInput{Name: name}
	var a surfaceAgent
	if withKey {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("x25519: %v", err)
		}
		a.priv = priv.Bytes()
		a.pub = priv.PublicKey().Bytes()
		in.PublicKey = a.pub
		in.PublicKeyAlgorithm = "x25519"
	}
	m, err := fx.agentSvc.Mint(t.Context(), in)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	a.id, a.secret = m.ID, m.AgentSecret
	return a
}

func (fx *agentSurface) call(t *testing.T, method, path, secret string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set("X-Agent-Secret", secret)
	}
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("app.Test %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

type claimedJob struct {
	ID      uuid.UUID      `json:"id"`
	JobType string         `json:"job_type"`
	Payload map[string]any `json:"payload"`
}

func (fx *agentSurface) claim(t *testing.T, a surfaceAgent) claimedJob {
	t.Helper()
	code, body := fx.call(t, http.MethodPost, "/api/v1/agents/"+a.id.String()+"/jobs/claim", a.secret, nil)
	if code != http.StatusOK {
		t.Fatalf("claim = %d (%s); want 200", code, body)
	}
	var j claimedJob
	if err := json.Unmarshal(body, &j); err != nil {
		t.Fatalf("decode claim: %v", err)
	}
	return j
}

func (fx *agentSurface) complete(t *testing.T, a surfaceAgent, jobID uuid.UUID, status, errText string) int {
	t.Helper()
	code, _ := fx.call(t, http.MethodPost,
		"/api/v1/agents/"+a.id.String()+"/jobs/"+jobID.String()+"/complete", a.secret,
		map[string]any{"status": status, "error": errText})
	return code
}

// envelope does what the agent's ReadExecutor does on the sealed path:
// fetch a DEK, AES-256-GCM the value locally, ship ciphertext + nonce +
// the KMS-wrapped DEK. nonce lets a test override the 12-byte nonce.
func (fx *agentSurface) envelope(t *testing.T, a surfaceAgent, value []byte, nonce []byte) map[string]any {
	t.Helper()
	code, body := fx.call(t, http.MethodPost, "/api/v1/agents/"+a.id.String()+"/dek", a.secret, nil)
	if code != http.StatusCreated {
		t.Fatalf("dek = %d (%s)", code, body)
	}
	var dek handlers.DEKResponse
	if err := json.Unmarshal(body, &dek); err != nil {
		t.Fatalf("decode dek: %v", err)
	}
	key, _ := base64.StdEncoding.DecodeString(dek.Plaintext)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	realNonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(realNonce)
	ct := gcm.Seal(nil, realNonce, value, nil)
	if nonce == nil {
		nonce = realNonce
	}
	return map[string]any{
		"algorithm":      "aes-256-gcm",
		"ciphertext":     base64.StdEncoding.EncodeToString(ct),
		"nonce":          base64.StdEncoding.EncodeToString(nonce),
		"dek_ciphertext": dek.Ciphertext,
		"dek_kms_key_id": dek.KeyID,
	}
}

func (fx *agentSurface) postWrap(t *testing.T, a surfaceAgent, reqID uuid.UUID, key string, env map[string]any) (int, []byte) {
	t.Helper()
	return fx.call(t, http.MethodPost, "/api/v1/agents/"+a.id.String()+"/wraps", a.secret,
		map[string]any{"request_id": reqID.String(), "key_name": key, "envelope": env})
}

func (fx *agentSurface) getWrap(t *testing.T, a surfaceAgent, wrapID string) (int, []byte) {
	t.Helper()
	return fx.call(t, http.MethodGet, "/api/v1/agents/"+a.id.String()+"/wraps/"+wrapID, a.secret, nil)
}

func (fx *agentSurface) approvedRead(t *testing.T, keys []string) *storage.AccessRequest {
	t.Helper()
	ctx := t.Context()
	req, err := fx.reqSvc.SubmitRead(ctx, services.ReadInput{
		RequesterID:        "alice",
		ProjectID:          "team-alpha",
		Environment:        "uat",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/team-alpha/uat/db",
		TargetKeys:         keys,
		Justification:      "agent surface regression",
	})
	if err != nil {
		t.Fatalf("SubmitRead: %v", err)
	}
	if _, err := fx.reqSvc.Approve(ctx, req.ID, "bob", ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	out, err := fx.reqSvc.Get(ctx, req.ID)
	if err != nil || out.JobID == nil {
		t.Fatalf("approved read has no job (err=%v)", err)
	}
	return out
}

func (fx *agentSurface) approvedPatch(t *testing.T, kv map[string][]byte) *storage.AccessRequest {
	t.Helper()
	ctx := t.Context()
	req, err := fx.reqSvc.Submit(ctx, services.PatchInput{
		RequesterID:        "alice",
		ProjectID:          "team-alpha",
		Environment:        "uat",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/team-alpha/uat/db",
		KeyValues:          kv,
		Justification:      "agent surface regression",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := fx.reqSvc.Approve(ctx, req.ID, "bob", ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	out, err := fx.reqSvc.Get(ctx, req.ID)
	if err != nil || out.JobID == nil {
		t.Fatalf("approved patch has no job (err=%v)", err)
	}
	return out
}

func (fx *agentSurface) countRows(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := fx.pool.QueryRow(t.Context(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func wrapIDsFromPayload(t *testing.T, j claimedJob) []string {
	t.Helper()
	raw, _ := j.Payload["wraps"].([]any)
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		m, _ := r.(map[string]any)
		id, _ := m["wrap_id"].(string)
		out = append(out, id)
	}
	if len(out) == 0 {
		t.Fatalf("patch job payload carries no wraps: %v", j.Payload)
	}
	return out
}

// ---- happy paths --------------------------------------------------

// Read flow end to end: agent claims, gets a DEK, posts sealed wraps for
// the declared keys, completes; the requester reveals each value once.
func TestAgentSurface_ReadFlow_HappyPath(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	ctx := t.Context()
	a := fx.mint(t, "agent-a", true)
	req := fx.approvedRead(t, []string{"DB_PASSWORD", "DB_USER"})

	job := fx.claim(t, a)
	if job.ID != *req.JobID || job.JobType != "read" {
		t.Fatalf("claimed %s/%s; want read job %s", job.ID, job.JobType, req.JobID)
	}
	values := map[string]string{"DB_PASSWORD": "canary-read-pw-7f3a", "DB_USER": "svc-team-alpha"}
	for k, v := range values {
		if code, body := fx.postWrap(t, a, req.ID, k, fx.envelope(t, a, []byte(v), nil)); code != http.StatusCreated {
			t.Fatalf("post wrap %s = %d (%s); want 201", k, code, body)
		}
	}
	if code := fx.complete(t, a, job.ID, "succeeded", ""); code != http.StatusNoContent {
		t.Fatalf("complete = %d; want 204", code)
	}
	got, _ := fx.reqSvc.Get(ctx, req.ID)
	if got.Status != storage.AccessRequestStatusExecuted {
		t.Fatalf("request status = %s; want executed", got.Status)
	}

	summaries, err := fx.reqSvc.WrapSummariesForRequest(ctx, req.ID)
	if err != nil || len(summaries) != 2 {
		t.Fatalf("summaries = %d (err=%v); want 2", len(summaries), err)
	}
	for _, s := range summaries {
		pt, _, err := fx.reqSvc.RetrieveWrapForUser(ctx, req.ID, s.ID, "alice")
		if err != nil {
			t.Fatalf("RetrieveWrapForUser %s: %v", s.KeyName, err)
		}
		if string(pt) != values[s.KeyName] {
			t.Fatalf("revealed %s does not match what the agent posted", s.KeyName)
		}
	}
	// API-S-24: user-consumed wraps keep no ciphertext.
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps
		WHERE request_id = $1 AND (octet_length(encrypted_value) > 0 OR octet_length(data_key_ciphertext) > 0)`, req.ID); n != 0 {
		t.Fatalf("%d consumed read wraps still hold ciphertext", n)
	}
}

// Patch flow end to end: agent claims the patch job, fetches each wrap
// (sealed to its key), completes; consumed rows hold no ciphertext.
func TestAgentSurface_PatchFlow_HappyPath(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	ctx := t.Context()
	a := fx.mint(t, "agent-a", true)
	req := fx.approvedPatch(t, map[string][]byte{"DB_PASSWORD": []byte("canary-patch-pw-91c2")})

	job := fx.claim(t, a)
	if job.ID != *req.JobID || job.JobType != "patch" {
		t.Fatalf("claimed %s/%s; want patch job %s", job.ID, job.JobType, req.JobID)
	}
	for _, wid := range wrapIDsFromPayload(t, job) {
		code, body := fx.getWrap(t, a, wid)
		if code != http.StatusOK {
			t.Fatalf("get wrap = %d (%s); want 200", code, body)
		}
		var p handlers.WrapPayload
		if err := json.Unmarshal(body, &p); err != nil || p.Sealed == nil {
			t.Fatalf("expected a sealed payload (err=%v)", err)
		}
		ct, _ := base64.StdEncoding.DecodeString(p.Sealed.Ciphertext)
		nonce, _ := base64.StdEncoding.DecodeString(p.Sealed.Nonce)
		eph, _ := base64.StdEncoding.DecodeString(p.Sealed.EphemeralPublicKey)
		pt, err := sealing.Open(&sealing.Envelope{Ciphertext: ct, Nonce: nonce, EphemeralPublicKey: eph, Algorithm: p.Sealed.Algorithm}, a.priv, a.pub)
		if err != nil || string(pt) != "canary-patch-pw-91c2" {
			t.Fatalf("sealed wrap did not open to the submitted value (err=%v)", err)
		}
	}
	// API-S-24: the agent-consumed wrap keeps no ciphertext.
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps
		WHERE request_id = $1 AND consumed_at IS NOT NULL
		  AND (octet_length(encrypted_value) > 0 OR octet_length(data_key_ciphertext) > 0)`, req.ID); n != 0 {
		t.Fatalf("%d consumed patch wraps still hold ciphertext", n)
	}
	if code := fx.complete(t, a, job.ID, "succeeded", ""); code != http.StatusNoContent {
		t.Fatalf("complete = %d; want 204", code)
	}
	got, _ := fx.reqSvc.Get(ctx, req.ID)
	if got.Status != storage.AccessRequestStatusExecuted {
		t.Fatalf("request status = %s; want executed", got.Status)
	}
}

// ---- H4: dispatch scoping -----------------------------------------

// Agent B cannot post a wrap into a read job agent A claimed, and no
// agent can post before the job is claimed at all.
func TestAgentSurface_OtherAgentCannotPostWrap(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", false)
	b := fx.mint(t, "agent-b", false)
	req := fx.approvedRead(t, []string{"DB_PASSWORD"})

	// Not claimed yet: nobody may post.
	if code, body := fx.postWrap(t, a, req.ID, "DB_PASSWORD", fx.envelope(t, a, []byte("injected"), nil)); code != http.StatusForbidden {
		t.Fatalf("post before claim = %d (%s); want 403", code, body)
	}

	fx.claim(t, a)
	if code, body := fx.postWrap(t, b, req.ID, "DB_PASSWORD", fx.envelope(t, b, []byte("injected"), nil)); code != http.StatusForbidden {
		t.Fatalf("agent B post into A's job = %d (%s); want 403", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE request_id = $1`, req.ID); n != 0 {
		t.Fatalf("refused posts still created %d wraps", n)
	}
	// The claimer is still served (the 403 was about ownership).
	if code, body := fx.postWrap(t, a, req.ID, "DB_PASSWORD", fx.envelope(t, a, []byte("real"), nil)); code != http.StatusCreated {
		t.Fatalf("claimer post = %d (%s); want 201", code, body)
	}
}

// Agent B cannot fetch (and so cannot burn) a patch wrap whose job agent
// A claimed.
func TestAgentSurface_OtherAgentCannotFetchWrap(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", true)
	b := fx.mint(t, "agent-b", true)
	req := fx.approvedPatch(t, map[string][]byte{"DB_PASSWORD": []byte("canary-patch-b")})

	// Unclaimed job: refused, wrap untouched.
	summaries, _ := fx.reqSvc.WrapSummariesForRequest(t.Context(), req.ID)
	wid := summaries[0].ID.String()
	if code, body := fx.getWrap(t, b, wid); code != http.StatusForbidden {
		t.Fatalf("fetch before claim = %d (%s); want 403", code, body)
	}

	job := fx.claim(t, a)
	wid = wrapIDsFromPayload(t, job)[0]
	if code, body := fx.getWrap(t, b, wid); code != http.StatusForbidden {
		t.Fatalf("agent B fetch of A's wrap = %d (%s); want 403", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE id = $1 AND consumed_at IS NULL`, wid); n != 1 {
		t.Fatal("refused fetch burned the wrap")
	}
	if code, body := fx.getWrap(t, a, wid); code != http.StatusOK {
		t.Fatalf("claimer fetch = %d (%s); want 200", code, body)
	}
}

// key_name must be one of the request's target_keys, and a key can be
// posted once per request.
func TestAgentSurface_UndeclaredAndDuplicateKeyRefused(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", false)
	req := fx.approvedRead(t, []string{"DB_PASSWORD"})
	fx.claim(t, a)

	if code, body := fx.postWrap(t, a, req.ID, "ADMIN_TOKEN", fx.envelope(t, a, []byte("x"), nil)); code != http.StatusForbidden {
		t.Fatalf("undeclared key = %d (%s); want 403", code, body)
	}
	if code, body := fx.postWrap(t, a, req.ID, "DB_PASSWORD", fx.envelope(t, a, []byte("first"), nil)); code != http.StatusCreated {
		t.Fatalf("declared key = %d (%s); want 201", code, body)
	}
	if code, body := fx.postWrap(t, a, req.ID, "DB_PASSWORD", fx.envelope(t, a, []byte("second"), nil)); code != http.StatusConflict {
		t.Fatalf("duplicate key = %d (%s); want 409", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE request_id = $1`, req.ID); n != 1 {
		t.Fatalf("wraps for request = %d; want exactly 1", n)
	}
	// The surviving wrap is the first value, not the duplicate.
	summaries, _ := fx.reqSvc.WrapSummariesForRequest(t.Context(), req.ID)
	pt, _, err := fx.reqSvc.RetrieveWrapForUser(t.Context(), req.ID, summaries[0].ID, "alice")
	if err != nil || string(pt) != "first" {
		t.Fatalf("requester got the wrong value (err=%v)", err)
	}
}

// Concurrent duplicate posts for the same key: exactly one lands.
func TestAgentSurface_ConcurrentDuplicateKeyOneWins(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", false)
	req := fx.approvedRead(t, []string{"DB_PASSWORD"})
	fx.claim(t, a)

	envs := make([]map[string]any, 6)
	for i := range envs {
		envs[i] = fx.envelope(t, a, []byte(fmt.Sprintf("v-%d", i)), nil)
	}
	var created atomic.Int32
	var wg sync.WaitGroup
	for i := range envs {
		wg.Add(1)
		go func(env map[string]any) {
			defer wg.Done()
			if code, _ := fx.postWrap(t, a, req.ID, "DB_PASSWORD", env); code == http.StatusCreated {
				created.Add(1)
			}
		}(envs[i])
	}
	wg.Wait()
	if created.Load() != 1 {
		t.Fatalf("concurrent duplicate posts created %d wraps; want 1", created.Load())
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE request_id = $1`, req.ID); n != 1 {
		t.Fatalf("wraps for request = %d; want 1", n)
	}
}

// Read-flow wraps are destined for the requester. No agent, not even
// the one that produced them, may fetch (and burn) them.
func TestAgentSurface_AgentCannotFetchUserDestinedWrap(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", true)
	b := fx.mint(t, "agent-b", true)
	req := fx.approvedRead(t, []string{"DB_PASSWORD"})
	fx.claim(t, a)
	code, body := fx.postWrap(t, a, req.ID, "DB_PASSWORD", fx.envelope(t, a, []byte("canary-user-only"), nil))
	if code != http.StatusCreated {
		t.Fatalf("post wrap = %d (%s)", code, body)
	}
	var cr handlers.CreateResponse
	_ = json.Unmarshal(body, &cr)

	for _, ag := range []surfaceAgent{a, b} {
		if code, body := fx.getWrap(t, ag, cr.WrapID); code != http.StatusForbidden {
			t.Fatalf("agent fetch of user wrap = %d (%s); want 403", code, body)
		}
	}
	pt, _, err := fx.reqSvc.RetrieveWrapForUser(t.Context(), req.ID, uuid.MustParse(cr.WrapID), "alice")
	if err != nil || string(pt) != "canary-user-only" {
		t.Fatalf("requester could not reveal after refused agent fetches (err=%v)", err)
	}
}

// ---- API-S-23: envelope validation --------------------------------

func TestAgentSurface_BadNonceIs400NotPanic(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", false)
	req := fx.approvedRead(t, []string{"DB_PASSWORD"})
	fx.claim(t, a)

	cases := map[string]func() map[string]any{
		"short nonce": func() map[string]any { return fx.envelope(t, a, []byte("v"), []byte{1, 2, 3, 4}) },
		"long nonce":  func() map[string]any { return fx.envelope(t, a, []byte("v"), make([]byte, 64)) },
		"short ciphertext": func() map[string]any {
			env := fx.envelope(t, a, []byte("v"), nil)
			env["ciphertext"] = base64.StdEncoding.EncodeToString([]byte{9, 9, 9})
			return env
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			code, body := fx.postWrap(t, a, req.ID, "DB_PASSWORD", mk())
			if code != http.StatusBadRequest {
				t.Fatalf("status = %d (%s); want 400", code, body)
			}
			if strings.Contains(strings.ToLower(string(body)), "nonce length") {
				t.Fatalf("400 body leaks crypto internals: %s", body)
			}
		})
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE request_id = $1`, req.ID); n != 0 {
		t.Fatalf("malformed envelopes created %d wraps", n)
	}
}

// ---- API-S-27: job error text -------------------------------------

func TestAgentSurface_JobErrorTruncatedAndScrubbed(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", false)

	t.Run("oversized", func(t *testing.T) {
		fx.approvedRead(t, []string{"DB_PASSWORD"})
		job := fx.claim(t, a)
		raw := "get value: AccessDenied for AKIAABCDEFGHIJKLMNOP " + strings.Repeat("x", 200_000)
		if code := fx.complete(t, a, job.ID, "failed", raw); code != http.StatusNoContent {
			t.Fatalf("complete = %d; want 204", code)
		}
		got, err := fx.jobsR.Get(t.Context(), job.ID)
		if err != nil {
			t.Fatalf("get job: %v", err)
		}
		if len(got.Error) == 0 || len(got.Error) > 1024 {
			t.Fatalf("stored job error is %d bytes; want 1..1024", len(got.Error))
		}
		if strings.Contains(got.Error, "AKIAABCDEFGHIJKLMNOP") {
			t.Fatal("credential-shaped text stored raw in job error")
		}
	})

	t.Run("nul byte", func(t *testing.T) {
		fx.approvedRead(t, []string{"DB_PASSWORD"})
		job := fx.claim(t, a)
		if code := fx.complete(t, a, job.ID, "failed", "provider\x00 said no"); code != http.StatusNoContent {
			t.Fatalf("complete with NUL in error = %d; want 204", code)
		}
	})
}

// ---- API-S-21: revocation -----------------------------------------

func TestAgentSurface_RevokedAgentRejectedWithWarmCache(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", false)
	claimPath := "/api/v1/agents/" + a.id.String() + "/jobs/claim"

	if code, _ := fx.call(t, http.MethodPost, claimPath, a.secret, nil); code != http.StatusNoContent {
		t.Fatalf("warm-up claim = %d; want 204", code)
	}
	if err := fx.agentSvc.Revoke(t.Context(), a.id, "admin-user-1", "test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if code, _ := fx.call(t, http.MethodPost, claimPath, a.secret, nil); code != http.StatusUnauthorized {
		t.Fatalf("post-revoke claim = %d; want 401", code)
	}
}

// gatedAgents blocks the first armed Get after it has read the row, so a
// test can land a Revoke between the auth cache-fill's DB read and its
// Redis write: the exact interleaving behind API-S-21.
type gatedAgents struct {
	*storage.Agents
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (g *gatedAgents) Get(ctx context.Context, id uuid.UUID) (*storage.Agent, error) {
	a, err := g.Agents.Get(ctx, id)
	if g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.release
	}
	return a, err
}

func TestAgentSurface_RevokeRacingCacheFillStillRejects(t *testing.T) {
	gate := &gatedAgents{entered: make(chan struct{}), release: make(chan struct{})}
	fx := bootstrapAgentSurfaceWith(t, func(r *storage.Agents) storage.AgentRepository {
		gate.Agents = r
		return gate
	})
	a := fx.mint(t, "agent-a", false)
	claimPath := "/api/v1/agents/" + a.id.String() + "/jobs/claim"

	// Cold cache. The in-flight request reads the agent as active, then
	// stalls before it can fill the cache.
	gate.armed.Store(true)
	done := make(chan int, 1)
	go func() {
		code, _ := fx.call(t, http.MethodPost, claimPath, a.secret, nil)
		done <- code
	}()
	<-gate.entered
	if err := fx.agentSvc.Revoke(t.Context(), a.id, "admin-user-1", "test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	close(gate.release)
	<-done // the in-flight request was admitted before revocation; fine

	if code, _ := fx.call(t, http.MethodPost, claimPath, a.secret, nil); code != http.StatusUnauthorized {
		t.Fatalf("claim after revoke = %d; want 401 (stale cache fill must not resurrect a revoked agent)", code)
	}
}

// ---- API-N-07: rejected-auth audit rollup --------------------------

func TestAgentSurface_RejectedAuthAuditRollup(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", false)

	for i := 0; i < 100; i++ {
		if code, _ := fx.call(t, http.MethodPost, "/api/v1/agents/"+a.id.String()+"/jobs/claim", "wrong-secret", nil); code != http.StatusUnauthorized {
			t.Fatalf("bad secret = %d; want 401", code)
		}
	}
	if n := fx.countRows(t, `SELECT count(*) FROM audit_events WHERE action = 'agent.auth.rejected' AND metadata->>'reason' = 'bad_secret'`); n != 1 {
		t.Fatalf("100 bad-secret rejections wrote %d audit rows; want 1", n)
	}

	for i := 0; i < 100; i++ {
		if code, _ := fx.call(t, http.MethodPost, "/api/v1/agents/"+uuid.NewString()+"/jobs/claim", "whatever", nil); code != http.StatusUnauthorized {
			t.Fatalf("unknown agent = %d; want 401", code)
		}
	}
	if n := fx.countRows(t, `SELECT count(*) FROM audit_events WHERE action = 'agent.auth.rejected' AND metadata->>'reason' = 'unknown_agent'`); n != 1 {
		t.Fatalf("100 unknown-agent rejections (random ids) wrote %d audit rows; want 1", n)
	}

	for i := 0; i < 100; i++ {
		code, _ := fx.call(t, http.MethodPost, "/api/v1/agents/enroll", "",
			map[string]any{"enrollment_token": fmt.Sprintf("bogus-%d", i), "agent_name": "x"})
		if code != http.StatusUnauthorized {
			t.Fatalf("bogus enroll = %d; want 401", code)
		}
	}
	if n := fx.countRows(t, `SELECT count(*) FROM audit_events WHERE action = 'agent.enrollment.rejected'`); n != 1 {
		t.Fatalf("100 bogus enrollments wrote %d audit rows; want 1", n)
	}

	// A different reason is its own bucket: still audited (api#187).
	if err := fx.agentSvc.Revoke(t.Context(), a.id, "admin-user-1", "test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	fx.call(t, http.MethodPost, "/api/v1/agents/"+a.id.String()+"/jobs/claim", a.secret, nil)
	if n := fx.countRows(t, `SELECT count(*) FROM audit_events WHERE action = 'agent.auth.rejected' AND metadata->>'reason' = 'revoked'`); n != 1 {
		t.Fatalf("revoked rejection wrote %d audit rows; want 1", n)
	}
}

// ---- API-18: enrollment -------------------------------------------

// 8 concurrent enrolls per token (the audit's repro), over several
// tokens: every round yields exactly one agent and no orphan rows. The
// deterministic version of this race is in services
// (TestEnroll_ConcurrentSameToken_NoOrphanAgents).
func TestAgentSurface_ConcurrentEnrollOneToken(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	const rounds, n = 5, 8
	for round := 1; round <= rounds; round++ {
		tok, err := fx.agentSvc.GenerateEnrollmentToken(t.Context(), services.GenerateEnrollmentTokenInput{
			ProviderConnectionID: fx.connID, CreatedBy: "admin-user-1",
		})
		if err != nil {
			t.Fatalf("GenerateEnrollmentToken: %v", err)
		}
		codes := make([]int, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				codes[i], _ = fx.call(t, http.MethodPost, "/api/v1/agents/enroll", "", map[string]any{
					"enrollment_token": tok.Token,
					"agent_name":       fmt.Sprintf("enroll-race-%d-%d", round, i),
					"provider_type":    "aws-sm",
				})
			}(i)
		}
		close(start)
		wg.Wait()

		created := 0
		for _, c := range codes {
			switch c {
			case http.StatusCreated:
				created++
			case http.StatusConflict:
			default:
				t.Fatalf("round %d: unexpected enroll status %d (all: %v)", round, c, codes)
			}
		}
		if created != 1 {
			t.Fatalf("round %d: one token enrolled %d agents; want exactly 1 (codes %v)", round, created, codes)
		}
		if rows := fx.countRows(t, `SELECT count(*) FROM agents`); rows != round {
			t.Fatalf("round %d: agents table has %d rows; want %d (no orphans)", round, rows, round)
		}
	}
	if rows := fx.countRows(t, `SELECT count(*) FROM agent_enrollment_tokens t
		JOIN agents a ON a.id = t.consumed_by_agent_id WHERE t.consumed_at IS NOT NULL`); rows != rounds {
		t.Fatalf("%d tokens linked to an enrolled agent; want %d", rows, rounds)
	}
}

// ---- discovery upload identity ------------------------------------

// enrollAgent enrolls an agent against a fresh provider connection of
// connType whose admin-set cluster_name is connCluster. The agent declares
// cluster at enroll the way the binary does (SB_CLUSTER_NAME); the token
// carries no expected_cluster_name, so nothing checks the two agree.
func (fx *agentSurface) enrollAgent(t *testing.T, name, cluster, connCluster, connType string) surfaceAgent {
	t.Helper()
	ctx := t.Context()
	var connID uuid.UUID
	if err := fx.pool.QueryRow(ctx, `
		INSERT INTO provider_connections (name, type, auth_method, scope, status, cluster_name)
		VALUES ($1, $2, 'token', '{}'::jsonb, 'active', NULLIF($3, '')) RETURNING id`, "conn-"+name, connType, connCluster).Scan(&connID); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	tok, err := fx.agentSvc.GenerateEnrollmentToken(ctx, services.GenerateEnrollmentTokenInput{
		ProviderConnectionID: connID, CreatedBy: "admin-user-1",
	})
	if err != nil {
		t.Fatalf("GenerateEnrollmentToken: %v", err)
	}
	res, err := fx.agentSvc.Enroll(ctx, services.EnrollInput{
		Token: tok.Token, AgentName: name, ClusterName: cluster, ProviderType: connType,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return surfaceAgent{id: res.AgentID, secret: res.AgentToken}
}

func (fx *agentSurface) postDiscovery(t *testing.T, a surfaceAgent, cluster, providerType, ref string) (int, []byte) {
	t.Helper()
	body := map[string]any{
		"provider_type": providerType,
		"items":         []map[string]any{{"secret_ref": ref, "labels": map[string]any{"team": "team-alpha"}}},
	}
	if cluster != "" {
		body["cluster_name"] = cluster
	}
	return fx.call(t, http.MethodPost, "/api/v1/agents/"+a.id.String()+"/secrets/bulk", a.secret, body)
}

// An agent writes catalog rows only under its own cluster and provider
// type, taken from its agents row / bound provider connection. Agent A
// cannot write (or overwrite) rows that belong to agent B's cluster.
func TestAgentSurface_DiscoveryUploadBoundToAgentIdentity(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.enrollAgent(t, "agent-a", "tenant-a-uat", "tenant-a-uat", "aws-sm")
	b := fx.enrollAgent(t, "agent-b", "tenant-b-uat", "tenant-b-uat", "vault")

	// B's legit row exists first; A must not be able to overwrite it.
	if code, body := fx.postDiscovery(t, b, "tenant-b-uat", "vault", "team-alpha/uat/db"); code != http.StatusOK {
		t.Fatalf("agent B own upload = %d (%s); want 200", code, body)
	}
	if code, body := fx.postDiscovery(t, a, "tenant-b-uat", "vault", "team-alpha/uat/db"); code != http.StatusForbidden {
		t.Fatalf("agent A with B's cluster+provider = %d (%s); want 403", code, body)
	}
	if code, body := fx.postDiscovery(t, a, "tenant-b-uat", "aws-sm", "team-alpha/uat/injected"); code != http.StatusForbidden {
		t.Fatalf("agent A with B's cluster = %d (%s); want 403", code, body)
	}
	if code, body := fx.postDiscovery(t, a, "tenant-a-uat", "vault", "team-alpha/uat/injected"); code != http.StatusForbidden {
		t.Fatalf("agent A with a foreign provider type = %d (%s); want 403", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secrets WHERE cluster_name = 'tenant-b-uat'`); n != 1 {
		t.Fatalf("tenant-b-uat has %d catalog rows; want only B's own 1", n)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secrets WHERE secret_ref = 'team-alpha/uat/injected'`); n != 0 {
		t.Fatalf("refused uploads wrote %d rows", n)
	}

	// A's own identity still works, and an omitted cluster_name is filled
	// from the bound connection rather than refused.
	if code, body := fx.postDiscovery(t, a, "tenant-a-uat", "aws-sm", "team-alpha/uat/api"); code != http.StatusOK {
		t.Fatalf("agent A own upload = %d (%s); want 200", code, body)
	}
	if code, body := fx.postDiscovery(t, a, "", "aws-sm", "team-alpha/uat/cache"); code != http.StatusOK {
		t.Fatalf("agent A upload without cluster_name = %d (%s); want 200", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secrets WHERE cluster_name = 'tenant-a-uat' AND provider_type = 'aws-sm'`); n != 2 {
		t.Fatalf("tenant-a-uat/aws-sm rows = %d; want 2", n)
	}
}

// B-2: an enrolled agent's discovery cluster is its bound connection's
// cluster_name, not the cluster it declared at enroll. Before the fix a
// uat-bound agent that enrolled declaring a prod cluster (the token had no
// expected_cluster_name) could overwrite that cluster's catalog rows,
// including the provider_config request jobs are derived from.
func TestAgentSurface_DiscoveryClusterComesFromConnection(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	owner := fx.enrollAgent(t, "agent-prod", "tenant-b-prod", "tenant-b-prod", "vault")
	rogue := fx.enrollAgent(t, "agent-rogue", "tenant-b-prod", "tenant-a-uat", "vault")

	if code, body := fx.postDiscovery(t, owner, "tenant-b-prod", "vault", "team-beta/prod/db"); code != http.StatusOK {
		t.Fatalf("owner upload = %d (%s); want 200", code, body)
	}
	if code, body := fx.postDiscovery(t, rogue, "tenant-b-prod", "vault", "team-beta/prod/db"); code != http.StatusForbidden {
		t.Fatalf("uat-bound agent naming the cluster it declared at enroll = %d (%s); want 403", code, body)
	}
	if code, body := fx.postDiscovery(t, rogue, "", "vault", "team-alpha/uat/db"); code != http.StatusOK {
		t.Fatalf("uat-bound agent without cluster_name = %d (%s); want 200", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secrets WHERE cluster_name = 'tenant-b-prod'`); n != 1 {
		t.Fatalf("tenant-b-prod has %d catalog rows; want only the owner's 1", n)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secrets WHERE cluster_name = 'tenant-a-uat' AND secret_ref = 'team-alpha/uat/db'`); n != 1 {
		t.Fatalf("omitted cluster_name was not filled from the connection (tenant-a-uat rows = %d)", n)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM audit_events WHERE action = 'discovery.upsert' AND metadata->>'reason' = 'cluster_mismatch'`); n != 1 {
		t.Fatalf("cluster_mismatch audit rows = %d; want 1", n)
	}

	// A connection without a cluster_name gives its agent no discovery
	// identity; the agent's own claim is not used instead.
	noCluster := fx.enrollAgent(t, "agent-nocluster", "tenant-b-prod", "", "vault")
	if code, body := fx.postDiscovery(t, noCluster, "", "vault", "team-beta/prod/other"); code != http.StatusForbidden {
		t.Fatalf("agent on a connection without cluster_name = %d (%s); want 403", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secrets WHERE secret_ref = 'team-beta/prod/other'`); n != 0 {
		t.Fatalf("refused upload wrote %d rows", n)
	}
}

// Legacy direct-mint agents (no provider connection) are bound to what
// their agents row holds: scope.cluster plus scope.provider(s). A row
// that names no cluster or no provider cannot upload at all.
func TestAgentSurface_DiscoveryUploadLegacyMintedAgent(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	mint := func(name string, scope map[string]any) surfaceAgent {
		m, err := fx.agentSvc.Mint(t.Context(), services.MintInput{Name: name, Scope: scope})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		return surfaceAgent{id: m.ID, secret: m.AgentSecret}
	}
	full := mint("legacy-full", map[string]any{"cluster": "legacy-c", "provider": "vault"})
	list := mint("legacy-list", map[string]any{"cluster": "legacy-d", "providers": []any{"vault", "aws-sm"}})
	clusterOnly := mint("legacy-cluster-only", map[string]any{"cluster": "legacy-e"})
	bare := mint("legacy-bare", nil)

	cases := []struct {
		name     string
		agent    surfaceAgent
		cluster  string
		provider string
		want     int
	}{
		{"own scope", full, "legacy-c", "vault", http.StatusOK},
		{"other cluster", full, "tenant-a-uat", "vault", http.StatusForbidden},
		{"other provider", full, "legacy-c", "aws-sm", http.StatusForbidden},
		{"provider from list", list, "legacy-d", "aws-sm", http.StatusOK},
		{"provider not in list", list, "legacy-d", "gcp-sm", http.StatusForbidden},
		{"no provider in row", clusterOnly, "legacy-e", "vault", http.StatusForbidden},
		{"empty row", bare, "anything", "vault", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, body := fx.postDiscovery(t, tc.agent, tc.cluster, tc.provider, "legacy/"+tc.name); code != tc.want {
				t.Fatalf("status = %d (%s); want %d", code, body, tc.want)
			}
		})
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secrets WHERE cluster_name NOT IN ('legacy-c', 'legacy-d')`); n != 0 {
		t.Fatalf("%d rows written outside the legacy agents' own clusters", n)
	}
}

// B-2 follow-up: deleting a connection sets the agent's
// provider_connection_id to NULL. The orphaned agent must not fall back
// to the cluster it declared at enroll, and a disabled connection's agent
// may not publish discovery at all.
func TestAgentSurface_DiscoveryRefusedForOrphanedOrDisabledConnection(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	orphan := fx.enrollAgent(t, "agent-orphan", "tenant-b-prod", "tenant-a-uat", "vault")
	if _, err := fx.pool.Exec(t.Context(), `DELETE FROM provider_connections WHERE name = 'conn-agent-orphan'`); err != nil {
		t.Fatalf("delete connection: %v", err)
	}
	if code, body := fx.postDiscovery(t, orphan, "tenant-b-prod", "vault", "team-beta/prod/db"); code != http.StatusForbidden {
		t.Fatalf("orphaned agent naming its declared cluster = %d (%s); want 403", code, body)
	}
	if code, body := fx.postDiscovery(t, orphan, "", "vault", "team-beta/prod/db"); code != http.StatusForbidden {
		t.Fatalf("orphaned agent without cluster_name = %d (%s); want 403", code, body)
	}

	disabled := fx.enrollAgent(t, "agent-disabled", "tenant-a-uat", "tenant-a-uat", "vault")
	if _, err := fx.pool.Exec(t.Context(), `UPDATE provider_connections SET status = 'disabled' WHERE name = 'conn-agent-disabled'`); err != nil {
		t.Fatalf("disable connection: %v", err)
	}
	if code, body := fx.postDiscovery(t, disabled, "tenant-a-uat", "vault", "team-alpha/uat/db"); code != http.StatusForbidden {
		t.Fatalf("agent on a disabled connection = %d (%s); want 403", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secrets`); n != 0 {
		t.Fatalf("refused uploads wrote %d catalog rows", n)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM audit_events WHERE action = 'discovery.upsert' AND metadata->>'reason' = 'connection_disabled'`); n != 1 {
		t.Fatalf("connection_disabled audit rows = %d; want 1", n)
	}
}

// Once a claim's lease has expired ClaimNext can hand the job to another
// agent, so the old holder can no longer post or fetch wraps for it.
func TestAgentSurface_ExpiredLeaseCannotPostOrFetch(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", true)

	read := fx.approvedRead(t, []string{"DB_PASSWORD"})
	rj := fx.claim(t, a)
	if _, err := fx.pool.Exec(t.Context(), `UPDATE sync_jobs SET claim_expires_at = now() - interval '1 second' WHERE id = $1`, rj.ID); err != nil {
		t.Fatalf("expire read lease: %v", err)
	}
	if code, body := fx.postWrap(t, a, read.ID, "DB_PASSWORD", fx.envelope(t, a, []byte("late"), nil)); code != http.StatusForbidden {
		t.Fatalf("post after lease expiry = %d (%s); want 403", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE request_id = $1`, read.ID); n != 0 {
		t.Fatalf("expired-lease post created %d wraps", n)
	}
	if _, err := fx.pool.Exec(t.Context(), `UPDATE sync_jobs SET status = 'succeeded' WHERE id = $1`, rj.ID); err != nil {
		t.Fatalf("retire read job: %v", err)
	}

	fx.approvedPatch(t, map[string][]byte{"DB_PASSWORD": []byte("canary-lease")})
	pj := fx.claim(t, a)
	wid := wrapIDsFromPayload(t, pj)[0]
	if _, err := fx.pool.Exec(t.Context(), `UPDATE sync_jobs SET claim_expires_at = now() - interval '1 second' WHERE id = $1`, pj.ID); err != nil {
		t.Fatalf("expire patch lease: %v", err)
	}
	if code, body := fx.getWrap(t, a, wid); code != http.StatusForbidden {
		t.Fatalf("fetch after lease expiry = %d (%s); want 403", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE id = $1 AND consumed_at IS NULL`, wid); n != 1 {
		t.Fatal("expired-lease fetch burned the wrap")
	}
}

// ---- api#264: sealed wraps only -------------------------------------

// An agent with no X25519 key on file gets a 409 for its own claimed
// patch wrap. The wrap is not consumed, no plaintext comes back, and the
// refusal is audited. The same agent with a key gets it sealed.
func TestAgentSurface_KeylessAgentFetchRefusedWithoutBurning(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-keyless", false)
	fx.approvedPatch(t, map[string][]byte{"DB_PASSWORD": []byte("canary-sealed-only")})
	job := fx.claim(t, a)
	wid := wrapIDsFromPayload(t, job)[0]

	code, body := fx.getWrap(t, a, wid)
	if code != http.StatusConflict {
		t.Fatalf("keyless fetch = %d (%s); want 409", code, body)
	}
	if bytes.Contains(body, []byte("canary-sealed-only")) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString([]byte("canary-sealed-only")))) ||
		bytes.Contains(body, []byte(`"value"`)) {
		t.Fatalf("refusal carries the value: %s", body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE id = $1 AND consumed_at IS NULL`, wid); n != 1 {
		t.Fatal("refused fetch burned the wrap")
	}
	if n := fx.countRows(t, `SELECT count(*) FROM audit_events WHERE action = 'wrap.retrieve' AND status = 'denied'
		AND metadata->>'reason' = 'agent_public_key_missing' AND metadata->>'wrap_id' = $1`, wid); n != 1 {
		t.Fatalf("refusal audit rows = %d; want 1", n)
	}
}

// Posting a plaintext `value` is refused with 400 and stores nothing;
// the envelope path still works for the same key.
func TestAgentSurface_PlaintextValueCreateRefused(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", true)
	req := fx.approvedRead(t, []string{"DB_PASSWORD"})
	fx.claim(t, a)

	code, body := fx.call(t, http.MethodPost, "/api/v1/agents/"+a.id.String()+"/wraps", a.secret, map[string]any{
		"request_id": req.ID.String(), "key_name": "DB_PASSWORD",
		"value": base64.StdEncoding.EncodeToString([]byte("canary-plain-post")),
	})
	if code != http.StatusBadRequest {
		t.Fatalf("plaintext value post = %d (%s); want 400", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE request_id = $1`, req.ID); n != 0 {
		t.Fatalf("plaintext post stored %d wraps", n)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM audit_events WHERE action = 'wrap.create' AND status = 'denied'
		AND metadata->>'reason' = 'plaintext_value_refused'`); n != 1 {
		t.Fatalf("refusal audit rows = %d; want 1", n)
	}
	if code, body := fx.postWrap(t, a, req.ID, "DB_PASSWORD", fx.envelope(t, a, []byte("canary-sealed-post"), nil)); code != http.StatusCreated {
		t.Fatalf("envelope post after the refusal = %d (%s); want 201", code, body)
	}
}

// With SB_ALLOW_UNSEALED_WRAPS the legacy shapes still work, for an agent
// that predates wire-envelope.
func TestAgentSurface_UnsealedBreakGlassKeepsLegacyShapes(t *testing.T) {
	fx := bootstrapAgentSurfaceOpts(t, nil, true)
	a := fx.mint(t, "agent-legacy", false)
	fx.approvedPatch(t, map[string][]byte{"DB_PASSWORD": []byte("canary-legacy")})
	job := fx.claim(t, a)
	wid := wrapIDsFromPayload(t, job)[0]
	code, body := fx.getWrap(t, a, wid)
	if code != http.StatusOK {
		t.Fatalf("legacy keyless fetch with the switch = %d (%s); want 200", code, body)
	}
	var p handlers.WrapPayload
	if err := json.Unmarshal(body, &p); err != nil || p.Sealed != nil || p.Value != base64.StdEncoding.EncodeToString([]byte("canary-legacy")) {
		t.Fatalf("legacy fetch did not return the plaintext shape (err=%v)", err)
	}

	b := fx.mint(t, "agent-legacy-read", false)
	req := fx.approvedRead(t, []string{"DB_PASSWORD"})
	fx.claim(t, b)
	if code, body := fx.call(t, http.MethodPost, "/api/v1/agents/"+b.id.String()+"/wraps", b.secret, map[string]any{
		"request_id": req.ID.String(), "key_name": "DB_PASSWORD",
		"value": base64.StdEncoding.EncodeToString([]byte("canary-legacy-post")),
	}); code != http.StatusCreated {
		t.Fatalf("legacy value post with the switch = %d (%s); want 201", code, body)
	}
}
