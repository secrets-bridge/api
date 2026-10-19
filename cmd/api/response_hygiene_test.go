package main

// Real-router regression tests for the 2026-10-16 response-hygiene
// items:
//
//	API-16     internal error text (pgx, KMS, Redis) in response bodies
//	API-S-20   secret-bearing responses without Cache-Control: no-store
//	API-S-22   http:// ArgoCD base URLs accepted in production, so the
//	           bearer token can travel in clear text
//
// Every DB-backed test drives the FULL app built by newApp (cookie
// session auth, the default-deny group, per-route permission gates,
// handlers, services, Postgres and Redis). The only fake is the KMS
// wrapper, which can be told to fail the way a Vault transit backend
// fails, so the leak of its error text can be observed end to end.
//
// DB + Redis backed tests SKIP without TEST_DATABASE_URL and
// TEST_REDIS_URL.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// hygVaultLeak is the internal detail a Vault transit KMS error carries:
// the transit URL including the key name. It must never reach a client.
const (
	hygVaultHost    = "vault.example.com"
	hygTransitKey   = "sb-hyg-transit-key"
	hygVaultLeakURL = "https://" + hygVaultHost + "/v1/transit/datakey/plaintext/" + hygTransitKey
)

// hygFlakyKMS wraps a real LocalKMS and can be told to fail the way a
// sealed or misconfigured Vault transit backend does, with the same
// error text shape (request URL + key name).
type hygFlakyKMS struct {
	keymgmt.KeyManager
	failGenerate atomic.Bool
	failDecrypt  atomic.Bool
}

func (k *hygFlakyKMS) GenerateDataKey(ctx context.Context) (keymgmt.DataKey, error) {
	if k.failGenerate.Load() {
		return keymgmt.DataKey{}, fmt.Errorf(
			"keymgmt: vault transit datakey: Error making API request.\n\nURL: PUT %s\nCode: 503. Errors:\n\n* Vault is sealed",
			hygVaultLeakURL)
	}
	return k.KeyManager.GenerateDataKey(ctx)
}

func (k *hygFlakyKMS) DecryptDataKey(ctx context.Context, ct []byte, keyID string) ([]byte, error) {
	if k.failDecrypt.Load() {
		return nil, fmt.Errorf(
			"keymgmt: vault transit decrypt: Error making API request.\n\nURL: PUT https://%s/v1/transit/decrypt/%s\nCode: 400. Errors:\n\n* invalid ciphertext",
			hygVaultHost, hygTransitKey)
	}
	return k.KeyManager.DecryptDataKey(ctx, ct, keyID)
}

func hygRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func hygName(prefix string) string { return prefix + "-" + uuid.NewString()[:8] }

func newHygKMS(t *testing.T) *hygFlakyKMS {
	t.Helper()
	local, err := keymgmt.NewLocalKMS(hygRandomBytes(t, 32))
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	return &hygFlakyKMS{KeyManager: local}
}

type hygFixture struct {
	app      *fiber.App
	pool     *storage.Pool
	rdb      *runtime.Client
	km       *hygFlakyKMS
	sessions *services.SessionService
	logs     *hygLogBuffer
}

// hygLogBuffer is a goroutine-safe sink for the app logger so a test
// can assert that internal detail went to the server log.
type hygLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *hygLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *hygLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newHygFixture builds the real app. km may be shared between two
// fixtures (for example a dev and a production app over one database)
// so a row written by one can be decrypted by the other.
func newHygFixture(t *testing.T, cfg Config, km *hygFlakyKMS) *hygFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL required; skipping")
	}
	ctx := t.Context()
	scfg := storage.Config{DSN: dsn, MaxConns: 8, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, scfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, scfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	rdb, err := runtime.Open(ctx, runtime.Config{URL: redisURL})
	if err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	if km == nil {
		km = newHygKMS(t)
	}
	auditRepo := storage.NewAuditEvents(pool)
	authSvc := services.NewAuthService(
		storage.NewLocalUsers(pool), storage.NewRoles(pool), storage.NewUserRoles(pool),
		auditRepo,
	)
	if cfg.Env == "" {
		cfg.Env = ModeDev
	}
	cfg.ProviderConnRejectSecretValues = true
	logs := &hygLogBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	// main() makes the app logger the process default; handlers that
	// answer with their own stable message log through slog.Default.
	swapDefaultLogger(t, logger)
	return &hygFixture{
		app:      newApp(cfg, logger, pool, rdb, km, authSvc),
		pool:     pool,
		rdb:      rdb,
		km:       km,
		sessions: services.NewSessionService(storage.NewSessions(pool), auditRepo),
		logs:     logs,
	}
}

type hygUser struct {
	id     uuid.UUID
	email  string
	cookie string
}

// user creates a local user holding the given GLOBAL permissions, with a
// cookie session whose MFA stamp is fresh.
func (fx *hygFixture) user(t *testing.T, name string, perms ...auth.Permission) *hygUser {
	t.Helper()
	return fx.userWithPassword(t, name, "", perms...)
}

func (fx *hygFixture) userWithPassword(t *testing.T, name, password string, perms ...auth.Permission) *hygUser {
	t.Helper()
	ctx := t.Context()
	hash := []byte("$2a$10$not-a-real-hash-for-tests-only-xxxxxxxxxxxxxxxxxxxxx")
	if password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("bcrypt: %v", err)
		}
		hash = h
	}
	u := &storage.LocalUser{
		Email:        hygName(name) + "@example.com",
		PasswordHash: hash,
		DisplayName:  name,
	}
	if err := storage.NewLocalUsers(fx.pool).Create(ctx, u); err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	if len(perms) > 0 {
		permsJSON, _ := json.Marshal(perms)
		roleID := uuid.New()
		if _, err := fx.pool.Exec(ctx,
			`INSERT INTO roles (id, name, permissions, is_system) VALUES ($1, $2, $3::jsonb, false)`,
			roleID, hygName(name+"-role"), string(permsJSON)); err != nil {
			t.Fatalf("seed role for %s: %v", name, err)
		}
		if _, err := fx.pool.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id, scope) VALUES ($1, $2, '{}'::jsonb)`,
			u.ID.String(), roleID); err != nil {
			t.Fatalf("seed grant for %s: %v", name, err)
		}
	}
	issued, err := fx.sessions.Issue(ctx, u.ID, "127.0.0.1", "response-hygiene-test")
	if err != nil {
		t.Fatalf("issue session for %s: %v", name, err)
	}
	if err := fx.sessions.MarkMFA(ctx, issued.Session.ID, time.Now().UTC()); err != nil {
		t.Fatalf("stamp mfa for %s: %v", name, err)
	}
	return &hygUser{id: u.ID, email: u.Email, cookie: issued.CookieValue}
}

type hygResp struct {
	status int
	body   string
	header http.Header
}

func (r hygResp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.body), &m); err != nil {
		t.Fatalf("body is not a JSON object: %v (%s)", err, r.body)
	}
	return m
}

func hygDo(t *testing.T, app *fiber.App, method, path string, u *hygUser, hdr map[string]string, body any) hygResp {
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
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if u != nil {
		req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: u.cookie})
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return hygResp{status: resp.StatusCode, body: string(b), header: resp.Header}
}

func (fx *hygFixture) do(t *testing.T, method, path string, u *hygUser, body any) hygResp {
	t.Helper()
	return hygDo(t, fx.app, method, path, u, nil, body)
}

func hygAssertNoLeak(t *testing.T, where string, r hygResp, leaks ...string) {
	t.Helper()
	for _, l := range leaks {
		if strings.Contains(strings.ToLower(r.body), strings.ToLower(l)) {
			t.Errorf("%s: response body leaks %q: %s", where, l, r.body)
		}
	}
}

func hygAssertNoStore(t *testing.T, where string, r hygResp) {
	t.Helper()
	if cc := r.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("%s: Cache-Control = %q; want no-store (status %d)", where, cc, r.status)
	}
	if p := r.header.Get("Pragma"); p != "no-cache" {
		t.Errorf("%s: Pragma = %q; want no-cache (status %d)", where, p, r.status)
	}
}

// mintAgent creates an agent straight through the service (no HTTP) and
// returns its id + secret for the AgentAuth group.
func (fx *hygFixture) mintAgent(t *testing.T) (uuid.UUID, string) {
	t.Helper()
	svc := services.NewAgentService(storage.NewAgents(fx.pool), storage.NewAuditEvents(fx.pool), fx.rdb)
	m, err := svc.Mint(t.Context(), services.MintInput{Name: hygName("hyg-agent")})
	if err != nil {
		t.Fatalf("mint agent: %v", err)
	}
	return m.ID, m.AgentSecret
}

// approvedReadWithWrap seeds an approved read request owned by owner
// plus one wrap for it, and returns (requestID, wrapID).
func (fx *hygFixture) approvedReadWithWrap(t *testing.T, owner uuid.UUID) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := t.Context()
	wf, err := storage.NewWorkflows(fx.pool).GetDefault(ctx)
	if err != nil {
		t.Fatalf("default workflow: %v", err)
	}
	req := &storage.AccessRequest{
		WorkflowID:         &wf.ID,
		RequesterID:        owner.String(),
		Type:               storage.AccessRequestTypeRead,
		Justification:      "response hygiene test",
		Status:             storage.AccessRequestStatusApproved,
		TargetProviderType: "vault",
		TargetSecretRef:    "team-alpha/uat/db",
		TargetKeys:         []string{"password"},
	}
	if err := storage.NewAccessRequests(fx.pool).Create(ctx, req); err != nil {
		t.Fatalf("seed request: %v", err)
	}
	wrapSvc := services.NewWrapService(storage.NewSecretWraps(fx.pool), storage.NewAuditEvents(fx.pool), fx.km)
	w, err := wrapSvc.Wrap(ctx, services.WrapRequest{
		Plaintext: []byte("hyg-fake-value-not-a-secret"),
		RequestID: &req.ID,
		KeyName:   "password",
		TTL:       10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("seed wrap: %v", err)
	}
	return req.ID, w.ID
}

// ---------------------------------------------------------------------
// API-16: storage error text on POST /jobs
// ---------------------------------------------------------------------

// A storage error on the admin enqueue path (FK violation, CHECK
// violation) used to be returned verbatim as a 400, naming the table and
// constraint. The body must now carry a stable message only.
func TestHygiene_JobsEnqueue_StorageErrorIsStable(t *testing.T) {
	fx := newHygFixture(t, Config{}, nil)
	admin := fx.user(t, "enqueuer", auth.PermJobEnqueue)
	pgLeaks := []string{"sync_jobs", "fkey", "_check", "SQLSTATE", "violates", "constraint"}

	// Unknown request_id → FK violation in Postgres.
	r := fx.do(t, http.MethodPost, "/api/v1/jobs", admin, map[string]any{
		"job_type": "read", "request_id": uuid.NewString(),
	})
	if r.status != http.StatusBadRequest {
		t.Fatalf("unknown request_id: status = %d; want 400 (%s)", r.status, r.body)
	}
	hygAssertNoLeak(t, "unknown request_id", r, pgLeaks...)
	if got, _ := r.json(t)["error"].(string); got != "request_id does not reference an existing request" {
		t.Errorf("unknown request_id: error = %q; want the stable message", got)
	}

	// Unknown job_type → CHECK violation in Postgres.
	r = fx.do(t, http.MethodPost, "/api/v1/jobs", admin, map[string]any{"job_type": "bogus"})
	if r.status != http.StatusBadRequest {
		t.Fatalf("bad job_type: status = %d; want 400 (%s)", r.status, r.body)
	}
	hygAssertNoLeak(t, "bad job_type", r, pgLeaks...)
	if got, _ := r.json(t)["error"].(string); got != "invalid job_type" {
		t.Errorf("bad job_type: error = %q; want %q", got, "invalid job_type")
	}

	// Missing job_type stays a clear 400.
	r = fx.do(t, http.MethodPost, "/api/v1/jobs", admin, map[string]any{})
	if r.status != http.StatusBadRequest || !strings.Contains(r.body, "job_type is required") {
		t.Errorf("missing job_type: %d %s; want 400 job_type is required", r.status, r.body)
	}

	// Happy path unchanged.
	r = fx.do(t, http.MethodPost, "/api/v1/jobs", admin, map[string]any{"job_type": "discover"})
	if r.status != http.StatusCreated {
		t.Errorf("valid enqueue: status = %d; want 201 (%s)", r.status, r.body)
	}
}

// A connection failure carries the DSN's user, database and host in the
// pgx error. It used to come back as a 400 body; it must now be a
// generic 500 with the detail only in the server log.
func TestHygiene_JobsEnqueue_ConnectErrorHidesDSN(t *testing.T) {
	const (
		canaryUser = "hyg_canary_user"
		canaryPass = "hyg-canary-pass"
		canaryDB   = "sb_hyg_leak_canary"
	)
	dsn := fmt.Sprintf("postgres://%s:%s@127.0.0.1:1/%s?sslmode=disable&connect_timeout=2", canaryUser, canaryPass, canaryDB)
	pgp, err := pgxpool.New(t.Context(), dsn) // lazy: no dial until first use
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pgp.Close)
	broken := &storage.Pool{Pool: pgp}
	jobsH := handlers.NewJobs(services.NewJobService(storage.NewSyncJobs(broken), storage.NewAuditEvents(broken)))

	logs := &hygLogBuffer{}
	app := fiber.New(fiber.Config{ErrorHandler: jsonErrorHandler(slog.New(slog.NewJSONHandler(logs, nil)))})
	app.Use(middleware.RequestID())
	app.Post("/api/v1/jobs", jobsH.Enqueue)

	r := hygDo(t, app, http.MethodPost, "/api/v1/jobs", nil, nil, map[string]any{"job_type": "read"})
	if r.status != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500 for a storage outage (%s)", r.status, r.body)
	}
	hygAssertNoLeak(t, "connect error", r, canaryUser, canaryPass, canaryDB, "127.0.0.1", "dial", "failed to connect")
	if got, _ := r.json(t)["error"].(string); got != "internal server error" {
		t.Errorf("error = %q; want the generic message", got)
	}
	// The detail is still observable server side, minus the password.
	logged := logs.String()
	if !strings.Contains(logged, canaryDB) {
		t.Errorf("server log should carry the storage detail for triage; got %s", logged)
	}
	if strings.Contains(logged, canaryPass) {
		t.Errorf("server log must not carry the DSN password: %s", logged)
	}
}

// ---------------------------------------------------------------------
// API-16: KMS error text on the MFA and wrap paths
// ---------------------------------------------------------------------

func TestHygiene_TOTPEnroll_KMSErrorIsStable(t *testing.T) {
	fx := newHygFixture(t, Config{}, nil)
	u := fx.user(t, "totp-user")

	fx.km.failGenerate.Store(true)
	r := fx.do(t, http.MethodPost, "/api/v1/users/me/mfa/totp/enroll", u, map[string]any{"label": "phone"})
	if r.status != http.StatusInternalServerError {
		t.Fatalf("KMS outage: status = %d; want 500 (%s)", r.status, r.body)
	}
	hygAssertNoLeak(t, "totp enroll KMS outage", r, hygVaultHost, hygTransitKey, "transit", "sealed", "keymgmt")
	if got, _ := r.json(t)["error"].(string); got != "internal server error" {
		t.Errorf("error = %q; want the generic message", got)
	}
	if !strings.Contains(fx.logs.String(), hygTransitKey) {
		t.Errorf("KMS detail should be logged server side for triage")
	}

	// Blank label is a client error with a stable message.
	r = fx.do(t, http.MethodPost, "/api/v1/users/me/mfa/totp/enroll", u, map[string]any{"label": "  "})
	if r.status != http.StatusBadRequest || !strings.Contains(r.body, "label required") {
		t.Errorf("blank label: %d %s; want 400 label required", r.status, r.body)
	}

	// Healthy KMS: enrollment works.
	fx.km.failGenerate.Store(false)
	r = fx.do(t, http.MethodPost, "/api/v1/users/me/mfa/totp/enroll", u, map[string]any{"label": "phone"})
	if r.status != http.StatusOK {
		t.Errorf("healthy enroll: status = %d; want 200 (%s)", r.status, r.body)
	}
}

func TestHygiene_WrapEnvelope_KMSErrorIsStable(t *testing.T) {
	fx := newHygFixture(t, Config{}, nil)
	agentID, secret := fx.mintAgent(t)
	hdr := map[string]string{"X-Agent-Secret": secret}

	fx.km.failDecrypt.Store(true)
	body := map[string]any{
		"request_id": uuid.NewString(),
		"key_name":   "password",
		"envelope": map[string]any{
			"algorithm":      "aes-256-gcm",
			"ciphertext":     base64.StdEncoding.EncodeToString([]byte("ciphertext-bytes")),
			"nonce":          base64.StdEncoding.EncodeToString(make([]byte, 12)),
			"dek_ciphertext": base64.StdEncoding.EncodeToString([]byte("vault:v1:not-a-real-dek")),
		},
	}
	r := hygDo(t, fx.app, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/wraps", nil, hdr, body)
	if r.status != http.StatusBadRequest {
		t.Fatalf("envelope KMS failure: status = %d; want 400 (%s)", r.status, r.body)
	}
	hygAssertNoLeak(t, "wrap envelope", r, hygVaultHost, hygTransitKey, "transit", "keymgmt", "invalid ciphertext")
	if got, _ := r.json(t)["error"].(string); got != "envelope: data key could not be decrypted" {
		t.Errorf("error = %q; want the stable envelope message", got)
	}
	if !strings.Contains(fx.logs.String(), hygTransitKey) {
		t.Errorf("KMS detail should be logged server side for triage")
	}

	// KMS fine but the agent's ciphertext does not authenticate.
	fx.km.failDecrypt.Store(false)
	dk, err := fx.km.GenerateDataKey(t.Context())
	if err != nil {
		t.Fatalf("dek: %v", err)
	}
	body["envelope"].(map[string]any)["dek_ciphertext"] = base64.StdEncoding.EncodeToString(dk.Ciphertext)
	body["envelope"].(map[string]any)["dek_kms_key_id"] = dk.KeyID
	r = hygDo(t, fx.app, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/wraps", nil, hdr, body)
	if r.status != http.StatusBadRequest {
		t.Fatalf("bad ciphertext: status = %d; want 400 (%s)", r.status, r.body)
	}
	hygAssertNoLeak(t, "bad ciphertext", r, "cipher:", "message authentication failed")
	if got, _ := r.json(t)["error"].(string); got != "envelope: ciphertext could not be authenticated" {
		t.Errorf("error = %q; want the stable envelope message", got)
	}

	// DEK issuance on a KMS outage: generic 500.
	fx.km.failGenerate.Store(true)
	r = hygDo(t, fx.app, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/dek", nil, hdr, nil)
	if r.status != http.StatusInternalServerError {
		t.Fatalf("dek KMS outage: status = %d; want 500 (%s)", r.status, r.body)
	}
	hygAssertNoLeak(t, "dek issue", r, hygVaultHost, hygTransitKey, "transit")
}

// ---------------------------------------------------------------------
// API-S-20: Cache-Control: no-store on secret-bearing responses
// ---------------------------------------------------------------------

func TestHygiene_NoStore_SecretBearingResponses(t *testing.T) {
	fx := newHygFixture(t, Config{AllowDirectAgentMint: true}, nil)
	ctx := t.Context()

	// 1. Login sets the session cookie.
	const pw = "hyg-test-password-not-real"
	loginUser := fx.userWithPassword(t, "login-user", pw)
	r := fx.do(t, http.MethodPost, "/api/v1/auth/login", nil, map[string]any{"email": loginUser.email, "password": pw})
	if r.status != http.StatusOK {
		t.Fatalf("login: status = %d (%s)", r.status, r.body)
	}
	hygAssertNoStore(t, "POST /auth/login", r)

	// 2. TOTP enroll returns the seed + otpauth URI.
	u := fx.user(t, "totp-nostore")
	r = fx.do(t, http.MethodPost, "/api/v1/users/me/mfa/totp/enroll", u, map[string]any{"label": "phone"})
	if r.status != http.StatusOK {
		t.Fatalf("totp enroll: status = %d (%s)", r.status, r.body)
	}
	if _, ok := r.json(t)["secret_base32"]; !ok {
		t.Fatalf("totp enroll should return the seed; got %s", r.body)
	}
	hygAssertNoStore(t, "POST /users/me/mfa/totp/enroll", r)

	// 3. Enrollment token creation returns a one-time token.
	minter := fx.user(t, "minter", auth.PermAgentMint)
	conn, err := storage.NewProviderConnections(fx.pool).Create(ctx, storage.ProviderConnectionInput{
		Name:       hygName("hyg-conn"),
		Type:       storage.ProviderConnectionTypeVault,
		AuthMethod: "kubernetes",
		Scope:      map[string]string{"address": "https://" + hygVaultHost, "mount": "secret", "role": "sb-agent"},
		Status:     storage.ProviderConnectionStatusActive,

		DiscoverIntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("seed provider connection: %v", err)
	}
	r = fx.do(t, http.MethodPost, "/api/v1/provider-connections/"+conn.ID.String()+"/agent-enrollment-token", minter,
		map[string]any{"name": "hyg"})
	if r.status != http.StatusCreated {
		t.Fatalf("enrollment token: status = %d (%s)", r.status, r.body)
	}
	hygAssertNoStore(t, "POST /provider-connections/:id/agent-enrollment-token", r)
	enrollToken, _ := r.json(t)["enrollment_token"].(string)

	// 4. Self-enrollment returns the persistent agent credential.
	r = fx.do(t, http.MethodPost, "/api/v1/agents/enroll", nil, map[string]any{
		"enrollment_token": enrollToken, "agent_name": hygName("hyg-enrolled"), "provider_type": "vault",
	})
	if r.status != http.StatusCreated {
		t.Fatalf("enroll: status = %d (%s)", r.status, r.body)
	}
	hygAssertNoStore(t, "POST /agents/enroll", r)

	// 5. Legacy direct mint returns agent_secret.
	r = fx.do(t, http.MethodPost, "/api/v1/agents", minter, map[string]any{"name": hygName("hyg-legacy")})
	if r.status != http.StatusCreated {
		t.Fatalf("legacy mint: status = %d (%s)", r.status, r.body)
	}
	hygAssertNoStore(t, "POST /agents", r)

	// 6. DEK issuance returns a plaintext data key.
	agentID, secret := fx.mintAgent(t)
	agentHdr := map[string]string{"X-Agent-Secret": secret}
	r = hygDo(t, fx.app, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/dek", nil, agentHdr, nil)
	if r.status != http.StatusCreated {
		t.Fatalf("dek: status = %d (%s)", r.status, r.body)
	}
	hygAssertNoStore(t, "POST /agents/:id/dek", r)

	// 7. Agent wrap retrieval returns the value (or the sealed value).
	_, agentWrap := fx.approvedReadWithWrap(t, u.id)
	r = hygDo(t, fx.app, http.MethodGet, "/api/v1/agents/"+agentID.String()+"/wraps/"+agentWrap.String(), nil, agentHdr, nil)
	if r.status == http.StatusOK && !strings.Contains(r.body, `"value"`) && !strings.Contains(r.body, `"sealed"`) {
		t.Errorf("agent wrap retrieve 200 without a value: %s", r.body)
	}
	hygAssertNoStore(t, "GET /agents/:id/wraps/:wrap_id", r)

	// 8. User wrap retrieval returns the plaintext.
	reqID, userWrap := fx.approvedReadWithWrap(t, u.id)
	r = fx.do(t, http.MethodGet, "/api/v1/requests/"+reqID.String()+"/wraps/"+userWrap.String(), u, nil)
	if r.status == http.StatusOK && !strings.Contains(r.body, `"value"`) {
		t.Errorf("user wrap retrieve 200 without a value: %s", r.body)
	}
	hygAssertNoStore(t, "GET /requests/:id/wraps/:wrap_id", r)

	// 9. Reveal-session open (value pickup handshake).
	revealReq, _ := fx.approvedReadWithWrap(t, u.id)
	r = fx.do(t, http.MethodPost, "/api/v1/reveal-sessions", u, map[string]any{"access_request_id": revealReq.String()})
	hygAssertNoStore(t, "POST /reveal-sessions", r)
}

// Every /api/v1 route carries no-store, whatever the status, so a route
// added later is covered without anyone remembering to opt in. The one
// deliberate exception is the static permission catalog, which keeps
// its public cache header for authenticated callers.
func TestHygiene_NoStore_EveryV1Route(t *testing.T) {
	fx := newHygFixture(t, Config{GitOpsEnabled: true, AllowDirectAgentMint: true}, nil)
	id := uuid.NewString()
	seen := 0
	for _, rt := range fx.app.GetRoutes(true) {
		if !strings.HasPrefix(rt.Path, "/api/v1/") {
			continue
		}
		path := rt.Path
		for _, p := range rt.Params {
			path = strings.Replace(path, ":"+p, id, 1)
		}
		r := hygDo(t, fx.app, rt.Method, path, nil, nil, nil)
		hygAssertNoStore(t, rt.Method+" "+rt.Path, r)
		seen++
	}
	if seen < 50 {
		t.Fatalf("only %d /api/v1 routes exercised; route enumeration looks broken", seen)
	}
	// An unmatched path under the group is covered as well.
	hygAssertNoStore(t, "GET /api/v1/does-not-exist", hygDo(t, fx.app, http.MethodGet, "/api/v1/does-not-exist", nil, nil, nil))

	u := fx.user(t, "catalog-reader")
	r := fx.do(t, http.MethodGet, "/api/v1/permissions", u, nil)
	if r.status != http.StatusOK {
		t.Fatalf("permissions: status = %d", r.status)
	}
	if cc := r.header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("permissions catalog Cache-Control = %q; want its public cache header kept", cc)
	}
	if p := r.header.Get("Pragma"); p != "" {
		t.Errorf("permissions catalog Pragma = %q; want none next to a public cache header", p)
	}

	// Probes and metrics are outside /api/v1 and keep their defaults.
	r = hygDo(t, fx.app, http.MethodGet, "/healthz", nil, nil, nil)
	if cc := r.header.Get("Cache-Control"); cc != "" {
		t.Errorf("/healthz Cache-Control = %q; want unchanged (none)", cc)
	}
}

// ---------------------------------------------------------------------
// API-S-22: ArgoCD base URL scheme
// ---------------------------------------------------------------------

func hygArgoBody(baseURL string) map[string]any {
	return map[string]any{
		"name":      hygName("hyg-argocd"),
		"base_url":  baseURL,
		"token_b64": base64.StdEncoding.EncodeToString([]byte("hyg-fake-argocd-token")),
	}
}

func TestHygiene_ArgoCD_BaseURLSchemeByEnv(t *testing.T) {
	km := newHygKMS(t)
	prod := newHygFixture(t, Config{Env: ModeProduction, GitOpsEnabled: true}, km)
	dev := newHygFixture(t, Config{Env: ModeDev, GitOpsEnabled: true}, km)
	flagged := newHygFixture(t, Config{Env: ModeProduction, GitOpsEnabled: true, AllowInsecureArgoCDAddr: true}, km)

	cases := []struct {
		name string
		fx   *hygFixture
		url  string
		want int
	}{
		{"prod http refused", prod, "http://argocd.example.com", http.StatusBadRequest},
		{"prod http in-cluster refused", prod, "http://argocd-server.argocd.svc", http.StatusBadRequest},
		{"prod https accepted", prod, "https://argocd.example.com", http.StatusCreated},
		{"prod https in-cluster accepted", prod, "https://argocd-server.argocd.svc.cluster.local", http.StatusCreated},
		{"prod malformed refused", prod, "ftp://argocd.example.com", http.StatusBadRequest},
		{"prod no host refused", prod, "https://", http.StatusBadRequest},
		{"prod user info refused", prod, "https://admin:pw@argocd.example.com", http.StatusBadRequest},
		{"prod user only refused", prod, "https://admin@argocd.example.com", http.StatusBadRequest},
		{"prod query refused", prod, "https://argocd.example.com/?token=abc", http.StatusBadRequest},
		{"prod empty query refused", prod, "https://argocd.example.com/?", http.StatusBadRequest},
		{"prod fragment refused", prod, "https://argocd.example.com/#x", http.StatusBadRequest},
		{"dev user info refused", dev, "http://admin:pw@argocd-server.argocd.svc", http.StatusBadRequest},
		{"prod https with port and path accepted", prod, "https://argocd.example.com:8443/argocd", http.StatusCreated},
		{"dev http accepted", dev, "http://argocd-server.argocd.svc", http.StatusCreated},
		{"dev https accepted", dev, "https://argocd.example.com", http.StatusCreated},
		{"prod+flag http accepted", flagged, "http://argocd-server.argocd.svc", http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			admin := tc.fx.user(t, "argo-admin", auth.PermIntegrationEdit)
			r := tc.fx.do(t, http.MethodPost, "/api/v1/argocd-endpoints", admin, hygArgoBody(tc.url))
			if r.status != tc.want {
				t.Fatalf("POST %s: status = %d; want %d (%s)", tc.url, r.status, tc.want, r.body)
			}
			if tc.want == http.StatusBadRequest {
				hygAssertNoLeak(t, tc.name, r, "hyg-fake-argocd-token")
				if !strings.Contains(r.body, "base_url") {
					t.Errorf("refusal should name base_url: %s", r.body)
				}
			}
		})
	}
}

// A row written before the check (an http:// base URL in production)
// must not be used to send the bearer token in clear text.
func TestHygiene_ArgoCD_LegacyHTTPRowNotUsedInProduction(t *testing.T) {
	var hits atomic.Int32
	var sawAuth atomic.Bool
	argo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "" {
			sawAuth.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	t.Cleanup(argo.Close)

	km := newHygKMS(t)
	dev := newHygFixture(t, Config{Env: ModeDev, GitOpsEnabled: true}, km)
	prod := newHygFixture(t, Config{Env: ModeProduction, GitOpsEnabled: true}, km)

	devAdmin := dev.user(t, "argo-dev-admin", auth.PermIntegrationEdit)
	r := dev.do(t, http.MethodPost, "/api/v1/argocd-endpoints", devAdmin, hygArgoBody(argo.URL))
	if r.status != http.StatusCreated {
		t.Fatalf("seed legacy http endpoint: %d %s", r.status, r.body)
	}
	epID, _ := r.json(t)["id"].(string)

	prodUser := prod.user(t, "argo-prod-user", auth.PermIntegrationEdit)
	r = prod.do(t, http.MethodGet, "/api/v1/argocd-endpoints/"+epID+"/discovered-apps", prodUser, nil)
	if r.status != http.StatusConflict {
		t.Fatalf("production discovery over http: status = %d; want 409 (%s)", r.status, r.body)
	}
	if hits.Load() != 0 || sawAuth.Load() {
		t.Fatalf("production sent %d request(s) to the http endpoint (auth header: %v)", hits.Load(), sawAuth.Load())
	}

	// Dev still works against the same row.
	r = dev.do(t, http.MethodGet, "/api/v1/argocd-endpoints/"+epID+"/discovered-apps", devAdmin, nil)
	if r.status != http.StatusOK {
		t.Fatalf("dev discovery: status = %d; want 200 (%s)", r.status, r.body)
	}
	if hits.Load() == 0 {
		t.Fatalf("dev discovery should reach the endpoint")
	}
}

// A row written before the user-info check (api#279) is refused on use
// too: nothing goes out to the endpoint.
func TestHygiene_ArgoCD_LegacyUserInfoRowNotUsed(t *testing.T) {
	var hits atomic.Int32
	argo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	t.Cleanup(argo.Close)

	dev := newHygFixture(t, Config{Env: ModeDev, GitOpsEnabled: true}, nil)
	admin := dev.user(t, "argo-userinfo-admin", auth.PermIntegrationEdit)
	r := dev.do(t, http.MethodPost, "/api/v1/argocd-endpoints", admin, hygArgoBody(argo.URL))
	if r.status != http.StatusCreated {
		t.Fatalf("seed endpoint: %d %s", r.status, r.body)
	}
	epID, _ := r.json(t)["id"].(string)
	legacy := strings.Replace(argo.URL, "http://", "http://admin:pw@", 1) + "/?token=abc"
	if _, err := dev.pool.Exec(t.Context(), `UPDATE argocd_endpoints SET base_url = $1 WHERE id = $2`, legacy, epID); err != nil {
		t.Fatalf("write legacy row: %v", err)
	}
	r = dev.do(t, http.MethodGet, "/api/v1/argocd-endpoints/"+epID+"/discovered-apps", admin, nil)
	if r.status != http.StatusConflict {
		t.Fatalf("discovery with user info: status = %d; want 409 (%s)", r.status, r.body)
	}
	if hits.Load() != 0 {
		t.Fatalf("sent %d request(s) to an endpoint whose URL carries user info", hits.Load())
	}
}

// ---------------------------------------------------------------------
// GitOps observation rows: legacy free text and raw last_error
// ---------------------------------------------------------------------

func TestHygiene_GitOpsObservations_LegacyRowShaped(t *testing.T) {
	fx := newHygFixture(t, Config{GitOpsEnabled: true}, nil)
	ctx := t.Context()
	requester := fx.user(t, "gitops-requester")
	reqID, _ := fx.approvedReadWithWrap(t, requester.id)

	admin := fx.user(t, "gitops-admin", auth.PermIntegrationEdit)
	r := fx.do(t, http.MethodPost, "/api/v1/argocd-endpoints", admin, hygArgoBody("https://argocd.example.com"))
	if r.status != http.StatusCreated {
		t.Fatalf("seed endpoint: %d %s", r.status, r.body)
	}
	epID := uuid.MustParse(r.json(t)["id"].(string))

	const (
		leakToken = "hvs.CAESIhygLegacyTokenLeakCanary0123456789"
		leakURL   = "https://argocd.example.com/api/v1/applications/billing-api"
	)
	obsRepo := storage.NewGitOpsObservations(fx.pool)
	obs := &storage.GitOpsObservation{
		RequestID:        reqID,
		ArgoCDEndpointID: epID,
		ApplicationName:  "billing-api",
		PollingState:     storage.GitOpsStateActive,
	}
	if err := obsRepo.Create(ctx, obs); err != nil {
		t.Fatalf("seed observation: %v", err)
	}
	// Shape written by the worker before it stopped persisting free text.
	legacy := map[string]any{
		"health_status":   "Degraded",
		"health_message":  "readiness probe failed: token=" + leakToken,
		"sync_status":     "Synced",
		"sync_revision":   "abc123",
		"operation_phase": "Running",
		"resource_count":  1,
		"resources": []any{map[string]any{
			"kind": "Deployment", "name": "billing-api", "namespace": "billing",
			"health": "Degraded", "message": "dial " + leakURL + " failed",
		}},
	}
	rawErr := `argocd fetch: argocd: /api/v1/applications/billing-api: Get "` + leakURL + `": dial tcp: lookup argocd.example.com: no such host`
	if err := obsRepo.RecordPoll(ctx, obs.ID, legacy, rawErr, time.Now().UTC()); err != nil {
		t.Fatalf("seed poll: %v", err)
	}

	r = fx.do(t, http.MethodGet, "/api/v1/requests/"+reqID.String()+"/gitops", requester, nil)
	if r.status != http.StatusOK {
		t.Fatalf("observations: status = %d (%s)", r.status, r.body)
	}
	hygAssertNoLeak(t, "observations", r, leakToken, "readiness probe", leakURL, "argocd.example.com", "no such host", "dial")

	var rows []map[string]any
	if err := json.Unmarshal([]byte(r.body), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("rows: %v (%s)", err, r.body)
	}
	row := rows[0]
	if got := row["last_error"]; got != "argocd_unreachable" {
		t.Errorf("last_error = %v; want the stable class argocd_unreachable", got)
	}
	state, _ := row["observed_state"].(map[string]any)
	if _, ok := state["health_message"]; ok {
		t.Errorf("health_message should be stripped: %v", state)
	}
	if state["health_status"] != "Degraded" || state["sync_status"] != "Synced" {
		t.Errorf("status fields must survive: %v", state)
	}
	res, _ := state["resources"].([]any)
	if len(res) != 1 {
		t.Fatalf("resources: %v", state["resources"])
	}
	if first, _ := res[0].(map[string]any); first["kind"] != "Deployment" || first["health"] != "Degraded" {
		t.Errorf("resource metadata must survive: %v", first)
	} else if _, ok := first["message"]; ok {
		t.Errorf("resource message should be stripped: %v", first)
	}

	// The stored row is untouched (read-side shaping only).
	stored, err := obsRepo.ListForRequest(ctx, reqID)
	if err != nil || len(stored) != 1 || stored[0].LastError != rawErr {
		t.Errorf("stored row should be unchanged by a read: %v", err)
	}
}

// ---------------------------------------------------------------------
// Cross-team: a disabled destination connection is a stable 409
// ---------------------------------------------------------------------

func TestHygiene_CrossTeamSubmit_DisabledDestinationIs409(t *testing.T) {
	fx := newHygFixture(t, Config{}, nil)
	ctx := t.Context()

	team := &storage.Team{Name: hygName("hyg-team-b"), Status: storage.TeamStatusActive}
	if err := storage.NewTeams(fx.pool).Create(ctx, team); err != nil {
		t.Fatalf("team: %v", err)
	}
	targetProj := &storage.Project{Name: hygName("hyg-target"), TeamID: &team.ID, Status: storage.ProjectStatusActive}
	if err := storage.NewProjects(fx.pool).Create(ctx, targetProj); err != nil {
		t.Fatalf("target project: %v", err)
	}
	targetEnv := &storage.Environment{ProjectID: targetProj.ID, Name: "tenant-a-uat", Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd}
	if err := storage.NewEnvironments(fx.pool).Create(ctx, targetEnv); err != nil {
		t.Fatalf("target env: %v", err)
	}
	sourceProj := &storage.Project{Name: hygName("hyg-source"), Status: storage.ProjectStatusActive}
	if err := storage.NewProjects(fx.pool).Create(ctx, sourceProj); err != nil {
		t.Fatalf("source project: %v", err)
	}
	conn, err := storage.NewProviderConnections(fx.pool).Create(ctx, storage.ProviderConnectionInput{
		Name:       hygName("hyg-dest"),
		Type:       storage.ProviderConnectionTypeVault,
		AuthMethod: "kubernetes",
		Scope:      map[string]string{"address": "https://" + hygVaultHost, "mount": "secret", "role": "sb-agent"},
		Status:     storage.ProviderConnectionStatusDisabled,

		DiscoverIntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("connection: %v", err)
	}
	// Bound to the source project so the only thing wrong is "disabled".
	if _, err := storage.NewProjectProviderConnections(fx.pool).Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: sourceProj.ID, ProviderConnectionID: conn.ID,
		Purpose: storage.ProjectProviderConnectionPurposeDestination, CreatedBy: "test",
	}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	requester := fx.user(t, "ct-requester", auth.PermSecretRequest)
	r := fx.do(t, http.MethodPost, "/api/v1/requests/cross-team", requester, map[string]any{
		"project_id":                         sourceProj.ID.String(),
		"environment":                        "tenant-a-uat",
		"target_team_id":                     team.ID.String(),
		"target_project_id":                  targetProj.ID.String(),
		"target_environment_id":              targetEnv.ID.String(),
		"destination_provider_connection_id": conn.ID.String(),
		"destination_secret_ref":             "team-alpha/uat/db",
		"destination_keys":                   []string{"password"},
		"justification":                      "response hygiene test",
	})
	if r.status != http.StatusConflict {
		t.Fatalf("disabled destination: status = %d; want 409 (%s)", r.status, r.body)
	}
	if got, _ := r.json(t)["error"].(string); got != "provider_connection_disabled" {
		t.Errorf("error = %q; want provider_connection_disabled", got)
	}
}

// ---------------------------------------------------------------------
// Scoped policy authoring: an unknown workflow_id is a stable 403
// ---------------------------------------------------------------------

// The team-anchored path collapses not-found / disabled / not-authorable
// workflows into one 403 envelope. The project-anchored path used to let
// the storage not-found fall through to a 500.
func TestHygiene_ScopedPolicyCreate_UnknownWorkflowIs403(t *testing.T) {
	fx := newHygFixture(t, Config{}, nil)
	proj := &storage.Project{Name: hygName("hyg-policy-proj"), Status: storage.ProjectStatusActive}
	if err := storage.NewProjects(fx.pool).Create(t.Context(), proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	author := fx.user(t, "policy-author", auth.PermPolicyAuthor)
	missingWF := uuid.NewString()
	r := fx.do(t, http.MethodPost, "/api/v1/projects/"+proj.ID.String()+"/policy-rules", author, map[string]any{
		"name":        hygName("hyg-rule"),
		"selector":    map[string]any{"environment_kind": "non_prod"},
		"priority":    100,
		"workflow_id": missingWF,
		"enabled":     true,
	})
	if r.status != http.StatusForbidden {
		t.Fatalf("unknown workflow: status = %d; want 403 (%s)", r.status, r.body)
	}
	m := r.json(t)
	if m["error_code"] != "workflow_not_authorable_for_scope" || m["workflow_id"] != missingWF {
		t.Errorf("envelope = %v; want workflow_not_authorable_for_scope + workflow_id", m)
	}
}

// swapDefaultLogger makes logger the slog default for one test.
// slog.SetDefault also points the standard log package at the new
// handler, and setting the default back does not undo that, so the log
// output, flags and prefix are saved and restored too. Without it every
// later log line in the package lands in this test's buffer (api#279).
func swapDefaultLogger(t *testing.T, logger *slog.Logger) {
	t.Helper()
	prev := slog.Default()
	prevOut, prevFlags, prevPrefix := log.Writer(), log.Flags(), log.Prefix()
	slog.SetDefault(logger)
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	})
}

// After a test that swapped the default logger, the standard log
// package writes where it did before, not into that test's buffer.
func TestSwapDefaultLogger_RestoresLogOutput(t *testing.T) {
	before := log.Writer()
	buf := &hygLogBuffer{}
	t.Run("swap", func(t *testing.T) {
		swapDefaultLogger(t, slog.New(slog.NewJSONHandler(buf, nil)))
		log.Print("inside")
	})
	if log.Writer() != before {
		t.Fatal("log output still points at the swapped logger")
	}
	log.Print("after the swap")
	if strings.Contains(buf.String(), "after the swap") {
		t.Fatal("a later log line landed in the swapped logger's buffer")
	}
}
