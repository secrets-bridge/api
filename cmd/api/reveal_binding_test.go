package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Regression tests for the direct-reveal / per-env request binding gate
// (api#191 H2, API-S-03, API-S-04, api#154). They drive the REAL router
// built by newApp (session cookie auth, default-deny group, auth.Require,
// requireMFA step-up, the real handlers and services) against real
// Postgres + Redis. SKIP without TEST_DATABASE_URL + TEST_REDIS_URL.
//
// Fixture (one project "tenant-a" with a non_prod "uat" env and a prod
// "prod" env):
//
//	team-alpha/uat/db       bound to uat, allowed_keys [DB_PASSWORD], ops [read]
//	team-alpha/uat/legacy   bound with environment_id NULL (pre-L3 row), ops [read]
//	team-alpha/uat/patch    bound to uat, ops [patch] only
//	team-alpha/prod/db      bound to prod only, ops [read]
//	team-alpha/uat/unbound  in the catalog, bound to nothing
//
// The catalog rows carry the provider_config discovery recorded, which
// includes a connection-identity key (address) the agent refuses in a
// job payload; the derived job config must drop it.

const (
	rbRequesterEmail = "dr-requester@example.com"
	rbFakeValue      = "fake-value-not-real"
)

type revealBindingFx struct {
	app       *fiber.App
	pool      *storage.Pool
	wrapSvc   *services.WrapService
	project   uuid.UUID
	uat       uuid.UUID
	prod      uuid.UUID
	requester uuid.UUID
	cookie    string
}

func bootstrapRevealBinding(t *testing.T) *revealBindingFx {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL required; skipping")
	}
	ctx := t.Context()

	cfg := storage.Config{DSN: dsn, MaxConns: 8, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	rdb, err := runtime.Open(ctx, runtime.Config{URL: redisURL, Namespace: "sb-test-reveal-binding"})
	if err != nil {
		t.Fatalf("redis Open: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	const wipe = `
		DELETE FROM reveal_sessions;
		DELETE FROM secret_wraps;
		DELETE FROM approvals;
		DELETE FROM sync_jobs;
		DELETE FROM access_requests;
		DELETE FROM project_secrets;
		DELETE FROM secrets;
		DELETE FROM team_members;
		DELETE FROM teams;
		DELETE FROM user_roles;
		DELETE FROM roles WHERE is_system = false;
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;
		DELETE FROM environments;
		DELETE FROM projects;
		DELETE FROM local_users;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	km, err := keymgmt.NewLocalKMS(masterKey)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}
	jwtSecret := make([]byte, 32)
	if _, err := rand.Read(jwtSecret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	authSvc := services.NewAuthService(
		storage.NewLocalUsers(pool), storage.NewRoles(pool), storage.NewUserRoles(pool),
		storage.NewAuditEvents(pool), auth.NewSigner(jwtSecret), time.Hour,
	)

	// newApp writes the package-level header-identity switch from cfg;
	// restore whatever the other tests in this package expect.
	prevHeader := middleware.AllowInsecureHeaderIdentity
	t.Cleanup(func() { middleware.AllowInsecureHeaderIdentity = prevHeader })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := newApp(Config{
		Env:                            ModeDev,
		JWTTokenTTL:                    time.Hour,
		MFATOTPIssuer:                  "Secrets Bridge",
		ProviderConnRejectSecretValues: true,
	}, logger, pool, rdb, km, authSvc)

	fx := &revealBindingFx{
		app:     app,
		pool:    pool,
		wrapSvc: services.NewWrapService(storage.NewSecretWraps(pool), storage.NewAuditEvents(pool), km),
	}

	// Requester: a local user holding global secret.reveal.direct +
	// secret.request (what the dev endpoints' auth.Require gates need).
	fx.requester = uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO local_users (id, email, password_hash, display_name) VALUES ($1, $2, $3, 'dr requester')`,
		fx.requester, rbRequesterEmail, []byte{0x00}); err != nil {
		t.Fatalf("seed local user: %v", err)
	}
	roleID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO roles (id, name, permissions, is_system) VALUES ($1, 'dr-requester-role', '["secret.reveal.direct","secret.request"]'::jsonb, false)`,
		roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (id, user_id, role_id, scope) VALUES ($1, $2, $3, '{}'::jsonb)`,
		uuid.New(), fx.requester, roleID); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}

	// Project + environments.
	project := &storage.Project{Name: "tenant-a"}
	if err := storage.NewProjects(pool).Create(ctx, project); err != nil {
		t.Fatalf("project Create: %v", err)
	}
	fx.project = project.ID
	envRepo := storage.NewEnvironments(pool)
	uat := &storage.Environment{ProjectID: project.ID, Name: "uat", Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd}
	prod := &storage.Environment{ProjectID: project.ID, Name: "prod", Type: storage.EnvironmentTypeProd, Kind: storage.EnvironmentKindProd}
	for _, e := range []*storage.Environment{uat, prod} {
		if err := envRepo.Create(ctx, e); err != nil {
			t.Fatalf("env Create %s: %v", e.Name, err)
		}
	}
	fx.uat, fx.prod = uat.ID, prod.ID

	// Policy: direct reveal allowed on tenant-a/uat (never reachable on
	// prod — Gate 1 refuses before the policy lookup).
	wf := &storage.WorkflowDefinition{
		Name: "rb-uat-wf", MinApprovers: 1, AllowSelfApproval: false,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := storage.NewWorkflows(pool).Create(ctx, wf); err != nil {
		t.Fatalf("workflow Create: %v", err)
	}
	if err := storage.NewPolicies(pool).Create(ctx, &storage.PolicyRule{
		Name:                "rb-uat-direct",
		Selector:            map[string]any{"project_id": project.ID.String(), "environment": "uat"},
		WorkflowID:          wf.ID,
		Priority:            500,
		Enabled:             true,
		DirectRevealAllowed: true,
		RevealTTLSeconds:    120,
	}); err != nil {
		t.Fatalf("policy Create: %v", err)
	}

	// Catalog rows + bindings.
	discovered := map[string]any{"address": "https://vault.example.com", "kvMount": "kv", "kvPrefix": "team-alpha"}
	secretsRepo := storage.NewSecrets(pool)
	bindings := storage.NewProjectSecrets(pool)
	seed := func(ref string, envID *uuid.UUID, keys []string, ops []string, bind bool) {
		t.Helper()
		sec := &storage.Secret{
			ClusterName: "tenant-a-uat", ProviderType: "vault", SecretRef: ref,
			ProviderConfig: discovered, Status: storage.SecretStatusPresent,
		}
		if err := secretsRepo.Upsert(ctx, sec); err != nil {
			t.Fatalf("secret Upsert %s: %v", ref, err)
		}
		if !bind {
			return
		}
		if err := bindings.Bind(ctx, &storage.ProjectSecret{
			ProjectID: project.ID, SecretID: sec.ID, EnvironmentID: envID,
			AllowedKeys: keys, AllowedOps: ops, CreatedBy: "reveal-binding-test",
		}); err != nil {
			t.Fatalf("Bind %s: %v", ref, err)
		}
	}
	seed("team-alpha/uat/db", &uat.ID, []string{"DB_PASSWORD"}, []string{storage.OpRead}, true)
	seed("team-alpha/uat/legacy", nil, nil, []string{storage.OpRead}, true)
	seed("team-alpha/uat/patch", &uat.ID, nil, []string{storage.OpPatch}, true)
	seed("team-alpha/prod/db", &prod.ID, nil, []string{storage.OpRead}, true)
	seed("team-alpha/uat/unbound", nil, nil, nil, false)
	// Env-scoped bindings would block other packages' wipes that delete
	// environments without clearing project_secrets first.
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM project_secrets WHERE project_id = $1`, project.ID)
	})

	// Cookie session with a fresh MFA stamp, so the real requireMFA
	// step-up gate in front of direct-reveal lets the request through.
	sessSvc := services.NewSessionService(storage.NewSessions(pool), storage.NewAuditEvents(pool))
	issued, err := sessSvc.Issue(ctx, fx.requester, "127.0.0.1", "reveal-binding-test")
	if err != nil {
		t.Fatalf("session Issue: %v", err)
	}
	if err := sessSvc.MarkMFA(ctx, issued.Session.ID, time.Now()); err != nil {
		t.Fatalf("MarkMFA: %v", err)
	}
	fx.cookie = issued.CookieValue
	return fx
}

// post sends an authenticated JSON POST through the real app and returns
// the status + decoded body (nil when the body isn't a JSON object).
func (fx *revealBindingFx) post(t *testing.T, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: fx.cookie})
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func (fx *revealBindingFx) directReveal(t *testing.T, envID uuid.UUID, body map[string]any) (int, map[string]any) {
	t.Helper()
	return fx.post(t, "/api/v1/projects/"+fx.project.String()+"/environments/"+envID.String()+"/direct-reveal", body)
}

func (fx *revealBindingFx) envRequest(t *testing.T, envID uuid.UUID, body map[string]any) (int, map[string]any) {
	t.Helper()
	return fx.post(t, "/api/v1/projects/"+fx.project.String()+"/environments/"+envID.String()+"/request", body)
}

func revealBody(ref string, keys ...string) map[string]any {
	b := map[string]any{
		"target_provider_type": "vault",
		"target_secret_ref":    ref,
		"justification":        "reveal-binding regression",
	}
	if keys != nil {
		b["target_keys"] = keys
	}
	return b
}

func (fx *revealBindingFx) countRequests(t *testing.T) int {
	t.Helper()
	var n int
	if err := fx.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM access_requests WHERE requester_id = $1`, fx.requester.String()).Scan(&n); err != nil {
		t.Fatalf("count requests: %v", err)
	}
	return n
}

func (fx *revealBindingFx) countAudit(t *testing.T, action, reason string) int {
	t.Helper()
	var n int
	if err := fx.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_events WHERE action = $1 AND metadata->>'refusal_reason' = $2`,
		action, reason).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// jobProviderConfig returns the target_provider_config the enqueued job
// carries for a request (the exact map an agent would receive).
func (fx *revealBindingFx) jobProviderConfig(t *testing.T, requestID string) map[string]any {
	t.Helper()
	var raw []byte
	if err := fx.pool.QueryRow(t.Context(),
		`SELECT payload->'target_provider_config' FROM sync_jobs WHERE request_id = $1`, requestID).Scan(&raw); err != nil {
		t.Fatalf("load job payload for %s: %v", requestID, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("decode job provider config: %v (raw %s)", err, raw)
	}
	return cfg
}

func (fx *revealBindingFx) storedProviderConfig(t *testing.T, requestID string) string {
	t.Helper()
	var raw string
	if err := fx.pool.QueryRow(t.Context(),
		`SELECT target_provider_config::text FROM access_requests WHERE id = $1`, requestID).Scan(&raw); err != nil {
		t.Fatalf("load stored provider config: %v", err)
	}
	return raw
}

var attackerProviderConfig = map[string]any{
	"kvMount":  "attacker-mount",
	"kvPrefix": "team-beta",
	"address":  "https://attacker.example.com",
}

func assertNoAttackerConfig(t *testing.T, where, got string) {
	t.Helper()
	for _, bad := range []string{"attacker-mount", "team-beta", "attacker.example.com"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s carries requester-supplied provider config %q: %s", where, bad, got)
		}
	}
}

// H2: a direct reveal of a ref the project has no read binding for is
// refused (fail closed, generic 403, audited) and writes no request row.
func TestDirectReveal_UnboundRefRefused(t *testing.T) {
	fx := bootstrapRevealBinding(t)

	for _, ref := range []string{
		"team-alpha/uat/unbound",        // in the catalog, bound to nothing
		"team-alpha/uat/not-in-catalog", // not in the catalog at all
	} {
		st, body := fx.directReveal(t, fx.uat, revealBody(ref, "DB_PASSWORD"))
		if st != http.StatusForbidden {
			t.Errorf("direct reveal of unbound %s = %d body=%v; want 403", ref, st, body)
		}
	}
	// A binding that does not allow the read op is not a read binding.
	if st, body := fx.directReveal(t, fx.uat, revealBody("team-alpha/uat/patch", "DB_PASSWORD")); st != http.StatusForbidden {
		t.Errorf("direct reveal of patch-only binding = %d body=%v; want 403", st, body)
	}

	if n := fx.countRequests(t); n != 0 {
		t.Errorf("access_requests rows = %d; want 0 (refusal must happen before the row is written)", n)
	}
	if n := fx.countAudit(t, "secret.reveal.direct.refused_binding", "secret_not_bound"); n != 2 {
		t.Errorf("refused_binding/secret_not_bound audit rows = %d; want 2", n)
	}
	if n := fx.countAudit(t, "secret.reveal.direct.refused_binding", "op_not_allowed"); n != 1 {
		t.Errorf("refused_binding/op_not_allowed audit rows = %d; want 1", n)
	}
}

// API-S-03: a ref bound only to the prod environment cannot be
// direct-revealed through the project's non-prod environment URL.
func TestDirectReveal_ProdBoundRefViaNonProdURLRefused(t *testing.T) {
	fx := bootstrapRevealBinding(t)

	st, body := fx.directReveal(t, fx.uat, revealBody("team-alpha/prod/db", "DB_PASSWORD"))
	if st != http.StatusForbidden {
		t.Fatalf("direct reveal of prod-bound ref via uat URL = %d body=%v; want 403", st, body)
	}
	if n := fx.countRequests(t); n != 0 {
		t.Errorf("access_requests rows = %d; want 0", n)
	}
	if n := fx.countAudit(t, "secret.reveal.direct.refused_binding", "binding_env_mismatch"); n != 1 {
		t.Errorf("refused_binding/binding_env_mismatch audit rows = %d; want 1", n)
	}
}

// API-S-04: target_provider_config from the request body never reaches
// the job payload (the agent would honour kvMount/kvPrefix from it). The
// job carries the config derived from the bound catalog row, filtered to
// the keys the agent accepts.
func TestDirectReveal_BodyProviderConfigNotForwarded(t *testing.T) {
	fx := bootstrapRevealBinding(t)

	body := revealBody("team-alpha/uat/db", "DB_PASSWORD")
	body["target_provider_config"] = attackerProviderConfig
	st, resp := fx.directReveal(t, fx.uat, body)
	if st != http.StatusCreated {
		t.Fatalf("direct reveal = %d body=%v; want 201", st, resp)
	}
	reqID, _ := resp["request_id"].(string)

	got := fx.jobProviderConfig(t, reqID)
	want := map[string]any{"kvMount": "kv", "kvPrefix": "team-alpha"}
	if len(got) != len(want) || got["kvMount"] != want["kvMount"] || got["kvPrefix"] != want["kvPrefix"] {
		t.Errorf("job target_provider_config = %v; want %v (derived from the binding, agent-accepted keys only)", got, want)
	}
	gotRaw, _ := json.Marshal(got)
	assertNoAttackerConfig(t, "job payload", string(gotRaw))
	assertNoAttackerConfig(t, "access_requests row", fx.storedProviderConfig(t, reqID))
}

// API-S-04 on the generic read flow: POST /requests/read must not store
// or forward the body config either, and (same allowlist class as
// api#154) an empty target_keys against a restrictive allowlist is
// refused instead of meaning "every key".
func TestRequestsRead_BodyProviderConfigNotStored(t *testing.T) {
	fx := bootstrapRevealBinding(t)

	read := func(keys []string) (int, map[string]any) {
		b := map[string]any{
			"requester_id":           fx.requester.String(),
			"project_id":             fx.project.String(),
			"environment":            "uat",
			"target_provider_type":   "vault",
			"target_provider_config": attackerProviderConfig,
			"target_secret_ref":      "team-alpha/uat/db",
			"justification":          "generic read regression",
		}
		if keys != nil {
			b["target_keys"] = keys
		}
		return fx.post(t, "/api/v1/requests/read", b)
	}

	st, resp := read([]string{"DB_PASSWORD"})
	if st != http.StatusCreated {
		t.Fatalf("POST /requests/read = %d body=%v; want 201", st, resp)
	}
	reqID, _ := resp["id"].(string)
	stored := fx.storedProviderConfig(t, reqID)
	assertNoAttackerConfig(t, "access_requests row", stored)
	if !strings.Contains(stored, `"kvPrefix": "team-alpha"`) {
		t.Errorf("stored provider config = %s; want the binding-derived config", stored)
	}

	if st, resp := read(nil); st != http.StatusForbidden {
		t.Errorf("POST /requests/read with no target_keys against a restrictive allowlist = %d body=%v; want 403", st, resp)
	}
}

// api#154: the per-env request endpoint applies the same tenancy gate as
// POST /requests/read — binding required (and scoped to this env), read
// op required, every key inside allowed_keys, empty keys refused when the
// allowlist is restrictive.
func TestEnvRequest_EnforcesBindingGate(t *testing.T) {
	fx := bootstrapRevealBinding(t)

	cases := []struct {
		name string
		env  uuid.UUID
		body map[string]any
	}{
		{"key outside allowed_keys", fx.uat, revealBody("team-alpha/uat/db", "NOT_ALLOWED")},
		{"no keys against restrictive allowlist", fx.uat, revealBody("team-alpha/uat/db")},
		{"unbound ref", fx.uat, revealBody("team-alpha/uat/unbound", "DB_PASSWORD")},
		{"prod-bound ref via uat URL", fx.uat, revealBody("team-alpha/prod/db", "DB_PASSWORD")},
		{"patch-only binding", fx.uat, revealBody("team-alpha/uat/patch", "DB_PASSWORD")},
	}
	for _, tc := range cases {
		if st, body := fx.envRequest(t, tc.env, tc.body); st != http.StatusForbidden {
			t.Errorf("%s: POST /request = %d body=%v; want 403", tc.name, st, body)
		}
	}
	if n := fx.countRequests(t); n != 0 {
		t.Fatalf("access_requests rows = %d; want 0 after refusals", n)
	}

	// Legit: an allowlisted key on the env-bound ref still lands pending,
	// with the binding-derived provider config and no body config.
	body := revealBody("team-alpha/uat/db", "DB_PASSWORD")
	body["target_provider_config"] = attackerProviderConfig
	st, resp := fx.envRequest(t, fx.uat, body)
	if st != http.StatusCreated {
		t.Fatalf("legit POST /request = %d body=%v; want 201", st, resp)
	}
	if resp["status"] != string(storage.AccessRequestStatusPending) {
		t.Errorf("legit request status = %v; want pending", resp["status"])
	}
	reqID, _ := resp["request_id"].(string)
	assertNoAttackerConfig(t, "access_requests row", fx.storedProviderConfig(t, reqID))
}

// The QA-certified path must keep working: a non-prod direct reveal of an
// env-bound ref auto-approves, enqueues the read job, and the requester
// can open a reveal session once the agent posts the wrap. A legacy
// binding with a NULL environment_id keeps its pre-fix behaviour.
func TestDirectReveal_LegitNonProdFlowStillWorks(t *testing.T) {
	fx := bootstrapRevealBinding(t)
	ctx := t.Context()

	st, resp := fx.directReveal(t, fx.uat, revealBody("team-alpha/uat/db", "DB_PASSWORD"))
	if st != http.StatusCreated {
		t.Fatalf("direct reveal = %d body=%v; want 201", st, resp)
	}
	if resp["status"] != string(storage.AccessRequestStatusApproved) || resp["direct_reveal"] != true {
		t.Fatalf("direct reveal response = %v; want approved + direct_reveal", resp)
	}
	reqID, _ := resp["request_id"].(string)

	var jobType string
	var jobOnRequest bool
	if err := fx.pool.QueryRow(ctx,
		`SELECT j.job_type, r.job_id = j.id FROM sync_jobs j JOIN access_requests r ON r.id = j.request_id WHERE j.request_id = $1`,
		reqID).Scan(&jobType, &jobOnRequest); err != nil {
		t.Fatalf("load read job: %v", err)
	}
	if jobType != string(storage.JobTypeRead) || !jobOnRequest {
		t.Errorf("job type=%q linked=%v; want read job linked to the request", jobType, jobOnRequest)
	}
	if n := fx.countAudit(t, "secret.reveal.direct.refused_binding", "secret_not_bound"); n != 0 {
		t.Errorf("legit reveal emitted a refusal audit")
	}

	// Simulate the agent posting the wrap, then open the reveal session
	// through the real route (fresh MFA + rate limit + allowlist gate).
	rid := uuid.MustParse(reqID)
	if _, err := fx.wrapSvc.WrapByAgent(ctx, uuid.New(), services.WrapRequest{
		Plaintext: []byte(rbFakeValue), RequestID: &rid, KeyName: "DB_PASSWORD", TTL: 10 * time.Minute,
	}); err != nil {
		t.Fatalf("WrapByAgent: %v", err)
	}
	st, sess := fx.post(t, "/api/v1/reveal-sessions", map[string]any{"access_request_id": reqID})
	if st != http.StatusCreated {
		t.Fatalf("open reveal session = %d body=%v; want 201", st, sess)
	}
	wraps, _ := sess["wraps"].([]any)
	if len(wraps) != 1 {
		t.Errorf("reveal session wraps = %v; want 1 handle", sess["wraps"])
	}

	// Legacy NULL-env binding: unchanged (URL env decides, non_prod here).
	if st, resp := fx.directReveal(t, fx.uat, revealBody("team-alpha/uat/legacy", "ANY_KEY")); st != http.StatusCreated {
		t.Errorf("direct reveal on legacy NULL-env binding = %d body=%v; want 201", st, resp)
	}
}

// Hard rule 8: prod direct reveal stays refused and audited, even for a
// ref that IS bound to the prod environment.
func TestDirectReveal_ProdStillRefusedAndAudited(t *testing.T) {
	fx := bootstrapRevealBinding(t)

	st, body := fx.directReveal(t, fx.prod, revealBody("team-alpha/prod/db", "DB_PASSWORD"))
	if st != http.StatusForbidden {
		t.Fatalf("prod direct reveal = %d body=%v; want 403", st, body)
	}
	var n int
	if err := fx.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit_events WHERE action = 'secret.reveal.direct.refused_prod' AND correlation_id = $1`,
		fx.prod).Scan(&n); err != nil {
		t.Fatalf("count refused_prod: %v", err)
	}
	if n != 1 {
		t.Errorf("refused_prod audit rows = %d; want 1", n)
	}
	if n := fx.countRequests(t); n != 0 {
		t.Errorf("access_requests rows = %d; want 0", n)
	}
}
