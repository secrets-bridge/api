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

	approverCookie string

	uatWorkflow  uuid.UUID
	prodWorkflow uuid.UUID
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
	authSvc := services.NewAuthService(
		storage.NewLocalUsers(pool), storage.NewRoles(pool), storage.NewUserRoles(pool),
		storage.NewAuditEvents(pool),
	)

	// newApp writes the package-level header-identity switch from cfg;
	// restore whatever the other tests in this package expect.
	prevHeader := middleware.AllowInsecureHeaderIdentity
	t.Cleanup(func() { middleware.AllowInsecureHeaderIdentity = prevHeader })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := newApp(Config{
		Env:                            ModeDev,
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
	fx.uatWorkflow = wf.ID

	// Policy: tenant-a/prod gets a stricter workflow of its own, so a
	// test can tell which environment's workflow a request was given.
	prodWF := &storage.WorkflowDefinition{
		Name: "rb-prod-wf", MinApprovers: 2, AllowSelfApproval: false,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := storage.NewWorkflows(pool).Create(ctx, prodWF); err != nil {
		t.Fatalf("prod workflow Create: %v", err)
	}
	if err := storage.NewPolicies(pool).Create(ctx, &storage.PolicyRule{
		Name:       "rb-prod",
		Selector:   map[string]any{"project_id": project.ID.String(), "environment": "prod"},
		WorkflowID: prodWF.ID,
		Priority:   500,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("prod policy Create: %v", err)
	}
	fx.prodWorkflow = prodWF.ID

	// Catalog rows + bindings.
	discovered := map[string]any{"address": "https://vault.example.com", "kvMount": "kv", "kvPrefix": "team-alpha"}
	secretsRepo := storage.NewSecrets(pool)
	bindings := storage.NewProjectSecrets(pool)
	seedOn := func(cluster, ref string, envID *uuid.UUID, keys []string, ops []string, bind bool) {
		t.Helper()
		sec := &storage.Secret{
			ClusterName: cluster, ProviderType: "vault", SecretRef: ref,
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
	seed := func(ref string, envID *uuid.UUID, keys []string, ops []string, bind bool) {
		t.Helper()
		seedOn("tenant-a-uat", ref, envID, keys, ops, bind)
	}
	seed("team-alpha/uat/db", &uat.ID, []string{"DB_PASSWORD"}, []string{storage.OpRead}, true)
	seed("team-alpha/uat/legacy", nil, nil, []string{storage.OpRead, storage.OpPatch}, true)
	seed("team-alpha/uat/patch", &uat.ID, nil, []string{storage.OpPatch}, true)
	seed("team-alpha/prod/db", &prod.ID, nil, []string{storage.OpRead, storage.OpPatch}, true)
	seed("team-alpha/uat/unbound", nil, nil, nil, false)
	// One ref discovered on two clusters: the prod-cluster row is bound to
	// the prod env with every key allowed, the uat-cluster row to the uat
	// env with only DB_PASSWORD. "tenant-a-prod" sorts first, so a gate
	// that takes the first binding regardless of env picks the prod one.
	seedOn("tenant-a-prod", "team-alpha/shared/db", &prod.ID, nil, []string{storage.OpRead}, true)
	seedOn("tenant-a-uat", "team-alpha/shared/db", &uat.ID, []string{"DB_PASSWORD"}, []string{storage.OpRead}, true)
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

	// Approver: a second local user with global secret.approve (and a
	// fresh-MFA session) for the plain approver-approved read flow.
	approver := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO local_users (id, email, password_hash, display_name) VALUES ($1, 'dr-approver@example.com', $2, 'dr approver')`,
		approver, []byte{0x00}); err != nil {
		t.Fatalf("seed approver: %v", err)
	}
	approverRole := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO roles (id, name, permissions, is_system) VALUES ($1, 'dr-approver-role', '["secret.approve"]'::jsonb, false)`,
		approverRole); err != nil {
		t.Fatalf("seed approver role: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (id, user_id, role_id, scope) VALUES ($1, $2, $3, '{}'::jsonb)`,
		uuid.New(), approver, approverRole); err != nil {
		t.Fatalf("seed approver user_role: %v", err)
	}
	approverSess, err := sessSvc.Issue(ctx, approver, "127.0.0.1", "reveal-binding-test")
	if err != nil {
		t.Fatalf("approver session Issue: %v", err)
	}
	if err := sessSvc.MarkMFA(ctx, approverSess.Session.ID, time.Now()); err != nil {
		t.Fatalf("approver MarkMFA: %v", err)
	}
	fx.approverCookie = approverSess.CookieValue
	return fx
}

// post sends an authenticated JSON POST through the real app as the
// requester and returns the status + decoded body (nil when the body
// isn't a JSON object).
func (fx *revealBindingFx) post(t *testing.T, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return fx.do(t, http.MethodPost, path, body, fx.cookie)
}

// do sends an authenticated request through the real app with the given
// session cookie. A nil body sends no body.
func (fx *revealBindingFx) do(t *testing.T, method, path string, body map[string]any, cookie string) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: cookie})
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
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

// wrapForAgent simulates the agent posting one wrap (fake value) for a
// request, the way POST /agents/:id/wraps would after a read job.
func (fx *revealBindingFx) wrapForAgent(t *testing.T, requestID, key string) string {
	t.Helper()
	rid := uuid.MustParse(requestID)
	w, err := fx.wrapSvc.WrapByAgent(t.Context(), uuid.New(), services.WrapRequest{
		Plaintext: []byte(rbFakeValue), RequestID: &rid, KeyName: key, TTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("WrapByAgent %s: %v", key, err)
	}
	return w.ID.String()
}

func (fx *revealBindingFx) openRevealSession(t *testing.T, requestID string) (int, map[string]any) {
	t.Helper()
	return fx.post(t, "/api/v1/reveal-sessions", map[string]any{"access_request_id": requestID})
}

func (fx *revealBindingFx) countWraps(t *testing.T) int {
	t.Helper()
	var n int
	if err := fx.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM secret_wraps w JOIN access_requests r ON r.id = w.request_id WHERE r.requester_id = $1`,
		fx.requester.String()).Scan(&n); err != nil {
		t.Fatalf("count wraps: %v", err)
	}
	return n
}

// API-S-03 on the generic request paths: the POST /requests tenancy gate
// used to take the first binding regardless of environment, so a secret
// bound only to prod could be requested (read or patch) under the
// non-prod environment name and get that environment's laxer workflow.
// An env-scoped binding now only governs in its own environment; a
// NULL-environment binding keeps the old behaviour; and a request the
// binding does allow gets the workflow of that environment.
func TestRequests_ProdBoundRefUnderNonProdEnvRefused(t *testing.T) {
	fx := bootstrapRevealBinding(t)
	ctx := t.Context()

	read := func(env, ref string) (int, map[string]any) {
		b := map[string]any{
			"requester_id":         fx.requester.String(),
			"project_id":           fx.project.String(),
			"target_provider_type": "vault",
			"target_secret_ref":    ref,
			"target_keys":          []string{"DB_PASSWORD"},
			"justification":        "env-scoped tenancy regression",
		}
		if env != "" {
			b["environment"] = env
		}
		return fx.post(t, "/api/v1/requests/read", b)
	}

	if st, body := read("uat", "team-alpha/prod/db"); st != http.StatusForbidden {
		t.Errorf("read of prod-bound ref under env=uat = %d body=%v; want 403", st, body)
	}
	if st, body := read("", "team-alpha/prod/db"); st != http.StatusForbidden {
		t.Errorf("read of prod-bound ref with no environment = %d body=%v; want 403", st, body)
	}
	if st, body := read("does-not-exist", "team-alpha/prod/db"); st != http.StatusForbidden {
		t.Errorf("read of prod-bound ref under unknown env = %d body=%v; want 403", st, body)
	}
	st, body := fx.post(t, "/api/v1/requests", map[string]any{
		"requester_id":         fx.requester.String(),
		"project_id":           fx.project.String(),
		"environment":          "uat",
		"target_provider_type": "vault",
		"target_secret_ref":    "team-alpha/prod/db",
		"key_values":           map[string]string{"DB_PASSWORD": rbFakeValue},
		"justification":        "env-scoped tenancy regression (patch)",
	})
	if st != http.StatusForbidden {
		t.Errorf("patch of prod-bound ref under env=uat = %d body=%v; want 403", st, body)
	}
	if n := fx.countRequests(t); n != 0 {
		t.Fatalf("access_requests rows = %d; want 0 after refusals", n)
	}
	if n := fx.countWraps(t); n != 0 {
		t.Fatalf("secret_wraps rows = %d; want 0 after refusals", n)
	}

	// The binding's own environment is allowed, and the request gets that
	// environment's workflow (the stricter prod one), not uat's.
	st, resp := read("prod", "team-alpha/prod/db")
	if st != http.StatusCreated {
		t.Fatalf("read of prod-bound ref under env=prod = %d body=%v; want 201", st, resp)
	}
	reqID, _ := resp["id"].(string)
	var envID, wfID uuid.UUID
	if err := fx.pool.QueryRow(ctx,
		`SELECT environment_id, workflow_id FROM access_requests WHERE id = $1`, reqID).Scan(&envID, &wfID); err != nil {
		t.Fatalf("load request: %v", err)
	}
	if envID != fx.prod || wfID != fx.prodWorkflow {
		t.Errorf("request env=%s workflow=%s; want prod env %s with prod workflow %s", envID, wfID, fx.prod, fx.prodWorkflow)
	}

	// Legacy NULL-environment binding: unchanged, with or without an env.
	for _, env := range []string{"uat", ""} {
		if st, resp := read(env, "team-alpha/uat/legacy"); st != http.StatusCreated {
			t.Errorf("read of legacy NULL-env binding under env=%q = %d body=%v; want 201", env, st, resp)
		}
	}
}

// The reveal-session allowlist (second boundary) used to take the first
// binding for the ref regardless of environment. With the same ref bound
// to prod (every key) on one cluster and to uat (DB_PASSWORD only) on
// another, a uat request bundling a non-allowlisted wrap was checked
// against the prod binding and opened. It must use the binding of the
// request's environment.
func TestRevealSession_AllowlistUsesEnvMatchingBinding(t *testing.T) {
	fx := bootstrapRevealBinding(t)

	st, resp := fx.directReveal(t, fx.uat, revealBody("team-alpha/shared/db", "DB_PASSWORD"))
	if st != http.StatusCreated {
		t.Fatalf("direct reveal of shared ref under uat = %d body=%v; want 201", st, resp)
	}
	reqID, _ := resp["request_id"].(string)
	fx.wrapForAgent(t, reqID, "DB_PASSWORD")
	fx.wrapForAgent(t, reqID, "API_TOKEN") // outside the uat binding's allowlist

	if st, body := fx.openRevealSession(t, reqID); st != http.StatusForbidden {
		t.Fatalf("open reveal session with a non-allowlisted wrap = %d body=%v; want 403 (uat binding governs)", st, body)
	}
	if n := fx.countAudit(t, "reveal.session.refused_binding", "key_not_allowed"); n != 1 {
		t.Errorf("reveal.session.refused_binding/key_not_allowed audit rows = %d; want 1", n)
	}

	// Control: the same ref with only the allowlisted wrap opens fine.
	st, resp = fx.directReveal(t, fx.uat, revealBody("team-alpha/shared/db", "DB_PASSWORD"))
	if st != http.StatusCreated {
		t.Fatalf("second direct reveal = %d body=%v; want 201", st, resp)
	}
	okID, _ := resp["request_id"].(string)
	fx.wrapForAgent(t, okID, "DB_PASSWORD")
	if st, body := fx.openRevealSession(t, okID); st != http.StatusCreated {
		t.Errorf("open reveal session with only allowlisted wraps = %d body=%v; want 201", st, body)
	}
}

// Fail closed at the unwrap boundary: when no binding governs the
// request's environment any more (re-scoped to another environment, or
// removed after submit), the reveal session is refused and audited.
func TestRevealSession_FailsClosedWhenNoBindingGoverns(t *testing.T) {
	fx := bootstrapRevealBinding(t)
	ctx := t.Context()

	st, resp := fx.directReveal(t, fx.uat, revealBody("team-alpha/uat/db", "DB_PASSWORD"))
	if st != http.StatusCreated {
		t.Fatalf("direct reveal = %d body=%v; want 201", st, resp)
	}
	reqID, _ := resp["request_id"].(string)
	fx.wrapForAgent(t, reqID, "DB_PASSWORD")

	// Re-scope the binding to prod after submit.
	if _, err := fx.pool.Exec(ctx,
		`UPDATE project_secrets SET environment_id = $1
		  WHERE project_id = $2 AND secret_id = (SELECT id FROM secrets WHERE secret_ref = 'team-alpha/uat/db')`,
		fx.prod, fx.project); err != nil {
		t.Fatalf("re-scope binding: %v", err)
	}
	if st, body := fx.openRevealSession(t, reqID); st != http.StatusForbidden {
		t.Errorf("open after binding re-scoped to prod = %d body=%v; want 403", st, body)
	}
	if n := fx.countAudit(t, "reveal.session.refused_binding", "binding_env_mismatch"); n != 1 {
		t.Errorf("refused_binding/binding_env_mismatch audit rows = %d; want 1", n)
	}

	// Remove the binding entirely.
	if _, err := fx.pool.Exec(ctx,
		`DELETE FROM project_secrets
		  WHERE project_id = $1 AND secret_id = (SELECT id FROM secrets WHERE secret_ref = 'team-alpha/uat/db')`,
		fx.project); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	if st, body := fx.openRevealSession(t, reqID); st != http.StatusForbidden {
		t.Errorf("open after binding removed = %d body=%v; want 403", st, body)
	}
	if n := fx.countAudit(t, "reveal.session.refused_binding", "secret_not_bound"); n != 1 {
		t.Errorf("refused_binding/secret_not_bound audit rows = %d; want 1", n)
	}

	var sessions int
	if err := fx.pool.QueryRow(ctx, `SELECT count(*) FROM reveal_sessions WHERE access_request_id = $1`, reqID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("reveal_sessions rows = %d; want 0", sessions)
	}
}

// retrieveWrap fetches one wrap as the requester through the real route
// (requireMFA + rate limit + handler). Only the status and key name are
// returned so a test can never print the (fake) value.
func (fx *revealBindingFx) retrieveWrap(t *testing.T, requestID, wrapID string) (int, string) {
	t.Helper()
	st, body := fx.do(t, http.MethodGet, "/api/v1/requests/"+requestID+"/wraps/"+wrapID, nil, fx.cookie)
	key, _ := body["key_name"].(string)
	return st, key
}

func (fx *revealBindingFx) wrapConsumed(t *testing.T, wrapID string) bool {
	t.Helper()
	var consumed bool
	if err := fx.pool.QueryRow(t.Context(),
		`SELECT consumed_at IS NOT NULL FROM secret_wraps WHERE id = $1`, wrapID).Scan(&consumed); err != nil {
		t.Fatalf("load wrap: %v", err)
	}
	return consumed
}

// API-S-20: a direct-reveal wrap is only handed out by
// GET /requests/:id/wraps/:wrap_id inside an open reveal session of the
// caller. Without one the fetch is refused, audited, and does NOT burn
// the single-shot wrap; with one it works as before.
func TestWrapRetrieve_DirectRevealNeedsOpenSession(t *testing.T) {
	fx := bootstrapRevealBinding(t)

	st, resp := fx.directReveal(t, fx.uat, revealBody("team-alpha/uat/db", "DB_PASSWORD"))
	if st != http.StatusCreated {
		t.Fatalf("direct reveal = %d body=%v; want 201", st, resp)
	}
	reqID, _ := resp["request_id"].(string)
	wrapID := fx.wrapForAgent(t, reqID, "DB_PASSWORD")

	if st, _ := fx.retrieveWrap(t, reqID, wrapID); st != http.StatusForbidden {
		t.Fatalf("retrieve direct-reveal wrap with no reveal session = %d; want 403", st)
	}
	if fx.wrapConsumed(t, wrapID) {
		t.Fatalf("refused retrieve consumed the wrap")
	}
	if n := fx.countAudit(t, "wrap.retrieve.refused_session", "no_open_session"); n != 1 {
		t.Errorf("wrap.retrieve.refused_session/no_open_session audit rows = %d; want 1", n)
	}

	// Legit: open the session, then the same wrap is handed out.
	if st, body := fx.openRevealSession(t, reqID); st != http.StatusCreated {
		t.Fatalf("open reveal session = %d body=%v; want 201", st, body)
	}
	st, key := fx.retrieveWrap(t, reqID, wrapID)
	if st != http.StatusOK || key != "DB_PASSWORD" {
		t.Fatalf("retrieve inside an open session = %d key=%q; want 200 DB_PASSWORD", st, key)
	}
}

// API-S-20: the session TTL holds on the single-wrap path even before
// the worker sweeper runs. The session's expires_at has passed (expired_at
// still NULL, sweeper not run) while the wrap's own expires_at is still in
// the future: the fetch must be refused.
func TestWrapRetrieve_ExpiredSessionRefusedEvenIfWrapStillValid(t *testing.T) {
	fx := bootstrapRevealBinding(t)
	ctx := t.Context()

	st, resp := fx.directReveal(t, fx.uat, revealBody("team-alpha/uat/db", "DB_PASSWORD"))
	if st != http.StatusCreated {
		t.Fatalf("direct reveal = %d body=%v; want 201", st, resp)
	}
	reqID, _ := resp["request_id"].(string)
	wrapID := fx.wrapForAgent(t, reqID, "DB_PASSWORD")
	st, sess := fx.openRevealSession(t, reqID)
	if st != http.StatusCreated {
		t.Fatalf("open reveal session = %d body=%v; want 201", st, sess)
	}
	sessionID, _ := sess["session_id"].(string)

	if _, err := fx.pool.Exec(ctx,
		`UPDATE reveal_sessions SET expires_at = now() - interval '1 second' WHERE id = $1`, sessionID); err != nil {
		t.Fatalf("age session: %v", err)
	}
	var wrapLive bool
	if err := fx.pool.QueryRow(ctx,
		`SELECT expires_at > now() FROM secret_wraps WHERE id = $1`, wrapID).Scan(&wrapLive); err != nil {
		t.Fatalf("load wrap expiry: %v", err)
	}
	if !wrapLive {
		t.Fatalf("precondition: wrap expires_at should still be in the future")
	}

	if st, _ := fx.retrieveWrap(t, reqID, wrapID); st != http.StatusForbidden {
		t.Fatalf("retrieve after the session TTL passed = %d; want 403", st)
	}
	if fx.wrapConsumed(t, wrapID) {
		t.Errorf("refused retrieve consumed the wrap")
	}
}

// API-S-20 + API-S-03: the single-wrap path applies the same env-matching
// allowlist Open does. The shared ref is bound to prod (every key) on one
// cluster and to uat (DB_PASSWORD only) on another; after the session is
// opened the uat allowlist is tightened, so the uat request's wrap is now
// outside the binding that governs it and must be refused, even though
// the prod binding (first in catalog order) would still allow it.
func TestWrapRetrieve_SessionAllowlistUsesEnvMatchingBinding(t *testing.T) {
	fx := bootstrapRevealBinding(t)
	ctx := t.Context()

	st, resp := fx.directReveal(t, fx.uat, revealBody("team-alpha/shared/db", "DB_PASSWORD"))
	if st != http.StatusCreated {
		t.Fatalf("direct reveal = %d body=%v; want 201", st, resp)
	}
	reqID, _ := resp["request_id"].(string)
	wrapID := fx.wrapForAgent(t, reqID, "DB_PASSWORD")
	if st, body := fx.openRevealSession(t, reqID); st != http.StatusCreated {
		t.Fatalf("open reveal session = %d body=%v; want 201", st, body)
	}

	if _, err := fx.pool.Exec(ctx,
		`UPDATE project_secrets SET allowed_keys = ARRAY['OTHER_KEY']
		  WHERE project_id = $1 AND environment_id = $2
		    AND secret_id IN (SELECT id FROM secrets WHERE secret_ref = 'team-alpha/shared/db')`,
		fx.project, fx.uat); err != nil {
		t.Fatalf("tighten uat allowlist: %v", err)
	}

	if st, _ := fx.retrieveWrap(t, reqID, wrapID); st != http.StatusForbidden {
		t.Fatalf("retrieve of a wrap outside the uat allowlist = %d; want 403", st)
	}
	if fx.wrapConsumed(t, wrapID) {
		t.Errorf("refused retrieve consumed the wrap")
	}
	if n := fx.countAudit(t, "wrap.retrieve.refused_session", "key_not_allowed"); n != 1 {
		t.Errorf("wrap.retrieve.refused_session/key_not_allowed audit rows = %d; want 1", n)
	}
}

// Control: the plain read flow (request → approver approves → agent
// wraps → requester fetches the wrap, no reveal session) is unchanged.
func TestWrapRetrieve_PlainReadFlowUnchanged(t *testing.T) {
	fx := bootstrapRevealBinding(t)

	st, resp := fx.post(t, "/api/v1/requests/read", map[string]any{
		"requester_id":         fx.requester.String(),
		"project_id":           fx.project.String(),
		"environment":          "uat",
		"target_provider_type": "vault",
		"target_secret_ref":    "team-alpha/uat/db",
		"target_keys":          []string{"DB_PASSWORD"},
		"justification":        "plain read flow control",
	})
	if st != http.StatusCreated {
		t.Fatalf("POST /requests/read = %d body=%v; want 201", st, resp)
	}
	reqID, _ := resp["id"].(string)

	st, resp = fx.do(t, http.MethodPost, "/api/v1/requests/"+reqID+"/approve", map[string]any{"comment": "ok"}, fx.approverCookie)
	if st != http.StatusOK || resp["status"] != string(storage.AccessRequestStatusApproved) {
		t.Fatalf("approve = %d body=%v; want 200 approved", st, resp)
	}

	wrapID := fx.wrapForAgent(t, reqID, "DB_PASSWORD")
	st, key := fx.retrieveWrap(t, reqID, wrapID)
	if st != http.StatusOK || key != "DB_PASSWORD" {
		t.Fatalf("plain read retrieve without a session = %d key=%q; want 200 DB_PASSWORD", st, key)
	}
}
