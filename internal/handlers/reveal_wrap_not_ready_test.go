package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

// api#160 — POST /reveal-sessions on an approved request whose wraps have
// NOT been produced yet (agent still processing / unavailable) must return
// a clear 503 wrap_not_ready, NOT the misleading 410 "all wraps already
// consumed". The body carries metadata only (error/message/request_id) —
// no plaintext, values, wrap bodies, ciphertext, or provider payloads.
func TestRevealOpen_NoWrapsProduced_Returns503WrapNotReady(t *testing.T) {
	enableHeaderIdentityForTest(t)
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 4, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	const wipe = `
		DELETE FROM reveal_sessions;
		DELETE FROM secret_wraps;
		DELETE FROM approvals;
		DELETE FROM sync_jobs;
		DELETE FROM access_requests;
		DELETE FROM project_secrets;
		DELETE FROM secrets;
		DELETE FROM environments;
		DELETE FROM workflow_definitions WHERE is_system = false;
		DELETE FROM projects;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}

	// project + uat env
	projectID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1,'rs-notready')`, projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	envRepo := storage.NewEnvironments(pool)
	env := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd}
	if err := envRepo.Create(ctx, env); err != nil {
		t.Fatalf("seed env: %v", err)
	}

	wfRepo := storage.NewWorkflows(pool)
	wf := &storage.WorkflowDefinition{
		Name: "rs-notready-wf", MinApprovers: 0, AllowSelfApproval: true,
		WrapTTLCreated: time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: time.Hour, Enabled: true,
	}
	if err := wfRepo.Create(ctx, wf); err != nil {
		t.Fatalf("seed workflow: %v", err)
	}

	// An APPROVED read request owned by alice, env-bound, with NO wraps.
	alice := uuid.New()
	reqRepo := storage.NewAccessRequests(pool)
	req := &storage.AccessRequest{
		RequesterID:        alice.String(),
		Type:               storage.AccessRequestTypeRead,
		Justification:      "no wraps produced yet",
		Status:             storage.AccessRequestStatusApproved,
		WorkflowID:         &wf.ID,
		EnvironmentID:      &env.ID,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetScope:        map[string]any{"project_id": projectID.String()},
	}
	if err := reqRepo.Create(ctx, req); err != nil {
		t.Fatalf("seed request: %v", err)
	}

	// Wire the reveal service + handler (mirrors cmd/api/main.go).
	auditRepo := storage.NewAuditEvents(pool)
	km, err := keymgmt.NewLocalKMS(make([]byte, 32))
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	wrapSvc := services.NewWrapService(storage.NewSecretWraps(pool), auditRepo, km)
	policyEng := services.NewPolicyEngine(storage.NewPolicies(pool), wfRepo, auditRepo)
	revealSvc := services.NewRevealSessionService(
		storage.NewRevealSessions(pool), reqRepo, wrapSvc, policyEng, auditRepo,
	).WithEnvironments(envRepo)
	revealH := handlers.NewRevealSessions(revealSvc)

	app := fiber.New()
	app.Use(middleware.Auth(nil))
	app.Post("/api/v1/reveal-sessions", revealH.Open)

	body := strings.NewReader(`{"access_request_id":"` + req.ID.String() + `"}`)
	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/reveal-sessions", body)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-User-Id", alice.String())
	resp, err := app.Test(httpReq, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("POST reveal-sessions: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	bodyStr := string(raw)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d want 503 (body %s)", resp.StatusCode, bodyStr)
	}
	if resp.StatusCode == http.StatusGone {
		t.Errorf("no-wraps case wrongly returned 410 (the api#160 bug)")
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode body: %v (%s)", err, bodyStr)
	}
	if got["error"] != "wrap_not_ready" {
		t.Errorf("error = %v want wrap_not_ready", got["error"])
	}
	if got["request_id"] != req.ID.String() {
		t.Errorf("request_id = %v want %s", got["request_id"], req.ID.String())
	}
	if _, ok := got["message"].(string); !ok || got["message"] == "" {
		t.Errorf("message missing/empty: %v", got["message"])
	}
	// No-leak: the response carries ONLY these three metadata keys — a
	// fixed error code, a fixed human message, and the request UUID. No
	// value, wrap body, ciphertext, envelope, KMS material, or provider
	// payload field can appear (there are no wraps to leak, and the body
	// is a fixed shape). Any extra key is a potential leak surface.
	allowed := map[string]bool{"error": true, "message": true, "request_id": true}
	for k := range got {
		if !allowed[k] {
			t.Errorf("unexpected field %q in wrap_not_ready response (possible leak surface): %s", k, bodyStr)
		}
	}
}
