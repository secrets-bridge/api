package handlers_test

// api#183 — the legacy POST /api/v1/agents direct mint is disabled by
// default (self-enrollment is the onboarding path) and only works when
// explicitly enabled as a break-glass admin action.

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

func postMint(t *testing.T, app *fiber.App, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("POST /agents: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Default (no WithDirectMint / false): direct mint is refused with 403,
// pointing at the enrollment flow. DB-free — the gate returns before the
// service is touched.
func TestMint_DirectMintDisabledByDefault_403(t *testing.T) {
	h := handlers.NewAgents(services.NewAgentService(nil, nil, nil))
	app := fiber.New()
	app.Post("/api/v1/agents", h.Mint)

	st, body := postMint(t, app, `{"name":"nope"}`)
	if st != http.StatusForbidden {
		t.Fatalf("direct mint (default) = %d want 403; body %s", st, body)
	}
	if !strings.Contains(body, "direct_agent_mint_disabled") {
		t.Errorf("403 body missing direct_agent_mint_disabled: %s", body)
	}
	if !strings.Contains(body, "agent-enrollment-token") || !strings.Contains(body, "enroll command") {
		t.Errorf("403 body should point at the enrollment flow: %s", body)
	}
}

// Break-glass: with the flag on, the direct mint works exactly as before
// (returns agent_secret once). Requires a DB.
func TestMint_DirectMintBreakGlassEnabled_201(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE TABLE audit_events, agents RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	svc := services.NewAgentService(storage.NewAgents(pool), storage.NewAuditEvents(pool), nil)
	h := handlers.NewAgents(svc).WithDirectMint(true)
	app := fiber.New()
	app.Post("/api/v1/agents", h.Mint)

	// skills#116: a direct mint needs a valid key too.
	for name, b := range map[string]string{
		"no key":   `{"name":"no-key"}`,
		"all zero": `{"name":"zero","public_key":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `","public_key_algorithm":"x25519"}`,
		"short":    `{"name":"short","public_key":"` + base64.StdEncoding.EncodeToString(make([]byte, 16)) + `","public_key_algorithm":"x25519"}`,
		"no alg":   `{"name":"noalg","public_key":"` + base64.StdEncoding.EncodeToString(testAgentPub) + `"}`,
	} {
		if st, body := postMint(t, app, b); st != http.StatusBadRequest || !strings.Contains(body, "invalid_public_key") {
			t.Errorf("%s: mint = %d %s; want 400 invalid_public_key", name, st, body)
		}
	}
	st, body := postMint(t, app, `{"name":"break-glass","public_key":"`+base64.StdEncoding.EncodeToString(testAgentPub)+`","public_key_algorithm":"x25519"}`)
	if st != http.StatusCreated {
		t.Fatalf("break-glass mint = %d want 201; body %s", st, body)
	}
	if !strings.Contains(body, "agent_secret") || !strings.Contains(body, testAgentFingerprint) {
		t.Errorf("break-glass mint should return agent_secret once and the fingerprint: %s", body)
	}
}
