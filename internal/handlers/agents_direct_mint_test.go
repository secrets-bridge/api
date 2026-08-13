package handlers_test

// api#183 — the legacy POST /api/v1/agents direct mint is disabled by
// default (self-enrollment is the onboarding path) and only works when
// explicitly enabled as a break-glass admin action.

import (
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
	if !strings.Contains(body, "agent-enrollment-token") || !strings.Contains(body, "/agents/enroll") {
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

	st, body := postMint(t, app, `{"name":"break-glass"}`)
	if st != http.StatusCreated {
		t.Fatalf("break-glass mint = %d want 201; body %s", st, body)
	}
	if !strings.Contains(body, "agent_secret") {
		t.Errorf("break-glass mint should return agent_secret once: %s", body)
	}
}
