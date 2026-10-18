package handlers_test

// API-16 regression tests for handler paths that write a response body
// themselves (stableErr, the readiness probe, query parsing) and so do
// not go through the app's generic 5xx handler.
//
// The storage failures are REAL pgx errors: the repositories sit on a
// pool pointed at a closed local port, so the error text carries the
// DSN's user, database and host exactly as a production connect
// failure would. No database is needed to run these.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

const (
	hygCanaryUser = "hyg_canary_user"
	hygCanaryDB   = "sb_hyg_leak_canary"
)

// hygBrokenPool returns a storage pool whose first use fails with a
// real pgx connect error naming hygCanaryUser / hygCanaryDB / 127.0.0.1.
func hygBrokenPool(t *testing.T) *storage.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(),
		"postgres://"+hygCanaryUser+":hyg-canary-pass@127.0.0.1:1/"+hygCanaryDB+"?sslmode=disable&connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(p.Close)
	return &storage.Pool{Pool: p}
}

var hygDSNLeaks = []string{hygCanaryUser, hygCanaryDB, "127.0.0.1", "dial", "failed to connect", "hyg-canary-pass"}

func hygAssertNoLeak(t *testing.T, where, body string, leaks ...string) {
	t.Helper()
	for _, l := range leaks {
		if strings.Contains(body, l) {
			t.Errorf("%s: body leaks %q: %s", where, l, body)
		}
	}
}

// hygGlobalResolver grants every caller a global policy.author.
type hygGlobalResolver struct{}

func (hygGlobalResolver) Resolve(context.Context, string) ([]auth.Grant, error) {
	return []auth.Grant{{Permission: string(auth.PermPolicyAuthor)}}, nil
}

// The policy-rule history 500 used to put the storage error into the
// {error_code, message} envelope verbatim. Both the project and the
// team anchored routes must now return a stable message.
func TestHygiene_PolicyHistory500IsStable(t *testing.T) {
	projectID, teamID, ruleID := uuid.New(), uuid.New(), uuid.New()
	brokenAudit := storage.NewAuditEvents(hygBrokenPool(t))
	historySvc := services.NewPolicyHistoryService(brokenAudit, &fakeWorkflowsForHandler{}, nil, nil)

	cases := []struct {
		name string
		path string
		app  func() *fiber.App
	}{
		{
			name: "project",
			path: "/api/v1/projects/" + projectID.String() + "/policy-rules/" + ruleID.String() + "/history",
			app: func() *fiber.App {
				policies := &stubPolicyRepo{rules: map[uuid.UUID]*storage.PolicyRule{
					ruleID: {ID: ruleID, Name: "r", ProjectID: &projectID},
				}}
				h := handlers.NewProjectPolicyRules(nil, policies, nil).WithHistory(historySvc, brokenAudit)
				app := fiber.New()
				app.Get("/api/v1/projects/:projectID/policy-rules/:ruleID/history", h.History)
				return app
			},
		},
		{
			name: "team",
			path: "/api/v1/teams/" + teamID.String() + "/policy-rules/" + ruleID.String() + "/history",
			app: func() *fiber.App {
				policies := &stubPolicyRepo{rules: map[uuid.UUID]*storage.PolicyRule{
					ruleID: {ID: ruleID, Name: "r", TeamID: &teamID},
				}}
				engine := services.NewPolicyEngine(nil, nil, nil).WithAuthorScope(hygGlobalResolver{}, nil)
				h := handlers.NewTeamPolicyRules(engine, policies, nil).WithHistory(historySvc, brokenAudit)
				app := fiber.New()
				// The coverage gate needs a caller to pass; hygGlobalResolver
				// gives it a global policy.author. Without one the gate
				// answers 403, which this test once missed because the
				// handler carried on past the gate (skills#86).
				app.Use(func(c fiber.Ctx) error {
					c.SetContext(context.WithValue(c.Context(), middleware.CtxKeyActor, "hyg-author"))
					return c.Next()
				})
				app.Get("/api/v1/teams/:teamID/policy-rules/:ruleID/history", h.History)
				return app
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := doGet(t, tc.app(), tc.path)
			if resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("status = %d; want 500 (%s)", resp.StatusCode, body)
			}
			hygAssertNoLeak(t, tc.name, string(body), hygDSNLeaks...)
			var env map[string]any
			if err := json.Unmarshal(body, &env); err != nil {
				t.Fatalf("body not JSON: %v (%s)", err, body)
			}
			if env["error_code"] != "history_internal_error" {
				t.Errorf("error_code = %v; want history_internal_error", env["error_code"])
			}
			if env["message"] != "policy rule history is temporarily unavailable" {
				t.Errorf("message = %v; want the stable message", env["message"])
			}
		})
	}
}

// /readyz is public. A failing Postgres or Redis ping must name the
// dependency but not echo the driver error (DSN user, database, host).
func TestHygiene_ReadyzDoesNotEchoDependencyError(t *testing.T) {
	broken := hygBrokenPool(t)
	p := handlers.NewProbes()
	p.AddReadinessCheck("postgres", func(ctx context.Context) error { return broken.Ping(ctx) })
	app := fiber.New()
	app.Get("/readyz", p.Readyz)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/readyz", nil), fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503 (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"postgres":"unavailable"`) {
		t.Errorf("readyz should name the failing check with a stable value: %s", body)
	}
	hygAssertNoLeak(t, "readyz", string(body), hygDSNLeaks...)
}

// Guard: query-parse errors on the audit log must not echo the raw
// input (a token pasted into the wrong filter box). The parsers already
// return fixed text; this pins it.
func TestHygiene_AuditQueryParseErrorsDoNotEchoInput(t *testing.T) {
	h := handlers.NewAudit(&stubAuditRepo{}, nil, nil)
	app := fiber.New()
	app.Get("/api/v1/audit-events", h.List)

	const canary = "hvs.CAESIhygAuditFilterCanary0123456789"
	for _, param := range []string{"since", "until", "correlation_id"} {
		resp, body := doGet(t, app, "/api/v1/audit-events?"+param+"="+canary)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d; want 400", param, resp.StatusCode)
		}
		hygAssertNoLeak(t, param, string(body), canary, "parsing time")
	}
}

// A healthy probe keeps its existing shape.
func TestHygiene_ReadyzHealthyUnchanged(t *testing.T) {
	p := handlers.NewProbes()
	p.AddReadinessCheck("redis", func(context.Context) error { return nil })
	app := fiber.New()
	app.Get("/readyz", p.Readyz)
	resp, body := doGet(t, app, "/readyz")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ready"`) {
		t.Fatalf("healthy readyz = %d %s", resp.StatusCode, body)
	}
}
