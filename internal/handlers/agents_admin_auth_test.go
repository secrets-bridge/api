package handlers_test

// Agent Onboarding MVP api-2 (api#179) — admin agent-management auth matrix.
//
// The admin list/get/revoke routes live OFF the /api/v1/agents/ session-exempt
// prefix (under /admin/agents) and each carries an explicit agent.list /
// agent.revoke permission. This test wires the REAL group chain
// (Auth → RequireAuthedExcept(..., "/api/v1/agents/") → auth.Require) and
// proves the required matrix:
//
//   unauthenticated              -> 401
//   user WITHOUT agent.list      -> 403
//   user WITH agent.list         -> 200
//   agent credential (no session)-> 401 (cannot reach the admin surface)

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

type adminAgentsFixture struct {
	app        *fiber.App
	adminUser  uuid.UUID // agent.list + agent.revoke
	noPermUser uuid.UUID // policy.author only
	agentID    uuid.UUID
}

func bootstrapAdminAgents(t *testing.T) *adminAgentsFixture {
	t.Helper()
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

	// NOTE: do NOT TRUNCATE roles with CASCADE — workflow_definitions has an
	// approver_role_id FK to roles, so TRUNCATE roles CASCADE would wipe the
	// seeded system workflow and break sibling suites. DELETE non-system
	// roles instead (preserves the seed; no cascade).
	const wipe = `
		TRUNCATE TABLE audit_events, agent_enrollment_tokens, sync_jobs, agents,
			provider_connections, user_roles, local_users
		RESTART IDENTITY CASCADE;
		DELETE FROM roles WHERE is_system = false;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}

	fx := &adminAgentsFixture{}
	var connID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO provider_connections (name, type, auth_method, scope, status)
		VALUES ('adm-conn','aws-sm','token','{}'::jsonb,'active') RETURNING id`).Scan(&connID); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (name, status, secret_hash, provider_connection_id, provider_type, cluster_name, capabilities)
		VALUES ('adm-agent','enrolled','\x00', $1, 'aws-sm', 'eks-x', '["discover"]'::jsonb)
		RETURNING id`, connID).Scan(&fx.agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	fx.adminUser = seedUserWithGrant(t, pool, "agent-admin", `["agent.list","agent.revoke"]`, "{}")
	fx.noPermUser = seedUserWithGrant(t, pool, "no-perm", `["policy.author"]`, "{}")

	resolver := auth.NewRepoResolver(storage.NewUserRoles(pool), storage.NewRoles(pool))
	agentsH := handlers.NewAgents(services.NewAgentService(storage.NewAgents(pool), storage.NewAuditEvents(pool), nil))

	app := fiber.New()
	v1 := app.Group("/api/v1",
		middleware.Auth(nil),
		middleware.RequireAuthedExcept(map[string]bool{}, "/api/v1/agents/"),
	)
	v1.Get("/admin/agents", auth.Require(auth.PermAgentList, resolver), agentsH.AdminListAgents)
	v1.Get("/admin/agents/:id", auth.Require(auth.PermAgentList, resolver), agentsH.AdminGetAgent)
	v1.Post("/admin/agents/:id/revoke", auth.Require(auth.PermAgentRevoke, resolver), agentsH.Revoke)
	// FU1: the legacy list is enforced with agent.list too (QA follow-up).
	// OFF the /api/v1/agents/ session-exempt prefix (exact path, no trailing
	// slash), so the session gate + explicit permission both apply.
	v1.Get("/agents", auth.Require(auth.PermAgentList, resolver), agentsH.List)
	fx.app = app
	return fx
}

func (fx *adminAgentsFixture) do(t *testing.T, method, path string, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestAdminAgents_AuthMatrix(t *testing.T) {
	fx := bootstrapAdminAgents(t)

	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"unauthenticated → 401", nil, http.StatusUnauthorized},
		{"agent credential (no session) → 401", map[string]string{"X-Agent-Secret": "whatever"}, http.StatusUnauthorized},
		{"user without agent.list → 403", map[string]string{"X-User-Id": fx.noPermUser.String()}, http.StatusForbidden},
		{"admin with agent.list → 200", map[string]string{"X-User-Id": fx.adminUser.String()}, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run("list: "+tc.name, func(t *testing.T) {
			if got := fx.do(t, http.MethodGet, "/api/v1/admin/agents", tc.headers); got != tc.want {
				t.Errorf("GET /admin/agents = %d; want %d", got, tc.want)
			}
		})
		t.Run("get: "+tc.name, func(t *testing.T) {
			if got := fx.do(t, http.MethodGet, "/api/v1/admin/agents/"+fx.agentID.String(), tc.headers); got != tc.want {
				t.Errorf("GET /admin/agents/:id = %d; want %d", got, tc.want)
			}
		})
	}

	// revoke: unauth → 401; no-perm → 403; admin → 204.
	if got := fx.do(t, http.MethodPost, "/api/v1/admin/agents/"+fx.agentID.String()+"/revoke", nil); got != http.StatusUnauthorized {
		t.Errorf("revoke unauth = %d; want 401", got)
	}
	if got := fx.do(t, http.MethodPost, "/api/v1/admin/agents/"+fx.agentID.String()+"/revoke",
		map[string]string{"X-User-Id": fx.noPermUser.String()}); got != http.StatusForbidden {
		t.Errorf("revoke no-perm = %d; want 403", got)
	}
	if got := fx.do(t, http.MethodPost, "/api/v1/admin/agents/"+fx.agentID.String()+"/revoke",
		map[string]string{"X-User-Id": fx.adminUser.String()}); got != http.StatusNoContent {
		t.Errorf("revoke admin = %d; want 204", got)
	}
}

// FU1 (QA follow-up): the legacy GET /api/v1/agents list now enforces
// agent.list. Same matrix as the admin surface, on the exact endpoint QA
// flagged. Prove-by-revert: removing auth.Require(PermAgentList) from the
// /agents route turns the no-perm case from 403 into 200.
func TestLegacyAgentsList_RequiresAgentList(t *testing.T) {
	fx := bootstrapAdminAgents(t)

	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"unauthenticated → 401", nil, http.StatusUnauthorized},
		{"agent credential (no session) → 401", map[string]string{"X-Agent-Secret": "whatever"}, http.StatusUnauthorized},
		{"user without agent.list → 403", map[string]string{"X-User-Id": fx.noPermUser.String()}, http.StatusForbidden},
		{"admin with agent.list → 200", map[string]string{"X-User-Id": fx.adminUser.String()}, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fx.do(t, http.MethodGet, "/api/v1/agents", tc.headers); got != tc.want {
				t.Errorf("GET /api/v1/agents = %d; want %d", got, tc.want)
			}
		})
	}
}
