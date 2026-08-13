package main

// Agent Onboarding MVP (api#178) — security-routing test.
//
// The /api/v1/agents/ prefix is session-exempt (RequireAuthedExcept with the
// AgentAuth prefix, api#151/#159). This test wires the REAL group chain and
// proves the two new routes land on the correct side of that line:
//
//   - POST /provider-connections/:id/agent-enrollment-token  (admin) is NOT
//     under the exempt prefix → an unauthenticated request is 401.
//   - POST /agents/enroll  IS under the exempt prefix by design (the enrolling
//     agent has no session; the token is validated in the handler) → the
//     session gate lets it through (the stand-in is reachable).
//
// DB-free: AuthWith(nil,nil) resolves to anonymous, so a 200 means the gate
// let the request reach the handler.

import (
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/middleware"
)

func newAgentEnrollRoutingApp() *fiber.App {
	app := fiber.New()
	// EXACTLY mirrors cmd/api/main.go's group chain, including the
	// "/api/v1/agents/" prefix exemption.
	v1 := app.Group("/api/v1",
		middleware.AuthWith(nil, nil),
		middleware.RequireAuthedExcept(publicV1Paths, "/api/v1/agents/"),
	)
	reachable := func(c fiber.Ctx) error { return c.SendString("reachable") }
	v1.Post("/provider-connections/:id/agent-enrollment-token", reachable)
	v1.Post("/agents/enroll", reachable)
	return app
}

func TestAgentEnroll_Routing_SessionGating(t *testing.T) {
	app := newAgentEnrollRoutingApp()

	// The admin token-mint route MUST NOT be silently session-exempt.
	const tokenPath = "/api/v1/provider-connections/11111111-1111-1111-1111-111111111111/agent-enrollment-token"
	if got := statusOf(t, app, http.MethodPost, tokenPath, nil); got != http.StatusUnauthorized {
		t.Errorf("unauthenticated enrollment-token route = %d; want 401 (must NOT be session-exempt)", got)
	}

	// The enroll route IS session-exempt by design — token-only auth is
	// enforced in the handler, not by the session gate.
	if got := statusOf(t, app, http.MethodPost, "/api/v1/agents/enroll", nil); got != http.StatusOK {
		t.Errorf("unauthenticated enroll route = %d; want 200 reachable (session-exempt; token checked in handler)", got)
	}
}
