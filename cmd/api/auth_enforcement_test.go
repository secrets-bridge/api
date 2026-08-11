package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/middleware"
)

// Wires the REAL group middleware chain (AuthWith → RequireAuthedExcept
// with the REAL publicV1Paths) in front of stand-in handlers, then
// asserts the unauthenticated-access matrix. No DB: AuthWith(nil,nil)
// with no cookie/bearer resolves to anonymous, and the stand-ins only
// run if the gate lets them through — so a 200 here means the endpoint
// was reachable unauthenticated, which is the P0 we are closing.
func newEnforcementTestApp() *fiber.App {
	app := fiber.New()
	v1 := app.Group("/api/v1",
		middleware.AuthWith(nil, nil),
		middleware.RequireAuthedExcept(publicV1Paths),
	)
	leak := func(c fiber.Ctx) error { return c.SendString("reachable") }
	for _, p := range []string{
		"/policies", "/workflows", "/roles", "/agents", "/permissions",
		"/projects", "/environments", "/teams", "/user-roles",
	} {
		v1.Get(p, leak)
	}
	// A representative public route must stay reachable.
	v1.Post("/auth/login", leak)
	return app
}

func statusOf(t *testing.T, app *fiber.App, method, path string, hdr map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestUnauthenticated_ProtectedEndpointsReturn401(t *testing.T) {
	app := newEnforcementTestApp()
	for _, p := range []string{
		"/api/v1/policies", "/api/v1/workflows", "/api/v1/roles",
		"/api/v1/agents", "/api/v1/permissions", "/api/v1/projects",
		"/api/v1/environments", "/api/v1/teams", "/api/v1/user-roles",
	} {
		if got := statusOf(t, app, http.MethodGet, p, nil); got != http.StatusUnauthorized {
			t.Errorf("GET %s unauthenticated = %d; want 401 (endpoint is world-readable)", p, got)
		}
	}
}

func TestUnauthenticated_PublicLoginStaysReachable(t *testing.T) {
	app := newEnforcementTestApp()
	// Not 401: the gate must let the login route through. (200 from the
	// stand-in; the real handler does its own thing.)
	if got := statusOf(t, app, http.MethodPost, "/api/v1/auth/login", nil); got == http.StatusUnauthorized {
		t.Fatalf("POST /api/v1/auth/login = 401; a public route must stay reachable unauthenticated")
	}
}

// Authenticated smoke: a legitimate identity still reaches protected
// routes after the middleware change. Uses the header path with the
// opt-in enabled — the mechanism under test is the gate, not how
// identity arrives.
func TestAuthenticated_ProtectedEndpointReachable(t *testing.T) {
	prev := middleware.AllowInsecureHeaderIdentity
	middleware.AllowInsecureHeaderIdentity = true
	t.Cleanup(func() { middleware.AllowInsecureHeaderIdentity = prev })

	app := newEnforcementTestApp()
	got := statusOf(t, app, http.MethodGet, "/api/v1/policies",
		map[string]string{"X-User-Id": "00000000-0000-4000-8000-000000000001"})
	if got != http.StatusOK {
		t.Fatalf("authenticated GET /api/v1/policies = %d; want 200", got)
	}
}

// The header path must NOT be a bypass by default: an anonymous caller
// setting X-User-Id, with the opt-in OFF, is still refused.
func TestUnauthenticated_HeaderIdentityIsNotABypass(t *testing.T) {
	// Explicitly ensure the opt-in is off for this test.
	prev := middleware.AllowInsecureHeaderIdentity
	middleware.AllowInsecureHeaderIdentity = false
	t.Cleanup(func() { middleware.AllowInsecureHeaderIdentity = prev })

	app := newEnforcementTestApp()
	got := statusOf(t, app, http.MethodGet, "/api/v1/policies",
		map[string]string{"X-User-Id": "00000000-0000-4000-8000-000000000001"})
	if got != http.StatusUnauthorized {
		t.Fatalf("X-User-Id with opt-in OFF = %d; want 401 (header must not grant identity)", got)
	}
}
