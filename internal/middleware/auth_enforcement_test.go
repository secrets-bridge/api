package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

// The X-User-Id header is a legacy identity path. Honoured
// unconditionally it is a full authentication bypass: any caller can
// claim to be any user by setting the header, and downstream
// `auth.Require` resolves that user's grants. It must be OFF by
// default and only enabled by an explicit, non-production opt-in.

func TestAuthWith_HeaderIdentityIgnoredByDefault(t *testing.T) {
	// Default (flag unset) must NOT honour the header.
	app := fiber.New()
	app.Use(AuthWith(nil, nil))
	app.Get("/x", func(c fiber.Ctx) error { return c.SendString(actor(c)) })

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-User-Id", "00000000-0000-4000-8000-000000000001")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	got := readBody(t, resp)
	if got != "anonymous" {
		t.Fatalf("actor = %q; header identity must be ignored by default (got a claimed user = auth bypass)", got)
	}
}

func TestAuthWith_HeaderIdentityHonouredWhenExplicitlyEnabled(t *testing.T) {
	prev := AllowInsecureHeaderIdentity
	AllowInsecureHeaderIdentity = true
	t.Cleanup(func() { AllowInsecureHeaderIdentity = prev })

	app := fiber.New()
	app.Use(AuthWith(nil, nil))
	app.Get("/x", func(c fiber.Ctx) error { return c.SendString(actor(c)) })

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-User-Id", "alice")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, resp); got != "alice" {
		t.Fatalf("actor = %q; want alice when the opt-in is enabled", got)
	}
}

// RequireAuthedExcept is the default-deny gate: every request must be
// authenticated unless its path is explicitly public. A new route is
// therefore protected by construction — the failure mode is a
// spurious 401 on a forgotten allow-list entry, never a silent open
// endpoint.

func TestRequireAuthedExcept_AnonymousProtectedIs401(t *testing.T) {
	app := fiber.New()
	app.Use(AuthWith(nil, nil))
	app.Use(RequireAuthedExcept(map[string]bool{"/api/v1/auth/login": true}))
	app.Get("/api/v1/policies", func(c fiber.Ctx) error { return c.SendString("leaked") })

	resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/policies", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("status = %d; anonymous access to a protected route must be 401", resp.StatusCode)
	}
}

func TestRequireAuthedExcept_PublicPathPassesAnonymous(t *testing.T) {
	app := fiber.New()
	app.Use(AuthWith(nil, nil))
	app.Use(RequireAuthedExcept(map[string]bool{"/api/v1/auth/login": true}))
	app.Post("/api/v1/auth/login", func(c fiber.Ctx) error { return c.SendString("ok") })

	resp, err := app.Test(httptest.NewRequest("POST", "/api/v1/auth/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d; a public path must pass unauthenticated", resp.StatusCode)
	}
}

func TestRequireAuthedExcept_AuthenticatedProtectedPasses(t *testing.T) {
	prev := AllowInsecureHeaderIdentity
	AllowInsecureHeaderIdentity = true
	t.Cleanup(func() { AllowInsecureHeaderIdentity = prev })

	app := fiber.New()
	app.Use(AuthWith(nil, nil))
	app.Use(RequireAuthedExcept(map[string]bool{}))
	app.Get("/api/v1/policies", func(c fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest("GET", "/api/v1/policies", nil)
	req.Header.Set("X-User-Id", "alice") // authenticated identity present
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d; an authenticated request to a protected route must pass", resp.StatusCode)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
