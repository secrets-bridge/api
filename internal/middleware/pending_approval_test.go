package middleware

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

// api#266: a waiting account reaches only the allowed "METHOD /path"
// entries and the public paths; everyone else is unaffected.
func TestRequireApprovedExcept(t *testing.T) {
	public := map[string]bool{"/api/v1/auth/login": true}
	allowed := map[string]bool{"GET /api/v1/users/me": true, "POST /api/v1/auth/logout": true}

	newApp := func(pending bool) *fiber.App {
		app := fiber.New()
		app.Use(func(c fiber.Ctx) error {
			if pending {
				c.SetContext(context.WithValue(c.Context(), CtxKeyPendingApproval, true))
			}
			return c.Next()
		})
		app.Use(RequireApprovedExcept(public, allowed))
		app.All("/*", func(c fiber.Ctx) error { return c.SendStatus(204) })
		return app
	}

	cases := []struct {
		pending      bool
		method, path string
		want         int
	}{
		{true, "GET", "/api/v1/users/me", 204},
		{true, "POST", "/api/v1/auth/logout", 204},
		{true, "POST", "/api/v1/auth/login", 204},
		{true, "GET", "/api/v1/requests", 403},
		{true, "GET", "/api/v1/policies", 403},
		{true, "POST", "/api/v1/users/me", 403},
		{true, "GET", "/api/v1/users/me/projects", 403},
		{false, "GET", "/api/v1/requests", 204},
	}
	for _, tc := range cases {
		resp, err := newApp(tc.pending).Test(httptest.NewRequest(tc.method, tc.path, nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != tc.want {
			t.Errorf("pending=%v %s %s = %d; want %d", tc.pending, tc.method, tc.path, resp.StatusCode, tc.want)
		}
	}
}
