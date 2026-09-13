package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
)

// h1Resolver is an in-memory auth.Resolver for the tenancy-write gate
// tests. Distinct name from any resolver stub in a sibling test file so
// the two security PRs coexist in this package without a symbol clash.
type h1Resolver struct{ grants map[string][]auth.Grant }

func (r h1Resolver) Resolve(_ context.Context, userID string) ([]auth.Grant, error) {
	return r.grants[userID], nil
}

const (
	h1TeamEditor = "00000000-0000-4000-8000-0000000000b1" // holds team.edit (global)
	h1NoPerm     = "00000000-0000-4000-8000-0000000000b2" // holds neither
)

func h1TestResolver() auth.Resolver {
	return h1Resolver{grants: map[string][]auth.Grant{
		h1TeamEditor: {{Permission: string(auth.PermTeamEdit)}},
		h1NoPerm:     {{Permission: string(auth.PermPolicyAuthor)}},
	}}
}

// newTenancyWriteAuthzApp wires the real group chain plus the API-04
// team.edit gates on the tenancy write routes, in front of stand-in
// handlers. A 200 means the gate let the request through.
func newTenancyWriteAuthzApp(res auth.Resolver) *fiber.App {
	app := fiber.New()
	v1 := app.Group("/api/v1",
		middleware.AuthWith(nil, nil),
		middleware.RequireAuthedExcept(publicV1Paths),
	)
	leak := func(c fiber.Ctx) error { return c.SendString("reachable") }
	v1.Post("/projects", auth.Require(auth.PermTeamEdit, res), leak)
	v1.Put("/projects/:id/status", auth.Require(auth.PermTeamEdit, res), leak)
	v1.Post("/environments", auth.Require(auth.PermTeamEdit, res), leak)
	v1.Put("/environments/:id", auth.Require(auth.PermTeamEdit, res), leak)
	v1.Delete("/environments/:id", auth.Require(auth.PermTeamEdit, res), leak)
	// A representative read stays open (no gate) so we don't over-claim.
	v1.Get("/projects", leak)
	return app
}

// API-04: project + environment mutation routes must require team.edit.
// Prove-by-revert: dropping auth.Require(PermTeamEdit) turns the no-perm
// cases from 403 into "reachable".
func TestTenancyWrites_RequireTeamEdit(t *testing.T) {
	prev := middleware.AllowInsecureHeaderIdentity
	middleware.AllowInsecureHeaderIdentity = true
	t.Cleanup(func() { middleware.AllowInsecureHeaderIdentity = prev })

	app := newTenancyWriteAuthzApp(h1TestResolver())
	const envID = "22222222-2222-4222-8222-222222222222"

	writes := []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/projects"},
		{http.MethodPut, "/api/v1/projects/" + envID + "/status"},
		{http.MethodPost, "/api/v1/environments"},
		{http.MethodPut, "/api/v1/environments/" + envID},
		{http.MethodDelete, "/api/v1/environments/" + envID},
	}
	for _, w := range writes {
		if got := statusOf(t, app, w.method, w.path, nil); got != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s %s = %d; want 401", w.method, w.path, got)
		}
		if got := statusOf(t, app, w.method, w.path, map[string]string{"X-User-Id": h1NoPerm}); got != http.StatusForbidden {
			t.Errorf("no-perm %s %s = %d; want 403", w.method, w.path, got)
		}
		if got := statusOf(t, app, w.method, w.path, map[string]string{"X-User-Id": h1TeamEditor}); got != http.StatusOK {
			t.Errorf("team-editor %s %s = %d; want 200 (reachable)", w.method, w.path, got)
		}
	}

	// A read route stays open to any authenticated caller.
	if got := statusOf(t, app, http.MethodGet, "/api/v1/projects", map[string]string{"X-User-Id": h1NoPerm}); got != http.StatusOK {
		t.Errorf("GET /projects for authenticated no-perm user = %d; want 200 (reads stay open)", got)
	}
}
