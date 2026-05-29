package auth_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
)

// stubResolver lets each test return a hand-crafted grant set without
// touching Postgres.
type stubResolver struct {
	byUser map[string][]auth.Grant
	err    error
}

func (s *stubResolver) Resolve(_ context.Context, userID string) ([]auth.Grant, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.byUser[userID], nil
}

// fakeAuth installs an identity into the context the way the upgraded
// middleware.Auth() does. Without it, the auth middleware can't see
// the actor.
func fakeAuth(userID string) fiber.Handler {
	return func(c fiber.Ctx) error {
		if userID != "" {
			c.SetContext(context.WithValue(c.Context(), middleware.CtxKeyActor, userID))
		}
		return c.Next()
	}
}

func okHandler(c fiber.Ctx) error { return c.SendStatus(204) }

func TestRequire_GrantsWhenUserHasGlobalPerm(t *testing.T) {
	resolver := &stubResolver{byUser: map[string][]auth.Grant{
		"alice": {{Permission: "role.edit"}}, // empty Scope = global
	}}
	app := fiber.New()
	app.Use(fakeAuth("alice"))
	app.Post("/roles", auth.Require(auth.PermRoleEdit, resolver), okHandler)

	resp, err := app.Test(httptest.NewRequest("POST", "/roles", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

func TestRequire_RejectsWhenUserMissingPerm(t *testing.T) {
	resolver := &stubResolver{byUser: map[string][]auth.Grant{
		"bob": {{Permission: "secret.request"}},
	}}
	app := fiber.New()
	app.Use(fakeAuth("bob"))
	app.Post("/roles", auth.Require(auth.PermRoleEdit, resolver), okHandler)

	resp, err := app.Test(httptest.NewRequest("POST", "/roles", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestRequire_RejectsScopedAssignmentForGlobalAction(t *testing.T) {
	// Alice has role.edit but ONLY for project=archive. The Require
	// middleware (no scope) demands a GLOBAL grant — scoped grants
	// don't count for unscoped admin actions.
	resolver := &stubResolver{byUser: map[string][]auth.Grant{
		"alice": {{Permission: "role.edit", Scope: map[string]string{"project_id": "archive"}}},
	}}
	app := fiber.New()
	app.Use(fakeAuth("alice"))
	app.Post("/roles", auth.Require(auth.PermRoleEdit, resolver), okHandler)

	resp, err := app.Test(httptest.NewRequest("POST", "/roles", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestRequire_RejectsAnonymous(t *testing.T) {
	resolver := &stubResolver{}
	app := fiber.New()
	app.Use(fakeAuth("")) // no identity
	app.Post("/roles", auth.Require(auth.PermRoleEdit, resolver), okHandler)

	resp, err := app.Test(httptest.NewRequest("POST", "/roles", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestRequire_SurfacesResolverError(t *testing.T) {
	resolver := &stubResolver{err: errors.New("db down")}
	app := fiber.New()
	app.Use(fakeAuth("alice"))
	app.Post("/roles", auth.Require(auth.PermRoleEdit, resolver), okHandler)

	resp, err := app.Test(httptest.NewRequest("POST", "/roles", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("want 500, got %d", resp.StatusCode)
	}
}

func TestRequireScoped_GrantsWhenScopedAssignmentCovers(t *testing.T) {
	resolver := &stubResolver{byUser: map[string][]auth.Grant{
		"alice": {{
			Permission: "secret.request",
			Scope:      map[string]string{"project_id": "archive", "environment": "uat"},
		}},
	}}
	scopeFn := func(c fiber.Ctx) (map[string]string, error) {
		return map[string]string{"project_id": "archive", "environment": "uat"}, nil
	}
	app := fiber.New()
	app.Use(fakeAuth("alice"))
	app.Post("/requests", auth.RequireScoped(auth.PermSecretRequest, scopeFn, resolver), okHandler)

	resp, err := app.Test(httptest.NewRequest("POST", "/requests", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

func TestRequireScoped_RejectsCrossProject(t *testing.T) {
	// Alice has secret.request for archive; request is for elite.
	resolver := &stubResolver{byUser: map[string][]auth.Grant{
		"alice": {{
			Permission: "secret.request",
			Scope:      map[string]string{"project_id": "archive"},
		}},
	}}
	scopeFn := func(c fiber.Ctx) (map[string]string, error) {
		return map[string]string{"project_id": "elite"}, nil
	}
	app := fiber.New()
	app.Use(fakeAuth("alice"))
	app.Post("/requests", auth.RequireScoped(auth.PermSecretRequest, scopeFn, resolver), okHandler)

	resp, err := app.Test(httptest.NewRequest("POST", "/requests", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestRequireScoped_GlobalAssignmentCoversAnyRequest(t *testing.T) {
	// Carol is global admin (empty scope). She can submit a request
	// for ANY (project, env) tuple.
	resolver := &stubResolver{byUser: map[string][]auth.Grant{
		"carol": {{Permission: "secret.request"}}, // empty Scope = global
	}}
	scopeFn := func(c fiber.Ctx) (map[string]string, error) {
		return map[string]string{"project_id": "any-project", "environment": "prod"}, nil
	}
	app := fiber.New()
	app.Use(fakeAuth("carol"))
	app.Post("/requests", auth.RequireScoped(auth.PermSecretRequest, scopeFn, resolver), okHandler)

	resp, err := app.Test(httptest.NewRequest("POST", "/requests", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
}

func TestRequireScoped_SecretRefPrefixMatch(t *testing.T) {
	// Alice can request anything under `billing/`. A request for
	// `billing/prod/db` matches; `payments/prod/db` doesn't.
	resolver := &stubResolver{byUser: map[string][]auth.Grant{
		"alice": {{
			Permission: "secret.request",
			Scope:      map[string]string{"secret_ref_prefix": "billing/"},
		}},
	}}
	cases := []struct {
		name, ref string
		want      int
	}{
		{"covered prefix", "billing/prod/db", 204},
		{"different prefix", "payments/prod/db", 403},
		{"exact prefix string", "billing/", 204},
		{"shorter than prefix", "billing", 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scopeFn := func(c fiber.Ctx) (map[string]string, error) {
				return map[string]string{"secret_ref_prefix": tc.ref}, nil
			}
			app := fiber.New()
			app.Use(fakeAuth("alice"))
			app.Post("/requests", auth.RequireScoped(auth.PermSecretRequest, scopeFn, resolver), okHandler)
			resp, err := app.Test(httptest.NewRequest("POST", "/requests", nil))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.want {
				t.Fatalf("ref %q: want %d, got %d", tc.ref, tc.want, resp.StatusCode)
			}
		})
	}
}

func TestRequireScoped_BadScopeFnReturns400(t *testing.T) {
	resolver := &stubResolver{}
	scopeFn := func(c fiber.Ctx) (map[string]string, error) {
		return nil, errors.New("malformed scope")
	}
	app := fiber.New()
	app.Use(fakeAuth("alice"))
	app.Post("/requests", auth.RequireScoped(auth.PermSecretRequest, scopeFn, resolver), okHandler)

	resp, err := app.Test(httptest.NewRequest("POST", "/requests", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestScopeFromQuery_OnlyAddsPresentKeys(t *testing.T) {
	resolver := &stubResolver{byUser: map[string][]auth.Grant{
		"alice": {{
			Permission: "secret.list",
			Scope:      map[string]string{"project_id": "archive"},
		}},
	}}
	scopeFn := auth.ScopeFromQuery("project_id", "environment")
	app := fiber.New()
	app.Use(fakeAuth("alice"))
	app.Get("/secrets", auth.RequireScoped(auth.PermSecretList, scopeFn, resolver), okHandler)

	// project_id matches → 204
	resp, _ := app.Test(httptest.NewRequest("GET", "/secrets?project_id=archive", nil))
	if resp.StatusCode != 204 {
		t.Fatalf("matching project_id: want 204, got %d", resp.StatusCode)
	}
	// Other project → 403
	resp, _ = app.Test(httptest.NewRequest("GET", "/secrets?project_id=elite", nil))
	if resp.StatusCode != 403 {
		t.Fatalf("non-matching project_id: want 403, got %d", resp.StatusCode)
	}
}

func TestIdentityFromContext(t *testing.T) {
	cases := []struct {
		name   string
		actor  any
		wantID string
		wantOk bool
	}{
		{"missing", nil, "", false},
		{"empty string", "", "", false},
		{"anonymous treated as unauthenticated", "anonymous", "", false},
		{"real user_id", "alice", "alice", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.actor != nil {
				ctx = context.WithValue(ctx, middleware.CtxKeyActor, tc.actor)
			}
			got, ok := auth.IdentityFromContext(ctx)
			if got != tc.wantID || ok != tc.wantOk {
				t.Fatalf("want (%q, %v), got (%q, %v)", tc.wantID, tc.wantOk, got, ok)
			}
		})
	}
}

func TestRequire_PanicsOnNilResolver(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("want panic, got none")
		} else if !strings.Contains(r.(string), "nil Resolver") {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	auth.Require(auth.PermRoleEdit, nil)
}
