package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
)

// stubResolver is an in-memory auth.Resolver: it maps a user id to a
// fixed set of global grants so the auth.Require gate can be exercised
// without a database. An empty grant list models a user who holds none
// of the required permissions.
type stubResolver struct {
	grants map[string][]auth.Grant
}

func (s stubResolver) Resolve(_ context.Context, userID string) ([]auth.Grant, error) {
	return s.grants[userID], nil
}

// newAuthzTestApp wires the REAL group middleware chain (AuthWith →
// RequireAuthedExcept with the REAL publicV1Paths) plus the per-route
// auth.Require gates added for API-01 (approve/reject) and API-03
// (POST /jobs), in front of stand-in handlers. A 200 means the gate let
// the request through to the stand-in.
func newAuthzTestApp(res auth.Resolver) *fiber.App {
	app := fiber.New()
	v1 := app.Group("/api/v1",
		middleware.AuthWith(nil, nil),
		middleware.RequireAuthedExcept(publicV1Paths),
	)
	leak := func(c fiber.Ctx) error { return c.SendString("reachable") }
	v1.Post("/requests/:id/approve", auth.Require(auth.PermSecretApprove, res), leak)
	v1.Post("/requests/:id/reject", auth.Require(auth.PermSecretApprove, res), leak)
	v1.Post("/jobs", auth.Require(auth.PermJobEnqueue, res), leak)
	return app
}

const (
	authzApprover = "00000000-0000-4000-8000-0000000000a1" // holds secret.approve
	authzEnqueuer = "00000000-0000-4000-8000-0000000000a2" // holds job.enqueue
	authzNoPerm   = "00000000-0000-4000-8000-0000000000a3" // holds neither
)

func authzResolver() auth.Resolver {
	return stubResolver{grants: map[string][]auth.Grant{
		authzApprover: {{Permission: string(auth.PermSecretApprove)}},
		authzEnqueuer: {{Permission: string(auth.PermJobEnqueue)}},
		authzNoPerm:   {{Permission: string(auth.PermPolicyAuthor)}},
	}}
}

func statusOfPost(t *testing.T, app *fiber.App, path string, hdr map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func enableHeaderIdentity(t *testing.T) {
	t.Helper()
	prev := middleware.AllowInsecureHeaderIdentity
	middleware.AllowInsecureHeaderIdentity = true
	t.Cleanup(func() { middleware.AllowInsecureHeaderIdentity = prev })
}

// API-01: approve + reject must be gated by secret.approve. An earlier
// version had only requireMFA on these routes, so any authenticated user
// with a fresh MFA stamp could approve any request. Prove-by-revert:
// dropping auth.Require(PermSecretApprove) turns the no-perm case from
// 403 into "reachable".
func TestApproveReject_RequireSecretApprove(t *testing.T) {
	enableHeaderIdentity(t)
	app := newAuthzTestApp(authzResolver())
	reqID := "11111111-1111-4111-8111-111111111111"

	for _, path := range []string{
		"/api/v1/requests/" + reqID + "/approve",
		"/api/v1/requests/" + reqID + "/reject",
	} {
		if got := statusOfPost(t, app, path, nil); got != http.StatusUnauthorized {
			t.Errorf("unauthenticated POST %s = %d; want 401", path, got)
		}
		if got := statusOfPost(t, app, path, map[string]string{"X-User-Id": authzNoPerm}); got != http.StatusForbidden {
			t.Errorf("no-perm POST %s = %d; want 403", path, got)
		}
		if got := statusOfPost(t, app, path, map[string]string{"X-User-Id": authzApprover}); got != http.StatusOK {
			t.Errorf("approver POST %s = %d; want 200 (reachable)", path, got)
		}
	}
}

// API-03: POST /jobs must be gated by job.enqueue. It was mounted with
// only the session gate, so any authenticated user could enqueue a
// free-form job. Prove-by-revert: dropping auth.Require(PermJobEnqueue)
// turns the no-perm case from 403 into "reachable".
func TestPostJobs_RequiresJobEnqueue(t *testing.T) {
	enableHeaderIdentity(t)
	app := newAuthzTestApp(authzResolver())
	const path = "/api/v1/jobs"

	if got := statusOfPost(t, app, path, nil); got != http.StatusUnauthorized {
		t.Errorf("unauthenticated POST /jobs = %d; want 401", got)
	}
	if got := statusOfPost(t, app, path, map[string]string{"X-User-Id": authzNoPerm}); got != http.StatusForbidden {
		t.Errorf("no-perm POST /jobs = %d; want 403", got)
	}
	// secret.approve does NOT grant job.enqueue — permissions are distinct.
	if got := statusOfPost(t, app, path, map[string]string{"X-User-Id": authzApprover}); got != http.StatusForbidden {
		t.Errorf("secret.approve holder POST /jobs = %d; want 403 (job.enqueue is distinct)", got)
	}
	if got := statusOfPost(t, app, path, map[string]string{"X-User-Id": authzEnqueuer}); got != http.StatusOK {
		t.Errorf("job.enqueue holder POST /jobs = %d; want 200 (reachable)", got)
	}
}
