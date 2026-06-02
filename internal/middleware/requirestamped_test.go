package middleware

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// fakeMFAStampVerifier returns a static StepUpMaxAge — the gate
// doesn't read freshness, only "has the session ever been stamped",
// so this is the minimal slice we need.
type fakeMFAStampVerifier struct{ maxAge int }

func (f *fakeMFAStampVerifier) StepUpMaxAge() int { return f.maxAge }

func TestRequireMFAStamped_StampedSessionPasses(t *testing.T) {
	now := time.Now()
	verifier := &fakeMFAStampVerifier{maxAge: 900}
	enroll := &fakeEnrollment{enrolled: true}
	app := fiber.New()
	app.Get("/api/v1/agents",
		injectSession(&storage.Session{
			ID: uuid.New(), UserID: uuid.New(), LastMFAAt: &now,
		}),
		RequireMFAStamped(verifier, enroll),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/agents", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200 (stamped session should pass)", resp.StatusCode)
	}
}

func TestRequireMFAStamped_UnstampedNoFactor_Returns412(t *testing.T) {
	verifier := &fakeMFAStampVerifier{maxAge: 900}
	enroll := &fakeEnrollment{enrolled: false}
	app := fiber.New()
	app.Get("/api/v1/agents",
		injectSession(&storage.Session{
			ID: uuid.New(), UserID: uuid.New(), LastMFAAt: nil,
		}),
		RequireMFAStamped(verifier, enroll),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/agents", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 412 {
		t.Fatalf("status %d, want 412 (unstamped + no factor → enrollment required)", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate=%q on 412, want empty (same posture as RequireFreshMFA)", got)
	}
}

func TestRequireMFAStamped_UnstampedWithFactor_Returns401(t *testing.T) {
	verifier := &fakeMFAStampVerifier{maxAge: 900}
	enroll := &fakeEnrollment{enrolled: true}
	app := fiber.New()
	app.Get("/api/v1/agents",
		injectSession(&storage.Session{
			ID: uuid.New(), UserID: uuid.New(), LastMFAAt: nil,
		}),
		RequireMFAStamped(verifier, enroll),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/agents", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("status %d, want 401 (unstamped + factor → step-up needed)", resp.StatusCode)
	}
	if !contains(resp.Header.Get("WWW-Authenticate"), "step-up") {
		t.Fatalf("expected step-up challenge on 401")
	}
}

func TestRequireMFAStamped_CarveOutsPassThrough(t *testing.T) {
	verifier := &fakeMFAStampVerifier{maxAge: 900}
	enroll := &fakeEnrollment{enrolled: false}
	for _, path := range []string{
		"/api/v1/users/me",
		"/api/v1/users/me/projects",
		"/api/v1/users/me/mfa/factors",
		"/api/v1/users/me/mfa/totp/enroll",
		"/api/v1/users/me/mfa/webauthn/register/start",
		"/api/v1/auth/logout",
		"/api/v1/auth/mfa/challenge",
		"/api/v1/auth/mfa/verify",
	} {
		t.Run(path, func(t *testing.T) {
			app := fiber.New()
			app.All(path,
				injectSession(&storage.Session{
					ID: uuid.New(), UserID: uuid.New(), LastMFAAt: nil,
				}),
				RequireMFAStamped(verifier, enroll),
				func(c fiber.Ctx) error { return c.SendStatus(200) },
			)
			req := httptest.NewRequest("GET", path, nil)
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("Test: %v", err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("status %d, want 200 (%s should be a carve-out)", resp.StatusCode, path)
			}
		})
	}
}

func TestRequireMFAStamped_NoSession_PassesThrough(t *testing.T) {
	// When no session pointer is in context, the gate lets the request
	// fall to the downstream auth chain (which produces its own 401).
	// The gate's contract is "given a session, do you have a stamp" —
	// NOT "is there a session at all".
	verifier := &fakeMFAStampVerifier{maxAge: 900}
	enroll := &fakeEnrollment{enrolled: false}
	app := fiber.New()
	app.Get("/api/v1/agents",
		RequireMFAStamped(verifier, enroll),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/agents", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200 (no session → fall through, not 401)", resp.StatusCode)
	}
}

func TestRequireMFAStamped_NilVerifier_PassesThrough(t *testing.T) {
	app := fiber.New()
	app.Get("/api/v1/agents",
		RequireMFAStamped(nil, nil),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/agents", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200 (nil deps → pass-through)", resp.StatusCode)
	}
}

func TestRequireMFAStamped_EnrollmentLookupErrors_FailsClosedToStepUp(t *testing.T) {
	// Symmetric with RequireFreshMFA's Slice H5 fail-direction.
	// AnyEnrolled error → 401 step-up (recoverable via the modal),
	// NOT 412 (would lock an enrolled user out of their own SPA).
	verifier := &fakeMFAStampVerifier{maxAge: 900}
	enroll := &fakeEnrollment{enrolled: false, err: context.DeadlineExceeded}
	app := fiber.New()
	app.Get("/api/v1/agents",
		injectSession(&storage.Session{
			ID: uuid.New(), UserID: uuid.New(), LastMFAAt: nil,
		}),
		RequireMFAStamped(verifier, enroll),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/agents", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("status %d, want 401 (enrollment lookup error → fall through to step-up)", resp.StatusCode)
	}
}

func TestIsLoginMFACarveOut(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/api/v1/users/me", true},
		{"/api/v1/users/me/projects", true},
		{"/api/v1/users/me/mfa/factors", true},
		{"/api/v1/users/me/mfa/totp/enroll", true},
		{"/api/v1/users/me/mfa/webauthn/register/finish", true},
		{"/api/v1/auth/logout", true},
		{"/api/v1/auth/mfa/challenge", true},
		{"/api/v1/auth/mfa/verify", true},

		// Adjacent paths that LOOK like carve-outs but aren't.
		{"/api/v1/users/me/projects/extra", false}, // narrower exact match fails
		{"/api/v1/auth/login", false},
		{"/api/v1/auth/oidc/callback", false},
		{"/api/v1/agents", false},
		{"/api/v1/requests", false},
		{"/api/v1/secrets", false},
		{"/api/v1/audit-events", false},
		{"/api/v1/users/meow/mfa/factors", false}, // partial-username trap
	}
	for _, c := range cases {
		got := isLoginMFACarveOut(c.path)
		if got != c.want {
			t.Errorf("isLoginMFACarveOut(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// --- helpers --------------------------------------------------------

// injectSession stashes a session pointer in the request context so
// the gate has something to read without booting the real
// AuthWith middleware.
func injectSession(s *storage.Session) fiber.Handler {
	return func(c fiber.Ctx) error {
		ctx := context.WithValue(c.Context(), CtxKeySession, s)
		c.SetContext(ctx)
		return c.Next()
	}
}
