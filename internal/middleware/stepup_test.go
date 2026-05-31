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

// fakeStepUp is a tiny StepUpVerifier the test injects so the
// middleware exercises the freshness check without booting a real
// SessionService.
type fakeStepUp struct {
	maxAge int
	fresh  bool
}

func (f *fakeStepUp) HasFreshMFA(_ *storage.Session) bool { return f.fresh }
func (f *fakeStepUp) StepUpMaxAge() int                   { return f.maxAge }

func TestRequireFreshMFA_StaleReturns401WithChallenge(t *testing.T) {
	verifier := &fakeStepUp{maxAge: 900, fresh: false}
	app := fiber.New()
	app.Get("/tier2",
		// Inject a session pointer so the middleware sees one and
		// runs the freshness check (vs the "no session" branch).
		func(c fiber.Ctx) error {
			ctx := context.WithValue(c.Context(), CtxKeySession,
				&storage.Session{ID: uuid.New(), UserID: uuid.New()})
			c.SetContext(ctx)
			return c.Next()
		},
		RequireFreshMFA(verifier),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/tier2", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Fatal("expected WWW-Authenticate on 401")
	}
	if !contains(wwwAuth, "step-up") || !contains(wwwAuth, "max_age=900") || !contains(wwwAuth, "acr_values=mfa") {
		t.Fatalf("WWW-Authenticate=%q, missing step-up/max_age/acr_values", wwwAuth)
	}
}

func TestRequireFreshMFA_FreshAllows(t *testing.T) {
	verifier := &fakeStepUp{maxAge: 900, fresh: true}
	app := fiber.New()
	app.Get("/tier2",
		func(c fiber.Ctx) error {
			ctx := context.WithValue(c.Context(), CtxKeySession,
				&storage.Session{ID: uuid.New(), UserID: uuid.New()})
			c.SetContext(ctx)
			return c.Next()
		},
		RequireFreshMFA(verifier),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/tier2", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200 (fresh MFA should pass)", resp.StatusCode)
	}
}

func TestRequireFreshMFA_NoSession_StillChallenges(t *testing.T) {
	verifier := &fakeStepUp{maxAge: 900, fresh: true}
	app := fiber.New()
	app.Get("/tier2",
		RequireFreshMFA(verifier),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/tier2", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("status %d, want 401 (no session = no auth = step-up needed)", resp.StatusCode)
	}
}

func TestRequireFreshMFA_NilVerifierPassesThrough(t *testing.T) {
	app := fiber.New()
	app.Get("/tier2",
		RequireFreshMFA(nil),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/tier2", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200 (nil verifier should pass through)", resp.StatusCode)
	}
}

func TestSessionFromContext_NilWhenAbsent(t *testing.T) {
	if got := SessionFromContext(context.Background()); got != nil {
		t.Fatalf("SessionFromContext on empty ctx = %v, want nil", got)
	}
}

func TestSessionFromContext_RoundTrip(t *testing.T) {
	s := &storage.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CreatedAt: time.Now(),
	}
	ctx := context.WithValue(context.Background(), CtxKeySession, s)
	got := SessionFromContext(ctx)
	if got == nil || got.ID != s.ID {
		t.Fatalf("SessionFromContext round-trip mismatch: got %v want id=%v", got, s.ID)
	}
}

// contains is a tiny stdlib-only helper so we don't pull strings in
// just for this test file.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
