package middleware

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// factorChangeApp mounts the gate with an identity (and optionally a
// session) injected the way AuthWith does.
func factorChangeApp(actorID string, session *storage.Session, v StepUpVerifier, e MFAEnrollmentChecker) *fiber.App {
	app := fiber.New()
	app.Post("/users/me/mfa/totp/enroll",
		func(c fiber.Ctx) error {
			ctx := context.WithValue(c.Context(), CtxKeyActor, actorID)
			if session != nil {
				ctx = context.WithValue(ctx, CtxKeySession, session)
			}
			c.SetContext(ctx)
			return c.Next()
		},
		RequireFreshMFAForFactorChange(v, e),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	return app
}

func TestRequireFreshMFAForFactorChange(t *testing.T) {
	uid := uuid.New()
	own := &storage.Session{ID: uuid.New(), UserID: uid}
	other := &storage.Session{ID: uuid.New(), UserID: uuid.New()}

	cases := []struct {
		name       string
		actor      string
		session    *storage.Session
		fresh      bool
		enrolled   bool
		lookupErr  error
		nilDeps    bool
		wantStatus int
	}{
		{name: "first factor, unstamped session", actor: uid.String(), session: own, wantStatus: 200},
		{name: "first factor, bearer (no session)", actor: uid.String(), wantStatus: 200},
		{name: "enrolled, fresh session", actor: uid.String(), session: own, fresh: true, enrolled: true, wantStatus: 200},
		{name: "enrolled, stale session", actor: uid.String(), session: own, enrolled: true, wantStatus: 401},
		{name: "enrolled, bearer (no session)", actor: uid.String(), enrolled: true, wantStatus: 401},
		{name: "enrolled, fresh session of another user", actor: uid.String(), session: other, fresh: true, enrolled: true, wantStatus: 401},
		{name: "lookup error fails closed", actor: uid.String(), session: own, lookupErr: errors.New("db down"), wantStatus: 401},
		{name: "lookup error, bearer", actor: uid.String(), lookupErr: errors.New("db down"), wantStatus: 401},
		{name: "anonymous left to the auth gate", actor: "anonymous", enrolled: true, wantStatus: 200},
		{name: "nil dependencies refuse", actor: uid.String(), session: own, nilDeps: true, wantStatus: 503},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v StepUpVerifier = &fakeStepUp{maxAge: 900, fresh: tc.fresh}
			var e MFAEnrollmentChecker = &fakeEnrollment{enrolled: tc.enrolled, err: tc.lookupErr}
			if tc.nilDeps {
				v, e = nil, nil
			}
			app := factorChangeApp(tc.actor, tc.session, v, e)
			resp, err := app.Test(httptest.NewRequest("POST", "/users/me/mfa/totp/enroll", nil))
			if err != nil {
				t.Fatalf("Test: %v", err)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantStatus == 401 && !contains(resp.Header.Get("WWW-Authenticate"), "step-up") {
				t.Fatal("401 must carry the step-up challenge header")
			}
		})
	}
}
