// Step-up auth gate (architect Q6, Slice D). Tier 2 operations —
// approve/reject/reveal/rotate/role-edit/provider-edit — require
// MFA-fresh sessions: the IdP must have prompted for a strong second
// factor within the past `step-up TTL` (default 15 min). Stale
// sessions get a 401 with a structured `WWW-Authenticate: step-up`
// challenge so the SPA can redirect to /auth/oidc/start with
// prompt=login + max_age=0 + acr_values=mfa.
//
// Routes mount the middleware AFTER `AuthWith` — the session pointer
// has to be in context. For sessions where last_mfa_at is NULL
// (local-admin sign-in, IdP without MFA) the gate fails closed.

package middleware

import (
	"context"
	"fmt"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/pkg/storage"
)

// StepUpVerifier is the slice of `services.SessionService` this
// middleware needs. Interface so tests can stub without booting a
// Postgres pool.
type StepUpVerifier interface {
	HasFreshMFA(session *storage.Session) bool
	StepUpMaxAge() int
}

// RequireFreshMFA returns a Fiber middleware that 401s with a
// `WWW-Authenticate: step-up` header when the request's session
// lacks a recent MFA stamp. Routes mount it as the LAST middleware
// before the handler so the auth + RBAC layers run first.
//
// When `verifier` is nil the middleware degrades to a pass-through
// — useful so test harnesses without a SessionService still exercise
// the route.
func RequireFreshMFA(verifier StepUpVerifier) fiber.Handler {
	return func(c fiber.Ctx) error {
		if verifier == nil {
			return c.Next()
		}
		session := SessionFromContext(c.Context())
		if session == nil {
			// No session = no cookie auth = treat as step-up needed.
			// AuthWith would have written one in if the cookie was
			// valid; absence is the same outcome as stale.
			challenge(c, verifier)
			return fiber.NewError(fiber.StatusUnauthorized, "step_up_required")
		}
		if verifier.HasFreshMFA(session) {
			return c.Next()
		}
		challenge(c, verifier)
		return fiber.NewError(fiber.StatusUnauthorized, "step_up_required")
	}
}

func challenge(c fiber.Ctx, verifier StepUpVerifier) {
	c.Set("WWW-Authenticate",
		fmt.Sprintf(`step-up max_age=%d acr_values=mfa`, verifier.StepUpMaxAge()))
}

// CtxKeySession carries the authenticated session pointer (not just
// the UUID string `CtxKeySessionID` holds) so downstream middleware
// — primarily `RequireFreshMFA` — can read its `last_mfa_at` without
// re-hitting the SessionRepository.
const CtxKeySession ctxKey = "authenticated_session"

// SessionFromContext returns the session pointer the cookie path
// stashed, or nil when the request didn't carry a cookie session.
func SessionFromContext(ctx context.Context) *storage.Session {
	v, _ := ctx.Value(CtxKeySession).(*storage.Session)
	return v
}
