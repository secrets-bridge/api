// Step-up auth gate (architect Q6, Slice D + H4). Tier 2 operations —
// approve/reject/reveal/rotate/role-edit/provider-edit — require
// MFA-fresh sessions: the user must have completed an /auth/mfa/verify
// challenge within the past `step-up TTL` (default 15 min). Stale
// sessions get a 401 with a structured `WWW-Authenticate: step-up`
// challenge so the SPA can open its step-up modal.
//
// Slice H5 adds a third outcome: 412 mfa_enrollment_required when the
// session is stale AND the user has NO enrolled factor at all. Without
// this distinction the SPA's step-up modal would be unreachable for
// brand-new users — they have nothing to verify with. The 412 routes
// them to /me/mfa instead.
//
// Routes mount the middleware AFTER `AuthWith` — the session pointer
// has to be in context. For sessions where last_mfa_at is NULL the
// gate fails closed (no MFA stamp == not fresh).

package middleware

import (
	"context"
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// StepUpVerifier is the slice of `services.SessionService` this
// middleware needs. Interface so tests can stub without booting a
// Postgres pool.
type StepUpVerifier interface {
	HasFreshMFA(session *storage.Session) bool
	StepUpMaxAge() int
}

// MFAEnrollmentChecker reports whether a user has any factor
// enrolled. Implemented by `services.MFAVerifyService.AnyEnrolled`.
// Optional — when nil, the middleware skips the 412 path and falls
// back to the 401 step-up challenge for every stale session.
type MFAEnrollmentChecker interface {
	AnyEnrolled(ctx context.Context, userID uuid.UUID) (bool, error)
}

// RequireFreshMFA returns a Fiber middleware that gates Tier-2 routes
// on a fresh `last_mfa_at`. Three outcomes:
//
//   * fresh    → c.Next()
//   * stale + user has at least one enrolled factor → 401 step_up_required
//                                                     with WWW-Authenticate
//   * stale + user has NO enrolled factor →           412 mfa_enrollment_required
//                                                     (Slice H5)
//
// When `verifier` is nil the middleware degrades to a pass-through —
// useful so test harnesses without a SessionService still exercise
// the route. When `enrollment` is nil the 412 path is skipped (every
// stale session returns 401), preserving Slice D behaviour for any
// boot path that hasn't wired the verify service yet.
func RequireFreshMFA(verifier StepUpVerifier, enrollment MFAEnrollmentChecker) fiber.Handler {
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
		// Session is stale. Distinguish "no factor to verify with"
		// from "stale but has a factor": the first one is a 412 so
		// the SPA can route to /me/mfa, the second is the usual 401.
		if enrollment != nil {
			enrolled, err := enrollment.AnyEnrolled(c.Context(), session.UserID)
			if err == nil && !enrolled {
				// The challenge header would be misleading here; the
				// SPA shouldn't try to start a step-up flow for a
				// user with nothing to verify with.
				return fiber.NewError(fiber.StatusPreconditionFailed, "mfa_enrollment_required")
			}
			// AnyEnrolled errored or returned true → fall through to
			// the legacy 401 path. Treating an error as "stale +
			// enrolled" fails open in the WRONG direction (the user
			// could be enrolled but stuck on /me/mfa); failing closed
			// to step-up is the safer default.
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
