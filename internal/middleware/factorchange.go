// Step-up gate for MFA factor changes (api#191 H3).
//
// Enrolling a factor, confirming a pending enrollment and deleting a
// factor all change what counts as "the user's second factor". Before
// this gate they only needed a session, so a password-only session
// could enroll its own TOTP, verify with it and mint a fresh MFA
// stamp: the second factor proved nothing.
//
// The rule:
//
//	user has no factor yet  -> allowed (first-factor bootstrap)
//	user has a factor       -> the session must carry a FRESH MFA stamp
//	                           (same StepUpTTL as Tier-2 routes)
//
// Identities without a session (only the dev-only X-User-Id header
// since M1) can never carry a stamp, so once a factor exists they are
// refused. Lookup errors fail
// closed. Every factor row in Postgres is a confirmed one (pending
// enrollments live only in Redis), so "has a factor" is "has a
// confirmed factor".
//
// Confirm is gated too, not only enroll: an enrollment started while
// the user had no factor must not be confirmable after a factor exists
// without fresh MFA.

package middleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
)

// RequireFreshMFAForFactorChange gates the factor-change routes. See
// the file comment for the rule. Both dependencies are required; a nil
// one refuses every request with 503 rather than silently opening the
// gate.
func RequireFreshMFAForFactorChange(verifier StepUpVerifier, enrollment MFAEnrollmentChecker) fiber.Handler {
	return func(c fiber.Ctx) error {
		if verifier == nil || enrollment == nil {
			return fiber.NewError(fiber.StatusServiceUnavailable, "mfa step-up gate not configured")
		}
		a := actor(c)
		if a == "" || a == "anonymous" {
			// The default-deny group gate answers 401 for these.
			return c.Next()
		}
		uid, err := uuid.Parse(a)
		if err != nil {
			// Not a user id: no factor row can reference it (FK to
			// local_users.id). The handler refuses it with 422.
			return c.Next()
		}

		session := SessionFromContext(c.Context())
		if session != nil && session.UserID == uid && verifier.HasFreshMFA(session) {
			return c.Next()
		}

		enrolled, err := enrollment.AnyEnrolled(c.Context(), uid)
		if err == nil && !enrolled {
			// First factor: nothing to step up with yet.
			return c.Next()
		}
		// Enrolled (or unknown because the lookup failed): the caller
		// needs fresh MFA. An identity with no session has nothing to
		// stamp, so it stays refused.
		challenge(c, verifier)
		return fiber.NewError(fiber.StatusUnauthorized, "step_up_required")
	}
}
