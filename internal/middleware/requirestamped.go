// Login-time MFA gate (Slice K).
//
// The base `RequireFreshMFA` middleware (Slice D + H4 + H5) gates
// individual Tier-2 routes — approve / reject / reveal-wrap. Tier-1
// browsing (lists, dashboards) only needs a valid session cookie.
//
// `RequireMFAStamped` lifts the gate up the stack: when the operator
// opts in via `SB_REQUIRE_MFA_AT_LOGIN=true`, EVERY authenticated
// route requires the session to have been MFA-verified at least once.
// The freshness window (15 min step-up TTL) still applies to Tier-2;
// this gate only cares about "has this session EVER been verified?"
//
// Carve-outs (paths the gate always allows through):
//
//   GET  /api/v1/users/me                   SPA hydration — needs to
//                                            render identity to show
//                                            the modal
//   GET  /api/v1/users/me/projects          identity-adjacent, no
//                                            value-bearing surface
//   GET  /api/v1/users/me/mfa/factors       SPA needs to know which
//                                            factor kinds are enrolled
//                                            to pick the verify path
//   POST /api/v1/users/me/mfa/totp/...      enrollment must be
//   POST /api/v1/users/me/mfa/webauthn/...  reachable BEFORE step-up
//                                            (chicken-and-egg)
//   DELETE /api/v1/users/me/mfa/factors/:id factor removal stays
//                                            available
//   POST /api/v1/auth/logout                always allow sign-out
//   POST /api/v1/auth/mfa/challenge         the gate's own ceremony
//   POST /api/v1/auth/mfa/verify            ditto
//
// All other authenticated routes return:
//
//   stale session + user has at least one factor  → 401 step_up_required
//   stale session + user has zero factors         → 412 mfa_enrollment_required
//
// The SPA's global onError interceptor (Slice I2) already routes both
// shapes correctly, so the consumer side needs zero changes.

package middleware

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// MFAStampVerifier is the slice of `services.SessionService` this
// middleware needs. Interface so tests can stub.
type MFAStampVerifier interface {
	StepUpMaxAge() int
}

// MFAStampedEnrollment is the lookup the gate consults when the
// session isn't stamped. Same interface as the `MFAEnrollmentChecker`
// used by `RequireFreshMFA`; we re-declare under a Slice-K name so the
// two gates can evolve independently if the contract diverges.
type MFAStampedEnrollment = MFAEnrollmentChecker

// loginMFACarveOuts is the set of paths that bypass the gate. The
// slice is small + lookup is exact-prefix; for the few paths we care
// about a linear scan beats a trie. Paths are matched WITHOUT a
// trailing slash; `/api/v1/users/me` matches exactly while
// `/api/v1/users/me/mfa/` matches every sub-path.
var loginMFACarveOuts = []string{
	"/api/v1/users/me",          // exact (also covers /users/me)
	"/api/v1/users/me/projects", // exact
	"/api/v1/users/me/mfa/",     // prefix — all MFA enrollment + factor list
	"/api/v1/auth/logout",
	"/api/v1/auth/mfa/",         // prefix — challenge + verify
}

// RequireMFAStamped returns a Fiber middleware that 401s with
// `step_up_required` (or 412s with `mfa_enrollment_required`) when
// the request's session lacks ANY MFA stamp. Designed to mount at
// the v1 group level alongside auth + RBAC + audit.
//
// When `verifier` is nil OR `enrollment` is nil the middleware
// degrades to pass-through — useful for boot paths that haven't
// reached the full service tree.
func RequireMFAStamped(verifier MFAStampVerifier, enrollment MFAStampedEnrollment) fiber.Handler {
	return func(c fiber.Ctx) error {
		if verifier == nil || enrollment == nil {
			return c.Next()
		}
		if isLoginMFACarveOut(c.Path()) {
			return c.Next()
		}
		session := SessionFromContext(c.Context())
		if session == nil {
			// No session — let the downstream auth chain return its
			// own 401. We don't want to mask a "no cookie" case with
			// our step-up shape.
			return c.Next()
		}
		if session.LastMFAAt != nil {
			// Session was verified at least once. Tier-2 routes still
			// have their own per-route RequireFreshMFA that enforces
			// the 15-min freshness window; this gate's contract is
			// "any stamp, ever."
			return c.Next()
		}

		// Unstamped session. Distinguish "no factors at all" (412 →
		// SPA routes to /me/mfa) from "has a factor but never
		// verified" (401 → SPA opens step-up modal). Failure of the
		// enrollment lookup falls through to the 401 path — same
		// fail-direction as RequireFreshMFA in Slice H5.
		enrolled, err := enrollment.AnyEnrolled(c.Context(), session.UserID)
		if err == nil && !enrolled {
			return fiber.NewError(fiber.StatusPreconditionFailed, "mfa_enrollment_required")
		}
		c.Set("WWW-Authenticate",
			fmt.Sprintf(`step-up max_age=%d acr_values=mfa`, verifier.StepUpMaxAge()))
		return fiber.NewError(fiber.StatusUnauthorized, "step_up_required")
	}
}

// isLoginMFACarveOut reports whether `path` matches one of the
// hard-coded carve-out paths. Exported as a free function (not a
// method) so handler tests can pin the list with the same
// assertions the middleware uses.
func isLoginMFACarveOut(path string) bool {
	for _, p := range loginMFACarveOuts {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(path, p) {
				return true
			}
		} else if path == p {
			return true
		}
	}
	return false
}

