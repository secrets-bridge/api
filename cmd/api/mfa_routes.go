package main

import (
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/pkg/runtime"
)

// mfaRouteDeps carries what the MFA route family needs. Kept as one
// struct so main.go and the route tests wire the exact same chains.
type mfaRouteDeps struct {
	factors *handlers.MFA
	verify  *handlers.AuthMFA

	// stepUp + enrollment drive the factor-change gate.
	stepUp     middleware.StepUpVerifier
	enrollment middleware.MFAEnrollmentChecker

	rdb    *runtime.Client
	logger *slog.Logger
}

// Per-user budgets for the MFA ceremony routes (api#191 M4). A user at
// the step-up modal needs a handful of calls per minute; 10 leaves room
// for typos and retries while capping scripted guessing. The per-factor
// TOTP lockout (5 wrong codes, 15 min) in the service is the actual
// brute-force stop; these limits bound the call volume around it.
const (
	mfaRouteLimit  = 10
	mfaRouteWindow = 60 * time.Second
)

// registerMFARoutes mounts /users/me/mfa/* (self-service factor
// management) and /auth/mfa/* (step-up challenge + verify) on r.
func registerMFARoutes(r fiber.Router, d mfaRouteDeps) {
	// H3: once the user has a factor, changing factors needs fresh MFA.
	// First-factor enrollment stays open (bootstrap).
	factorChange := middleware.RequireFreshMFAForFactorChange(d.stepUp, d.enrollment)

	// M4: per-user limiter keyed on the authenticated identity. Fails
	// CLOSED (503) on a Redis error: these are per-user auth controls,
	// unlike the per-IP edge limiters that fail open (M5). Routes that
	// share a name share one bucket.
	perUser := func(name string) fiber.Handler {
		return middleware.RateLimit(d.rdb, d.logger, middleware.RateLimitConfig{
			Name:       name,
			Bucket:     middleware.ByIdentity(),
			Limit:      mfaRouteLimit,
			Window:     mfaRouteWindow,
			FailClosed: true,
		})
	}

	// Slice H2 (api#64): user-self MFA enrollment + management. No
	// RBAC gate: every authenticated user manages their OWN factors.
	// Handler derives the user id from the session, never from the
	// body, so cross-user paths are structurally impossible.
	//
	// The step-up gate runs BEFORE the limiter so a 401 step_up_required
	// (the user then verifies and retries) does not burn the budget.
	r.Get("/users/me/mfa/factors", d.factors.List)
	r.Delete("/users/me/mfa/factors/:id", factorChange, d.factors.Delete)
	r.Post("/users/me/mfa/totp/enroll", factorChange, perUser("mfa:enroll"), d.factors.EnrollTOTP)
	r.Post("/users/me/mfa/totp/confirm", factorChange, perUser("mfa:confirm"), d.factors.ConfirmTOTP)
	r.Post("/users/me/mfa/webauthn/register/start", factorChange, perUser("mfa:enroll"), d.factors.EnrollWebAuthnStart)
	r.Post("/users/me/mfa/webauthn/register/finish", factorChange, perUser("mfa:confirm"), d.factors.EnrollWebAuthnFinish)

	// Slice H4: step-up verification, the SOLE path post-H4 that
	// stamps `last_mfa_at` on a session. /auth/mfa/challenge mints
	// the per-kind nonce (TOTP ticket OR WebAuthn assertion options),
	// /auth/mfa/verify consumes the user's response and stamps on
	// success. Same cookie auth chain as /users/me/mfa/*.
	r.Post("/auth/mfa/challenge", perUser("mfa:challenge"), d.verify.Challenge)
	r.Post("/auth/mfa/verify", perUser("mfa:verify"), d.verify.Verify)
}
