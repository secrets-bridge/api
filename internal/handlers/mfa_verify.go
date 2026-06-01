// Handlers — /auth/mfa/{challenge,verify} (Slice H4).
//
// These two endpoints close the step-up loop for Slice D's
// RequireFreshMFA middleware:
//
//   1. Tier-2 op (approve/reject/reveal) returns 401 + WWW-Authenticate: step-up
//   2. SPA opens the step-up modal, POSTs /auth/mfa/challenge {kind}
//   3. Server returns {challenge_id, options?} — options for WebAuthn
//   4. User completes the ceremony (types TOTP code OR uses authenticator)
//   5. SPA POSTs /auth/mfa/verify {challenge_id, code | response}
//   6. Server stamps last_mfa_at on the current session, returns 204
//   7. SPA retries the original Tier-2 op
//
// Both endpoints require a cookie session — the user id + session id
// come from the auth context, never from the body. Cross-user
// verification is structurally impossible.
//
// Slice H5 attaches the `mfa_enrolled` projection to /users/me using
// the same `MFAVerifyService.AnyEnrolled` check this handler uses
// for the 412 path.

package handlers

import (
	"encoding/json"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// AuthMFA is the HTTP layer for /auth/mfa/*.
type AuthMFA struct {
	svc *services.MFAVerifyService
}

// NewAuthMFA wires the handler. `svc` may be nil — the endpoints
// return 503 when MFA verification isn't wired (tests + boot paths
// that haven't reached the service yet).
func NewAuthMFA(svc *services.MFAVerifyService) *AuthMFA {
	return &AuthMFA{svc: svc}
}

// AuthMFAChallengeRequest is the body for POST /auth/mfa/challenge.
type AuthMFAChallengeRequest struct {
	Kind string `json:"kind"`
}

// AuthMFAChallengeResponse mirrors services.ChallengeResult. `Options`
// is only present for kind=webauthn.
type AuthMFAChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Kind        string `json:"kind"`
	Options     any    `json:"options,omitempty"`
}

// Challenge handles POST /auth/mfa/challenge. Returns 412
// mfa_enrollment_required when the user has zero factors so the SPA
// can route to /me/mfa instead of staying stuck on the step-up modal.
func (h *AuthMFA) Challenge(c fiber.Ctx) error {
	if h.svc == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "mfa not wired")
	}
	uid, sid, err := authIdentity(c)
	if err != nil {
		return err
	}
	var body AuthMFAChallengeRequest
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid body")
	}
	out, err := h.svc.BeginChallenge(c.Context(), sid, uid, services.ChallengeKind(body.Kind))
	if err != nil {
		return mapVerifyError(err)
	}
	return c.JSON(AuthMFAChallengeResponse{
		ChallengeID: out.ChallengeID,
		Kind:        string(out.Kind),
		Options:     out.Options,
	})
}

// AuthMFAVerifyRequest is the body for POST /auth/mfa/verify.
type AuthMFAVerifyRequest struct {
	ChallengeID string          `json:"challenge_id"`
	FactorID    string          `json:"factor_id,omitempty"` // TOTP path
	Code        string          `json:"code,omitempty"`      // TOTP path
	Response    json.RawMessage `json:"response,omitempty"`  // WebAuthn path
}

// Verify handles POST /auth/mfa/verify. On success the user's current
// session is MFA-fresh — the Tier-2 op the SPA retries next will pass
// the RequireFreshMFA gate.
func (h *AuthMFA) Verify(c fiber.Ctx) error {
	if h.svc == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "mfa not wired")
	}
	uid, sid, err := authIdentity(c)
	if err != nil {
		return err
	}
	var body AuthMFAVerifyRequest
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid body")
	}
	if body.ChallengeID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "challenge_id required")
	}
	req := services.VerifyRequest{
		ChallengeID:      body.ChallengeID,
		Code:             body.Code,
		WebAuthnResponse: body.Response,
	}
	if body.FactorID != "" {
		fid, perr := uuid.Parse(body.FactorID)
		if perr != nil {
			return fiber.NewError(fiber.StatusBadRequest, "factor_id must be a uuid")
		}
		req.FactorID = &fid
	}
	if err := h.svc.Verify(c.Context(), sid, uid, req); err != nil {
		return mapVerifyError(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- helpers ---------------------------------------------------------

// authIdentity reads the caller's user id (UUID) + session id from the
// auth middleware's context plumbing. Either missing → 401.
func authIdentity(c fiber.Ctx) (uuid.UUID, uuid.UUID, error) {
	sub, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return uuid.Nil, uuid.Nil, fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	uid, err := uuid.Parse(sub)
	if err != nil {
		return uuid.Nil, uuid.Nil, fiber.NewError(fiber.StatusUnprocessableEntity, "identity is not a user id")
	}
	session := middleware.SessionFromContext(c.Context())
	if session == nil {
		// /auth/mfa/* requires the cookie path specifically. Bearer
		// JWTs (legacy) can't carry a step-up stamp; force a real
		// session.
		return uuid.Nil, uuid.Nil, fiber.NewError(fiber.StatusUnauthorized, "session cookie required")
	}
	return uid, session.ID, nil
}

func mapVerifyError(err error) error {
	switch {
	case errors.Is(err, services.ErrMFANoFactors):
		// Distinct status from "challenge expired" — SPA hint to
		// route to /me/mfa rather than restart at /challenge.
		return fiber.NewError(fiber.StatusPreconditionFailed, "mfa_enrollment_required")
	case errors.Is(err, services.ErrMFAKindNotEnrolled):
		return fiber.NewError(fiber.StatusPreconditionFailed, "mfa_kind_not_enrolled")
	case errors.Is(err, services.ErrMFAUnknownKind):
		return fiber.NewError(fiber.StatusBadRequest, "unknown kind")
	case errors.Is(err, services.ErrMFAChallengeNotFound),
		errors.Is(err, services.ErrMFAChallengeUser):
		// Same 410 for both — owner-enumeration impossible.
		return fiber.NewError(fiber.StatusGone, "challenge expired or already used")
	case errors.Is(err, services.ErrMFAInvalid):
		return fiber.NewError(fiber.StatusBadRequest, "verification failed")
	case errors.Is(err, services.ErrMFASessionRequired):
		return fiber.NewError(fiber.StatusUnauthorized, "session required")
	case errors.Is(err, services.ErrWebAuthnNotConfigured):
		return fiber.NewError(fiber.StatusServiceUnavailable, "webauthn not configured")
	case errors.Is(err, services.ErrWebAuthnNoFactors):
		return fiber.NewError(fiber.StatusPreconditionFailed, "mfa_kind_not_enrolled")
	case errors.Is(err, storage.ErrSignCountRegression):
		// Clone-detection trip happened mid-verify — the verify
		// service has already revoked sessions + audited. Surface
		// to the SPA as 401 so the user is bounced to /login.
		return fiber.NewError(fiber.StatusUnauthorized, "factor compromised")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}
