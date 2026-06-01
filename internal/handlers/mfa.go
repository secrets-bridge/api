// Handlers — MFA enrollment + management (Slice H2 / H3 / H5).
//
// Today only the TOTP enrollment endpoints land. WebAuthn (H3),
// challenge / verify (H4), and the management UX (delete, list) wire
// into this same handler in subsequent slices.
//
// All endpoints derive the caller's user id from the authenticated
// session — never trust a body field. Cross-user paths are
// structurally impossible:
//   - Enroll / Confirm read `auth.IdentityFromContext` only
//   - Delete (Slice H3+) passes (factor_id, userID) to the repository
//     so a hostile request can't delete another user's factor

package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// MFA is the HTTP layer for /users/me/mfa/*.
type MFA struct {
	factors storage.UserMFAFactorRepository
	users   storage.LocalUserRepository
	totp    *services.TOTPService
}

// NewMFA wires the handler. `totp` may be nil — endpoints under
// /totp/* return 503 in that case (useful in tests that don't
// instantiate the service).
func NewMFA(factors storage.UserMFAFactorRepository, users storage.LocalUserRepository, totp *services.TOTPService) *MFA {
	return &MFA{factors: factors, users: users, totp: totp}
}

// MFAFactorBody is the public read shape — does NOT include the
// envelope-encrypted secret columns, only the metadata the user needs
// to recognise + manage their factors.
type MFAFactorBody struct {
	ID         string  `json:"id"`
	Kind       string  `json:"kind"`
	Label      string  `json:"label"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
}

// List handles GET /users/me/mfa/factors — the enrollment page's
// "your factors" table. Empty array when nothing is enrolled.
func (h *MFA) List(c fiber.Ctx) error {
	uid, err := h.userIDFromCtx(c)
	if err != nil {
		return err
	}
	rows, err := h.factors.ListForUser(c.Context(), uid)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	out := make([]MFAFactorBody, 0, len(rows))
	for _, f := range rows {
		var last *string
		if f.LastUsedAt != nil {
			s := f.LastUsedAt.UTC().Format("2006-01-02T15:04:05Z")
			last = &s
		}
		out = append(out, MFAFactorBody{
			ID:         f.ID.String(),
			Kind:       string(f.Kind),
			Label:      f.Label,
			CreatedAt:  f.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			LastUsedAt: last,
		})
	}
	return c.JSON(out)
}

// Delete handles DELETE /users/me/mfa/factors/:id. User-scoped — the
// repository rejects (id, userID) mismatches with ErrNotFound, which
// surfaces as 404 here. We deliberately don't distinguish "not yours"
// from "doesn't exist" so a hostile caller can't enumerate factor IDs.
func (h *MFA) Delete(c fiber.Ctx) error {
	uid, err := h.userIDFromCtx(c)
	if err != nil {
		return err
	}
	fid, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "factor id must be a uuid")
	}
	if err := h.factors.Delete(c.Context(), fid, uid); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "factor not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- TOTP ------------------------------------------------------------

// TOTPEnrollRequest is the body for POST /users/me/mfa/totp/enroll.
// `label` is what the user wants this factor called in their factor
// list ("iPhone backup", "Yubikey", ...). Required + per-user UNIQUE.
type TOTPEnrollRequest struct {
	Label string `json:"label"`
}

// TOTPEnrollResponse is the wire shape — the SPA renders
// `provisioning_uri` as a QR code and shows `secret_base32` as a
// "can't scan? type this" fallback. `challenge_id` round-trips into
// the confirm call.
type TOTPEnrollResponse struct {
	ChallengeID     string `json:"challenge_id"`
	SecretBase32    string `json:"secret_base32"`
	ProvisioningURI string `json:"provisioning_uri"`
	ExpiresAt       string `json:"expires_at"`
}

// TOTPConfirmRequest is the body for POST /users/me/mfa/totp/confirm.
type TOTPConfirmRequest struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
}

// EnrollTOTP handles POST /users/me/mfa/totp/enroll. Returns the
// QR-renderable provisioning URI + cached base32 secret. Nothing
// lands in Postgres until the matching /confirm call succeeds.
func (h *MFA) EnrollTOTP(c fiber.Ctx) error {
	if h.totp == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "totp not wired")
	}
	uid, err := h.userIDFromCtx(c)
	if err != nil {
		return err
	}
	var body TOTPEnrollRequest
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid body")
	}
	// Pull the user's email for the otpauth label so the
	// authenticator app distinguishes multi-account devices.
	accountName := ""
	if h.users != nil {
		if u, err := h.users.Get(c.Context(), uid); err == nil && u != nil {
			accountName = u.Email
		}
	}
	out, err := h.totp.Enroll(c.Context(), uid, body.Label, accountName)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(TOTPEnrollResponse{
		ChallengeID:     out.ChallengeID,
		SecretBase32:    out.SecretBase32,
		ProvisioningURI: out.ProvisioningURI,
		ExpiresAt:       out.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// ConfirmTOTP handles POST /users/me/mfa/totp/confirm. On success the
// factor row is persisted and returned (same shape as List). On
// invalid code: 400 + the Redis challenge is gone (single-shot) so
// the user must restart enrollment.
func (h *MFA) ConfirmTOTP(c fiber.Ctx) error {
	if h.totp == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "totp not wired")
	}
	uid, err := h.userIDFromCtx(c)
	if err != nil {
		return err
	}
	var body TOTPConfirmRequest
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid body")
	}
	if body.ChallengeID == "" || body.Code == "" {
		return fiber.NewError(fiber.StatusBadRequest, "challenge_id + code required")
	}
	factor, err := h.totp.ConfirmEnroll(c.Context(), uid, body.ChallengeID, body.Code)
	if err != nil {
		return mapTOTPError(err)
	}
	var last *string
	if factor.LastUsedAt != nil {
		s := factor.LastUsedAt.UTC().Format("2006-01-02T15:04:05Z")
		last = &s
	}
	return c.Status(fiber.StatusCreated).JSON(MFAFactorBody{
		ID:         factor.ID.String(),
		Kind:       string(factor.Kind),
		Label:      factor.Label,
		CreatedAt:  factor.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		LastUsedAt: last,
	})
}

// --- helpers ---------------------------------------------------------

func (h *MFA) userIDFromCtx(c fiber.Ctx) (uuid.UUID, error) {
	sub, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return uuid.Nil, fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	uid, err := uuid.Parse(sub)
	if err != nil {
		return uuid.Nil, fiber.NewError(fiber.StatusUnprocessableEntity, "identity is not a user id")
	}
	return uid, nil
}

func mapTOTPError(err error) error {
	switch {
	case errors.Is(err, services.ErrTOTPChallengeNotFound):
		return fiber.NewError(fiber.StatusGone, "enrollment challenge expired or already used")
	case errors.Is(err, services.ErrTOTPChallengeUser):
		// Same status as challenge_missing so a probing attacker
		// can't distinguish "wrong owner" from "challenge gone".
		return fiber.NewError(fiber.StatusGone, "enrollment challenge expired or already used")
	case errors.Is(err, services.ErrTOTPInvalidCode):
		return fiber.NewError(fiber.StatusBadRequest, "invalid code")
	case errors.Is(err, storage.ErrMFALabelExists):
		return fiber.NewError(fiber.StatusConflict, "label already used")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}
