package handlers

// Agent key rotation (skills#116): the admin's one-time rotation token,
// then the agent-side challenge and confirm. This is the only way an
// agent's wire key changes.

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// KeyRotationTokenResponse returns the rotation token EXACTLY ONCE.
type KeyRotationTokenResponse struct {
	RotationToken string `json:"rotation_token"`
	ExpiresAt     string `json:"expires_at"`
}

// RequestKeyRotation handles POST /admin/agents/:id/key-rotation
// (session, agent.mint and a fresh second factor).
func (h *Agents) RequestKeyRotation(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "agent id must be a UUID")
	}
	actor, ok := auth.IdentityFromContext(c.Context())
	if !ok || actor == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	res, err := h.svc.RequestKeyRotation(c.Context(), id, actor)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrNotFound):
			return fiber.NewError(fiber.StatusNotFound, "agent not found or revoked")
		case errors.Is(err, services.ErrKeyRotationNotConfigured):
			return fiber.NewError(fiber.StatusServiceUnavailable, "key rotation is not configured")
		}
		return fiber.NewError(fiber.StatusInternalServerError, "could not issue rotation token")
	}
	return c.Status(fiber.StatusCreated).JSON(KeyRotationTokenResponse{
		RotationToken: res.Token,
		ExpiresAt:     res.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// KeyRotationChallengeRequest is the body of POST
// /agents/:id/key-rotation/challenge.
type KeyRotationChallengeRequest struct {
	SchemaVersion      string `json:"schema_version"`
	RotationToken      string `json:"rotation_token"`
	PublicKey          string `json:"public_key"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
}

// KeyRotationConfirmRequest is the body of POST /agents/:id/key-rotation.
type KeyRotationConfirmRequest struct {
	SchemaVersion     string `json:"schema_version"`
	RotationToken     string `json:"rotation_token"`
	ChallengeID       string `json:"challenge_id"`
	ChallengeResponse string `json:"challenge_response"`
}

// KeyRotationResponse is returned by a confirmed rotation.
type KeyRotationResponse struct {
	AgentID              string `json:"agent_id"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	PublicKeyVersion     int    `json:"public_key_version"`
}

// KeyRotationChallenge handles POST /agents/:id/key-rotation/challenge,
// behind AgentSecretAuth (X-Agent-Secret; no key fingerprint, since the
// old private key may be the thing that was lost).
func (h *Agents) KeyRotationChallenge(c fiber.Ctx) error {
	agentID, ok := middleware.AgentIDFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "agent identity missing in context")
	}
	var req KeyRotationChallengeRequest
	if err := c.Bind().JSON(&req); err != nil {
		return enrollError(c, fiber.StatusBadRequest, "invalid_request")
	}
	ch, err := h.svc.KeyRotationChallenge(c.Context(), agentID, services.KeyRotationChallengeInput{
		SchemaVersion:      req.SchemaVersion,
		RotationToken:      req.RotationToken,
		PublicKey:          req.PublicKey,
		PublicKeyAlgorithm: req.PublicKeyAlgorithm,
	})
	if err != nil {
		return enrollErr(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(challengeResponse(ch))
}

// ConfirmKeyRotation handles POST /agents/:id/key-rotation, behind
// AgentSecretAuth.
func (h *Agents) ConfirmKeyRotation(c fiber.Ctx) error {
	agentID, ok := middleware.AgentIDFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "agent identity missing in context")
	}
	var req KeyRotationConfirmRequest
	if err := c.Bind().JSON(&req); err != nil {
		return enrollError(c, fiber.StatusBadRequest, "invalid_request")
	}
	res, err := h.svc.ConfirmKeyRotation(c.Context(), agentID, services.KeyRotationConfirmInput{
		SchemaVersion:     req.SchemaVersion,
		RotationToken:     req.RotationToken,
		ChallengeID:       req.ChallengeID,
		ChallengeResponse: req.ChallengeResponse,
	})
	if err != nil {
		return enrollErr(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(KeyRotationResponse{
		AgentID:              res.AgentID.String(),
		PublicKeyFingerprint: res.PublicKeyFingerprint,
		PublicKeyVersion:     res.PublicKeyVersion,
	})
}
