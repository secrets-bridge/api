package handlers

// Agent Onboarding MVP (api#178) — HTTP layer for enrollment-token
// generation (admin) + agent self-enrollment (token-only).

import (
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// GenerateEnrollmentTokenRequest is the admin body for
// POST /provider-connections/:id/agent-enrollment-token.
type GenerateEnrollmentTokenRequest struct {
	Name                 string `json:"name,omitempty"`
	ExpiresInSeconds     int    `json:"expires_in_seconds,omitempty"`
	ExpectedClusterName  string `json:"expected_cluster_name,omitempty"`
	ExpectedProviderType string `json:"expected_provider_type,omitempty"`
}

// EnrollmentTokenResponse returns the one-time token EXACTLY ONCE.
type EnrollmentTokenResponse struct {
	EnrollmentToken      string            `json:"enrollment_token"`
	ExpiresAt            string            `json:"expires_at"`
	ProviderConnectionID string            `json:"provider_connection_id"`
	InstallHint          map[string]string `json:"install_hint"`
}

// GenerateEnrollmentToken handles POST
// /provider-connections/:id/agent-enrollment-token. Session-gated +
// agent.mint. NOT under the /api/v1/agents/ session-exempt prefix.
func (h *Agents) GenerateEnrollmentToken(c fiber.Ctx) error {
	connID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "provider connection id must be a UUID")
	}
	actor, ok := auth.IdentityFromContext(c.Context())
	if !ok || actor == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	var req GenerateEnrollmentTokenRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	res, err := h.svc.GenerateEnrollmentToken(c.Context(), services.GenerateEnrollmentTokenInput{
		ProviderConnectionID: connID,
		Name:                 req.Name,
		ExpiresInSeconds:     req.ExpiresInSeconds,
		ExpectedClusterName:  req.ExpectedClusterName,
		ExpectedProviderType: req.ExpectedProviderType,
		CreatedBy:            actor,
	})
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrConnectionNotFound):
			return fiber.NewError(fiber.StatusNotFound, "provider connection not found")
		case errors.Is(err, services.ErrEnrollmentConnectionUnusable):
			return fiber.NewError(fiber.StatusConflict, "provider connection is not active")
		case errors.Is(err, services.ErrEnrollmentNotConfigured):
			return fiber.NewError(fiber.StatusServiceUnavailable, "agent enrollment is not configured")
		default:
			return fiber.NewError(fiber.StatusInternalServerError, "could not generate enrollment token")
		}
	}

	// install_hint embeds the token (this is its one-time return); the
	// control-plane URL is a placeholder the operator/UI substitutes.
	hint := map[string]string{
		"helm": fmt.Sprintf(
			"helm upgrade --install secrets-bridge-agent secrets-bridge/agent "+
				"--set controlPlane.url=<CONTROL_PLANE_URL> --set enrollment.token=%s",
			res.Token),
		"cli": fmt.Sprintf(
			"secrets-bridge agent enroll --control-plane-url <CONTROL_PLANE_URL> "+
				"--enrollment-token %s", res.Token),
	}
	return c.Status(fiber.StatusCreated).JSON(EnrollmentTokenResponse{
		EnrollmentToken:      res.Token,
		ExpiresAt:            res.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		ProviderConnectionID: res.ProviderConnectionID.String(),
		InstallHint:          hint,
	})
}

// EnrollRequest is the agent body for POST /agents/enroll.
type EnrollRequest struct {
	EnrollmentToken      string   `json:"enrollment_token"`
	AgentName            string   `json:"agent_name"`
	AgentVersion         string   `json:"agent_version,omitempty"`
	ClusterName          string   `json:"cluster_name,omitempty"`
	ProviderType         string   `json:"provider_type,omitempty"`
	Region               string   `json:"region,omitempty"`
	Capabilities         []string `json:"capabilities,omitempty"`
	PublicKeyFingerprint string   `json:"public_key_fingerprint,omitempty"`
}

// EnrollResponse returns the persistent agent credential EXACTLY ONCE.
type EnrollResponse struct {
	AgentID                  string `json:"agent_id"`
	ProviderConnectionID     string `json:"provider_connection_id"`
	AgentToken               string `json:"agent_token"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	JobPollIntervalSeconds   int    `json:"job_poll_interval_seconds"`
}

// Enroll handles POST /agents/enroll. Auth is the enrollment token ONLY —
// no session, no AgentAuth (the agent has no credential yet). This route is
// under the /api/v1/agents/ session-exempt prefix by design; the token is
// its authentication.
func (h *Agents) Enroll(c fiber.Ctx) error {
	var req EnrollRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	res, err := h.svc.Enroll(c.Context(), services.EnrollInput{
		Token:                req.EnrollmentToken,
		AgentName:            req.AgentName,
		AgentVersion:         req.AgentVersion,
		ClusterName:          req.ClusterName,
		ProviderType:         req.ProviderType,
		Region:               req.Region,
		Capabilities:         req.Capabilities,
		PublicKeyFingerprint: req.PublicKeyFingerprint,
	})
	if err != nil {
		return enrollErr(c, err)
	}

	return c.Status(fiber.StatusCreated).JSON(EnrollResponse{
		AgentID:                  res.AgentID.String(),
		ProviderConnectionID:     res.ProviderConnectionID.String(),
		AgentToken:               res.AgentToken,
		HeartbeatIntervalSeconds: res.HeartbeatIntervalSeconds,
		JobPollIntervalSeconds:   res.JobPollIntervalSeconds,
	})
}

// enrollErr maps enrollment sentinels to safe, metadata-only error bodies
// ({"error": "<code>"}). No token, hash, or provider payload ever appears.
func enrollErr(c fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	body := "enrollment_failed"
	switch {
	case errors.Is(err, services.ErrEnrollmentTokenInvalid):
		code, body = fiber.StatusUnauthorized, "enrollment_token_invalid"
	case errors.Is(err, services.ErrEnrollmentTokenExpired):
		code, body = fiber.StatusUnauthorized, "enrollment_token_expired"
	case errors.Is(err, services.ErrEnrollmentTokenConsumed):
		code, body = fiber.StatusConflict, "enrollment_token_already_consumed"
	case errors.Is(err, services.ErrEnrollmentTokenRevoked):
		code, body = fiber.StatusForbidden, "enrollment_token_revoked"
	case errors.Is(err, services.ErrEnrollmentProviderMismatch):
		code, body = fiber.StatusBadRequest, "provider_type_mismatch"
	case errors.Is(err, services.ErrEnrollmentClusterMismatch):
		code, body = fiber.StatusBadRequest, "cluster_name_mismatch"
	case errors.Is(err, services.ErrEnrollmentConnectionUnusable):
		code, body = fiber.StatusConflict, "provider_connection_unavailable"
	case errors.Is(err, services.ErrEnrollmentNotConfigured):
		code, body = fiber.StatusServiceUnavailable, "enrollment_not_configured"
	case errors.Is(err, services.ErrInvalidInput):
		code, body = fiber.StatusBadRequest, "invalid_request"
	default:
		// agent_name required + any unexpected error → generic 400/500.
		if err != nil && err.Error() == "agents: agent_name is required" {
			code, body = fiber.StatusBadRequest, "agent_name_required"
		}
	}
	return c.Status(code).JSON(fiber.Map{"error": body})
}
