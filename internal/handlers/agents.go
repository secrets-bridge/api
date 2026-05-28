package handlers

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Agents is the HTTP layer over services.AgentService.
type Agents struct {
	svc *services.AgentService
}

// NewAgents binds an Agents handler to its service.
func NewAgents(svc *services.AgentService) *Agents { return &Agents{svc: svc} }

// MintRequest is the body of POST /api/v1/agents.
type MintRequest struct {
	Name  string         `json:"name"`
	Scope map[string]any `json:"scope,omitempty"`
}

// MintResponse is returned by POST /api/v1/agents. The registration
// token is returned EXACTLY ONCE — the admin must save it.
type MintResponse struct {
	ID                uuid.UUID `json:"id"`
	Name              string    `json:"name"`
	RegistrationToken string    `json:"registration_token"`
}

// Mint handles the admin-initiated mint of a new agent registration
// token. Treated as authenticated by the api/v1 group's middleware
// chain (auth stub today; real RBAC in #10).
func (h *Agents) Mint(c fiber.Ctx) error {
	var req MintRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if strings.TrimSpace(req.Name) == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	minted, err := h.svc.MintRegistrationToken(c.Context(), req.Name, req.Scope)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(MintResponse{
		ID:                minted.ID,
		Name:              minted.Name,
		RegistrationToken: minted.RegistrationToken,
	})
}

// RegisterRequest is the body of POST /api/v1/agents/{id}/register.
type RegisterRequest struct {
	RegistrationToken string `json:"registration_token"`
}

// RegisterResponse is returned to the agent after a successful
// register. The agent_secret is the credential used on every
// subsequent heartbeat — the agent must persist it.
type RegisterResponse struct {
	ID          uuid.UUID `json:"id"`
	AgentSecret string    `json:"agent_secret"`
}

// Register accepts a one-time registration token and returns the
// long-lived agent secret. Unauthenticated by design — the bearer of
// the registration token is the agent we just provisioned.
func (h *Agents) Register(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid agent id")
	}
	var req RegisterRequest
	if err := c.Bind().JSON(&req); err != nil || req.RegistrationToken == "" {
		return fiber.NewError(fiber.StatusBadRequest, "registration_token is required")
	}

	reg, err := h.svc.Register(c.Context(), id, req.RegistrationToken)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "agent not found")
	case errors.Is(err, storage.ErrUnauthorized):
		// Generic message — don't leak whether the agent exists or
		// the token is wrong. The audit log holds the specifics.
		return fiber.NewError(fiber.StatusUnauthorized, "registration rejected")
	case err != nil:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.Status(fiber.StatusOK).JSON(RegisterResponse{
		ID:          reg.ID,
		AgentSecret: reg.AgentSecret,
	})
}

// Heartbeat is the agent's check-in. Authentication is via the agent
// secret in the X-Agent-Secret header — the path id MUST match the
// owner of that secret.
func (h *Agents) Heartbeat(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid agent id")
	}
	secret := c.Get("X-Agent-Secret")
	if secret == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "X-Agent-Secret header required")
	}

	err = h.svc.Heartbeat(c.Context(), id, secret)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "agent not found")
	case errors.Is(err, storage.ErrUnauthorized):
		return fiber.NewError(fiber.StatusUnauthorized, "heartbeat rejected")
	case err != nil:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// AgentListItem is one row in the response to GET /api/v1/agents.
// Notice the registration_token and agent_secret are NOT exposed.
type AgentListItem struct {
	ID         uuid.UUID      `json:"id"`
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	Scope      map[string]any `json:"scope,omitempty"`
	CreatedAt  string         `json:"created_at"`
	LastSeenAt *string        `json:"last_seen_at,omitempty"`
}

// List returns every agent. Admin-only in production; the auth stub
// in middleware.Auth() admits everything during scaffolding.
func (h *Agents) List(c fiber.Ctx) error {
	views, err := h.svc.List(c.Context())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	out := make([]AgentListItem, 0, len(views))
	for _, v := range views {
		item := AgentListItem{
			ID:        v.ID,
			Name:      v.Name,
			Status:    string(v.Status),
			Scope:     v.Scope,
			CreatedAt: v.CreatedAt.UTC().Format(rfc3339Nano),
		}
		if v.LastSeenAt != nil {
			s := v.LastSeenAt.UTC().Format(rfc3339Nano)
			item.LastSeenAt = &s
		}
		out = append(out, item)
	}
	return c.Status(fiber.StatusOK).JSON(out)
}

const rfc3339Nano = "2006-01-02T15:04:05.000000000Z07:00"
