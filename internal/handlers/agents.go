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

// MintResponse is returned by POST /api/v1/agents. The agent_secret is
// returned EXACTLY ONCE — the admin must save it and hand it to the
// agent through a K8s Secret / env vars / SOPS-encrypted Helm values.
type MintResponse struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	AgentSecret string    `json:"agent_secret"`
}

// Mint handles the admin-initiated mint of a new agent. The response
// includes the plaintext long-lived secret; the API does NOT support
// retrieving it after the fact.
func (h *Agents) Mint(c fiber.Ctx) error {
	var req MintRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if strings.TrimSpace(req.Name) == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	minted, err := h.svc.Mint(c.Context(), req.Name, req.Scope)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(MintResponse{
		ID:          minted.ID,
		Name:        minted.Name,
		AgentSecret: minted.AgentSecret,
	})
}

// Heartbeat is the agent's check-in. Authentication is via the agent
// secret in the X-Agent-Secret header.
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
// The agent secret is NOT exposed.
type AgentListItem struct {
	ID         uuid.UUID      `json:"id"`
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	Scope      map[string]any `json:"scope,omitempty"`
	CreatedAt  string         `json:"created_at"`
	LastSeenAt *string        `json:"last_seen_at,omitempty"`
}

// List returns every agent. Admin-only in production; today the auth
// stub admits everything.
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
