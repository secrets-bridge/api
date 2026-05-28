package handlers

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Agents is the HTTP layer over services.AgentService.
type Agents struct {
	svc *services.AgentService
}

// NewAgents binds an Agents handler to its service.
func NewAgents(svc *services.AgentService) *Agents { return &Agents{svc: svc} }

// MintRequest is the body of POST /api/v1/agents. PublicKey is the
// agent's X25519 public key, base64-encoded. When present, the CP
// SEALS wrap retrieval responses to this key (Piece 8b); when absent,
// the CP falls back to plaintext-over-TLS (backwards compat).
type MintRequest struct {
	Name               string         `json:"name"`
	Scope              map[string]any `json:"scope,omitempty"`
	PublicKey          string         `json:"public_key,omitempty"`           // base64
	PublicKeyAlgorithm string         `json:"public_key_algorithm,omitempty"` // "x25519" today
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

	in := services.MintInput{Name: req.Name, Scope: req.Scope}
	if req.PublicKey != "" {
		pk, err := base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "public_key is not valid base64: "+err.Error())
		}
		in.PublicKey = pk
		in.PublicKeyAlgorithm = req.PublicKeyAlgorithm
		if in.PublicKeyAlgorithm == "" {
			in.PublicKeyAlgorithm = "x25519"
		}
	}
	minted, err := h.svc.Mint(c.Context(), in)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(MintResponse{
		ID:          minted.ID,
		Name:        minted.Name,
		AgentSecret: minted.AgentSecret,
	})
}

// PublicKeyRequest is the body the agent PUTs to register its X25519
// public key after generating the keypair at startup. Idempotent —
// repeatedly posting the same key is a no-op.
type PublicKeyRequest struct {
	PublicKey          string `json:"public_key"`           // base64
	PublicKeyAlgorithm string `json:"public_key_algorithm"` // "x25519"
}

// SetPublicKey handles PUT /api/v1/agents/:id/public-key. Authentication
// is AgentAuth — only the agent itself can register its own public key.
func (h *Agents) SetPublicKey(c fiber.Ctx) error {
	agentID, ok := middleware.AgentIDFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "agent identity missing in context")
	}
	var body PublicKeyRequest
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.PublicKey == "" {
		return fiber.NewError(fiber.StatusBadRequest, "public_key is required")
	}
	pk, err := base64.StdEncoding.DecodeString(body.PublicKey)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "public_key is not valid base64: "+err.Error())
	}
	alg := body.PublicKeyAlgorithm
	if alg == "" {
		alg = "x25519"
	}
	if err := h.svc.SetPublicKey(c.Context(), agentID, pk, alg); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Heartbeat is the agent's check-in. Authentication is handled by the
// AgentAuth middleware on the enclosing route group, so the handler
// simply pulls the authenticated agent ID from context, bumps
// last_seen_at, and returns 204.
func (h *Agents) Heartbeat(c fiber.Ctx) error {
	id, ok := middleware.AgentIDFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "agent identity missing in context")
	}
	// The header is still required for the service call — the
	// middleware has already validated it; we re-read so Heartbeat can
	// touch last_seen_at without a second cache lookup pattern that'd
	// fork the validation path.
	secret := c.Get("X-Agent-Secret")
	if err := h.svc.Heartbeat(c.Context(), id, secret); err != nil {
		switch {
		case errors.Is(err, storage.ErrNotFound):
			return fiber.NewError(fiber.StatusNotFound, "agent not found")
		case errors.Is(err, storage.ErrUnauthorized):
			return fiber.NewError(fiber.StatusUnauthorized, "heartbeat rejected")
		}
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
