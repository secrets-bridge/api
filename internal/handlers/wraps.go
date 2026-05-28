// Package handlers — wraps.go: agent-side wrap retrieval.
//
// The single endpoint mounted here lives under the AgentAuth route
// group. It is the ONLY way for an authenticated agent to obtain the
// plaintext of an approved wrap. Every call:
//   - is gated by AgentAuth (X-Agent-Secret)
//   - requires the owning request to be in `approved` status
//   - atomically marks the wrap consumed (single-shot — concurrent
//     racers see ErrAlreadyConsumed)
//   - audits both success and the typed failure modes
//
// The response carries the plaintext as base64 (JSON-friendly) plus
// the wrap's content_hash + byte_length so the agent can verify
// integrity locally before writing to the provider.
package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Wraps is the agent-side HTTP layer over RequestService.RetrieveWrap.
type Wraps struct {
	requests *services.RequestService
}

// NewWraps binds a Wraps handler to its service.
func NewWraps(requests *services.RequestService) *Wraps { return &Wraps{requests: requests} }

// WrapPayload is the JSON returned to the agent.
type WrapPayload struct {
	WrapID      string `json:"wrap_id"`
	RequestID   string `json:"request_id,omitempty"`
	KeyName     string `json:"key_name,omitempty"`
	Value       string `json:"value"`        // base64-encoded plaintext
	ByteLength  int    `json:"byte_length"`
	ContentHash string `json:"content_hash"` // hex SHA-256 of plaintext
	Algorithm   string `json:"algorithm"`
}

func wrapErr(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "wrap not found")
	case errors.Is(err, storage.ErrAlreadyConsumed):
		return fiber.NewError(fiber.StatusGone, "wrap already consumed")
	case errors.Is(err, storage.ErrExpired):
		return fiber.NewError(fiber.StatusGone, "wrap expired")
	case errors.Is(err, services.ErrRequestNotApproved):
		return fiber.NewError(fiber.StatusConflict, "owning request is not approved")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}

// Retrieve handles GET /api/v1/agents/:id/wraps/:wrap_id.
func (h *Wraps) Retrieve(c fiber.Ctx) error {
	wrapID, err := parseID(c, "wrap_id")
	if err != nil {
		return err
	}
	agentID, ok := middleware.AgentIDFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "agent identity missing in context")
	}

	plaintext, wrap, err := h.requests.RetrieveWrap(c.Context(), wrapID, agentID)
	if err != nil {
		return wrapErr(err)
	}
	defer zero(plaintext)

	body := WrapPayload{
		WrapID:      wrap.ID.String(),
		KeyName:     wrap.KeyName,
		Value:       base64.StdEncoding.EncodeToString(plaintext),
		ByteLength:  wrap.ByteLength,
		ContentHash: hex.EncodeToString(wrap.ContentHash),
		Algorithm:   wrap.Algorithm,
	}
	if wrap.RequestID != nil {
		body.RequestID = wrap.RequestID.String()
	}
	return c.Status(fiber.StatusOK).JSON(body)
}

// zero scrubs a byte slice. Defense in depth — the handler returns
// promptly after JSON-encoding so the plaintext lifetime is short,
// but explicit zero keeps it out of any deferred-allocation reuse.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
