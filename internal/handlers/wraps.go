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
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Wraps is the agent-side HTTP layer over the wrap surface. Today it
// covers two endpoints:
//
//	GET  /api/v1/agents/:id/wraps/:wrap_id  — fetch (Piece 3c)
//	POST /api/v1/agents/:id/wraps           — create (Piece 5a, read flow)
//
// Both are gated by AgentAuth.
type Wraps struct {
	requests *services.RequestService
	wraps    *services.WrapService
}

// NewWraps binds a Wraps handler to its services.
func NewWraps(requests *services.RequestService, wraps *services.WrapService) *Wraps {
	return &Wraps{requests: requests, wraps: wraps}
}

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

// CreateWrapBody is the JSON the agent POSTs to create a wrap during
// the read flow. The value is base64-encoded; the agent computed it
// from core/providers.GetValue and is about to send it over TLS so
// the CP can envelope-encrypt + persist it.
type CreateWrapBody struct {
	RequestID string `json:"request_id"`
	KeyName   string `json:"key_name"`
	Value     string `json:"value"` // base64-encoded plaintext
}

// CreateResponse is the JSON returned after the wrap is persisted.
// The agent uses wrap_id to report which wrap belongs to which key —
// the requester then retrieves it through the user-bound endpoint.
type CreateResponse struct {
	WrapID      string `json:"wrap_id"`
	RequestID   string `json:"request_id"`
	KeyName     string `json:"key_name"`
	ByteLength  int    `json:"byte_length"`
	ContentHash string `json:"content_hash"`
	ExpiresAt   string `json:"expires_at"`
}

// Create handles POST /api/v1/agents/:id/wraps.
//
// Used by the agent's ReadExecutor: after GetValue returns the bundle,
// the agent splits it by key, base64-encodes each plaintext, and POSTs
// one wrap per key. The CP runs WrapService.Wrap which envelope-
// encrypts via the KMS layer and persists.
//
// Authorization (today): AgentAuth middleware confirms the request is
// from a valid agent. A stricter check — "this agent owns the job for
// this request" — lands in a follow-up once jobs carry an assigned
// agent ID.
func (h *Wraps) Create(c fiber.Ctx) error {
	agentID, ok := middleware.AgentIDFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "agent identity missing in context")
	}
	var body CreateWrapBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.RequestID == "" || body.KeyName == "" || body.Value == "" {
		return fiber.NewError(fiber.StatusBadRequest, "request_id, key_name, value required")
	}
	reqID, err := uuid.Parse(body.RequestID)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request_id UUID")
	}
	plaintext, err := base64.StdEncoding.DecodeString(body.Value)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "value is not valid base64")
	}
	defer zero(plaintext)

	// Validate the request: must exist, must be a read request, must
	// be in `approved` status. The agent should never be creating
	// wraps against a pending or terminal request.
	req, err := h.requests.Get(c.Context(), reqID)
	if err != nil {
		return wrapErr(err)
	}
	if req.Type != storage.AccessRequestTypeRead {
		return fiber.NewError(fiber.StatusBadRequest, "wrap creation only supported for read requests")
	}
	if req.Status != storage.AccessRequestStatusApproved {
		return fiber.NewError(fiber.StatusConflict, "owning request is not approved")
	}

	wf, err := h.requests.WorkflowFor(c.Context(), req)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "load workflow: "+err.Error())
	}

	wrap, err := h.wraps.WrapByAgent(c.Context(), agentID, services.WrapRequest{
		Plaintext: plaintext,
		RequestID: &reqID,
		KeyName:   body.KeyName,
		TTL:       wf.WrapTTLApproved,
	})
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "wrap: "+err.Error())
	}

	return c.Status(fiber.StatusCreated).JSON(CreateResponse{
		WrapID:      wrap.ID.String(),
		RequestID:   reqID.String(),
		KeyName:     body.KeyName,
		ByteLength:  wrap.ByteLength,
		ContentHash: hex.EncodeToString(wrap.ContentHash),
		ExpiresAt:   wrap.ExpiresAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	})
}

// zero scrubs a byte slice. Defense in depth — the handler returns
// promptly after JSON-encoding so the plaintext lifetime is short,
// but explicit zero keeps it out of any deferred-allocation reuse.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
