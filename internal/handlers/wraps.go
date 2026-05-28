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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/sealing"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Wraps is the agent-side HTTP layer over the wrap surface. Endpoints:
//
//	GET  /api/v1/agents/:id/wraps/:wrap_id  — fetch (Piece 3c)
//	POST /api/v1/agents/:id/wraps           — create (Piece 5a, read flow)
//	POST /api/v1/agents/:id/dek             — issue a wire-envelope DEK (Piece 8b)
//
// All gated by AgentAuth.
type Wraps struct {
	requests *services.RequestService
	wraps    *services.WrapService
	agents   AgentLookup
	kms      keymgmt.KeyManager
}

// AgentLookup is the slice of AgentRepository the Wraps handler needs:
// just GET by ID. Kept narrow so unit tests can fake it.
type AgentLookup interface {
	Get(ctx context.Context, id uuid.UUID) (*storage.Agent, error)
}

// NewWraps binds a Wraps handler to its services.
func NewWraps(requests *services.RequestService, wraps *services.WrapService, agents AgentLookup, km keymgmt.KeyManager) *Wraps {
	return &Wraps{requests: requests, wraps: wraps, agents: agents, kms: km}
}

// WrapPayload is the JSON returned to the agent. EXACTLY ONE of Value
// (plaintext-over-TLS) or Sealed (wire-envelope) is populated:
//
//   - If the agent registered a public_key at mint time, the CP
//     SEALS the response to that key; only the Sealed field is set.
//   - If no public_key is registered (backwards-compat agents), the
//     CP falls back to Value with plaintext base64.
//
// The agent inspects which field is populated and decodes accordingly.
type WrapPayload struct {
	WrapID      string            `json:"wrap_id"`
	RequestID   string            `json:"request_id,omitempty"`
	KeyName     string            `json:"key_name,omitempty"`
	Value       string            `json:"value,omitempty"`  // base64 — present when not sealed
	Sealed      *SealedEnvelope   `json:"sealed,omitempty"` // present when sealed
	ByteLength  int               `json:"byte_length"`
	ContentHash string            `json:"content_hash"` // hex SHA-256 of plaintext
	Algorithm   string            `json:"algorithm"`    // the wrap's AEAD (storage layer)
}

// SealedEnvelope is the wire-envelope shape returned by the CP when the
// agent has a registered public key. All byte fields are base64.
//
// The agent decrypts by:
//
//	shared = X25519(agent_private_key, ephemeral_public_key)
//	aes_key = HKDF(shared, salt=ephemeral_public_key || agent_public_key, info="secrets-bridge.wrap.v1")
//	plaintext = AES-256-GCM-Open(aes_key, ciphertext, nonce)
type SealedEnvelope struct {
	Algorithm          string `json:"algorithm"`             // "x25519-hkdf-aes-gcm"
	Ciphertext         string `json:"ciphertext"`            // base64
	Nonce              string `json:"nonce"`                 // base64
	EphemeralPublicKey string `json:"ephemeral_public_key"`  // base64
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
		ByteLength:  wrap.ByteLength,
		ContentHash: hex.EncodeToString(wrap.ContentHash),
		Algorithm:   wrap.Algorithm,
	}
	if wrap.RequestID != nil {
		body.RequestID = wrap.RequestID.String()
	}

	// SEAL when the requesting agent has a public key on file.
	// Otherwise fall back to plaintext-over-TLS (backwards compat for
	// agents that registered before wire-envelope was wired).
	agent, err := h.agents.Get(c.Context(), agentID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "load agent: "+err.Error())
	}
	if len(agent.PublicKey) > 0 && agent.PublicKeyAlgorithm == "x25519" {
		env, err := sealing.Seal(plaintext, agent.PublicKey)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "seal: "+err.Error())
		}
		body.Sealed = &SealedEnvelope{
			Algorithm:          env.Algorithm,
			Ciphertext:         base64.StdEncoding.EncodeToString(env.Ciphertext),
			Nonce:              base64.StdEncoding.EncodeToString(env.Nonce),
			EphemeralPublicKey: base64.StdEncoding.EncodeToString(env.EphemeralPublicKey),
		}
	} else {
		body.Value = base64.StdEncoding.EncodeToString(plaintext)
	}
	return c.Status(fiber.StatusOK).JSON(body)
}

// DEKResponse is what POST /api/v1/agents/:id/dek returns. The agent
// uses Plaintext to AES-256-GCM-encrypt one payload and immediately
// throws it away. Ciphertext is the KMS-wrapped form to ship back
// in the wrap creation request.
type DEKResponse struct {
	Algorithm  string `json:"algorithm"`            // "aes-256-gcm"
	Plaintext  string `json:"plaintext"`            // base64; ephemeral, single-use
	Ciphertext string `json:"ciphertext"`           // base64; for ROUND-TRIPPING to /wraps
	KeyID      string `json:"kms_key_id,omitempty"` // tells the agent which master wrapped the DEK
}

// IssueDEK handles POST /api/v1/agents/:id/dek. Returns a fresh DEK
// the agent uses to wire-envelope a single value before POSTing to
// /agents/:id/wraps.
//
// Single-use semantics: nothing prevents the agent from caching the
// DEK and using it twice, but the wrap-creation endpoint accepts each
// dek_ciphertext at most once per call — the design encourages a
// 1:1 DEK:wrap mapping so a compromised DEK only affects one value.
func (h *Wraps) IssueDEK(c fiber.Ctx) error {
	dk, err := h.kms.GenerateDataKey(c.Context())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "generate data key: "+err.Error())
	}
	defer zero(dk.Plaintext)
	return c.Status(fiber.StatusCreated).JSON(DEKResponse{
		Algorithm:  "aes-256-gcm",
		Plaintext:  base64.StdEncoding.EncodeToString(dk.Plaintext),
		Ciphertext: base64.StdEncoding.EncodeToString(dk.Ciphertext),
		KeyID:      dk.KeyID,
	})
}

// CreateWrapBody is the JSON the agent POSTs to create a wrap during
// the read flow. EXACTLY ONE of Value (plaintext-over-TLS) or Envelope
// (wire-envelope, Piece 8b) is populated:
//
//   - Value: base64 plaintext. Legacy shape; TLS is the only thing
//     protecting it in flight.
//   - Envelope: agent first called /agents/:id/dek to get a fresh
//     KMS DEK, AES-256-GCM-encrypted the plaintext locally, and
//     POSTs the ciphertext + nonce + dek_ciphertext here. The CP
//     unwraps the DEK via KMS, decrypts, then re-envelopes for
//     storage. Plaintext never on the wire.
type CreateWrapBody struct {
	RequestID string                 `json:"request_id"`
	KeyName   string                 `json:"key_name"`
	Value     string                 `json:"value,omitempty"`    // base64; legacy path
	Envelope  *CreateWrapEnvelope    `json:"envelope,omitempty"` // wire-envelope path
}

// CreateWrapEnvelope is the agent-side wire-envelope shape posted to
// the wrap-creation endpoint. All byte fields are base64.
type CreateWrapEnvelope struct {
	Algorithm        string `json:"algorithm"`         // "aes-256-gcm"
	Ciphertext       string `json:"ciphertext"`        // AES-GCM(dek, plaintext)
	Nonce            string `json:"nonce"`             // GCM nonce
	DEKCiphertext    string `json:"dek_ciphertext"`    // KMS-wrapped DEK (round-trip from /dek)
	DEKKMSKeyID      string `json:"dek_kms_key_id,omitempty"`
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
	if body.RequestID == "" || body.KeyName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "request_id, key_name required")
	}
	if (body.Value == "") == (body.Envelope == nil) {
		return fiber.NewError(fiber.StatusBadRequest, "exactly one of value or envelope is required")
	}
	reqID, err := uuid.Parse(body.RequestID)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request_id UUID")
	}

	var plaintext []byte
	if body.Value != "" {
		// Legacy plaintext-over-TLS path.
		plaintext, err = base64.StdEncoding.DecodeString(body.Value)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "value is not valid base64")
		}
	} else {
		// Wire-envelope path: unwrap the agent-supplied DEK envelope.
		plaintext, err = h.unsealAgentEnvelope(c.Context(), body.Envelope)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "envelope: "+err.Error())
		}
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

// unsealAgentEnvelope reverses what the agent did with the DEK that
// /agents/:id/dek issued: KMS-decrypt the DEK ciphertext to recover
// the plaintext data key, then AES-GCM-open the ciphertext.
//
// The plaintext DEK is zeroed inside this function; only the unwrapped
// plaintext escapes (and the caller defer-zeroes it).
func (h *Wraps) unsealAgentEnvelope(ctx context.Context, env *CreateWrapEnvelope) ([]byte, error) {
	if env.Algorithm != "aes-256-gcm" {
		return nil, errors.New("unsupported algorithm")
	}
	if env.Ciphertext == "" || env.Nonce == "" || env.DEKCiphertext == "" {
		return nil, errors.New("ciphertext, nonce, dek_ciphertext required")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, errors.New("ciphertext is not valid base64")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, errors.New("nonce is not valid base64")
	}
	dekCt, err := base64.StdEncoding.DecodeString(env.DEKCiphertext)
	if err != nil {
		return nil, errors.New("dek_ciphertext is not valid base64")
	}

	dek, err := h.kms.DecryptDataKey(ctx, dekCt, env.DEKKMSKeyID)
	if err != nil {
		return nil, errors.New("decrypt data key: " + err.Error())
	}
	defer zero(dek)
	if len(dek) != 32 {
		return nil, errors.New("dek is not 32 bytes")
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, errors.New("aes cipher: " + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("gcm: " + err.Error())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("authenticate envelope ciphertext: " + err.Error())
	}
	return plaintext, nil
}

// zero scrubs a byte slice. Defense in depth — the handler returns
// promptly after JSON-encoding so the plaintext lifetime is short,
// but explicit zero keeps it out of any deferred-allocation reuse.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

