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
	"crypto/subtle"
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
	// allowUnsealed brings back the legacy plaintext-over-TLS shapes
	// (SB_ALLOW_UNSEALED_WRAPS). Off by default.
	allowUnsealed bool
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

// WithAllowUnsealed turns the legacy plaintext-over-TLS wrap shapes back
// on (SB_ALLOW_UNSEALED_WRAPS, api#264). Without it a wrap reaches an
// agent only sealed to its X25519 key, and agents post envelopes only.
func (h *Wraps) WithAllowUnsealed(allow bool) *Wraps {
	h.allowUnsealed = allow
	return h
}

// sealable reports whether an agent has a public key a wrap can be
// sealed to.
func sealable(a *storage.Agent) bool {
	return a.PublicKeyAlgorithm == "x25519" && len(a.PublicKey) == 32
}

// WrapPayload is the JSON returned to the agent. EXACTLY ONE of Value
// (plaintext-over-TLS) or Sealed (wire-envelope) is populated:
//
//   - The CP SEALS the response to the agent's bound X25519 public
//     key; Sealed and RecipientKeyFingerprint are always set.
//   - Value is never set by retrieval any more (skills#116): every
//     agent has a key. The field stays for the wire shape.
//
// The agent inspects which field is populated and decodes accordingly.
type WrapPayload struct {
	WrapID      string          `json:"wrap_id"`
	RequestID   string          `json:"request_id,omitempty"`
	KeyName     string          `json:"key_name,omitempty"`
	Value       *string         `json:"value,omitempty"`  // base64, present when not sealed ("" for an empty value)
	Sealed      *SealedEnvelope `json:"sealed,omitempty"` // present when sealed
	ByteLength  int             `json:"byte_length"`
	ContentHash string          `json:"content_hash"` // hex SHA-256 of plaintext
	Algorithm   string          `json:"algorithm"`    // the wrap's AEAD (storage layer)
	// RecipientKeyFingerprint names the key Sealed is sealed to
	// (skills#116). The Agent refuses a wrap whose fingerprint isn't its
	// own key's.
	RecipientKeyFingerprint string `json:"recipient_key_fingerprint"`
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
	Algorithm          string `json:"algorithm"`            // "x25519-hkdf-aes-gcm"
	Ciphertext         string `json:"ciphertext"`           // base64
	Nonce              string `json:"nonce"`                // base64
	EphemeralPublicKey string `json:"ephemeral_public_key"` // base64
}

// wrapErr maps an agent wrap retrieve error to its status. Create has
// its own coded mapping (createWrapErr).
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
	case errors.Is(err, storage.ErrJobNotClaimed):
		return fiber.NewError(fiber.StatusForbidden, "request is not dispatched to this agent")
	case errors.Is(err, services.ErrWrapNotForAgent):
		return fiber.NewError(fiber.StatusForbidden, "wrap is not retrievable by an agent")
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

	// Decide how the value can travel BEFORE the single-shot consume, so
	// a refusal never burns the wrap. An agent with no usable X25519 key
	// gets the same answer for every wrap id, so the refusal says
	// nothing about whether the wrap exists (api#264).
	agent, err := h.agents.Get(c.Context(), agentID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "load agent: "+err.Error())
	}
	// Every agent that is not revoked has a key (migration 0051), so a
	// wrap always leaves sealed; SB_ALLOW_UNSEALED_WRAPS no longer
	// applies to retrieval (skills#116).
	if !sealable(agent) {
		h.requests.AuditUnsealedWrapRefused(c.Context(), "wrap.retrieve", agentID, wrapID, "agent_public_key_missing")
		return fiber.NewError(fiber.StatusConflict,
			"agent_public_key_required: wraps are only delivered sealed")
	}
	// The key AgentAuth checked must still be the bound key: a rotation
	// between that read and this one would seal the wrap to a key the
	// caller does not hold and burn it. Checked before the consume.
	fingerprint := sealing.Fingerprint(agent.PublicKey)
	if checked, ok := middleware.AgentKeyFingerprintFromContext(c.Context()); !ok ||
		subtle.ConstantTimeCompare([]byte(checked), []byte(fingerprint)) != 1 {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "agent_key_mismatch"})
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

	// SEAL to the agent's key, the one AgentAuth just checked.
	env, err := sealing.Seal(plaintext, agent.PublicKey)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "seal failed")
	}
	body.RecipientKeyFingerprint = fingerprint
	body.Sealed = &SealedEnvelope{
		Algorithm:          env.Algorithm,
		Ciphertext:         base64.StdEncoding.EncodeToString(env.Ciphertext),
		Nonce:              base64.StdEncoding.EncodeToString(env.Nonce),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(env.EphemeralPublicKey),
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
//     protecting it in flight. Refused with 400 unless
//     SB_ALLOW_UNSEALED_WRAPS is on (api#264).
//   - Envelope: agent first called /agents/:id/dek to get a fresh
//     KMS DEK, AES-256-GCM-encrypted the plaintext locally, and
//     POSTs the ciphertext + nonce + dek_ciphertext here. The CP
//     unwraps the DEK via KMS, decrypts, then re-envelopes for
//     storage. Plaintext never on the wire.
//
// A pointer, so a legacy post of an empty value (`"value": ""`) is told
// apart from no value at all (api#286).
type CreateWrapBody struct {
	RequestID string              `json:"request_id"`
	KeyName   string              `json:"key_name"`
	Value     *string             `json:"value,omitempty"`    // base64; legacy path
	Envelope  *CreateWrapEnvelope `json:"envelope,omitempty"` // wire-envelope path
}

// CreateWrapEnvelope is the agent-side wire-envelope shape posted to
// the wrap-creation endpoint. All byte fields are base64.
type CreateWrapEnvelope struct {
	Algorithm     string `json:"algorithm"`      // "aes-256-gcm"
	Ciphertext    string `json:"ciphertext"`     // AES-GCM(dek, plaintext)
	Nonce         string `json:"nonce"`          // GCM nonce
	DEKCiphertext string `json:"dek_ciphertext"` // KMS-wrapped DEK (round-trip from /dek)
	DEKKMSKeyID   string `json:"dek_kms_key_id,omitempty"`
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
// encrypts via the KMS layer and persists. An empty value is a valid
// value and is sealed like any other (api#286).
//
// Authorization: AgentAuth confirms the caller is a valid agent; then
// RequestService.CreateAgentWrap requires the read request's job to be
// claimed by THIS agent, key_name to be one of the request's target
// keys, and no earlier wrap for the same key (H4, api#191).
//
// Every refusal of the agent's input is a 4xx whose JSON body carries a
// stable code in `error` and a human message in `message` (see the
// WrapCreateCode* constants). Only a server-side failure is a 500.
func (h *Wraps) Create(c fiber.Ctx) error {
	agentID, ok := middleware.AgentIDFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "agent identity missing in context")
	}
	var body CreateWrapBody
	if err := c.Bind().JSON(&body); err != nil {
		return createRefusal(c, fiber.StatusBadRequest, WrapCreateCodeInvalidJSON, "invalid JSON body")
	}
	if body.RequestID == "" || body.KeyName == "" {
		return createRefusal(c, fiber.StatusBadRequest, WrapCreateCodeMissingField, "request_id, key_name required")
	}
	if (body.Value == nil) == (body.Envelope == nil) {
		return createRefusal(c, fiber.StatusBadRequest, WrapCreateCodeValueOrEnvelope, "exactly one of value or envelope is required")
	}
	if body.Value != nil && !h.allowUnsealed {
		h.requests.AuditUnsealedWrapRefused(c.Context(), "wrap.create", agentID, uuid.Nil, "plaintext_value_refused")
		return createRefusal(c, fiber.StatusBadRequest, WrapCreateCodeEnvelopeRequired,
			"post the value as a wire envelope (POST /dek first); plaintext value is refused")
	}
	reqID, err := uuid.Parse(body.RequestID)
	if err != nil {
		return createRefusal(c, fiber.StatusBadRequest, WrapCreateCodeInvalidRequestID, "invalid request_id UUID")
	}

	var plaintext []byte
	if body.Value != nil {
		// Legacy plaintext-over-TLS path. "" decodes to an empty value.
		plaintext, err = base64.StdEncoding.DecodeString(*body.Value)
		if err != nil {
			return createRefusal(c, fiber.StatusBadRequest, WrapCreateCodeInvalidValue, "value is not valid base64")
		}
	} else {
		// Wire-envelope path: unwrap the agent-supplied DEK envelope.
		var ee *envelopeError
		plaintext, ee = h.unsealAgentEnvelope(c.Context(), body.Envelope)
		if ee != nil {
			if ee.cause != nil {
				logInternalError(c, "wrap envelope rejected", ee.cause)
			}
			return createRefusal(c, fiber.StatusBadRequest, ee.code, "envelope: "+ee.msg)
		}
	}
	defer zero(plaintext)

	// The request must exist, be an approved read request whose job THIS
	// agent has claimed, and name key_name among its target keys; a key
	// lands at most once per request.
	wrap, err := h.requests.CreateAgentWrap(c.Context(), agentID, reqID, body.KeyName, plaintext)
	if err != nil {
		return createWrapErr(c, err)
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

// Stable codes in the `error` field of a refused POST /agents/:id/wraps.
// Agents and operators match on these; the `message` text may change.
const (
	WrapCreateCodeInvalidJSON        = "invalid_json"
	WrapCreateCodeMissingField       = "missing_required_field"
	WrapCreateCodeValueOrEnvelope    = "value_or_envelope_required"
	WrapCreateCodeEnvelopeRequired   = "envelope_required"
	WrapCreateCodeInvalidRequestID   = "invalid_request_id"
	WrapCreateCodeInvalidValue       = "invalid_value_encoding"
	WrapCreateCodeUnsupportedAlg     = "unsupported_envelope_algorithm"
	WrapCreateCodeInvalidEnvelope    = "invalid_envelope"
	WrapCreateCodeDataKeyUndecrypted = "envelope_data_key_undecryptable"
	WrapCreateCodeUnauthenticated    = "envelope_unauthenticated"
	WrapCreateCodeRequestNotFound    = "request_not_found"
	WrapCreateCodeNotReadRequest     = "request_not_read"
	WrapCreateCodeNotApproved        = "request_not_approved"
	WrapCreateCodeJobNotClaimed      = "job_not_claimed"
	WrapCreateCodeKeyNotRequested    = "key_not_requested"
	WrapCreateCodeDuplicateKey       = "duplicate_key"
)

// createRefusal answers a refused wrap create with a stable code and a
// client-safe message.
func createRefusal(c fiber.Ctx, status int, code, msg string) error {
	return c.Status(status).JSON(fiber.Map{"error": code, "message": msg})
}

// createWrapErr maps a RequestService.CreateAgentWrap error to its
// refusal. Anything not listed is a server-side failure and goes to the
// app error handler, which logs it and answers a generic 500.
func createWrapErr(c fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return createRefusal(c, fiber.StatusNotFound, WrapCreateCodeRequestNotFound, "request not found")
	case errors.Is(err, services.ErrWrapCreateNotRead):
		return createRefusal(c, fiber.StatusBadRequest, WrapCreateCodeNotReadRequest, "wrap creation only supported for read requests")
	case errors.Is(err, services.ErrRequestNotApproved):
		return createRefusal(c, fiber.StatusConflict, WrapCreateCodeNotApproved, "owning request is not approved")
	case errors.Is(err, storage.ErrJobNotClaimed):
		return createRefusal(c, fiber.StatusForbidden, WrapCreateCodeJobNotClaimed, "request is not dispatched to this agent")
	case errors.Is(err, services.ErrKeyNotRequested):
		return createRefusal(c, fiber.StatusForbidden, WrapCreateCodeKeyNotRequested, "key_name is not one of the request's target keys")
	case errors.Is(err, storage.ErrDuplicateWrapKey):
		return createRefusal(c, fiber.StatusConflict, WrapCreateCodeDuplicateKey, "a wrap for this key already exists on the request")
	default:
		return err
	}
}

// AES-256-GCM shape of an agent wire envelope (cipher.NewGCM defaults).
const (
	gcmStandardNonceSize = 12
	gcmTagSize           = 16
)

// envelopeError is a wrap-envelope refusal: a stable code, a client-safe
// message and, for KMS or crypto failures, the cause. The cause (a KMS
// backend error carrying the backend URL and key name, or a crypto
// error) is logged server side by the caller and never returned to the
// agent (API-16).
type envelopeError struct {
	code  string
	msg   string
	cause error
}

func (e *envelopeError) Error() string { return e.msg }
func (e *envelopeError) Unwrap() error { return e.cause }

func invalidEnvelope(msg string) *envelopeError {
	return &envelopeError{code: WrapCreateCodeInvalidEnvelope, msg: msg}
}

// unsealAgentEnvelope reverses what the agent did with the DEK that
// /agents/:id/dek issued: KMS-decrypt the DEK ciphertext to recover
// the plaintext data key, then AES-GCM-open the ciphertext.
//
// An empty value is valid: its ciphertext is just the 16-byte GCM tag,
// and it opens to a non-nil empty slice (api#286).
//
// The plaintext DEK is zeroed inside this function; only the unwrapped
// plaintext escapes (and the caller defer-zeroes it).
func (h *Wraps) unsealAgentEnvelope(ctx context.Context, env *CreateWrapEnvelope) ([]byte, *envelopeError) {
	if env.Algorithm != "aes-256-gcm" {
		return nil, &envelopeError{code: WrapCreateCodeUnsupportedAlg, msg: "unsupported algorithm"}
	}
	if env.Ciphertext == "" || env.Nonce == "" || env.DEKCiphertext == "" {
		return nil, invalidEnvelope("ciphertext, nonce, dek_ciphertext required")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, invalidEnvelope("ciphertext is not valid base64")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, invalidEnvelope("nonce is not valid base64")
	}
	dekCt, err := base64.StdEncoding.DecodeString(env.DEKCiphertext)
	if err != nil {
		return nil, invalidEnvelope("dek_ciphertext is not valid base64")
	}
	// API-S-23: gcm.Open panics on a nonce that is not exactly the GCM
	// nonce size. Check the shape before any KMS call and answer with
	// one generic message.
	if len(nonce) != gcmStandardNonceSize || len(ciphertext) < gcmTagSize {
		return nil, invalidEnvelope("invalid envelope")
	}

	dek, err := h.kms.DecryptDataKey(ctx, dekCt, env.DEKKMSKeyID)
	if err != nil {
		return nil, &envelopeError{code: WrapCreateCodeDataKeyUndecrypted, msg: "data key could not be decrypted", cause: err}
	}
	defer zero(dek)
	if len(dek) != 32 {
		return nil, invalidEnvelope("dek is not 32 bytes")
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, &envelopeError{code: WrapCreateCodeUnauthenticated, msg: "ciphertext could not be authenticated", cause: err}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &envelopeError{code: WrapCreateCodeUnauthenticated, msg: "ciphertext could not be authenticated", cause: err}
	}
	if len(nonce) != gcm.NonceSize() || len(ciphertext) < gcm.Overhead() {
		return nil, invalidEnvelope("invalid envelope")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, &envelopeError{code: WrapCreateCodeUnauthenticated, msg: "ciphertext could not be authenticated", cause: err}
	}
	if plaintext == nil {
		plaintext = []byte{}
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
