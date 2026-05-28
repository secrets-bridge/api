package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

// WrapService is the envelope-encryption layer over the wraps
// repository + KMS. The plaintext lives in CP API process memory ONLY
// inside Wrap() and Retrieve(); the storage layer never sees it.
type WrapService struct {
	wraps storage.SecretWrapRepository
	audit storage.AuditEventRepository
	kms   keymgmt.KeyManager
	now   func() time.Time
}

// NewWrapService binds a WrapService to its dependencies.
func NewWrapService(wraps storage.SecretWrapRepository, audit storage.AuditEventRepository, km keymgmt.KeyManager) *WrapService {
	return &WrapService{
		wraps: wraps,
		audit: audit,
		kms:   km,
		now:   time.Now,
	}
}

// WrapRequest captures everything Wrap needs.
type WrapRequest struct {
	// Plaintext is the value to encrypt. The service zeroes this slice
	// after a successful wrap; callers MUST NOT reuse it.
	Plaintext []byte

	// RequestID ties the wrap to an access_request row. Optional in
	// this PR (the workflow PR makes it required at the service
	// layer).
	RequestID *uuid.UUID

	// KeyName is the key the value will be written under in the
	// provider's secret bundle (e.g. "DB_PASSWORD"). The agent reads
	// it back when retrieving the wrap so it knows which key to PUT.
	// Optional — leaving it empty is fine for single-value flows.
	KeyName string

	// TTL determines expires_at. Workflow engine picks the value based
	// on policy (default 7 days, refreshed on state transitions).
	TTL time.Duration

	// Actor is for audit. Comes from the request's authn principal.
	Actor string
}

// Wrap encrypts plaintext via envelope encryption and stores the row.
// On success, plaintext is zeroed in place — callers must not reuse it.
func (s *WrapService) Wrap(ctx context.Context, req WrapRequest) (*storage.SecretWrap, error) {
	if len(req.Plaintext) == 0 {
		return nil, errors.New("wraps: plaintext is empty")
	}
	if req.TTL <= 0 {
		return nil, errors.New("wraps: TTL must be positive")
	}

	dk, err := s.kms.GenerateDataKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("wraps: generate data key: %w", err)
	}
	// Best-effort zero the data key plaintext at the end of this call.
	defer zero(dk.Plaintext)

	encrypted, nonce, err := aeadEncrypt(dk.Plaintext, req.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("wraps: encrypt: %w", err)
	}

	contentHash := sha256.Sum256(req.Plaintext)
	byteLen := len(req.Plaintext)

	w := &storage.SecretWrap{
		RequestID:         req.RequestID,
		KeyName:           req.KeyName,
		EncryptedValue:    encrypted,
		Nonce:             nonce,
		DataKeyCiphertext: dk.Ciphertext,
		KMSKeyID:          dk.KeyID,
		Algorithm:         "AES-256-GCM",
		ContentHash:       contentHash[:],
		ByteLength:        byteLen,
		ExpiresAt:         s.now().Add(req.TTL).UTC(),
	}
	if err := s.wraps.Create(ctx, w); err != nil {
		return nil, fmt.Errorf("wraps: store: %w", err)
	}

	// Zero the caller's plaintext to shrink the in-memory window.
	zero(req.Plaintext)

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    nonEmpty(req.Actor, "user"),
		Action:   "wrap.create",
		Resource: "wrap:" + w.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"byte_length":  byteLen,
			"content_hash": fmt.Sprintf("%x", contentHash[:]),
			"kms_key_id":   dk.KeyID,
			"ttl_seconds":  int64(req.TTL.Seconds()),
		},
	})
	return w, nil
}

// Retrieve unwraps a stored value. The plaintext is returned to the
// caller as bytes; the caller (typically the agent-wrap-retrieval
// HTTP handler) is responsible for streaming it out and zeroing
// promptly. MarkConsumed is called inside the same transaction-ish
// sequence so the wrap can never be retrieved twice.
func (s *WrapService) Retrieve(ctx context.Context, id, agentID uuid.UUID) ([]byte, *storage.SecretWrap, error) {
	w, err := s.wraps.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if err := s.wraps.MarkConsumed(ctx, id, agentID, s.now().UTC()); err != nil {
		s.auditRetrieveOutcome(ctx, agentID, id, err)
		return nil, nil, err
	}

	dataKey, err := s.kms.DecryptDataKey(ctx, w.DataKeyCiphertext, w.KMSKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("wraps: decrypt data key: %w", err)
	}
	defer zero(dataKey)

	plaintext, err := aeadDecrypt(dataKey, w.Nonce, w.EncryptedValue)
	if err != nil {
		return nil, nil, fmt.Errorf("wraps: decrypt value: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:" + agentID.String(),
		Action:   "wrap.retrieve",
		Resource: "wrap:" + id.String(),
		Status:   storage.AuditStatusSuccess,
	})
	return plaintext, w, nil
}

// Refresh shortens (or extends) the wrap's TTL. Called by the workflow
// engine on state transitions.
func (s *WrapService) Refresh(ctx context.Context, id uuid.UUID, newTTL time.Duration) error {
	if newTTL <= 0 {
		return errors.New("wraps: newTTL must be positive")
	}
	return s.wraps.SetExpiry(ctx, id, s.now().Add(newTTL).UTC())
}

// ListIDsForRequest exposes the storage-layer enumeration so the
// RequestService can bulk-refresh TTLs without reaching past the
// service-layer boundary.
func (s *WrapService) ListIDsForRequest(ctx context.Context, requestID uuid.UUID) ([]uuid.UUID, error) {
	return s.wraps.ListIDsForRequest(ctx, requestID)
}

// ListSummariesForRequest returns value-free summaries of every wrap
// tied to a request. Safe to expose to the UI / agent — no ciphertext,
// no plaintext, just IDs and key names.
func (s *WrapService) ListSummariesForRequest(ctx context.Context, requestID uuid.UUID) ([]storage.WrapSummary, error) {
	return s.wraps.ListSummariesForRequest(ctx, requestID)
}

// Peek returns the wrap row WITHOUT consuming it. The returned struct
// carries ciphertext fields too — callers must NOT log it. Intended
// for orchestration code (e.g. RequestService) that needs to inspect
// request_id / key_name before deciding whether to call Retrieve.
func (s *WrapService) Peek(ctx context.Context, id uuid.UUID) (*storage.SecretWrap, error) {
	return s.wraps.Get(ctx, id)
}

func (s *WrapService) auditRetrieveOutcome(ctx context.Context, agentID, wrapID uuid.UUID, err error) {
	status := storage.AuditStatusDenied
	kind := "other"
	switch {
	case errors.Is(err, storage.ErrAlreadyConsumed):
		kind = "already_consumed"
	case errors.Is(err, storage.ErrExpired):
		kind = "expired"
	case errors.Is(err, storage.ErrNotFound):
		kind = "not_found"
		status = storage.AuditStatusDenied
	default:
		status = storage.AuditStatusFailure
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:" + agentID.String(),
		Action:   "wrap.retrieve",
		Resource: "wrap:" + wrapID.String(),
		Status:   status,
		Metadata: map[string]any{"error_kind": kind},
	})
}

// aeadEncrypt does AES-256-GCM with a fresh nonce. Returns the
// ciphertext and the nonce separately so the storage layer can
// persist them in named columns (rather than packing).
func aeadEncrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func aeadDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// zero overwrites b in place. Best-effort: Go's compiler can elide
// stores it can prove the result is unreachable. Reasonable defense
// against casual heap inspection; not bulletproof.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func nonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
