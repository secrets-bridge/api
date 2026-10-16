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
	return s.wrapWith(ctx, req, s.wraps.Create)
}

// WrapForClaimedJob is the agent-side create behind POST
// /agents/:id/wraps (H4). Same envelope encryption as Wrap, but the row
// is stored through storage.CreateForClaimedJob: only while jobID (the
// request's read job) is claimed by agentID, and only if the request has
// no wrap for this key yet. Returns storage.ErrJobNotClaimed or
// storage.ErrDuplicateWrapKey.
func (s *WrapService) WrapForClaimedJob(ctx context.Context, agentID, jobID uuid.UUID, req WrapRequest) (*storage.SecretWrap, error) {
	if req.Actor == "" {
		req.Actor = "agent:" + agentID.String()
	}
	return s.wrapWith(ctx, req, func(ctx context.Context, w *storage.SecretWrap) error {
		return s.wraps.CreateForClaimedJob(ctx, w, jobID, agentID, storage.JobTypeRead)
	})
}

// AgentHoldsJob reports whether jobID is requestID's job of jobType and
// is claimed by agentID right now. A cheap pre-check so callers can
// refuse a non-owner before any other validation; the create / consume
// paths re-check atomically.
func (s *WrapService) AgentHoldsJob(ctx context.Context, jobID, requestID, agentID uuid.UUID, jobType storage.JobType) (bool, error) {
	return s.wraps.JobClaimedBy(ctx, jobID, requestID, agentID, jobType)
}

func (s *WrapService) wrapWith(ctx context.Context, req WrapRequest, store func(context.Context, *storage.SecretWrap) error) (*storage.SecretWrap, error) {
	w, err := s.Seal(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := store(ctx, w); err != nil {
		return nil, fmt.Errorf("wraps: store: %w", err)
	}

	// Zero the caller's plaintext to shrink the in-memory window.
	zero(req.Plaintext)

	s.RecordCreated(ctx, w, req.Actor, req.TTL)
	return w, nil
}

// Seal envelope-encrypts req.Plaintext into a wrap row WITHOUT storing
// it or auditing. It is for callers that must insert the row inside
// their own transaction (cross-team Fill writes the wraps and the
// status change together, so a fill that loses a race leaves nothing
// behind). Once the row is committed the caller emits RecordCreated.
// Seal does not zero req.Plaintext; the caller does.
func (s *WrapService) Seal(ctx context.Context, req WrapRequest) (*storage.SecretWrap, error) {
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
	return &storage.SecretWrap{
		RequestID:         req.RequestID,
		KeyName:           req.KeyName,
		EncryptedValue:    encrypted,
		Nonce:             nonce,
		DataKeyCiphertext: dk.Ciphertext,
		KMSKeyID:          dk.KeyID,
		Algorithm:         "AES-256-GCM",
		ContentHash:       contentHash[:],
		ByteLength:        len(req.Plaintext),
		ExpiresAt:         s.now().Add(req.TTL).UTC(),
	}, nil
}

// RecordCreated emits the wrap.create audit event for a stored wrap.
// Metadata only: byte length, content hash, KMS key id, TTL.
func (s *WrapService) RecordCreated(ctx context.Context, w *storage.SecretWrap, actor string, ttl time.Duration) {
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         nonEmpty(actor, "user"),
		Action:        "wrap.create",
		Resource:      "wrap:" + w.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: wrapCorrelation(w.RequestID),
		Metadata: map[string]any{
			"byte_length":  w.ByteLength,
			"content_hash": fmt.Sprintf("%x", w.ContentHash),
			"kms_key_id":   w.KMSKeyID,
			"ttl_seconds":  int64(ttl.Seconds()),
		},
	})
}

// Retrieve unwraps a stored value. The plaintext is returned to the
// caller as bytes; the caller (typically the agent-wrap-retrieval
// HTTP handler) is responsible for streaming it out and zeroing
// promptly. MarkConsumed is called inside the same transaction-ish
// sequence so the wrap can never be retrieved twice.
func (s *WrapService) Retrieve(ctx context.Context, id, agentID uuid.UUID) ([]byte, *storage.SecretWrap, error) {
	return s.retrieveAsAgent(ctx, id, agentID, func(at time.Time) error {
		return s.wraps.MarkConsumed(ctx, id, agentID, at)
	})
}

// RetrieveForAgentJob is the agent fetch behind GET
// /agents/:id/wraps/:wrap_id (H4): the single-shot consume only succeeds
// while jobID, the wrap's request (patch) job, is claimed by agentID.
// A refusal (storage.ErrJobNotClaimed) does not burn the wrap.
func (s *WrapService) RetrieveForAgentJob(ctx context.Context, id, agentID, jobID uuid.UUID) ([]byte, *storage.SecretWrap, error) {
	return s.retrieveAsAgent(ctx, id, agentID, func(at time.Time) error {
		return s.wraps.MarkConsumedForJob(ctx, id, agentID, jobID, storage.JobTypePatch, at)
	})
}

func (s *WrapService) retrieveAsAgent(ctx context.Context, id, agentID uuid.UUID, consume func(time.Time) error) ([]byte, *storage.SecretWrap, error) {
	// Read before consuming: the consume clears the ciphertext columns.
	w, err := s.wraps.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if err := consume(s.now().UTC()); err != nil {
		s.auditRetrieveOutcome(ctx, agentID, id, wrapCorrelation(w.RequestID), err)
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
		Actor:         "agent:" + agentID.String(),
		Action:        "wrap.retrieve",
		Resource:      "wrap:" + id.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: wrapCorrelation(w.RequestID),
	})
	return plaintext, w, nil
}

// RetrieveByUser is the user-facing counterpart of Retrieve. Same
// atomic single-shot consume + KMS decrypt, but the consumer is a
// user (named via userID) rather than an agent. Used by the read
// flow's user-bound retrieval endpoint.
func (s *WrapService) RetrieveByUser(ctx context.Context, id uuid.UUID, userID string) ([]byte, *storage.SecretWrap, error) {
	// Read before consuming: the consume clears the ciphertext columns.
	w, err := s.wraps.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if err := s.wraps.MarkConsumedByUser(ctx, id, userID, s.now().UTC()); err != nil {
		s.auditRetrieveOutcomeUser(ctx, userID, id, wrapCorrelation(w.RequestID), err)
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
		Actor:         "user:" + userID,
		Action:        "wrap.retrieve",
		Resource:      "wrap:" + id.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: wrapCorrelation(w.RequestID),
	})
	return plaintext, w, nil
}

func (s *WrapService) auditRetrieveOutcomeUser(ctx context.Context, userID string, wrapID, corr uuid.UUID, err error) {
	status := storage.AuditStatusDenied
	kind := "other"
	switch {
	case errors.Is(err, storage.ErrAlreadyConsumed):
		kind = "already_consumed"
	case errors.Is(err, storage.ErrExpired):
		kind = "expired"
	case errors.Is(err, storage.ErrNotFound):
		kind = "not_found"
	default:
		status = storage.AuditStatusFailure
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + userID,
		Action:        "wrap.retrieve",
		Resource:      "wrap:" + wrapID.String(),
		Status:        status,
		CorrelationID: corr,
		Metadata:      map[string]any{"error_kind": kind},
	})
}

// Refresh caps the wrap's remaining lifetime at newTTL from now. It can
// only shorten: storage keeps LEAST(expires_at, now+newTTL), so a
// transition never revives an expired wrap or stretches a live one.
// Called by the workflow engine on state transitions.
func (s *WrapService) Refresh(ctx context.Context, id uuid.UUID, newTTL time.Duration) error {
	if newTTL <= 0 {
		return errors.New("wraps: newTTL must be positive")
	}
	return s.wraps.SetExpiry(ctx, id, s.now().Add(newTTL).UTC())
}

// Expire shoves the wrap's expires_at to "now" so any further retrieve
// returns ErrExpired. Used by reveal-session expiry (Slice M2) to
// close the window the moment the SPA stops needing the value — the
// underlying wrap row stays for the audit trail and the M3 sweeper.
func (s *WrapService) Expire(ctx context.Context, id uuid.UUID) error {
	return s.wraps.SetExpiry(ctx, id, s.now().UTC())
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

// WrapByAgent is the read-flow counterpart of the original Wrap, with
// the agent ID as the audit Actor. It does NOT check job ownership, the
// key allowlist or duplicates: the HTTP endpoint goes through
// RequestService.CreateAgentWrap → WrapForClaimedJob instead. Kept as a
// primitive for seeding agent-produced wraps in tests.
//
// Caller is responsible for zeroing the plaintext slice — Wrap zeros
// it internally on success, but on error the caller may want a chance
// to log byte_length / hash before discarding.
func (s *WrapService) WrapByAgent(ctx context.Context, agentID uuid.UUID, req WrapRequest) (*storage.SecretWrap, error) {
	if req.Actor == "" {
		req.Actor = "agent:" + agentID.String()
	}
	return s.Wrap(ctx, req)
}

func (s *WrapService) auditRetrieveOutcome(ctx context.Context, agentID, wrapID, corr uuid.UUID, err error) {
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
	case errors.Is(err, storage.ErrJobNotClaimed):
		kind = "job_not_claimed"
	default:
		status = storage.AuditStatusFailure
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "agent:" + agentID.String(),
		Action:        "wrap.retrieve",
		Resource:      "wrap:" + wrapID.String(),
		Status:        status,
		CorrelationID: corr,
		Metadata:      map[string]any{"error_kind": kind},
	})
}

// wrapCorrelation ties a wrap's audit rows to its access request, whose
// id is the request's correlation id (request.submit / approve / job.*).
// A wrap with no request gets uuid.Nil, and storage assigns a fresh one.
func wrapCorrelation(requestID *uuid.UUID) uuid.UUID {
	if requestID == nil {
		return uuid.Nil
	}
	return *requestID
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
	// gcm.Open panics on a wrong-size nonce. A consumed wrap's cleared
	// row (API-S-24) or a damaged row must fail, not crash the request.
	if len(nonce) != gcm.NonceSize() || len(ciphertext) < gcm.Overhead() {
		return nil, errors.New("wraps: stored ciphertext is malformed")
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
