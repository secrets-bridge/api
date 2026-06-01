// MFA verification orchestration (Slice H4).
//
// Two endpoints sit on top of this service:
//
//   POST /auth/mfa/challenge
//   POST /auth/mfa/verify
//
// They drive the step-up flow: when a Tier-2 op hits the
// RequireFreshMFA gate and returns 401 + WWW-Authenticate: step-up,
// the SPA opens a modal, calls /challenge to get a TOTP ticket or a
// WebAuthn assertion options blob, prompts the user, then calls
// /verify with the response. On success the user's CURRENT session
// gets `last_mfa_at` stamped and the original Tier-2 request can be
// retried.
//
// Why a separate orchestration service rather than calling
// TOTPService / WebAuthnService directly from the handler?
//
//   1. Both kinds funnel into the SAME single audit-event family
//      (`mfa.verify`), the SAME session-stamping behaviour
//      (`SessionService.MarkMFA`), and the SAME 412 "no factors
//      enrolled" surface. Centralising those keeps the contract
//      consistent.
//
//   2. The challenge-id is the only thing the SPA round-trips, but
//      different kinds need different server-side state — TOTP just
//      needs (user, factor) to know which row to verify; WebAuthn
//      needs the library's SessionData. The service owns that
//      asymmetry so the handler doesn't.
//
//   3. Slice H5 (mfa_enrolled flag on /users/me) reads the same
//      "any-factor-enrolled" check this service uses for the 412
//      path. Single source of truth.

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// MFA verification sentinel errors. The HTTP layer maps each.
var (
	// ErrMFANoFactors — user has zero enrolled factors of any kind.
	// Surfaces as 412 mfa_enrollment_required so the SPA can route the
	// user to /me/mfa.
	ErrMFANoFactors = errors.New("mfa/verify: user has no enrolled factors")

	// ErrMFAKindNotEnrolled — user has no factor of the REQUESTED
	// kind (e.g. asked for webauthn but only has TOTP enrolled).
	// Distinct from NoFactors so the SPA can hint "fall back to TOTP"
	// vs "enroll first".
	ErrMFAKindNotEnrolled = errors.New("mfa/verify: user has no enrolled factor of this kind")

	// ErrMFAUnknownKind — body kind field isn't `totp` or `webauthn`.
	ErrMFAUnknownKind = errors.New("mfa/verify: unknown factor kind")

	// ErrMFAChallengeNotFound — Redis blob expired / already consumed.
	ErrMFAChallengeNotFound = errors.New("mfa/verify: challenge not found or expired")

	// ErrMFAChallengeUser — challenge id was issued to a different
	// user. Mapped to the SAME 410 as ChallengeNotFound at the HTTP
	// layer so owner-enumeration is impossible.
	ErrMFAChallengeUser = errors.New("mfa/verify: challenge does not belong to this user")

	// ErrMFAInvalid — code or assertion didn't verify.
	ErrMFAInvalid = errors.New("mfa/verify: code or assertion did not verify")

	// ErrMFASessionRequired — verify was called without a session
	// context (no cookie). Mapped to 401.
	ErrMFASessionRequired = errors.New("mfa/verify: session required")
)

// ChallengeKind discriminates the factor flavour. The wire shape
// uses the lowercase form.
type ChallengeKind string

const (
	ChallengeKindTOTP     ChallengeKind = "totp"
	ChallengeKindWebAuthn ChallengeKind = "webauthn"
)

// ChallengeResult is what BeginChallenge returns. `Options` is nil
// for TOTP (the user types a code from their authenticator app; no
// server-issued nonce is meaningful for a time-based factor). For
// WebAuthn it carries the W3C PublicKeyCredentialRequestOptions.
type ChallengeResult struct {
	ChallengeID string                        `json:"challenge_id"`
	Kind        ChallengeKind                 `json:"kind"`
	Options     *protocol.CredentialAssertion `json:"options,omitempty"`
}

// pendingMFAChallenge is the TOTP-side Redis blob. WebAuthn uses its
// own webauthnService keyspace (mfa:webauthn:assert:<id>) and the
// challengeID round-trips through that side.
type pendingMFAChallenge struct {
	UserID    string `json:"u"`
	SessionID string `json:"s"`
	Kind      string `json:"k"`
}

// MFAVerifyConfig holds runtime knobs. `ChallengeTTL` defaults to 5
// minutes if zero. The user is sitting at the step-up modal with
// their factor already in hand; long TTLs add risk without ergonomic
// payoff.
type MFAVerifyConfig struct {
	ChallengeTTL time.Duration
	Clock        func() time.Time
}

// MFAVerifyService coordinates challenge issuance + verification +
// session stamping across TOTP and WebAuthn.
type MFAVerifyService struct {
	factors  storage.UserMFAFactorRepository
	totp     *TOTPService
	webauthn *WebAuthnService
	sessions *SessionService
	audit    storage.AuditEventRepository
	rdb      *runtime.Client
	ttl      time.Duration
	clock    func() time.Time
}

// NewMFAVerifyService wires the dependencies. `webauthn` may be nil
// when the operator left the WebAuthn knobs unset — BeginChallenge
// for kind=webauthn then returns ErrWebAuthnNotConfigured. `totp` is
// always required.
func NewMFAVerifyService(
	factors storage.UserMFAFactorRepository,
	totp *TOTPService,
	webauthnSvc *WebAuthnService,
	sessions *SessionService,
	audit storage.AuditEventRepository,
	rdb *runtime.Client,
	cfg MFAVerifyConfig,
) *MFAVerifyService {
	ttl := cfg.ChallengeTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &MFAVerifyService{
		factors:  factors,
		totp:     totp,
		webauthn: webauthnSvc,
		sessions: sessions,
		audit:    audit,
		rdb:      rdb,
		ttl:      ttl,
		clock:    clock,
	}
}

// BeginChallenge mints the challenge for the requested kind. Returns
// ErrMFANoFactors when the user has nothing enrolled at all,
// ErrMFAKindNotEnrolled when they have factors but none of the
// requested kind.
func (s *MFAVerifyService) BeginChallenge(ctx context.Context, sessionID, userID uuid.UUID, kind ChallengeKind) (*ChallengeResult, error) {
	switch kind {
	case ChallengeKindTOTP, ChallengeKindWebAuthn:
	default:
		return nil, ErrMFAUnknownKind
	}

	rows, err := s.factors.ListForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mfa/verify: list factors: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrMFANoFactors
	}
	hasKind := false
	for _, f := range rows {
		if string(f.Kind) == string(kind) {
			hasKind = true
			break
		}
	}
	if !hasKind {
		return nil, ErrMFAKindNotEnrolled
	}

	switch kind {
	case ChallengeKindTOTP:
		return s.beginTOTPChallenge(ctx, sessionID, userID)
	case ChallengeKindWebAuthn:
		if s.webauthn == nil {
			return nil, ErrWebAuthnNotConfigured
		}
		out, err := s.webauthn.BeginAssertion(ctx, userID)
		if err != nil {
			return nil, err
		}
		// Pin the session_id into a parallel pending blob so Verify
		// can MarkMFA on the right session even if the cookie rotates
		// mid-challenge. WebAuthn's own pending blob doesn't carry
		// session context.
		if err := s.persistChallengeSessionPin(ctx, out.ChallengeID, userID, sessionID, string(kind)); err != nil {
			return nil, err
		}
		return &ChallengeResult{
			ChallengeID: out.ChallengeID,
			Kind:        ChallengeKindWebAuthn,
			Options:     out.Options,
		}, nil
	}
	// Unreachable — the early kind switch covers everything.
	return nil, ErrMFAUnknownKind
}

func (s *MFAVerifyService) beginTOTPChallenge(ctx context.Context, sessionID, userID uuid.UUID) (*ChallengeResult, error) {
	id := newChallengeID()
	pending := pendingMFAChallenge{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		Kind:      string(ChallengeKindTOTP),
	}
	payload, err := json.Marshal(pending)
	if err != nil {
		return nil, fmt.Errorf("mfa/verify: encode pending: %w", err)
	}
	if err := s.rdb.Raw().Set(ctx, mfaChallengeKey(s.rdb, id), payload, s.ttl).Err(); err != nil {
		return nil, fmt.Errorf("mfa/verify: persist pending: %w", err)
	}
	return &ChallengeResult{ChallengeID: id, Kind: ChallengeKindTOTP}, nil
}

// persistChallengeSessionPin parks a session pin alongside the
// WebAuthn assertion's own pending blob. Same key family as TOTP so
// Verify can look up either kind with one Redis call before
// dispatching. The WebAuthn assertion blob (managed by WebAuthnService)
// stays the source of truth for the actual SessionData.
func (s *MFAVerifyService) persistChallengeSessionPin(ctx context.Context, challengeID string, userID, sessionID uuid.UUID, kind string) error {
	payload, err := json.Marshal(pendingMFAChallenge{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		Kind:      kind,
	})
	if err != nil {
		return fmt.Errorf("mfa/verify: encode session pin: %w", err)
	}
	if err := s.rdb.Raw().Set(ctx, mfaChallengeKey(s.rdb, challengeID), payload, s.ttl).Err(); err != nil {
		return fmt.Errorf("mfa/verify: persist session pin: %w", err)
	}
	return nil
}

// VerifyRequest is the input to Verify. `Code` is the TOTP digits
// (TOTP path); `WebAuthnResponse` is the raw JSON the browser
// returned (WebAuthn path). `FactorID` is required for TOTP — there
// may be multiple TOTP rows and we don't try them all blindly. For
// WebAuthn the library matches via the credential id in the response.
type VerifyRequest struct {
	ChallengeID      string
	FactorID         *uuid.UUID
	Code             string
	WebAuthnResponse json.RawMessage
}

// Verify consumes the challenge, dispatches to the right factor
// verifier, and on success stamps `last_mfa_at` on the user's CURRENT
// session via SessionService.MarkMFA. On failure the challenge is
// already gone (single-shot) — the user must restart at /challenge.
func (s *MFAVerifyService) Verify(ctx context.Context, sessionID, userID uuid.UUID, req VerifyRequest) error {
	if sessionID == uuid.Nil {
		return ErrMFASessionRequired
	}
	if strings.TrimSpace(req.ChallengeID) == "" {
		return ErrMFAChallengeNotFound
	}

	pending, err := s.consumePendingChallenge(ctx, req.ChallengeID)
	if err != nil {
		s.auditVerifyFailure(ctx, userID, "challenge_missing", "")
		return ErrMFAChallengeNotFound
	}
	if pending.UserID != userID.String() {
		s.auditVerifyFailure(ctx, userID, "challenge_user_mismatch", pending.Kind)
		return ErrMFAChallengeUser
	}
	// Pin the session: a Tier-2 op for a rotated session shouldn't
	// stamp a different session's last_mfa_at than the one the user
	// is sitting on. The handler always passes the SAME session id
	// it pulled from the cookie middleware; the in-Redis pin guards
	// against a stale challenge.
	if pending.SessionID != "" && pending.SessionID != sessionID.String() {
		s.auditVerifyFailure(ctx, userID, "challenge_session_mismatch", pending.Kind)
		return ErrMFAChallengeUser
	}

	switch pending.Kind {
	case string(ChallengeKindTOTP):
		if req.FactorID == nil {
			s.auditVerifyFailure(ctx, userID, "factor_id_missing", pending.Kind)
			return ErrMFAInvalid
		}
		// Confirm the factor belongs to the user before passing the
		// code into TOTP.Verify — defence in depth against a hostile
		// caller trying to verify someone else's factor.
		factor, err := s.factors.Get(ctx, *req.FactorID)
		if err != nil || factor.UserID != userID || factor.Kind != storage.MFAFactorKindTOTP {
			s.auditVerifyFailure(ctx, userID, "factor_lookup", pending.Kind)
			return ErrMFAInvalid
		}
		if err := s.totp.Verify(ctx, *req.FactorID, req.Code); err != nil {
			// TOTP.Verify emits its own granular audit; this layer
			// surfaces the generic outcome.
			return ErrMFAInvalid
		}
	case string(ChallengeKindWebAuthn):
		if s.webauthn == nil {
			return ErrWebAuthnNotConfigured
		}
		if len(req.WebAuthnResponse) == 0 {
			s.auditVerifyFailure(ctx, userID, "response_missing", pending.Kind)
			return ErrMFAInvalid
		}
		_, err := s.webauthn.FinishAssertion(ctx, userID, req.ChallengeID, req.WebAuthnResponse)
		if err != nil {
			if errors.Is(err, storage.ErrSignCountRegression) {
				// Clone-detection trip. Revoke every session for the
				// user — the WebAuthn spec's only reliable signal.
				_, revokeErr := s.sessions.RevokeAllForUser(ctx, userID)
				_ = s.audit.Append(ctx, &storage.AuditEvent{
					Actor:    "user:" + userID.String(),
					Action:   "mfa.webauthn.clone_detected",
					Resource: "user:" + userID.String(),
					Status:   storage.AuditStatusFailure,
					Metadata: map[string]any{
						"sessions_revoke_err": errString(revokeErr),
					},
				})
				return ErrMFAInvalid
			}
			return ErrMFAInvalid
		}
	default:
		s.auditVerifyFailure(ctx, userID, "unknown_kind", pending.Kind)
		return ErrMFAUnknownKind
	}

	// Stamp last_mfa_at on the current session. This is the SOLE
	// path that updates `last_mfa_at` post-H4 — the OIDC callback's
	// amr-based stamping is gated off by default (operators flip
	// SB_OIDC_TRUSTED_AMR_MFA=true to opt back in to compatibility
	// behaviour).
	if err := s.sessions.MarkMFA(ctx, sessionID, s.clock()); err != nil {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "user:" + userID.String(),
			Action:   "mfa.verify",
			Resource: "session:" + sessionID.String(),
			Status:   storage.AuditStatusFailure,
			Metadata: map[string]any{
				"error_kind": "mark_mfa_failed",
				"factor":     pending.Kind,
				"error":      err.Error(),
			},
		})
		return fmt.Errorf("mfa/verify: mark mfa: %w", err)
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + userID.String(),
		Action:   "mfa.verify",
		Resource: "session:" + sessionID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"factor": pending.Kind},
	})
	return nil
}

// AnyEnrolled returns true when the user has at least one factor.
// Drives the /users/me mfa_enrolled flag (Slice H5) — single source
// of truth so the SPA + this service don't diverge.
func (s *MFAVerifyService) AnyEnrolled(ctx context.Context, userID uuid.UUID) (bool, error) {
	n, err := s.factors.CountForUser(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("mfa/verify: count factors: %w", err)
	}
	return n > 0, nil
}

func (s *MFAVerifyService) consumePendingChallenge(ctx context.Context, challengeID string) (*pendingMFAChallenge, error) {
	key := mfaChallengeKey(s.rdb, challengeID)
	val, err := s.rdb.Raw().GetDel(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	if len(val) == 0 {
		return nil, errors.New("empty")
	}
	var pending pendingMFAChallenge
	if err := json.Unmarshal(val, &pending); err != nil {
		return nil, err
	}
	return &pending, nil
}

func (s *MFAVerifyService) auditVerifyFailure(ctx context.Context, userID uuid.UUID, kind, factor string) {
	meta := map[string]any{"error_kind": kind}
	if factor != "" {
		meta["factor"] = factor
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + userID.String(),
		Action:   "mfa.verify",
		Resource: "user:" + userID.String(),
		Status:   storage.AuditStatusFailure,
		Metadata: meta,
	})
}

func mfaChallengeKey(rdb *runtime.Client, id string) string {
	return rdb.Key("mfa:verify:challenge", id)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
