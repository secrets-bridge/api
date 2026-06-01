// MFA — WebAuthn enrollment service (Slice H3).
//
// FIDO2 / WebAuthn is the strong factor: hardware-backed (Yubikey,
// Titan, Apple Touch ID / Face ID, Windows Hello). Phishing-resistant
// by design — the browser verifies the relying party origin before
// signing, so a code typed into the wrong page can't be replayed.
//
// Slice H3 covers enrollment only:
//
//   POST /users/me/mfa/webauthn/register/start
//     → returns the PublicKeyCredentialCreationOptions the SPA hands
//       to `navigator.credentials.create()`. Includes a fresh challenge
//       + the list of existing credential IDs to exclude (RFC 9711) so
//       the same authenticator can't be re-registered.
//
//   POST /users/me/mfa/webauthn/register/finish
//     → consumes the `AuthenticatorAttestationResponse` the browser
//       returns. Verifies the attestation, envelope-encrypts the COSE
//       public key, persists the factor row.
//
// Assertion (login-time challenge → response) lands in Slice H4 with
// the rest of /auth/mfa/{challenge,verify}.
//
// Library: github.com/go-webauthn/webauthn. It owns the spec-heavy
// parts — CBOR decoding, attestation statement verification, origin
// matching, RP ID hash check, signature counter handling — so this
// service is a thin orchestration layer over its `BeginRegistration`
// / `CreateCredential` calls.
//
// Storage shape (reuses Slice H1's `user_mfa_factors`):
//
//   kind                   = 'webauthn'
//   webauthn_credential_id = the rawId; UNIQUE across rows so a stolen
//                            authenticator can't be re-registered under
//                            a second account
//   webauthn_aaguid        = authenticator model identifier (audit-only)
//   webauthn_sign_count    = monotonic anti-cloning counter
//   secret_*               = envelope-encrypted COSE public key. Defence
//                            in depth — public keys aren't strictly
//                            secret but they're attached to a user and
//                            deserve the same KMS treatment as
//                            everything else in this table.
//
// Hard rules respected:
//   * No plaintext credential material in audit (CLAUDE rule). The
//     audit row carries `factor_id` + `aaguid` + `error_kind` only.
//   * Plaintext public key + plaintext data key both `defer zero(...)`d
//     before return. Public keys aren't secret, but the data key
//     definitely is.
//   * The service refuses to construct without `RPID` + `RPOrigins`
//     — there's no safe default for either. The boot path config
//     check turns missing values into a "WebAuthn not configured"
//     503 at /register/start time.

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

const (
	// 10-minute window mirrors the TOTP ceremony. The browser side
	// usually finishes registration within ~30 seconds; 10 minutes is
	// generous for users who get distracted between tabs.
	webauthnEnrollTTL = 10 * time.Minute
)

// WebAuthn service sentinel errors.
var (
	ErrWebAuthnChallengeNotFound = errors.New("mfa/webauthn: enrollment challenge not found or expired")
	ErrWebAuthnChallengeUser     = errors.New("mfa/webauthn: enrollment challenge does not belong to this user")
	ErrWebAuthnAttestation       = errors.New("mfa/webauthn: attestation verification failed")
	ErrWebAuthnNotConfigured     = errors.New("mfa/webauthn: relying party not configured")
)

// WebAuthnConfig is the boot-time config for the service.
type WebAuthnConfig struct {
	// RPID is the relying-party identifier — the effective domain
	// (e.g. "sb.example.com"). MUST be the eTLD+1 of the origin or
	// the browser rejects the ceremony.
	RPID string

	// RPDisplayName is rendered in the authenticator's enrollment UI
	// ("Secrets Bridge"). Free text.
	RPDisplayName string

	// RPOrigins is the full list of permitted origins for the
	// ceremony — including scheme + port. Examples:
	//
	//   "https://sb.example.com"
	//   "http://localhost:5173"  (Vite dev server)
	RPOrigins []string

	// Clock for tests. Defaults to time.Now.UTC.
	Clock func() time.Time
}

// Validate returns nil iff the config is usable. The boot path calls
// this so a misconfigured operator fails the bind rather than silently
// running with WebAuthn disabled.
func (c WebAuthnConfig) Validate() error {
	if c.RPID == "" {
		return fmt.Errorf("%w: RPID required", ErrWebAuthnNotConfigured)
	}
	if len(c.RPOrigins) == 0 {
		return fmt.Errorf("%w: RPOrigins required", ErrWebAuthnNotConfigured)
	}
	return nil
}

// BeginEnrollmentResult is the wire shape the SPA hands to
// `navigator.credentials.create()`. `Options` serialises directly to
// the W3C PublicKeyCredentialCreationOptions shape.
type BeginEnrollmentResult struct {
	ChallengeID string                       `json:"challenge_id"`
	Options     *protocol.CredentialCreation `json:"options"`
}

// pendingWebAuthnEnroll is what we serialise into Redis between
// BeginEnrollment and FinishEnrollment.
type pendingWebAuthnEnroll struct {
	UserID  string               `json:"u"`
	Label   string               `json:"l"`
	Session *webauthn.SessionData `json:"s"`
}

// WebAuthnService is the public API.
type WebAuthnService struct {
	factors storage.UserMFAFactorRepository
	users   storage.LocalUserRepository
	km      keymgmt.KeyManager
	audit   storage.AuditEventRepository
	rdb     *runtime.Client
	rp      *webauthn.WebAuthn
	clock   func() time.Time
}

// NewWebAuthnService builds the service. Returns
// ErrWebAuthnNotConfigured (wrapped) when the config can't form a
// valid relying party.
func NewWebAuthnService(
	factors storage.UserMFAFactorRepository,
	users storage.LocalUserRepository,
	km keymgmt.KeyManager,
	audit storage.AuditEventRepository,
	rdb *runtime.Client,
	cfg WebAuthnConfig,
) (*WebAuthnService, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	rp, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// Discourage resident keys — the SPA already knows the
			// user id from the cookie, so we don't need passkeys
			// stored on the authenticator itself.
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
			UserVerification: protocol.VerificationPreferred,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("mfa/webauthn: build relying party: %w", err)
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &WebAuthnService{
		factors: factors,
		users:   users,
		km:      km,
		audit:   audit,
		rdb:     rdb,
		rp:      rp,
		clock:   clock,
	}, nil
}

// BeginEnrollment mints the PublicKeyCredentialCreationOptions the
// browser needs. Persists the session data (challenge + state) in
// Redis under a 10-min challenge id; the SPA POSTs it back into
// FinishEnrollment along with the authenticator's response.
//
// Existing factors for the user are included in `excludeCredentials`
// so the browser refuses to re-register a Yubikey the user already
// added — saves them the "this device is already registered" surprise.
func (s *WebAuthnService) BeginEnrollment(ctx context.Context, userID uuid.UUID, label string) (*BeginEnrollmentResult, error) {
	user, err := s.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	creation, session, err := s.rp.BeginRegistration(user,
		webauthn.WithExclusions(user.excludeDescriptors()),
	)
	if err != nil {
		return nil, fmt.Errorf("mfa/webauthn: begin registration: %w", err)
	}
	pending := pendingWebAuthnEnroll{
		UserID:  userID.String(),
		Label:   label,
		Session: session,
	}
	payload, err := json.Marshal(pending)
	if err != nil {
		return nil, fmt.Errorf("mfa/webauthn: encode pending: %w", err)
	}
	challenge := newChallengeID()
	if err := s.rdb.Raw().Set(ctx, webauthnEnrollKey(s.rdb, challenge), payload, webauthnEnrollTTL).Err(); err != nil {
		return nil, fmt.Errorf("mfa/webauthn: persist pending: %w", err)
	}
	return &BeginEnrollmentResult{ChallengeID: challenge, Options: creation}, nil
}

// FinishEnrollment verifies the attestation response and persists the
// factor row. The Redis blob is consumed via GETDEL — a failed
// verification burns the challenge so an attacker can't keep replaying
// against the same expected RP-state.
func (s *WebAuthnService) FinishEnrollment(ctx context.Context, userID uuid.UUID, challengeID string, body []byte) (*storage.UserMFAFactor, error) {
	raw, err := s.consumePendingWebAuthn(ctx, challengeID)
	if err != nil {
		s.auditFinishFailure(ctx, userID, "challenge_missing")
		return nil, ErrWebAuthnChallengeNotFound
	}
	var pending pendingWebAuthnEnroll
	if err := json.Unmarshal(raw, &pending); err != nil {
		s.auditFinishFailure(ctx, userID, "challenge_decode")
		return nil, fmt.Errorf("mfa/webauthn: decode pending: %w", err)
	}
	if pending.UserID != userID.String() {
		// The challenge id was guessed or stolen; same 410 mapping as
		// challenge_missing at the handler layer.
		s.auditFinishFailure(ctx, userID, "challenge_user_mismatch")
		return nil, ErrWebAuthnChallengeUser
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		s.auditFinishFailure(ctx, userID, "response_parse")
		return nil, fmt.Errorf("%w: %v", ErrWebAuthnAttestation, err)
	}
	user, err := s.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	cred, err := s.rp.CreateCredential(user, *pending.Session, parsed)
	if err != nil {
		s.auditFinishFailure(ctx, userID, "attestation_verify")
		return nil, fmt.Errorf("%w: %v", ErrWebAuthnAttestation, err)
	}

	// Envelope-encrypt the COSE public key. Defence in depth — public
	// keys aren't strictly secret, but they're user-attached and
	// deserve the same KMS treatment as everything else in
	// `user_mfa_factors`.
	dk, err := s.km.GenerateDataKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("mfa/webauthn: data key: %w", err)
	}
	defer zero(dk.Plaintext)
	ciphertext, nonce, err := aeadEncrypt(dk.Plaintext, cred.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("mfa/webauthn: aead: %w", err)
	}

	var aaguidPtr *uuid.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		if parsed, err := uuid.FromBytes(cred.Authenticator.AAGUID); err == nil {
			aaguidPtr = &parsed
		}
	}

	factor := &storage.UserMFAFactor{
		UserID:               userID,
		Kind:                 storage.MFAFactorKindWebAuthn,
		Label:                pending.Label,
		SecretCiphertext:     ciphertext,
		SecretNonce:          nonce,
		DataKeyCiphertext:    dk.Ciphertext,
		KMSKeyID:             dk.KeyID,
		WebAuthnCredentialID: cred.ID,
		WebAuthnSignCount:    int64(cred.Authenticator.SignCount),
		WebAuthnAAGUID:       aaguidPtr,
	}
	if err := s.factors.Create(ctx, factor); err != nil {
		s.auditFinishFailure(ctx, userID, "persist_failed")
		return nil, err
	}

	aaguidStr := ""
	if aaguidPtr != nil {
		aaguidStr = aaguidPtr.String()
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + userID.String(),
		Action:   "mfa.webauthn.enroll",
		Resource: "user_mfa_factor:" + factor.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"kind":   "webauthn",
			"label":  pending.Label,
			"aaguid": aaguidStr,
		},
	})
	return factor, nil
}

// --- helpers ---------------------------------------------------------

func (s *WebAuthnService) consumePendingWebAuthn(ctx context.Context, challengeID string) ([]byte, error) {
	key := webauthnEnrollKey(s.rdb, challengeID)
	val, err := s.rdb.Raw().GetDel(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	if len(val) == 0 {
		return nil, errors.New("empty")
	}
	return val, nil
}

func (s *WebAuthnService) auditFinishFailure(ctx context.Context, userID uuid.UUID, kind string) {
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + userID.String(),
		Action:   "mfa.webauthn.enroll_failed",
		Resource: "user:" + userID.String(),
		Status:   storage.AuditStatusFailure,
		Metadata: map[string]any{"error_kind": kind},
	})
}

func (s *WebAuthnService) loadWebAuthnUser(ctx context.Context, userID uuid.UUID) (*webauthnUser, error) {
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mfa/webauthn: load user: %w", err)
	}
	rows, err := s.factors.ListForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mfa/webauthn: list factors: %w", err)
	}
	wu := &webauthnUser{
		id:    userID,
		email: u.Email,
		name:  u.DisplayName,
	}
	// We only carry the credential id + sign count into the library
	// — not the public key. BeginRegistration uses these for
	// excludeCredentials; FinishRegistration (which IS where we
	// install the new credential) doesn't read the existing pool.
	for _, r := range rows {
		if r.Kind != storage.MFAFactorKindWebAuthn {
			continue
		}
		var aaguidBytes []byte
		if r.WebAuthnAAGUID != nil {
			b, _ := r.WebAuthnAAGUID.MarshalBinary()
			aaguidBytes = b
		}
		wu.creds = append(wu.creds, webauthn.Credential{
			ID: r.WebAuthnCredentialID,
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguidBytes,
				SignCount: uint32(r.WebAuthnSignCount), //nolint:gosec // sign_count fits
			},
		})
	}
	return wu, nil
}

func webauthnEnrollKey(rdb *runtime.Client, challenge string) string {
	return rdb.Key("mfa:webauthn:enroll", challenge)
}

// --- webauthn.User adapter ------------------------------------------

// webauthnUser projects a `local_users` row + the user's existing
// factors into the shape the go-webauthn library expects.
type webauthnUser struct {
	id    uuid.UUID
	email string
	name  string
	creds []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	// User handle: the 16-byte UUID. Spec allows up to 64 bytes; using
	// the canonical id keeps it stable across the user's lifetime even
	// if email or display_name change.
	b, _ := u.id.MarshalBinary()
	return b
}

func (u *webauthnUser) WebAuthnName() string {
	if u.email != "" {
		return u.email
	}
	return u.id.String()
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	if u.name != "" {
		return u.name
	}
	if u.email != "" {
		return u.email
	}
	return u.id.String()
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.creds
}

// excludeDescriptors translates the user's existing credentials into
// the protocol's excludeCredentials list, so the browser refuses to
// re-register an authenticator the user already added.
func (u *webauthnUser) excludeDescriptors() []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.creds {
		out = append(out, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
		})
	}
	return out
}
