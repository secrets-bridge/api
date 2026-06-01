// MFA — TOTP enrollment service (Slice H2).
//
// App-level Time-based One-Time Password (RFC 6238) is the universal
// fallback factor — every authenticator app (Google Authenticator,
// Authy, 1Password, Bitwarden) and YubiKey can mint TOTP codes.
// WebAuthn is the strong path; TOTP is the "no hardware token" fallback.
//
// Enrollment is a two-step ceremony, modelled on Stripe / GitHub / AWS
// Console / Plaid:
//
//  1. POST /users/me/mfa/totp/enroll → returns a fresh secret + an
//     `otpauth://` provisioning URI. The secret is envelope-encrypted
//     and persisted in Redis under a per-challenge key with 10-min
//     TTL. Nothing lands in Postgres yet.
//
//  2. POST /users/me/mfa/totp/confirm → user types a 6-digit code from
//     their authenticator app. Service unwraps the pending blob,
//     verifies the code against the stored secret (RFC 6238 default
//     30s window + ±1 step skew tolerance), and only then persists the
//     factor row via `user_mfa_factors`.
//
// The two-step shape prevents the user from accidentally enrolling and
// getting locked out without verifying their device actually works.
// Stripe / GitHub / AWS Console all require code confirmation before
// the factor "counts".
//
// Verification (Verify) is what Slice H4's /auth/mfa/verify calls into
// for step-up. Same code path as confirmation: decrypt the row's
// envelope blob, compute the current step's expected codes (±1 for
// skew), compare. TouchLastUsed stamps the row on success.
//
// Hard rules respected:
//   * Plaintext shared secret lives in process memory ONLY for the
//     duration of the encrypt/decrypt call. `defer zero(...)` overwrites
//     it before return.
//   * No plaintext code, secret, or counter ever lands in audit metadata
//     (CLAUDE rule). The audit row carries `factor_id` + `kind` only.
//   * Storage layer is dumb byte handling — this service owns the
//     envelope encryption (same posture as wraps.go).
//   * Wrong codes deplete the per-challenge / per-factor budget so an
//     attacker can't brute-force the 6-digit space; rate limit is the
//     existing `/auth/oidc/start`-shaped per-IP bucket plus a per-actor
//     bucket the handler layer applies.

package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA1 for TOTP interop
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// TOTP RFC 6238 defaults. Hard-coded — these are also the values the
// otpauth:// URI carries, and every authenticator app on the market
// assumes them. Changing any of these silently breaks every previously
// enrolled factor.
const (
	totpDigits     = 6
	totpStepSecs   = 30
	totpSecretSize = 20 // 160 bits; RFC 6238 §5.1 minimum

	// Skew window: ±1 step (RFC 6238 §5.2 recommendation). The user's
	// authenticator clock can be 30s ahead or behind the server's
	// without breaking verification.
	totpSkewSteps = 1

	// Per-enroll challenge stays in Redis for 10 minutes. Beyond that
	// the user should restart the enrollment ceremony — the secret
	// printed in the QR code is no longer cached.
	totpEnrollTTL = 10 * time.Minute
)

// TOTP service sentinel errors. The HTTP layer maps each to a status
// code; the operator-facing audit emits the constant name so triage
// against the audit log is unambiguous.
var (
	ErrTOTPChallengeNotFound = errors.New("mfa/totp: enrollment challenge not found or expired")
	ErrTOTPChallengeUser     = errors.New("mfa/totp: enrollment challenge does not belong to this user")
	ErrTOTPInvalidCode       = errors.New("mfa/totp: invalid code")
	ErrTOTPFactorNotFound    = errors.New("mfa/totp: factor not found")
	ErrTOTPFactorWrongKind   = errors.New("mfa/totp: factor is not a TOTP factor")
)

// TOTPEnrollChallenge is the wire shape returned to the SPA after a
// successful Enroll call. The SPA renders SecretBase32 + ProvisioningURI
// (as a QR code) and asks the user to type the 6-digit code their
// authenticator produces, which it POSTs to /confirm along with the
// ChallengeID.
type TOTPEnrollChallenge struct {
	ChallengeID      string
	SecretBase32     string
	ProvisioningURI  string
	// ExpiresAt mirrors the Redis TTL so the SPA can show "Restart
	// enrollment" once the cached secret is gone.
	ExpiresAt time.Time
}

// pendingTOTPEnroll is what we serialise into Redis between Enroll
// and ConfirmEnroll. The factor secret stays envelope-encrypted at
// rest in Redis the SAME way it will land in Postgres on confirm —
// no plaintext in Redis even for the 10-min pending window.
type pendingTOTPEnroll struct {
	UserID            string `json:"u"`
	Label             string `json:"l"`
	SecretCiphertext  []byte `json:"sc"`
	SecretNonce       []byte `json:"sn"`
	DataKeyCiphertext []byte `json:"dk"`
	KMSKeyID          string `json:"k"`
}

// TOTPConfig is the boot-time configuration for the service. Issuer
// is what authenticator apps display under the account name; keep it
// stable across deployments or users see two entries for the same
// account.
type TOTPConfig struct {
	// Issuer rendered in the otpauth:// URI's `issuer=` param + the
	// label prefix. Default "Secrets Bridge". Must not contain a
	// colon — the otpauth label uses ':' as the issuer/account
	// separator.
	Issuer string

	// Clock is the time source. Optional — defaults to time.Now.UTC.
	// Tests inject a frozen clock so the 30s window is deterministic.
	Clock func() time.Time
}

// TOTPService is the public API.
type TOTPService struct {
	factors storage.UserMFAFactorRepository
	km      keymgmt.KeyManager
	audit   storage.AuditEventRepository
	rdb     *runtime.Client
	issuer  string
	clock   func() time.Time
}

// NewTOTPService wires the dependencies.
func NewTOTPService(
	factors storage.UserMFAFactorRepository,
	km keymgmt.KeyManager,
	audit storage.AuditEventRepository,
	rdb *runtime.Client,
	cfg TOTPConfig,
) *TOTPService {
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		issuer = "Secrets Bridge"
	}
	return &TOTPService{
		factors: factors,
		km:      km,
		audit:   audit,
		rdb:     rdb,
		issuer:  issuer,
		clock:   clock,
	}
}

// Enroll generates a fresh TOTP secret, envelope-encrypts it, parks
// the encrypted blob in Redis under a 10-min challenge id, and returns
// the otpauth:// URI + base32 secret so the SPA can render a QR code.
//
// Nothing lands in Postgres yet — the user must POST /confirm with a
// valid code first.
//
// `accountName` is what shows up in the authenticator app under the
// issuer (typically the user's email). Empty falls back to the
// user_id so the app still distinguishes multiple accounts on the
// same device.
func (s *TOTPService) Enroll(ctx context.Context, userID uuid.UUID, label, accountName string) (*TOTPEnrollChallenge, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return nil, fmt.Errorf("mfa/totp: label required")
	}

	// Generate the 20-byte shared secret. crypto/rand is the right
	// source — the secret is the entire security of the factor.
	secret := make([]byte, totpSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("mfa/totp: random: %w", err)
	}
	defer zero(secret)

	dk, err := s.km.GenerateDataKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("mfa/totp: data key: %w", err)
	}
	defer zero(dk.Plaintext)

	ciphertext, nonce, err := aeadEncrypt(dk.Plaintext, secret)
	if err != nil {
		return nil, fmt.Errorf("mfa/totp: aead: %w", err)
	}

	challenge := newChallengeID()
	pending := pendingTOTPEnroll{
		UserID:            userID.String(),
		Label:             label,
		SecretCiphertext:  ciphertext,
		SecretNonce:       nonce,
		DataKeyCiphertext: dk.Ciphertext,
		KMSKeyID:          dk.KeyID,
	}
	payload, err := json.Marshal(pending)
	if err != nil {
		return nil, fmt.Errorf("mfa/totp: encode pending: %w", err)
	}
	if err := s.rdb.Raw().Set(ctx, totpEnrollKey(s.rdb, challenge), payload, totpEnrollTTL).Err(); err != nil {
		return nil, fmt.Errorf("mfa/totp: persist pending: %w", err)
	}

	secretB32 := strings.TrimRight(base32.StdEncoding.EncodeToString(secret), "=")
	if accountName == "" {
		accountName = userID.String()
	}
	return &TOTPEnrollChallenge{
		ChallengeID:     challenge,
		SecretBase32:    secretB32,
		ProvisioningURI: s.buildProvisioningURI(accountName, secretB32),
		ExpiresAt:       s.clock().Add(totpEnrollTTL),
	}, nil
}

// ConfirmEnroll verifies the user's 6-digit code against the pending
// challenge and, on success, persists the factor row.
//
// The Redis blob is consumed via GETDEL — a wrong code burns the
// challenge so the attacker can't keep guessing against the same
// secret. The user restarts enrollment.
func (s *TOTPService) ConfirmEnroll(ctx context.Context, userID uuid.UUID, challengeID, code string) (*storage.UserMFAFactor, error) {
	raw, err := s.consumePendingTOTP(ctx, challengeID)
	if err != nil {
		s.auditConfirmFailure(ctx, userID, "challenge_missing")
		return nil, ErrTOTPChallengeNotFound
	}
	var pending pendingTOTPEnroll
	if err := json.Unmarshal(raw, &pending); err != nil {
		s.auditConfirmFailure(ctx, userID, "challenge_decode")
		return nil, fmt.Errorf("mfa/totp: decode pending: %w", err)
	}
	if pending.UserID != userID.String() {
		// The challenge id was guessed or stolen; user mismatch is
		// auditable. The Redis row is already gone (GETDEL).
		s.auditConfirmFailure(ctx, userID, "challenge_user_mismatch")
		return nil, ErrTOTPChallengeUser
	}

	plaintext, err := s.decryptSecret(ctx, pending.SecretCiphertext, pending.SecretNonce, pending.DataKeyCiphertext, pending.KMSKeyID)
	if err != nil {
		s.auditConfirmFailure(ctx, userID, "kms_unwrap")
		return nil, err
	}
	defer zero(plaintext)

	if !verifyTOTP(plaintext, code, s.clock(), totpSkewSteps) {
		s.auditConfirmFailure(ctx, userID, "code_invalid")
		return nil, ErrTOTPInvalidCode
	}

	factor := &storage.UserMFAFactor{
		UserID:            userID,
		Kind:              storage.MFAFactorKindTOTP,
		Label:             pending.Label,
		SecretCiphertext:  pending.SecretCiphertext,
		SecretNonce:       pending.SecretNonce,
		DataKeyCiphertext: pending.DataKeyCiphertext,
		KMSKeyID:          pending.KMSKeyID,
	}
	if err := s.factors.Create(ctx, factor); err != nil {
		// Surface the label-collision specifically — the UI shows
		// "this name is already used".
		s.auditConfirmFailure(ctx, userID, "persist_failed")
		return nil, err
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + userID.String(),
		Action:   "mfa.totp.enroll",
		Resource: "user_mfa_factor:" + factor.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"kind": "totp", "label": pending.Label},
	})
	return factor, nil
}

// Verify checks a 6-digit code against a persisted TOTP factor. On
// success TouchLastUsed stamps the row so the user can see "Last used"
// in the enrollment UI + the audit row records the verification.
//
// Slice H4's /auth/mfa/verify is the primary caller. Verify does NOT
// stamp `last_mfa_at` on any session — that's the session service's
// job once H4 is in.
func (s *TOTPService) Verify(ctx context.Context, factorID uuid.UUID, code string) error {
	factor, err := s.factors.Get(ctx, factorID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrTOTPFactorNotFound
		}
		return err
	}
	if factor.Kind != storage.MFAFactorKindTOTP {
		return ErrTOTPFactorWrongKind
	}
	plaintext, err := s.decryptSecret(ctx, factor.SecretCiphertext, factor.SecretNonce, factor.DataKeyCiphertext, factor.KMSKeyID)
	if err != nil {
		return err
	}
	defer zero(plaintext)
	if !verifyTOTP(plaintext, code, s.clock(), totpSkewSteps) {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "user:" + factor.UserID.String(),
			Action:   "mfa.totp.verify",
			Resource: "user_mfa_factor:" + factorID.String(),
			Status:   storage.AuditStatusFailure,
			Metadata: map[string]any{"error_kind": "code_invalid"},
		})
		return ErrTOTPInvalidCode
	}
	if err := s.factors.TouchLastUsed(ctx, factorID, s.clock()); err != nil {
		// Verification succeeded; failing to update last_used_at
		// shouldn't block the user. Audit it as a soft warning.
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "user:" + factor.UserID.String(),
			Action:   "mfa.totp.touch_last_used_failed",
			Resource: "user_mfa_factor:" + factorID.String(),
			Status:   storage.AuditStatusFailure,
			Metadata: map[string]any{"error": err.Error()},
		})
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + factor.UserID.String(),
		Action:   "mfa.totp.verify",
		Resource: "user_mfa_factor:" + factorID.String(),
		Status:   storage.AuditStatusSuccess,
	})
	return nil
}

// --- helpers ---------------------------------------------------------

func (s *TOTPService) decryptSecret(ctx context.Context, ciphertext, nonce, dataKeyCt []byte, keyID string) ([]byte, error) {
	dataKey, err := s.km.DecryptDataKey(ctx, dataKeyCt, keyID)
	if err != nil {
		return nil, fmt.Errorf("mfa/totp: unwrap dk: %w", err)
	}
	defer zero(dataKey)
	plaintext, err := aeadDecrypt(dataKey, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("mfa/totp: aead open: %w", err)
	}
	return plaintext, nil
}

func (s *TOTPService) buildProvisioningURI(accountName, secretB32 string) string {
	// otpauth://totp/<Issuer>:<Account>?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
	// The label spec wants `Issuer:Account` with both URL-encoded.
	label := s.issuer + ":" + accountName
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", s.issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpStepSecs))
	u := &url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + label,
		RawQuery: q.Encode(),
	}
	return u.String()
}

func (s *TOTPService) consumePendingTOTP(ctx context.Context, challengeID string) ([]byte, error) {
	key := totpEnrollKey(s.rdb, challengeID)
	val, err := s.rdb.Raw().GetDel(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	if len(val) == 0 {
		return nil, errors.New("empty")
	}
	return val, nil
}

func (s *TOTPService) auditConfirmFailure(ctx context.Context, userID uuid.UUID, kind string) {
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + userID.String(),
		Action:   "mfa.totp.enroll_failed",
		Resource: "user:" + userID.String(),
		Status:   storage.AuditStatusFailure,
		Metadata: map[string]any{"error_kind": kind},
	})
}

func totpEnrollKey(rdb *runtime.Client, challenge string) string {
	return rdb.Key("mfa:totp:enroll", challenge)
}

func newChallengeID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	// uuid.UUID accepts any 16-byte array; we don't need the v4
	// version bits because the challenge id is opaque to clients.
	return uuid.Must(uuid.FromBytes(b[:])).String()
}

// --- RFC 6238 primitives --------------------------------------------

// generateTOTP returns the RFC 6238 6-digit code for the given secret
// at the given step counter. HMAC-SHA1 per spec (every authenticator
// app expects SHA1; SHA256/512 variants exist but are not the default
// and would silently break interop).
func generateTOTP(secret []byte, counter uint64) string {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, truncated%mod)
}

// verifyTOTP returns true iff `code` matches the expected code for the
// current step or any step within ±skewSteps. Constant-time string
// comparison so an attacker doesn't get a timing oracle on partial
// matches.
//
// `code` is trimmed + length-checked first — a non-6-digit input can't
// possibly match, so we short-circuit without running HMAC.
func verifyTOTP(secret []byte, code string, now time.Time, skewSteps int) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	currentStep := uint64(now.Unix()) / totpStepSecs
	codeBytes := []byte(code)
	for delta := -skewSteps; delta <= skewSteps; delta++ {
		// Clamp at zero so we don't underflow into a huge counter.
		var step uint64
		if delta < 0 {
			if uint64(-delta) > currentStep {
				continue
			}
			step = currentStep - uint64(-delta)
		} else {
			step = currentStep + uint64(delta)
		}
		expected := generateTOTP(secret, step)
		if subtle.ConstantTimeCompare(codeBytes, []byte(expected)) == 1 {
			return true
		}
	}
	return false
}
