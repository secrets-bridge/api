// User MFA factors repository — app-level MFA enrollment storage
// (Slice H1, migration 0021).
//
// The schema supports two kinds:
//   - 'totp'     — RFC 6238 shared secret in envelope-encrypted form
//   - 'webauthn' — FIDO2 / WebAuthn public-key credential (COSE blob
//                  in envelope-encrypted form, plus credential_id,
//                  sign_count, aaguid)
//
// Storage layer is dumb byte-handling: callers MUST envelope-encrypt
// the secret blob via `pkg/keymgmt` before Create — this repository
// never sees plaintext factor material. Same posture as
// `secret_wraps.go`.
//
// Authentication-time lookup: `GetByWebAuthnCredentialID` is the hot
// path during a WebAuthn assertion. The partial UNIQUE index on
// `webauthn_credential_id` makes this O(log n) regardless of how
// many TOTP rows the table accumulates.
//
// Anti-cloning: `IncrementSignCount` enforces the WebAuthn spec's
// monotonic counter rule — `new > current` or the update is rejected
// as `ErrSignCountRegression`. A regression indicates the
// authenticator was cloned and MUST end the session (the services
// layer maps this to a hard logout + audit).

package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MFAFactorKind discriminates the row's shape. Mirrors the
// schema's CHECK constraint — keep the two in lock-step.
type MFAFactorKind string

const (
	MFAFactorKindTOTP     MFAFactorKind = "totp"
	MFAFactorKindWebAuthn MFAFactorKind = "webauthn"
)

// UserMFAFactor mirrors one row in `user_mfa_factors`. The
// `Secret*` fields hold the ENVELOPE-ENCRYPTED form of the factor
// secret — TOTP shared key (RFC 6238) or WebAuthn COSE public key.
// Plaintext never lives in this struct.
type UserMFAFactor struct {
	ID     uuid.UUID
	UserID uuid.UUID
	Kind   MFAFactorKind
	Label  string

	SecretCiphertext    []byte
	SecretNonce         []byte
	DataKeyCiphertext   []byte
	KMSKeyID            string

	// WebAuthn-only — zero values for TOTP rows.
	WebAuthnCredentialID []byte
	WebAuthnSignCount    int64
	WebAuthnAAGUID       *uuid.UUID

	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// MFA factor sentinel errors.
var (
	// ErrMFALabelExists — `(user_id, label)` collision. Surface to
	// the API layer so the user gets "this name is already used".
	ErrMFALabelExists = errors.New("storage: mfa factor label already used for this user")

	// ErrMFACredentialExists — same WebAuthn credential id is
	// already registered (under this user or another). RFC 8809
	// recommends rejecting re-registration.
	ErrMFACredentialExists = errors.New("storage: webauthn credential already registered")

	// ErrSignCountRegression — a WebAuthn assertion came back with
	// a sign_count that did not strictly increase. Spec-defined
	// clone indicator: callers MUST revoke sessions + audit.
	ErrSignCountRegression = errors.New("storage: webauthn sign_count did not increase")

	// ErrKindMismatch — caller asked for a kind-specific operation
	// against a row of the wrong kind (e.g. IncrementSignCount on
	// a TOTP row).
	ErrKindMismatch = errors.New("storage: mfa factor kind does not support this operation")
)

// UserMFAFactorRepository is the public read/write surface.
type UserMFAFactorRepository interface {
	// Create inserts a new row. The `Secret*` and `DataKey*` fields
	// MUST already be in envelope-encrypted form (caller wrapped
	// the plaintext through pkg/keymgmt). Per-user label collision
	// surfaces as ErrMFALabelExists; WebAuthn credential reuse as
	// ErrMFACredentialExists. ID + CreatedAt are populated on
	// return.
	Create(ctx context.Context, f *UserMFAFactor) error

	// Get returns a single factor by id. ErrNotFound when no row
	// matches.
	Get(ctx context.Context, id uuid.UUID) (*UserMFAFactor, error)

	// GetByWebAuthnCredentialID resolves the WebAuthn rawId the
	// browser sent during an assertion. Returns ErrNotFound when
	// no row matches (treat as authentication failure — do NOT
	// disclose). TOTP rows are NEVER returned because the partial
	// UNIQUE index excludes them.
	GetByWebAuthnCredentialID(ctx context.Context, rawID []byte) (*UserMFAFactor, error)

	// ListForUser returns every factor the user has enrolled, most
	// recent first. Empty slice when nothing is enrolled.
	ListForUser(ctx context.Context, userID uuid.UUID) ([]*UserMFAFactor, error)

	// CountForUser returns how many factors the user has enrolled.
	// Drives the `mfa_enrolled` boolean on `/users/me` (Slice H5)
	// without having to read every row.
	CountForUser(ctx context.Context, userID uuid.UUID) (int, error)

	// Delete removes a single factor — scoped to (id, userID) so a
	// hostile request can't delete another user's factor by id
	// alone. Returns ErrNotFound when (id, userID) doesn't match.
	Delete(ctx context.Context, id, userID uuid.UUID) error

	// TouchLastUsed stamps `last_used_at = at`. Called after every
	// successful TOTP / WebAuthn verification so users can see
	// "Last used 2 minutes ago" in the enrollment UI.
	TouchLastUsed(ctx context.Context, id uuid.UUID, at time.Time) error

	// IncrementSignCount enforces the WebAuthn monotonic counter
	// invariant. `newCount` MUST be strictly greater than the
	// stored value — otherwise ErrSignCountRegression. Only valid
	// for WebAuthn rows; TOTP rows return ErrKindMismatch.
	IncrementSignCount(ctx context.Context, id uuid.UUID, newCount int64) error
}

// UserMFAFactors is the Postgres implementation.
type UserMFAFactors struct {
	pool *Pool
}

// NewUserMFAFactors binds a UserMFAFactors repository to the pool.
func NewUserMFAFactors(pool *Pool) *UserMFAFactors { return &UserMFAFactors{pool: pool} }

// Create inserts a new row.
func (r *UserMFAFactors) Create(ctx context.Context, f *UserMFAFactor) error {
	if f.UserID == uuid.Nil {
		return errors.New("storage: mfa factor user_id required")
	}
	if !validKind(f.Kind) {
		return fmt.Errorf("storage: mfa factor kind %q invalid", f.Kind)
	}
	if strings.TrimSpace(f.Label) == "" {
		return errors.New("storage: mfa factor label required")
	}
	if len(f.SecretCiphertext) == 0 || len(f.SecretNonce) == 0 ||
		len(f.DataKeyCiphertext) == 0 || f.KMSKeyID == "" {
		return errors.New("storage: mfa factor envelope fields required")
	}
	if f.Kind == MFAFactorKindWebAuthn && len(f.WebAuthnCredentialID) == 0 {
		return errors.New("storage: webauthn factor credential_id required")
	}
	if f.Kind == MFAFactorKindTOTP &&
		(len(f.WebAuthnCredentialID) > 0 || f.WebAuthnAAGUID != nil) {
		return errors.New("storage: totp factor must not carry webauthn metadata")
	}

	const q = `
		INSERT INTO user_mfa_factors
		    (user_id, kind, label,
		     secret_ciphertext, secret_nonce, data_key_ciphertext, kms_key_id,
		     webauthn_credential_id, webauthn_sign_count, webauthn_aaguid)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at`
	var credID any
	if len(f.WebAuthnCredentialID) > 0 {
		credID = f.WebAuthnCredentialID
	}
	var aaguid any
	if f.WebAuthnAAGUID != nil {
		aaguid = *f.WebAuthnAAGUID
	}
	err := r.pool.QueryRow(ctx, q,
		f.UserID, string(f.Kind), f.Label,
		f.SecretCiphertext, f.SecretNonce, f.DataKeyCiphertext, f.KMSKeyID,
		credID, f.WebAuthnSignCount, aaguid,
	).Scan(&f.ID, &f.CreatedAt)
	if err != nil {
		return mapMFAUniqueErr(err)
	}
	return nil
}

// Get returns the factor by id.
func (r *UserMFAFactors) Get(ctx context.Context, id uuid.UUID) (*UserMFAFactor, error) {
	const q = baseSelect + `WHERE id = $1`
	row := r.pool.QueryRow(ctx, q, id)
	return scanMFAFactor(row)
}

// GetByWebAuthnCredentialID resolves a WebAuthn rawId.
func (r *UserMFAFactors) GetByWebAuthnCredentialID(ctx context.Context, rawID []byte) (*UserMFAFactor, error) {
	if len(rawID) == 0 {
		return nil, ErrNotFound
	}
	const q = baseSelect + `WHERE webauthn_credential_id = $1`
	row := r.pool.QueryRow(ctx, q, rawID)
	return scanMFAFactor(row)
}

// ListForUser returns every factor for a user.
func (r *UserMFAFactors) ListForUser(ctx context.Context, userID uuid.UUID) ([]*UserMFAFactor, error) {
	const q = baseSelect + `WHERE user_id = $1 ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("storage: list mfa factors: %w", err)
	}
	defer rows.Close()
	out := []*UserMFAFactor{}
	for rows.Next() {
		f, err := scanMFAFactor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CountForUser counts enrolled factors.
func (r *UserMFAFactors) CountForUser(ctx context.Context, userID uuid.UUID) (int, error) {
	const q = `SELECT COUNT(*) FROM user_mfa_factors WHERE user_id = $1`
	var n int
	if err := r.pool.QueryRow(ctx, q, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("storage: count mfa factors: %w", err)
	}
	return n, nil
}

// Delete removes a factor scoped to (id, userID).
func (r *UserMFAFactors) Delete(ctx context.Context, id, userID uuid.UUID) error {
	const q = `DELETE FROM user_mfa_factors WHERE id = $1 AND user_id = $2`
	tag, err := r.pool.Exec(ctx, q, id, userID)
	if err != nil {
		return fmt.Errorf("storage: delete mfa factor: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLastUsed stamps `last_used_at`.
func (r *UserMFAFactors) TouchLastUsed(ctx context.Context, id uuid.UUID, at time.Time) error {
	const q = `UPDATE user_mfa_factors SET last_used_at = $1 WHERE id = $2`
	tag, err := r.pool.Exec(ctx, q, at.UTC(), id)
	if err != nil {
		return fmt.Errorf("storage: touch mfa last_used_at: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// IncrementSignCount enforces the WebAuthn monotonic counter rule.
// The UPDATE's WHERE clause asserts `webauthn_sign_count < $1` AND
// `kind = 'webauthn'` atomically — so a concurrent regression or a
// TOTP row both produce zero RowsAffected, and we distinguish the
// two with a follow-up SELECT only on the unhappy path. Saves the
// common case from a round-trip.
func (r *UserMFAFactors) IncrementSignCount(ctx context.Context, id uuid.UUID, newCount int64) error {
	const q = `UPDATE user_mfa_factors
	           SET webauthn_sign_count = $1
	           WHERE id = $2
	             AND kind = 'webauthn'
	             AND webauthn_sign_count < $1`
	tag, err := r.pool.Exec(ctx, q, newCount, id)
	if err != nil {
		return fmt.Errorf("storage: increment sign_count: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Disambiguate: no-such-row vs wrong-kind vs regression.
	const probe = `SELECT kind, webauthn_sign_count
	               FROM user_mfa_factors WHERE id = $1`
	var kind string
	var current int64
	switch err := r.pool.QueryRow(ctx, probe, id).Scan(&kind, &current); {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("storage: probe sign_count: %w", err)
	}
	if kind != string(MFAFactorKindWebAuthn) {
		return ErrKindMismatch
	}
	return ErrSignCountRegression
}

// --- helpers --------------------------------------------------------

const baseSelect = `
SELECT id, user_id, kind, label,
       secret_ciphertext, secret_nonce, data_key_ciphertext, kms_key_id,
       webauthn_credential_id, webauthn_sign_count, webauthn_aaguid,
       created_at, last_used_at
FROM user_mfa_factors
`

// rowScanner abstracts pgx.Row and pgx.Rows so the same scan path
// covers Get / GetByWebAuthnCredentialID and ListForUser.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanMFAFactor(row rowScanner) (*UserMFAFactor, error) {
	var f UserMFAFactor
	var kind string
	var credID []byte
	var aaguid *uuid.UUID
	if err := row.Scan(
		&f.ID, &f.UserID, &kind, &f.Label,
		&f.SecretCiphertext, &f.SecretNonce, &f.DataKeyCiphertext, &f.KMSKeyID,
		&credID, &f.WebAuthnSignCount, &aaguid,
		&f.CreatedAt, &f.LastUsedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan mfa factor: %w", err)
	}
	f.Kind = MFAFactorKind(kind)
	f.WebAuthnCredentialID = credID
	f.WebAuthnAAGUID = aaguid
	return &f, nil
}

func validKind(k MFAFactorKind) bool {
	return k == MFAFactorKindTOTP || k == MFAFactorKindWebAuthn
}

// mapMFAUniqueErr translates the two UNIQUE-constraint violations
// into typed sentinel errors. Any other pg error returns wrapped.
func mapMFAUniqueErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		switch pgErr.ConstraintName {
		case "user_mfa_factors_user_label_uniq":
			return ErrMFALabelExists
		case "user_mfa_factors_webauthn_credential_id_uniq":
			return ErrMFACredentialExists
		}
	}
	return fmt.Errorf("storage: create mfa factor: %w", err)
}
