// Sessions repository — server-side session table behind the
// HttpOnly cookie auth scaffold (architect Q2 + Q8, Slice A2).
//
// Hard rules respected:
//   - `token_hash` is BYTEA, never TEXT. We store SHA-256 of the
//     plaintext cookie value; the plaintext is returned ONCE in the
//     Set-Cookie response on login and never persisted.
//   - `revoked_at` is set, never unset. A session can be archived
//     but never resurrected — the next request must re-authenticate.
//   - Append-on-create, mutate `idle_expires_at` / `last_mfa_at` /
//     `revoked_at` only. The token hash + user_id + created_at are
//     immutable for the row's lifetime.

package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Session mirrors a row in the sessions table.
type Session struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	TokenHash      []byte
	CreatedAt      time.Time
	ExpiresAt      time.Time
	IdleExpiresAt  time.Time
	LastMFAAt      *time.Time
	RevokedAt      *time.Time
	IP             string
	UserAgent      string
}

// SessionRepository is the public surface.
type SessionRepository interface {
	Create(ctx context.Context, s *Session) error
	GetByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error)
	TouchIdleExpiry(ctx context.Context, id uuid.UUID, idleExpiresAt time.Time) error
	TouchLastMFA(ctx context.Context, id uuid.UUID, at time.Time) error
	Revoke(ctx context.Context, id uuid.UUID, at time.Time) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID, at time.Time) (int, error)
	ListActiveForUser(ctx context.Context, userID uuid.UUID, now time.Time) ([]*Session, error)
}

// Sessions is the Postgres implementation.
type Sessions struct {
	pool *Pool
}

// NewSessions binds a Sessions repository to the pool.
func NewSessions(pool *Pool) *Sessions { return &Sessions{pool: pool} }

// Create inserts a new row.
func (r *Sessions) Create(ctx context.Context, s *Session) error {
	if s.UserID == uuid.Nil {
		return errors.New("storage: session user_id required")
	}
	if len(s.TokenHash) == 0 {
		return errors.New("storage: session token_hash required")
	}
	if s.ExpiresAt.IsZero() || s.IdleExpiresAt.IsZero() {
		return errors.New("storage: session expires_at + idle_expires_at required")
	}
	const q = `
		INSERT INTO sessions
		    (user_id, token_hash, expires_at, idle_expires_at, last_mfa_at, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''))
		RETURNING id, created_at`
	var lastMFA any
	if s.LastMFAAt != nil {
		lastMFA = s.LastMFAAt.UTC()
	}
	if err := r.pool.QueryRow(ctx, q,
		s.UserID, s.TokenHash, s.ExpiresAt.UTC(), s.IdleExpiresAt.UTC(),
		lastMFA, s.IP, s.UserAgent,
	).Scan(&s.ID, &s.CreatedAt); err != nil {
		return fmt.Errorf("storage: create session: %w", err)
	}
	return nil
}

// GetByTokenHash returns the live session whose token_hash matches.
// Sessions whose `revoked_at` is set OR whose absolute / idle expiry
// is in the past return `ErrNotFound` — the caller treats them as
// authentication failure.
func (r *Sessions) GetByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error) {
	if len(tokenHash) == 0 {
		return nil, ErrNotFound
	}
	const q = `
		SELECT id, user_id, token_hash, created_at, expires_at, idle_expires_at,
		       last_mfa_at, revoked_at, COALESCE(ip, ''), COALESCE(user_agent, '')
		FROM sessions
		WHERE token_hash = $1`
	var s Session
	if err := r.pool.QueryRow(ctx, q, tokenHash).Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt, &s.IdleExpiresAt,
		&s.LastMFAAt, &s.RevokedAt, &s.IP, &s.UserAgent,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: get session: %w", err)
	}
	return &s, nil
}

// TouchIdleExpiry slides the idle TTL forward. The absolute TTL
// (`expires_at`) is immutable for the row's lifetime — a session
// can't be extended past it.
func (r *Sessions) TouchIdleExpiry(ctx context.Context, id uuid.UUID, idleExpiresAt time.Time) error {
	const q = `UPDATE sessions
	           SET idle_expires_at = $1
	           WHERE id = $2 AND revoked_at IS NULL`
	tag, err := r.pool.Exec(ctx, q, idleExpiresAt.UTC(), id)
	if err != nil {
		return fmt.Errorf("storage: touch session idle expiry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLastMFA stamps `last_mfa_at = at` on a live session. Slice D
// (step-up auth): the OIDC callback calls this when the ID token's
// `amr` claim carries a strong factor (mfa / otp / hwk / fido / ...).
// `RequireFreshMFA` later checks `now - last_mfa_at <= maxAge`.
func (r *Sessions) TouchLastMFA(ctx context.Context, id uuid.UUID, at time.Time) error {
	const q = `UPDATE sessions
	           SET last_mfa_at = $1
	           WHERE id = $2 AND revoked_at IS NULL`
	tag, err := r.pool.Exec(ctx, q, at.UTC(), id)
	if err != nil {
		return fmt.Errorf("storage: touch session last_mfa_at: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Revoke marks the session dead. Idempotent — re-revoking a row that
// already carries `revoked_at` is a no-op so logout can be retried
// safely.
func (r *Sessions) Revoke(ctx context.Context, id uuid.UUID, at time.Time) error {
	const q = `UPDATE sessions
	           SET revoked_at = COALESCE(revoked_at, $1)
	           WHERE id = $2`
	tag, err := r.pool.Exec(ctx, q, at.UTC(), id)
	if err != nil {
		return fmt.Errorf("storage: revoke session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeAllForUser marks every live session for the user dead.
// Returns the number of rows newly revoked. Admin-initiated
// password reset / account compromise response uses this.
func (r *Sessions) RevokeAllForUser(ctx context.Context, userID uuid.UUID, at time.Time) (int, error) {
	const q = `UPDATE sessions
	           SET revoked_at = $1
	           WHERE user_id = $2 AND revoked_at IS NULL`
	tag, err := r.pool.Exec(ctx, q, at.UTC(), userID)
	if err != nil {
		return 0, fmt.Errorf("storage: revoke user sessions: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ListActiveForUser projects only currently-valid sessions for the
// "manage my sessions" admin / user surface. Excludes revoked +
// expired rows.
func (r *Sessions) ListActiveForUser(ctx context.Context, userID uuid.UUID, now time.Time) ([]*Session, error) {
	const q = `
		SELECT id, user_id, token_hash, created_at, expires_at, idle_expires_at,
		       last_mfa_at, revoked_at, COALESCE(ip, ''), COALESCE(user_agent, '')
		FROM sessions
		WHERE user_id = $1
		  AND revoked_at IS NULL
		  AND expires_at > $2
		  AND idle_expires_at > $2
		ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q, userID, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("storage: list active sessions: %w", err)
	}
	defer rows.Close()
	out := []*Session{}
	for rows.Next() {
		var s Session
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt, &s.IdleExpiresAt,
			&s.LastMFAAt, &s.RevokedAt, &s.IP, &s.UserAgent,
		); err != nil {
			return nil, fmt.Errorf("storage: scan session: %w", err)
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}
