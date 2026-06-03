package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RevealSession mirrors a row in reveal_sessions. One row per open bulk
// reveal in the SPA — Slice M ships the page that consumes it.
//
// HARD RULE: this struct holds NO secret values. The plaintext lives in
// the SPA's React refs during the visible window; the ciphertext lives
// in secret_wraps. The row's purpose is metadata-only: an operator
// breadcrumb to "user X opened a reveal on (project, env) at time T,
// holding N wraps until expires_at."
type RevealSession struct {
	ID              uuid.UUID
	UserID          string
	ProjectID       uuid.UUID
	EnvironmentID   uuid.UUID
	AccessRequestID *uuid.UUID
	TTLSeconds      int
	OpenedAt        time.Time
	ExpiresAt       time.Time
	ExpiredAt       *time.Time
	ExpiredReason   string
	WrapIDs         []uuid.UUID
	CreatedAt       time.Time
}

// RevealSessionExpiredReason is constrained by the schema CHECK on
// reveal_sessions.expired_reason.
type RevealSessionExpiredReason string

const (
	// RevealSessionExpiredTTL — server-side sweeper observed expires_at
	// past and tore the session down (Slice M3).
	RevealSessionExpiredTTL RevealSessionExpiredReason = "ttl"
	// RevealSessionExpiredUserHide — user clicked the Hide Now button.
	RevealSessionExpiredUserHide RevealSessionExpiredReason = "user_hide"
	// RevealSessionExpiredUnmount — SPA navigated away mid-session
	// (fire-and-forget POST on unmount).
	RevealSessionExpiredUnmount RevealSessionExpiredReason = "unmount"
)

// ErrRevealSessionExpired is returned by MarkExpired when the session
// has already been expired (double-tap on Hide Now, or sweeper +
// user-hide racing). Idempotent intent — the caller can swallow.
var ErrRevealSessionExpired = errors.New("storage: reveal session already expired")

// RevealSessionRepository is the read/write surface for reveal_sessions.
type RevealSessionRepository interface {
	Create(ctx context.Context, s *RevealSession) error
	Get(ctx context.Context, id uuid.UUID) (*RevealSession, error)
	// ListActiveForUser returns the caller's sessions whose expired_at
	// IS NULL, ordered by opened_at DESC. Used by the SPA on tab
	// restore to detect orphan sessions left mid-window.
	ListActiveForUser(ctx context.Context, userID string) ([]*RevealSession, error)
	// MarkExpired transitions a session from active to expired. Returns
	// ErrRevealSessionExpired if the row is already expired.
	MarkExpired(ctx context.Context, id uuid.UUID, at time.Time, reason RevealSessionExpiredReason) error
	// SweepExpired marks every row whose expires_at <= now AND
	// expired_at IS NULL as expired with reason='ttl'. Returns the
	// list of session IDs swept + the corresponding wrap_ids slice so
	// the caller (worker sweeper, Slice M3) can advance the wraps'
	// expires_at in lockstep.
	SweepExpired(ctx context.Context, now time.Time) ([]SweptRevealSession, error)
}

// SweptRevealSession is the payload returned by SweepExpired — the
// worker uses both the session ID (for logging / metrics) and the
// wrap_ids (to invalidate the underlying wraps).
type SweptRevealSession struct {
	ID      uuid.UUID
	WrapIDs []uuid.UUID
}

// RevealSessions is the Postgres-backed implementation.
type RevealSessions struct {
	pool *Pool
}

// NewRevealSessions binds the repository to a pool.
func NewRevealSessions(pool *Pool) *RevealSessions { return &RevealSessions{pool: pool} }

// Create inserts a new session. Caller-supplied ID (when non-Nil) is
// honoured.
func (r *RevealSessions) Create(ctx context.Context, s *RevealSession) error {
	if s.UserID == "" {
		return errors.New("storage: reveal session UserID is required")
	}
	if s.ProjectID == uuid.Nil {
		return errors.New("storage: reveal session ProjectID is required")
	}
	if s.EnvironmentID == uuid.Nil {
		return errors.New("storage: reveal session EnvironmentID is required")
	}
	if s.TTLSeconds <= 0 {
		return errors.New("storage: reveal session TTLSeconds is required")
	}
	if s.ExpiresAt.IsZero() {
		return errors.New("storage: reveal session ExpiresAt is required")
	}
	if s.WrapIDs == nil {
		s.WrapIDs = []uuid.UUID{}
	}

	const insertGenerated = `
		INSERT INTO reveal_sessions (
		    user_id, project_id, environment_id, access_request_id,
		    ttl_seconds, expires_at, wrap_ids
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, opened_at, created_at`
	const insertWithID = `
		INSERT INTO reveal_sessions (
		    id, user_id, project_id, environment_id, access_request_id,
		    ttl_seconds, expires_at, wrap_ids
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING opened_at, created_at`

	if s.ID == uuid.Nil {
		return r.pool.QueryRow(ctx, insertGenerated,
			s.UserID, s.ProjectID, s.EnvironmentID, s.AccessRequestID,
			s.TTLSeconds, s.ExpiresAt, s.WrapIDs,
		).Scan(&s.ID, &s.OpenedAt, &s.CreatedAt)
	}
	return r.pool.QueryRow(ctx, insertWithID,
		s.ID, s.UserID, s.ProjectID, s.EnvironmentID, s.AccessRequestID,
		s.TTLSeconds, s.ExpiresAt, s.WrapIDs,
	).Scan(&s.OpenedAt, &s.CreatedAt)
}

// Get returns a session by id. ErrNotFound when absent.
func (r *RevealSessions) Get(ctx context.Context, id uuid.UUID) (*RevealSession, error) {
	return scanRevealSession(r.pool.QueryRow(ctx, revealSessionSelect+` WHERE id = $1`, id))
}

// ListActiveForUser returns every active session for the user, ordered
// by opened_at DESC.
func (r *RevealSessions) ListActiveForUser(ctx context.Context, userID string) ([]*RevealSession, error) {
	const q = revealSessionSelect + `
		WHERE user_id = $1 AND expired_at IS NULL
		ORDER BY opened_at DESC`
	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("storage: list active reveal sessions: %w", err)
	}
	defer rows.Close()

	var out []*RevealSession
	for rows.Next() {
		s, err := scanRevealSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// MarkExpired atomically transitions the row to expired. Returns
// ErrRevealSessionExpired when the row was already expired (race or
// double-tap on Hide Now).
func (r *RevealSessions) MarkExpired(ctx context.Context, id uuid.UUID, at time.Time, reason RevealSessionExpiredReason) error {
	const q = `
		UPDATE reveal_sessions
		SET expired_at = $2, expired_reason = $3
		WHERE id = $1 AND expired_at IS NULL`
	tag, err := r.pool.Exec(ctx, q, id, at, string(reason))
	if err != nil {
		return fmt.Errorf("storage: mark reveal session expired: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Distinguish absent from already-expired so the caller can branch.
	cur, getErr := r.Get(ctx, id)
	if getErr != nil {
		return getErr
	}
	if cur.ExpiredAt != nil {
		return ErrRevealSessionExpired
	}
	// Should be unreachable — UPDATE matched 0 rows but Get found an
	// active row. Treat as a benign race; tell the caller it expired.
	return ErrRevealSessionExpired
}

// SweepExpired marks every active session whose TTL has passed as
// expired with reason='ttl'. Returns the affected (session_id,
// wrap_ids) pairs so the worker sweeper can advance the wraps'
// expires_at in lockstep.
//
// Uses a single round-trip: UPDATE ... RETURNING. Postgres processes
// the WHERE filter and the UPDATE atomically so the same row can't be
// returned twice across concurrent sweeper replicas (and the partial
// index keeps the scan cheap).
func (r *RevealSessions) SweepExpired(ctx context.Context, now time.Time) ([]SweptRevealSession, error) {
	const q = `
		UPDATE reveal_sessions
		SET expired_at = $1, expired_reason = 'ttl'
		WHERE expires_at <= $1 AND expired_at IS NULL
		RETURNING id, wrap_ids`
	rows, err := r.pool.Query(ctx, q, now)
	if err != nil {
		return nil, fmt.Errorf("storage: sweep expired reveal sessions: %w", err)
	}
	defer rows.Close()

	var out []SweptRevealSession
	for rows.Next() {
		var s SweptRevealSession
		if err := rows.Scan(&s.ID, &s.WrapIDs); err != nil {
			return nil, fmt.Errorf("storage: scan swept reveal session: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

const revealSessionSelect = `
	SELECT id, user_id, project_id, environment_id, access_request_id,
	       ttl_seconds, opened_at, expires_at, expired_at,
	       COALESCE(expired_reason, ''),
	       wrap_ids, created_at
	FROM reveal_sessions`

func scanRevealSession(row interface {
	Scan(dest ...any) error
}) (*RevealSession, error) {
	var (
		s         RevealSession
		accessReq *uuid.UUID
		expiredAt *time.Time
	)
	err := row.Scan(
		&s.ID, &s.UserID, &s.ProjectID, &s.EnvironmentID, &accessReq,
		&s.TTLSeconds, &s.OpenedAt, &s.ExpiresAt, &expiredAt,
		&s.ExpiredReason,
		&s.WrapIDs, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan reveal session: %w", err)
	}
	s.AccessRequestID = accessReq
	s.ExpiredAt = expiredAt
	return &s, nil
}
