package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SecretWrap mirrors a row in secret_wraps. The plaintext fields here
// are the ENCRYPTED forms — the plaintext value never lives in this
// struct. The services layer (pkg/services.WrapService) is what does
// the encrypt/decrypt; the storage layer is just dumb byte storage.
type SecretWrap struct {
	ID                uuid.UUID
	RequestID         *uuid.UUID
	EncryptedValue    []byte
	Nonce             []byte
	DataKeyCiphertext []byte
	KMSKeyID          string
	Algorithm         string
	ContentHash       []byte
	ByteLength        int
	CreatedAt         time.Time
	ExpiresAt         time.Time
	ConsumedAt        *time.Time
	ConsumedByAgent   *uuid.UUID
}

// SecretWrapRepository is the read/write surface for secret_wraps.
type SecretWrapRepository interface {
	// Create inserts a new wrap row and returns its assigned id +
	// timestamps. The provided ExpiresAt is what lands on disk; the
	// service layer is responsible for picking the value based on the
	// owning workflow's TTL.
	Create(ctx context.Context, w *SecretWrap) error

	// Get returns the wrap by id. Returns ErrNotFound when no row
	// matches.
	Get(ctx context.Context, id uuid.UUID) (*SecretWrap, error)

	// MarkConsumed atomically transitions a wrap from "available" to
	// "consumed" — sets consumed_at, consumed_by_agent. Returns
	// ErrAlreadyConsumed when the row is already consumed and
	// ErrExpired when the wrap has aged past expires_at. Both are
	// observable, so the service layer can produce the right HTTP
	// status to the agent.
	MarkConsumed(ctx context.Context, id, agentID uuid.UUID, at time.Time) error

	// SetExpiry updates expires_at. Called by the workflow engine
	// during state transitions (request approved → shorter TTL).
	SetExpiry(ctx context.Context, id uuid.UUID, expiresAt time.Time) error

	// DeleteExpired removes rows past their expiry. Returns the
	// number of rows deleted. Called by the background cleanup
	// worker (Step 11).
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)

	// ListIDsForRequest returns every wrap id tied to a given
	// access_request. The workflow engine uses this to refresh TTLs in
	// bulk on state transitions (approved → 1h, rejected → 5m, etc.).
	ListIDsForRequest(ctx context.Context, requestID uuid.UUID) ([]uuid.UUID, error)
}

// ErrAlreadyConsumed signals a single-shot violation.
var ErrAlreadyConsumed = errors.New("storage: wrap already consumed")

// ErrExpired signals the wrap has aged past its TTL.
var ErrExpired = errors.New("storage: wrap expired")

// SecretWraps is the Postgres implementation.
type SecretWraps struct {
	pool *Pool
}

// NewSecretWraps binds a SecretWraps repository to the given pool.
func NewSecretWraps(pool *Pool) *SecretWraps { return &SecretWraps{pool: pool} }

// Create inserts the wrap. Caller-supplied ID (when non-Nil) is
// honoured so callers running their own UUID generation can match
// wraps to other entities they create in the same transaction.
func (r *SecretWraps) Create(ctx context.Context, w *SecretWrap) error {
	if len(w.EncryptedValue) == 0 || len(w.Nonce) == 0 || len(w.DataKeyCiphertext) == 0 {
		return errors.New("storage: encrypted_value / nonce / data_key_ciphertext are required")
	}
	if w.KMSKeyID == "" {
		return errors.New("storage: kms_key_id is required")
	}
	if w.Algorithm == "" {
		w.Algorithm = "AES-256-GCM"
	}
	if w.ExpiresAt.IsZero() {
		return errors.New("storage: expires_at is required")
	}

	const insertGenerated = `
		INSERT INTO secret_wraps
		  (request_id, encrypted_value, nonce, data_key_ciphertext,
		   kms_key_id, algorithm, content_hash, byte_length, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at`
	const insertWithID = `
		INSERT INTO secret_wraps
		  (id, request_id, encrypted_value, nonce, data_key_ciphertext,
		   kms_key_id, algorithm, content_hash, byte_length, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING created_at`

	if w.ID == uuid.Nil {
		return r.pool.QueryRow(ctx, insertGenerated,
			w.RequestID, w.EncryptedValue, w.Nonce, w.DataKeyCiphertext,
			w.KMSKeyID, w.Algorithm, w.ContentHash, w.ByteLength, w.ExpiresAt,
		).Scan(&w.ID, &w.CreatedAt)
	}
	return r.pool.QueryRow(ctx, insertWithID,
		w.ID, w.RequestID, w.EncryptedValue, w.Nonce, w.DataKeyCiphertext,
		w.KMSKeyID, w.Algorithm, w.ContentHash, w.ByteLength, w.ExpiresAt,
	).Scan(&w.CreatedAt)
}

// Get returns the wrap by id.
func (r *SecretWraps) Get(ctx context.Context, id uuid.UUID) (*SecretWrap, error) {
	const q = `
		SELECT id, request_id, encrypted_value, nonce, data_key_ciphertext,
		       kms_key_id, algorithm, content_hash, byte_length,
		       created_at, expires_at, consumed_at, consumed_by_agent
		FROM secret_wraps
		WHERE id = $1`
	return scanSecretWrap(r.pool.QueryRow(ctx, q, id))
}

// MarkConsumed atomically transitions to consumed. The single SQL
// statement does ALL three checks (exists, not consumed, not expired)
// so concurrent agents racing to retrieve the same wrap see consistent
// results: exactly one wins.
func (r *SecretWraps) MarkConsumed(ctx context.Context, id, agentID uuid.UUID, at time.Time) error {
	const q = `
		UPDATE secret_wraps
		SET consumed_at = $3, consumed_by_agent = $2
		WHERE id = $1
		  AND consumed_at IS NULL
		  AND expires_at > $3`
	tag, err := r.pool.Exec(ctx, q, id, agentID, at)
	if err != nil {
		return fmt.Errorf("storage: mark consumed: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Distinguish absent from already-consumed-or-expired so the
	// service layer can produce the right HTTP status.
	cur, getErr := r.Get(ctx, id)
	if getErr != nil {
		return getErr // ErrNotFound or DB error
	}
	if cur.ConsumedAt != nil {
		return ErrAlreadyConsumed
	}
	if !cur.ExpiresAt.After(at) {
		return ErrExpired
	}
	// Race we lost: someone else consumed it between our UPDATE and
	// our Get. Treat as already-consumed.
	return ErrAlreadyConsumed
}

// SetExpiry updates expires_at. Used by the workflow engine when state
// transitions shorten the wrap's TTL.
func (r *SecretWraps) SetExpiry(ctx context.Context, id uuid.UUID, expiresAt time.Time) error {
	const q = `
		UPDATE secret_wraps
		SET expires_at = $2
		WHERE id = $1 AND consumed_at IS NULL`
	tag, err := r.pool.Exec(ctx, q, id, expiresAt)
	if err != nil {
		return fmt.Errorf("storage: set expiry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either no row or already consumed. Get() distinguishes.
		if _, err := r.Get(ctx, id); err != nil {
			return err
		}
		return ErrAlreadyConsumed
	}
	return nil
}

// DeleteExpired removes wraps past their expiry. Background cleanup.
// Returns the number of rows deleted so the worker can log throughput.
func (r *SecretWraps) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	const q = `DELETE FROM secret_wraps WHERE expires_at <= $1`
	tag, err := r.pool.Exec(ctx, q, now)
	if err != nil {
		return 0, fmt.Errorf("storage: delete expired: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListIDsForRequest returns every wrap id tied to a given request.
func (r *SecretWraps) ListIDsForRequest(ctx context.Context, requestID uuid.UUID) ([]uuid.UUID, error) {
	const q = `SELECT id FROM secret_wraps WHERE request_id = $1 ORDER BY created_at ASC`
	rows, err := r.pool.Query(ctx, q, requestID)
	if err != nil {
		return nil, fmt.Errorf("storage: list wrap ids: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("storage: scan wrap id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func scanSecretWrap(row interface {
	Scan(dest ...any) error
}) (*SecretWrap, error) {
	var (
		w               SecretWrap
		requestID       *uuid.UUID
		consumedAt      *time.Time
		consumedByAgent *uuid.UUID
	)
	err := row.Scan(
		&w.ID, &requestID, &w.EncryptedValue, &w.Nonce, &w.DataKeyCiphertext,
		&w.KMSKeyID, &w.Algorithm, &w.ContentHash, &w.ByteLength,
		&w.CreatedAt, &w.ExpiresAt, &consumedAt, &consumedByAgent,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan secret_wrap: %w", err)
	}
	w.RequestID = requestID
	w.ConsumedAt = consumedAt
	w.ConsumedByAgent = consumedByAgent
	return &w, nil
}
