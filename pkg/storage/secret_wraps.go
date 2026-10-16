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
	// EnvironmentID is the authoritative env binding added by Slice L3.
	// For request-flow wraps it's copied from the parent access_request;
	// for direct_reveal wraps it's set inline at issue time. Nullable
	// during migration.
	EnvironmentID *uuid.UUID
	// IssuedVia distinguishes wraps issued through the access-request
	// lifecycle (`request`) from those issued by the Slice L4 dev
	// direct-reveal endpoint (`direct_reveal`). Schema CHECK pins the
	// allowed values.
	IssuedVia         WrapIssuedVia
	KeyName           string
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
	ConsumedByUser    string
}

// WrapIssuedVia is constrained by the schema CHECK on
// secret_wraps.issued_via.
type WrapIssuedVia string

const (
	WrapIssuedViaRequest      WrapIssuedVia = "request"
	WrapIssuedViaDirectReveal WrapIssuedVia = "direct_reveal"
)

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
	// "consumed" by an AGENT — sets consumed_at, consumed_by_agent.
	// Returns ErrAlreadyConsumed when the row is already consumed and
	// ErrExpired when the wrap has aged past expires_at. Both are
	// observable, so the service layer can produce the right HTTP
	// status to the agent. The consume also clears the ciphertext
	// columns (API-S-24); callers read the row before consuming.
	MarkConsumed(ctx context.Context, id, agentID uuid.UUID, at time.Time) error

	// MarkConsumedForJob is MarkConsumed gated, in the same statement,
	// on jobID being the wrap's request job, of jobType, and currently
	// claimed by agentID (H4). Returns ErrJobNotClaimed when it is not;
	// a refused call never burns the wrap.
	MarkConsumedForJob(ctx context.Context, id, agentID, jobID uuid.UUID, jobType JobType, at time.Time) error

	// CreateForClaimedJob inserts an agent-produced wrap only while
	// jobID (the request's job, of jobType) is claimed by agentID and
	// the request holds no other wrap for the same key_name (H4).
	// Returns ErrJobNotClaimed or ErrDuplicateWrapKey.
	CreateForClaimedJob(ctx context.Context, w *SecretWrap, jobID, agentID uuid.UUID, jobType JobType) error

	// JobClaimedBy reports whether jobID is requestID's job, of jobType,
	// and currently claimed by agentID. A read-only pre-check; the two
	// methods above re-check atomically.
	JobClaimedBy(ctx context.Context, jobID, requestID, agentID uuid.UUID, jobType JobType) (bool, error)

	// MarkConsumedByUser is the user-bound counterpart of MarkConsumed.
	// Used by the read flow's user-bound retrieval endpoint to
	// atomically consume a wrap created by an agent. Same single-shot
	// semantics; same error mapping.
	MarkConsumedByUser(ctx context.Context, id uuid.UUID, userID string, at time.Time) error

	// SetExpiry moves expires_at EARLIER, never later: the stored value
	// becomes LEAST(expires_at, expiresAt). Called by the workflow engine
	// on state transitions and by reveal-session expiry. Consumed wraps
	// are left untouched (ErrAlreadyConsumed); an already-expired wrap
	// stays expired.
	SetExpiry(ctx context.Context, id uuid.UUID, expiresAt time.Time) error

	// DeleteExpired removes rows past their expiry. Returns the
	// number of rows deleted. Called by the background cleanup
	// worker (Step 11).
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)

	// ListIDsForRequest returns every wrap id tied to a given
	// access_request. The workflow engine uses this to refresh TTLs in
	// bulk on state transitions (approved → 1h, rejected → 5m, etc.).
	ListIDsForRequest(ctx context.Context, requestID uuid.UUID) ([]uuid.UUID, error)

	// ListSummariesForRequest returns every wrap tied to a request as
	// a (wrap_id, key_name, consumed) triple. Used by the agent
	// retrieval endpoint to enumerate which wraps still need fetching
	// without leaking value-bearing fields.
	ListSummariesForRequest(ctx context.Context, requestID uuid.UUID) ([]WrapSummary, error)
}

// WrapSummary is the value-free metadata view of a wrap used for
// listing endpoints (e.g. "what wraps does this request own?").
type WrapSummary struct {
	ID        uuid.UUID
	KeyName   string
	Consumed  bool
	ExpiresAt time.Time
}

// ErrAlreadyConsumed signals a single-shot violation.
var ErrAlreadyConsumed = errors.New("storage: wrap already consumed")

// ErrExpired signals the wrap has aged past its TTL.
var ErrExpired = errors.New("storage: wrap expired")

// ErrJobNotClaimed signals that the request's job is not currently
// claimed by the calling agent, so the agent may not create or fetch
// wraps for that request (H4).
var ErrJobNotClaimed = errors.New("storage: request job is not claimed by this agent")

// ErrDuplicateWrapKey signals that the request already holds a wrap for
// the key an agent tried to post (H4).
var ErrDuplicateWrapKey = errors.New("storage: request already has a wrap for this key")

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
	if err := prepareWrap(w); err != nil {
		return err
	}
	return insertWrap(ctx, r.pool, w)
}

// CreateForClaimedJob is the agent-side create (H4). One transaction:
//
//  1. Lock the job row FOR UPDATE, requiring it to be the request's job,
//     of jobType, claimed by agentID with an unexpired lease (ClaimNext
//     hands an expired claim to another agent). The lock serialises concurrent
//     posts for the same job and holds off Complete / a re-claim until
//     the insert commits, so a wrap can never land on a job the agent
//     no longer owns.
//  2. Refuse a second wrap for the same (request_id, key_name).
//  3. Insert.
func (r *SecretWraps) CreateForClaimedJob(ctx context.Context, w *SecretWrap, jobID, agentID uuid.UUID, jobType JobType) error {
	if err := prepareWrap(w); err != nil {
		return err
	}
	if w.RequestID == nil || w.KeyName == "" {
		return errors.New("storage: request_id and key_name are required for an agent wrap")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: begin agent wrap create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT id FROM sync_jobs
		WHERE id = $1 AND request_id = $2 AND claimed_by = $3
		  AND status = 'claimed' AND job_type = $4
		  AND claim_expires_at > now()
		FOR UPDATE`, jobID, *w.RequestID, agentID, jobType).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrJobNotClaimed
	}
	if err != nil {
		return fmt.Errorf("storage: lock job for agent wrap: %w", err)
	}

	var dup bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM secret_wraps WHERE request_id = $1 AND key_name = $2)`,
		*w.RequestID, w.KeyName).Scan(&dup); err != nil {
		return fmt.Errorf("storage: check duplicate wrap key: %w", err)
	}
	if dup {
		return ErrDuplicateWrapKey
	}
	if err := insertWrap(ctx, tx, w); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: commit agent wrap create: %w", err)
	}
	return nil
}

// JobClaimedBy reports whether jobID is requestID's job of jobType and
// is currently claimed by agentID, lease not expired.
func (r *SecretWraps) JobClaimedBy(ctx context.Context, jobID, requestID, agentID uuid.UUID, jobType JobType) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM sync_jobs
			WHERE id = $1 AND request_id = $2 AND claimed_by = $3
			  AND status = 'claimed' AND job_type = $4
			  AND claim_expires_at > now())`,
		jobID, requestID, agentID, jobType).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("storage: check job claim: %w", err)
	}
	return ok, nil
}

// prepareWrap validates a wrap and fills its defaults before insert.
func prepareWrap(w *SecretWrap) error {
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
	if w.IssuedVia == "" {
		w.IssuedVia = WrapIssuedViaRequest
	}
	return nil
}

// insertWrap writes a prepared wrap through q (the pool or a tx).
func insertWrap(ctx context.Context, q rowQuerier, w *SecretWrap) error {
	const insertGenerated = `
		INSERT INTO secret_wraps
		  (request_id, environment_id, issued_via, key_name,
		   encrypted_value, nonce, data_key_ciphertext,
		   kms_key_id, algorithm, content_hash, byte_length, expires_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at`
	const insertWithID = `
		INSERT INTO secret_wraps
		  (id, request_id, environment_id, issued_via, key_name,
		   encrypted_value, nonce, data_key_ciphertext,
		   kms_key_id, algorithm, content_hash, byte_length, expires_at)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING created_at`

	if w.ID == uuid.Nil {
		return q.QueryRow(ctx, insertGenerated,
			w.RequestID, w.EnvironmentID, w.IssuedVia, w.KeyName,
			w.EncryptedValue, w.Nonce, w.DataKeyCiphertext,
			w.KMSKeyID, w.Algorithm, w.ContentHash, w.ByteLength, w.ExpiresAt,
		).Scan(&w.ID, &w.CreatedAt)
	}
	return q.QueryRow(ctx, insertWithID,
		w.ID, w.RequestID, w.EnvironmentID, w.IssuedVia, w.KeyName,
		w.EncryptedValue, w.Nonce, w.DataKeyCiphertext,
		w.KMSKeyID, w.Algorithm, w.ContentHash, w.ByteLength, w.ExpiresAt,
	).Scan(&w.CreatedAt)
}

// Get returns the wrap by id.
func (r *SecretWraps) Get(ctx context.Context, id uuid.UUID) (*SecretWrap, error) {
	const q = `
		SELECT id, request_id, environment_id, issued_via,
		       COALESCE(key_name, ''),
		       encrypted_value, nonce, data_key_ciphertext,
		       kms_key_id, algorithm, content_hash, byte_length,
		       created_at, expires_at, consumed_at, consumed_by_agent,
		       COALESCE(consumed_by_user, '')
		FROM secret_wraps
		WHERE id = $1`
	return scanSecretWrap(r.pool.QueryRow(ctx, q, id))
}

// clearCiphertextSQL is the SET fragment every consume applies
// (API-S-24). The columns are NOT NULL, so the consume writes an empty
// bytea: once the single-shot read has happened nothing on disk can be
// decrypted, even before the expiry sweeper deletes the row. The nonce
// is not secret and stays.
const clearCiphertextSQL = `encrypted_value = ''::bytea, data_key_ciphertext = ''::bytea`

// MarkConsumed atomically transitions to consumed. The single SQL
// statement does ALL three checks (exists, not consumed, not expired)
// so concurrent agents racing to retrieve the same wrap see consistent
// results: exactly one wins.
func (r *SecretWraps) MarkConsumed(ctx context.Context, id, agentID uuid.UUID, at time.Time) error {
	const q = `
		UPDATE secret_wraps
		SET consumed_at = $3, consumed_by_agent = $2, ` + clearCiphertextSQL + `
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
	return r.consumeRefusal(ctx, id, at)
}

// MarkConsumedForJob consumes the wrap only when, in the same statement,
// jobID is the wrap's request job, of jobType, and claimed by agentID
// with an unexpired lease. Once the lease runs out ClaimNext may give the
// job to another agent, so the old holder must not take the plaintext.
func (r *SecretWraps) MarkConsumedForJob(ctx context.Context, id, agentID, jobID uuid.UUID, jobType JobType, at time.Time) error {
	const q = `
		UPDATE secret_wraps w
		SET consumed_at = $3, consumed_by_agent = $2, ` + clearCiphertextSQL + `
		WHERE w.id = $1
		  AND w.consumed_at IS NULL
		  AND w.expires_at > $3
		  AND EXISTS (
		      SELECT 1 FROM sync_jobs j
		      WHERE j.id = $4 AND j.request_id = w.request_id
		        AND j.claimed_by = $2 AND j.status = 'claimed' AND j.job_type = $5
		        AND j.claim_expires_at > now())`
	tag, err := r.pool.Exec(ctx, q, id, agentID, at, jobID, jobType)
	if err != nil {
		return fmt.Errorf("storage: mark consumed for job: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Ownership first: a non-owner learns nothing about the wrap's state.
	cur, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	if cur.RequestID == nil {
		return ErrJobNotClaimed
	}
	owned, err := r.JobClaimedBy(ctx, jobID, *cur.RequestID, agentID, jobType)
	if err != nil {
		return err
	}
	if !owned {
		return ErrJobNotClaimed
	}
	return r.consumeRefusal(ctx, id, at)
}

// consumeRefusal explains a consume UPDATE that matched no row.
// Distinguishes absent from already-consumed-or-expired so the service
// layer can produce the right HTTP status.
func (r *SecretWraps) consumeRefusal(ctx context.Context, id uuid.UUID, at time.Time) error {
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

// MarkConsumedByUser is the user-bound counterpart of MarkConsumed.
// See the MarkConsumed comment for the contract.
func (r *SecretWraps) MarkConsumedByUser(ctx context.Context, id uuid.UUID, userID string, at time.Time) error {
	const q = `
		UPDATE secret_wraps
		SET consumed_at = $3, consumed_by_user = $2, ` + clearCiphertextSQL + `
		WHERE id = $1
		  AND consumed_at IS NULL
		  AND expires_at > $3`
	tag, err := r.pool.Exec(ctx, q, id, userID, at)
	if err != nil {
		return fmt.Errorf("storage: mark consumed by user: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	return r.consumeRefusal(ctx, id, at)
}

// SetExpiry shortens expires_at to expiresAt when that is earlier than
// the stored value. It never extends: a later deadline is a no-op, so a
// state transition can't revive a wrap that already expired (the row
// may sit around until the worker's wraps-expired sweep deletes it).
// Consumed wraps are not touched.
func (r *SecretWraps) SetExpiry(ctx context.Context, id uuid.UUID, expiresAt time.Time) error {
	const q = `
		UPDATE secret_wraps
		SET expires_at = LEAST(expires_at, $2)
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

// ListSummariesForRequest returns a value-free enumeration of wraps
// tied to the given request. Used by the agent to discover which wraps
// it must retrieve.
func (r *SecretWraps) ListSummariesForRequest(ctx context.Context, requestID uuid.UUID) ([]WrapSummary, error) {
	const q = `
		SELECT id, COALESCE(key_name, ''), consumed_at IS NOT NULL, expires_at
		FROM secret_wraps
		WHERE request_id = $1
		ORDER BY created_at ASC`
	rows, err := r.pool.Query(ctx, q, requestID)
	if err != nil {
		return nil, fmt.Errorf("storage: list wrap summaries: %w", err)
	}
	defer rows.Close()
	var out []WrapSummary
	for rows.Next() {
		var s WrapSummary
		if err := rows.Scan(&s.ID, &s.KeyName, &s.Consumed, &s.ExpiresAt); err != nil {
			return nil, fmt.Errorf("storage: scan wrap summary: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanSecretWrap(row interface {
	Scan(dest ...any) error
}) (*SecretWrap, error) {
	var (
		w               SecretWrap
		requestID       *uuid.UUID
		envID           *uuid.UUID
		consumedAt      *time.Time
		consumedByAgent *uuid.UUID
	)
	err := row.Scan(
		&w.ID, &requestID, &envID, &w.IssuedVia, &w.KeyName,
		&w.EncryptedValue, &w.Nonce, &w.DataKeyCiphertext,
		&w.KMSKeyID, &w.Algorithm, &w.ContentHash, &w.ByteLength,
		&w.CreatedAt, &w.ExpiresAt, &consumedAt, &consumedByAgent,
		&w.ConsumedByUser,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan secret_wrap: %w", err)
	}
	w.RequestID = requestID
	w.EnvironmentID = envID
	w.ConsumedAt = consumedAt
	w.ConsumedByAgent = consumedByAgent
	return &w, nil
}

// insertSecretWrap validates and writes one wrap row through q, which is
// the pool or the transaction AccessRequests.FillWithWraps holds the
// request row lock in.
func insertSecretWrap(ctx context.Context, q querier, w *SecretWrap) error {
	if err := prepareWrap(w); err != nil {
		return err
	}
	return insertWrap(ctx, q, w)
}
