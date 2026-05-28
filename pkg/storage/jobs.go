package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SyncJob mirrors a row in the sync_jobs table. The payload is opaque
// JSON the agent interprets per JobType — never contains a secret
// value (per BRD §11; the value lives in the provider, the agent
// reads it at execution time).
type SyncJob struct {
	ID               uuid.UUID
	AgentScope       map[string]any
	JobType          JobType
	Status           JobStatus
	CorrelationID    uuid.UUID
	ClaimedBy        *uuid.UUID
	ClaimExpiresAt   *time.Time
	RequestID        *uuid.UUID
	Payload          map[string]any
	Error            string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// JobType is constrained by a CHECK in the schema.
type JobType string

const (
	JobTypeSync     JobType = "sync"
	JobTypeDiscover JobType = "discover"
	JobTypeVerify   JobType = "verify"
	JobTypeDelete   JobType = "delete"
)

// JobStatus is constrained by a CHECK in the schema.
type JobStatus string

const (
	JobStatusQueued    JobStatus = "queued"
	JobStatusClaimed   JobStatus = "claimed"
	JobStatusSucceeded JobStatus = "succeeded"
	JobStatusFailed    JobStatus = "failed"
	JobStatusExpired   JobStatus = "expired"
)

// SyncJobRepository is the read/write surface for the sync_jobs table.
type SyncJobRepository interface {
	// Create enqueues a new job. CorrelationID is generated when
	// caller-supplied uuid.Nil.
	Create(ctx context.Context, j *SyncJob) error

	// Get returns one job by ID. Returns ErrNotFound when no row matches.
	Get(ctx context.Context, id uuid.UUID) (*SyncJob, error)

	// ClaimNext atomically transitions the oldest queued job to
	// `claimed`, assigning it to agentID with the supplied lease. Uses
	// FOR UPDATE SKIP LOCKED so concurrent claim calls from multiple
	// agents never see the same row. Returns ErrNoJobs when nothing
	// is queued.
	ClaimNext(ctx context.Context, agentID uuid.UUID, lease time.Duration) (*SyncJob, error)

	// Complete transitions a claimed job to a terminal status. Only
	// succeeds when the job is currently `claimed` AND claimed by
	// agentID. Idempotent on already-terminal rows (returns
	// ErrAlreadyComplete).
	Complete(ctx context.Context, jobID, agentID uuid.UUID, status JobStatus, errMsg string) error
}

// ErrNoJobs is returned by ClaimNext when the queue is empty.
var ErrNoJobs = errors.New("storage: no jobs queued")

// ErrAlreadyComplete is returned by Complete when the job is in a
// terminal state already. Caller can treat as a successful no-op for
// idempotency.
var ErrAlreadyComplete = errors.New("storage: job already complete")

// SyncJobs is the Postgres implementation of SyncJobRepository.
type SyncJobs struct {
	pool *Pool
}

// NewSyncJobs binds a SyncJobs repository to the given pool.
func NewSyncJobs(pool *Pool) *SyncJobs { return &SyncJobs{pool: pool} }

// Create inserts a new queued job.
func (r *SyncJobs) Create(ctx context.Context, j *SyncJob) error {
	if j.JobType == "" {
		return errors.New("storage: JobType is required")
	}
	if j.Status == "" {
		j.Status = JobStatusQueued
	}
	if j.CorrelationID == uuid.Nil {
		j.CorrelationID = uuid.New()
	}
	if j.AgentScope == nil {
		j.AgentScope = map[string]any{}
	}
	if j.Payload == nil {
		j.Payload = map[string]any{}
	}
	scope, err := json.Marshal(j.AgentScope)
	if err != nil {
		return fmt.Errorf("storage: marshal job scope: %w", err)
	}
	payload, err := json.Marshal(j.Payload)
	if err != nil {
		return fmt.Errorf("storage: marshal job payload: %w", err)
	}

	const q = `
		INSERT INTO sync_jobs (agent_scope, job_type, status, correlation_id, request_id, payload)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q, scope, j.JobType, j.Status, j.CorrelationID, j.RequestID, payload)
	return row.Scan(&j.ID, &j.CreatedAt, &j.UpdatedAt)
}

// Get fetches one job by ID.
func (r *SyncJobs) Get(ctx context.Context, id uuid.UUID) (*SyncJob, error) {
	const q = `
		SELECT id, agent_scope, job_type, status, correlation_id,
		       claimed_by, claim_expires_at, request_id, payload,
		       created_at, updated_at
		FROM sync_jobs WHERE id = $1`
	return scanSyncJob(r.pool.QueryRow(ctx, q, id))
}

// ClaimNext atomically claims the oldest queued job. Implementation
// notes:
//
//   - FOR UPDATE SKIP LOCKED ensures concurrent claim transactions
//     never see the same row — Postgres native pattern, faster than a
//     Redis lock here because the operation already needs the row
//     anyway.
//   - Filters out claimed-but-expired rows alongside queued ones so the
//     worker's re-enqueue step (Step 11) doesn't have to keep up with
//     claim expirations in real time.
func (r *SyncJobs) ClaimNext(ctx context.Context, agentID uuid.UUID, lease time.Duration) (*SyncJob, error) {
	const q = `
		WITH next_job AS (
			SELECT id
			FROM sync_jobs
			WHERE status = 'queued'
			   OR (status = 'claimed' AND claim_expires_at < now())
			ORDER BY created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE sync_jobs
		SET status = 'claimed',
		    claimed_by = $1,
		    claim_expires_at = now() + $2::interval
		WHERE id IN (SELECT id FROM next_job)
		RETURNING id, agent_scope, job_type, status, correlation_id,
		          claimed_by, claim_expires_at, request_id, payload,
		          created_at, updated_at`
	leaseInterval := fmt.Sprintf("%d milliseconds", lease.Milliseconds())
	job, err := scanSyncJob(r.pool.QueryRow(ctx, q, agentID, leaseInterval))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoJobs
	}
	return job, err
}

// Complete transitions a claimed job to a terminal state. The
// ownership check (claimed_by = $2) prevents a leftover caller whose
// lease has expired (and the job was re-claimed by someone else) from
// overwriting the new owner's result.
func (r *SyncJobs) Complete(ctx context.Context, jobID, agentID uuid.UUID, status JobStatus, errMsg string) error {
	switch status {
	case JobStatusSucceeded, JobStatusFailed:
		// ok
	default:
		return fmt.Errorf("storage: Complete: invalid terminal status %q", status)
	}

	const q = `
		UPDATE sync_jobs
		SET status = $1,
		    payload = jsonb_set(payload, '{error}', to_jsonb($2::text), true)
		WHERE id = $3 AND claimed_by = $4 AND status = 'claimed'
		RETURNING id`
	var out uuid.UUID
	err := r.pool.QueryRow(ctx, q, status, errMsg, jobID, agentID).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either the job doesn't exist, the agent doesn't own it, or
		// the row is in a terminal state. Distinguish with a follow-up
		// read so callers can branch.
		cur, getErr := r.Get(ctx, jobID)
		if getErr != nil {
			return getErr
		}
		if cur.Status == JobStatusSucceeded || cur.Status == JobStatusFailed {
			return ErrAlreadyComplete
		}
		return ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("storage: complete job: %w", err)
	}
	return nil
}

func scanSyncJob(row interface {
	Scan(dest ...any) error
}) (*SyncJob, error) {
	var (
		j              SyncJob
		scopeRaw       []byte
		payloadRaw     []byte
		claimedBy      *uuid.UUID
		claimExpiresAt *time.Time
		requestID      *uuid.UUID
	)
	err := row.Scan(
		&j.ID, &scopeRaw, &j.JobType, &j.Status, &j.CorrelationID,
		&claimedBy, &claimExpiresAt, &requestID, &payloadRaw,
		&j.CreatedAt, &j.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan sync_job: %w", err)
	}
	if len(scopeRaw) > 0 {
		if err := json.Unmarshal(scopeRaw, &j.AgentScope); err != nil {
			return nil, fmt.Errorf("storage: unmarshal job scope: %w", err)
		}
	}
	if len(payloadRaw) > 0 {
		if err := json.Unmarshal(payloadRaw, &j.Payload); err != nil {
			return nil, fmt.Errorf("storage: unmarshal job payload: %w", err)
		}
	}
	j.ClaimedBy = claimedBy
	j.ClaimExpiresAt = claimExpiresAt
	j.RequestID = requestID
	if errMsg, ok := j.Payload["error"].(string); ok {
		j.Error = errMsg
	}
	return &j, nil
}
