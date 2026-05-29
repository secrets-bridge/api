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

// GitOpsObservationState is the polling lifecycle.
type GitOpsObservationState string

const (
	// GitOpsStateQueued — created right after request.transition(executed).
	GitOpsStateQueued GitOpsObservationState = "queued"
	// GitOpsStateActive — the poller has begun ticking.
	GitOpsStateActive GitOpsObservationState = "active"
	// GitOpsStateApplied — workload healthy + sync completed.
	GitOpsStateApplied GitOpsObservationState = "applied"
	// GitOpsStateAppliedUnverified — timeout fired before applied.
	GitOpsStateAppliedUnverified GitOpsObservationState = "applied_unverified"
	// GitOpsStateFailed — ArgoCD reported a permanent failure.
	GitOpsStateFailed GitOpsObservationState = "failed"
)

// GitOpsObservation is one row per (request, application) tracking the
// polling lifecycle and the latest observed state.
//
// ObservedState is metadata-only: health, sync, last revision, rollout
// progress, pod readiness. NEVER the underlying resource manifests.
type GitOpsObservation struct {
	ID                   uuid.UUID
	RequestID            uuid.UUID
	ArgoCDEndpointID     uuid.UUID
	ApplicationName      string
	ApplicationNamespace string
	PollingState         GitOpsObservationState
	ObservedState        map[string]any
	LastPolledAt         *time.Time
	PollsCount           int
	LastError            string
	TimeoutAt            *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
	TerminalAt           *time.Time
}

// GitOpsObservationRepository is the read/write surface.
type GitOpsObservationRepository interface {
	Create(ctx context.Context, o *GitOpsObservation) error
	Get(ctx context.Context, id uuid.UUID) (*GitOpsObservation, error)
	ListForRequest(ctx context.Context, requestID uuid.UUID) ([]*GitOpsObservation, error)
	// ClaimNextActive returns up to `limit` observation rows in
	// queued/active state for the poller to process. Uses FOR UPDATE
	// SKIP LOCKED so multiple worker replicas don't double-poll.
	ClaimNextActive(ctx context.Context, limit int, claimedBy uuid.UUID) ([]*GitOpsObservation, error)
	// RecordPoll updates observed_state + last_polled_at + polls_count
	// + last_error. State transition is separate.
	RecordPoll(ctx context.Context, id uuid.UUID, observed map[string]any, pollErr string, polledAt time.Time) error
	// Transition moves the row to a terminal state (applied,
	// applied_unverified, failed) and stamps terminal_at.
	Transition(ctx context.Context, id uuid.UUID, state GitOpsObservationState, at time.Time) error
	// FindTimedOut returns rows past their timeout_at that are still
	// in queued/active. Caller flips them to applied_unverified.
	FindTimedOut(ctx context.Context, now time.Time, limit int) ([]*GitOpsObservation, error)
}

// GitOpsObservations is the Postgres impl.
type GitOpsObservations struct {
	pool *Pool
}

// NewGitOpsObservations binds to the pool.
func NewGitOpsObservations(pool *Pool) *GitOpsObservations { return &GitOpsObservations{pool: pool} }

// Create inserts a new observation row in `queued` state.
func (r *GitOpsObservations) Create(ctx context.Context, o *GitOpsObservation) error {
	if o.RequestID == uuid.Nil {
		return errors.New("storage: gitops observation RequestID required")
	}
	if o.ArgoCDEndpointID == uuid.Nil {
		return errors.New("storage: gitops observation ArgoCDEndpointID required")
	}
	if o.ApplicationName == "" {
		return errors.New("storage: gitops observation ApplicationName required")
	}
	if o.PollingState == "" {
		o.PollingState = GitOpsStateQueued
	}
	if o.ObservedState == nil {
		o.ObservedState = map[string]any{}
	}
	observed, err := json.Marshal(o.ObservedState)
	if err != nil {
		return fmt.Errorf("storage: marshal observed_state: %w", err)
	}
	const q = `
		INSERT INTO gitops_observations (
			request_id, argocd_endpoint_id, application_name, application_namespace,
			polling_state, observed_state, timeout_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q,
		o.RequestID, o.ArgoCDEndpointID, o.ApplicationName, nullString(o.ApplicationNamespace),
		o.PollingState, observed, o.TimeoutAt,
	)
	return row.Scan(&o.ID, &o.CreatedAt, &o.UpdatedAt)
}

// Get fetches by id.
func (r *GitOpsObservations) Get(ctx context.Context, id uuid.UUID) (*GitOpsObservation, error) {
	const q = baseSelectGitOpsObservation + ` WHERE id = $1`
	return scanGitOpsObservation(r.pool.QueryRow(ctx, q, id))
}

// ListForRequest returns observations for one request, newest first
// per application, then by application_name for stable ordering.
func (r *GitOpsObservations) ListForRequest(ctx context.Context, requestID uuid.UUID) ([]*GitOpsObservation, error) {
	const q = baseSelectGitOpsObservation + ` WHERE request_id = $1 ORDER BY application_name, created_at DESC`
	rows, err := r.pool.Query(ctx, q, requestID)
	if err != nil {
		return nil, fmt.Errorf("storage: list gitops observations: %w", err)
	}
	defer rows.Close()
	var out []*GitOpsObservation
	for rows.Next() {
		o, err := scanGitOpsObservation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ClaimNextActive selects up to `limit` rows in queued/active state,
// transitions any queued rows to active, and returns them. Uses
// FOR UPDATE SKIP LOCKED so multiple worker replicas don't see the
// same rows for the same tick.
//
// claimedBy is informational today (no claimed_by column on this
// table); kept in the signature for symmetry with sync_jobs.ClaimNext
// in case a future migration adds one.
func (r *GitOpsObservations) ClaimNextActive(ctx context.Context, limit int, _ uuid.UUID) ([]*GitOpsObservation, error) {
	if limit <= 0 {
		limit = 10
	}
	const q = `
		WITH picked AS (
			SELECT id FROM gitops_observations
			WHERE polling_state IN ('queued', 'active')
			ORDER BY last_polled_at NULLS FIRST, created_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE gitops_observations o
		SET polling_state = 'active'
		FROM picked
		WHERE o.id = picked.id
		RETURNING o.id, o.request_id, o.argocd_endpoint_id, o.application_name,
		          COALESCE(o.application_namespace, ''), o.polling_state, o.observed_state,
		          o.last_polled_at, o.polls_count, COALESCE(o.last_error, ''),
		          o.timeout_at, o.created_at, o.updated_at, o.terminal_at`
	rows, err := r.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: claim gitops observations: %w", err)
	}
	defer rows.Close()
	var out []*GitOpsObservation
	for rows.Next() {
		o, err := scanGitOpsObservation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// RecordPoll updates observed_state + last_polled_at + polls_count.
// If pollErr is empty, last_error is cleared.
func (r *GitOpsObservations) RecordPoll(ctx context.Context, id uuid.UUID, observed map[string]any, pollErr string, polledAt time.Time) error {
	if observed == nil {
		observed = map[string]any{}
	}
	observedJSON, err := json.Marshal(observed)
	if err != nil {
		return fmt.Errorf("storage: marshal observed_state: %w", err)
	}
	const q = `
		UPDATE gitops_observations
		SET observed_state = $2, last_polled_at = $3, polls_count = polls_count + 1, last_error = NULLIF($4, '')
		WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, observedJSON, polledAt, pollErr)
	if err != nil {
		return fmt.Errorf("storage: record gitops poll: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Transition moves the row to a terminal state and stamps terminal_at.
func (r *GitOpsObservations) Transition(ctx context.Context, id uuid.UUID, state GitOpsObservationState, at time.Time) error {
	const q = `
		UPDATE gitops_observations
		SET polling_state = $2, terminal_at = $3
		WHERE id = $1 AND polling_state IN ('queued', 'active')`
	tag, err := r.pool.Exec(ctx, q, id, state, at)
	if err != nil {
		return fmt.Errorf("storage: transition gitops observation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Already terminal — idempotent no-op.
		return nil
	}
	return nil
}

// FindTimedOut returns observations past timeout_at still in
// queued/active. Caller flips them to applied_unverified via Transition.
func (r *GitOpsObservations) FindTimedOut(ctx context.Context, now time.Time, limit int) ([]*GitOpsObservation, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = baseSelectGitOpsObservation + `
		WHERE polling_state IN ('queued', 'active')
		  AND timeout_at IS NOT NULL AND timeout_at < $1
		ORDER BY timeout_at LIMIT $2`
	rows, err := r.pool.Query(ctx, q, now, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: find timed-out gitops observations: %w", err)
	}
	defer rows.Close()
	var out []*GitOpsObservation
	for rows.Next() {
		o, err := scanGitOpsObservation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

const baseSelectGitOpsObservation = `
	SELECT id, request_id, argocd_endpoint_id, application_name,
	       COALESCE(application_namespace, ''),
	       polling_state, observed_state,
	       last_polled_at, polls_count, COALESCE(last_error, ''),
	       timeout_at, created_at, updated_at, terminal_at
	FROM gitops_observations`

func scanGitOpsObservation(row pgx.Row) (*GitOpsObservation, error) {
	var o GitOpsObservation
	var observedJSON []byte
	err := row.Scan(
		&o.ID, &o.RequestID, &o.ArgoCDEndpointID, &o.ApplicationName,
		&o.ApplicationNamespace,
		&o.PollingState, &observedJSON,
		&o.LastPolledAt, &o.PollsCount, &o.LastError,
		&o.TimeoutAt, &o.CreatedAt, &o.UpdatedAt, &o.TerminalAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: scan gitops observation: %w", err)
	}
	if len(observedJSON) > 0 {
		if err := json.Unmarshal(observedJSON, &o.ObservedState); err != nil {
			return nil, fmt.Errorf("storage: unmarshal observed_state: %w", err)
		}
	}
	return &o, nil
}
