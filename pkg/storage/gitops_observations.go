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

// gitops_observations is history. The control-plane Argo CD poller that
// wrote these rows was removed at the Gateway R1 cutover
// (secrets-bridge/gateway#13): nothing creates, polls or transitions a
// row any more, and no stored row is rewritten (ADR 0001 section 9 step
// 5). This file is the read side only, for the request page's history
// view.

// GitOpsObservationState is the polling state a row was left in.
type GitOpsObservationState string

const (
	GitOpsStateQueued            GitOpsObservationState = "queued"
	GitOpsStateActive            GitOpsObservationState = "active"
	GitOpsStateApplied           GitOpsObservationState = "applied"
	GitOpsStateAppliedUnverified GitOpsObservationState = "applied_unverified"
	GitOpsStateFailed            GitOpsObservationState = "failed"
)

// GitOpsObservation is one historical row per (request, application).
// ObservedState is the metadata-only snapshot the poller stored.
type GitOpsObservation struct {
	ID                   uuid.UUID
	RequestID            uuid.UUID
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

// GitOpsObservationHistory reads the historical rows. It has no write
// method on purpose.
type GitOpsObservationHistory interface {
	ListForRequest(ctx context.Context, requestID uuid.UUID) ([]*GitOpsObservation, error)
}

// GitOpsObservations is the Postgres reader.
type GitOpsObservations struct {
	pool *Pool
}

// NewGitOpsObservations binds to the pool.
func NewGitOpsObservations(pool *Pool) *GitOpsObservations { return &GitOpsObservations{pool: pool} }

// ListForRequest returns a request's historical rows, by application.
func (r *GitOpsObservations) ListForRequest(ctx context.Context, requestID uuid.UUID) ([]*GitOpsObservation, error) {
	const q = `
		SELECT id, request_id, application_name,
		       COALESCE(application_namespace, ''),
		       polling_state, observed_state,
		       last_polled_at, polls_count, COALESCE(last_error, ''),
		       timeout_at, created_at, updated_at, terminal_at
		FROM gitops_observations
		WHERE request_id = $1 ORDER BY application_name, created_at DESC`
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

func scanGitOpsObservation(row pgx.Row) (*GitOpsObservation, error) {
	var o GitOpsObservation
	var observedJSON []byte
	err := row.Scan(
		&o.ID, &o.RequestID, &o.ApplicationName, &o.ApplicationNamespace,
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
