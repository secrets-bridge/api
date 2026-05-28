package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AuditEvent mirrors a row in the audit_events table. The metadata
// field is opaque JSON; the repository layer is responsible for
// stripping any field that could leak secret values before Append is
// called (CLAUDE.md hard rule). The audit_events table itself is
// append-only — UPDATE and DELETE are rejected by triggers in the
// schema, so callers can rely on the history not being rewritten.
type AuditEvent struct {
	ID            uuid.UUID
	Actor         string
	Action        string
	Resource      string
	Status        AuditStatus
	CorrelationID uuid.UUID
	Metadata      map[string]any
	OccurredAt    time.Time
}

// AuditStatus is constrained by a CHECK in the schema.
type AuditStatus string

const (
	AuditStatusSuccess AuditStatus = "success"
	AuditStatusFailure AuditStatus = "failure"
	AuditStatusDenied  AuditStatus = "denied"
)

// AuditQuery narrows a Query call. All fields are optional; zero
// values mean "no constraint".
type AuditQuery struct {
	Actor         string
	Resource      string
	Action        string
	CorrelationID uuid.UUID
	Since         time.Time
	Until         time.Time
	Limit         int // defaults to 100, capped at 1000
}

// AuditEventRepository is the public surface. Notice there are NO
// Update or Delete methods — the table is append-only by design.
type AuditEventRepository interface {
	Append(ctx context.Context, evt *AuditEvent) error
	Query(ctx context.Context, q AuditQuery) ([]*AuditEvent, error)
}

// AuditEvents is the Postgres implementation of AuditEventRepository.
type AuditEvents struct {
	pool *Pool
}

// NewAuditEvents binds an AuditEvents repository to the given pool.
func NewAuditEvents(pool *Pool) *AuditEvents { return &AuditEvents{pool: pool} }

// Append inserts one event. If CorrelationID is uuid.Nil a fresh one
// is generated so every audit row has a traceable correlation.
func (r *AuditEvents) Append(ctx context.Context, evt *AuditEvent) error {
	if evt.Actor == "" || evt.Action == "" || evt.Resource == "" {
		return errors.New("storage: audit event requires actor, action, and resource")
	}
	if evt.Status == "" {
		evt.Status = AuditStatusSuccess
	}
	if evt.CorrelationID == uuid.Nil {
		evt.CorrelationID = uuid.New()
	}
	if evt.Metadata == nil {
		evt.Metadata = map[string]any{}
	}

	metadataJSON, err := json.Marshal(evt.Metadata)
	if err != nil {
		return fmt.Errorf("storage: marshal audit metadata: %w", err)
	}

	const q = `
		INSERT INTO audit_events (actor, action, resource, status, correlation_id, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, occurred_at`
	row := r.pool.QueryRow(ctx, q,
		evt.Actor, evt.Action, evt.Resource, evt.Status, evt.CorrelationID, metadataJSON)
	return row.Scan(&evt.ID, &evt.OccurredAt)
}

// Query returns audit events matching the filter ordered by
// occurred_at DESC. The implementation builds a dynamic WHERE clause
// — empty filter returns everything (subject to Limit).
func (r *AuditEvents) Query(ctx context.Context, q AuditQuery) ([]*AuditEvent, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 1000 {
		q.Limit = 1000
	}

	clauses := make([]string, 0, 6)
	args := make([]any, 0, 7)
	add := func(clause string, val any) {
		args = append(args, val)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if q.Actor != "" {
		add("actor = $%d", q.Actor)
	}
	if q.Resource != "" {
		add("resource = $%d", q.Resource)
	}
	if q.Action != "" {
		add("action = $%d", q.Action)
	}
	if q.CorrelationID != uuid.Nil {
		add("correlation_id = $%d", q.CorrelationID)
	}
	if !q.Since.IsZero() {
		add("occurred_at >= $%d", q.Since)
	}
	if !q.Until.IsZero() {
		add("occurred_at < $%d", q.Until)
	}

	sql := `
		SELECT id, actor, action, resource, status, correlation_id, metadata, occurred_at
		FROM audit_events`
	if len(clauses) > 0 {
		sql += " WHERE " + clauses[0]
		for _, c := range clauses[1:] {
			sql += " AND " + c
		}
	}
	args = append(args, q.Limit)
	sql += fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d", len(args))

	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: query audit events: %w", err)
	}
	defer rows.Close()

	var out []*AuditEvent
	for rows.Next() {
		var (
			evt          AuditEvent
			metadataJSON []byte
		)
		if err := rows.Scan(
			&evt.ID, &evt.Actor, &evt.Action, &evt.Resource, &evt.Status,
			&evt.CorrelationID, &metadataJSON, &evt.OccurredAt,
		); err != nil {
			return nil, fmt.Errorf("storage: scan audit event: %w", err)
		}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &evt.Metadata); err != nil {
				return nil, fmt.Errorf("storage: unmarshal audit metadata: %w", err)
			}
		}
		out = append(out, &evt)
	}
	return out, rows.Err()
}
