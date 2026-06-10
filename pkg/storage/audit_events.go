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
	AppendTx(ctx context.Context, tx pgx.Tx, evt *AuditEvent) error
	Query(ctx context.Context, q AuditQuery) ([]*AuditEvent, error)
	// ListPolicyRuleHistory returns audit events for a single policy
	// rule ordered ASC for chain reconstruction. Filters resource =
	// 'policy_rule:<uuid>' AND action ∈ {policy.create/.update/.delete}
	// PLUS the R-follow-up #3 pre-cutover names
	// (policy.created_for_scope / .updated_for_scope /
	// .deleted_for_scope) for compatibility — slice-1c's service
	// layer remaps the legacy names before returning to the SPA.
	//
	// ORDER BY occurred_at ASC, id ASC — stable tie-break for
	// same-instant events (R-follow-up #5 §2 OQ-1).
	//
	// limit caps the returned row count; the returned `hasMore` flag
	// is true when there's at least one more event past the limit.
	// limit ≤ 0 → DefaultPolicyHistoryLimit; cap MaxPolicyHistoryLimit.
	ListPolicyRuleHistory(
		ctx context.Context,
		ruleID uuid.UUID,
		limit int,
	) (events []*AuditEvent, hasMore bool, err error)
}

// R-follow-up #5 (api#133) — limit bounds for the policy history
// endpoint. Default matches the SPA's initial-page-size; the cap
// guards against operator typo requests (e.g. limit=10000000).
const (
	DefaultPolicyHistoryLimit = 50
	MaxPolicyHistoryLimit     = 500
)

// Policy audit action names — normalized (R-follow-up #3 §4 C2) and
// legacy (pre-cutover, EPIC R + R-follow-up #1). The history WHERE
// clause includes BOTH sets per R-follow-up #5 §2 D7; the service
// layer remaps legacy → normalized before returning to the SPA.
var policyMutationActions = []string{
	"policy.create", "policy.update", "policy.delete",
	"policy.created_for_scope", "policy.updated_for_scope", "policy.deleted_for_scope",
}

// AuditEvents is the Postgres implementation of AuditEventRepository.
type AuditEvents struct {
	pool *Pool
}

// NewAuditEvents binds an AuditEvents repository to the given pool.
func NewAuditEvents(pool *Pool) *AuditEvents { return &AuditEvents{pool: pool} }

// AppendTx is the transactional sibling of Append. Inserts the event
// using the caller's pgx.Tx so audit emission can ride the same
// transaction as a domain mutation (used by teams.UpdateWithLineageAudit
// for R-follow-up #3's transactional lineage-change audit per §2 C6).
//
// If the caller commits → both the domain UPDATE and the audit row
// commit. If the caller rolls back (e.g. audit insert failed) → both
// roll back together.
func (r *AuditEvents) AppendTx(ctx context.Context, tx pgx.Tx, evt *AuditEvent) error {
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
	row := tx.QueryRow(ctx, q,
		evt.Actor, evt.Action, evt.Resource, evt.Status, evt.CorrelationID, metadataJSON)
	return row.Scan(&evt.ID, &evt.OccurredAt)
}

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

// ListPolicyRuleHistory implements AuditEventRepository.
// See the interface doc-comment for the contract.
func (r *AuditEvents) ListPolicyRuleHistory(
	ctx context.Context,
	ruleID uuid.UUID,
	limit int,
) ([]*AuditEvent, bool, error) {
	if limit <= 0 {
		limit = DefaultPolicyHistoryLimit
	}
	if limit > MaxPolicyHistoryLimit {
		limit = MaxPolicyHistoryLimit
	}

	// LIMIT $3 + 1 is the standard "is there at least one more?" trick.
	// Fetch one row over the limit; if we got it, truncate + flag.
	rows, err := r.pool.Query(ctx, `
		SELECT id, actor, action, resource, status, correlation_id, metadata, occurred_at
		  FROM audit_events
		 WHERE resource = $1
		   AND action = ANY($2)
		 ORDER BY occurred_at ASC, id ASC
		 LIMIT $3
	`, "policy_rule:"+ruleID.String(), policyMutationActions, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("storage: list policy rule history: %w", err)
	}
	defer rows.Close()

	out := make([]*AuditEvent, 0, limit)
	for rows.Next() {
		var (
			evt          AuditEvent
			metadataJSON []byte
		)
		if err := rows.Scan(
			&evt.ID, &evt.Actor, &evt.Action, &evt.Resource, &evt.Status,
			&evt.CorrelationID, &metadataJSON, &evt.OccurredAt,
		); err != nil {
			return nil, false, fmt.Errorf("storage: scan policy history event: %w", err)
		}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &evt.Metadata); err != nil {
				return nil, false, fmt.Errorf("storage: unmarshal policy history metadata: %w", err)
			}
		}
		out = append(out, &evt)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}
