package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrApprovalExists is returned by Append when the (request_id,
// approver_id) unique index rejects a duplicate vote. The service
// layer maps this to ErrDuplicateVote.
var ErrApprovalExists = errors.New("storage: approver already voted on this request")

// Approval is a single approve/reject decision against a request.
// Separation of duties (requester ≠ approver) is enforced at the
// service layer so multi-approver flows can layer on without a
// schema rewrite.
type Approval struct {
	ID         uuid.UUID
	RequestID  uuid.UUID
	ApproverID string
	Decision   ApprovalDecision
	Comment    string
	CreatedAt  time.Time
}

// ApprovalDecision is constrained by the schema CHECK.
type ApprovalDecision string

const (
	ApprovalDecisionApprove ApprovalDecision = "approve"
	ApprovalDecisionReject  ApprovalDecision = "reject"
)

// ApprovalCounts summarizes votes on a single request.
type ApprovalCounts struct {
	Approves int
	Rejects  int
}

// ApprovalRepository is the read/write surface.
type ApprovalRepository interface {
	Append(ctx context.Context, a *Approval) error
	ListByRequest(ctx context.Context, requestID uuid.UUID) ([]*Approval, error)
	Counts(ctx context.Context, requestID uuid.UUID) (ApprovalCounts, error)
}

// Approvals is the Postgres implementation.
type Approvals struct {
	pool *Pool
}

// NewApprovals binds a repository to the pool.
func NewApprovals(pool *Pool) *Approvals { return &Approvals{pool: pool} }

func (r *Approvals) Append(ctx context.Context, a *Approval) error {
	if a.RequestID == uuid.Nil {
		return errors.New("storage: RequestID is required")
	}
	if a.ApproverID == "" {
		return errors.New("storage: ApproverID is required")
	}
	if a.Decision != ApprovalDecisionApprove && a.Decision != ApprovalDecisionReject {
		return fmt.Errorf("storage: invalid decision %q", a.Decision)
	}
	const q = `
		INSERT INTO approvals (request_id, approver_id, decision, comment)
		VALUES ($1, $2, $3, NULLIF($4, ''))
		RETURNING id, created_at`
	err := r.pool.QueryRow(ctx, q,
		a.RequestID, a.ApproverID, a.Decision, a.Comment,
	).Scan(&a.ID, &a.CreatedAt)
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		// approvals_one_decision_per_approver violated.
		return ErrApprovalExists
	}
	return fmt.Errorf("storage: append approval: %w", err)
}

func (r *Approvals) ListByRequest(ctx context.Context, requestID uuid.UUID) ([]*Approval, error) {
	const q = `
		SELECT id, request_id, approver_id, decision, COALESCE(comment, ''), created_at
		FROM approvals
		WHERE request_id = $1
		ORDER BY created_at ASC`
	rows, err := r.pool.Query(ctx, q, requestID)
	if err != nil {
		return nil, fmt.Errorf("storage: list approvals: %w", err)
	}
	defer rows.Close()
	var out []*Approval
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.RequestID, &a.ApproverID, &a.Decision, &a.Comment, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("storage: scan approval: %w", err)
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

func (r *Approvals) Counts(ctx context.Context, requestID uuid.UUID) (ApprovalCounts, error) {
	const q = `
		SELECT
			COUNT(*) FILTER (WHERE decision = 'approve'),
			COUNT(*) FILTER (WHERE decision = 'reject')
		FROM approvals
		WHERE request_id = $1`
	var c ApprovalCounts
	err := r.pool.QueryRow(ctx, q, requestID).Scan(&c.Approves, &c.Rejects)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c, nil
		}
		return c, fmt.Errorf("storage: count approvals: %w", err)
	}
	return c, nil
}
