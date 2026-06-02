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

// PolicyRule maps a request scope to the workflow that should govern
// it. Resolution: PolicyEngine walks enabled rules in priority DESC
// order; the first whose selector fully matches the scope wins.
//
// Slice L2 fields carry the access DECISION (separate from the
// approval CEREMONY which stays on the workflow):
//
//   - DirectRevealAllowed: when true AND the matched environment is
//     non_prod, the API bypasses access_requests and issues a
//     single-shot wrap. The PolicyEngine ZEROES this whenever the
//     scope's environment.kind is 'prod', regardless of what the
//     operator wrote.
//   - RequiresMFA: when true, the API attaches RequireFreshMFA
//     middleware on the matched route.
//   - RevealTTLSeconds: server-enforced reveal-session/wrap TTL.
//     CHECK constraint pins to 10..300.
type PolicyRule struct {
	ID                  uuid.UUID
	Name                string
	Selector            map[string]any
	WorkflowID          uuid.UUID
	Priority            int
	Enabled             bool
	IsSystem            bool
	DirectRevealAllowed bool
	RequiresMFA         bool
	RevealTTLSeconds    int
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// PolicyRepository is the read/write surface for policy_rules.
type PolicyRepository interface {
	Create(ctx context.Context, p *PolicyRule) error
	Get(ctx context.Context, id uuid.UUID) (*PolicyRule, error)
	List(ctx context.Context) ([]*PolicyRule, error)
	// ListEnabledOrderedByPriority returns enabled rules ordered for
	// resolution: highest priority first, then oldest first as
	// tiebreaker. PolicyEngine.Resolve iterates this list.
	ListEnabledOrderedByPriority(ctx context.Context) ([]*PolicyRule, error)
	Update(ctx context.Context, p *PolicyRule) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// Policies is the Postgres implementation.
type Policies struct {
	pool *Pool
}

// NewPolicies binds a Policies repository to the given pool.
func NewPolicies(pool *Pool) *Policies { return &Policies{pool: pool} }

func (r *Policies) Create(ctx context.Context, p *PolicyRule) error {
	if p.Name == "" {
		return errors.New("storage: policy Name is required")
	}
	if p.WorkflowID == uuid.Nil {
		return errors.New("storage: policy WorkflowID is required")
	}
	if p.Selector == nil {
		p.Selector = map[string]any{}
	}
	selector, err := json.Marshal(p.Selector)
	if err != nil {
		return fmt.Errorf("storage: marshal policy selector: %w", err)
	}
	// Defaults that mirror the schema so a Create with zero values
	// for the L2 columns still lands a usable row. RevealTTLSeconds=0
	// would be rejected by the CHECK; default to 60 (the schema default
	// too) so the test column matches what a bare INSERT would produce.
	if p.RevealTTLSeconds == 0 {
		p.RevealTTLSeconds = 60
	}
	const q = `
		INSERT INTO policy_rules (
			name, selector, workflow_id, priority, enabled, is_system,
			direct_reveal_allowed, requires_mfa, reveal_ttl_seconds
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		p.Name, selector, p.WorkflowID, p.Priority, p.Enabled, p.IsSystem,
		p.DirectRevealAllowed, p.RequiresMFA, p.RevealTTLSeconds,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
}

func (r *Policies) Get(ctx context.Context, id uuid.UUID) (*PolicyRule, error) {
	return scanPolicy(r.pool.QueryRow(ctx, policySelect+` WHERE id = $1`, id))
}

func (r *Policies) List(ctx context.Context) ([]*PolicyRule, error) {
	rows, err := r.pool.Query(ctx, policySelect+` ORDER BY priority DESC, created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("storage: list policies: %w", err)
	}
	defer rows.Close()

	var out []*PolicyRule
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *Policies) ListEnabledOrderedByPriority(ctx context.Context) ([]*PolicyRule, error) {
	rows, err := r.pool.Query(ctx, policySelect+`
		WHERE enabled = true
		ORDER BY priority DESC, created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("storage: list enabled policies: %w", err)
	}
	defer rows.Close()

	var out []*PolicyRule
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *Policies) Update(ctx context.Context, p *PolicyRule) error {
	if p.Selector == nil {
		p.Selector = map[string]any{}
	}
	selector, err := json.Marshal(p.Selector)
	if err != nil {
		return fmt.Errorf("storage: marshal policy selector: %w", err)
	}
	if p.RevealTTLSeconds == 0 {
		p.RevealTTLSeconds = 60
	}
	const q = `
		UPDATE policy_rules
		SET name = $2, selector = $3, workflow_id = $4, priority = $5, enabled = $6,
		    direct_reveal_allowed = $7, requires_mfa = $8, reveal_ttl_seconds = $9
		WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q,
		p.ID, p.Name, selector, p.WorkflowID, p.Priority, p.Enabled,
		p.DirectRevealAllowed, p.RequiresMFA, p.RevealTTLSeconds,
	)
	if err != nil {
		return fmt.Errorf("storage: update policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Policies) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM policy_rules WHERE id = $1 AND is_system = false`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("storage: delete policy: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	p, getErr := r.Get(ctx, id)
	if getErr != nil {
		return getErr
	}
	if p.IsSystem {
		return ErrSystemRow
	}
	return ErrNotFound
}

const policySelect = `
	SELECT id, name, selector, workflow_id, priority, enabled, is_system,
	       direct_reveal_allowed, requires_mfa, reveal_ttl_seconds,
	       created_at, updated_at
	FROM policy_rules`

func scanPolicy(row interface {
	Scan(dest ...any) error
}) (*PolicyRule, error) {
	var (
		p           PolicyRule
		selectorRaw []byte
	)
	err := row.Scan(
		&p.ID, &p.Name, &selectorRaw, &p.WorkflowID, &p.Priority, &p.Enabled, &p.IsSystem,
		&p.DirectRevealAllowed, &p.RequiresMFA, &p.RevealTTLSeconds,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan policy: %w", err)
	}
	if len(selectorRaw) > 0 {
		if err := json.Unmarshal(selectorRaw, &p.Selector); err != nil {
			return nil, fmt.Errorf("storage: unmarshal policy selector: %w", err)
		}
	}
	return &p, nil
}
