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

// WorkflowDefinition is an admin-defined approval template.
type WorkflowDefinition struct {
	ID                   uuid.UUID
	Name                 string
	Description          string
	MinApprovers         int
	ApproverRoleID       *uuid.UUID
	WrapTTLCreated       time.Duration
	WrapTTLApproved      time.Duration
	WrapTTLClaimed       time.Duration
	RequestTTL           time.Duration
	RequireJustification bool
	AllowSelfApproval    bool
	NotificationChannels []string
	IsDefault            bool
	Enabled              bool
	IsSystem             bool

	// Slice N1 knobs. fill_ttl_seconds bounds how long Team B has to
	// fill a cross_team request before the sweeper expires it.
	// requires_security_approval flips on the third-vote requirement
	// for cross_team requests in PROD.
	FillTTLSeconds           int
	RequiresSecurityApproval bool

	// R-follow-up #1 (api#118) — opt-in flag exposing this workflow
	// to scoped policy authors (policy.author on /projects/:id/policy-
	// rules). Default false; platform admin flips explicitly via the
	// admin Workflows page. Closes the §5 correction 3 gap from EPIC
	// R's design pass (the defensive client-side filter in Slice R3).
	ScopedPolicyAuthorable bool

	CreatedAt time.Time
	UpdatedAt time.Time
}

// WorkflowRepository is the read/write surface for workflow_definitions.
type WorkflowRepository interface {
	Create(ctx context.Context, w *WorkflowDefinition) error
	Get(ctx context.Context, id uuid.UUID) (*WorkflowDefinition, error)
	GetByName(ctx context.Context, name string) (*WorkflowDefinition, error)
	GetDefault(ctx context.Context) (*WorkflowDefinition, error)
	List(ctx context.Context) ([]*WorkflowDefinition, error)
	// ListScopedPolicyAuthorable returns workflows that platform
	// admin has explicitly opted into the scoped policy authoring
	// surface (R-follow-up #1, api#118). Filtered to enabled = true
	// AND scoped_policy_authorable = true. The R3 author drawer
	// reads this list verbatim — no client-side filtering needed
	// once this method ships.
	ListScopedPolicyAuthorable(ctx context.Context) ([]*WorkflowDefinition, error)
	Update(ctx context.Context, w *WorkflowDefinition) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// Workflows is the Postgres implementation.
type Workflows struct {
	pool *Pool
}

// NewWorkflows binds a Workflows repository to the given pool.
func NewWorkflows(pool *Pool) *Workflows { return &Workflows{pool: pool} }

func (r *Workflows) Create(ctx context.Context, w *WorkflowDefinition) error {
	if w.Name == "" {
		return errors.New("storage: workflow Name is required")
	}
	if w.NotificationChannels == nil {
		w.NotificationChannels = []string{}
	}
	channels, err := json.Marshal(w.NotificationChannels)
	if err != nil {
		return fmt.Errorf("storage: marshal notification channels: %w", err)
	}

	if w.FillTTLSeconds == 0 {
		w.FillTTLSeconds = 86400 // matches the DB DEFAULT for safety
	}
	const q = `
		INSERT INTO workflow_definitions (
		    name, description, min_approvers, approver_role_id,
		    wrap_ttl_created, wrap_ttl_approved, wrap_ttl_claimed,
		    request_ttl, require_justification, allow_self_approval,
		    notification_channels, is_default, enabled, is_system,
		    fill_ttl_seconds, requires_security_approval,
		    scoped_policy_authorable
		) VALUES (
		    $1, $2, $3, $4,
		    $5::interval, $6::interval, $7::interval,
		    $8::interval, $9, $10,
		    $11, $12, $13, $14,
		    $15, $16,
		    $17
		)
		RETURNING id, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		w.Name, w.Description, w.MinApprovers, w.ApproverRoleID,
		intervalString(w.WrapTTLCreated), intervalString(w.WrapTTLApproved),
		intervalString(w.WrapTTLClaimed),
		intervalString(w.RequestTTL), w.RequireJustification, w.AllowSelfApproval,
		channels, w.IsDefault, w.Enabled, w.IsSystem,
		w.FillTTLSeconds, w.RequiresSecurityApproval,
		w.ScopedPolicyAuthorable,
	).Scan(&w.ID, &w.CreatedAt, &w.UpdatedAt)
}

func (r *Workflows) Get(ctx context.Context, id uuid.UUID) (*WorkflowDefinition, error) {
	return scanWorkflow(r.pool.QueryRow(ctx, workflowSelect+` WHERE id = $1`, id))
}

func (r *Workflows) GetByName(ctx context.Context, name string) (*WorkflowDefinition, error) {
	return scanWorkflow(r.pool.QueryRow(ctx, workflowSelect+` WHERE name = $1`, name))
}

func (r *Workflows) GetDefault(ctx context.Context) (*WorkflowDefinition, error) {
	return scanWorkflow(r.pool.QueryRow(ctx, workflowSelect+` WHERE is_default = true`))
}

func (r *Workflows) List(ctx context.Context) ([]*WorkflowDefinition, error) {
	rows, err := r.pool.Query(ctx, workflowSelect+` ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("storage: list workflows: %w", err)
	}
	defer rows.Close()

	var out []*WorkflowDefinition
	for rows.Next() {
		w, err := scanWorkflow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ListScopedPolicyAuthorable returns the workflows platform admin
// has opted into the scoped policy authoring surface. Predicate matches
// the partial index from migration 0035 verbatim.
func (r *Workflows) ListScopedPolicyAuthorable(ctx context.Context) ([]*WorkflowDefinition, error) {
	rows, err := r.pool.Query(ctx, workflowSelect+`
		WHERE enabled = true AND scoped_policy_authorable = true
		ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("storage: list scoped-authorable workflows: %w", err)
	}
	defer rows.Close()

	var out []*WorkflowDefinition
	for rows.Next() {
		w, err := scanWorkflow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (r *Workflows) Update(ctx context.Context, w *WorkflowDefinition) error {
	if w.NotificationChannels == nil {
		w.NotificationChannels = []string{}
	}
	channels, err := json.Marshal(w.NotificationChannels)
	if err != nil {
		return fmt.Errorf("storage: marshal notification channels: %w", err)
	}
	if w.FillTTLSeconds == 0 {
		w.FillTTLSeconds = 86400
	}
	const q = `
		UPDATE workflow_definitions SET
		    description = $2,
		    min_approvers = $3,
		    approver_role_id = $4,
		    wrap_ttl_created = $5::interval,
		    wrap_ttl_approved = $6::interval,
		    wrap_ttl_claimed = $7::interval,
		    request_ttl = $8::interval,
		    require_justification = $9,
		    allow_self_approval = $10,
		    notification_channels = $11,
		    enabled = $12,
		    fill_ttl_seconds = $13,
		    requires_security_approval = $14,
		    scoped_policy_authorable = $15
		WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q,
		w.ID, w.Description, w.MinApprovers, w.ApproverRoleID,
		intervalString(w.WrapTTLCreated), intervalString(w.WrapTTLApproved),
		intervalString(w.WrapTTLClaimed),
		intervalString(w.RequestTTL), w.RequireJustification, w.AllowSelfApproval,
		channels, w.Enabled,
		w.FillTTLSeconds, w.RequiresSecurityApproval,
		w.ScopedPolicyAuthorable,
	)
	if err != nil {
		return fmt.Errorf("storage: update workflow: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Workflows) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM workflow_definitions WHERE id = $1 AND is_system = false`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("storage: delete workflow: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	w, getErr := r.Get(ctx, id)
	if getErr != nil {
		return getErr
	}
	if w.IsSystem {
		return ErrSystemRow
	}
	return ErrNotFound
}

const workflowSelect = `
	SELECT id, name, description, min_approvers, approver_role_id,
	       EXTRACT(EPOCH FROM wrap_ttl_created)::bigint,
	       EXTRACT(EPOCH FROM wrap_ttl_approved)::bigint,
	       EXTRACT(EPOCH FROM wrap_ttl_claimed)::bigint,
	       EXTRACT(EPOCH FROM request_ttl)::bigint,
	       require_justification, allow_self_approval,
	       notification_channels, is_default, enabled, is_system,
	       fill_ttl_seconds, requires_security_approval,
	       scoped_policy_authorable,
	       created_at, updated_at
	FROM workflow_definitions`

func scanWorkflow(row interface {
	Scan(dest ...any) error
}) (*WorkflowDefinition, error) {
	var (
		w                                    WorkflowDefinition
		approverRoleID                       *uuid.UUID
		wrapCreated, wrapApproved, wrapClaim int64
		requestTTL                           int64
		channelsRaw                          []byte
	)
	err := row.Scan(
		&w.ID, &w.Name, &w.Description, &w.MinApprovers, &approverRoleID,
		&wrapCreated, &wrapApproved, &wrapClaim, &requestTTL,
		&w.RequireJustification, &w.AllowSelfApproval,
		&channelsRaw, &w.IsDefault, &w.Enabled, &w.IsSystem,
		&w.FillTTLSeconds, &w.RequiresSecurityApproval,
		&w.ScopedPolicyAuthorable,
		&w.CreatedAt, &w.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan workflow: %w", err)
	}
	w.ApproverRoleID = approverRoleID
	w.WrapTTLCreated = time.Duration(wrapCreated) * time.Second
	w.WrapTTLApproved = time.Duration(wrapApproved) * time.Second
	w.WrapTTLClaimed = time.Duration(wrapClaim) * time.Second
	w.RequestTTL = time.Duration(requestTTL) * time.Second
	if len(channelsRaw) > 0 {
		if err := json.Unmarshal(channelsRaw, &w.NotificationChannels); err != nil {
			return nil, fmt.Errorf("storage: unmarshal notification channels: %w", err)
		}
	}
	return &w, nil
}

// intervalString renders a Go duration as Postgres interval input.
func intervalString(d time.Duration) string {
	return fmt.Sprintf("%d seconds", int64(d.Seconds()))
}
