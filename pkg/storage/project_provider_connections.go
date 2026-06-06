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

// ProjectProviderConnectionBinding mirrors a row in the
// project_provider_connections join table — the N:M binding between
// projects (+ optional environments) and provider connections.
//
// environment_id is nullable for project-wide bindings. The dropdown
// query returns BOTH env-specific bindings (when env_id is supplied)
// AND project-wide bindings (env_id IS NULL).
type ProjectProviderConnectionBinding struct {
	ID                   uuid.UUID
	ProjectID            uuid.UUID
	EnvironmentID        *uuid.UUID
	ProviderConnectionID uuid.UUID
	Purpose              ProjectProviderConnectionPurpose
	CreatedAt            time.Time
	UpdatedAt            time.Time
	CreatedBy            string
}

// ProjectProviderConnectionPurpose is constrained by a CHECK on the
// schema. v1 ships only 'destination'; future purposes ('source',
// 'discover_target', …) extend the CHECK without a column change.
type ProjectProviderConnectionPurpose string

const (
	ProjectProviderConnectionPurposeDestination ProjectProviderConnectionPurpose = "destination"
)

// ProjectProviderConnectionBindingInput is what the service layer
// hands the repository on Bind.
type ProjectProviderConnectionBindingInput struct {
	ProjectID            uuid.UUID
	EnvironmentID        *uuid.UUID
	ProviderConnectionID uuid.UUID
	Purpose              ProjectProviderConnectionPurpose
	CreatedBy            string
}

// ProviderConnectionSummary is the value-free shape returned by
// ListForProjectEnv. The dropdown the developer sees on the cross-
// team submit drawer (Slice N5 / future P5) hydrates from this — no
// scope, no auth_method, no discovery fields, no timestamps. Just
// enough to render `name (type)` in a <select>.
type ProviderConnectionSummary struct {
	ID   uuid.UUID
	Name string
	Type ProviderConnectionType
}

// ProviderConnectionBindingRepository is the read/write surface for
// the project_provider_connections join table.
type ProviderConnectionBindingRepository interface {
	Bind(ctx context.Context, in ProjectProviderConnectionBindingInput) (*ProjectProviderConnectionBinding, error)
	Unbind(ctx context.Context, bindingID uuid.UUID) error
	GetBinding(ctx context.Context, bindingID uuid.UUID) (*ProjectProviderConnectionBinding, error)
	ListForConnection(ctx context.Context, connectionID uuid.UUID) ([]*ProjectProviderConnectionBinding, error)

	// ListForProjectEnv returns active connections bound to the
	// project either env-specifically (b.environment_id = envID)
	// OR project-wide (b.environment_id IS NULL). envID may be
	// uuid.Nil to filter to project-wide only. Used by the developer
	// dropdown — strictly sanitized projection.
	ListForProjectEnv(ctx context.Context, projectID uuid.UUID, envID uuid.UUID) ([]ProviderConnectionSummary, error)
}

// ProjectProviderConnections is the Postgres implementation.
type ProjectProviderConnections struct {
	pool *Pool
}

// NewProjectProviderConnections binds the repository to a pool.
func NewProjectProviderConnections(pool *Pool) *ProjectProviderConnections {
	return &ProjectProviderConnections{pool: pool}
}

// Compile-time interface check.
var _ ProviderConnectionBindingRepository = (*ProjectProviderConnections)(nil)

// Sentinels — declared here so the package surface is the single
// source of truth. The service layer maps to HTTP codes in P3.
var (
	ErrBindingExists   = errors.New("storage: provider_connection binding already exists")
	ErrBindingNotFound = errors.New("storage: provider_connection binding not found")
)

// Bind inserts a new binding row. UNIQUE violations (from either of
// the two partial unique indexes — env-specific or project-wide) map
// to ErrBindingExists. FK violations on project_id / environment_id /
// provider_connection_id surface as wrapped pg errors.
func (r *ProjectProviderConnections) Bind(ctx context.Context, in ProjectProviderConnectionBindingInput) (*ProjectProviderConnectionBinding, error) {
	purpose := in.Purpose
	if purpose == "" {
		purpose = ProjectProviderConnectionPurposeDestination
	}
	const q = `
INSERT INTO project_provider_connections
	(project_id, environment_id, provider_connection_id, purpose, created_by)
VALUES ($1, $2, $3, $4, NULLIF($5, ''))
RETURNING id, project_id, environment_id, provider_connection_id,
	purpose, created_at, updated_at, created_by
`
	row := r.pool.QueryRow(ctx, q,
		in.ProjectID, in.EnvironmentID, in.ProviderConnectionID, purpose, in.CreatedBy,
	)
	b, err := scanBinding(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrBindingExists
		}
		return nil, fmt.Errorf("storage: bind provider_connection: %w", err)
	}
	return b, nil
}

// Unbind removes a binding by its id.
func (r *ProjectProviderConnections) Unbind(ctx context.Context, bindingID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM project_provider_connections WHERE id = $1`, bindingID)
	if err != nil {
		return fmt.Errorf("storage: unbind provider_connection: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrBindingNotFound
	}
	return nil
}

// GetBinding returns a single binding row by id.
func (r *ProjectProviderConnections) GetBinding(ctx context.Context, bindingID uuid.UUID) (*ProjectProviderConnectionBinding, error) {
	const q = `
SELECT id, project_id, environment_id, provider_connection_id,
	purpose, created_at, updated_at, created_by
FROM project_provider_connections
WHERE id = $1
`
	b, err := scanBinding(r.pool.QueryRow(ctx, q, bindingID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrBindingNotFound
		}
		return nil, fmt.Errorf("storage: get binding: %w", err)
	}
	return b, nil
}

// ListForConnection returns every binding referencing the given
// provider connection. Used by the admin UI's edit drawer to render
// the per-connection bindings sub-panel.
func (r *ProjectProviderConnections) ListForConnection(ctx context.Context, connectionID uuid.UUID) ([]*ProjectProviderConnectionBinding, error) {
	const q = `
SELECT id, project_id, environment_id, provider_connection_id,
	purpose, created_at, updated_at, created_by
FROM project_provider_connections
WHERE provider_connection_id = $1
ORDER BY project_id, environment_id NULLS LAST, created_at
`
	rows, err := r.pool.Query(ctx, q, connectionID)
	if err != nil {
		return nil, fmt.Errorf("storage: list bindings for connection: %w", err)
	}
	defer rows.Close()
	out := []*ProjectProviderConnectionBinding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, fmt.Errorf("storage: scan binding: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListForProjectEnv returns active connections bound to the project
// either env-specifically (b.environment_id = envID) OR project-wide
// (b.environment_id IS NULL).
//
// Pass envID = uuid.Nil to filter to project-wide only — useful for
// admin "what connections are available across all envs" views; the
// developer dropdown always passes a real envID.
//
// Returns sanitized ProviderConnectionSummary{id, name, type} — NO
// scope, NO auth_method, NO discovery fields, NO timestamps. The
// query joins on the partial UNIQUE indexes for both env-specific
// and project-wide bindings.
func (r *ProjectProviderConnections) ListForProjectEnv(ctx context.Context, projectID uuid.UUID, envID uuid.UUID) ([]ProviderConnectionSummary, error) {
	var q string
	var args []any
	if envID == uuid.Nil {
		// Project-wide only.
		q = `
SELECT DISTINCT pc.id, pc.name, pc.type
FROM provider_connections pc
JOIN project_provider_connections b
	ON b.provider_connection_id = pc.id
WHERE pc.status = 'active'
  AND b.project_id = $1
  AND b.environment_id IS NULL
  AND b.purpose = 'destination'
ORDER BY pc.name
`
		args = []any{projectID}
	} else {
		// Env-specific OR project-wide.
		q = `
SELECT DISTINCT pc.id, pc.name, pc.type
FROM provider_connections pc
JOIN project_provider_connections b
	ON b.provider_connection_id = pc.id
WHERE pc.status = 'active'
  AND b.project_id = $1
  AND (b.environment_id = $2 OR b.environment_id IS NULL)
  AND b.purpose = 'destination'
ORDER BY pc.name
`
		args = []any{projectID, envID}
	}
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list for project/env: %w", err)
	}
	defer rows.Close()
	out := []ProviderConnectionSummary{}
	for rows.Next() {
		var s ProviderConnectionSummary
		if err := rows.Scan(&s.ID, &s.Name, &s.Type); err != nil {
			return nil, fmt.Errorf("storage: scan summary: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// scanBinding reads from a pgx Row / Rows into a
// *ProjectProviderConnectionBinding.
func scanBinding(row interface {
	Scan(dest ...any) error
}) (*ProjectProviderConnectionBinding, error) {
	var b ProjectProviderConnectionBinding
	var envID *uuid.UUID
	var createdBy *string
	if err := row.Scan(
		&b.ID, &b.ProjectID, &envID, &b.ProviderConnectionID,
		&b.Purpose, &b.CreatedAt, &b.UpdatedAt, &createdBy,
	); err != nil {
		return nil, err
	}
	b.EnvironmentID = envID
	if createdBy != nil {
		b.CreatedBy = *createdBy
	}
	return &b, nil
}
