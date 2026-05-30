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

// Operations recognised by the project_secrets.allowed_ops schema CHECK.
// Kept in sync with the constraint in 0014_project_secrets.up.sql.
const (
	OpRead     = "read"
	OpPatch    = "patch"
	OpDiscover = "discover"
)

// ProjectSecret is one binding in the project_secrets join table. A
// nil AllowedKeys slice means "every key the secret exposes is
// allowed for this project"; a non-nil empty slice means "no keys
// allowed" (which would make the binding meaningless — reject in the
// repository).
type ProjectSecret struct {
	ProjectID   uuid.UUID
	SecretID    uuid.UUID
	AllowedKeys []string // nil = all
	AllowedOps  []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   string
}

// ErrEmptyAllowedKeys is returned when a caller hands the repository
// a non-nil but empty AllowedKeys slice. The caller almost certainly
// meant nil (=all keys); failing loud prevents an accidental "block
// everything" binding.
var ErrEmptyAllowedKeys = errors.New("storage: allowed_keys must be nil (all) or non-empty (allowlist)")

// ErrEmptyAllowedOps is returned when AllowedOps is empty. Defaults
// land at the handler layer; the repository refuses zero-length ops.
var ErrEmptyAllowedOps = errors.New("storage: allowed_ops must be non-empty")

// ProjectSecretRepository is the read/write surface for
// project_secrets. The interface keeps handler tests injectable.
type ProjectSecretRepository interface {
	// Bind creates a new (project, secret) binding. ErrAlreadyExists
	// (mapped from 23505 unique_violation) is returned when one
	// already exists.
	Bind(ctx context.Context, b *ProjectSecret) error

	// Update overwrites AllowedKeys + AllowedOps on an existing
	// binding. ErrNotFound when no binding exists for the pair.
	Update(ctx context.Context, projectID, secretID uuid.UUID, allowedKeys []string, allowedOps []string) error

	// Unbind removes the binding. ErrNotFound when no binding exists.
	Unbind(ctx context.Context, projectID, secretID uuid.UUID) error

	// Get returns a single binding. ErrNotFound when absent — the
	// submit-validation hot path uses this to refuse out-of-scope
	// requests cheaply.
	Get(ctx context.Context, projectID, secretID uuid.UUID) (*ProjectSecret, error)

	// ListByProject returns all bindings owned by a project.
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]*ProjectSecret, error)

	// ListSecretIDsForProjects returns the set of secret IDs that
	// any of the given projects has bound. Drives the catalog filter
	// (GET /secrets) for non-admin callers.
	ListSecretIDsForProjects(ctx context.Context, projectIDs []uuid.UUID) ([]uuid.UUID, error)
}

// ErrAlreadyExists wraps a 23505 (unique_violation) on a binding INSERT.
var ErrAlreadyExists = errors.New("storage: binding already exists")

// ProjectSecrets is the Postgres-backed implementation.
type ProjectSecrets struct {
	pool *Pool
}

// NewProjectSecrets binds the repository to the given pool.
func NewProjectSecrets(pool *Pool) *ProjectSecrets { return &ProjectSecrets{pool: pool} }

// Bind inserts a new binding. AllowedKeys may be nil (=all keys
// allowed); a non-nil empty slice is rejected as a safety guard.
func (r *ProjectSecrets) Bind(ctx context.Context, b *ProjectSecret) error {
	if b.ProjectID == uuid.Nil || b.SecretID == uuid.Nil {
		return errors.New("storage: project_id + secret_id required")
	}
	if b.AllowedKeys != nil && len(b.AllowedKeys) == 0 {
		return ErrEmptyAllowedKeys
	}
	if len(b.AllowedOps) == 0 {
		return ErrEmptyAllowedOps
	}

	const q = `
		INSERT INTO project_secrets (
		    project_id, secret_id, allowed_keys, allowed_ops, created_by
		) VALUES ($1, $2, $3, $4, NULLIF($5, ''))
		RETURNING created_at, updated_at`

	err := r.pool.QueryRow(ctx, q,
		b.ProjectID, b.SecretID, b.AllowedKeys, b.AllowedOps, b.CreatedBy,
	).Scan(&b.CreatedAt, &b.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyExists
		}
		return fmt.Errorf("storage: bind project secret: %w", err)
	}
	return nil
}

// Update rewrites AllowedKeys + AllowedOps on an existing row.
func (r *ProjectSecrets) Update(ctx context.Context, projectID, secretID uuid.UUID, allowedKeys []string, allowedOps []string) error {
	if allowedKeys != nil && len(allowedKeys) == 0 {
		return ErrEmptyAllowedKeys
	}
	if len(allowedOps) == 0 {
		return ErrEmptyAllowedOps
	}

	const q = `
		UPDATE project_secrets
		SET allowed_keys = $1, allowed_ops = $2
		WHERE project_id = $3 AND secret_id = $4`
	tag, err := r.pool.Exec(ctx, q, allowedKeys, allowedOps, projectID, secretID)
	if err != nil {
		return fmt.Errorf("storage: update project secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Unbind drops the (project, secret) row.
func (r *ProjectSecrets) Unbind(ctx context.Context, projectID, secretID uuid.UUID) error {
	const q = `DELETE FROM project_secrets WHERE project_id = $1 AND secret_id = $2`
	tag, err := r.pool.Exec(ctx, q, projectID, secretID)
	if err != nil {
		return fmt.Errorf("storage: unbind project secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Get returns the binding for one (project, secret) pair.
func (r *ProjectSecrets) Get(ctx context.Context, projectID, secretID uuid.UUID) (*ProjectSecret, error) {
	const q = `
		SELECT project_id, secret_id, allowed_keys, allowed_ops,
		       created_at, updated_at, COALESCE(created_by, '')
		FROM project_secrets
		WHERE project_id = $1 AND secret_id = $2`
	row := r.pool.QueryRow(ctx, q, projectID, secretID)
	return scanProjectSecret(row)
}

// ListByProject returns every binding for the project, ordered by
// the secret's creation time.
func (r *ProjectSecrets) ListByProject(ctx context.Context, projectID uuid.UUID) ([]*ProjectSecret, error) {
	const q = `
		SELECT project_id, secret_id, allowed_keys, allowed_ops,
		       created_at, updated_at, COALESCE(created_by, '')
		FROM project_secrets
		WHERE project_id = $1
		ORDER BY created_at ASC`
	rows, err := r.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("storage: list project secrets: %w", err)
	}
	defer rows.Close()

	var out []*ProjectSecret
	for rows.Next() {
		b, err := scanProjectSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListSecretIDsForProjects returns the set of secret IDs that any of
// the given projects has bound. Empty projectIDs slice returns an
// empty result (so the catalog filter intersects to "no rows" rather
// than "all rows" — least-privilege default).
func (r *ProjectSecrets) ListSecretIDsForProjects(ctx context.Context, projectIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(projectIDs) == 0 {
		return []uuid.UUID{}, nil
	}
	const q = `
		SELECT DISTINCT secret_id
		FROM project_secrets
		WHERE project_id = ANY($1)`
	rows, err := r.pool.Query(ctx, q, projectIDs)
	if err != nil {
		return nil, fmt.Errorf("storage: list secret ids for projects: %w", err)
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("storage: scan secret id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// scanProjectSecret centralises the column order.
func scanProjectSecret(row interface {
	Scan(dest ...any) error
}) (*ProjectSecret, error) {
	var b ProjectSecret
	err := row.Scan(
		&b.ProjectID, &b.SecretID, &b.AllowedKeys, &b.AllowedOps,
		&b.CreatedAt, &b.UpdatedAt, &b.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan project secret: %w", err)
	}
	return &b, nil
}
