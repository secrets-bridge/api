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

// Environment mirrors a row in the environments table. Every
// environment belongs to exactly one project (FK with ON DELETE
// CASCADE — archiving a project removes its environment rows).
//
// The (project_id, name) tuple is UNIQUE per the schema, so two
// environments inside one project cannot share a name.
type Environment struct {
	ID        uuid.UUID
	ProjectID uuid.UUID
	Name      string
	Type      EnvironmentType
	CreatedAt time.Time
	UpdatedAt time.Time
}

// EnvironmentType is constrained by a CHECK in the schema. Values are
// the BRD §17 set; "other" is the fallback for sites that don't fit
// the dev/uat/staging/prod model (e.g. shared-tooling environments).
type EnvironmentType string

const (
	EnvironmentTypeDev     EnvironmentType = "dev"
	EnvironmentTypeStaging EnvironmentType = "staging"
	EnvironmentTypeUAT     EnvironmentType = "uat"
	EnvironmentTypeProd    EnvironmentType = "prod"
	EnvironmentTypeOther   EnvironmentType = "other"
)

// EnvironmentRepository is the read/write surface for the environments
// table. Same testability split as ProjectRepository — handler tests
// inject a fake.
type EnvironmentRepository interface {
	Create(ctx context.Context, e *Environment) error
	Get(ctx context.Context, id uuid.UUID) (*Environment, error)
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]*Environment, error)
	List(ctx context.Context) ([]*Environment, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// ErrDuplicateName is returned when a Create violates the
// `(project_id, name)` unique index. Handlers map this to HTTP 409.
var ErrDuplicateName = errors.New("storage: duplicate name within project")

// Environments is the Postgres-backed implementation of
// EnvironmentRepository.
type Environments struct {
	pool *Pool
}

// NewEnvironments binds an Environments repository to the given pool.
func NewEnvironments(pool *Pool) *Environments { return &Environments{pool: pool} }

// Create inserts a new environment. ID is assigned by the database
// when e.ID is uuid.Nil; otherwise the caller-supplied UUID is used.
// Returns ErrDuplicateName when (ProjectID, Name) already exists.
func (r *Environments) Create(ctx context.Context, e *Environment) error {
	if e.ProjectID == uuid.Nil {
		return errors.New("storage: environment ProjectID is required")
	}
	if e.Name == "" {
		return errors.New("storage: environment Name is required")
	}
	if e.Type == "" {
		e.Type = EnvironmentTypeOther
	}

	const insertGenerated = `
		INSERT INTO environments (project_id, name, type)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at`
	const insertWithID = `
		INSERT INTO environments (id, project_id, name, type)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at, updated_at`

	var err error
	if e.ID == uuid.Nil {
		err = r.pool.QueryRow(ctx, insertGenerated, e.ProjectID, e.Name, e.Type).
			Scan(&e.ID, &e.CreatedAt, &e.UpdatedAt)
	} else {
		err = r.pool.QueryRow(ctx, insertWithID, e.ID, e.ProjectID, e.Name, e.Type).
			Scan(&e.CreatedAt, &e.UpdatedAt)
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicateName
		}
		return fmt.Errorf("storage: create environment: %w", err)
	}
	return nil
}

// Get fetches one environment by ID. Returns ErrNotFound when no row
// matches.
func (r *Environments) Get(ctx context.Context, id uuid.UUID) (*Environment, error) {
	const q = `
		SELECT id, project_id, name, type, created_at, updated_at
		FROM environments
		WHERE id = $1`
	return scanEnvironment(r.pool.QueryRow(ctx, q, id))
}

// ListByProject returns every environment under a project, ordered by
// name ascending. Empty slice + nil error when the project has no
// environments yet.
func (r *Environments) ListByProject(ctx context.Context, projectID uuid.UUID) ([]*Environment, error) {
	const q = `
		SELECT id, project_id, name, type, created_at, updated_at
		FROM environments
		WHERE project_id = $1
		ORDER BY name ASC`
	rows, err := r.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("storage: list environments by project: %w", err)
	}
	defer rows.Close()

	var out []*Environment
	for rows.Next() {
		e, err := scanEnvironment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// List returns every environment across all projects, ordered by
// project_id then name. Useful for admin listing where the caller
// wants a flat view.
func (r *Environments) List(ctx context.Context) ([]*Environment, error) {
	const q = `
		SELECT id, project_id, name, type, created_at, updated_at
		FROM environments
		ORDER BY project_id ASC, name ASC`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("storage: list environments: %w", err)
	}
	defer rows.Close()

	var out []*Environment
	for rows.Next() {
		e, err := scanEnvironment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Delete removes an environment by ID. ErrNotFound is returned when no
// row exists. FK constraints elsewhere (e.g. user_roles.scope JSON
// references) are NOT cascaded — the caller / service layer must
// reject the delete when downstream rows still reference this
// environment.
func (r *Environments) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM environments WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("storage: delete environment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanEnvironment(row interface {
	Scan(dest ...any) error
}) (*Environment, error) {
	var e Environment
	err := row.Scan(&e.ID, &e.ProjectID, &e.Name, &e.Type, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan environment: %w", err)
	}
	return &e, nil
}
