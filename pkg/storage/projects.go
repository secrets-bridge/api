package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Project mirrors a row in the projects table. The mutable fields are
// safe to log; the table has no secret-bearing columns by design.
type Project struct {
	ID          uuid.UUID
	Name        string
	OwnerTeamID string // empty when unset
	Status      ProjectStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ProjectStatus is constrained by a CHECK in the schema.
type ProjectStatus string

const (
	ProjectStatusActive   ProjectStatus = "active"
	ProjectStatusArchived ProjectStatus = "archived"
)

// ErrNotFound is returned by repository methods that look up a single
// row when no row matches. Wraps pgx.ErrNoRows so callers can branch on
// either via errors.Is.
var ErrNotFound = errors.New("storage: not found")

// ProjectRepository is the read/write surface for the projects table.
// The interface is exposed (not just the Postgres implementation) so
// handler tests can inject a fake; per FR-04 the fake should also
// refuse to store secret values.
type ProjectRepository interface {
	Create(ctx context.Context, p *Project) error
	Get(ctx context.Context, id uuid.UUID) (*Project, error)
	GetByName(ctx context.Context, name string) (*Project, error)
	List(ctx context.Context) ([]*Project, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status ProjectStatus) error
}

// Projects is the Postgres-backed implementation of ProjectRepository.
type Projects struct {
	pool *Pool
}

// NewProjects binds a Projects repository to the given pool.
func NewProjects(pool *Pool) *Projects { return &Projects{pool: pool} }

// Create inserts a new project. ID is assigned by the database when
// p.ID is uuid.Nil; otherwise the caller-supplied UUID is used.
func (r *Projects) Create(ctx context.Context, p *Project) error {
	if p.Name == "" {
		return errors.New("storage: project Name is required")
	}
	if p.Status == "" {
		p.Status = ProjectStatusActive
	}

	const insertGenerated = `
		INSERT INTO projects (name, owner_team_id, status)
		VALUES ($1, NULLIF($2, ''), $3)
		RETURNING id, created_at, updated_at`
	const insertWithID = `
		INSERT INTO projects (id, name, owner_team_id, status)
		VALUES ($1, $2, NULLIF($3, ''), $4)
		RETURNING created_at, updated_at`

	var row pgx.Row
	if p.ID == uuid.Nil {
		row = r.pool.QueryRow(ctx, insertGenerated, p.Name, p.OwnerTeamID, p.Status)
		return row.Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	}
	row = r.pool.QueryRow(ctx, insertWithID, p.ID, p.Name, p.OwnerTeamID, p.Status)
	return row.Scan(&p.CreatedAt, &p.UpdatedAt)
}

// Get fetches one project by ID. Returns ErrNotFound when no row matches.
func (r *Projects) Get(ctx context.Context, id uuid.UUID) (*Project, error) {
	const q = `
		SELECT id, name, COALESCE(owner_team_id, ''), status, created_at, updated_at
		FROM projects
		WHERE id = $1`
	return scanProject(r.pool.QueryRow(ctx, q, id))
}

// GetByName fetches one project by name. Names are UNIQUE in the schema.
func (r *Projects) GetByName(ctx context.Context, name string) (*Project, error) {
	const q = `
		SELECT id, name, COALESCE(owner_team_id, ''), status, created_at, updated_at
		FROM projects
		WHERE name = $1`
	return scanProject(r.pool.QueryRow(ctx, q, name))
}

// List returns every project ordered by created_at ascending. Small
// table by design; pagination lands when the data shape demands it.
func (r *Projects) List(ctx context.Context) ([]*Project, error) {
	const q = `
		SELECT id, name, COALESCE(owner_team_id, ''), status, created_at, updated_at
		FROM projects
		ORDER BY created_at ASC`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("storage: list projects: %w", err)
	}
	defer rows.Close()

	var out []*Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateStatus transitions a project to a new status. ErrNotFound is
// returned when no row exists.
func (r *Projects) UpdateStatus(ctx context.Context, id uuid.UUID, status ProjectStatus) error {
	const q = `UPDATE projects SET status = $1 WHERE id = $2`
	tag, err := r.pool.Exec(ctx, q, status, id)
	if err != nil {
		return fmt.Errorf("storage: update project status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// scanProject is shared between QueryRow.Scan and the rows-iter Scan
// paths so the column order is declared once.
func scanProject(row interface {
	Scan(dest ...any) error
}) (*Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.Name, &p.OwnerTeamID, &p.Status, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan project: %w", err)
	}
	return &p, nil
}
