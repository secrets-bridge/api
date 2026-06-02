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
//
// Two enums describe a row:
//
//   - Type — operator-chosen lifecycle label (dev / staging / uat /
//     prod / other). Free to evolve with the team's conventions.
//   - Kind — the hard safety boundary (non_prod / prod). Slice L2's
//     PolicyEngine refuses to honour `direct_reveal_allowed=true`
//     against `kind='prod'` regardless of policy or permission.
//
// Operators typically pick Kind to follow Type, but the two are
// independently mutable for the case where Type is, say, "staging"
// but the environment carries real customer data — Kind=prod still
// blocks direct reveal.
type Environment struct {
	ID          uuid.UUID
	ProjectID   uuid.UUID
	Name        string
	Type        EnvironmentType
	Kind        EnvironmentKind
	RiskLevel   int
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
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

// EnvironmentKind is the hard safety boundary (Slice L1). The
// PolicyEngine never permits direct reveal against kind='prod'.
// Stored as a Postgres ENUM `environment_kind` (`non_prod` | `prod`).
type EnvironmentKind string

const (
	EnvironmentKindNonProd EnvironmentKind = "non_prod"
	EnvironmentKindProd    EnvironmentKind = "prod"
)

// DeriveKindFromType returns the canonical Kind for a given Type when
// the operator hasn't set Kind explicitly. The only mapping that
// auto-elevates to `prod` is Type=="prod"; everything else lands in
// `non_prod`. Operators who want a staging-labelled environment
// treated as PROD must set Kind explicitly at Create time.
func DeriveKindFromType(t EnvironmentType) EnvironmentKind {
	if t == EnvironmentTypeProd {
		return EnvironmentKindProd
	}
	return EnvironmentKindNonProd
}

// EnvironmentRepository is the read/write surface for the environments
// table. Same testability split as ProjectRepository — handler tests
// inject a fake.
//
// Update is intentionally narrow: only description + risk_level may
// be mutated post-creation. Kind and Name are immutable so the
// PolicyEngine (Slice L2) can cache resolution results keyed off the
// environment without invalidation churn, and so an operator can't
// silently flip a `prod` row to `non_prod` after grants exist.
type EnvironmentRepository interface {
	Create(ctx context.Context, e *Environment) error
	Get(ctx context.Context, id uuid.UUID) (*Environment, error)
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]*Environment, error)
	List(ctx context.Context) ([]*Environment, error)
	Update(ctx context.Context, id uuid.UUID, description string, riskLevel int) error
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
//
// Kind defaults: an empty Kind is derived from Type via
// DeriveKindFromType. Operators who want to override (e.g. mark a
// `staging` lifecycle env as `kind=prod` because it carries customer
// data) set Kind explicitly.
//
// RiskLevel defaults to 1 (lowest non-zero) when 0; the DB CHECK
// rejects values outside 0-4.
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
	if e.Kind == "" {
		e.Kind = DeriveKindFromType(e.Type)
	}
	if e.RiskLevel == 0 {
		// Mirror the schema DEFAULT so the test column matches what a
		// raw INSERT would produce. Highest is reserved for explicit
		// risk_level=4 set by the operator.
		e.RiskLevel = 1
	}

	const insertGenerated = `
		INSERT INTO environments (project_id, name, type, kind, risk_level, description)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''))
		RETURNING id, created_at, updated_at`
	const insertWithID = `
		INSERT INTO environments (id, project_id, name, type, kind, risk_level, description)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))
		RETURNING created_at, updated_at`

	var err error
	if e.ID == uuid.Nil {
		err = r.pool.QueryRow(ctx, insertGenerated,
			e.ProjectID, e.Name, e.Type, e.Kind, e.RiskLevel, e.Description,
		).Scan(&e.ID, &e.CreatedAt, &e.UpdatedAt)
	} else {
		err = r.pool.QueryRow(ctx, insertWithID,
			e.ID, e.ProjectID, e.Name, e.Type, e.Kind, e.RiskLevel, e.Description,
		).Scan(&e.CreatedAt, &e.UpdatedAt)
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

// Update mutates the description + risk_level of an existing row.
// Kind and Name are intentionally NOT mutable — see the
// EnvironmentRepository doc for why.
//
// Returns ErrNotFound when no row matches. The schema's CHECK on
// risk_level rejects out-of-range values with pgError code 23514;
// callers can surface that as 400.
func (r *Environments) Update(ctx context.Context, id uuid.UUID, description string, riskLevel int) error {
	const q = `
		UPDATE environments
		SET description = NULLIF($1, ''),
		    risk_level  = $2,
		    updated_at  = now()
		WHERE id = $3`
	tag, err := r.pool.Exec(ctx, q, description, riskLevel, id)
	if err != nil {
		return fmt.Errorf("storage: update environment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Get fetches one environment by ID. Returns ErrNotFound when no row
// matches.
func (r *Environments) Get(ctx context.Context, id uuid.UUID) (*Environment, error) {
	const q = `
		SELECT id, project_id, name, type, kind, risk_level,
		       COALESCE(description, ''),
		       created_at, updated_at
		FROM environments
		WHERE id = $1`
	return scanEnvironment(r.pool.QueryRow(ctx, q, id))
}

// ListByProject returns every environment under a project, ordered by
// name ascending. Empty slice + nil error when the project has no
// environments yet.
func (r *Environments) ListByProject(ctx context.Context, projectID uuid.UUID) ([]*Environment, error) {
	const q = `
		SELECT id, project_id, name, type, kind, risk_level,
		       COALESCE(description, ''),
		       created_at, updated_at
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
		SELECT id, project_id, name, type, kind, risk_level,
		       COALESCE(description, ''),
		       created_at, updated_at
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
	err := row.Scan(
		&e.ID, &e.ProjectID, &e.Name, &e.Type, &e.Kind, &e.RiskLevel, &e.Description,
		&e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan environment: %w", err)
	}
	return &e, nil
}
