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

// Role is a named bundle of permission strings.
type Role struct {
	ID          uuid.UUID
	Name        string
	Description string
	Permissions []string
	IsSystem    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// HasPermission returns true when p is in the role's permission list.
// Exact-match only today; wildcard support can come later.
func (r *Role) HasPermission(p string) bool {
	for _, perm := range r.Permissions {
		if perm == p {
			return true
		}
	}
	return false
}

// RoleRepository is the read/write surface for the roles table.
type RoleRepository interface {
	Create(ctx context.Context, r *Role) error
	Get(ctx context.Context, id uuid.UUID) (*Role, error)
	GetByName(ctx context.Context, name string) (*Role, error)
	List(ctx context.Context) ([]*Role, error)
	UpdatePermissions(ctx context.Context, id uuid.UUID, perms []string) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// ErrSystemRow is returned by Delete (on any of the policy-engine
// tables) when the caller tries to delete a row that is_system=true.
// System rows can be edited but not removed — they're seeded so the
// platform starts in a usable state and removing them would lock the
// admin out.
var ErrSystemRow = errors.New("storage: cannot delete system row")

// Roles is the Postgres implementation of RoleRepository.
type Roles struct {
	pool *Pool
}

// NewRoles binds a Roles repository to the given pool.
func NewRoles(pool *Pool) *Roles { return &Roles{pool: pool} }

func (r *Roles) Create(ctx context.Context, role *Role) error {
	if role.Name == "" {
		return errors.New("storage: role Name is required")
	}
	if role.Permissions == nil {
		role.Permissions = []string{}
	}
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("storage: marshal role permissions: %w", err)
	}
	const q = `
		INSERT INTO roles (name, description, permissions, is_system)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		role.Name, role.Description, perms, role.IsSystem,
	).Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)
}

func (r *Roles) Get(ctx context.Context, id uuid.UUID) (*Role, error) {
	const q = `
		SELECT id, name, description, permissions, is_system, created_at, updated_at
		FROM roles WHERE id = $1`
	return scanRole(r.pool.QueryRow(ctx, q, id))
}

func (r *Roles) GetByName(ctx context.Context, name string) (*Role, error) {
	const q = `
		SELECT id, name, description, permissions, is_system, created_at, updated_at
		FROM roles WHERE name = $1`
	return scanRole(r.pool.QueryRow(ctx, q, name))
}

func (r *Roles) List(ctx context.Context) ([]*Role, error) {
	const q = `
		SELECT id, name, description, permissions, is_system, created_at, updated_at
		FROM roles ORDER BY name ASC`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("storage: list roles: %w", err)
	}
	defer rows.Close()

	var out []*Role
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (r *Roles) UpdatePermissions(ctx context.Context, id uuid.UUID, perms []string) error {
	if perms == nil {
		perms = []string{}
	}
	raw, err := json.Marshal(perms)
	if err != nil {
		return fmt.Errorf("storage: marshal role permissions: %w", err)
	}
	const q = `UPDATE roles SET permissions = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, raw)
	if err != nil {
		return fmt.Errorf("storage: update role permissions: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Roles) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM roles WHERE id = $1 AND is_system = false`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("storage: delete role: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Distinguish ErrNotFound from ErrSystemRow so the API can return
	// 404 vs 409 appropriately.
	role, getErr := r.Get(ctx, id)
	if getErr != nil {
		return getErr
	}
	if role.IsSystem {
		return ErrSystemRow
	}
	return ErrNotFound
}

func scanRole(row interface {
	Scan(dest ...any) error
}) (*Role, error) {
	var (
		r        Role
		permsRaw []byte
	)
	err := row.Scan(&r.ID, &r.Name, &r.Description, &permsRaw, &r.IsSystem, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan role: %w", err)
	}
	if len(permsRaw) > 0 {
		if err := json.Unmarshal(permsRaw, &r.Permissions); err != nil {
			return nil, fmt.Errorf("storage: unmarshal role permissions: %w", err)
		}
	}
	return &r, nil
}
