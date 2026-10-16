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

// UserRole is one RBAC assignment.
type UserRole struct {
	ID        uuid.UUID
	UserID    string
	RoleID    uuid.UUID
	Scope     map[string]any // empty = global; e.g. {"project_id":"...","environment":"prod"}
	GrantedBy string
	GrantedAt time.Time

	// ScopeMalformed is set on read when the stored scope is not a JSON
	// object (for example a hand-written jsonb null). Scope is nil then,
	// and the RBAC resolver must treat the grant as covering nothing,
	// never as an empty (global) scope.
	ScopeMalformed bool
}

// UserRoleRepository is the read/write surface for the user_roles table.
type UserRoleRepository interface {
	Grant(ctx context.Context, ur *UserRole) error
	Get(ctx context.Context, id uuid.UUID) (*UserRole, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context) ([]*UserRole, error)
	ListByUser(ctx context.Context, userID string) ([]*UserRole, error)
	ListByRole(ctx context.Context, roleID uuid.UUID) ([]*UserRole, error)
}

// UserRoles is the Postgres implementation.
type UserRoles struct {
	pool *Pool
}

// NewUserRoles binds a UserRoles repository to the given pool.
func NewUserRoles(pool *Pool) *UserRoles { return &UserRoles{pool: pool} }

func (r *UserRoles) Grant(ctx context.Context, ur *UserRole) error {
	if ur.UserID == "" {
		return errors.New("storage: UserID is required")
	}
	if ur.RoleID == uuid.Nil {
		return errors.New("storage: RoleID is required")
	}
	if ur.Scope == nil {
		ur.Scope = map[string]any{}
	}
	scope, err := json.Marshal(ur.Scope)
	if err != nil {
		return fmt.Errorf("storage: marshal user_role scope: %w", err)
	}
	const q = `
		INSERT INTO user_roles (user_id, role_id, scope, granted_by)
		VALUES ($1, $2, $3, NULLIF($4, ''))
		RETURNING id, granted_at`
	return r.pool.QueryRow(ctx, q, ur.UserID, ur.RoleID, scope, ur.GrantedBy).Scan(&ur.ID, &ur.GrantedAt)
}

// Get returns one assignment by id, or ErrNotFound.
func (r *UserRoles) Get(ctx context.Context, id uuid.UUID) (*UserRole, error) {
	const q = `
		SELECT id, user_id, role_id, scope, COALESCE(granted_by, ''), granted_at
		FROM user_roles WHERE id = $1`
	return scanUserRole(r.pool.QueryRow(ctx, q, id))
}

func (r *UserRoles) Revoke(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM user_roles WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("storage: revoke user_role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *UserRoles) ListByUser(ctx context.Context, userID string) ([]*UserRole, error) {
	const q = `
		SELECT id, user_id, role_id, scope, COALESCE(granted_by, ''), granted_at
		FROM user_roles WHERE user_id = $1 ORDER BY granted_at ASC`
	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("storage: list user_roles by user: %w", err)
	}
	defer rows.Close()

	var out []*UserRole
	for rows.Next() {
		ur, err := scanUserRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ur)
	}
	return out, rows.Err()
}

// List returns every assignment ordered by user_id then granted_at.
// Small table by design — no pagination yet.
func (r *UserRoles) List(ctx context.Context) ([]*UserRole, error) {
	const q = `
		SELECT id, user_id, role_id, scope, COALESCE(granted_by, ''), granted_at
		FROM user_roles
		ORDER BY user_id ASC, granted_at ASC`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("storage: list user_roles: %w", err)
	}
	defer rows.Close()

	var out []*UserRole
	for rows.Next() {
		ur, err := scanUserRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ur)
	}
	return out, rows.Err()
}

func (r *UserRoles) ListByRole(ctx context.Context, roleID uuid.UUID) ([]*UserRole, error) {
	const q = `
		SELECT id, user_id, role_id, scope, COALESCE(granted_by, ''), granted_at
		FROM user_roles WHERE role_id = $1 ORDER BY granted_at ASC`
	rows, err := r.pool.Query(ctx, q, roleID)
	if err != nil {
		return nil, fmt.Errorf("storage: list user_roles by role: %w", err)
	}
	defer rows.Close()

	var out []*UserRole
	for rows.Next() {
		ur, err := scanUserRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ur)
	}
	return out, rows.Err()
}

func scanUserRole(row interface {
	Scan(dest ...any) error
}) (*UserRole, error) {
	var (
		ur       UserRole
		scopeRaw []byte
	)
	err := row.Scan(&ur.ID, &ur.UserID, &ur.RoleID, &scopeRaw, &ur.GrantedBy, &ur.GrantedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan user_role: %w", err)
	}
	if len(scopeRaw) > 0 {
		var raw any
		if err := json.Unmarshal(scopeRaw, &raw); err != nil {
			return nil, fmt.Errorf("storage: unmarshal user_role scope: %w", err)
		}
		obj, ok := raw.(map[string]any)
		if !ok {
			// null, array or scalar. Decoding null straight into the map
			// used to yield an empty (global) scope.
			ur.ScopeMalformed = true
		} else {
			ur.Scope = obj
		}
	}
	return &ur, nil
}
