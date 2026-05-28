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
}

// UserRoleRepository is the read/write surface for the user_roles table.
type UserRoleRepository interface {
	Grant(ctx context.Context, ur *UserRole) error
	Revoke(ctx context.Context, id uuid.UUID) error
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
		if err := json.Unmarshal(scopeRaw, &ur.Scope); err != nil {
			return nil, fmt.Errorf("storage: unmarshal user_role scope: %w", err)
		}
	}
	return &ur, nil
}
