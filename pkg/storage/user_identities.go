// Package storage, user_identities.go: accounts bound to an external
// identity by (issuer, subject) (migration 0044, api#267).
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrIdentityTaken is returned when the (issuer, subject) is already
// linked to an account, or the account already has an identity from
// that issuer.
var ErrIdentityTaken = errors.New("storage: identity already linked")

// UserIdentity mirrors a row in user_identities.
type UserIdentity struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	ProviderType string
	Issuer       string
	Subject      string
	EmailAtLink  string
	LinkedAt     time.Time
}

// UserIdentities is the Postgres implementation.
type UserIdentities struct {
	pool *Pool
}

// NewUserIdentities binds the repository to a pool.
func NewUserIdentities(pool *Pool) *UserIdentities { return &UserIdentities{pool: pool} }

const userIdentityColumns = `id, user_id, provider_type, issuer, subject, email_at_link, linked_at`

func scanUserIdentity(row pgx.Row) (*UserIdentity, error) {
	var id UserIdentity
	if err := row.Scan(&id.ID, &id.UserID, &id.ProviderType, &id.Issuer, &id.Subject, &id.EmailAtLink, &id.LinkedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan user identity: %w", err)
	}
	return &id, nil
}

// GetBySubject returns the identity for (issuer, subject), or ErrNotFound.
func (r *UserIdentities) GetBySubject(ctx context.Context, issuer, subject string) (*UserIdentity, error) {
	return scanUserIdentity(r.pool.QueryRow(ctx,
		`SELECT `+userIdentityColumns+` FROM user_identities WHERE issuer = $1 AND subject = $2`, issuer, subject))
}

// ListByUser returns an account's identities.
func (r *UserIdentities) ListByUser(ctx context.Context, userID uuid.UUID) ([]*UserIdentity, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+userIdentityColumns+` FROM user_identities WHERE user_id = $1 ORDER BY linked_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("storage: list user identities: %w", err)
	}
	defer rows.Close()
	out := []*UserIdentity{}
	for rows.Next() {
		id, err := scanUserIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Link binds an identity to an existing account. ErrIdentityTaken when
// the identity or the account's slot for that issuer is taken.
func (r *UserIdentities) Link(ctx context.Context, id *UserIdentity) error {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO user_identities (user_id, provider_type, issuer, subject, email_at_link)
		VALUES ($1, $2, $3, $4, $5) RETURNING id, linked_at`,
		id.UserID, id.ProviderType, id.Issuer, id.Subject, id.EmailAtLink).Scan(&id.ID, &id.LinkedAt)
	return mapIdentityErr(err)
}

// Unlink removes an account's identity of a provider type and returns
// it, or ErrNotFound.
func (r *UserIdentities) Unlink(ctx context.Context, userID uuid.UUID, providerType string) (*UserIdentity, error) {
	return scanUserIdentity(r.pool.QueryRow(ctx,
		`DELETE FROM user_identities WHERE user_id = $1 AND provider_type = $2 RETURNING `+userIdentityColumns,
		userID, providerType))
}

// CreateAccount creates a new account bound to an identity in one
// transaction, so an account never exists without its identity. When
// defaultRole is set, the account also gets that role (granted_by
// grantedBy). ErrLocalUserExists when the email has an account;
// ErrIdentityTaken when the identity is linked already.
func (r *UserIdentities) CreateAccount(ctx context.Context, u *LocalUser, id *UserIdentity, defaultRole *uuid.UUID, grantedBy string) error {
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: begin create account: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := tx.QueryRow(ctx, `
		INSERT INTO local_users (email, password_hash, display_name, pending_approval)
		VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`,
		u.Email, u.PasswordHash, u.DisplayName, u.PendingApproval).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrLocalUserExists
		}
		return fmt.Errorf("storage: create account: %w", err)
	}
	id.UserID = u.ID
	if err := tx.QueryRow(ctx, `
		INSERT INTO user_identities (user_id, provider_type, issuer, subject, email_at_link)
		VALUES ($1, $2, $3, $4, $5) RETURNING id, linked_at`,
		id.UserID, id.ProviderType, id.Issuer, id.Subject, id.EmailAtLink).Scan(&id.ID, &id.LinkedAt); err != nil {
		return mapIdentityErr(err)
	}
	if defaultRole != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, scope, granted_by) VALUES ($1, $2, $3, NULLIF($4, ''))`,
			u.ID.String(), *defaultRole, json.RawMessage(`{}`), grantedBy); err != nil {
			return fmt.Errorf("storage: grant default role: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: commit create account: %w", err)
	}
	return nil
}

func mapIdentityErr(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrIdentityTaken
	}
	return fmt.Errorf("storage: write user identity: %w", err)
}
