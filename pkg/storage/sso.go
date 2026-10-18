// Package storage, sso.go: sign-in providers configured from the console
// and the sign-in settings (migration 0042, api#267).
//
// The client secret is stored only as an envelope: AES-256-GCM
// ciphertext and nonce, plus the KMS-encrypted data key and its key id.
// This file never sees the plaintext; services/sso.go seals and opens it.
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

// SSOProviderTypeGoogle is the only provider type the console offers so
// far.
const SSOProviderTypeGoogle = "google"

// ErrSSOProviderExists is returned when a provider of that type already
// exists (one of each type).
var ErrSSOProviderExists = errors.New("storage: a sign-in provider of that type already exists")

// SSOSecret is an envelope-encrypted client secret.
type SSOSecret struct {
	Ciphertext        []byte
	Nonce             []byte
	DataKeyCiphertext []byte
	KMSKeyID          string
}

// SSOProvider mirrors a row in sso_providers.
type SSOProvider struct {
	ID              uuid.UUID
	Type            string
	DisplayName     string
	ClientID        string
	Secret          *SSOSecret // nil until a secret is set
	AllowedDomains  []string
	RequireApproval bool
	DefaultRoleID   *uuid.UUID
	Enabled         bool
	CreatedBy       string
	UpdatedBy       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// SSOSettings mirrors the single sso_settings row.
type SSOSettings struct {
	PublicURL  string // empty when not set from the console
	PendingCap int
	UpdatedBy  string
	UpdatedAt  time.Time
}

// SSOStore is the Postgres implementation for providers and settings.
type SSOStore struct {
	pool *Pool
}

// NewSSOStore binds the store to a pool.
func NewSSOStore(pool *Pool) *SSOStore { return &SSOStore{pool: pool} }

const ssoProviderColumns = `
	id, type, display_name, client_id,
	client_secret_ciphertext, client_secret_nonce, client_secret_data_key_ciphertext, client_secret_kms_key_id,
	allowed_domains, require_approval, default_role_id, enabled,
	COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at`

func scanSSOProvider(row pgx.Row) (*SSOProvider, error) {
	var (
		p     SSOProvider
		ct    []byte
		nonce []byte
		dk    []byte
		keyID *string
	)
	if err := row.Scan(&p.ID, &p.Type, &p.DisplayName, &p.ClientID,
		&ct, &nonce, &dk, &keyID,
		&p.AllowedDomains, &p.RequireApproval, &p.DefaultRoleID, &p.Enabled,
		&p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan sso provider: %w", err)
	}
	if ct != nil && keyID != nil {
		p.Secret = &SSOSecret{Ciphertext: ct, Nonce: nonce, DataKeyCiphertext: dk, KMSKeyID: *keyID}
	}
	return &p, nil
}

// CreateProvider inserts p, disabled. ErrSSOProviderExists when one of
// that type exists; ErrNotFound when DefaultRoleID names no role.
func (s *SSOStore) CreateProvider(ctx context.Context, p *SSOProvider) error {
	var ct, nonce, dk []byte
	var keyID *string
	if p.Secret != nil {
		ct, nonce, dk, keyID = p.Secret.Ciphertext, p.Secret.Nonce, p.Secret.DataKeyCiphertext, &p.Secret.KMSKeyID
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO sso_providers (type, display_name, client_id,
			client_secret_ciphertext, client_secret_nonce, client_secret_data_key_ciphertext, client_secret_kms_key_id,
			allowed_domains, require_approval, default_role_id, enabled, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, FALSE, NULLIF($11, ''), NULLIF($11, ''))
		RETURNING id, enabled, created_at, updated_at`,
		p.Type, p.DisplayName, p.ClientID, ct, nonce, dk, keyID,
		p.AllowedDomains, p.RequireApproval, p.DefaultRoleID, p.CreatedBy,
	).Scan(&p.ID, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	return mapSSOWriteErr(err)
}

// GetProvider returns one provider, or ErrNotFound.
func (s *SSOStore) GetProvider(ctx context.Context, id uuid.UUID) (*SSOProvider, error) {
	return scanSSOProvider(s.pool.QueryRow(ctx, `SELECT `+ssoProviderColumns+` FROM sso_providers WHERE id = $1`, id))
}

// GetProviderByType returns the provider of a type, or ErrNotFound.
func (s *SSOStore) GetProviderByType(ctx context.Context, providerType string) (*SSOProvider, error) {
	return scanSSOProvider(s.pool.QueryRow(ctx, `SELECT `+ssoProviderColumns+` FROM sso_providers WHERE type = $1`, providerType))
}

// ListProviders returns every provider, by type.
func (s *SSOStore) ListProviders(ctx context.Context) ([]*SSOProvider, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ssoProviderColumns+` FROM sso_providers ORDER BY type`)
	if err != nil {
		return nil, fmt.Errorf("storage: list sso providers: %w", err)
	}
	defer rows.Close()
	out := []*SSOProvider{}
	for rows.Next() {
		p, err := scanSSOProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateProvider replaces the editable fields (not the secret, not
// enabled) and returns the row as it was before, for the audit trail.
func (s *SSOStore) UpdateProvider(ctx context.Context, p *SSOProvider) (*SSOProvider, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin update sso provider: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	before, err := scanSSOProvider(tx.QueryRow(ctx, `SELECT `+ssoProviderColumns+` FROM sso_providers WHERE id = $1 FOR UPDATE`, p.ID))
	if err != nil {
		return nil, err
	}
	err = tx.QueryRow(ctx, `
		UPDATE sso_providers
		SET display_name = $2, client_id = $3, allowed_domains = $4, require_approval = $5,
		    default_role_id = $6, updated_by = NULLIF($7, ''), updated_at = now()
		WHERE id = $1
		RETURNING updated_at`,
		p.ID, p.DisplayName, p.ClientID, p.AllowedDomains, p.RequireApproval, p.DefaultRoleID, p.UpdatedBy,
	).Scan(&p.UpdatedAt)
	if err := mapSSOWriteErr(err); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit update sso provider: %w", err)
	}
	return before, nil
}

// SetProviderSecret replaces the client secret envelope.
func (s *SSOStore) SetProviderSecret(ctx context.Context, id uuid.UUID, secret SSOSecret, by string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE sso_providers
		SET client_secret_ciphertext = $2, client_secret_nonce = $3,
		    client_secret_data_key_ciphertext = $4, client_secret_kms_key_id = $5,
		    updated_by = NULLIF($6, ''), updated_at = now()
		WHERE id = $1`,
		id, secret.Ciphertext, secret.Nonce, secret.DataKeyCiphertext, secret.KMSKeyID, by)
	if err != nil {
		return fmt.Errorf("storage: set sso provider secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetProviderEnabled turns a provider on or off.
func (s *SSOStore) SetProviderEnabled(ctx context.Context, id uuid.UUID, enabled bool, by string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE sso_providers SET enabled = $2, updated_by = NULLIF($3, ''), updated_at = now() WHERE id = $1`,
		id, enabled, by)
	if err != nil {
		return fmt.Errorf("storage: set sso provider enabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteProvider removes a provider and returns it as it was.
func (s *SSOStore) DeleteProvider(ctx context.Context, id uuid.UUID) (*SSOProvider, error) {
	return scanSSOProvider(s.pool.QueryRow(ctx, `DELETE FROM sso_providers WHERE id = $1 RETURNING `+ssoProviderColumns, id))
}

// GetSettings returns the sign-in settings row.
func (s *SSOStore) GetSettings(ctx context.Context) (*SSOSettings, error) {
	var st SSOSettings
	var publicURL *string
	if err := s.pool.QueryRow(ctx, `
		SELECT public_url, pending_cap, COALESCE(updated_by, ''), updated_at FROM sso_settings WHERE id`).
		Scan(&publicURL, &st.PendingCap, &st.UpdatedBy, &st.UpdatedAt); err != nil {
		return nil, fmt.Errorf("storage: get sso settings: %w", err)
	}
	if publicURL != nil {
		st.PublicURL = *publicURL
	}
	return &st, nil
}

// UpdateSettings writes the settings and returns them as they were.
func (s *SSOStore) UpdateSettings(ctx context.Context, st *SSOSettings) (*SSOSettings, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin update sso settings: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var before SSOSettings
	var publicURL *string
	if err := tx.QueryRow(ctx, `
		SELECT public_url, pending_cap, COALESCE(updated_by, ''), updated_at FROM sso_settings WHERE id FOR UPDATE`).
		Scan(&publicURL, &before.PendingCap, &before.UpdatedBy, &before.UpdatedAt); err != nil {
		return nil, fmt.Errorf("storage: lock sso settings: %w", err)
	}
	if publicURL != nil {
		before.PublicURL = *publicURL
	}
	if err := tx.QueryRow(ctx, `
		UPDATE sso_settings SET public_url = NULLIF($1, ''), pending_cap = $2, updated_by = NULLIF($3, ''), updated_at = now()
		WHERE id RETURNING updated_at`, st.PublicURL, st.PendingCap, st.UpdatedBy).Scan(&st.UpdatedAt); err != nil {
		return nil, fmt.Errorf("storage: update sso settings: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit sso settings: %w", err)
	}
	return &before, nil
}

func mapSSOWriteErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation: one provider per type
			return ErrSSOProviderExists
		case "23503": // foreign_key_violation: no such default role
			return ErrNotFound
		}
	}
	return fmt.Errorf("storage: write sso provider: %w", err)
}
