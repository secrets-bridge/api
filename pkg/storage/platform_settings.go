// R-follow-up #2 (api#121) — platform_settings storage layer.
//
// Whitelist enforcement lives at the SERVICE layer; this repo accepts
// any key. The list helper takes an explicit allowlist so a future
// repo caller cannot accidentally surface non-whitelisted rows in an
// admin response.
//
// HARD RULE — values stored here are admin-set CONFIGURATION
// (integers, durations, booleans, fixed enums). NEVER secrets,
// credentials, tokens, or provider auth material.

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// PlatformSetting is one row in the platform_settings table.
type PlatformSetting struct {
	Key       string
	Value     []byte // raw JSONB bytes; caller decodes per-key shape
	UpdatedAt time.Time
	UpdatedBy *string
}

// ErrPlatformSettingNotFound is returned when a row with the given
// key doesn't exist. Distinct from the whitelist check at the
// service layer; this is the storage-level "row missing" signal.
var ErrPlatformSettingNotFound = errors.New("storage: platform setting not found")

// PlatformSettingRepository is the read/write surface.
type PlatformSettingRepository interface {
	// Get reads the row for `key`. Returns ErrPlatformSettingNotFound
	// if no row exists. Caller is responsible for whitelist checking.
	Get(ctx context.Context, key string) (*PlatformSetting, error)

	// List returns rows whose keys are in `allowed`. The whitelist
	// is passed in by the caller — the repo never surfaces rows the
	// caller didn't explicitly request, even if the DB has them.
	List(ctx context.Context, allowed []string) ([]*PlatformSetting, error)

	// SetTx writes a new value within an existing transaction. The
	// caller (typically a service-layer method coordinating the
	// settings update with an audit insert) is responsible for the
	// BEGIN/COMMIT. updatedBy is the actor identity, persisted to
	// the row's updated_by column.
	//
	// The DB-level CHECK enforces bounds for known keys; this method
	// surfaces a constraint violation as ErrInvalidPlatformSetting so
	// the service layer can produce a stable error envelope.
	SetTx(ctx context.Context, tx pgx.Tx, key string, value []byte, updatedBy string) error
}

// ErrInvalidPlatformSetting is returned when the DB CHECK rejects a
// value (out-of-bounds, wrong shape for the key). The service layer
// pre-validates so this is a defense-in-depth path; if it fires it's
// usually a programming error.
var ErrInvalidPlatformSetting = errors.New("storage: platform setting value rejected by DB CHECK")

// PlatformSettings is the Postgres implementation.
type PlatformSettings struct {
	pool *Pool
}

// NewPlatformSettings binds a repo to the given pool.
func NewPlatformSettings(pool *Pool) *PlatformSettings { return &PlatformSettings{pool: pool} }

func (r *PlatformSettings) Get(ctx context.Context, key string) (*PlatformSetting, error) {
	return scanPlatformSetting(r.pool.QueryRow(ctx,
		`SELECT key, value, updated_at, updated_by FROM platform_settings WHERE key = $1`,
		key,
	))
}

func (r *PlatformSettings) List(ctx context.Context, allowed []string) ([]*PlatformSetting, error) {
	if len(allowed) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT key, value, updated_at, updated_by
		 FROM platform_settings
		 WHERE key = ANY($1::text[])
		 ORDER BY key ASC`,
		allowed,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: list platform_settings: %w", err)
	}
	defer rows.Close()

	var out []*PlatformSetting
	for rows.Next() {
		s, err := scanPlatformSetting(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *PlatformSettings) SetTx(ctx context.Context, tx pgx.Tx, key string, value []byte, updatedBy string) error {
	if !json.Valid(value) {
		return fmt.Errorf("storage: platform_settings value is not valid JSON")
	}
	// updated_at is bumped by the trigger; updated_by we set explicitly.
	tag, err := tx.Exec(ctx,
		`UPDATE platform_settings SET value = $2, updated_by = $3 WHERE key = $1`,
		key, value, updatedBy,
	)
	if err != nil {
		// Map the CHECK constraint violation to a typed error.
		// pgx surfaces the constraint name; we match on it.
		if pgErr := pgxErrCode(err); pgErr == "23514" {
			return ErrInvalidPlatformSetting
		}
		return fmt.Errorf("storage: update platform_settings: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Row missing entirely. The seed migration should have inserted
		// every whitelisted key; if we hit this it's likely an unknown
		// key got past the service whitelist.
		return ErrPlatformSettingNotFound
	}
	return nil
}

func scanPlatformSetting(row interface {
	Scan(dest ...any) error
}) (*PlatformSetting, error) {
	var s PlatformSetting
	err := row.Scan(&s.Key, &s.Value, &s.UpdatedAt, &s.UpdatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPlatformSettingNotFound
		}
		return nil, fmt.Errorf("storage: scan platform_setting: %w", err)
	}
	return &s, nil
}

// pgxErrCode extracts the Postgres SQLSTATE from a pgx error chain.
// Returns "" when err is nil or doesn't carry a pg-level code.
func pgxErrCode(err error) string {
	type coded interface {
		SQLState() string
	}
	var c coded
	if errors.As(err, &c) {
		return c.SQLState()
	}
	return ""
}
