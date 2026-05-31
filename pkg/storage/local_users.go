// Local users repository — backs the minimal email+password login slice
// behind /api/v1/auth/login. This is a stop-gap until OIDC lands; the
// shape is deliberately small so the OIDC swap touches one file
// (`internal/services/auth.go`) and leaves the rest of the platform
// alone.
//
// Hard rules respected:
//   - `password_hash` is BYTEA — we store bcrypt hashes, never the
//     plaintext password. The scan / insert paths treat it as opaque
//     bytes.
//   - No "find by password" / "reset by question" / "remember me"
//     anti-pattern surfaces — the interface only exposes Create / Get /
//     GetByEmail / List / SetPasswordHash / Disable / Enable.

package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// LocalUser mirrors a row in the local_users table. `PasswordHash` is
// the raw bcrypt output (the algorithm marker `$2a$...` lives inside).
//
// `FailedLoginCount` + `LockedUntil` back the account-lockout state
// machine: 5 consecutive wrong-password failures lock the account for
// 15 minutes. State lives in Postgres so a Redis flush can't silently
// re-enable a previously-locked account.
type LocalUser struct {
	ID               uuid.UUID
	Email            string
	PasswordHash     []byte
	DisplayName      string
	Disabled         bool
	FailedLoginCount int
	LockedUntil      *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ErrLocalUserExists signals an email collision (unique-violation
// 23505 from the partial index on `email`).
var ErrLocalUserExists = errors.New("storage: local user with that email already exists")

// LocalUserRepository is the public surface.
type LocalUserRepository interface {
	Create(ctx context.Context, u *LocalUser) error
	Get(ctx context.Context, id uuid.UUID) (*LocalUser, error)
	GetByEmail(ctx context.Context, email string) (*LocalUser, error)
	List(ctx context.Context) ([]*LocalUser, error)
	Count(ctx context.Context) (int, error)
	SetPasswordHash(ctx context.Context, id uuid.UUID, hash []byte) error
	SetDisabled(ctx context.Context, id uuid.UUID, disabled bool) error
	// IncrementFailedLogins atomically bumps failed_login_count and
	// returns the new value. Callers compare against the lockout
	// threshold and call Lock once the threshold is crossed.
	IncrementFailedLogins(ctx context.Context, id uuid.UUID) (int, error)
	// Lock pins the account out until the given timestamp. Pass a
	// future time to lock; pass time.Time{} via ClearLockout to
	// clear it explicitly.
	Lock(ctx context.Context, id uuid.UUID, until time.Time) error
	// ClearLockout resets failed_login_count to 0 and clears
	// locked_until. Called on every successful login.
	ClearLockout(ctx context.Context, id uuid.UUID) error
}

// LocalUsers is the Postgres implementation of LocalUserRepository.
type LocalUsers struct {
	pool *Pool
}

func NewLocalUsers(pool *Pool) *LocalUsers { return &LocalUsers{pool: pool} }

// Create inserts a new local user. `Email` is lowercased so the
// unique index catches case-only collisions. Returns
// `ErrLocalUserExists` on duplicate email.
func (r *LocalUsers) Create(ctx context.Context, u *LocalUser) error {
	if len(u.PasswordHash) == 0 {
		return errors.New("storage: password_hash required")
	}
	if strings.TrimSpace(u.Email) == "" {
		return errors.New("storage: email required")
	}
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))

	const q = `
		INSERT INTO local_users (id, email, password_hash, display_name, disabled)
		VALUES (COALESCE(NULLIF($1, '00000000-0000-0000-0000-000000000000'::uuid), gen_random_uuid()),
		        $2, $3, $4, $5)
		RETURNING id, created_at, updated_at`
	if err := r.pool.QueryRow(ctx, q,
		u.ID, u.Email, u.PasswordHash, u.DisplayName, u.Disabled,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrLocalUserExists
		}
		return fmt.Errorf("storage: create local user: %w", err)
	}
	return nil
}

func (r *LocalUsers) Get(ctx context.Context, id uuid.UUID) (*LocalUser, error) {
	const q = `SELECT id, email, password_hash, display_name, disabled,
	                  failed_login_count, locked_until, created_at, updated_at
	           FROM local_users WHERE id = $1`
	return r.scan(ctx, q, id)
}

func (r *LocalUsers) GetByEmail(ctx context.Context, email string) (*LocalUser, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	const q = `SELECT id, email, password_hash, display_name, disabled,
	                  failed_login_count, locked_until, created_at, updated_at
	           FROM local_users WHERE email = $1`
	return r.scan(ctx, q, email)
}

func (r *LocalUsers) scan(ctx context.Context, q string, arg any) (*LocalUser, error) {
	var u LocalUser
	if err := r.pool.QueryRow(ctx, q, arg).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Disabled,
		&u.FailedLoginCount, &u.LockedUntil,
		&u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: get local user: %w", err)
	}
	return &u, nil
}

func (r *LocalUsers) List(ctx context.Context) ([]*LocalUser, error) {
	const q = `SELECT id, email, password_hash, display_name, disabled,
	                  failed_login_count, locked_until, created_at, updated_at
	           FROM local_users
	           ORDER BY email ASC`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("storage: list local users: %w", err)
	}
	defer rows.Close()
	out := []*LocalUser{}
	for rows.Next() {
		var u LocalUser
		if err := rows.Scan(
			&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Disabled,
			&u.FailedLoginCount, &u.LockedUntil,
			&u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("storage: scan local user: %w", err)
		}
		out = append(out, &u)
	}
	return out, rows.Err()
}

func (r *LocalUsers) Count(ctx context.Context) (int, error) {
	const q = `SELECT count(*) FROM local_users`
	var n int
	if err := r.pool.QueryRow(ctx, q).Scan(&n); err != nil {
		return 0, fmt.Errorf("storage: count local users: %w", err)
	}
	return n, nil
}

func (r *LocalUsers) SetPasswordHash(ctx context.Context, id uuid.UUID, hash []byte) error {
	if len(hash) == 0 {
		return errors.New("storage: empty password_hash")
	}
	const q = `UPDATE local_users SET password_hash = $1 WHERE id = $2`
	tag, err := r.pool.Exec(ctx, q, hash, id)
	if err != nil {
		return fmt.Errorf("storage: update password_hash: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *LocalUsers) SetDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	const q = `UPDATE local_users SET disabled = $1 WHERE id = $2`
	tag, err := r.pool.Exec(ctx, q, disabled, id)
	if err != nil {
		return fmt.Errorf("storage: set disabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// IncrementFailedLogins atomically bumps failed_login_count for `id`
// and returns the post-update value. The single UPDATE RETURNING is
// race-safe across concurrent failed-login attempts so the lockout
// threshold check uses an authoritative counter.
func (r *LocalUsers) IncrementFailedLogins(ctx context.Context, id uuid.UUID) (int, error) {
	const q = `UPDATE local_users
	           SET failed_login_count = failed_login_count + 1
	           WHERE id = $1
	           RETURNING failed_login_count`
	var n int
	if err := r.pool.QueryRow(ctx, q, id).Scan(&n); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("storage: increment failed_login_count: %w", err)
	}
	return n, nil
}

// Lock pins the account out until the given timestamp. Passing a
// past timestamp is allowed (callers that want to clear should use
// ClearLockout instead — the application semantic is explicit).
func (r *LocalUsers) Lock(ctx context.Context, id uuid.UUID, until time.Time) error {
	const q = `UPDATE local_users SET locked_until = $1 WHERE id = $2`
	tag, err := r.pool.Exec(ctx, q, until.UTC(), id)
	if err != nil {
		return fmt.Errorf("storage: lock local user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearLockout resets failed_login_count to 0 and clears
// locked_until. Called on every successful login so a recovered
// account starts each session with a clean counter.
func (r *LocalUsers) ClearLockout(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE local_users
	           SET failed_login_count = 0, locked_until = NULL
	           WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("storage: clear lockout: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
