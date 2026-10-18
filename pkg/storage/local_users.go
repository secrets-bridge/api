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
	// BeginLoginAttempt atomically reserves one password attempt for
	// the account BEFORE the bcrypt compare runs. See the method doc
	// on LocalUsers for the exact semantics.
	BeginLoginAttempt(ctx context.Context, id uuid.UUID, threshold int, lockFor time.Duration, now time.Time) (*LoginAttempt, error)
}

// LoginAttempt is the outcome of BeginLoginAttempt.
//
// Allowed=true means the attempt was counted and the caller may run
// the password compare. FailedLoginCount is the post-increment value
// and LockedUntil is set when this attempt reached the threshold (the
// lock is already in force for every concurrent attempt).
//
// Allowed=false means nothing was counted: the account is disabled,
// currently locked, or gone. Disabled / LockedUntil / NotFound say
// which, for the audit trail only.
type LoginAttempt struct {
	Allowed          bool
	FailedLoginCount int
	LockedUntil      *time.Time
	Disabled         bool
	NotFound         bool
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

// BeginLoginAttempt reserves one password attempt in a single
// UPDATE ... RETURNING, before the caller pays for bcrypt (API-S-25).
//
// The row is only touched when the account is enabled and not locked
// at `now` (an expired lock counts as unlocked). The counter goes up
// by one and, when it reaches `threshold`, locked_until is pinned to
// now+lockFor in the same statement. Postgres re-checks the WHERE
// clause against the latest row version for concurrent UPDATEs, so
// at most `threshold` attempts get through from a clean counter and
// exactly one per lock window after a lock expires. A successful
// compare must call ClearLockout to give the attempt back.
func (r *LocalUsers) BeginLoginAttempt(ctx context.Context, id uuid.UUID, threshold int, lockFor time.Duration, now time.Time) (*LoginAttempt, error) {
	if threshold <= 0 || lockFor <= 0 {
		return nil, errors.New("storage: login attempt threshold and lock duration must be positive")
	}
	now = now.UTC()
	const q = `
		UPDATE local_users
		   SET failed_login_count = failed_login_count + 1,
		       locked_until = CASE WHEN failed_login_count + 1 >= $2 THEN $3 ELSE locked_until END
		 WHERE id = $1
		   AND disabled = FALSE
		   AND (locked_until IS NULL OR locked_until <= $4)
		RETURNING failed_login_count, locked_until`
	var (
		n      int
		locked *time.Time
	)
	err := r.pool.QueryRow(ctx, q, id, threshold, now.Add(lockFor), now).Scan(&n, &locked)
	if err == nil {
		out := &LoginAttempt{Allowed: true, FailedLoginCount: n}
		if n >= threshold {
			out.LockedUntil = locked
		}
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("storage: begin login attempt: %w", err)
	}
	// Refused. Read the row back only to say why, for the audit trail.
	cur, getErr := r.Get(ctx, id)
	if getErr != nil {
		if errors.Is(getErr, ErrNotFound) {
			return &LoginAttempt{NotFound: true}, nil
		}
		return nil, getErr
	}
	return &LoginAttempt{
		FailedLoginCount: cur.FailedLoginCount,
		LockedUntil:      cur.LockedUntil,
		Disabled:         cur.Disabled,
	}, nil
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

// LocalUserLookupMax caps how many users ListByIDs and Search return.
const LocalUserLookupMax = 100

// ListByIDs returns the users with the given ids, ordered by email.
// Unknown ids are skipped. Only id, email, display name and the
// disabled flag are read; the password hash and lockout state are
// left empty. Used by the admin user lookup (api#240).
func (r *LocalUsers) ListByIDs(ctx context.Context, ids []uuid.UUID) ([]*LocalUser, error) {
	if len(ids) == 0 {
		return []*LocalUser{}, nil
	}
	const q = `SELECT id, email, display_name, disabled
	           FROM local_users
	           WHERE id = ANY($1)
	           ORDER BY email ASC
	           LIMIT $2`
	return r.lookup(ctx, q, ids, LocalUserLookupMax)
}

// Search returns up to limit users (at most LocalUserLookupMax) whose
// email or display name contains text, ignoring case, ordered by email.
// `%`, `_` and `\` in text match literally. Same columns as ListByIDs.
func (r *LocalUsers) Search(ctx context.Context, text string, limit int) ([]*LocalUser, error) {
	if limit <= 0 || limit > LocalUserLookupMax {
		limit = LocalUserLookupMax
	}
	pattern := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(text) + "%"
	const q = `SELECT id, email, display_name, disabled
	           FROM local_users
	           WHERE email ILIKE $1 ESCAPE '\' OR display_name ILIKE $1 ESCAPE '\'
	           ORDER BY email ASC
	           LIMIT $2`
	return r.lookup(ctx, q, pattern, limit)
}

func (r *LocalUsers) lookup(ctx context.Context, q string, arg any, limit int) ([]*LocalUser, error) {
	rows, err := r.pool.Query(ctx, q, arg, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: look up local users: %w", err)
	}
	defer rows.Close()
	out := []*LocalUser{}
	for rows.Next() {
		u := &LocalUser{}
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Disabled); err != nil {
			return nil, fmt.Errorf("storage: scan local user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
