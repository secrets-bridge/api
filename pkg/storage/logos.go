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

// LogoKind names the entity a logo belongs to. Each kind has its own
// table (project_logos, team_logos) with a foreign key to the owner.
type LogoKind string

const (
	LogoKindProject LogoKind = "project"
	LogoKindTeam    LogoKind = "team"
)

// LogoVersionLength is how many hex characters of the PNG's sha256 make
// up the logo_version clients put in the image URL.
const LogoVersionLength = 12

// ErrUnknownLogoKind is returned for a LogoKind with no table.
var ErrUnknownLogoKind = errors.New("storage: unknown logo kind")

// Logo is one stored logo's metadata. The image itself lives in object
// storage under ObjectKey (secrets-bridge/api#253).
//
// PNG is set only for a row written before the move to object storage
// (or by a replica still on the old version during a rolling deploy),
// until the backfill copies it out. When PNG is set it is the image to
// serve, whatever ObjectKey says. The image is never a secret, but it
// is also never written to logs or audit metadata (only its size and
// digest are).
type Logo struct {
	EntityID  uuid.UUID
	ObjectKey string
	PNG       []byte
	// ByteLength is the size of the stored PNG, wherever it lives.
	ByteLength int
	SHA256     string
	Width      int
	Height     int
	UpdatedBy  string
	UpdatedAt  time.Time
}

// Version is the short form of the digest clients use for cache busting.
func (l *Logo) Version() string {
	if len(l.SHA256) < LogoVersionLength {
		return l.SHA256
	}
	return l.SHA256[:LogoVersionLength]
}

// LogoRepository stores project and team logo metadata.
type LogoRepository interface {
	// Get returns the logo for one entity, or ErrNotFound.
	Get(ctx context.Context, kind LogoKind, entityID uuid.UUID) (*Logo, error)
	// Upsert inserts or replaces the logo for l.EntityID so it points at
	// l.ObjectKey (png NULL), sets l.UpdatedAt from the database and
	// returns the object key the row pointed at before ("" for none).
	// ErrNotFound when the owner doesn't exist (the foreign key refuses
	// the row).
	Upsert(ctx context.Context, kind LogoKind, l *Logo) (previousKey string, err error)
	// Delete removes the logo and returns what was removed (without the
	// image bytes, with its object key), or ErrNotFound when there was
	// none.
	Delete(ctx context.Context, kind LogoKind, entityID uuid.UUID) (*Logo, error)
	// Versions returns entity id → logo version for the ids that have a
	// logo. One query whatever the number of ids; empty input, empty map.
	Versions(ctx context.Context, kind LogoKind, entityIDs []uuid.UUID) (map[uuid.UUID]string, error)
	// ListInline returns up to limit logos whose image is still in the
	// png column, ordered by entity id and starting after the given id
	// (uuid.Nil for the start). Used by the object-storage backfill.
	ListInline(ctx context.Context, kind LogoKind, after uuid.UUID, limit int) ([]*Logo, error)
	// MoveToObject points one inline logo at objectKey and clears its
	// png, but only while the row still holds the image with digest
	// sha256 inline. It reports whether the row was moved and the object
	// key the row held before.
	MoveToObject(ctx context.Context, kind LogoKind, entityID uuid.UUID, sha256, objectKey string, byteLength int) (moved bool, previousKey string, err error)
	// CountInline counts logos of every kind still stored inline.
	CountInline(ctx context.Context) (int, error)
}

// Logos is the Postgres-backed LogoRepository.
type Logos struct {
	pool *Pool
}

// NewLogos binds a Logos repository to the given pool.
func NewLogos(pool *Pool) *Logos { return &Logos{pool: pool} }

// logoTable maps a kind to its table and key column. The values are
// constants, never caller input, so they are safe to put in SQL text.
func logoTable(kind LogoKind) (table, column string, err error) {
	switch kind {
	case LogoKindProject:
		return "project_logos", "project_id", nil
	case LogoKindTeam:
		return "team_logos", "team_id", nil
	}
	return "", "", fmt.Errorf("%w: %q", ErrUnknownLogoKind, kind)
}

// Get fetches one logo.
func (r *Logos) Get(ctx context.Context, kind LogoKind, entityID uuid.UUID) (*Logo, error) {
	table, column, err := logoTable(kind)
	if err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`
		SELECT %[2]s, COALESCE(object_key, ''), png,
		       COALESCE(octet_length(png), byte_length, 0),
		       sha256, width, height, updated_by, updated_at
		FROM %[1]s
		WHERE %[2]s = $1`, table, column)
	l := &Logo{}
	err = r.pool.QueryRow(ctx, q, entityID).Scan(
		&l.EntityID, &l.ObjectKey, &l.PNG, &l.ByteLength, &l.SHA256, &l.Width, &l.Height, &l.UpdatedBy, &l.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get %s logo: %w", kind, err)
	}
	return l, nil
}

// Upsert inserts or replaces one logo. The previous object key is read
// under a row lock in the same transaction, so two concurrent uploads
// each learn the key they actually replaced.
func (r *Logos) Upsert(ctx context.Context, kind LogoKind, l *Logo) (string, error) {
	table, column, err := logoTable(kind)
	if err != nil {
		return "", err
	}
	if l.ObjectKey == "" {
		return "", fmt.Errorf("storage: upsert %s logo: object key is required", kind)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("storage: upsert %s logo: begin: %w", kind, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var previous string
	err = tx.QueryRow(ctx, fmt.Sprintf(
		`SELECT COALESCE(object_key, '') FROM %[1]s WHERE %[2]s = $1 FOR UPDATE`, table, column),
		l.EntityID).Scan(&previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("storage: upsert %s logo: lock: %w", kind, err)
	}
	q := fmt.Sprintf(`
		INSERT INTO %[1]s (%[2]s, png, object_key, byte_length, sha256, width, height, updated_by)
		VALUES ($1, NULL, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (%[2]s) DO UPDATE SET
			png         = NULL,
			object_key  = EXCLUDED.object_key,
			byte_length = EXCLUDED.byte_length,
			sha256      = EXCLUDED.sha256,
			width       = EXCLUDED.width,
			height      = EXCLUDED.height,
			updated_by  = EXCLUDED.updated_by,
			updated_at  = now()
		RETURNING updated_at`, table, column)
	if err := tx.QueryRow(ctx, q, l.EntityID, l.ObjectKey, l.ByteLength, l.SHA256, l.Width, l.Height, l.UpdatedBy).Scan(&l.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign_key_violation
			return "", ErrNotFound
		}
		return "", fmt.Errorf("storage: upsert %s logo: %w", kind, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("storage: upsert %s logo: commit: %w", kind, err)
	}
	l.PNG = nil
	return previous, nil
}

// Delete removes one logo and returns its metadata.
func (r *Logos) Delete(ctx context.Context, kind LogoKind, entityID uuid.UUID) (*Logo, error) {
	table, column, err := logoTable(kind)
	if err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`
		DELETE FROM %[1]s
		WHERE %[2]s = $1
		RETURNING %[2]s, COALESCE(object_key, ''), sha256, width, height,
		          COALESCE(octet_length(png), byte_length, 0), updated_by, updated_at`, table, column)
	l := &Logo{}
	err = r.pool.QueryRow(ctx, q, entityID).Scan(
		&l.EntityID, &l.ObjectKey, &l.SHA256, &l.Width, &l.Height, &l.ByteLength, &l.UpdatedBy, &l.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: delete %s logo: %w", kind, err)
	}
	return l, nil
}

// Versions looks up logo versions for many entities at once.
func (r *Logos) Versions(ctx context.Context, kind LogoKind, entityIDs []uuid.UUID) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string)
	if len(entityIDs) == 0 {
		return out, nil
	}
	table, column, err := logoTable(kind)
	if err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`
		SELECT %[2]s, left(sha256, %[3]d)
		FROM %[1]s
		WHERE %[2]s = ANY($1)`, table, column, LogoVersionLength)
	rows, err := r.pool.Query(ctx, q, entityIDs)
	if err != nil {
		return nil, fmt.Errorf("storage: %s logo versions: %w", kind, err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var v string
		if err := rows.Scan(&id, &v); err != nil {
			return nil, fmt.Errorf("storage: scan %s logo version: %w", kind, err)
		}
		out[id] = v
	}
	return out, rows.Err()
}

// ListInline pages through logos still stored in the png column.
func (r *Logos) ListInline(ctx context.Context, kind LogoKind, after uuid.UUID, limit int) ([]*Logo, error) {
	table, column, err := logoTable(kind)
	if err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`
		SELECT %[2]s, COALESCE(object_key, ''), png, octet_length(png),
		       sha256, width, height, updated_by, updated_at
		FROM %[1]s
		WHERE png IS NOT NULL AND %[2]s > $1
		ORDER BY %[2]s
		LIMIT $2`, table, column)
	rows, err := r.pool.Query(ctx, q, after, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: list inline %s logos: %w", kind, err)
	}
	defer rows.Close()
	var out []*Logo
	for rows.Next() {
		l := &Logo{}
		if err := rows.Scan(&l.EntityID, &l.ObjectKey, &l.PNG, &l.ByteLength, &l.SHA256, &l.Width, &l.Height, &l.UpdatedBy, &l.UpdatedAt); err != nil {
			return nil, fmt.Errorf("storage: scan inline %s logo: %w", kind, err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// MoveToObject clears png for one logo that now lives at objectKey. The
// row is locked and re-checked first: if it was replaced or removed
// since ListInline read it, nothing changes and moved is false.
// updated_at and updated_by are left alone; the image didn't change.
func (r *Logos) MoveToObject(ctx context.Context, kind LogoKind, entityID uuid.UUID, sha256, objectKey string, byteLength int) (bool, string, error) {
	table, column, err := logoTable(kind)
	if err != nil {
		return false, "", err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, "", fmt.Errorf("storage: move %s logo: begin: %w", kind, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var previous, currentSHA string
	var inline bool
	err = tx.QueryRow(ctx, fmt.Sprintf(
		`SELECT COALESCE(object_key, ''), sha256, png IS NOT NULL FROM %[1]s WHERE %[2]s = $1 FOR UPDATE`, table, column),
		entityID).Scan(&previous, &currentSHA, &inline)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("storage: move %s logo: lock: %w", kind, err)
	}
	if !inline || currentSHA != sha256 {
		return false, previous, nil
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(
		`UPDATE %[1]s SET png = NULL, object_key = $2, byte_length = $3 WHERE %[2]s = $1`, table, column),
		entityID, objectKey, byteLength); err != nil {
		return false, "", fmt.Errorf("storage: move %s logo: %w", kind, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, "", fmt.Errorf("storage: move %s logo: commit: %w", kind, err)
	}
	return true, previous, nil
}

// CountInline counts logos still stored in a png column.
func (r *Logos) CountInline(ctx context.Context) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM project_logos WHERE png IS NOT NULL)
		     + (SELECT count(*) FROM team_logos WHERE png IS NOT NULL)`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("storage: count inline logos: %w", err)
	}
	return n, nil
}
