package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

// Logo is one stored logo. PNG is the re-encoded image the service
// produced; it is never a secret, but it is also never written to logs
// or audit metadata (only its size and digest are).
type Logo struct {
	EntityID uuid.UUID
	PNG      []byte
	// ByteLength is the size of the stored PNG. Delete fills it without
	// returning the bytes, so the audit can say what was removed.
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

// LogoRepository stores project and team logos.
type LogoRepository interface {
	// Get returns the logo for one entity, or ErrNotFound.
	Get(ctx context.Context, kind LogoKind, entityID uuid.UUID) (*Logo, error)
	// Upsert inserts or replaces the logo for l.EntityID and sets
	// l.UpdatedAt from the database.
	Upsert(ctx context.Context, kind LogoKind, l *Logo) error
	// Delete removes the logo and returns what was removed (without the
	// image bytes), or ErrNotFound when there was none.
	Delete(ctx context.Context, kind LogoKind, entityID uuid.UUID) (*Logo, error)
	// Versions returns entity id → logo version for the ids that have a
	// logo. One query whatever the number of ids; empty input, empty map.
	Versions(ctx context.Context, kind LogoKind, entityIDs []uuid.UUID) (map[uuid.UUID]string, error)
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
		SELECT %[2]s, png, sha256, width, height, updated_by, updated_at
		FROM %[1]s
		WHERE %[2]s = $1`, table, column)
	l := &Logo{}
	err = r.pool.QueryRow(ctx, q, entityID).Scan(
		&l.EntityID, &l.PNG, &l.SHA256, &l.Width, &l.Height, &l.UpdatedBy, &l.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get %s logo: %w", kind, err)
	}
	l.ByteLength = len(l.PNG)
	return l, nil
}

// Upsert inserts or replaces one logo.
func (r *Logos) Upsert(ctx context.Context, kind LogoKind, l *Logo) error {
	table, column, err := logoTable(kind)
	if err != nil {
		return err
	}
	q := fmt.Sprintf(`
		INSERT INTO %[1]s (%[2]s, png, sha256, width, height, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (%[2]s) DO UPDATE SET
			png        = EXCLUDED.png,
			sha256     = EXCLUDED.sha256,
			width      = EXCLUDED.width,
			height     = EXCLUDED.height,
			updated_by = EXCLUDED.updated_by,
			updated_at = now()
		RETURNING updated_at`, table, column)
	if err := r.pool.QueryRow(ctx, q, l.EntityID, l.PNG, l.SHA256, l.Width, l.Height, l.UpdatedBy).Scan(&l.UpdatedAt); err != nil {
		return fmt.Errorf("storage: upsert %s logo: %w", kind, err)
	}
	return nil
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
		RETURNING %[2]s, sha256, width, height, octet_length(png), updated_by, updated_at`, table, column)
	l := &Logo{}
	err = r.pool.QueryRow(ctx, q, entityID).Scan(
		&l.EntityID, &l.SHA256, &l.Width, &l.Height, &l.ByteLength, &l.UpdatedBy, &l.UpdatedAt,
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
