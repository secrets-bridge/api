package storage

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// migrateDSN reshapes the user-facing DSN into the form golang-migrate's
// pgx/v5 driver expects. callers pass a standard `postgres://...` URL
// (the same one pgxpool understands); migrate wants `pgx5://...`.
// Any other scheme passes through unchanged so an explicit `pgx5://`
// supplied by the caller still works.
func migrateDSN(dsn string) string {
	switch {
	case strings.HasPrefix(dsn, "postgres://"):
		return "pgx5://" + strings.TrimPrefix(dsn, "postgres://")
	case strings.HasPrefix(dsn, "postgresql://"):
		return "pgx5://" + strings.TrimPrefix(dsn, "postgresql://")
	default:
		return dsn
	}
}

//go:embed migrations/*.sql
var migrationFS embed.FS

// MigrationsFS exposes the embedded migration files so the test suite
// can list them, count them, and assert on naming without poking at the
// unexported variable.
func MigrationsFS() fs.FS { return migrationFS }

// Migrate applies every up migration newer than the database's current
// version. Safe to call repeatedly; a no-op when the schema is already
// at head. Intended to be invoked from main on startup before /readyz
// is allowed to flip green.
func Migrate(ctx context.Context, cfg Config) error {
	srcDriver, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("storage: migration source: %w", err)
	}

	// The migrate driver opens its own *sql.DB rather than reusing the
	// pgx pool. That's deliberate: migration locks shouldn't compete
	// with serving traffic over the same connection budget.
	m, err := migrate.NewWithSourceInstance("iofs", srcDriver, migrateDSN(cfg.DSN))
	if err != nil {
		return fmt.Errorf("storage: open migration driver: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	doneCh := make(chan error, 1)
	go func() {
		err := m.Up()
		if err != nil && !errors.Is(err, migrate.ErrNoChange) {
			doneCh <- fmt.Errorf("storage: migrate up: %w", err)
			return
		}
		doneCh <- nil
	}()

	select {
	case <-ctx.Done():
		// Caller cancelled (e.g. shutting down during boot). Best
		// effort: kick the migrate driver to abort.
		_ = m.GracefulStop
		return ctx.Err()
	case err := <-doneCh:
		return err
	}
}

// Version returns the current schema version. Useful for /readyz
// instrumentation and debug endpoints.
func Version(ctx context.Context, cfg Config) (uint, bool, error) {
	srcDriver, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		return 0, false, fmt.Errorf("storage: migration source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", srcDriver, migrateDSN(cfg.DSN))
	if err != nil {
		return 0, false, fmt.Errorf("storage: open migration driver: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	v, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("storage: version: %w", err)
	}
	return v, dirty, nil
}

// Compile-time assertion: the pgx/v5 migrate driver is registered via
// its blank-import side-effect on package init. Keeping the import in
// the same file as Migrate makes this dependency obvious.
var _ = pgx.Postgres{}
