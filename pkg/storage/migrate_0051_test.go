package storage

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// Migration 0051 on existing rows (skills#116): an agent without a usable
// key is revoked, an agent with one keeps it at version 1 with the
// fingerprint recomputed from the key, and the down migration reverts
// cleanly.
func TestMigration0051_ExistingAgents(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := Config{DSN: dsn, MaxConns: 2, ConnLifetime: time.Minute}
	if err := Migrate(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	src, err := iofs.New(migrationFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, migrateDSN(dsn))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.Close() }()
	// Leave the database at head for the other tests.
	t.Cleanup(func() { _ = Migrate(context.Background(), cfg) })

	pool, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `TRUNCATE agents RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(50); err != nil {
		t.Fatalf("down to 50: %v", err)
	}

	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub := priv.PublicKey().Bytes()
	if _, err := pool.Exec(ctx, `
		INSERT INTO agents (name, scope, status, secret_hash, public_key, public_key_algorithm, public_key_fingerprint) VALUES
		  ('keyless', '{}', 'active', '\x01', NULL, NULL, NULL),
		  ('short',   '{}', 'enrolled', '\x01', '\x0102', 'x25519', 'agent-said-so'),
		  ('keyed',   '{}', 'active', '\x01', $1, 'x25519', 'agent-said-so'),
		  ('gone',    '{}', 'revoked', '\x01', NULL, NULL, NULL)`, pub); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("up: %v", err)
	}
	sum := sha256.Sum256(pub)
	short := sha256.Sum256([]byte{1, 2})
	want := map[string]struct{ status, fp string }{
		"keyless": {"revoked", ""},
		"short":   {"revoked", "sha256:" + hex.EncodeToString(short[:])},
		"keyed":   {"active", "sha256:" + hex.EncodeToString(sum[:])},
		"gone":    {"revoked", ""},
	}
	rows, err := pool.Query(ctx, `SELECT name, status, COALESCE(public_key_fingerprint, ''), public_key_version, COALESCE(revoked_by, '') FROM agents`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, status, fp, by string
		var version int
		if err := rows.Scan(&name, &status, &fp, &version, &by); err != nil {
			t.Fatal(err)
		}
		w := want[name]
		if status != w.status || fp != w.fp || version != 1 {
			t.Errorf("%s: status=%s fp=%q version=%d; want %s %q 1", name, status, fp, version, w.status, w.fp)
		}
		if (name == "keyless" || name == "short") && by != "migration:0051_agent_enrollment_v2" {
			t.Errorf("%s revoked_by = %q", name, by)
		}
	}
	if err := m.Migrate(50); err != nil {
		t.Fatalf("down again: %v", err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
