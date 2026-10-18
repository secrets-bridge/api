package storage_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

func TestLogos_UpsertVersionsDeleteAndCascade(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewLogos(pool)

	a, b := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1,'alpha'),($2,'beta')`, a, b); err != nil {
		t.Fatalf("seed projects: %v", err)
	}

	if v, err := repo.Versions(ctx, storage.LogoKindProject, nil); err != nil || len(v) != 0 {
		t.Fatalf("Versions(nil) = %v, %v; want empty", v, err)
	}
	if _, err := repo.Get(ctx, storage.LogoKindProject, a); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get before upsert: %v, want ErrNotFound", err)
	}

	sha := strings.Repeat("ab", 32)
	logo := &storage.Logo{EntityID: a, ObjectKey: "k1", ByteLength: 9, SHA256: sha, Width: 32, Height: 32, UpdatedBy: "tester"}
	prev, err := repo.Upsert(ctx, storage.LogoKindProject, logo)
	if err != nil || prev != "" {
		t.Fatalf("Upsert: prev %q, %v", prev, err)
	}
	if logo.UpdatedAt.IsZero() {
		t.Error("Upsert did not set UpdatedAt")
	}
	// A second upsert replaces the row and reports the key it replaced.
	sha2 := strings.Repeat("cd", 32)
	prev, err = repo.Upsert(ctx, storage.LogoKindProject, &storage.Logo{EntityID: a, ObjectKey: "k2", ByteLength: 3, SHA256: sha2, Width: 16, Height: 16, UpdatedBy: "tester"})
	if err != nil || prev != "k1" {
		t.Fatalf("second Upsert: prev %q, %v; want k1", prev, err)
	}
	got, err := repo.Get(ctx, storage.LogoKindProject, a)
	if err != nil || got.SHA256 != sha2 || got.PNG != nil || got.ObjectKey != "k2" || got.ByteLength != 3 || got.Version() != sha2[:storage.LogoVersionLength] {
		t.Fatalf("Get after replace = %+v, %v", got, err)
	}
	// No image bytes in Postgres for a row written by the new path.
	var inline bool
	if err := pool.QueryRow(ctx, `SELECT png IS NOT NULL FROM project_logos WHERE project_id = $1`, a).Scan(&inline); err != nil || inline {
		t.Fatalf("png column set after Upsert: %v %v", inline, err)
	}

	versions, err := repo.Versions(ctx, storage.LogoKindProject, []uuid.UUID{a, b})
	if err != nil || len(versions) != 1 || versions[a] != sha2[:storage.LogoVersionLength] {
		t.Fatalf("Versions = %v, %v; want only %s", versions, err, a)
	}

	removed, err := repo.Delete(ctx, storage.LogoKindProject, a)
	if err != nil || removed.SHA256 != sha2 || removed.ByteLength != 3 || removed.PNG != nil || removed.ObjectKey != "k2" {
		t.Fatalf("Delete = %+v, %v", removed, err)
	}
	if _, err := repo.Delete(ctx, storage.LogoKindProject, a); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second Delete: %v, want ErrNotFound", err)
	}

	// The logo goes away with its project.
	if _, err := repo.Upsert(ctx, storage.LogoKindProject, &storage.Logo{EntityID: b, ObjectKey: "kb", ByteLength: 1, SHA256: sha, Width: 16, Height: 16, UpdatedBy: "tester"}); err != nil {
		t.Fatalf("Upsert b: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, b); err != nil {
		t.Fatalf("delete project: %v", err)
	}
	if _, err := repo.Get(ctx, storage.LogoKindProject, b); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("logo survived its project: %v", err)
	}

	// The stored image size is capped in the schema too, and a row
	// needs an object key.
	tooBig := &storage.Logo{EntityID: a, ObjectKey: "big", ByteLength: 65537, SHA256: sha, Width: 16, Height: 16, UpdatedBy: "tester"}
	if _, err := repo.Upsert(ctx, storage.LogoKindProject, tooBig); err == nil {
		t.Fatal("a stored logo over 64 KiB was accepted")
	}
	if _, err := repo.Upsert(ctx, storage.LogoKindProject, &storage.Logo{EntityID: a, ByteLength: 1, SHA256: sha, Width: 16, Height: 16, UpdatedBy: "tester"}); err == nil {
		t.Fatal("a logo without an object key was accepted")
	}

	if _, err := repo.Get(ctx, storage.LogoKind("nope"), a); !errors.Is(err, storage.ErrUnknownLogoKind) {
		t.Fatalf("unknown kind: %v", err)
	}
}

func TestLogos_TeamKindUsesTeamTable(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewLogos(pool)
	team := &storage.Team{Name: "payments"}
	if err := storage.NewTeams(pool).Create(ctx, team); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	sha := strings.Repeat("ef", 32)
	if _, err := repo.Upsert(ctx, storage.LogoKindTeam, &storage.Logo{EntityID: team.ID, ObjectKey: "t", ByteLength: 1, SHA256: sha, Width: 20, Height: 20, UpdatedBy: "tester"}); err != nil {
		t.Fatalf("Upsert team logo: %v", err)
	}
	// A project id with the same value has no logo: the kinds don't mix.
	if _, err := repo.Get(ctx, storage.LogoKindProject, team.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("team logo visible as a project logo: %v", err)
	}
	// A logo for a team that doesn't exist is refused by the foreign key.
	if _, err := repo.Upsert(ctx, storage.LogoKindTeam, &storage.Logo{EntityID: uuid.New(), ObjectKey: "t", ByteLength: 1, SHA256: sha, Width: 20, Height: 20, UpdatedBy: "tester"}); err == nil {
		t.Fatal("logo for a missing team was stored")
	}
}

// The foreign key refuses a logo for an owner that doesn't exist, for
// example one deleted after the service checked it. Upsert reports that
// as ErrNotFound rather than a raw constraint error.
func TestLogos_UpsertForMissingOwnerIsNotFound(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewLogos(pool)
	for _, kind := range []storage.LogoKind{storage.LogoKindProject, storage.LogoKindTeam} {
		logo := &storage.Logo{EntityID: uuid.New(), ObjectKey: "k", ByteLength: 9, SHA256: strings.Repeat("ab", 32), Width: 16, Height: 16, UpdatedBy: "tester"}
		if _, err := repo.Upsert(t.Context(), kind, logo); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("%s: Upsert for a missing owner = %v, want ErrNotFound", kind, err)
		}
	}
}

// Rows written before 0040 keep their bytes in png until the backfill
// moves them. ListInline pages through them, MoveToObject switches one
// over only while it still holds the expected image inline, and the
// schema refuses a row with neither png nor object_key.
func TestLogos_InlineRowsAndMoveToObject(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewLogos(pool)

	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for i, id := range ids {
		if _, err := pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1, $2)`, id, "p"+string(rune('a'+i))); err != nil {
			t.Fatalf("seed project: %v", err)
		}
		// The pre-0040 write shape: bytes inline, no object key.
		if _, err := pool.Exec(ctx, `INSERT INTO project_logos (project_id, png, sha256, width, height, updated_by)
			VALUES ($1, $2, $3, 16, 16, 'old')`, id, []byte("inline"), strings.Repeat("ab", 32)); err != nil {
			t.Fatalf("seed inline logo: %v", err)
		}
	}
	if n, err := repo.CountInline(ctx); err != nil || n != 3 {
		t.Fatalf("CountInline = %d, %v", n, err)
	}
	got, err := repo.Get(ctx, storage.LogoKindProject, ids[0])
	if err != nil || string(got.PNG) != "inline" || got.ObjectKey != "" || got.ByteLength != 6 {
		t.Fatalf("Get inline row = %+v, %v", got, err)
	}

	page, err := repo.ListInline(ctx, storage.LogoKindProject, uuid.Nil, 2)
	if err != nil || len(page) != 2 {
		t.Fatalf("ListInline page 1 = %d, %v", len(page), err)
	}
	rest, err := repo.ListInline(ctx, storage.LogoKindProject, page[1].EntityID, 2)
	if err != nil || len(rest) != 1 || string(rest[0].PNG) != "inline" {
		t.Fatalf("ListInline page 2 = %d, %v", len(rest), err)
	}

	// Wrong digest: the row changed since it was listed; nothing moves.
	moved, _, err := repo.MoveToObject(ctx, storage.LogoKindProject, ids[0], strings.Repeat("ff", 32), "k0", 6)
	if err != nil || moved {
		t.Fatalf("MoveToObject with a stale digest = %v, %v", moved, err)
	}
	moved, prev, err := repo.MoveToObject(ctx, storage.LogoKindProject, ids[0], strings.Repeat("ab", 32), "k0", 6)
	if err != nil || !moved || prev != "" {
		t.Fatalf("MoveToObject = %v %q %v", moved, prev, err)
	}
	got, _ = repo.Get(ctx, storage.LogoKindProject, ids[0])
	if got.PNG != nil || got.ObjectKey != "k0" || got.ByteLength != 6 || got.UpdatedBy != "old" {
		t.Fatalf("after move = %+v", got)
	}
	// Moving again is a no-op that reports the current key.
	if moved, prev, err := repo.MoveToObject(ctx, storage.LogoKindProject, ids[0], strings.Repeat("ab", 32), "k0", 6); err != nil || moved || prev != "k0" {
		t.Fatalf("second move = %v %q %v", moved, prev, err)
	}
	if moved, _, err := repo.MoveToObject(ctx, storage.LogoKindProject, uuid.New(), strings.Repeat("ab", 32), "k", 6); err != nil || moved {
		t.Fatalf("move of a missing row = %v %v", moved, err)
	}
	if n, _ := repo.CountInline(ctx); n != 2 {
		t.Fatalf("CountInline after one move = %d", n)
	}

	// An old replica's write (png set) over a moved row: png wins on read,
	// and the row still carries the old key for the backfill to clean.
	if _, err := pool.Exec(ctx, `UPDATE project_logos SET png = $2 WHERE project_id = $1`, ids[0], []byte("newer")); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.Get(ctx, storage.LogoKindProject, ids[0])
	if string(got.PNG) != "newer" || got.ObjectKey != "k0" || got.ByteLength != 5 {
		t.Fatalf("Get after old-replica write = %+v", got)
	}

	if _, err := pool.Exec(ctx, `UPDATE project_logos SET png = NULL, object_key = NULL WHERE project_id = $1`, ids[1]); err == nil {
		t.Fatal("a row with neither png nor object_key was accepted")
	}
}
