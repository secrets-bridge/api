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
	logo := &storage.Logo{EntityID: a, PNG: []byte("png-bytes"), SHA256: sha, Width: 32, Height: 32, UpdatedBy: "tester"}
	if err := repo.Upsert(ctx, storage.LogoKindProject, logo); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if logo.UpdatedAt.IsZero() {
		t.Error("Upsert did not set UpdatedAt")
	}
	// A second upsert replaces the row.
	sha2 := strings.Repeat("cd", 32)
	if err := repo.Upsert(ctx, storage.LogoKindProject, &storage.Logo{EntityID: a, PNG: []byte("new"), SHA256: sha2, Width: 16, Height: 16, UpdatedBy: "tester"}); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	got, err := repo.Get(ctx, storage.LogoKindProject, a)
	if err != nil || got.SHA256 != sha2 || string(got.PNG) != "new" || got.ByteLength != 3 || got.Version() != sha2[:storage.LogoVersionLength] {
		t.Fatalf("Get after replace = %+v, %v", got, err)
	}

	versions, err := repo.Versions(ctx, storage.LogoKindProject, []uuid.UUID{a, b})
	if err != nil || len(versions) != 1 || versions[a] != sha2[:storage.LogoVersionLength] {
		t.Fatalf("Versions = %v, %v; want only %s", versions, err, a)
	}

	removed, err := repo.Delete(ctx, storage.LogoKindProject, a)
	if err != nil || removed.SHA256 != sha2 || removed.ByteLength != 3 || removed.PNG != nil {
		t.Fatalf("Delete = %+v, %v", removed, err)
	}
	if _, err := repo.Delete(ctx, storage.LogoKindProject, a); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second Delete: %v, want ErrNotFound", err)
	}

	// The logo goes away with its project.
	if err := repo.Upsert(ctx, storage.LogoKindProject, &storage.Logo{EntityID: b, PNG: []byte("x"), SHA256: sha, Width: 16, Height: 16, UpdatedBy: "tester"}); err != nil {
		t.Fatalf("Upsert b: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, b); err != nil {
		t.Fatalf("delete project: %v", err)
	}
	if _, err := repo.Get(ctx, storage.LogoKindProject, b); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("logo survived its project: %v", err)
	}

	// The stored image is capped in the schema too.
	tooBig := &storage.Logo{EntityID: a, PNG: make([]byte, 65537), SHA256: sha, Width: 16, Height: 16, UpdatedBy: "tester"}
	if err := repo.Upsert(ctx, storage.LogoKindProject, tooBig); err == nil {
		t.Fatal("a stored logo over 64 KiB was accepted")
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
	if err := repo.Upsert(ctx, storage.LogoKindTeam, &storage.Logo{EntityID: team.ID, PNG: []byte("t"), SHA256: sha, Width: 20, Height: 20, UpdatedBy: "tester"}); err != nil {
		t.Fatalf("Upsert team logo: %v", err)
	}
	// A project id with the same value has no logo: the kinds don't mix.
	if _, err := repo.Get(ctx, storage.LogoKindProject, team.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("team logo visible as a project logo: %v", err)
	}
	// A logo for a team that doesn't exist is refused by the foreign key.
	if err := repo.Upsert(ctx, storage.LogoKindTeam, &storage.Logo{EntityID: uuid.New(), PNG: []byte("t"), SHA256: sha, Width: 20, Height: 20, UpdatedBy: "tester"}); err == nil {
		t.Fatal("logo for a missing team was stored")
	}
}
