package storage_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Tests in this file all rely on the storage_test.go truncate to clean
// teams + team_members + local_users between cases. Each helper boots a
// fresh pool via freshDB(t).

// makeUser inserts a minimal local_users row so a team_members FK can
// resolve. Returns the new UUID.
func makeUser(t *testing.T, pool *storage.Pool, email string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(t.Context(),
		`INSERT INTO local_users (id, email, password_hash, display_name)
		 VALUES ($1, $2, '\x00', $3)`,
		id, email, email,
	)
	if err != nil {
		t.Fatalf("makeUser %q: %v", email, err)
	}
	return id
}

func TestTeams_CRUDLifecycle(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewTeams(pool)
	ctx := t.Context()

	root := &storage.Team{Name: "platform"}
	if err := repo.Create(ctx, root); err != nil {
		t.Fatalf("Create root: %v", err)
	}
	if root.ID == uuid.Nil {
		t.Fatal("Create: ID was not assigned")
	}
	if root.Status != storage.TeamStatusActive {
		t.Errorf("Create: default status got %q want active", root.Status)
	}

	child := &storage.Team{Name: "alpha", ParentTeamID: &root.ID, Description: "alpha squad"}
	if err := repo.Create(ctx, child); err != nil {
		t.Fatalf("Create child: %v", err)
	}

	got, err := repo.Get(ctx, child.ID)
	if err != nil {
		t.Fatalf("Get child: %v", err)
	}
	if got.Name != "alpha" || got.ParentTeamID == nil || *got.ParentTeamID != root.ID {
		t.Errorf("Get child mismatch: %+v", got)
	}
	if got.Description != "alpha squad" {
		t.Errorf("Get child Description: got %q want %q", got.Description, "alpha squad")
	}

	all, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("List: got %d teams, want 2", len(all))
	}

	if err := repo.Update(ctx, child.ID, "alpha-renamed", "", &root.ID); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ = repo.Get(ctx, child.ID)
	if got.Name != "alpha-renamed" || got.Description != "" {
		t.Errorf("Update did not apply: %+v", got)
	}

	if err := repo.UpdateStatus(ctx, child.ID, storage.TeamStatusArchived); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	got, _ = repo.Get(ctx, child.ID)
	if got.Status != storage.TeamStatusArchived {
		t.Errorf("UpdateStatus: got %q want archived", got.Status)
	}

	if err := repo.Delete(ctx, child.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repo.Get(ctx, child.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get after Delete: want ErrNotFound, got %v", err)
	}
}

func TestTeams_DuplicateNameAmongSiblings(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewTeams(pool)
	ctx := t.Context()

	parent := &storage.Team{Name: "platform"}
	if err := repo.Create(ctx, parent); err != nil {
		t.Fatalf("Create parent: %v", err)
	}
	c1 := &storage.Team{Name: "alpha", ParentTeamID: &parent.ID}
	if err := repo.Create(ctx, c1); err != nil {
		t.Fatalf("Create c1: %v", err)
	}
	c2 := &storage.Team{Name: "alpha", ParentTeamID: &parent.ID}
	if err := repo.Create(ctx, c2); !errors.Is(err, storage.ErrDuplicateName) {
		t.Fatalf("Create c2 (same name, same parent): want ErrDuplicateName, got %v", err)
	}
}

func TestTeams_DuplicateRootName(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewTeams(pool)
	ctx := t.Context()

	if err := repo.Create(ctx, &storage.Team{Name: "platform"}); err != nil {
		t.Fatalf("Create first root: %v", err)
	}
	err := repo.Create(ctx, &storage.Team{Name: "platform"})
	if !errors.Is(err, storage.ErrDuplicateName) {
		t.Fatalf("Create second root with same name: want ErrDuplicateName, got %v", err)
	}
}

func TestTeams_SameNameAcrossDifferentParents(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewTeams(pool)
	ctx := t.Context()

	p1 := &storage.Team{Name: "platform"}
	p2 := &storage.Team{Name: "security"}
	if err := repo.Create(ctx, p1); err != nil {
		t.Fatalf("Create p1: %v", err)
	}
	if err := repo.Create(ctx, p2); err != nil {
		t.Fatalf("Create p2: %v", err)
	}

	// Both parents get an "ops" child — must succeed.
	if err := repo.Create(ctx, &storage.Team{Name: "ops", ParentTeamID: &p1.ID}); err != nil {
		t.Fatalf("Create p1.ops: %v", err)
	}
	if err := repo.Create(ctx, &storage.Team{Name: "ops", ParentTeamID: &p2.ID}); err != nil {
		t.Errorf("Create p2.ops should succeed (different parents): %v", err)
	}
}

func TestTeams_DescendantIDs(t *testing.T) {
	// Build:
	//   root
	//   ├── east
	//   │   ├── east-billing
	//   │   └── east-audit
	//   └── west
	pool := freshDB(t)
	repo := storage.NewTeams(pool)
	ctx := t.Context()

	root := &storage.Team{Name: "root"}
	if err := repo.Create(ctx, root); err != nil {
		t.Fatalf("Create root: %v", err)
	}
	east := &storage.Team{Name: "east", ParentTeamID: &root.ID}
	if err := repo.Create(ctx, east); err != nil {
		t.Fatalf("Create east: %v", err)
	}
	west := &storage.Team{Name: "west", ParentTeamID: &root.ID}
	if err := repo.Create(ctx, west); err != nil {
		t.Fatalf("Create west: %v", err)
	}
	eastBilling := &storage.Team{Name: "billing", ParentTeamID: &east.ID}
	if err := repo.Create(ctx, eastBilling); err != nil {
		t.Fatalf("Create east.billing: %v", err)
	}
	eastAudit := &storage.Team{Name: "audit", ParentTeamID: &east.ID}
	if err := repo.Create(ctx, eastAudit); err != nil {
		t.Fatalf("Create east.audit: %v", err)
	}

	gotRoot, err := repo.DescendantIDs(ctx, root.ID)
	if err != nil {
		t.Fatalf("DescendantIDs(root): %v", err)
	}
	if len(gotRoot) != 5 {
		t.Fatalf("DescendantIDs(root): got %d want 5 (root+east+west+billing+audit)", len(gotRoot))
	}

	gotEast, err := repo.DescendantIDs(ctx, east.ID)
	if err != nil {
		t.Fatalf("DescendantIDs(east): %v", err)
	}
	// east + east.billing + east.audit  →  3
	if len(gotEast) != 3 {
		t.Fatalf("DescendantIDs(east): got %d want 3 (east+billing+audit)", len(gotEast))
	}

	// Leaf with no descendants is just itself.
	gotLeaf, err := repo.DescendantIDs(ctx, eastBilling.ID)
	if err != nil {
		t.Fatalf("DescendantIDs(eastBilling): %v", err)
	}
	if len(gotLeaf) != 1 || gotLeaf[0] != eastBilling.ID {
		t.Errorf("DescendantIDs(leaf): got %v want [%v]", gotLeaf, eastBilling.ID)
	}
}

func TestTeams_AncestorIDs(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewTeams(pool)
	ctx := t.Context()

	root := &storage.Team{Name: "root"}
	if err := repo.Create(ctx, root); err != nil {
		t.Fatalf("Create root: %v", err)
	}
	mid := &storage.Team{Name: "mid", ParentTeamID: &root.ID}
	if err := repo.Create(ctx, mid); err != nil {
		t.Fatalf("Create mid: %v", err)
	}
	leaf := &storage.Team{Name: "leaf", ParentTeamID: &mid.ID}
	if err := repo.Create(ctx, leaf); err != nil {
		t.Fatalf("Create leaf: %v", err)
	}

	got, err := repo.AncestorIDs(ctx, leaf.ID)
	if err != nil {
		t.Fatalf("AncestorIDs: %v", err)
	}
	// leaf → mid → root  ⇒  3 ids
	if len(got) != 3 {
		t.Fatalf("AncestorIDs: got %d want 3", len(got))
	}
	if got[0] != leaf.ID || got[2] != root.ID {
		t.Errorf("AncestorIDs ordering: got %v", got)
	}
}

func TestTeams_CycleRejected(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewTeams(pool)
	ctx := t.Context()

	a := &storage.Team{Name: "a"}
	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	b := &storage.Team{Name: "b", ParentTeamID: &a.ID}
	if err := repo.Create(ctx, b); err != nil {
		t.Fatalf("Create b: %v", err)
	}
	// Try to set a.parent = b — b is in a's subtree, must be rejected.
	if err := repo.Update(ctx, a.ID, "a", "", &b.ID); !errors.Is(err, storage.ErrCyclicParent) {
		t.Fatalf("self-cycle: want ErrCyclicParent, got %v", err)
	}
	// Direct self-parent is also a cycle.
	if err := repo.Update(ctx, a.ID, "a", "", &a.ID); !errors.Is(err, storage.ErrCyclicParent) {
		t.Fatalf("direct self-parent: want ErrCyclicParent, got %v", err)
	}
}

func TestTeams_DeleteRejectsTeamWithChildren(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewTeams(pool)
	ctx := t.Context()

	parent := &storage.Team{Name: "parent"}
	if err := repo.Create(ctx, parent); err != nil {
		t.Fatalf("Create parent: %v", err)
	}
	child := &storage.Team{Name: "child", ParentTeamID: &parent.ID}
	if err := repo.Create(ctx, child); err != nil {
		t.Fatalf("Create child: %v", err)
	}
	err := repo.Delete(ctx, parent.ID)
	if !errors.Is(err, storage.ErrHasChildren) {
		t.Fatalf("Delete parent (has child): want ErrHasChildren, got %v", err)
	}
	// Unparent the child, then parent is deletable.
	if err := repo.Update(ctx, child.ID, "child", "", nil); err != nil {
		t.Fatalf("Unparent child: %v", err)
	}
	if err := repo.Delete(ctx, parent.ID); err != nil {
		t.Errorf("Delete parent after unparent: %v", err)
	}
}

func TestTeams_Membership(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewTeams(pool)
	ctx := t.Context()

	team := &storage.Team{Name: "alpha"}
	if err := repo.Create(ctx, team); err != nil {
		t.Fatalf("Create team: %v", err)
	}
	u1 := makeUser(t, pool, "alice@example.com")
	u2 := makeUser(t, pool, "bob@example.com")
	by := makeUser(t, pool, "admin@example.com")

	if err := repo.AddMember(ctx, team.ID, u1, &by); err != nil {
		t.Fatalf("AddMember alice: %v", err)
	}
	if err := repo.AddMember(ctx, team.ID, u2, &by); err != nil {
		t.Fatalf("AddMember bob: %v", err)
	}

	// Duplicate add fails cleanly.
	err := repo.AddMember(ctx, team.ID, u1, &by)
	if !errors.Is(err, storage.ErrAlreadyMember) {
		t.Fatalf("AddMember duplicate: want ErrAlreadyMember, got %v", err)
	}

	members, err := repo.ListMembers(ctx, team.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("ListMembers: got %d want 2", len(members))
	}

	teams, err := repo.ListTeamsForUser(ctx, u1)
	if err != nil {
		t.Fatalf("ListTeamsForUser: %v", err)
	}
	if len(teams) != 1 || teams[0].ID != team.ID {
		t.Errorf("ListTeamsForUser(alice): got %v want one team %v", teams, team.ID)
	}

	if err := repo.RemoveMember(ctx, team.ID, u1); err != nil {
		t.Fatalf("RemoveMember alice: %v", err)
	}
	if err := repo.RemoveMember(ctx, team.ID, u1); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("RemoveMember alice (again): want ErrNotFound, got %v", err)
	}
}

func TestTeams_DeleteCascadesMemberships(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewTeams(pool)
	ctx := t.Context()

	team := &storage.Team{Name: "ephemeral"}
	if err := repo.Create(ctx, team); err != nil {
		t.Fatalf("Create team: %v", err)
	}
	u := makeUser(t, pool, "carol@example.com")
	if err := repo.AddMember(ctx, team.ID, u, nil); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := repo.Delete(ctx, team.ID); err != nil {
		t.Fatalf("Delete team: %v", err)
	}
	// team_members row is gone via CASCADE.
	teams, err := repo.ListTeamsForUser(ctx, u)
	if err != nil {
		t.Fatalf("ListTeamsForUser after team delete: %v", err)
	}
	if len(teams) != 0 {
		t.Errorf("expected 0 teams for carol after cascade, got %d", len(teams))
	}
}
