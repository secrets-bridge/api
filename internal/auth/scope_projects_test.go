package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
)

type scopeStub struct {
	grants []auth.Grant
	err    error
}

func (s *scopeStub) Resolve(ctx context.Context, userID string) ([]auth.Grant, error) {
	return s.grants, s.err
}

func TestEffectiveProjectAccess_EmptyUserID(t *testing.T) {
	pa, err := auth.EffectiveProjectAccess(context.Background(), "", auth.PermSecretList, &scopeStub{}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if pa.IsGlobal {
		t.Fatal("expected IsGlobal false")
	}
	if len(pa.ProjectIDs) != 0 {
		t.Fatalf("expected empty, got %v", pa.ProjectIDs)
	}
}

func TestEffectiveProjectAccess_NilResolver(t *testing.T) {
	_, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList, nil, nil)
	if err == nil {
		t.Fatal("expected error on nil resolver")
	}
}

func TestEffectiveProjectAccess_ResolverError(t *testing.T) {
	want := errors.New("boom")
	_, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList, &scopeStub{err: want}, nil)
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

func TestEffectiveProjectAccess_GlobalAdmin(t *testing.T) {
	pa, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList,
		&scopeStub{grants: []auth.Grant{{Permission: "secret.list"}}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !pa.IsGlobal {
		t.Fatal("expected IsGlobal true (empty scope = global)")
	}
}

func TestEffectiveProjectAccess_NonProjectScopeIsGlobalForFilter(t *testing.T) {
	// A grant scoped to environment but not project should not narrow
	// the project filter — Slice C still enforces env later.
	pa, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList,
		&scopeStub{grants: []auth.Grant{{Permission: "secret.list", Scope: map[string]string{"environment": "uat"}}}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !pa.IsGlobal {
		t.Fatal("expected IsGlobal true when scope has no project_id key")
	}
}

func TestEffectiveProjectAccess_ProjectScopedCollectsUUIDs(t *testing.T) {
	p1 := uuid.New()
	p2 := uuid.New()
	other := uuid.New()
	pa, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList,
		&scopeStub{grants: []auth.Grant{
			{Permission: "secret.list", Scope: map[string]string{"project_id": p1.String()}},
			{Permission: "secret.list", Scope: map[string]string{"project_id": p2.String()}},
			{Permission: "secret.request", Scope: map[string]string{"project_id": other.String()}}, // wrong perm — ignored
			{Permission: "secret.list", Scope: map[string]string{"project_id": p1.String()}},      // duplicate — dedup
		}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if pa.IsGlobal {
		t.Fatal("expected IsGlobal false")
	}
	if len(pa.ProjectIDs) != 2 {
		t.Fatalf("expected 2 unique project ids, got %d: %v", len(pa.ProjectIDs), pa.ProjectIDs)
	}
}

func TestEffectiveProjectAccess_BadUUIDIsDropped(t *testing.T) {
	pa, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList,
		&scopeStub{grants: []auth.Grant{
			{Permission: "secret.list", Scope: map[string]string{"project_id": "not-a-uuid"}},
		}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if pa.IsGlobal {
		t.Fatal("expected IsGlobal false")
	}
	if len(pa.ProjectIDs) != 0 {
		t.Fatalf("expected dropped bad uuid, got %v", pa.ProjectIDs)
	}
}

// --- team-scoped grants ---------------------------------------------

// fakeTeamScope is a hand-rolled TeamScopeResolver. The descendants
// map is canonical (root → entire subtree including root itself);
// the projects map answers "which projects sit under these teams".
type fakeTeamScope struct {
	descendants map[uuid.UUID][]uuid.UUID
	projects    map[uuid.UUID][]uuid.UUID
	descErr     error
	projErr     error
}

func (f *fakeTeamScope) DescendantTeamIDs(_ context.Context, root uuid.UUID) ([]uuid.UUID, error) {
	if f.descErr != nil {
		return nil, f.descErr
	}
	return f.descendants[root], nil
}

func (f *fakeTeamScope) ProjectIDsForTeams(_ context.Context, teamIDs []uuid.UUID) ([]uuid.UUID, error) {
	if f.projErr != nil {
		return nil, f.projErr
	}
	seen := map[uuid.UUID]struct{}{}
	var out []uuid.UUID
	for _, t := range teamIDs {
		for _, p := range f.projects[t] {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}

func TestEffectiveProjectAccess_TeamScopeExpandsSubtree(t *testing.T) {
	root, mid, leaf := uuid.New(), uuid.New(), uuid.New()
	pRoot, pMid, pLeaf := uuid.New(), uuid.New(), uuid.New()
	tr := &fakeTeamScope{
		descendants: map[uuid.UUID][]uuid.UUID{
			root: {root, mid, leaf},
		},
		projects: map[uuid.UUID][]uuid.UUID{
			root: {pRoot},
			mid:  {pMid},
			leaf: {pLeaf},
		},
	}
	pa, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretApprove,
		&scopeStub{grants: []auth.Grant{
			{Permission: "secret.approve", Scope: map[string]string{"team_id": root.String()}},
		}}, tr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if pa.IsGlobal {
		t.Fatal("expected IsGlobal false")
	}
	if len(pa.ProjectIDs) != 3 {
		t.Fatalf("expected 3 projects rolled up from subtree, got %d: %v", len(pa.ProjectIDs), pa.ProjectIDs)
	}
}

func TestEffectiveProjectAccess_TeamScopeIgnoredWhenResolverNil(t *testing.T) {
	team := uuid.New()
	pa, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretApprove,
		&scopeStub{grants: []auth.Grant{
			{Permission: "secret.approve", Scope: map[string]string{"team_id": team.String()}},
		}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if pa.IsGlobal {
		t.Fatal("expected IsGlobal false")
	}
	if len(pa.ProjectIDs) != 0 {
		t.Fatalf("expected no projects when no team scope resolver, got %v", pa.ProjectIDs)
	}
}

func TestEffectiveProjectAccess_TeamAndProjectScopeMerge(t *testing.T) {
	root := uuid.New()
	pSub := uuid.New()
	pDirect := uuid.New()
	tr := &fakeTeamScope{
		descendants: map[uuid.UUID][]uuid.UUID{root: {root}},
		projects:    map[uuid.UUID][]uuid.UUID{root: {pSub}},
	}
	pa, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList,
		&scopeStub{grants: []auth.Grant{
			{Permission: "secret.list", Scope: map[string]string{"team_id": root.String()}},
			{Permission: "secret.list", Scope: map[string]string{"project_id": pDirect.String()}},
		}}, tr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if pa.IsGlobal {
		t.Fatal("expected IsGlobal false")
	}
	if len(pa.ProjectIDs) != 2 {
		t.Fatalf("expected pSub + pDirect merged, got %d: %v", len(pa.ProjectIDs), pa.ProjectIDs)
	}
}

func TestEffectiveProjectAccess_TeamScopeGlobalGrantStillShortCircuits(t *testing.T) {
	root := uuid.New()
	tr := &fakeTeamScope{
		descendants: map[uuid.UUID][]uuid.UUID{root: {root}},
	}
	pa, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList,
		&scopeStub{grants: []auth.Grant{
			{Permission: "secret.list", Scope: map[string]string{"team_id": root.String()}},
			{Permission: "secret.list"}, // empty scope = global; should win
		}}, tr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !pa.IsGlobal {
		t.Fatal("expected IsGlobal true (global grant wins over team-scoped)")
	}
}

// --- EffectiveTeamAccess --------------------------------------------

func TestEffectiveTeamAccess_GlobalShortCircuits(t *testing.T) {
	ta, err := auth.EffectiveTeamAccess(context.Background(), "u1", auth.PermSecretApprove,
		&scopeStub{grants: []auth.Grant{{Permission: "secret.approve"}}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ta.IsGlobal {
		t.Fatal("expected IsGlobal true on empty-scope grant")
	}
}

func TestEffectiveTeamAccess_ExpandsAndDedups(t *testing.T) {
	root, mid, leaf := uuid.New(), uuid.New(), uuid.New()
	tr := &fakeTeamScope{
		descendants: map[uuid.UUID][]uuid.UUID{
			root: {root, mid, leaf},
			mid:  {mid, leaf}, // overlaps with root's subtree
		},
	}
	ta, err := auth.EffectiveTeamAccess(context.Background(), "u1", auth.PermSecretApprove,
		&scopeStub{grants: []auth.Grant{
			{Permission: "secret.approve", Scope: map[string]string{"team_id": root.String()}},
			{Permission: "secret.approve", Scope: map[string]string{"team_id": mid.String()}},
		}}, tr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ta.IsGlobal {
		t.Fatal("expected IsGlobal false")
	}
	if len(ta.TeamIDs) != 3 {
		t.Fatalf("expected 3 deduped team ids, got %d: %v", len(ta.TeamIDs), ta.TeamIDs)
	}
}

func TestEffectiveTeamAccess_NonTeamScopeIgnored(t *testing.T) {
	ta, err := auth.EffectiveTeamAccess(context.Background(), "u1", auth.PermSecretApprove,
		&scopeStub{grants: []auth.Grant{
			{Permission: "secret.approve", Scope: map[string]string{"project_id": uuid.New().String()}},
		}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ta.IsGlobal {
		t.Fatal("expected IsGlobal false")
	}
	if len(ta.TeamIDs) != 0 {
		t.Fatalf("expected empty TeamIDs, got %v", ta.TeamIDs)
	}
}
