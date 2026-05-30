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
	pa, err := auth.EffectiveProjectAccess(context.Background(), "", auth.PermSecretList, &scopeStub{})
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
	_, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList, nil)
	if err == nil {
		t.Fatal("expected error on nil resolver")
	}
}

func TestEffectiveProjectAccess_ResolverError(t *testing.T) {
	want := errors.New("boom")
	_, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList, &scopeStub{err: want})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

func TestEffectiveProjectAccess_GlobalAdmin(t *testing.T) {
	pa, err := auth.EffectiveProjectAccess(context.Background(), "u1", auth.PermSecretList,
		&scopeStub{grants: []auth.Grant{{Permission: "secret.list"}}})
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
		&scopeStub{grants: []auth.Grant{{Permission: "secret.list", Scope: map[string]string{"environment": "uat"}}}})
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
		}})
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
		}})
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
