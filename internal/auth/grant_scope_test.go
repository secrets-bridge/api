package auth_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// API-N-06: grant scopes are validated on write and fail closed on read.

func TestNormalizeGrantScope_AcceptsAndCanonicalises(t *testing.T) {
	pid := uuid.New()
	tid := uuid.New()
	got, err := auth.NormalizeGrantScope(map[string]any{
		"project_id":        strings.ToUpper(pid.String()),
		"team_id":           tid.String(),
		"environment":       "uat",
		"secret_ref_prefix": "team-alpha/uat/",
		"provider_type":     "vault",
	})
	if err != nil {
		t.Fatalf("valid scope refused: %v", err)
	}
	if got["project_id"] != pid.String() {
		t.Errorf("project_id not canonical: %v", got["project_id"])
	}
	if got["team_id"] != tid.String() || got["environment"] != "uat" {
		t.Errorf("scope changed unexpectedly: %v", got)
	}

	for _, empty := range []map[string]any{nil, {}} {
		got, err := auth.NormalizeGrantScope(empty)
		if err != nil || len(got) != 0 {
			t.Errorf("global scope %v -> %v, %v; want empty, nil", empty, got, err)
		}
	}
}

func TestNormalizeGrantScope_RejectsMalformed(t *testing.T) {
	cases := map[string]map[string]any{
		"empty project_id":   {"project_id": ""},
		"null project_id":    {"project_id": nil},
		"numeric team_id":    {"team_id": 123},
		"non-uuid project":   {"project_id": "tenant-a"},
		"unknown key":        {"tenant": "tenant-a"},
		"empty prefix":       {"secret_ref_prefix": ""},
		"blank environment":  {"environment": "   "},
		"bool provider_type": {"provider_type": true},
		"object value":       {"environment": map[string]any{"name": "uat"}},
		"one bad among good": {"project_id": uuid.NewString(), "environment": ""},
	}
	for name, scope := range cases {
		if _, err := auth.NormalizeGrantScope(scope); !errors.Is(err, auth.ErrInvalidGrantScope) {
			t.Errorf("%s: err = %v, want ErrInvalidGrantScope", name, err)
		}
	}
}

func TestNormalizeGrantScope_ErrorDoesNotEchoValues(t *testing.T) {
	_, err := auth.NormalizeGrantScope(map[string]any{"tenant-secret-key": "tenant-secret-value"})
	if err == nil || strings.Contains(err.Error(), "tenant-secret") {
		t.Fatalf("error should not echo caller input: %v", err)
	}
}

// --- RepoResolver over in-memory repositories --------------------------

type fakeUserRoles struct {
	storage.UserRoleRepository
	rows []*storage.UserRole
}

func (f *fakeUserRoles) ListByUser(_ context.Context, userID string) ([]*storage.UserRole, error) {
	var out []*storage.UserRole
	for _, r := range f.rows {
		if r.UserID == userID {
			out = append(out, r)
		}
	}
	return out, nil
}

type fakeRoles struct {
	storage.RoleRepository
	byID map[uuid.UUID]*storage.Role
}

func (f *fakeRoles) Get(_ context.Context, id uuid.UUID) (*storage.Role, error) {
	if r, ok := f.byID[id]; ok {
		return r, nil
	}
	return nil, storage.ErrNotFound
}

func TestRepoResolver_MalformedScopeCoversNothing(t *testing.T) {
	roleID := uuid.New()
	roles := &fakeRoles{byID: map[uuid.UUID]*storage.Role{
		roleID: {ID: roleID, Permissions: []string{string(auth.PermAuditRead)}},
	}}
	pid := uuid.NewString()
	urs := &fakeUserRoles{rows: []*storage.UserRole{
		{ID: uuid.New(), UserID: "empty-pid", RoleID: roleID, Scope: map[string]any{"project_id": ""}},
		{ID: uuid.New(), UserID: "null-pid", RoleID: roleID, Scope: map[string]any{"project_id": nil}},
		{ID: uuid.New(), UserID: "num-team", RoleID: roleID, Scope: map[string]any{"team_id": float64(123)}},
		{ID: uuid.New(), UserID: "partial", RoleID: roleID, Scope: map[string]any{"project_id": "", "environment": "uat"}},
		{ID: uuid.New(), UserID: "non-object", RoleID: roleID, ScopeMalformed: true},
		{ID: uuid.New(), UserID: "global", RoleID: roleID, Scope: map[string]any{}},
		{ID: uuid.New(), UserID: "legacy-nil", RoleID: roleID},
		{ID: uuid.New(), UserID: "scoped", RoleID: roleID, Scope: map[string]any{"project_id": pid}},
	}}
	r := auth.NewRepoResolver(urs, roles)

	for _, user := range []string{"empty-pid", "null-pid", "num-team", "partial", "non-object"} {
		grants, err := r.Resolve(context.Background(), user)
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		if len(grants) != 0 {
			t.Errorf("%s: malformed grant resolved to %v; want none", user, grants)
		}
	}

	grants, _ := r.Resolve(context.Background(), "scoped")
	if len(grants) != 1 || grants[0].Scope["project_id"] != pid {
		t.Errorf("well-formed scoped grant = %v", grants)
	}
	for _, user := range []string{"global", "legacy-nil"} {
		grants, _ := r.Resolve(context.Background(), user)
		if len(grants) != 1 || len(grants[0].Scope) != 0 {
			t.Errorf("%s: global grant = %v; want one empty-scope grant", user, grants)
		}
	}

	// End to end through the global-only gate.
	app := fiber.New()
	gate := auth.Require(auth.PermAuditRead, r)
	for _, user := range []string{"empty-pid", "null-pid", "num-team", "partial", "non-object", "global"} {
		u := user
		app.Get("/"+u, fakeAuth(u), gate, okHandler)
	}
	for user, want := range map[string]int{
		"empty-pid": 403, "null-pid": 403, "num-team": 403, "partial": 403, "non-object": 403, "global": 204,
	} {
		resp, err := app.Test(httptest.NewRequest("GET", "/"+user, nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Errorf("%s through Require = %d, want %d", user, resp.StatusCode, want)
		}
	}
}

// --- ProjectAccessForAny ------------------------------------------------

type countingResolver struct {
	grants []auth.Grant
	calls  int
}

func (c *countingResolver) Resolve(context.Context, string) ([]auth.Grant, error) {
	c.calls++
	return c.grants, nil
}

func TestProjectAccessForAny_UnionsAndResolvesOnce(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	r := &countingResolver{grants: []auth.Grant{
		{Permission: string(auth.PermSecretList), Scope: map[string]string{"project_id": a.String()}},
		{Permission: string(auth.PermPolicyAuthor), Scope: map[string]string{"project_id": b.String()}},
		{Permission: string(auth.PermAuditRead)}, // global, but not in the asked set
	}}
	pa, err := auth.ProjectAccessForAny(context.Background(), "u", r, nil,
		auth.PermSecretList, auth.PermSecretRequest, auth.PermPolicyAuthor)
	if err != nil {
		t.Fatal(err)
	}
	if pa.IsGlobal || !pa.Covers(a) || !pa.Covers(b) || len(pa.ProjectIDs) != 2 {
		t.Errorf("union = %+v; want exactly {a, b}, not global", pa)
	}
	if r.calls != 1 {
		t.Errorf("resolver called %d times; want 1", r.calls)
	}

	// Without policy.author, b is not covered.
	pa, _ = auth.ProjectAccessForAny(context.Background(), "u", r, nil, auth.PermSecretList, auth.PermSecretRequest)
	if pa.Covers(b) {
		t.Error("project b covered without policy.author in the set")
	}

	// A global grant on any listed permission is global.
	r.grants = append(r.grants, auth.Grant{Permission: string(auth.PermSecretRequest)})
	pa, _ = auth.ProjectAccessForAny(context.Background(), "u", r, nil, auth.PermSecretList, auth.PermSecretRequest)
	if !pa.IsGlobal {
		t.Error("global secret.request should make the union global")
	}

	// No identity → no access.
	pa, _ = auth.ProjectAccessForAny(context.Background(), "", r, nil, auth.PermSecretList)
	if pa.IsGlobal || len(pa.ProjectIDs) != 0 {
		t.Errorf("empty user = %+v; want nothing", pa)
	}
}
