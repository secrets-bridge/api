package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

// api#167 — the cross-team inbox LIST (GET /requests/inbox) and its badge
// COUNT (GET /requests/inbox/count) must resolve team scope identically.
// Before the fix, an explicit out-of-scope team_id was a 403 on the list
// but a 200 {"total":0} on the count (silent, inconsistent, and the count
// ignored the filter entirely). Both now delegate to one shared
// resolveInboxTeamScope helper, so every input yields the same status.

type inboxScopeFixture struct {
	app            *fiber.App
	teamB          uuid.UUID
	otherTeam      uuid.UUID
	globalProvider uuid.UUID // secret.value.provide at global scope
	teamProvider   uuid.UUID // secret.value.provide scoped to teamB only
}

func bootstrapInboxScope(t *testing.T) *inboxScopeFixture {
	t.Helper()
	enableHeaderIdentityForTest(t)
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 4, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	const wipe = `
		DELETE FROM reveal_sessions;
		DELETE FROM secret_wraps;
		DELETE FROM approvals;
		DELETE FROM sync_jobs;
		DELETE FROM access_requests;
		DELETE FROM project_secrets;
		DELETE FROM secrets;
		DELETE FROM team_members;
		DELETE FROM teams;
		DELETE FROM user_roles;
		DELETE FROM roles WHERE is_system = false;
		DELETE FROM environments;
		DELETE FROM projects;
		DELETE FROM local_users;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}

	fx := &inboxScopeFixture{}

	teamsRepo := storage.NewTeams(pool)
	teamB := &storage.Team{Name: "inbox-team-b"}
	if err := teamsRepo.Create(ctx, teamB); err != nil {
		t.Fatalf("team B: %v", err)
	}
	fx.teamB = teamB.ID
	otherTeam := &storage.Team{Name: "inbox-other-team"}
	if err := teamsRepo.Create(ctx, otherTeam); err != nil {
		t.Fatalf("other team: %v", err)
	}
	fx.otherTeam = otherTeam.ID

	fx.globalProvider = seedUserWithGrant(t, pool, "inbox-global", `["secret.value.provide"]`, "{}")
	fx.teamProvider = seedUserWithGrant(t, pool, "inbox-team", `["secret.value.provide"]`,
		`{"team_id":"`+fx.teamB.String()+`"}`)

	// Wire the CrossTeam handler exactly as cmd/api/main.go does: a real
	// repo-backed resolver + team-scope resolver. Inbox only needs the
	// RequestService's ListInbox path, so the other deps are minimal.
	userRoles := storage.NewUserRoles(pool)
	roles := storage.NewRoles(pool)
	projectRepo := storage.NewProjects(pool)
	resolver := auth.NewRepoResolver(userRoles, roles)
	tsr := auth.NewRepoTeamScopeResolver(teamsRepo, projectRepo)

	auditRepo := storage.NewAuditEvents(pool)
	km, err := keymgmt.NewLocalKMS(make([]byte, 32))
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	wrapSvc := services.NewWrapService(storage.NewSecretWraps(pool), auditRepo, km)
	wfRepo := storage.NewWorkflows(pool)
	policyEng := services.NewPolicyEngine(storage.NewPolicies(pool), wfRepo, auditRepo)
	reqSvc := services.NewRequestService(storage.NewAccessRequests(pool), storage.NewApprovals(pool),
		wrapSvc, wfRepo, policyEng, auditRepo, nil)
	crossTeamH := handlers.NewCrossTeam(reqSvc, resolver, tsr)

	app := fiber.New()
	app.Use(middleware.Auth(nil))
	app.Get("/api/v1/requests/inbox", crossTeamH.Inbox)
	app.Get("/api/v1/requests/inbox/count", crossTeamH.InboxCount)
	fx.app = app
	return fx
}

func inboxGet(t *testing.T, app *fiber.App, path string, userID uuid.UUID) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-User-Id", userID.String())
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestInboxListAndCount_ScopeConsistent(t *testing.T) {
	fx := bootstrapInboxScope(t)

	cases := []struct {
		name  string
		user  uuid.UUID
		query string
		want  int
	}{
		{"team-scoped: out-of-scope team_id → 403", fx.teamProvider, "?team_id=" + fx.otherTeam.String(), http.StatusForbidden},
		{"team-scoped: unknown team_id → 403", fx.teamProvider, "?team_id=" + uuid.NewString(), http.StatusForbidden},
		{"team-scoped: malformed team_id → 400", fx.teamProvider, "?team_id=not-a-uuid", http.StatusBadRequest},
		{"team-scoped: in-scope team_id → 200", fx.teamProvider, "?team_id=" + fx.teamB.String(), http.StatusOK},
		{"team-scoped: no filter → 200", fx.teamProvider, "", http.StatusOK},
		{"global: any team_id → 200", fx.globalProvider, "?team_id=" + fx.otherTeam.String(), http.StatusOK},
		{"global: no filter → 200", fx.globalProvider, "", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lst, lbody := inboxGet(t, fx.app, "/api/v1/requests/inbox"+tc.query, tc.user)
			cst, cbody := inboxGet(t, fx.app, "/api/v1/requests/inbox/count"+tc.query, tc.user)

			if lst != tc.want {
				t.Errorf("list status = %d want %d (body %s)", lst, tc.want, lbody)
			}
			if cst != tc.want {
				t.Errorf("count status = %d want %d (body %s)", cst, tc.want, cbody)
			}
			if lst != cst {
				t.Errorf("list/count status diverged: list=%d count=%d (the api#167 bug)", lst, cst)
			}

			switch tc.want {
			case http.StatusForbidden:
				// The count must refuse too — never leak a total for an
				// out-of-scope team.
				if !strings.Contains(cbody, "out_of_scope_team") {
					t.Errorf("count 403 body missing out_of_scope_team: %s", cbody)
				}
				if strings.Contains(cbody, `"total"`) {
					t.Errorf("count 403 leaked a total field (the api#167 bug): %s", cbody)
				}
			case http.StatusOK:
				// count.total must equal the number of rows the list returns.
				var cr struct {
					Total int `json:"total"`
				}
				if err := json.Unmarshal([]byte(cbody), &cr); err != nil {
					t.Fatalf("count body: %v (%s)", err, cbody)
				}
				var list []json.RawMessage
				if err := json.Unmarshal([]byte(lbody), &list); err != nil {
					t.Fatalf("list body: %v (%s)", err, lbody)
				}
				if cr.Total != len(list) {
					t.Errorf("count.total=%d but list returned %d rows; they must agree", cr.Total, len(list))
				}
			}
		})
	}
}
