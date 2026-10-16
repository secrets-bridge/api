package main

// Real-router regression tests for the 2026-10-16 audit items on the
// request approval paths:
//
//	API-N-01            cross-team POST /requests/:id/verify had no permission
//	                    check and let the body pick the vote lane
//	API-N-02 / API-S-01 POST /requests and /requests/read stored the body's
//	                    requester_id, so a requester could self-approve
//	API-N-03 / API-S-15 cross-team submit accepted a destination connection
//	                    that is not bound to the source project
//	API-S-07            cross-team fill wrapped keys outside destination_keys
//
// Every test drives the FULL app built by newApp: cookie session auth, the
// default-deny group, the per-route permission gates, the step-up MFA gate,
// the handlers, the services and Postgres. Users are real local_users rows
// with a real session whose MFA stamp is fresh, so the only thing deciding
// each outcome is the authorization logic under test.
//
// DB + Redis backed: SKIP without TEST_DATABASE_URL and TEST_REDIS_URL.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

type gateFixture struct {
	app      *fiber.App
	pool     *storage.Pool
	sessions *services.SessionService
	wraps    *services.WrapService
	bindings *storage.ProjectProviderConnections
}

type gateUser struct {
	id     uuid.UUID
	cookie string
}

type gateGrant struct {
	perms []auth.Permission
	scope map[string]string
}

func global(perms ...auth.Permission) gateGrant { return gateGrant{perms: perms} }

func onProject(pid uuid.UUID, perms ...auth.Permission) gateGrant {
	return gateGrant{perms: perms, scope: map[string]string{"project_id": pid.String()}}
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dsn, MaxConns: 8, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	rdb, err := runtime.Open(ctx, runtime.Config{URL: redisURL})
	if err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	km, err := keymgmt.NewLocalKMS(randomBytes(t, 32))
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	authSvc := services.NewAuthService(
		storage.NewLocalUsers(pool), storage.NewRoles(pool), storage.NewUserRoles(pool),
		storage.NewAuditEvents(pool), auth.NewSigner(randomBytes(t, 32)), time.Hour,
	)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := newApp(Config{Env: ModeDev, ProviderConnRejectSecretValues: true}, logger, pool, rdb, km, authSvc)

	auditRepo := storage.NewAuditEvents(pool)
	return &gateFixture{
		app:      app,
		pool:     pool,
		sessions: services.NewSessionService(storage.NewSessions(pool), auditRepo),
		wraps:    services.NewWrapService(storage.NewSecretWraps(pool), auditRepo, km),
		bindings: storage.NewProjectProviderConnections(pool),
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func uniq(prefix string) string { return prefix + "-" + uuid.NewString()[:8] }

// user creates a local user holding exactly the given grants, issues a
// cookie session for it and stamps a fresh MFA verification on that
// session (what a user who self-enrolled TOTP and passed step-up has).
func (fx *gateFixture) user(t *testing.T, name string, grants ...gateGrant) *gateUser {
	t.Helper()
	return fx.newUser(t, name, true, grants...)
}

// staleUser is like user but never passed step-up on this session.
func (fx *gateFixture) staleUser(t *testing.T, name string, grants ...gateGrant) *gateUser {
	t.Helper()
	return fx.newUser(t, name, false, grants...)
}

func (fx *gateFixture) newUser(t *testing.T, name string, freshMFA bool, grants ...gateGrant) *gateUser {
	t.Helper()
	ctx := t.Context()
	u := &storage.LocalUser{
		Email:        uniq(name) + "@example.com",
		PasswordHash: []byte("$2a$10$not-a-real-hash-for-tests-only-xxxxxxxxxxxxxxxxxxxxx"),
		DisplayName:  name,
	}
	if err := storage.NewLocalUsers(fx.pool).Create(ctx, u); err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	for _, g := range grants {
		perms, _ := json.Marshal(g.perms)
		scope, _ := json.Marshal(g.scope)
		if g.scope == nil {
			scope = []byte("{}")
		}
		roleID := uuid.New()
		if _, err := fx.pool.Exec(ctx,
			`INSERT INTO roles (id, name, permissions, is_system) VALUES ($1, $2, $3::jsonb, false)`,
			roleID, uniq(name+"-role"), string(perms)); err != nil {
			t.Fatalf("seed role for %s: %v", name, err)
		}
		if _, err := fx.pool.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id, scope) VALUES ($1, $2, $3::jsonb)`,
			u.ID.String(), roleID, string(scope)); err != nil {
			t.Fatalf("seed grant for %s: %v", name, err)
		}
	}
	issued, err := fx.sessions.Issue(ctx, u.ID, "127.0.0.1", "approval-gates-test")
	if err != nil {
		t.Fatalf("issue session for %s: %v", name, err)
	}
	if freshMFA {
		if err := fx.sessions.MarkMFA(ctx, issued.Session.ID, time.Now().UTC()); err != nil {
			t.Fatalf("stamp mfa for %s: %v", name, err)
		}
	}
	return &gateUser{id: u.ID, cookie: issued.CookieValue}
}

// do sends one JSON request as u through the real app. The response body
// is decoded into a generic map (or left nil when it is not an object).
func (fx *gateFixture) do(t *testing.T, method, path string, u *gateUser, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if u != nil {
		req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: u.cookie})
	}
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// gateScenario is a source project (Team A side) with one env, a
// destination provider connection bound to it, a target team / project /
// env (Team B side) and a second project owning a foreign connection.
type gateScenario struct {
	srcProject, srcEnv     uuid.UUID
	srcEnvName             string
	otherSrcEnvName        string
	otherProject           uuid.UUID
	targetTeam             uuid.UUID
	targetProject          uuid.UUID
	targetEnv              uuid.UUID
	destConn               uuid.UUID
	destBinding            uuid.UUID
	foreignConn            uuid.UUID
	destinationSecretRef   string
	destinationKeys        []string
	requiresSecurityReview bool
}

func (fx *gateFixture) scenario(t *testing.T, requiresSecurity bool) *gateScenario {
	t.Helper()
	ctx := t.Context()
	projects := storage.NewProjects(fx.pool)
	envs := storage.NewEnvironments(fx.pool)
	teams := storage.NewTeams(fx.pool)

	sc := &gateScenario{
		srcEnvName:             "uat",
		otherSrcEnvName:        "dev",
		destinationSecretRef:   "team-alpha/uat/db",
		destinationKeys:        []string{"DB_PASSWORD", "DB_USER"},
		requiresSecurityReview: requiresSecurity,
	}

	src := &storage.Project{Name: uniq("gate-src")}
	if err := projects.Create(ctx, src); err != nil {
		t.Fatalf("src project: %v", err)
	}
	sc.srcProject = src.ID
	srcEnv := &storage.Environment{ProjectID: src.ID, Name: sc.srcEnvName,
		Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd}
	if err := envs.Create(ctx, srcEnv); err != nil {
		t.Fatalf("src env: %v", err)
	}
	sc.srcEnv = srcEnv.ID
	devEnv := &storage.Environment{ProjectID: src.ID, Name: sc.otherSrcEnvName,
		Type: storage.EnvironmentTypeDev, Kind: storage.EnvironmentKindNonProd}
	if err := envs.Create(ctx, devEnv); err != nil {
		t.Fatalf("src dev env: %v", err)
	}

	other := &storage.Project{Name: uniq("gate-other")}
	if err := projects.Create(ctx, other); err != nil {
		t.Fatalf("other project: %v", err)
	}
	sc.otherProject = other.ID

	team := &storage.Team{Name: uniq("gate-team-b")}
	if err := teams.Create(ctx, team); err != nil {
		t.Fatalf("target team: %v", err)
	}
	sc.targetTeam = team.ID
	tp := &storage.Project{Name: uniq("gate-target"), TeamID: &team.ID}
	if err := projects.Create(ctx, tp); err != nil {
		t.Fatalf("target project: %v", err)
	}
	if err := projects.SetTeam(ctx, tp.ID, &team.ID); err != nil {
		t.Fatalf("set team: %v", err)
	}
	sc.targetProject = tp.ID
	te := &storage.Environment{ProjectID: tp.ID, Name: "uat",
		Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd}
	if err := envs.Create(ctx, te); err != nil {
		t.Fatalf("target env: %v", err)
	}
	sc.targetEnv = te.ID

	sc.destConn = fx.providerConnection(t, "gate-dest")
	b, err := fx.bindings.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: sc.srcProject, EnvironmentID: &sc.srcEnv, ProviderConnectionID: sc.destConn,
	})
	if err != nil {
		t.Fatalf("bind destination: %v", err)
	}
	sc.destBinding = b.ID
	sc.foreignConn = fx.providerConnection(t, "gate-foreign")
	if _, err := fx.bindings.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: sc.otherProject, ProviderConnectionID: sc.foreignConn,
	}); err != nil {
		t.Fatalf("bind foreign: %v", err)
	}

	// The scenario's own workflow, selected for the source project by a
	// high-priority rule so leftovers from other suites can't interfere.
	wf := &storage.WorkflowDefinition{
		Name: uniq("gate-wf"), MinApprovers: 1, AllowSelfApproval: false,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour,
		FillTTLSeconds: 3600, RequiresSecurityApproval: requiresSecurity, Enabled: true,
	}
	if err := storage.NewWorkflows(fx.pool).Create(ctx, wf); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if err := storage.NewPolicies(fx.pool).Create(ctx, &storage.PolicyRule{
		Name:             uniq("gate-rule"),
		Selector:         map[string]any{"project_id": sc.srcProject.String()},
		WorkflowID:       wf.ID,
		Priority:         9500,
		Enabled:          true,
		RevealTTLSeconds: 60,
	}); err != nil {
		t.Fatalf("policy rule: %v", err)
	}
	return sc
}

func (fx *gateFixture) providerConnection(t *testing.T, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := fx.pool.QueryRow(t.Context(), `
		INSERT INTO provider_connections (name, type, auth_method, scope, status)
		VALUES ($1, 'vault', 'token', '{}'::jsonb, 'active')
		RETURNING id`, uniq(name)).Scan(&id); err != nil {
		t.Fatalf("provider connection %s: %v", name, err)
	}
	return id
}

func (sc *gateScenario) submitBody() map[string]any {
	return map[string]any{
		"project_id":                         sc.srcProject.String(),
		"environment":                        sc.srcEnvName,
		"target_team_id":                     sc.targetTeam.String(),
		"target_project_id":                  sc.targetProject.String(),
		"target_environment_id":              sc.targetEnv.String(),
		"destination_provider_connection_id": sc.destConn.String(),
		"destination_secret_ref":             sc.destinationSecretRef,
		"destination_keys":                   sc.destinationKeys,
		"justification":                      "rotate the shared db creds for the cross-team handoff",
	}
}

func fillBody(kv map[string]string) map[string]any {
	enc := make(map[string]string, len(kv))
	for k, v := range kv {
		enc[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	return map[string]any{"key_values": enc}
}

func verifyBody(lane, decision string) map[string]any {
	return map[string]any{"voted_as": lane, "decision": decision}
}

// submitAndFill runs a legit requester + value provider through submit
// and fill, leaving the request in pending_verification.
func (fx *gateFixture) submitAndFill(t *testing.T, sc *gateScenario, requester, filler *gateUser) uuid.UUID {
	t.Helper()
	st, body := fx.do(t, http.MethodPost, "/api/v1/requests/cross-team", requester, sc.submitBody())
	if st != http.StatusCreated {
		t.Fatalf("cross-team submit = %d %v; want 201", st, body)
	}
	id := uuid.MustParse(body["id"].(string))
	st, body = fx.do(t, http.MethodPost, "/api/v1/requests/"+id.String()+"/fill", filler,
		fillBody(map[string]string{"DB_PASSWORD": "fake-pw-value", "DB_USER": "fake-user-value"}))
	if st != http.StatusOK || body["status"] != "pending_verification" {
		t.Fatalf("fill = %d %v; want 200 pending_verification", st, body)
	}
	return id
}

func (fx *gateFixture) requestRow(t *testing.T, id uuid.UUID) *storage.AccessRequest {
	t.Helper()
	r, err := storage.NewAccessRequests(fx.pool).Get(t.Context(), id)
	if err != nil {
		t.Fatalf("get request %s: %v", id, err)
	}
	return r
}

func (fx *gateFixture) approvalCount(t *testing.T, id uuid.UUID) int {
	t.Helper()
	var n int
	if err := fx.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM approvals WHERE request_id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count approvals: %v", err)
	}
	return n
}

func (fx *gateFixture) auditActions(t *testing.T, id uuid.UUID) []string {
	t.Helper()
	rows, err := fx.pool.Query(t.Context(),
		`SELECT action FROM audit_events WHERE correlation_id = $1`, id)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		out = append(out, a)
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func verifyPath(id uuid.UUID) string { return "/api/v1/requests/" + id.String() + "/verify" }

func errText(body map[string]any) string {
	s, _ := body["error"].(string)
	return s
}

// API-N-01: a user with zero grants (who self-enrolled TOTP, so the
// step-up gate is satisfied) must not be able to cast any vote. Before the
// fix the route was guarded by requireMFA only and the service never
// checked a permission: this exact call returned 200 approved + a job_id.
func TestVerify_ZeroGrantUserIsRefused(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, false)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))
	nobody := fx.user(t, "zero-grant")
	id := fx.submitAndFill(t, sc, requester, filler)

	for _, b := range []map[string]any{
		verifyBody("source", "approve"),
		verifyBody("security", "approve"),
		verifyBody("source", "reject"),
	} {
		if st, body := fx.do(t, http.MethodPost, verifyPath(id), nobody, b); st != http.StatusForbidden {
			t.Fatalf("zero-grant verify %v = %d %v; want 403", b, st, body)
		}
	}
	// No session at all is a 401 from the default-deny group.
	if st, body := fx.do(t, http.MethodPost, verifyPath(id), nil, verifyBody("source", "approve")); st != http.StatusUnauthorized {
		t.Fatalf("anonymous verify = %d %v; want 401", st, body)
	}
	// The permission gate runs before step-up: a zero-grant user is told
	// 403, not prompted for MFA they could then satisfy.
	stale := fx.staleUser(t, "zero-grant-stale")
	if st, body := fx.do(t, http.MethodPost, verifyPath(id), stale, verifyBody("source", "approve")); st != http.StatusForbidden {
		t.Fatalf("zero-grant verify without fresh MFA = %d %v; want 403", st, body)
	}
	got := fx.requestRow(t, id)
	if got.Status != storage.AccessRequestStatusPendingVerification || got.JobID != nil {
		t.Fatalf("request moved to %s (job %v) after refused votes; want pending_verification, no job", got.Status, got.JobID)
	}
	if n := fx.approvalCount(t, id); n != 0 {
		t.Fatalf("approvals recorded = %d; want 0", n)
	}
}

// API-N-01: the source lane needs secret.approve COVERING the source
// project. A project-scoped approver of a different project, and a
// security-only approver, are both refused; a project-scoped approver of
// the source project is accepted (scoped approvers keep working).
func TestVerify_SourceLaneNeedsApproveOnSourceProject(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, false)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))
	foreignApprover := fx.user(t, "foreign-approver", onProject(sc.otherProject, auth.PermSecretApprove))
	securityOnly := fx.user(t, "security-only", global(auth.PermSecretSecurityApprove))
	srcApprover := fx.user(t, "src-approver", onProject(sc.srcProject, auth.PermSecretApprove))
	id := fx.submitAndFill(t, sc, requester, filler)

	if st, body := fx.do(t, http.MethodPost, verifyPath(id), foreignApprover, verifyBody("source", "approve")); st != http.StatusForbidden {
		t.Fatalf("approver scoped to another project voting source = %d %v; want 403", st, body)
	}
	if st, body := fx.do(t, http.MethodPost, verifyPath(id), securityOnly, verifyBody("source", "approve")); st != http.StatusForbidden {
		t.Fatalf("security-only approver voting source = %d %v; want 403", st, body)
	}
	if n := fx.approvalCount(t, id); n != 0 {
		t.Fatalf("approvals recorded after refused votes = %d; want 0", n)
	}
	if !contains(fx.auditActions(t, id), "request.cross_team.verify.denied") {
		t.Fatal("refused lane vote left no request.cross_team.verify.denied audit event")
	}
	st, body := fx.do(t, http.MethodPost, verifyPath(id), srcApprover, verifyBody("source", "approve"))
	if st != http.StatusOK || body["status"] != "approved" {
		t.Fatalf("source-project approver voting source = %d %v; want 200 approved", st, body)
	}
}

// API-N-01: the security lane needs secret.security.approve. A plain
// approver can no longer claim the security lane in the body.
func TestVerify_SecurityLaneNeedsSecurityApprove(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, true)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))
	srcApprover := fx.user(t, "src-approver", onProject(sc.srcProject, auth.PermSecretApprove))
	approveOnly := fx.user(t, "approve-only", global(auth.PermSecretApprove))
	id := fx.submitAndFill(t, sc, requester, filler)

	st, body := fx.do(t, http.MethodPost, verifyPath(id), srcApprover, verifyBody("source", "approve"))
	if st != http.StatusOK || body["status"] != "pending_verification" {
		t.Fatalf("source vote = %d %v; want 200 pending_verification", st, body)
	}
	st, body = fx.do(t, http.MethodPost, verifyPath(id), approveOnly, verifyBody("security", "approve"))
	if st != http.StatusForbidden {
		t.Fatalf("secret.approve holder voting security = %d %v; want 403", st, body)
	}
	got := fx.requestRow(t, id)
	if got.Status != storage.AccessRequestStatusPendingVerification || got.JobID != nil {
		t.Fatalf("request = %s job=%v after refused security vote; want pending_verification, no job", got.Status, got.JobID)
	}
}

// API-N-01: one person cannot fill both lanes, even holding both
// permissions.
func TestVerify_SameUserCannotCastBothLanes(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, true)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))
	both := fx.user(t, "both-lanes", global(auth.PermSecretApprove, auth.PermSecretSecurityApprove))
	id := fx.submitAndFill(t, sc, requester, filler)

	if st, body := fx.do(t, http.MethodPost, verifyPath(id), both, verifyBody("source", "approve")); st != http.StatusOK {
		t.Fatalf("source vote = %d %v; want 200", st, body)
	}
	st, body := fx.do(t, http.MethodPost, verifyPath(id), both, verifyBody("security", "approve"))
	if st != http.StatusForbidden || errText(body) != "separation_of_duties_violated" {
		t.Fatalf("same user security vote = %d %v; want 403 separation_of_duties_violated", st, body)
	}
	if got := fx.requestRow(t, id); got.Status != storage.AccessRequestStatusPendingVerification {
		t.Fatalf("status = %s; want pending_verification", got.Status)
	}
}

// API-N-01: lanes are counted, not inferred from "some other approver".
// Two plain source approvers used to satisfy a security-required request
// (the second source vote was counted as the security vote), and a
// security vote cast first was later re-read as a source vote.
func TestVerify_LanesAreNotInterchangeable(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, true)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))
	srcApprover := fx.user(t, "src-approver", onProject(sc.srcProject, auth.PermSecretApprove))
	secondApprover := fx.user(t, "second-approver", global(auth.PermSecretApprove))
	security := fx.user(t, "security", global(auth.PermSecretSecurityApprove))

	id := fx.submitAndFill(t, sc, requester, filler)
	if st, body := fx.do(t, http.MethodPost, verifyPath(id), srcApprover, verifyBody("source", "approve")); st != http.StatusOK {
		t.Fatalf("first source vote = %d %v; want 200", st, body)
	}
	st, body := fx.do(t, http.MethodPost, verifyPath(id), secondApprover, verifyBody("source", "approve"))
	if st != http.StatusConflict {
		t.Fatalf("second source vote on a security-required request = %d %v; want 409", st, body)
	}
	if got := fx.requestRow(t, id); got.Status != storage.AccessRequestStatusPendingVerification || got.JobID != nil {
		t.Fatalf("two source votes moved the request to %s (job %v); security approval was bypassed", got.Status, got.JobID)
	}

	// The security vote now completes it.
	st, body = fx.do(t, http.MethodPost, verifyPath(id), security, verifyBody("security", "approve"))
	if st != http.StatusOK || body["status"] != "approved" {
		t.Fatalf("security vote = %d %v; want 200 approved", st, body)
	}

	// A security vote cast before any source vote is out of turn: without
	// a lane column it would later be indistinguishable from a source vote.
	id2 := fx.submitAndFill(t, sc, requester, filler)
	if st, body := fx.do(t, http.MethodPost, verifyPath(id2), security, verifyBody("security", "approve")); st != http.StatusConflict {
		t.Fatalf("security vote before source = %d %v; want 409", st, body)
	}
	if n := fx.approvalCount(t, id2); n != 0 {
		t.Fatalf("approvals after out-of-turn vote = %d; want 0", n)
	}
}

// API-N-01: a vote recorded before the fix by someone who does not hold
// the source-lane permission (e.g. the zero-grant exploit) must not count
// towards a later approval.
func TestVerify_LegacyVoteWithoutPermissionDoesNotCount(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, true)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))
	security := fx.user(t, "security", global(auth.PermSecretSecurityApprove))
	id := fx.submitAndFill(t, sc, requester, filler)

	// The pre-fix zero-grant vote, written straight to the approvals table.
	if err := storage.NewApprovals(fx.pool).Append(t.Context(), &storage.Approval{
		RequestID: id, ApproverID: uuid.NewString(), Decision: storage.ApprovalDecisionApprove,
	}); err != nil {
		t.Fatalf("seed legacy vote: %v", err)
	}
	st, body := fx.do(t, http.MethodPost, verifyPath(id), security, verifyBody("security", "approve"))
	if st != http.StatusConflict {
		t.Fatalf("security vote on top of an unauthorized legacy vote = %d %v; want 409", st, body)
	}
	if got := fx.requestRow(t, id); got.Status != storage.AccessRequestStatusPendingVerification || got.JobID != nil {
		t.Fatalf("request = %s job=%v; an unauthorized legacy vote counted as the source approval", got.Status, got.JobID)
	}
}

// The requester can never verify their own cross-team request, even
// holding secret.approve.
func TestVerify_RequesterCannotVerifyOwnRequest(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, false)
	requester := fx.user(t, "requester-approver", global(auth.PermSecretRequest, auth.PermSecretApprove))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))
	id := fx.submitAndFill(t, sc, requester, filler)

	st, body := fx.do(t, http.MethodPost, verifyPath(id), requester, verifyBody("source", "approve"))
	if st != http.StatusForbidden || errText(body) != "separation_of_duties_violated" {
		t.Fatalf("requester verifying own request = %d %v; want 403 separation_of_duties_violated", st, body)
	}
}

// API-N-02 / API-S-01: POST /requests and POST /requests/read take the
// requester from the session. A body requester_id is ignored, so a user
// holding secret.request + secret.approve can no longer file a request
// "as" someone else and then approve it.
func TestSubmit_RequesterComesFromSessionNotBody(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, false)
	ctx := t.Context()

	sec := &storage.Secret{ClusterName: uniq("gate-cluster"), ProviderType: "vault",
		SecretRef: "team-alpha/uat/app", Status: "present"}
	if err := storage.NewSecrets(fx.pool).Upsert(ctx, sec); err != nil {
		t.Fatalf("catalog secret: %v", err)
	}
	if err := storage.NewProjectSecrets(fx.pool).Bind(ctx, &storage.ProjectSecret{
		ProjectID: sc.srcProject, SecretID: sec.ID,
		AllowedOps: []string{storage.OpRead, storage.OpPatch}, CreatedBy: "approval-gates-test",
	}); err != nil {
		t.Fatalf("project secret binding: %v", err)
	}

	attacker := fx.user(t, "attacker", global(auth.PermSecretRequest, auth.PermSecretApprove))
	victim := fx.user(t, "victim", global(auth.PermSecretRequest))

	cases := []struct {
		path string
		body map[string]any
	}{
		{"/api/v1/requests", map[string]any{
			"requester_id":         victim.id.String(),
			"project_id":           sc.srcProject.String(),
			"environment":          sc.srcEnvName,
			"target_provider_type": "vault",
			"target_secret_ref":    sec.SecretRef,
			"key_values":           map[string]string{"API_TOKEN": "fake-token-value"},
			"justification":        "rotate the app token",
		}},
		{"/api/v1/requests/read", map[string]any{
			"requester_id":         victim.id.String(),
			"project_id":           sc.srcProject.String(),
			"environment":          sc.srcEnvName,
			"target_provider_type": "vault",
			"target_secret_ref":    sec.SecretRef,
			"target_keys":          []string{"API_TOKEN"},
			"justification":        "read the app token",
		}},
	}
	for _, tc := range cases {
		st, body := fx.do(t, http.MethodPost, tc.path, attacker, tc.body)
		if st != http.StatusCreated {
			t.Fatalf("POST %s = %d %v; want 201", tc.path, st, body)
		}
		if body["requester_id"] != attacker.id.String() {
			t.Fatalf("POST %s stored requester_id %v; want the session user %s (body value must be ignored)",
				tc.path, body["requester_id"], attacker.id)
		}
		id := uuid.MustParse(body["id"].(string))
		if got := fx.requestRow(t, id); got.RequesterID != attacker.id.String() {
			t.Fatalf("persisted requester_id = %s; want %s", got.RequesterID, attacker.id)
		}
		st, body = fx.do(t, http.MethodPost, "/api/v1/requests/"+id.String()+"/approve", attacker, map[string]any{})
		if st != http.StatusForbidden {
			t.Fatalf("self-approve after borrowed requester_id on %s = %d %v; want 403", tc.path, st, body)
		}
		if got := fx.requestRow(t, id); got.Status != storage.AccessRequestStatusPending {
			t.Fatalf("request status = %s after refused self-approval; want pending", got.Status)
		}
	}
}

// API-N-03 / API-S-15: the destination provider connection must be bound
// to the source project (and to the source environment when the binding
// is environment-specific).
func TestCrossTeamSubmit_DestinationMustBeBoundToSourceProject(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, false)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))

	countRequests := func() int {
		var n int
		if err := fx.pool.QueryRow(t.Context(),
			`SELECT count(*) FROM access_requests WHERE requester_id = $1`, requester.id.String()).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	foreign := sc.submitBody()
	foreign["destination_provider_connection_id"] = sc.foreignConn.String()
	if st, body := fx.do(t, http.MethodPost, "/api/v1/requests/cross-team", requester, foreign); st != http.StatusForbidden || errText(body) != "cross_team_destination_unbound" {
		t.Fatalf("connection bound to another project = %d %v; want 403 cross_team_destination_unbound", st, body)
	}

	// The binding is specific to the source "uat" env; another env of the
	// same project does not inherit it.
	otherEnv := sc.submitBody()
	otherEnv["environment"] = sc.otherSrcEnvName
	if st, body := fx.do(t, http.MethodPost, "/api/v1/requests/cross-team", requester, otherEnv); st != http.StatusForbidden {
		t.Fatalf("env-specific binding used from another env = %d %v; want 403", st, body)
	}

	// No environment named: an env-specific binding doesn't apply.
	noEnv := sc.submitBody()
	delete(noEnv, "environment")
	if st, body := fx.do(t, http.MethodPost, "/api/v1/requests/cross-team", requester, noEnv); st != http.StatusForbidden {
		t.Fatalf("env-specific binding with no environment named = %d %v; want 403", st, body)
	}

	// Without a source project there is nothing to check the binding
	// against (and nothing to scope the source approver to).
	noProject := sc.submitBody()
	delete(noProject, "project_id")
	if st, body := fx.do(t, http.MethodPost, "/api/v1/requests/cross-team", requester, noProject); st != http.StatusBadRequest {
		t.Fatalf("submit without project_id = %d %v; want 400", st, body)
	}
	if n := countRequests(); n != 0 {
		t.Fatalf("refused submits created %d requests; want 0", n)
	}

	if st, body := fx.do(t, http.MethodPost, "/api/v1/requests/cross-team", requester, sc.submitBody()); st != http.StatusCreated {
		t.Fatalf("bound destination = %d %v; want 201", st, body)
	}

	// A project-wide binding covers every env of the source project,
	// including a submit that names none.
	wide := fx.providerConnection(t, "gate-project-wide")
	if _, err := fx.bindings.Bind(t.Context(), storage.ProjectProviderConnectionBindingInput{
		ProjectID: sc.srcProject, ProviderConnectionID: wide,
	}); err != nil {
		t.Fatalf("bind project-wide: %v", err)
	}
	for _, env := range []string{sc.otherSrcEnvName, ""} {
		b := sc.submitBody()
		b["destination_provider_connection_id"] = wide.String()
		if env == "" {
			delete(b, "environment")
		} else {
			b["environment"] = env
		}
		if st, body := fx.do(t, http.MethodPost, "/api/v1/requests/cross-team", requester, b); st != http.StatusCreated {
			t.Fatalf("project-wide binding, environment %q = %d %v; want 201", env, st, body)
		}
	}
}

// API-S-07: fill only accepts the keys the request declared.
func TestCrossTeamFill_RejectsUndeclaredKey(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, false)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))

	st, body := fx.do(t, http.MethodPost, "/api/v1/requests/cross-team", requester, sc.submitBody())
	if st != http.StatusCreated {
		t.Fatalf("submit = %d %v", st, body)
	}
	id := uuid.MustParse(body["id"].(string))

	st, body = fx.do(t, http.MethodPost, "/api/v1/requests/"+id.String()+"/fill", filler,
		fillBody(map[string]string{"DB_PASSWORD": "fake-pw-value", "DB_ROOT": "fake-root-value"}))
	if st < 400 || st >= 500 {
		t.Fatalf("fill with an undeclared key = %d %v; want 4xx", st, body)
	}
	if strings.Contains(errText(body), "DB_ROOT") {
		t.Fatalf("error echoes the undeclared key name: %q", errText(body))
	}
	if got := fx.requestRow(t, id); got.Status != storage.AccessRequestStatusPendingValues {
		t.Fatalf("status = %s after refused fill; want pending_values", got.Status)
	}
	var wraps int
	if err := fx.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM secret_wraps WHERE request_id = $1`, id).Scan(&wraps); err != nil {
		t.Fatalf("count wraps: %v", err)
	}
	if wraps != 0 {
		t.Fatalf("refused fill left %d wraps; want 0", wraps)
	}
	if !contains(fx.auditActions(t, id), "request.cross_team.fill.rejected") {
		t.Fatal("refused fill left no request.cross_team.fill.rejected audit event")
	}

	st, body = fx.do(t, http.MethodPost, "/api/v1/requests/"+id.String()+"/fill", filler,
		fillBody(map[string]string{"DB_PASSWORD": "fake-pw-value", "DB_USER": "fake-user-value"}))
	if st != http.StatusOK {
		t.Fatalf("fill with declared keys = %d %v; want 200", st, body)
	}
}

// jobWrapKeys returns the sorted key names in the job payload's wraps.
func (fx *gateFixture) jobWrapKeys(t *testing.T, jobID uuid.UUID) (keys []string, job *storage.SyncJob) {
	t.Helper()
	job, err := storage.NewSyncJobs(fx.pool).Get(t.Context(), jobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	raw, _ := job.Payload["wraps"].([]any)
	for _, w := range raw {
		m, _ := w.(map[string]any)
		k, _ := m["key_name"].(string)
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, job
}

// The full legit chain still works: requester, value provider, a
// project-scoped source approver and a security approver take the request
// to approved, and the patch job carries exactly the declared keys.
func TestCrossTeam_HappyPathReachesApprovedWithDeclaredKeysOnly(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, true)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))
	srcApprover := fx.user(t, "src-approver", onProject(sc.srcProject, auth.PermSecretApprove))
	security := fx.user(t, "security", global(auth.PermSecretSecurityApprove))
	id := fx.submitAndFill(t, sc, requester, filler)

	st, body := fx.do(t, http.MethodPost, verifyPath(id), srcApprover, verifyBody("source", "approve"))
	if st != http.StatusOK || body["status"] != "pending_verification" {
		t.Fatalf("source vote = %d %v; want 200 pending_verification", st, body)
	}
	st, body = fx.do(t, http.MethodPost, verifyPath(id), security, verifyBody("security", "approve"))
	if st != http.StatusOK || body["status"] != "approved" {
		t.Fatalf("security vote = %d %v; want 200 approved", st, body)
	}
	got := fx.requestRow(t, id)
	if got.Status != storage.AccessRequestStatusApproved || got.JobID == nil {
		t.Fatalf("request = %s job=%v; want approved with a job", got.Status, got.JobID)
	}
	keys, job := fx.jobWrapKeys(t, *got.JobID)
	if job.JobType != storage.JobTypePatch {
		t.Fatalf("job type = %s; want patch", job.JobType)
	}
	if strings.Join(keys, ",") != "DB_PASSWORD,DB_USER" {
		t.Fatalf("patch job wraps = %v; want exactly the declared keys", keys)
	}

	// Values never leave the wrap layer.
	for _, q := range []string{
		`SELECT count(*) FROM audit_events WHERE correlation_id = $1 AND metadata::text LIKE '%fake-pw-value%'`,
		`SELECT count(*) FROM sync_jobs WHERE request_id = $1 AND payload::text LIKE '%fake-pw-value%'`,
	} {
		var n int
		if err := fx.pool.QueryRow(t.Context(), q, id).Scan(&n); err != nil {
			t.Fatalf("leak scan: %v", err)
		}
		if n != 0 {
			t.Fatalf("fill value leaked: %s", q)
		}
	}
}

// API-S-07 defense in depth: a wrap for a key the request never declared
// (a fill accepted before the fix) is not handed to the agent.
func TestCrossTeam_PatchJobDropsUndeclaredLegacyWrap(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, false)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))
	srcApprover := fx.user(t, "src-approver", onProject(sc.srcProject, auth.PermSecretApprove))
	id := fx.submitAndFill(t, sc, requester, filler)

	if _, err := fx.wraps.Wrap(t.Context(), services.WrapRequest{
		Plaintext: []byte("fake-root-value"), RequestID: &id, KeyName: "DB_ROOT",
		TTL: time.Hour, Actor: "user:legacy-filler",
	}); err != nil {
		t.Fatalf("seed legacy undeclared wrap: %v", err)
	}

	st, body := fx.do(t, http.MethodPost, verifyPath(id), srcApprover, verifyBody("source", "approve"))
	if st != http.StatusOK || body["status"] != "approved" {
		t.Fatalf("source vote = %d %v; want 200 approved", st, body)
	}
	got := fx.requestRow(t, id)
	if got.JobID == nil {
		t.Fatal("approved request has no job")
	}
	keys, _ := fx.jobWrapKeys(t, *got.JobID)
	if strings.Join(keys, ",") != "DB_PASSWORD,DB_USER" {
		t.Fatalf("patch job wraps = %v; an undeclared key reached the agent", keys)
	}
}

// API-N-03 defense in depth: a destination unbound from the source
// project after submit is not written at execute time.
func TestCrossTeam_UnboundAfterSubmitIsNotExecuted(t *testing.T) {
	fx := newGateFixture(t)
	sc := fx.scenario(t, false)
	requester := fx.user(t, "requester", global(auth.PermSecretRequest))
	filler := fx.user(t, "filler", global(auth.PermSecretValueProvide))
	srcApprover := fx.user(t, "src-approver", onProject(sc.srcProject, auth.PermSecretApprove))
	id := fx.submitAndFill(t, sc, requester, filler)

	if err := fx.bindings.Unbind(t.Context(), sc.destBinding); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	st, body := fx.do(t, http.MethodPost, verifyPath(id), srcApprover, verifyBody("source", "approve"))
	if st != http.StatusOK {
		t.Fatalf("source vote = %d %v; want 200", st, body)
	}
	got := fx.requestRow(t, id)
	if got.JobID != nil || got.Status != storage.AccessRequestStatusFailed {
		t.Fatalf("request = %s job=%v; want failed with no job (destination no longer bound)", got.Status, got.JobID)
	}
}
