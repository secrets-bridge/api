package handlers_test

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

// API-S-09 / API-S-18 regression suite. Every access_request status
// change has to be a conditional write: two callers racing on the same
// request must leave exactly one outcome, and the side effects (job
// enqueue, wrap TTL changes, audit) must only happen for the caller
// whose write won. The tests drive the real request + cross-team
// handlers over a real Postgres and fire the competing calls from
// goroutines released by one barrier, many times over, so an
// interleaving that lets both callers through shows up.
//
// The approve / reject / verify routes are wired WITHOUT the
// auth.Require + step-up gates on purpose: those gates are proven in
// cmd/api; this suite is about what happens once two allowed callers
// race.

const raceIterations = 30

type lifecycleFixture struct {
	app      *fiber.App
	pool     *storage.Pool
	reqSvc   *services.RequestService
	reqRepo  *storage.AccessRequests
	wfRepo   *storage.Workflows
	projRepo *storage.Projects
	envRepo  *storage.Environments
	teamRepo *storage.Teams
}

func bootstrapLifecycle(t *testing.T) *lifecycleFixture {
	t.Helper()
	enableHeaderIdentityForTest(t)
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 12, ConnLifetime: 5 * time.Minute}
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
		DELETE FROM project_provider_connections;
		DELETE FROM provider_connections;
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;
		DELETE FROM environments;
		DELETE FROM projects;
		DELETE FROM team_members;
		DELETE FROM teams;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}

	km, err := keymgmt.NewLocalKMS(make([]byte, 32))
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	auditRepo := storage.NewAuditEvents(pool)
	reqRepo := storage.NewAccessRequests(pool)
	wfRepo := storage.NewWorkflows(pool)
	projRepo := storage.NewProjects(pool)
	envRepo := storage.NewEnvironments(pool)
	teamRepo := storage.NewTeams(pool)
	wrapSvc := services.NewWrapService(storage.NewSecretWraps(pool), auditRepo, km)
	policyEng := services.NewPolicyEngine(storage.NewPolicies(pool), wfRepo, auditRepo)
	jobSvc := services.NewJobService(storage.NewSyncJobs(pool), auditRepo)
	reqSvc := services.NewRequestService(reqRepo, storage.NewApprovals(pool), wrapSvc, wfRepo, policyEng, auditRepo, jobSvc).
		WithEnvironments(envRepo).
		WithCrossTeamRepos(teamRepo, projRepo, envRepo, storage.NewProviderConnections(pool))
	jobSvc.OnCompleted(reqSvc.OnJobCompleted)

	requestsH := handlers.NewRequests(reqSvc)
	crossTeamH := handlers.NewCrossTeam(reqSvc, nil, nil)

	app := fiber.New()
	app.Use(middleware.Auth(nil))
	app.Post("/api/v1/requests/:id/approve", requestsH.Approve)
	app.Post("/api/v1/requests/:id/reject", requestsH.Reject)
	app.Post("/api/v1/requests/:id/cancel", requestsH.Cancel)
	app.Post("/api/v1/requests/:id/fill", crossTeamH.Fill)
	app.Post("/api/v1/requests/:id/refuse", crossTeamH.Refuse)
	app.Post("/api/v1/requests/:id/verify", crossTeamH.Verify)

	return &lifecycleFixture{
		app: app, pool: pool, reqSvc: reqSvc, reqRepo: reqRepo, wfRepo: wfRepo,
		projRepo: projRepo, envRepo: envRepo, teamRepo: teamRepo,
	}
}

func (fx *lifecycleFixture) post(t *testing.T, path, userID, jsonBody string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Id", userID)
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 20 * time.Second})
	if err != nil {
		t.Errorf("POST %s: %v", path, err)
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

type raceCall struct {
	path, user, body string
}

type raceResult struct {
	code int
	body string
}

// race fires every call at once (one barrier) and returns the results in
// call order.
func (fx *lifecycleFixture) race(t *testing.T, calls ...raceCall) []raceResult {
	t.Helper()
	out := make([]raceResult, len(calls))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, c := range calls {
		wg.Add(1)
		go func(i int, c raceCall) {
			defer wg.Done()
			<-start
			code, body := fx.post(t, c.path, c.user, c.body)
			out[i] = raceResult{code: code, body: body}
		}(i, c)
	}
	close(start)
	wg.Wait()
	return out
}

func (fx *lifecycleFixture) workflow(t *testing.T, name string, minApprovers int, requestTTL time.Duration) uuid.UUID {
	t.Helper()
	wf := &storage.WorkflowDefinition{
		Name: name, MinApprovers: minApprovers,
		WrapTTLCreated: 7 * 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: requestTTL, Enabled: true,
	}
	if err := fx.wfRepo.Create(t.Context(), wf); err != nil {
		t.Fatalf("seed workflow %s: %v", name, err)
	}
	return wf.ID
}

// readRequest seeds a pending read request — the minimal row the
// approve / reject / cancel handlers act on.
func (fx *lifecycleFixture) readRequest(t *testing.T, requester string, wfID uuid.UUID) uuid.UUID {
	t.Helper()
	req := &storage.AccessRequest{
		RequesterID:        requester,
		Type:               storage.AccessRequestTypeRead,
		Justification:      "lifecycle race seed",
		Status:             storage.AccessRequestStatusPending,
		WorkflowID:         &wfID,
		TargetProviderType: "vault",
		TargetSecretRef:    "team-alpha/uat/db",
		TargetKeys:         []string{"DB_PASSWORD"},
	}
	if err := fx.reqRepo.Create(t.Context(), req); err != nil {
		t.Fatalf("seed read request: %v", err)
	}
	return req.ID
}

type requestState struct {
	status       string
	rejectReason string
	jobs         int
	votes        int
	wraps        int
}

func (fx *lifecycleFixture) state(t *testing.T, id uuid.UUID) requestState {
	t.Helper()
	var s requestState
	if err := fx.pool.QueryRow(t.Context(), `
		SELECT r.status, COALESCE(r.reject_reason, ''),
		       (SELECT count(*) FROM sync_jobs j WHERE j.request_id = r.id),
		       (SELECT count(*) FROM approvals a WHERE a.request_id = r.id),
		       (SELECT count(*) FROM secret_wraps w WHERE w.request_id = r.id)
		FROM access_requests r WHERE r.id = $1`, id,
	).Scan(&s.status, &s.rejectReason, &s.jobs, &s.votes, &s.wraps); err != nil {
		t.Fatalf("load state for %s: %v", id, err)
	}
	return s
}

// oneWinner reports whether exactly one of two racing calls got 200 and
// the other 409.
func oneWinner(codes []int) bool {
	return len(codes) == 2 &&
		((codes[0] == http.StatusOK && codes[1] == http.StatusConflict) ||
			(codes[0] == http.StatusConflict && codes[1] == http.StatusOK))
}

func reqPath(id uuid.UUID, action string) string {
	return "/api/v1/requests/" + id.String() + "/" + action
}

// A concurrent approve and reject on a single-approver request must end
// in exactly one decision. Before the fix both callers passed the
// "status == pending" read, both unconditional UPDATEs ran, and the
// request could end `rejected` with an approve job already enqueued (or
// `approved` with a reject reason stamped on it).
func TestRequestLifecycle_ConcurrentApproveReject_SingleOutcome(t *testing.T) {
	fx := bootstrapLifecycle(t)
	wf := fx.workflow(t, "race-approve-reject", 1, 14*24*time.Hour)

	outcomes := map[string]int{}
	for i := 0; i < raceIterations; i++ {
		id := fx.readRequest(t, uuid.NewString(), wf)
		res := fx.race(t,
			raceCall{reqPath(id, "approve"), uuid.NewString(), `{"comment":"ok"}`},
			raceCall{reqPath(id, "reject"), uuid.NewString(), `{"reason":"not needed"}`},
		)
		approve, reject := res[0], res[1]
		st := fx.state(t, id)
		outcomes[st.status]++
		switch st.status {
		case "approved":
			if approve.code != http.StatusOK || reject.code != http.StatusConflict {
				t.Fatalf("iter %d: approved but approve=%d reject=%d (%s); want 200/409", i, approve.code, reject.code, reject.body)
			}
			if st.jobs != 1 || st.rejectReason != "" {
				t.Fatalf("iter %d: approved with jobs=%d reject_reason=%q; want 1 job and no reject reason", i, st.jobs, st.rejectReason)
			}
		case "rejected":
			if reject.code != http.StatusOK || approve.code != http.StatusConflict {
				t.Fatalf("iter %d: rejected but approve=%d (%s) reject=%d; want 409/200", i, approve.code, approve.body, reject.code)
			}
			if st.jobs != 0 {
				t.Fatalf("iter %d: rejected request has %d enqueued job(s); want 0", i, st.jobs)
			}
		default:
			t.Fatalf("iter %d: unexpected status %q (approve=%d reject=%d)", i, st.status, approve.code, reject.code)
		}
		if st.votes != 1 {
			t.Fatalf("iter %d: %d vote rows; the losing caller's vote must not persist", i, st.votes)
		}
	}
	t.Logf("outcomes over %d races: %v", raceIterations, outcomes)
}

// N-approver flow: with min_approvers=2 and three approvers voting at
// once, the threshold must be crossed exactly once. Before the fix every
// caller counted the votes after its own insert, more than one saw
// count >= 2 and each enqueued a job.
func TestRequestLifecycle_ConcurrentApprovals_NoOverCount(t *testing.T) {
	fx := bootstrapLifecycle(t)
	wf := fx.workflow(t, "race-two-approvers", 2, 14*24*time.Hour)

	for i := 0; i < raceIterations; i++ {
		id := fx.readRequest(t, uuid.NewString(), wf)
		res := fx.race(t,
			raceCall{reqPath(id, "approve"), uuid.NewString(), `{}`},
			raceCall{reqPath(id, "approve"), uuid.NewString(), `{}`},
			raceCall{reqPath(id, "approve"), uuid.NewString(), `{}`},
		)
		ok, conflict := 0, 0
		for _, r := range res {
			switch r.code {
			case http.StatusOK:
				ok++
			case http.StatusConflict:
				conflict++
			default:
				t.Fatalf("iter %d: unexpected approve response %d %s", i, r.code, r.body)
			}
		}
		st := fx.state(t, id)
		if st.status != "approved" || st.jobs != 1 || st.votes != 2 || ok != 2 || conflict != 1 {
			t.Fatalf("iter %d: status=%s jobs=%d votes=%d ok=%d conflict=%d; want approved, 1 job, 2 votes, 2x200, 1x409",
				i, st.status, st.jobs, st.votes, ok, conflict)
		}
	}
}

// The same approver double-submitting on an N-approver request counts
// once: one vote row, still pending, no job.
func TestRequestLifecycle_SameApproverDoubleVote_CountsOnce(t *testing.T) {
	fx := bootstrapLifecycle(t)
	wf := fx.workflow(t, "race-double-vote", 2, 14*24*time.Hour)

	for i := 0; i < raceIterations; i++ {
		id := fx.readRequest(t, uuid.NewString(), wf)
		approver := uuid.NewString()
		res := fx.race(t,
			raceCall{reqPath(id, "approve"), approver, `{}`},
			raceCall{reqPath(id, "approve"), approver, `{}`},
		)
		codes := []int{res[0].code, res[1].code}
		if !oneWinner(codes) {
			t.Fatalf("iter %d: double vote codes %v; want one 200 and one 409", i, codes)
		}
		st := fx.state(t, id)
		if st.status != "pending" || st.votes != 1 || st.jobs != 0 {
			t.Fatalf("iter %d: status=%s votes=%d jobs=%d; want pending, 1 vote, 0 jobs", i, st.status, st.votes, st.jobs)
		}
	}
}

// Cancel racing approve: the requester withdrawing and an approver
// approving at the same moment. Before the fix the request could end
// `cancelled` while the approve call had already enqueued a job.
func TestRequestLifecycle_CancelRacesApprove_SingleOutcome(t *testing.T) {
	fx := bootstrapLifecycle(t)
	wf := fx.workflow(t, "race-cancel-approve", 1, 14*24*time.Hour)

	outcomes := map[string]int{}
	for i := 0; i < raceIterations; i++ {
		requester := uuid.NewString()
		id := fx.readRequest(t, requester, wf)
		res := fx.race(t,
			raceCall{reqPath(id, "approve"), uuid.NewString(), `{}`},
			raceCall{reqPath(id, "cancel"), requester, ``},
		)
		approve, cancel := res[0], res[1]
		st := fx.state(t, id)
		outcomes[st.status]++
		switch st.status {
		case "approved":
			if approve.code != http.StatusOK || cancel.code != http.StatusConflict || st.jobs != 1 {
				t.Fatalf("iter %d: approved but approve=%d cancel=%d jobs=%d; want 200/409/1", i, approve.code, cancel.code, st.jobs)
			}
		case "cancelled":
			if cancel.code != http.StatusOK || approve.code != http.StatusConflict || st.jobs != 0 {
				t.Fatalf("iter %d: cancelled but approve=%d (%s) cancel=%d jobs=%d; want 409/200/0", i, approve.code, approve.body, cancel.code, st.jobs)
			}
		default:
			t.Fatalf("iter %d: unexpected status %q", i, st.status)
		}
	}
	t.Logf("outcomes over %d races: %v", raceIterations, outcomes)
}

// SetExpiry may only shorten. Approving a patch request whose wraps
// already aged out must not bring them back: before the fix the
// approve-time refresh overwrote expires_at with now+wrap_ttl_approved
// and the expired value became retrievable again.
func TestRequestLifecycle_ApproveCannotReviveExpiredWrap(t *testing.T) {
	fx := bootstrapLifecycle(t)
	ctx := t.Context()

	// Submit resolves the seed "standard" workflow (one approver).
	req, err := fx.reqSvc.Submit(ctx, services.PatchInput{
		RequesterID:        uuid.NewString(),
		TargetProviderType: "vault",
		TargetSecretRef:    "team-alpha/uat/db",
		KeyValues:          map[string][]byte{"DB_PASSWORD": []byte("fake-value-1")},
		Justification:      "revive check",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := fx.pool.Exec(ctx,
		`UPDATE secret_wraps SET expires_at = now() - interval '1 minute' WHERE request_id = $1`, req.ID); err != nil {
		t.Fatalf("age wraps: %v", err)
	}

	if code, body := fx.post(t, reqPath(req.ID, "approve"), uuid.NewString(), `{}`); code != http.StatusOK {
		t.Fatalf("approve = %d %s; want 200", code, body)
	}
	var live int
	if err := fx.pool.QueryRow(ctx,
		`SELECT count(*) FROM secret_wraps WHERE request_id = $1 AND expires_at > now()`, req.ID).Scan(&live); err != nil {
		t.Fatalf("count live wraps: %v", err)
	}
	if live != 0 {
		t.Fatalf("%d expired wrap(s) revived by the approve-time TTL refresh; want 0", live)
	}
}

// --- request_ttl (API-S-18) ---------------------------------------------

// A pending request older than its workflow's request_ttl can no longer
// be approved. The approve call is refused with 410 request_expired, the
// request is marked expired through the same conditional write, no vote
// or job is recorded, the patch wraps are shrunk and an audit event is
// written. A second approve sees a closed request (409).
func TestRequestLifecycle_RequestTTL_ApproveRefusedAndExpired(t *testing.T) {
	fx := bootstrapLifecycle(t)
	ctx := t.Context()

	// Submit resolves the seed "standard" workflow: request_ttl = 14 days.
	req, err := fx.reqSvc.Submit(ctx, services.PatchInput{
		RequesterID:        uuid.NewString(),
		TargetProviderType: "vault",
		TargetSecretRef:    "team-alpha/uat/db",
		KeyValues:          map[string][]byte{"DB_PASSWORD": []byte("fake-value-1")},
		Justification:      "ttl check",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := fx.pool.Exec(ctx,
		`UPDATE access_requests SET created_at = now() - interval '15 days' WHERE id = $1`, req.ID); err != nil {
		t.Fatalf("backdate request: %v", err)
	}

	code, body := fx.post(t, reqPath(req.ID, "approve"), uuid.NewString(), `{}`)
	if code != http.StatusGone || !strings.Contains(body, "request_expired") {
		t.Fatalf("approve past request_ttl = %d %s; want 410 request_expired", code, body)
	}
	st := fx.state(t, req.ID)
	if st.status != "expired" || st.votes != 0 || st.jobs != 0 {
		t.Fatalf("after refused approve: status=%s votes=%d jobs=%d; want expired, 0, 0", st.status, st.votes, st.jobs)
	}
	var longLived int
	if err := fx.pool.QueryRow(ctx,
		`SELECT count(*) FROM secret_wraps WHERE request_id = $1 AND expires_at > now() + interval '6 minutes'`, req.ID).Scan(&longLived); err != nil {
		t.Fatalf("count wraps: %v", err)
	}
	if longLived != 0 {
		t.Fatalf("%d wrap(s) still on the 7d created TTL after expiry; want them shrunk", longLived)
	}
	var audits int
	if err := fx.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'request.expire' AND correlation_id = $1`, req.ID).Scan(&audits); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if audits != 1 {
		t.Fatalf("request.expire audit events = %d; want 1", audits)
	}

	if code, body := fx.post(t, reqPath(req.ID, "approve"), uuid.NewString(), `{}`); code != http.StatusConflict {
		t.Fatalf("second approve on expired request = %d %s; want 409", code, body)
	}
}

// Control: inside the TTL window the same flow approves normally, and a
// reject (a closing action) is not blocked by request_ttl.
func TestRequestLifecycle_RequestTTL_WithinWindowUnaffected(t *testing.T) {
	fx := bootstrapLifecycle(t)
	wf := fx.workflow(t, "ttl-window-wf", 1, time.Hour)

	fresh := fx.readRequest(t, uuid.NewString(), wf)
	if code, body := fx.post(t, reqPath(fresh, "approve"), uuid.NewString(), `{}`); code != http.StatusOK {
		t.Fatalf("approve within request_ttl = %d %s; want 200", code, body)
	}
	if st := fx.state(t, fresh); st.status != "approved" || st.jobs != 1 {
		t.Fatalf("within window: status=%s jobs=%d; want approved, 1 job", st.status, st.jobs)
	}

	old := fx.readRequest(t, uuid.NewString(), wf)
	if _, err := fx.pool.Exec(t.Context(),
		`UPDATE access_requests SET created_at = now() - interval '2 hours' WHERE id = $1`, old); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if code, body := fx.post(t, reqPath(old, "reject"), uuid.NewString(), `{"reason":"too old"}`); code != http.StatusOK {
		t.Fatalf("reject past request_ttl = %d %s; want 200 (closing actions stay allowed)", code, body)
	}
}

// --- cross-team ------------------------------------------------------------

// crossTeamRequest submits a cross-team request through the service
// (default "standard" workflow: one source approver, no security vote).
// When fill is true it is also filled, leaving it in
// pending_verification.
func (fx *lifecycleFixture) crossTeamRequest(t *testing.T, slug string, fill bool) (id uuid.UUID, requester string) {
	t.Helper()
	ctx := t.Context()
	src := &storage.Project{Name: slug + "-src"}
	if err := fx.projRepo.Create(ctx, src); err != nil {
		t.Fatalf("src project: %v", err)
	}
	if err := fx.envRepo.Create(ctx, &storage.Environment{
		ProjectID: src.ID, Name: "uat", Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd,
	}); err != nil {
		t.Fatalf("src env: %v", err)
	}
	team := &storage.Team{Name: slug + "-team"}
	if err := fx.teamRepo.Create(ctx, team); err != nil {
		t.Fatalf("team: %v", err)
	}
	target := &storage.Project{Name: slug + "-target"}
	if err := fx.projRepo.Create(ctx, target); err != nil {
		t.Fatalf("target project: %v", err)
	}
	if err := fx.projRepo.SetTeam(ctx, target.ID, &team.ID); err != nil {
		t.Fatalf("set team: %v", err)
	}
	targetEnv := &storage.Environment{
		ProjectID: target.ID, Name: "uat", Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd,
	}
	if err := fx.envRepo.Create(ctx, targetEnv); err != nil {
		t.Fatalf("target env: %v", err)
	}
	var connID uuid.UUID
	if err := fx.pool.QueryRow(ctx, `
		INSERT INTO provider_connections (name, type, auth_method, scope, status)
		VALUES ($1, 'vault', 'token', '{"address":"https://vault.example.com"}'::jsonb, 'active')
		RETURNING id`, slug+"-dest").Scan(&connID); err != nil {
		t.Fatalf("provider connection: %v", err)
	}

	requester = uuid.NewString()
	req, err := fx.reqSvc.SubmitCrossTeam(ctx, services.CrossTeamSubmitInput{
		RequesterID:                     requester,
		ProjectID:                       src.ID.String(),
		Environment:                     "uat",
		TargetTeamID:                    team.ID,
		TargetProjectID:                 target.ID,
		TargetEnvironmentID:             targetEnv.ID,
		DestinationProviderConnectionID: connID,
		DestinationSecretRef:            "team-alpha/uat/db",
		DestinationKeys:                 []string{"DB_PASSWORD", "DB_USER"},
		Justification:                   "cross-team lifecycle race seed",
	})
	if err != nil {
		t.Fatalf("SubmitCrossTeam: %v", err)
	}
	if fill {
		if _, err := fx.reqSvc.Fill(ctx, services.FillCrossTeamInput{
			RequestID: req.ID,
			FillerID:  uuid.NewString(),
			KeyValues: map[string][]byte{"DB_PASSWORD": []byte("fake-value-1"), "DB_USER": []byte("fake-user-1")},
		}); err != nil {
			t.Fatalf("Fill: %v", err)
		}
	}
	return req.ID, requester
}

func fillBody(pw string) string {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	return `{"key_values":{"DB_PASSWORD":"` + b64(pw) + `","DB_USER":"` + b64("fake-user") + `"}}`
}

// Two value providers filling the same request at once: only one fill
// may land. Before the fix both callers wrapped their values first and
// only then ran the conditional status update, so the loser got a 409
// but its wraps stayed attached to the request and rode along in the
// patch job payload next to the winner's.
func TestRequestLifecycle_CrossTeamConcurrentFill_OnlyWinnerWraps(t *testing.T) {
	fx := bootstrapLifecycle(t)
	for i := 0; i < raceIterations; i++ {
		id, _ := fx.crossTeamRequest(t, "fill-race-"+uuid.NewString()[:8], false)
		res := fx.race(t,
			raceCall{reqPath(id, "fill"), uuid.NewString(), fillBody("fake-value-a")},
			raceCall{reqPath(id, "fill"), uuid.NewString(), fillBody("fake-value-b")},
		)
		codes := []int{res[0].code, res[1].code}
		if !oneWinner(codes) {
			t.Fatalf("iter %d: fill codes %v (%s | %s); want one 200 and one 409", i, codes, res[0].body, res[1].body)
		}
		st := fx.state(t, id)
		if st.status != "pending_verification" || st.wraps != 2 {
			t.Fatalf("iter %d: status=%s wraps=%d; want pending_verification with only the winner's 2 wraps", i, st.status, st.wraps)
		}
	}
}

// Fill racing the requester's cancel. Cancel is allowed both before and
// after a fill, so the request always ends cancelled; the fill either
// landed first (its wraps are then shrunk by the cancel) or lost (and
// must have stored nothing). Before the fix a losing fill still left
// its wraps on the request with the 7d created TTL.
func TestRequestLifecycle_CrossTeamFillRacesCancel_NoLingeringWraps(t *testing.T) {
	fx := bootstrapLifecycle(t)
	outcomes := map[string]int{}
	for i := 0; i < raceIterations; i++ {
		id, requester := fx.crossTeamRequest(t, "fill-cancel-"+uuid.NewString()[:8], false)
		res := fx.race(t,
			raceCall{reqPath(id, "fill"), uuid.NewString(), fillBody("fake-value-a")},
			raceCall{reqPath(id, "cancel"), requester, ``},
		)
		st := fx.state(t, id)
		outcomes[fmt.Sprintf("fill=%d cancel=%d", res[0].code, res[1].code)]++
		if st.status != "cancelled" || res[1].code != http.StatusOK {
			t.Fatalf("iter %d: status=%s cancel=%d; want cancelled/200", i, st.status, res[1].code)
		}
		if res[0].code == http.StatusConflict && st.wraps != 0 {
			t.Fatalf("iter %d: the losing fill left %d wrap(s) on the request", i, st.wraps)
		}
		var longLived int
		if err := fx.pool.QueryRow(t.Context(),
			`SELECT count(*) FROM secret_wraps WHERE request_id = $1 AND expires_at > now() + interval '6 minutes'`, id).Scan(&longLived); err != nil {
			t.Fatalf("count wraps: %v", err)
		}
		if longLived != 0 {
			t.Fatalf("iter %d: cancelled request still holds %d fill wrap(s) on the created TTL (fill=%d cancel=%d)",
				i, longLived, res[0].code, res[1].code)
		}
	}
	t.Logf("outcomes over %d races: %v", raceIterations, outcomes)
}

// Source approve and source reject on a filled request at once: one
// decision, and a job only when it ended approved.
func TestRequestLifecycle_CrossTeamConcurrentVerify_SingleOutcome(t *testing.T) {
	fx := bootstrapLifecycle(t)
	outcomes := map[string]int{}
	for i := 0; i < raceIterations; i++ {
		id, _ := fx.crossTeamRequest(t, "verify-race-"+uuid.NewString()[:8], true)
		res := fx.race(t,
			raceCall{reqPath(id, "verify"), uuid.NewString(), `{"voted_as":"source","decision":"approve"}`},
			raceCall{reqPath(id, "verify"), uuid.NewString(), `{"voted_as":"source","decision":"reject"}`},
		)
		approve, reject := res[0], res[1]
		st := fx.state(t, id)
		outcomes[st.status]++
		switch st.status {
		case "approved":
			if approve.code != http.StatusOK || reject.code != http.StatusConflict || st.jobs != 1 {
				t.Fatalf("iter %d: approved but approve=%d reject=%d (%s) jobs=%d; want 200/409/1", i, approve.code, reject.code, reject.body, st.jobs)
			}
		case "rejected":
			if reject.code != http.StatusOK || approve.code != http.StatusConflict || st.jobs != 0 {
				t.Fatalf("iter %d: rejected but approve=%d (%s) reject=%d jobs=%d; want 409/200/0", i, approve.code, approve.body, reject.code, st.jobs)
			}
		default:
			t.Fatalf("iter %d: unexpected status %q", i, st.status)
		}
		if st.votes != 1 {
			t.Fatalf("iter %d: %d vote rows; want 1", i, st.votes)
		}
	}
	t.Logf("outcomes over %d races: %v", raceIterations, outcomes)
}

// Verify approve racing the requester's cancel on a filled request.
func TestRequestLifecycle_CrossTeamVerifyRacesCancel_SingleOutcome(t *testing.T) {
	fx := bootstrapLifecycle(t)
	outcomes := map[string]int{}
	for i := 0; i < raceIterations; i++ {
		id, requester := fx.crossTeamRequest(t, "verify-cancel-"+uuid.NewString()[:8], true)
		res := fx.race(t,
			raceCall{reqPath(id, "verify"), uuid.NewString(), `{"voted_as":"source","decision":"approve"}`},
			raceCall{reqPath(id, "cancel"), requester, ``},
		)
		verify, cancel := res[0], res[1]
		st := fx.state(t, id)
		outcomes[st.status]++
		switch st.status {
		case "approved":
			if verify.code != http.StatusOK || cancel.code != http.StatusConflict || st.jobs != 1 {
				t.Fatalf("iter %d: approved but verify=%d cancel=%d jobs=%d", i, verify.code, cancel.code, st.jobs)
			}
		case "cancelled":
			if cancel.code != http.StatusOK || verify.code != http.StatusConflict || st.jobs != 0 {
				t.Fatalf("iter %d: cancelled but verify=%d (%s) cancel=%d jobs=%d", i, verify.code, verify.body, cancel.code, st.jobs)
			}
		default:
			t.Fatalf("iter %d: unexpected status %q", i, st.status)
		}
	}
	t.Logf("outcomes over %d races: %v", raceIterations, outcomes)
}

// request_ttl also bounds the cross-team flow: a verify or fill on a
// request past created_at + request_ttl is refused with 410 and the
// request is marked expired. A fill refused this way persists no wraps.
func TestRequestLifecycle_RequestTTL_CrossTeamVerifyAndFill(t *testing.T) {
	fx := bootstrapLifecycle(t)
	ctx := t.Context()
	backdate := func(id uuid.UUID) {
		t.Helper()
		// The seed "standard" workflow carries request_ttl = 14 days.
		// Keep the fill window open so only request_ttl can refuse.
		if _, err := fx.pool.Exec(ctx, `
			UPDATE access_requests
			SET created_at = now() - interval '15 days',
			    fill_expires_at = now() + interval '1 hour'
			WHERE id = $1`, id); err != nil {
			t.Fatalf("backdate: %v", err)
		}
	}

	verifyID, _ := fx.crossTeamRequest(t, "ttl-verify", true)
	backdate(verifyID)
	code, body := fx.post(t, reqPath(verifyID, "verify"), uuid.NewString(), `{"voted_as":"source","decision":"approve"}`)
	if code != http.StatusGone || !strings.Contains(body, "request_expired") {
		t.Fatalf("verify past request_ttl = %d %s; want 410 request_expired", code, body)
	}
	if st := fx.state(t, verifyID); st.status != "expired" || st.votes != 0 || st.jobs != 0 {
		t.Fatalf("verify: status=%s votes=%d jobs=%d; want expired, 0, 0", st.status, st.votes, st.jobs)
	}

	fillID, _ := fx.crossTeamRequest(t, "ttl-fill", false)
	backdate(fillID)
	code, body = fx.post(t, reqPath(fillID, "fill"), uuid.NewString(), fillBody("fake-value-a"))
	if code != http.StatusGone || !strings.Contains(body, "request_expired") {
		t.Fatalf("fill past request_ttl = %d %s; want 410 request_expired", code, body)
	}
	if st := fx.state(t, fillID); st.status != "expired" || st.wraps != 0 {
		t.Fatalf("fill: status=%s wraps=%d; want expired with no wraps", st.status, st.wraps)
	}
}
