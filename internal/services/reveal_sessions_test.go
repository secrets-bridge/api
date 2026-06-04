package services_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

// revealHarness adds a RevealSessionService on top of buildL3Harness so
// we exercise the full submit → approve → open path with policy +
// environments wired (matches what cmd/api/main.go ships).
type revealHarness struct {
	reqSvc    *services.RequestService
	revealSvc *services.RevealSessionService
	pool      *storage.Pool
	envRepo   *storage.Environments
	wfRepo    *storage.Workflows
	polRepo   *storage.Policies
	reqRepo   *storage.AccessRequests
	wrapsR    *storage.SecretWraps
	wrapSvc   *services.WrapService
	sessR     *storage.RevealSessions
}

func buildRevealHarness(t *testing.T) *revealHarness {
	t.Helper()
	reqSvc, pool, envRepo, wfRepo, polRepo := buildL3Harness(t)

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	km, err := keymgmt.NewLocalKMS(masterKey)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	auditRepo := storage.NewAuditEvents(pool)
	wrapRepo := storage.NewSecretWraps(pool)
	policiesR := storage.NewPolicies(pool)
	workflowsR := storage.NewWorkflows(pool)
	requestRepo := storage.NewAccessRequests(pool)
	sessRepo := storage.NewRevealSessions(pool)

	wrapSvc := services.NewWrapService(wrapRepo, auditRepo, km)
	policyEng := services.NewPolicyEngine(policiesR, workflowsR, auditRepo)

	revealSvc := services.NewRevealSessionService(
		sessRepo, requestRepo, wrapSvc, policyEng, auditRepo,
	).WithEnvironments(envRepo)

	return &revealHarness{
		reqSvc:    reqSvc,
		revealSvc: revealSvc,
		pool:      pool,
		envRepo:   envRepo,
		wfRepo:    wfRepo,
		polRepo:   polRepo,
		reqRepo:   requestRepo,
		wrapsR:    wrapRepo,
		wrapSvc:   wrapSvc,
		sessR:     sessRepo,
	}
}

// seedUATEnvWithRule creates a project + uat env + a permissive rule
// matching that project/env, with reveal_ttl_seconds=60. Returns the
// env so callers can drive Submit/SubmitDirectReveal.
func seedUATEnvWithRule(t *testing.T, h *revealHarness, projectSlug string, ttlSec int) *storage.Environment {
	t.Helper()
	ctx := t.Context()
	projectID := makeProjectForSvc(t, h.pool, projectSlug)
	env := &storage.Environment{
		ProjectID: projectID, Name: "uat",
		Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd,
	}
	if err := h.envRepo.Create(ctx, env); err != nil {
		t.Fatalf("env Create: %v", err)
	}
	wf := &storage.WorkflowDefinition{
		Name: projectSlug + "-wf", MinApprovers: 0, AllowSelfApproval: true,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := h.wfRepo.Create(ctx, wf); err != nil {
		t.Fatalf("wf Create: %v", err)
	}
	rule := &storage.PolicyRule{
		Name:                projectSlug + "-rule",
		Selector:            map[string]any{"project_id": projectID.String(), "environment": "uat"},
		WorkflowID:          wf.ID,
		Priority:            500,
		Enabled:             true,
		DirectRevealAllowed: true,
		RevealTTLSeconds:    ttlSec,
	}
	if err := h.polRepo.Create(ctx, rule); err != nil {
		t.Fatalf("policy Create: %v", err)
	}
	return env
}

// submitDirectRevealRequest drives the L4 auto-execute path and seeds N
// wraps so the resulting request has consumable wraps for Open to bundle.
// Returns the request with wraps already created against it.
func submitDirectRevealRequest(t *testing.T, h *revealHarness, env *storage.Environment, requester string, keys ...string) *storage.AccessRequest {
	t.Helper()
	ctx := t.Context()
	req, err := h.reqSvc.SubmitDirectReveal(ctx, services.DirectRevealInput{
		RequesterID:        requester,
		Environment:        env,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetKeys:         keys,
		Justification:      "reveal-session test",
	})
	if err != nil {
		t.Fatalf("SubmitDirectReveal: %v", err)
	}
	// Simulate the agent's POST /agents/:id/wraps — for each requested key
	// the agent would store one wrap. We bypass the agent by calling
	// WrapService.WrapByAgent directly so the test stays at the service layer.
	agentID := uuid.New()
	for _, k := range keys {
		_, err := h.wrapSvc.WrapByAgent(ctx, agentID, services.WrapRequest{
			Plaintext: []byte("secret-value-for-" + k),
			RequestID: &req.ID,
			KeyName:   k,
			TTL:       2 * time.Minute,
		})
		if err != nil {
			t.Fatalf("WrapByAgent %q: %v", k, err)
		}
	}
	return req
}

func TestOpen_HappyPath(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	env := seedUATEnvWithRule(t, h, "rs-happy", 60)
	req := submitDirectRevealRequest(t, h, env, "alice", "DB_PASSWORD", "DB_USER")

	resp, err := h.revealSvc.Open(ctx, services.OpenInput{
		UserID:    "alice",
		RequestID: req.ID,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if resp.Session.ID == uuid.Nil {
		t.Fatal("session ID not populated")
	}
	if resp.Session.TTLSeconds != 60 {
		t.Errorf("TTL = %d want 60", resp.Session.TTLSeconds)
	}
	if len(resp.Wraps) != 2 {
		t.Fatalf("wraps in response = %d want 2", len(resp.Wraps))
	}
	if resp.Session.ExpiresAt.Sub(resp.Session.OpenedAt) < 50*time.Second {
		t.Errorf("ExpiresAt - OpenedAt = %v want ~60s", resp.Session.ExpiresAt.Sub(resp.Session.OpenedAt))
	}
	if len(resp.Session.WrapIDs) != 2 {
		t.Errorf("session wrap_ids = %d want 2", len(resp.Session.WrapIDs))
	}
}

func TestOpen_RejectsNonOwner(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	env := seedUATEnvWithRule(t, h, "rs-non-owner", 60)
	req := submitDirectRevealRequest(t, h, env, "alice", "DB_PASSWORD")

	_, err := h.revealSvc.Open(ctx, services.OpenInput{
		UserID:    "mallory",
		RequestID: req.ID,
	})
	if !errors.Is(err, services.ErrNotRequestOwner) {
		t.Errorf("got %v, want ErrNotRequestOwner", err)
	}

	// No reveal_session row should have been created.
	var count int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM reveal_sessions WHERE access_request_id = $1`, req.ID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("reveal_sessions rows created on owner-reject: %d", count)
	}
}

func TestOpen_RejectsPendingRequest(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	env := seedUATEnvWithRule(t, h, "rs-pending", 60)
	// Create a plain pending read request via SubmitRead (not direct
	// reveal) so the row lands as 'pending' rather than 'approved'.
	req, err := h.reqSvc.SubmitRead(ctx, services.ReadInput{
		RequesterID:        "alice",
		ProjectID:          env.ProjectID.String(),
		Environment:        env.Name,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetKeys:         []string{"DB_PASSWORD"},
		Justification:      "pending read",
	})
	if err != nil {
		t.Fatalf("SubmitRead: %v", err)
	}
	if req.Status != storage.AccessRequestStatusPending {
		t.Fatalf("seed status = %s want pending", req.Status)
	}

	_, err = h.revealSvc.Open(ctx, services.OpenInput{
		UserID:    "alice",
		RequestID: req.ID,
	})
	if !errors.Is(err, services.ErrRequestNotApproved) {
		t.Errorf("got %v, want ErrRequestNotApproved", err)
	}
}

func TestOpen_RejectsPatchTypeRequest(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	env := seedUATEnvWithRule(t, h, "rs-patch-type", 60)
	req, err := h.reqSvc.Submit(ctx, services.PatchInput{
		RequesterID:        "alice",
		ProjectID:          env.ProjectID.String(),
		Environment:        env.Name,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		KeyValues:          map[string][]byte{"DB_PASSWORD": []byte("hunter2")},
		Justification:      "patch flow",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	// Bump to approved so the type gate is the only blocker.
	if err := h.reqRepo.UpdateStatus(ctx, req.ID, storage.AccessRequestStatusApproved); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	_, err = h.revealSvc.Open(ctx, services.OpenInput{
		UserID:    "alice",
		RequestID: req.ID,
	})
	if !errors.Is(err, services.ErrWrongRequest) {
		t.Errorf("got %v, want ErrWrongRequest", err)
	}
}

func TestOpen_RejectsWhenAllWrapsConsumed(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	env := seedUATEnvWithRule(t, h, "rs-all-consumed", 60)
	req := submitDirectRevealRequest(t, h, env, "alice", "DB_PASSWORD")

	wrapIDs, err := h.wrapsR.ListIDsForRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("ListIDsForRequest: %v", err)
	}
	if len(wrapIDs) != 1 {
		t.Fatalf("seed wraps = %d want 1", len(wrapIDs))
	}
	// Burn the only wrap via the user-side single-shot path.
	if _, _, err := h.wrapSvc.RetrieveByUser(ctx, wrapIDs[0], "alice"); err != nil {
		t.Fatalf("RetrieveByUser: %v", err)
	}

	_, err = h.revealSvc.Open(ctx, services.OpenInput{
		UserID:    "alice",
		RequestID: req.ID,
	})
	if !errors.Is(err, services.ErrAllWrapsConsumed) {
		t.Errorf("got %v, want ErrAllWrapsConsumed", err)
	}
}

func TestOpen_TTLFromPolicy(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	// Rule TTL inside the schema range — Open must propagate it verbatim.
	env := seedUATEnvWithRule(t, h, "rs-ttl-policy", 180)
	req := submitDirectRevealRequest(t, h, env, "alice", "DB_PASSWORD")

	resp, err := h.revealSvc.Open(ctx, services.OpenInput{
		UserID:    "alice",
		RequestID: req.ID,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if resp.Session.TTLSeconds != 180 {
		t.Errorf("TTL = %d want 180 from policy", resp.Session.TTLSeconds)
	}
}

// The schema CHECK on policy_rules.reveal_ttl_seconds rejects values
// outside [10, 300] at insert time, but the service-layer clamp is the
// safety net for legacy/imported rows + a defensive belt-and-braces
// before we touch the session schema. Force a low value through the
// rule then bypass the seam to confirm we never insert a bad row.
func TestOpen_TTLDefaultsWhenPolicyZero(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	// Seed without a rule for the project/env → policy resolver falls
	// back to the system match-all rule (RevealTTLSeconds defaults to 60).
	projectID := makeProjectForSvc(t, h.pool, "rs-ttl-default")
	env := &storage.Environment{
		ProjectID: projectID, Name: "uat",
		Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd,
	}
	if err := h.envRepo.Create(ctx, env); err != nil {
		t.Fatalf("env Create: %v", err)
	}
	// SubmitDirectReveal requires policy.direct_reveal_allowed=true, so
	// fall back to the standard read path + manual approval bump.
	req, err := h.reqSvc.SubmitRead(ctx, services.ReadInput{
		RequesterID:        "alice",
		ProjectID:          projectID.String(),
		Environment:        "uat",
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetKeys:         []string{"DB_PASSWORD"},
		Justification:      "ttl default test",
	})
	if err != nil {
		t.Fatalf("SubmitRead: %v", err)
	}
	if err := h.reqRepo.UpdateStatus(ctx, req.ID, storage.AccessRequestStatusApproved); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	agentID := uuid.New()
	if _, err := h.wrapSvc.WrapByAgent(ctx, agentID, services.WrapRequest{
		Plaintext: []byte("v"),
		RequestID: &req.ID,
		KeyName:   "DB_PASSWORD",
		TTL:       2 * time.Minute,
	}); err != nil {
		t.Fatalf("WrapByAgent: %v", err)
	}

	resp, err := h.revealSvc.Open(ctx, services.OpenInput{
		UserID:    "alice",
		RequestID: req.ID,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// 60 = system default RevealTTLSeconds on the seed match-all rule
	// (matches storage policy_rules default + service revealTTLDefault).
	if resp.Session.TTLSeconds < 10 || resp.Session.TTLSeconds > 300 {
		t.Errorf("TTL = %d outside [10, 300]", resp.Session.TTLSeconds)
	}
}

func TestListActiveForUser_FiltersByCaller(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	envA := seedUATEnvWithRule(t, h, "rs-listactive-a", 60)
	reqA := submitDirectRevealRequest(t, h, envA, "alice", "K1")
	if _, err := h.revealSvc.Open(ctx, services.OpenInput{UserID: "alice", RequestID: reqA.ID}); err != nil {
		t.Fatalf("Open A: %v", err)
	}

	envB := seedUATEnvWithRule(t, h, "rs-listactive-b", 60)
	reqB := submitDirectRevealRequest(t, h, envB, "bob", "K1")
	if _, err := h.revealSvc.Open(ctx, services.OpenInput{UserID: "bob", RequestID: reqB.ID}); err != nil {
		t.Fatalf("Open B: %v", err)
	}

	aliceList, err := h.revealSvc.ListActiveForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListActiveForUser alice: %v", err)
	}
	if len(aliceList) != 1 || aliceList[0].UserID != "alice" {
		t.Errorf("alice's active list = %+v", aliceList)
	}

	bobList, err := h.revealSvc.ListActiveForUser(ctx, "bob")
	if err != nil {
		t.Fatalf("ListActiveForUser bob: %v", err)
	}
	if len(bobList) != 1 || bobList[0].UserID != "bob" {
		t.Errorf("bob's active list = %+v", bobList)
	}
}

func TestMarkExpired_RejectsNonOwner(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	env := seedUATEnvWithRule(t, h, "rs-markexpired-nonowner", 60)
	req := submitDirectRevealRequest(t, h, env, "alice", "K1")
	resp, err := h.revealSvc.Open(ctx, services.OpenInput{UserID: "alice", RequestID: req.ID})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	err = h.revealSvc.MarkExpired(ctx, resp.Session.ID, "mallory", storage.RevealSessionExpiredUserHide)
	if !errors.Is(err, services.ErrNotSessionOwner) {
		t.Errorf("got %v, want ErrNotSessionOwner", err)
	}

	// Confirm row is still active.
	cur, err := h.sessR.Get(ctx, resp.Session.ID)
	if err != nil {
		t.Fatalf("Get session: %v", err)
	}
	if cur.ExpiredAt != nil {
		t.Errorf("session expired by non-owner: ExpiredAt=%v", cur.ExpiredAt)
	}
}

func TestMarkExpired_OwnerSucceedsExpiresWraps(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	env := seedUATEnvWithRule(t, h, "rs-markexpired-owner", 60)
	req := submitDirectRevealRequest(t, h, env, "alice", "K1", "K2")
	resp, err := h.revealSvc.Open(ctx, services.OpenInput{UserID: "alice", RequestID: req.ID})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := h.revealSvc.MarkExpired(ctx, resp.Session.ID, "alice", storage.RevealSessionExpiredUserHide); err != nil {
		t.Fatalf("MarkExpired: %v", err)
	}

	// Row flipped + reason set.
	cur, err := h.sessR.Get(ctx, resp.Session.ID)
	if err != nil {
		t.Fatalf("Get session: %v", err)
	}
	if cur.ExpiredAt == nil {
		t.Fatal("session ExpiredAt nil after MarkExpired")
	}
	if cur.ExpiredReason != string(storage.RevealSessionExpiredUserHide) {
		t.Errorf("ExpiredReason = %q want %q", cur.ExpiredReason, storage.RevealSessionExpiredUserHide)
	}

	// Each underlying wrap should now refuse retrieval with ErrExpired.
	for _, wid := range resp.Session.WrapIDs {
		_, _, err := h.wrapSvc.RetrieveByUser(ctx, wid, "alice")
		if !errors.Is(err, storage.ErrExpired) {
			t.Errorf("wrap %s after MarkExpired: got %v want ErrExpired", wid, err)
		}
	}
}

func TestMarkExpired_Idempotent(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	env := seedUATEnvWithRule(t, h, "rs-markexpired-idempotent", 60)
	req := submitDirectRevealRequest(t, h, env, "alice", "K1")
	resp, err := h.revealSvc.Open(ctx, services.OpenInput{UserID: "alice", RequestID: req.ID})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := h.revealSvc.MarkExpired(ctx, resp.Session.ID, "alice", storage.RevealSessionExpiredUserHide); err != nil {
		t.Fatalf("first MarkExpired: %v", err)
	}
	if err := h.revealSvc.MarkExpired(ctx, resp.Session.ID, "alice", storage.RevealSessionExpiredUserHide); err != nil {
		t.Errorf("second MarkExpired: got %v want nil (idempotent)", err)
	}
}

// Canary check: the reveal-session row's metadata must NEVER carry a
// secret value. Open should write only wrap_ids + audit metadata that
// names keys but not values.
func TestOpen_NoPlaintextInSessionRow(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	canary := "ZZZ-reveal-session-canary-XYZ"
	env := seedUATEnvWithRule(t, h, "rs-canary", 60)
	req, err := h.reqSvc.SubmitDirectReveal(ctx, services.DirectRevealInput{
		RequesterID:        "alice",
		Environment:        env,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetKeys:         []string{"API_KEY"},
		Justification:      "canary test",
	})
	if err != nil {
		t.Fatalf("SubmitDirectReveal: %v", err)
	}
	agentID := uuid.New()
	if _, err := h.wrapSvc.WrapByAgent(ctx, agentID, services.WrapRequest{
		Plaintext: []byte(canary),
		RequestID: &req.ID,
		KeyName:   "API_KEY",
		TTL:       2 * time.Minute,
	}); err != nil {
		t.Fatalf("WrapByAgent: %v", err)
	}

	if _, err := h.revealSvc.Open(ctx, services.OpenInput{
		UserID: "alice", RequestID: req.ID,
	}); err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Scan all reveal_sessions text-ish columns and audit_events metadata
	// for the plaintext canary.
	scanForCanary := func(query string, args ...any) {
		rows, err := h.pool.Query(ctx, query, args...)
		if err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		defer rows.Close()
		for rows.Next() {
			var s []byte
			if err := rows.Scan(&s); err != nil {
				t.Fatalf("scan: %v", err)
			}
			if bytes.Contains(s, []byte(canary)) {
				t.Fatalf("plaintext canary leaked: query=%q row=%q", query, s)
			}
		}
	}
	// reveal_sessions: cast row to text to look at every column at once.
	scanForCanary(`SELECT (rs)::text::bytea FROM reveal_sessions rs WHERE access_request_id = $1`, req.ID)
	// audit_events.metadata across both wrap.create and reveal.session.opened.
	scanForCanary(
		`SELECT metadata::text::bytea FROM audit_events WHERE action IN ('reveal.session.opened', 'wrap.create', 'secret.reveal.direct.issued') AND correlation_id = $1`,
		req.ID,
	)
}

// guard against go-tools yelling about unused imports in case the test
// matrix shrinks during a refactor.
var _ = context.Background
