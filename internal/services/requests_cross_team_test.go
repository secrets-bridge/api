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

// Slice N3 — service-layer tests for the cross-team request flow.
//
// Coverage:
//   - SubmitCrossTeam happy path (snapshot columns + fill_expires_at)
//   - target chain validation (project ⊄ team / env ⊄ project / FK)
//   - destination provider connection unbound
//   - empty destination_keys
//   - min_approvers > 1 rejection at submit
//   - Fill happy path → pending_verification + N wraps + audit
//   - Fill SoD: filler == requester → 403
//   - Fill on non-pending_values → ErrCrossTeamAlreadyFilled
//   - Refuse happy path; SoD; short reason rejection
//   - VerifyCrossTeam: source approve transitions to approved when
//     no security required
//   - VerifyCrossTeam: source approve + requires_security → status
//     stays pending_verification + next_required has security
//   - VerifyCrossTeam: SoD requester / filler / same-actor double-vote
//   - Cancel works from pending_values + pending_verification
//   - Inbox filters by team + fail-closed on empty TeamIDs
//   - Canary scan after Fill: plaintext not in access_requests /
//     audit_events metadata

type crossTeamHarness struct {
	reqSvc        *services.RequestService
	pool          *storage.Pool
	envRepo       *storage.Environments
	teamRepo      *storage.Teams
	projRepo      *storage.Projects
	wrapsR        *storage.SecretWraps
	requestsR     *storage.AccessRequests
	approvalsR    *storage.Approvals
	provConnRepo  *storage.ProviderConnections
	wfRepo        *storage.Workflows
	policiesR     *storage.Policies
}

func buildCrossTeamHarness(t *testing.T) *crossTeamHarness {
	t.Helper()
	engine, pool, policies, workflows := bootstrapPolicy(t)
	envRepo := storage.NewEnvironments(pool)
	teamRepo := storage.NewTeams(pool)
	projRepo := storage.NewProjects(pool)

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	km, err := keymgmt.NewLocalKMS(masterKey)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	requestRepo := storage.NewAccessRequests(pool)
	approvalRepo := storage.NewApprovals(pool)
	auditRepo := storage.NewAuditEvents(pool)
	wrapRepo := storage.NewSecretWraps(pool)
	wrapSvc := services.NewWrapService(wrapRepo, auditRepo, km)
	jobsRepo := storage.NewSyncJobs(pool)
	jobSvc := services.NewJobService(jobsRepo, auditRepo)
	provConnRepo := storage.NewProviderConnections(pool)

	reqSvc := services.NewRequestService(requestRepo, approvalRepo, wrapSvc, workflows, engine, auditRepo, jobSvc).
		WithEnvironments(envRepo).
		WithCrossTeamRepos(teamRepo, projRepo, envRepo, provConnRepo)
	jobSvc.OnCompleted(reqSvc.OnJobCompleted)

	return &crossTeamHarness{
		reqSvc:       reqSvc,
		pool:         pool,
		envRepo:      envRepo,
		teamRepo:     teamRepo,
		projRepo:     projRepo,
		wrapsR:       wrapRepo,
		requestsR:    requestRepo,
		approvalsR:   approvalRepo,
		provConnRepo: provConnRepo,
		wfRepo:       workflows,
		policiesR:    policies,
	}
}

// seedCrossTeamScope builds the minimum scope graph for a happy-path
// submit + returns a ready-to-go input.
func seedCrossTeamScope(t *testing.T, h *crossTeamHarness, slug string) services.CrossTeamSubmitInput {
	t.Helper()
	ctx := t.Context()

	srcProject := &storage.Project{Name: slug + "-src"}
	if err := h.projRepo.Create(ctx, srcProject); err != nil {
		t.Fatalf("src project: %v", err)
	}
	srcEnv := &storage.Environment{
		ProjectID: srcProject.ID, Name: "uat",
		Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd,
	}
	if err := h.envRepo.Create(ctx, srcEnv); err != nil {
		t.Fatalf("src env: %v", err)
	}

	targetTeam := &storage.Team{Name: slug + "-target-team"}
	if err := h.teamRepo.Create(ctx, targetTeam); err != nil {
		t.Fatalf("target team: %v", err)
	}
	targetProject := &storage.Project{Name: slug + "-target", TeamID: &targetTeam.ID}
	if err := h.projRepo.Create(ctx, targetProject); err != nil {
		t.Fatalf("target project: %v", err)
	}
	// Bind project to team explicitly via SetTeam (Create may not
	// pick up the TeamID).
	if err := h.projRepo.SetTeam(ctx, targetProject.ID, &targetTeam.ID); err != nil {
		t.Fatalf("set team: %v", err)
	}
	targetEnv := &storage.Environment{
		ProjectID: targetProject.ID, Name: "uat",
		Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd,
	}
	if err := h.envRepo.Create(ctx, targetEnv); err != nil {
		t.Fatalf("target env: %v", err)
	}

	var provConnID uuid.UUID
	if err := h.pool.QueryRow(ctx, `
		INSERT INTO provider_connections (name, type, auth_method, scope, status)
		VALUES ($1, 'vault', 'token', '{}'::jsonb, 'active')
		RETURNING id`, slug+"-dest-vault").Scan(&provConnID); err != nil {
		t.Fatalf("provider_connection: %v", err)
	}

	return services.CrossTeamSubmitInput{
		RequesterID:                     "alice@example.com",
		ProjectID:                       srcProject.ID.String(),
		Environment:                     "uat",
		TargetTeamID:                    targetTeam.ID,
		TargetProjectID:                 targetProject.ID,
		TargetEnvironmentID:             targetEnv.ID,
		DestinationProviderConnectionID: provConnID,
		DestinationSecretRef:            "billing/prod/db",
		DestinationKeys:                 []string{"DB_PASSWORD", "DB_USER"},
		Justification:                   "rotate billing creds; cross-team handoff for compliance",
	}
}

func TestSubmitCrossTeam_HappyPath(t *testing.T) {
	h := buildCrossTeamHarness(t)
	in := seedCrossTeamScope(t, h, "ct-happy")
	req, err := h.reqSvc.SubmitCrossTeam(t.Context(), in)
	if err != nil {
		t.Fatalf("SubmitCrossTeam: %v", err)
	}
	if req.Type != storage.AccessRequestTypeCrossTeam {
		t.Errorf("Type = %s", req.Type)
	}
	if req.Status != storage.AccessRequestStatusPendingValues {
		t.Errorf("Status = %s want pending_values", req.Status)
	}
	if req.SnapMinApprovers == nil || *req.SnapMinApprovers != 1 {
		t.Errorf("SnapMinApprovers = %v want 1", req.SnapMinApprovers)
	}
	if req.SnapRequiresSecurityApproval == nil || *req.SnapRequiresSecurityApproval != false {
		t.Errorf("SnapRequiresSecurityApproval = %v want false", req.SnapRequiresSecurityApproval)
	}
	if req.FillExpiresAt == nil {
		t.Error("FillExpiresAt is nil")
	} else if !req.FillExpiresAt.After(time.Now()) {
		t.Errorf("FillExpiresAt = %v not in the future", req.FillExpiresAt)
	}
}

func TestSubmitCrossTeam_TargetProjectNotInTeam(t *testing.T) {
	h := buildCrossTeamHarness(t)
	in := seedCrossTeamScope(t, h, "ct-bad-target")
	// Substitute a different team's ID.
	otherTeam := &storage.Team{Name: "ct-bad-target-other-team"}
	if err := h.teamRepo.Create(t.Context(), otherTeam); err != nil {
		t.Fatalf("other team: %v", err)
	}
	in.TargetTeamID = otherTeam.ID

	_, err := h.reqSvc.SubmitCrossTeam(t.Context(), in)
	if !errors.Is(err, services.ErrCrossTeamInvalidTarget) {
		t.Fatalf("err = %v want ErrCrossTeamInvalidTarget", err)
	}
}

func TestSubmitCrossTeam_EmptyDestKeys(t *testing.T) {
	h := buildCrossTeamHarness(t)
	in := seedCrossTeamScope(t, h, "ct-empty-keys")
	in.DestinationKeys = nil
	_, err := h.reqSvc.SubmitCrossTeam(t.Context(), in)
	if !errors.Is(err, services.ErrCrossTeamKeysEmpty) {
		t.Fatalf("err = %v want ErrCrossTeamKeysEmpty", err)
	}
}

func TestSubmitCrossTeam_UnboundDestination(t *testing.T) {
	h := buildCrossTeamHarness(t)
	in := seedCrossTeamScope(t, h, "ct-unbound")
	in.DestinationProviderConnectionID = uuid.New() // random — no row
	_, err := h.reqSvc.SubmitCrossTeam(t.Context(), in)
	if !errors.Is(err, services.ErrCrossTeamDestinationUnbound) {
		t.Fatalf("err = %v want ErrCrossTeamDestinationUnbound", err)
	}
}

func TestSubmitCrossTeam_RejectsMinApproversGreaterThanOne(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	// Custom workflow + a policy that selects it for our scope.
	wf := &storage.WorkflowDefinition{
		Name: "ct-strict", MinApprovers: 2, AllowSelfApproval: false,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour,
		FillTTLSeconds: 7200, Enabled: true,
	}
	if err := h.wfRepo.Create(ctx, wf); err != nil {
		t.Fatalf("wf Create: %v", err)
	}
	in := seedCrossTeamScope(t, h, "ct-strict")
	// Match-all on the source project scope so the engine picks the
	// strict workflow.
	rule := &storage.PolicyRule{
		Name:                "ct-strict-rule",
		Selector:            map[string]any{"project_id": in.ProjectID, "environment": "uat"},
		WorkflowID:          wf.ID,
		Priority:            500,
		Enabled:             true,
		DirectRevealAllowed: false,
		RevealTTLSeconds:    60,
	}
	if err := h.policiesR.Create(ctx, rule); err != nil {
		t.Fatalf("policy Create: %v", err)
	}

	_, err := h.reqSvc.SubmitCrossTeam(ctx, in)
	if !errors.Is(err, services.ErrCrossTeamMinApproversUnsupported) {
		t.Fatalf("err = %v want ErrCrossTeamMinApproversUnsupported", err)
	}
}

func TestFill_HappyPath(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-fill")
	req, err := h.reqSvc.SubmitCrossTeam(ctx, in)
	if err != nil {
		t.Fatalf("SubmitCrossTeam: %v", err)
	}

	filled, err := h.reqSvc.Fill(ctx, services.FillCrossTeamInput{
		RequestID:   req.ID,
		FillerID:    "bob@example.com",
		KeyValues:   map[string][]byte{"DB_PASSWORD": []byte("hunter2-rotated"), "DB_USER": []byte("billing-svc")},
		FillComment: "rotated; expires in 90d",
	})
	if err != nil {
		t.Fatalf("Fill: %v", err)
	}
	if filled.Status != storage.AccessRequestStatusPendingVerification {
		t.Errorf("Status = %s want pending_verification", filled.Status)
	}
	if filled.FilledByUserID != "bob@example.com" {
		t.Errorf("FilledByUserID = %q", filled.FilledByUserID)
	}
	// 2 wraps should exist for this request.
	ids, err := h.wrapsR.ListIDsForRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("ListIDsForRequest: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("wraps for request = %d want 2", len(ids))
	}
}

func TestFill_RequesterCannotFill(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-fill-sod")
	req, _ := h.reqSvc.SubmitCrossTeam(ctx, in)

	_, err := h.reqSvc.Fill(ctx, services.FillCrossTeamInput{
		RequestID: req.ID,
		FillerID:  in.RequesterID,
		KeyValues: map[string][]byte{"DB_PASSWORD": []byte("x")},
	})
	if !errors.Is(err, services.ErrSeparationOfDuties) {
		t.Fatalf("err = %v want ErrSeparationOfDuties", err)
	}
}

func TestFill_SecondCallRejected(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-fill-2nd")
	req, _ := h.reqSvc.SubmitCrossTeam(ctx, in)

	if _, err := h.reqSvc.Fill(ctx, services.FillCrossTeamInput{
		RequestID: req.ID, FillerID: "bob@example.com",
		KeyValues: map[string][]byte{"DB_PASSWORD": []byte("a"), "DB_USER": []byte("b")},
	}); err != nil {
		t.Fatalf("first Fill: %v", err)
	}
	_, err := h.reqSvc.Fill(ctx, services.FillCrossTeamInput{
		RequestID: req.ID, FillerID: "carol@example.com",
		KeyValues: map[string][]byte{"DB_PASSWORD": []byte("c"), "DB_USER": []byte("d")},
	})
	if !errors.Is(err, storage.ErrCrossTeamAlreadyFilled) {
		t.Fatalf("err = %v want ErrCrossTeamAlreadyFilled", err)
	}
}

func TestRefuse_HappyPath(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-refuse")
	req, _ := h.reqSvc.SubmitCrossTeam(ctx, in)
	refused, err := h.reqSvc.Refuse(ctx, services.RefuseCrossTeamInput{
		RequestID: req.ID, UserID: "bob@example.com", Reason: "out of scope ask",
	})
	if err != nil {
		t.Fatalf("Refuse: %v", err)
	}
	if refused.Status != storage.AccessRequestStatusRefused {
		t.Errorf("Status = %s want refused", refused.Status)
	}
}

func TestRefuse_RequesterCannotRefuse(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-refuse-sod")
	req, _ := h.reqSvc.SubmitCrossTeam(ctx, in)
	_, err := h.reqSvc.Refuse(ctx, services.RefuseCrossTeamInput{
		RequestID: req.ID, UserID: in.RequesterID, Reason: "self-refuse attempt",
	})
	if !errors.Is(err, services.ErrSeparationOfDuties) {
		t.Fatalf("err = %v want ErrSeparationOfDuties", err)
	}
}

func TestVerify_SourceApproveWithoutSecurityRequirement(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-verify-no-sec")
	req, _ := h.reqSvc.SubmitCrossTeam(ctx, in)
	if _, err := h.reqSvc.Fill(ctx, services.FillCrossTeamInput{
		RequestID: req.ID, FillerID: "bob@example.com",
		KeyValues: map[string][]byte{"DB_PASSWORD": []byte("a"), "DB_USER": []byte("b")},
	}); err != nil {
		t.Fatalf("Fill: %v", err)
	}

	resp, err := h.reqSvc.VerifyCrossTeam(ctx, services.VerifyCrossTeamInput{
		RequestID: req.ID, ApproverID: "carol@example.com",
		VotedAs: services.VotedAsSource, Decision: storage.ApprovalDecisionApprove,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if resp.Status != storage.AccessRequestStatusApproved {
		t.Errorf("Status = %s want approved", resp.Status)
	}
	if len(resp.NextRequired) != 0 {
		t.Errorf("NextRequired = %v want empty", resp.NextRequired)
	}
}

func TestVerify_SourceApproveStillNeedsSecurityWhenRequired(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	// Custom workflow requiring security approval.
	wf := &storage.WorkflowDefinition{
		Name: "ct-prod-sec", MinApprovers: 1, AllowSelfApproval: false,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour,
		FillTTLSeconds: 86400, RequiresSecurityApproval: true, Enabled: true,
	}
	if err := h.wfRepo.Create(ctx, wf); err != nil {
		t.Fatalf("wf Create: %v", err)
	}
	in := seedCrossTeamScope(t, h, "ct-verify-sec")
	rule := &storage.PolicyRule{
		Name:                "ct-prod-sec-rule",
		Selector:            map[string]any{"project_id": in.ProjectID, "environment": "uat"},
		WorkflowID:          wf.ID,
		Priority:            500,
		Enabled:             true,
		DirectRevealAllowed: false,
		RevealTTLSeconds:    60,
	}
	if err := h.policiesR.Create(ctx, rule); err != nil {
		t.Fatalf("policy Create: %v", err)
	}
	req, err := h.reqSvc.SubmitCrossTeam(ctx, in)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if req.SnapRequiresSecurityApproval == nil || !*req.SnapRequiresSecurityApproval {
		t.Fatalf("snapshot did not capture requires_security_approval")
	}
	if _, err := h.reqSvc.Fill(ctx, services.FillCrossTeamInput{
		RequestID: req.ID, FillerID: "bob@example.com",
		KeyValues: map[string][]byte{"DB_PASSWORD": []byte("a"), "DB_USER": []byte("b")},
	}); err != nil {
		t.Fatalf("Fill: %v", err)
	}

	// Source approve — should NOT transition yet.
	resp, err := h.reqSvc.VerifyCrossTeam(ctx, services.VerifyCrossTeamInput{
		RequestID: req.ID, ApproverID: "carol@example.com",
		VotedAs: services.VotedAsSource, Decision: storage.ApprovalDecisionApprove,
	})
	if err != nil {
		t.Fatalf("Verify source: %v", err)
	}
	if resp.Status != storage.AccessRequestStatusPendingVerification {
		t.Errorf("Status = %s want pending_verification (security still required)", resp.Status)
	}
	if !sliceContains(resp.NextRequired, "security_approval") {
		t.Errorf("NextRequired = %v want to include security_approval", resp.NextRequired)
	}

	// Security approve by a DIFFERENT user — completes the chain.
	resp, err = h.reqSvc.VerifyCrossTeam(ctx, services.VerifyCrossTeamInput{
		RequestID: req.ID, ApproverID: "diana-security@example.com",
		VotedAs: services.VotedAsSecurity, Decision: storage.ApprovalDecisionApprove,
	})
	if err != nil {
		t.Fatalf("Verify security: %v", err)
	}
	if resp.Status != storage.AccessRequestStatusApproved {
		t.Errorf("Status = %s want approved", resp.Status)
	}
}

func TestVerify_RequesterCannotVote(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-verify-req-sod")
	req, _ := h.reqSvc.SubmitCrossTeam(ctx, in)
	if _, err := h.reqSvc.Fill(ctx, services.FillCrossTeamInput{
		RequestID: req.ID, FillerID: "bob@example.com",
		KeyValues: map[string][]byte{"DB_PASSWORD": []byte("a"), "DB_USER": []byte("b")},
	}); err != nil {
		t.Fatalf("Fill: %v", err)
	}

	_, err := h.reqSvc.VerifyCrossTeam(ctx, services.VerifyCrossTeamInput{
		RequestID: req.ID, ApproverID: in.RequesterID,
		VotedAs: services.VotedAsSource, Decision: storage.ApprovalDecisionApprove,
	})
	if !errors.Is(err, services.ErrSeparationOfDuties) {
		t.Fatalf("err = %v want ErrSeparationOfDuties", err)
	}
}

func TestVerify_FillerCannotVote(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-verify-filler-sod")
	req, _ := h.reqSvc.SubmitCrossTeam(ctx, in)
	if _, err := h.reqSvc.Fill(ctx, services.FillCrossTeamInput{
		RequestID: req.ID, FillerID: "bob@example.com",
		KeyValues: map[string][]byte{"DB_PASSWORD": []byte("a"), "DB_USER": []byte("b")},
	}); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	_, err := h.reqSvc.VerifyCrossTeam(ctx, services.VerifyCrossTeamInput{
		RequestID: req.ID, ApproverID: "bob@example.com",
		VotedAs: services.VotedAsSource, Decision: storage.ApprovalDecisionApprove,
	})
	if !errors.Is(err, services.ErrSeparationOfDuties) {
		t.Fatalf("err = %v want ErrSeparationOfDuties", err)
	}
}

func TestCancel_AllowedFromPendingValues(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-cancel-pv")
	req, _ := h.reqSvc.SubmitCrossTeam(ctx, in)
	cancelled, err := h.reqSvc.Cancel(ctx, req.ID, in.RequesterID)
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if cancelled.Status != storage.AccessRequestStatusCancelled {
		t.Errorf("Status = %s want cancelled", cancelled.Status)
	}
}

func TestInbox_FiltersByTeam(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-inbox")
	req, _ := h.reqSvc.SubmitCrossTeam(ctx, in)

	rows, err := h.reqSvc.Inbox(ctx, services.InboxInput{
		TeamIDs: []uuid.UUID{in.TargetTeamID},
	})
	if err != nil {
		t.Fatalf("Inbox: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != req.ID {
		t.Errorf("Inbox returned %d rows; expected 1 with id %s", len(rows), req.ID)
	}

	// Fail-closed on empty team set.
	empty, err := h.reqSvc.Inbox(ctx, services.InboxInput{TeamIDs: nil})
	if err != nil {
		t.Fatalf("Inbox empty: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("empty-team-set returned %d rows", len(empty))
	}
}

func TestFill_NoPlaintextInDBOrAudit(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	in := seedCrossTeamScope(t, h, "ct-canary")
	req, _ := h.reqSvc.SubmitCrossTeam(ctx, in)

	canary := []byte("ZZZ-ct-fill-canary-XYZ")
	if _, err := h.reqSvc.Fill(ctx, services.FillCrossTeamInput{
		RequestID: req.ID, FillerID: "bob@example.com",
		KeyValues: map[string][]byte{"DB_PASSWORD": append([]byte(nil), canary...), "DB_USER": []byte("billing-svc")},
	}); err != nil {
		t.Fatalf("Fill: %v", err)
	}

	// Scan secret_wraps.encrypted_value for the canary.
	rows, err := h.pool.Query(ctx,
		`SELECT encrypted_value FROM secret_wraps WHERE request_id = $1`, req.ID)
	if err != nil {
		t.Fatalf("query wraps: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		_ = rows.Scan(&raw)
		if bytes.Contains(raw, canary) {
			t.Fatal("canary leaked into encrypted_value")
		}
	}

	// Scan audit_events.metadata for the canary.
	rows2, err := h.pool.Query(ctx,
		`SELECT metadata::text::bytea FROM audit_events WHERE correlation_id = $1`, req.ID)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var raw []byte
		_ = rows2.Scan(&raw)
		if bytes.Contains(raw, canary) {
			t.Fatal("canary leaked into audit_events.metadata")
		}
	}

	// And on the access_requests row itself.
	rows3, err := h.pool.Query(ctx, `
		SELECT COALESCE(justification, ''), COALESCE(fill_comment, ''),
		       COALESCE(refuse_reason, ''), COALESCE(destination_secret_ref, '')
		FROM access_requests WHERE id = $1`, req.ID)
	if err != nil {
		t.Fatalf("query request: %v", err)
	}
	defer rows3.Close()
	if !rows3.Next() {
		t.Fatal("request row gone")
	}
	var j, fc, rr, dsr string
	if err := rows3.Scan(&j, &fc, &rr, &dsr); err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, s := range []string{j, fc, rr, dsr} {
		if bytes.Contains([]byte(s), canary) {
			t.Fatalf("canary leaked into access_requests column: %q", s)
		}
	}
}

func sliceContains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// guards the package's context import non-dead in case other tests
// remove their usages later.
var _ = context.Background
