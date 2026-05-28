package services_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

// requestHarness wires the full Submit/Approve/Reject/Cancel surface
// against a real Postgres. Tests that don't need a custom workflow
// just rely on the seed default ("standard", min_approvers=1).
type requestHarness struct {
	requests *services.RequestService
	wraps    *services.WrapService
	pool     *storage.Pool
	requestsR *storage.AccessRequests
	approvalsR *storage.Approvals
	workflowsR *storage.Workflows
	policiesR  *storage.Policies
	wrapsR     *storage.SecretWraps
}

func bootstrapRequests(t *testing.T) *requestHarness {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 6, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	// Preserve system-seeded workflow/policy rows; clear everything
	// else so each test sees a clean slate. audit_events uses TRUNCATE
	// because of its append-only triggers.
	const wipe = `
		DELETE FROM approvals;
		DELETE FROM secret_wraps;
		DELETE FROM access_requests;
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;
		DELETE FROM user_roles;
		DELETE FROM roles WHERE is_system = false;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	km, err := keymgmt.NewLocalKMS(masterKey)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	auditR := storage.NewAuditEvents(pool)
	wrapsR := storage.NewSecretWraps(pool)
	requestsR := storage.NewAccessRequests(pool)
	approvalsR := storage.NewApprovals(pool)
	workflowsR := storage.NewWorkflows(pool)
	policiesR := storage.NewPolicies(pool)

	wrapSvc := services.NewWrapService(wrapsR, auditR, km)
	policy := services.NewPolicyEngine(policiesR, workflowsR)
	reqSvc := services.NewRequestService(requestsR, approvalsR, wrapSvc, workflowsR, policy, auditR)

	return &requestHarness{
		requests:   reqSvc,
		wraps:      wrapSvc,
		pool:       pool,
		requestsR:  requestsR,
		approvalsR: approvalsR,
		workflowsR: workflowsR,
		policiesR:  policiesR,
		wrapsR:     wrapsR,
	}
}

func samplePatch(requester string) services.PatchInput {
	return services.PatchInput{
		RequesterID:        requester,
		ProjectID:          "billing",
		Environment:        "prod",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/billing/prod/db",
		KeyValues: map[string][]byte{
			"DB_PASSWORD": []byte("hunter2-the-real-prod-password"),
			"DB_USER":     []byte("billing-svc"),
		},
		Justification: "Rotating DB credentials per quarterly compliance",
	}
}

func TestSubmit_HappyPath_SeedWorkflow(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, err := h.requests.Submit(ctx, samplePatch("alice"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if req.ID == uuid.Nil {
		t.Fatal("Submit returned nil ID")
	}
	if req.Status != storage.AccessRequestStatusPending {
		t.Fatalf("status = %s want pending", req.Status)
	}
	if req.WorkflowID == nil {
		t.Fatal("WorkflowID nil — policy engine did not bind a workflow")
	}
	if len(req.TargetKeys) != 2 {
		t.Fatalf("TargetKeys = %v want 2", req.TargetKeys)
	}

	// Two wraps must exist for this request.
	ids, err := h.wrapsR.ListIDsForRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("ListIDsForRequest: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("wraps for request = %d want 2", len(ids))
	}
}

func TestSubmit_NoPlaintextInDB(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	canary := []byte("ZZZ-distinctive-canary-XYZ")
	in := samplePatch("alice")
	in.KeyValues = map[string][]byte{"API_KEY": append([]byte(nil), canary...)}

	req, err := h.requests.Submit(ctx, in)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	// Scan every wrap row for the canary.
	rows, err := h.pool.Query(ctx,
		`SELECT encrypted_value FROM secret_wraps WHERE request_id = $1`, req.ID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		_ = rows.Scan(&raw)
		if containsBytes(raw, canary) {
			t.Fatal("plaintext canary leaked into encrypted_value")
		}
	}

	// And on the access_requests row itself.
	var (
		justif    string
		targetRef string
	)
	if err := h.pool.QueryRow(ctx,
		`SELECT justification, target_secret_ref FROM access_requests WHERE id = $1`,
		req.ID).Scan(&justif, &targetRef); err != nil {
		t.Fatalf("query request: %v", err)
	}
	if containsBytes([]byte(justif), canary) || containsBytes([]byte(targetRef), canary) {
		t.Fatal("plaintext canary leaked into access_requests metadata")
	}
}

func TestApprove_HappyPath_TransitionsToApproved(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, err := h.requests.Submit(ctx, samplePatch("alice"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	updated, err := h.requests.Approve(ctx, req.ID, "bob", "LGTM")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if updated.Status != storage.AccessRequestStatusApproved {
		t.Fatalf("status = %s want approved", updated.Status)
	}

	// Approvals list should reflect bob's vote.
	approvals, err := h.requests.Approvals(ctx, req.ID)
	if err != nil {
		t.Fatalf("Approvals: %v", err)
	}
	if len(approvals) != 1 || approvals[0].ApproverID != "bob" {
		t.Fatalf("approvals = %+v want one from bob", approvals)
	}
}

func TestApprove_SelfApprovalRejected_BySeedWorkflow(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, _ := h.requests.Submit(ctx, samplePatch("alice"))
	_, err := h.requests.Approve(ctx, req.ID, "alice", "")
	if !errors.Is(err, services.ErrSelfApprovalDenied) {
		t.Fatalf("expected ErrSelfApprovalDenied, got %v", err)
	}
}

func TestApprove_DuplicateVoteRejected(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	// Custom workflow needing 2 approvers so bob's first vote doesn't
	// flip the request to approved on its own.
	wf := newWorkflow(t, ctx, h, "two-approvers", 2, false)
	policyRule(t, ctx, h, "two-approvers-rule", wf.ID, 100)

	req, _ := h.requests.Submit(ctx, samplePatch("alice"))
	if _, err := h.requests.Approve(ctx, req.ID, "bob", ""); err != nil {
		t.Fatalf("first Approve: %v", err)
	}
	if _, err := h.requests.Approve(ctx, req.ID, "bob", ""); !errors.Is(err, services.ErrDuplicateVote) {
		t.Fatalf("expected ErrDuplicateVote, got %v", err)
	}
}

func TestApprove_TwoApproversThresholdCrossed(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	wf := newWorkflow(t, ctx, h, "two-approvers", 2, false)
	policyRule(t, ctx, h, "two-approvers-rule", wf.ID, 100)

	req, _ := h.requests.Submit(ctx, samplePatch("alice"))
	bobUpd, err := h.requests.Approve(ctx, req.ID, "bob", "")
	if err != nil {
		t.Fatalf("bob Approve: %v", err)
	}
	if bobUpd.Status != storage.AccessRequestStatusPending {
		t.Fatalf("after bob: status = %s want pending", bobUpd.Status)
	}

	carolUpd, err := h.requests.Approve(ctx, req.ID, "carol", "")
	if err != nil {
		t.Fatalf("carol Approve: %v", err)
	}
	if carolUpd.Status != storage.AccessRequestStatusApproved {
		t.Fatalf("after carol: status = %s want approved", carolUpd.Status)
	}
}

func TestReject_TransitionsToRejected_WithReason(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, _ := h.requests.Submit(ctx, samplePatch("alice"))
	updated, err := h.requests.Reject(ctx, req.ID, "bob", "missing change ticket")
	if err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if updated.Status != storage.AccessRequestStatusRejected {
		t.Fatalf("status = %s want rejected", updated.Status)
	}
	if updated.RejectReason != "missing change ticket" {
		t.Fatalf("reject_reason = %q", updated.RejectReason)
	}
}

func TestCancel_OnlyRequester(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, _ := h.requests.Submit(ctx, samplePatch("alice"))
	if _, err := h.requests.Cancel(ctx, req.ID, "mallory"); !errors.Is(err, services.ErrNotRequester) {
		t.Fatalf("non-requester cancel: got %v want ErrNotRequester", err)
	}
	updated, err := h.requests.Cancel(ctx, req.ID, "alice")
	if err != nil {
		t.Fatalf("alice Cancel: %v", err)
	}
	if updated.Status != storage.AccessRequestStatusCancelled {
		t.Fatalf("status = %s want cancelled", updated.Status)
	}
}

func TestApprove_RefreshesWrapTTL(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	// Seed default has 7d created → 1h approved. We assert that after
	// approval the wrap's expires_at is shorter than the created TTL
	// would suggest, i.e. ≤ now + 2h (comfortable upper bound for 1h).
	req, _ := h.requests.Submit(ctx, samplePatch("alice"))

	if _, err := h.requests.Approve(ctx, req.ID, "bob", ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	ids, _ := h.wrapsR.ListIDsForRequest(ctx, req.ID)
	if len(ids) == 0 {
		t.Fatal("no wraps found")
	}
	var expires time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT expires_at FROM secret_wraps WHERE id = $1`, ids[0]).Scan(&expires); err != nil {
		t.Fatalf("query: %v", err)
	}
	if expires.After(time.Now().Add(2 * time.Hour)) {
		t.Fatalf("expires_at = %v looks like the unrefreshed 7d TTL", expires)
	}
}

func TestSubmit_ValidatesRequiredFields(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	cases := []struct {
		name string
		in   func() services.PatchInput
	}{
		{"missing requester_id", func() services.PatchInput {
			p := samplePatch("alice")
			p.RequesterID = ""
			return p
		}},
		{"missing target_secret_ref", func() services.PatchInput {
			p := samplePatch("alice")
			p.TargetSecretRef = ""
			return p
		}},
		{"missing key_values", func() services.PatchInput {
			p := samplePatch("alice")
			p.KeyValues = nil
			return p
		}},
		{"missing justification", func() services.PatchInput {
			p := samplePatch("alice")
			p.Justification = ""
			return p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.requests.Submit(ctx, tc.in())
			if !errors.Is(err, services.ErrInvalidInput) {
				t.Fatalf("got %v want ErrInvalidInput", err)
			}
		})
	}
}

// --------- helpers ---------------------------------------------------

func newWorkflow(t *testing.T, ctx context.Context, h *requestHarness, name string, minApprovers int, allowSelf bool) *storage.WorkflowDefinition {
	t.Helper()
	wf := &storage.WorkflowDefinition{
		Name:                 name,
		MinApprovers:         minApprovers,
		AllowSelfApproval:    allowSelf,
		WrapTTLCreated:       24 * time.Hour,
		WrapTTLApproved:      time.Hour,
		WrapTTLClaimed:       5 * time.Minute,
		RequestTTL:           14 * 24 * time.Hour,
		RequireJustification: true,
		NotificationChannels: []string{},
		Enabled:              true,
	}
	if err := h.workflowsR.Create(ctx, wf); err != nil {
		t.Fatalf("workflow Create: %v", err)
	}
	return wf
}

func policyRule(t *testing.T, ctx context.Context, h *requestHarness, name string, wfID uuid.UUID, priority int) {
	t.Helper()
	if err := h.policiesR.Create(ctx, &storage.PolicyRule{
		Name:       name,
		Selector:   map[string]any{},
		WorkflowID: wfID,
		Priority:   priority,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("policy Create: %v", err)
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
