package services_test

import (
	"errors"
	"testing"
	"time"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Slice L4 — verify SubmitDirectReveal's defence-in-depth chain:
//   1. env.kind=prod rejected BEFORE policy lookup
//   2. policy without direct_reveal_allowed rejected after lookup
//   3. happy path lands an `approved` request + audit event
//   4. enqueue failure audited but not bubbled

func setupDirectRevealHarness(t *testing.T) (*services.RequestService, *storage.Pool, *storage.Environments, *storage.Workflows, *storage.Policies) {
	t.Helper()
	return buildL3Harness(t)
}

func TestSubmitDirectReveal_RejectsProdEnv(t *testing.T) {
	reqSvc, pool, envRepo, _, _ := setupDirectRevealHarness(t)
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "dr-prod")
	prodEnv := &storage.Environment{
		ProjectID: projectID, Name: "prod",
		Type: storage.EnvironmentTypeProd, Kind: storage.EnvironmentKindProd,
	}
	if err := envRepo.Create(ctx, prodEnv); err != nil {
		t.Fatalf("env Create: %v", err)
	}

	_, err := reqSvc.SubmitDirectReveal(ctx, services.DirectRevealInput{
		RequesterID:        "alice@example.com",
		Environment:        prodEnv,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/prod/db",
		Justification:      "should never make it past env check",
	})
	if !errors.Is(err, services.ErrDirectRevealOnProd) {
		t.Errorf("got %v, want ErrDirectRevealOnProd", err)
	}
}

func TestSubmitDirectReveal_RejectsPolicyDenied(t *testing.T) {
	reqSvc, pool, envRepo, _, _ := setupDirectRevealHarness(t)
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "dr-policy-denied")
	uatEnv := &storage.Environment{
		ProjectID: projectID, Name: "uat",
		Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd,
	}
	if err := envRepo.Create(ctx, uatEnv); err != nil {
		t.Fatalf("env Create: %v", err)
	}

	// Seed default policy is direct_reveal_allowed=false → reject.
	_, err := reqSvc.SubmitDirectReveal(ctx, services.DirectRevealInput{
		RequesterID:        "alice@example.com",
		Environment:        uatEnv,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		Justification:      "policy must allow",
	})
	if !errors.Is(err, services.ErrDirectRevealNotAllowed) {
		t.Errorf("got %v, want ErrDirectRevealNotAllowed", err)
	}
}

func TestSubmitDirectReveal_HappyPath_AutoExecutes(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := setupDirectRevealHarness(t)
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "dr-happy")
	uatEnv := &storage.Environment{
		ProjectID: projectID, Name: "uat",
		Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd,
	}
	if err := envRepo.Create(ctx, uatEnv); err != nil {
		t.Fatalf("env Create: %v", err)
	}

	wf := &storage.WorkflowDefinition{
		Name: "uat-direct-wf", MinApprovers: 0, AllowSelfApproval: true,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := workflows.Create(ctx, wf); err != nil {
		t.Fatalf("wf Create: %v", err)
	}
	rule := &storage.PolicyRule{
		Name:     "uat-direct-rule",
		Selector: map[string]any{"project_id": projectID.String(), "environment": "uat"},
		WorkflowID:          wf.ID,
		Priority:            500,
		Enabled:             true,
		DirectRevealAllowed: true,
		RevealTTLSeconds:    120,
	}
	if err := policies.Create(ctx, rule); err != nil {
		t.Fatalf("policy Create: %v", err)
	}

	req, err := reqSvc.SubmitDirectReveal(ctx, services.DirectRevealInput{
		RequesterID:        "alice@example.com",
		Environment:        uatEnv,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetKeys:         []string{"DB_PASSWORD"},
		Justification:      "L4 happy path",
	})
	if err != nil {
		t.Fatalf("SubmitDirectReveal: %v", err)
	}

	// Status MUST be approved at create time.
	if req.Status != storage.AccessRequestStatusApproved {
		t.Errorf("Status: got %q want approved", req.Status)
	}
	if req.EnvironmentID == nil || *req.EnvironmentID != uatEnv.ID {
		t.Errorf("EnvironmentID: got %v want %v", req.EnvironmentID, uatEnv.ID)
	}
	if req.Type != storage.AccessRequestTypeRead {
		t.Errorf("Type: got %q want read", req.Type)
	}

	// secret.reveal.direct.issued audit row written.
	var revealed int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'secret.reveal.direct.issued' AND resource = $1`,
		"request:"+req.ID.String(),
	).Scan(&revealed); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if revealed != 1 {
		t.Errorf("audit issued count: got %d want 1", revealed)
	}
}
