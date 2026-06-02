package services_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Slice L3 — verify the env lookup path lands on AccessRequest.EnvironmentID
// AND that the PolicyEngine PROD invariant fires when the resolved
// environment is kind=prod. Without WithEnvironments wired, the back-compat
// path produces no env_id and the invariant cannot fire.

func buildL3Harness(t *testing.T) (*services.RequestService, *storage.Pool, *storage.Environments, *storage.Workflows, *storage.Policies) {
	t.Helper()
	engine, pool, policies, workflows := bootstrapPolicy(t)
	envRepo := storage.NewEnvironments(pool)

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

	reqSvc := services.NewRequestService(requestRepo, approvalRepo, wrapSvc, workflows, engine, auditRepo, jobSvc).
		WithEnvironments(envRepo)

	return reqSvc, pool, envRepo, workflows, policies
}

func makeProjectForSvc(t *testing.T, pool *storage.Pool, name string) uuid.UUID {
	t.Helper()
	repo := storage.NewProjects(pool)
	p := &storage.Project{Name: name}
	if err := repo.Create(t.Context(), p); err != nil {
		t.Fatalf("makeProjectForSvc %q: %v", name, err)
	}
	return p.ID
}

func TestSubmit_WithEnvironments_PopulatesEnvID(t *testing.T) {
	reqSvc, pool, envRepo, _, _ := buildL3Harness(t)
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "envwire-uat")
	env := &storage.Environment{
		ProjectID: projectID, Name: "uat",
		Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd,
	}
	if err := envRepo.Create(ctx, env); err != nil {
		t.Fatalf("env Create: %v", err)
	}

	req, err := reqSvc.Submit(ctx, services.PatchInput{
		RequesterID:        "alice@example.com",
		ProjectID:          projectID.String(),
		Environment:        "uat",
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		KeyValues:          map[string][]byte{"DB_PASSWORD": []byte("hunter2")},
		Justification:      "L3 envwire test",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if req.EnvironmentID == nil || *req.EnvironmentID != env.ID {
		t.Errorf("EnvironmentID on request: got %v want %v", req.EnvironmentID, env.ID)
	}
}

// Back-compat: no WithEnvironments wired → no env lookup → no env_id on the
// row, and the PolicyEngine invariant cannot fire because the scope's
// EnvironmentKind stays empty.
func TestSubmit_NoEnvironmentsRepo_BackCompat(t *testing.T) {
	engine, pool, _, _ := bootstrapPolicy(t)
	ctx := t.Context()

	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)
	km, _ := keymgmt.NewLocalKMS(masterKey)

	requestRepo := storage.NewAccessRequests(pool)
	approvalRepo := storage.NewApprovals(pool)
	auditRepo := storage.NewAuditEvents(pool)
	wrapRepo := storage.NewSecretWraps(pool)
	wrapSvc := services.NewWrapService(wrapRepo, auditRepo, km)
	jobsRepo := storage.NewSyncJobs(pool)
	jobSvc := services.NewJobService(jobsRepo, auditRepo)
	wfRepo := storage.NewWorkflows(pool)

	// NOTE: no WithEnvironments — the back-compat path.
	reqSvc := services.NewRequestService(requestRepo, approvalRepo, wrapSvc, wfRepo, engine, auditRepo, jobSvc)

	req, err := reqSvc.Submit(ctx, services.PatchInput{
		RequesterID:        "alice@example.com",
		ProjectID:          uuid.NewString(),
		Environment:        "uat",
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		KeyValues:          map[string][]byte{"DB_PASSWORD": []byte("hunter2")},
		Justification:      "L3 back-compat test",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if req.EnvironmentID != nil {
		t.Errorf("EnvironmentID: got %v want nil (back-compat path)", req.EnvironmentID)
	}
}

// PROD invariant: when the env is prod-kind and a matching rule has
// DirectRevealAllowed=true, the PolicyEngine zeroes the flag AND writes a
// `policy.invariant.violated` audit row. Submit's response doesn't carry
// the decision but the audit trail proves the engine fired correctly from
// the request hot path.
func TestSubmit_ProdEnv_FiresPolicyInvariant(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "envwire-prod")
	prodEnv := &storage.Environment{
		ProjectID: projectID, Name: "prod",
		Type: storage.EnvironmentTypeProd, Kind: storage.EnvironmentKindProd,
	}
	if err := envRepo.Create(ctx, prodEnv); err != nil {
		t.Fatalf("env Create: %v", err)
	}

	wf := &storage.WorkflowDefinition{
		Name: "envwire-prod-wf", MinApprovers: 1, AllowSelfApproval: true,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := workflows.Create(ctx, wf); err != nil {
		t.Fatalf("wf Create: %v", err)
	}
	rule := &storage.PolicyRule{
		Name: "envwire-prod-rule",
		Selector: map[string]any{
			"project_id":  projectID.String(),
			"environment": "prod",
		},
		WorkflowID: wf.ID, Priority: 500, Enabled: true,
		DirectRevealAllowed: true,
	}
	if err := policies.Create(ctx, rule); err != nil {
		t.Fatalf("policy Create: %v", err)
	}

	if _, err := reqSvc.Submit(ctx, services.PatchInput{
		RequesterID:        "alice@example.com",
		ProjectID:          projectID.String(),
		Environment:        "prod",
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/prod/db",
		KeyValues:          map[string][]byte{"DB_PASSWORD": []byte("hunter2")},
		Justification:      "L3 prod invariant test",
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'policy.invariant.violated' AND resource = $1`,
		"policy_rule:"+rule.ID.String(),
	).Scan(&count); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if count != 1 {
		t.Errorf("policy.invariant.violated audit rows: got %d want 1", count)
	}
}
