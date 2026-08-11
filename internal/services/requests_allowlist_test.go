package services_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// These tests pin the project_secrets `allowed_keys` allowlist across
// the two plaintext-reveal boundaries:
//
//  1. Submit-time (SubmitDirectReveal) — a direct reveal must not name a
//     key outside the binding allowlist. Primary gate.
//  2. Unwrap-time (RevealSessionService.Open) — even if a request row
//     somehow carries an out-of-allowlist wrap, the bulk-reveal session
//     refuses to bundle it. Defense-in-depth second boundary.
//
// Before this fix the direct-reveal path never consulted the binding at
// all: a request for a denied key returned 201 approved.

// bindSecretWithAllowedKeys upserts a catalog row for (vault, secretRef)
// and binds it to projectID with the given allowed_keys allowlist. A nil
// allowedKeys means "all keys"; a non-empty slice is a restrictive
// allowlist. The catalog cluster is a throwaway — ListByRef matches on
// (provider_type, secret_ref) across every cluster.
func bindSecretWithAllowedKeys(t *testing.T, pool *storage.Pool, projectID uuid.UUID, secretRef string, allowedKeys []string) {
	t.Helper()
	ctx := t.Context()
	secretsRepo := storage.NewSecrets(pool)
	sec := &storage.Secret{
		ClusterName:  "allowlist-test-cluster",
		ProviderType: "vault",
		SecretRef:    secretRef,
		Status:       "present",
	}
	if err := secretsRepo.Upsert(ctx, sec); err != nil {
		t.Fatalf("secret Upsert: %v", err)
	}
	bindings := storage.NewProjectSecrets(pool)
	b := &storage.ProjectSecret{
		ProjectID:   projectID,
		SecretID:    sec.ID,
		AllowedKeys: allowedKeys,
		AllowedOps:  []string{storage.OpRead},
		CreatedBy:   "allowlist-test",
	}
	if err := bindings.Bind(ctx, b); err != nil {
		t.Fatalf("binding Bind: %v", err)
	}
}

// seedDirectRevealRule creates a workflow + a matching policy rule with
// DirectRevealAllowed=true so SubmitDirectReveal reaches the allowlist
// gate (past the env-kind + policy gates).
func seedDirectRevealRule(t *testing.T, pool *storage.Pool, workflows *storage.Workflows, policies *storage.Policies, projectID uuid.UUID) {
	t.Helper()
	ctx := t.Context()
	suffix := projectID.String()[:8]
	wf := &storage.WorkflowDefinition{
		Name: "dr-allowlist-wf-" + suffix, MinApprovers: 0, AllowSelfApproval: true,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := workflows.Create(ctx, wf); err != nil {
		t.Fatalf("wf Create: %v", err)
	}
	rule := &storage.PolicyRule{
		Name:                "dr-allowlist-rule-" + suffix,
		Selector:            map[string]any{"project_id": projectID.String(), "environment": "uat"},
		WorkflowID:          wf.ID,
		Priority:            500,
		Enabled:             true,
		DirectRevealAllowed: true,
		RevealTTLSeconds:    120,
	}
	if err := policies.Create(ctx, rule); err != nil {
		t.Fatalf("policy Create: %v", err)
	}
}

func newUATEnv(t *testing.T, envRepo *storage.Environments, projectID uuid.UUID) *storage.Environment {
	t.Helper()
	env := &storage.Environment{
		ProjectID: projectID, Name: "uat",
		Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd,
	}
	if err := envRepo.Create(t.Context(), env); err != nil {
		t.Fatalf("env Create: %v", err)
	}
	return env
}

// --- Boundary 1: submit-time -----------------------------------------

func TestSubmitDirectReveal_DeniedKeyRefusedByAllowlist(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	reqSvc.WithProjectBindings(storage.NewProjectSecrets(pool), storage.NewSecrets(pool))
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "dr-allowlist-denied")
	env := newUATEnv(t, envRepo, projectID)
	seedDirectRevealRule(t, pool, workflows, policies, projectID)
	bindSecretWithAllowedKeys(t, pool, projectID, "billing/uat/db", []string{"QA_PROBE"})

	_, err := reqSvc.SubmitDirectReveal(ctx, services.DirectRevealInput{
		RequesterID:        "alice-denied@example.com",
		Environment:        env,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetKeys:         []string{"NOT_ALLOWED_KEY"},
		Justification:      "denied key must be refused before approval",
	})
	if !errors.Is(err, services.ErrKeyNotAllowed) {
		t.Fatalf("got %v, want ErrKeyNotAllowed", err)
	}

	// The request must NOT have been created — refusal happens before
	// the row is written.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM access_requests WHERE requester_id = $1`, "alice-denied@example.com",
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("access_requests rows created despite denied key: %d", count)
	}
}

func TestSubmitDirectReveal_AllowedKeyPasses(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	reqSvc.WithProjectBindings(storage.NewProjectSecrets(pool), storage.NewSecrets(pool))
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "dr-allowlist-ok")
	env := newUATEnv(t, envRepo, projectID)
	seedDirectRevealRule(t, pool, workflows, policies, projectID)
	bindSecretWithAllowedKeys(t, pool, projectID, "billing/uat/db", []string{"QA_PROBE"})

	req, err := reqSvc.SubmitDirectReveal(ctx, services.DirectRevealInput{
		RequesterID:        "alice-ok@example.com",
		Environment:        env,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetKeys:         []string{"QA_PROBE"},
		Justification:      "allowed key must pass",
	})
	if err != nil {
		t.Fatalf("SubmitDirectReveal: %v", err)
	}
	if req.Status != storage.AccessRequestStatusApproved {
		t.Errorf("Status: got %q want approved", req.Status)
	}
}

func TestSubmitDirectReveal_EmptyKeysWithRestrictiveAllowlistRefused(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	reqSvc.WithProjectBindings(storage.NewProjectSecrets(pool), storage.NewSecrets(pool))
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "dr-allowlist-empty")
	env := newUATEnv(t, envRepo, projectID)
	seedDirectRevealRule(t, pool, workflows, policies, projectID)
	bindSecretWithAllowedKeys(t, pool, projectID, "billing/uat/db", []string{"QA_PROBE"})

	// Empty target_keys against a restrictive allowlist means "reveal
	// every key" — a bypass. Must be refused.
	_, err := reqSvc.SubmitDirectReveal(ctx, services.DirectRevealInput{
		RequesterID:        "alice-empty@example.com",
		Environment:        env,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		Justification:      "empty keys against a restrictive allowlist must be refused",
	})
	if !errors.Is(err, services.ErrKeyNotAllowed) {
		t.Fatalf("got %v, want ErrKeyNotAllowed", err)
	}
}

func TestSubmitDirectReveal_NoBinding_PolicyOnlyPathUnchanged(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	reqSvc.WithProjectBindings(storage.NewProjectSecrets(pool), storage.NewSecrets(pool))
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "dr-allowlist-nobind")
	env := newUATEnv(t, envRepo, projectID)
	seedDirectRevealRule(t, pool, workflows, policies, projectID)
	// No binding created — the allowlist lives on the binding and there
	// is none, so the policy-only direct-reveal path is unchanged.

	req, err := reqSvc.SubmitDirectReveal(ctx, services.DirectRevealInput{
		RequesterID:        "alice-nobind@example.com",
		Environment:        env,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetKeys:         []string{"ANY_KEY"},
		Justification:      "no binding => policy-only path still works",
	})
	if err != nil {
		t.Fatalf("SubmitDirectReveal (no binding): %v", err)
	}
	if req.Status != storage.AccessRequestStatusApproved {
		t.Errorf("Status: got %q want approved", req.Status)
	}
}

// --- Boundary 2: unwrap-time (reveal session) ------------------------

func TestOpen_RefusesWrapOutsideAllowlist(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	// The reveal harness's request service has NO allowlist gate wired,
	// so a wrap for an out-of-allowlist key can exist — exactly the
	// tampered/legacy-row scenario the second boundary defends against.
	env := seedUATEnvWithRule(t, h, "rs-allowlist-deny", 60)
	req := submitDirectRevealRequest(t, h, env, "alice", "SNEAKY_KEY")

	bindSecretWithAllowedKeys(t, h.pool, env.ProjectID, "billing/uat/db", []string{"QA_PROBE"})
	h.revealSvc.WithAllowlist(storage.NewProjectSecrets(h.pool), storage.NewSecrets(h.pool))

	_, err := h.revealSvc.Open(ctx, services.OpenInput{UserID: "alice", RequestID: req.ID})
	if !errors.Is(err, services.ErrKeyNotAllowed) {
		t.Fatalf("got %v, want ErrKeyNotAllowed", err)
	}

	var count int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM reveal_sessions WHERE access_request_id = $1`, req.ID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("reveal_sessions rows created despite out-of-allowlist wrap: %d", count)
	}
}

func TestOpen_AllowsWrapWithinAllowlist(t *testing.T) {
	h := buildRevealHarness(t)
	ctx := t.Context()

	env := seedUATEnvWithRule(t, h, "rs-allowlist-ok", 60)
	req := submitDirectRevealRequest(t, h, env, "alice", "QA_PROBE")

	bindSecretWithAllowedKeys(t, h.pool, env.ProjectID, "billing/uat/db", []string{"QA_PROBE"})
	h.revealSvc.WithAllowlist(storage.NewProjectSecrets(h.pool), storage.NewSecrets(h.pool))

	resp, err := h.revealSvc.Open(ctx, services.OpenInput{UserID: "alice", RequestID: req.ID})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(resp.Wraps) != 1 {
		t.Fatalf("wraps = %d want 1", len(resp.Wraps))
	}
}
