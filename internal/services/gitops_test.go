package services_test

// Integration tests for the GitOps observation service.
// Requires TEST_DATABASE_URL (Postgres). SKIPs otherwise.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapGitOps(t *testing.T) (*storage.Pool, *services.GitOpsService, *services.ArgoCDEndpointService, storage.GitOpsAppMappingRepository, storage.GitOpsObservationRepository, storage.AccessRequestRepository) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL is required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	const truncate = `
		TRUNCATE TABLE
			gitops_observations, gitops_app_mappings, argocd_endpoints,
			audit_events, sync_runs, sync_jobs, approvals,
			access_requests, secret_mappings, agents,
			provider_connections, environments, projects
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	// Clean up any non-system workflows / policies / roles left by
	// previous test runs — keeps the admin_test suite from tripping
	// on FK violations when it tries to wipe the same tables.
	if _, err := pool.Exec(ctx, `
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;
	`); err != nil {
		t.Fatalf("delete non-system rows: %v", err)
	}

	auditRepo := storage.NewAuditEvents(pool)
	endpointRepo := storage.NewArgoCDEndpoints(pool)
	mappingRepo := storage.NewGitOpsAppMappings(pool)
	obsRepo := storage.NewGitOpsObservations(pool)
	reqRepo := storage.NewAccessRequests(pool)

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	km, err := keymgmt.NewLocalKMS(masterKey)
	if err != nil {
		t.Fatalf("local kms: %v", err)
	}

	endpointSvc := services.NewArgoCDEndpointService(endpointRepo, km, auditRepo)
	gitopsSvc := services.NewGitOpsService(endpointRepo, mappingRepo, obsRepo, reqRepo, auditRepo, services.GitOpsConfig{ObservationTimeout: 30 * time.Minute})
	return pool, gitopsSvc, endpointSvc, mappingRepo, obsRepo, reqRepo
}

func TestArgoCDEndpointService_RoundTrip(t *testing.T) {
	_, _, endpointSvc, _, _, _ := bootstrapGitOps(t)
	ctx := context.Background()

	const plaintextToken = "the-actual-argocd-bearer-token-not-stored-in-db"
	e, err := endpointSvc.Create(ctx, services.CreateArgoCDEndpointInput{
		Name:    "prod-argocd",
		BaseURL: "https://argocd.example.com",
		Token:   []byte(plaintextToken),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(e.TokenCiphertext) == 0 || len(e.TokenDataKeyCiphertext) == 0 || len(e.TokenNonce) == 0 {
		t.Fatal("token envelope empty")
	}
	if e.TokenKMSKeyID == "" {
		t.Fatal("kms_key_id empty")
	}

	got, err := endpointSvc.Get(ctx, e.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	tok, err := endpointSvc.ResolveToken(ctx, got)
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if string(tok) != plaintextToken {
		t.Fatalf("token round-trip = %q want %q", tok, plaintextToken)
	}
}

func TestArgoCDEndpointService_TokenNotInRowJSON(t *testing.T) {
	// Defends the audit trail: scanning the row's exposed JSON
	// representation MUST NOT contain the plaintext.
	pool, _, endpointSvc, _, _, _ := bootstrapGitOps(t)
	ctx := context.Background()
	const canary = "ZZZ-canary-token-XXX-easy-to-grep"
	_, err := endpointSvc.Create(ctx, services.CreateArgoCDEndpointInput{
		Name:    "canary-test",
		BaseURL: "https://argocd.example.com",
		Token:   []byte(canary),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Scan ALL argocd_endpoints rows for the canary; should be zero.
	var hits int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM argocd_endpoints WHERE position($1::bytea in token_ciphertext) > 0`,
		canary,
	).Scan(&hits); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if hits != 0 {
		t.Fatalf("canary token found in token_ciphertext (%d hits) — encryption broken", hits)
	}
}

func TestGitOpsService_Start_NoMappings_AuditsSkip(t *testing.T) {
	pool, gitopsSvc, _, _, _, _ := bootstrapGitOps(t)
	ctx := context.Background()

	// We need a workflow for the access_requests CHECK constraint
	// even though the gitops Start path doesn't read it.
	var wfID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO workflow_definitions (name, min_approvers, wrap_ttl_created, wrap_ttl_approved, wrap_ttl_claimed, request_ttl) VALUES ('wf-' || gen_random_uuid()::text, 1, '1h'::interval, '1h'::interval, '5m'::interval, '1h'::interval) RETURNING id`,
	).Scan(&wfID); err != nil {
		t.Fatalf("workflow: %v", err)
	}

	// Insert a minimal access_request with NO secret_mapping_id —
	// triggers the "skipped: no mapping" path.
	req := &storage.AccessRequest{
		RequesterID:        "alice",
		Type:               storage.AccessRequestTypePatch,
		Status:             storage.AccessRequestStatusExecuted,
		Justification:      "test",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/x",
		TargetKeys:         []string{"K"},
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO access_requests (requester_id, type, status, justification, workflow_id, target_provider_type, target_secret_ref, target_keys)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id`,
		req.RequesterID, req.Type, req.Status, req.Justification, wfID, req.TargetProviderType, req.TargetSecretRef, req.TargetKeys,
	).Scan(&req.ID); err != nil {
		t.Fatalf("insert request: %v", err)
	}

	if err := gitopsSvc.Start(ctx, req); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Expect a "skipped" audit row.
	var action string
	if err := pool.QueryRow(ctx,
		`SELECT action FROM audit_events WHERE resource = $1 ORDER BY occurred_at DESC LIMIT 1`,
		"request:"+req.ID.String(),
	).Scan(&action); err != nil {
		t.Fatalf("scan audit: %v", err)
	}
	if action != "request.gitops_observation_skipped" {
		t.Fatalf("audit action = %q want request.gitops_observation_skipped", action)
	}
}

func TestGitOpsService_Start_CreatesObservationPerMapping(t *testing.T) {
	pool, gitopsSvc, endpointSvc, mappingRepo, obsRepo, _ := bootstrapGitOps(t)
	ctx := context.Background()

	// Bootstrap: project → environment → provider_connection → secret_mapping
	var projectID, envID, providerID, sourceProviderID, sourceMappingID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (name, owner_team_id) VALUES ('test', NULL) RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("project: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO environments (project_id, name, type) VALUES ($1, 'prod', 'prod') RETURNING id`,
		projectID,
	).Scan(&envID); err != nil {
		t.Fatalf("env: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO provider_connections (name, type, auth_method, scope) VALUES ('vault', 'vault', 'token', '{}'::jsonb) RETURNING id`).Scan(&providerID); err != nil {
		t.Fatalf("provider: %v", err)
	}
	sourceProviderID = providerID
	if err := pool.QueryRow(ctx,
		`INSERT INTO secret_mappings (source_provider_id, destination_provider_id, secret_ref, policy) VALUES ($1, $2, 'secret/data/x', '{}'::jsonb) RETURNING id`,
		sourceProviderID, providerID,
	).Scan(&sourceMappingID); err != nil {
		t.Fatalf("secret_mapping: %v", err)
	}

	// Endpoint + mapping
	ep, err := endpointSvc.Create(ctx, services.CreateArgoCDEndpointInput{
		Name:    "prod-argocd",
		BaseURL: "https://argocd.example.com",
		Token:   []byte("test-token"),
	})
	if err != nil {
		t.Fatalf("endpoint Create: %v", err)
	}
	for _, app := range []string{"billing-api", "billing-worker"} {
		mapping := &storage.GitOpsAppMapping{
			SecretMappingID:  &sourceMappingID,
			ArgoCDEndpointID: ep.ID,
			ApplicationName:  app,
			Enabled:          true,
		}
		if err := mappingRepo.Create(ctx, mapping); err != nil {
			t.Fatalf("mapping Create: %v", err)
		}
	}

	// Access request bound to the secret_mapping (needs workflow_id
	// for the CHECK constraint).
	var wfID uuid.UUID
	_ = pool.QueryRow(ctx,
		`INSERT INTO workflow_definitions (name, min_approvers, wrap_ttl_created, wrap_ttl_approved, wrap_ttl_claimed, request_ttl) VALUES ('wf-' || gen_random_uuid()::text, 1, '1h'::interval, '1h'::interval, '5m'::interval, '1h'::interval) RETURNING id`,
	).Scan(&wfID)
	var reqID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO access_requests (requester_id, type, status, justification, workflow_id, target_provider_type, target_secret_ref, target_keys, secret_mapping_id)
		 VALUES ('alice', 'patch', 'executed', 'test', $1, 'vault', 'secret/data/x', $2, $3)
		 RETURNING id`,
		wfID, []string{"K"}, sourceMappingID,
	).Scan(&reqID); err != nil {
		t.Fatalf("insert request: %v", err)
	}
	req := &storage.AccessRequest{ID: reqID, SecretMappingID: &sourceMappingID}

	if err := gitopsSvc.Start(ctx, req); err != nil {
		t.Fatalf("Start: %v", err)
	}

	rows, err := obsRepo.ListForRequest(ctx, reqID)
	if err != nil {
		t.Fatalf("ListForRequest: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("observations = %d want 2", len(rows))
	}
	apps := map[string]bool{}
	for _, r := range rows {
		apps[r.ApplicationName] = true
		if r.PollingState != storage.GitOpsStateQueued {
			t.Fatalf("polling_state = %q want queued", r.PollingState)
		}
		if r.TimeoutAt == nil {
			t.Fatal("timeout_at not set")
		}
	}
	if !apps["billing-api"] || !apps["billing-worker"] {
		t.Fatalf("apps = %v want both billing-api + billing-worker", apps)
	}
}

func TestGitOpsObservations_ClaimNextActive_TransitionsQueuedToActive(t *testing.T) {
	pool, _, endpointSvc, mappingRepo, obsRepo, _ := bootstrapGitOps(t)
	ctx := context.Background()

	// Build the minimum schema chain.
	var projectID, envID, providerID, mappingID uuid.UUID
	_ = pool.QueryRow(ctx, `INSERT INTO projects (name) VALUES ('p-' || gen_random_uuid()::text) RETURNING id`).Scan(&projectID)
	_ = pool.QueryRow(ctx, `INSERT INTO environments (project_id, name, type) VALUES ($1, 'prod', 'prod') RETURNING id`, projectID).Scan(&envID)
	_ = pool.QueryRow(ctx, `INSERT INTO provider_connections (name, type, auth_method, scope) VALUES ('v-' || gen_random_uuid()::text, 'vault', 'token', '{}'::jsonb) RETURNING id`).Scan(&providerID)
	_ = pool.QueryRow(ctx, `INSERT INTO secret_mappings (source_provider_id, destination_provider_id, secret_ref, policy) VALUES ($1, $1, 'x', '{}'::jsonb) RETURNING id`, providerID).Scan(&mappingID)

	ep, err := endpointSvc.Create(ctx, services.CreateArgoCDEndpointInput{Name: "e", BaseURL: "https://x", Token: []byte("t")})
	if err != nil {
		t.Fatalf("endpoint Create: %v", err)
	}
	mapping := &storage.GitOpsAppMapping{SecretMappingID: &mappingID, ArgoCDEndpointID: ep.ID, ApplicationName: "app1", Enabled: true}
	if err := mappingRepo.Create(ctx, mapping); err != nil {
		t.Fatalf("mapping Create: %v", err)
	}

	var wfID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO workflow_definitions (name, min_approvers, wrap_ttl_created, wrap_ttl_approved, wrap_ttl_claimed, request_ttl) VALUES ('w-' || gen_random_uuid()::text, 1, '1h'::interval, '1h'::interval, '5m'::interval, '1h'::interval) RETURNING id`).Scan(&wfID); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	var reqID uuid.UUID
	_ = pool.QueryRow(ctx,
		`INSERT INTO access_requests (requester_id, type, status, justification, workflow_id, target_provider_type, target_secret_ref, secret_mapping_id)
		 VALUES ('alice', 'patch', 'executed', 't', $1, 'vault', 'secret/data/x', $2) RETURNING id`,
		wfID, mappingID,
	).Scan(&reqID)

	// Insert a queued observation.
	o := &storage.GitOpsObservation{
		RequestID:        reqID,
		ArgoCDEndpointID: ep.ID,
		ApplicationName:  "app1",
		PollingState:     storage.GitOpsStateQueued,
	}
	if err := obsRepo.Create(ctx, o); err != nil {
		t.Fatalf("Create observation: %v", err)
	}

	claimed, err := obsRepo.ClaimNextActive(ctx, 5, uuid.New())
	if err != nil {
		t.Fatalf("ClaimNextActive: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed = %d want 1", len(claimed))
	}
	// Re-fetch and confirm state flipped to active.
	again, err := obsRepo.Get(ctx, claimed[0].ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if again.PollingState != storage.GitOpsStateActive {
		t.Fatalf("polling_state = %q want active", again.PollingState)
	}
}

func TestGitOpsObservations_Transition_Idempotent(t *testing.T) {
	pool, _, endpointSvc, mappingRepo, obsRepo, _ := bootstrapGitOps(t)
	ctx := context.Background()

	var projectID, envID, providerID, mappingID uuid.UUID
	_ = pool.QueryRow(ctx, `INSERT INTO projects (name) VALUES ('p-' || gen_random_uuid()::text) RETURNING id`).Scan(&projectID)
	_ = pool.QueryRow(ctx, `INSERT INTO environments (project_id, name, type) VALUES ($1, 'prod', 'prod') RETURNING id`, projectID).Scan(&envID)
	_ = pool.QueryRow(ctx, `INSERT INTO provider_connections (name, type, auth_method, scope) VALUES ('v-' || gen_random_uuid()::text, 'vault', 'token', '{}'::jsonb) RETURNING id`).Scan(&providerID)
	_ = pool.QueryRow(ctx, `INSERT INTO secret_mappings (source_provider_id, destination_provider_id, secret_ref, policy) VALUES ($1, $1, 'x', '{}'::jsonb) RETURNING id`, providerID).Scan(&mappingID)

	ep, _ := endpointSvc.Create(ctx, services.CreateArgoCDEndpointInput{Name: "e", BaseURL: "https://x", Token: []byte("t")})
	_ = mappingRepo.Create(ctx, &storage.GitOpsAppMapping{SecretMappingID: &mappingID, ArgoCDEndpointID: ep.ID, ApplicationName: "app", Enabled: true})

	var wfID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO workflow_definitions (name, min_approvers, wrap_ttl_created, wrap_ttl_approved, wrap_ttl_claimed, request_ttl) VALUES ('w-' || gen_random_uuid()::text, 1, '1h'::interval, '1h'::interval, '5m'::interval, '1h'::interval) RETURNING id`).Scan(&wfID); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	var reqID uuid.UUID
	_ = pool.QueryRow(ctx,
		`INSERT INTO access_requests (requester_id, type, status, justification, workflow_id, target_provider_type, target_secret_ref, secret_mapping_id)
		 VALUES ('alice', 'patch', 'executed', 't', $1, 'vault', 'secret/data/x', $2) RETURNING id`,
		wfID, mappingID,
	).Scan(&reqID)

	o := &storage.GitOpsObservation{RequestID: reqID, ArgoCDEndpointID: ep.ID, ApplicationName: "app", PollingState: storage.GitOpsStateActive}
	_ = obsRepo.Create(ctx, o)
	now := time.Now()
	if err := obsRepo.Transition(ctx, o.ID, storage.GitOpsStateApplied, now); err != nil {
		t.Fatalf("Transition 1: %v", err)
	}
	// Second transition is a no-op (already terminal).
	if err := obsRepo.Transition(ctx, o.ID, storage.GitOpsStateApplied, now.Add(time.Minute)); err != nil {
		t.Fatalf("Transition 2: %v", err)
	}
}
