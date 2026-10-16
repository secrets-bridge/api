package handlers_test

// Agent job payloads carry only the provider keys the agent accepts.
//
// Since agent#20 the agent pins its connection (vault address/namespace/
// auth, aws region/roleArn/endpoint) from its own env and fails any job
// whose target_provider_config carries one of those keys. These tests
// drive the real stack (discover-now handler with the real JobService,
// AgentAuth + the agent claim handler, Postgres + Redis) and check what
// an agent actually receives on POST /agents/:id/jobs/claim:
//
//   - a discover job from discover-now on a vault connection
//     ({address, mount, ...}) is stored and served as {kvMount, kvPrefix}
//   - jobs written before the fix (worker scheduler, cross-team patch)
//     still carry the raw scope in Postgres and are translated on claim
//   - aws-sm keeps only tagFilter
//   - a payload already in agent format passes through unchanged
//   - unknown keys are dropped

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

type agentClaimHarness struct {
	app    *fiber.App
	pool   *storage.Pool
	jobs   *storage.SyncJobs
	agents *services.AgentService
}

func bootstrapAgentClaim(t *testing.T) *agentClaimHarness {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbDSN == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL required; skipping")
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

	const wipe = `
		TRUNCATE TABLE
			audit_events, sync_runs, sync_jobs, approvals,
			access_requests, secret_mappings, agents,
			provider_connections, environments, projects
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}

	rdb, err := runtime.Open(ctx, runtime.Config{
		URL:       redisURL,
		PoolSize:  4,
		Namespace: "sb-claimcfg-test-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("Open runtime: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	auditRepo := storage.NewAuditEvents(pool)
	jobsRepo := storage.NewSyncJobs(pool)
	jobSvc := services.NewJobService(jobsRepo, auditRepo)
	agentSvc := services.NewAgentService(storage.NewAgents(pool), auditRepo, rdb)
	pcSvc := services.NewProviderConnections(
		storage.NewProviderConnections(pool),
		storage.NewProjectProviderConnections(pool),
		auditRepo,
	)

	resolver := &stubResolver{}
	pcH := handlers.NewProviderConnections(pcSvc, jobSvc, rdb, resolver, envLookup{pool: pool})
	jobsH := handlers.NewJobs(jobSvc)

	app := fiber.New()
	app.Use(testAuthMW)
	v1 := app.Group("/api/v1")
	// Same chains as cmd/api/main.go.
	v1.Post("/provider-connections", auth.Require(auth.PermIntegrationEdit, resolver), pcH.Create)
	v1.Post("/provider-connections/:id/discover-now", auth.Require(auth.PermIntegrationEdit, resolver), pcH.DiscoverNow)
	agentRoutes := v1.Group("/agents/:id", middleware.AgentAuth(agentSvc))
	agentRoutes.Post("/jobs/claim", jobsH.Claim)

	t.Cleanup(func() { resolver.grants = nil })
	currentResolver = resolver
	return &agentClaimHarness{app: app, pool: pool, jobs: jobsRepo, agents: agentSvc}
}

// claim mints a fresh agent and claims the next job over HTTP, returning
// the decoded claim response.
func (h *agentClaimHarness) claim(t *testing.T) map[string]any {
	t.Helper()
	agent, err := h.agents.Mint(t.Context(), services.MintInput{Name: "claim-test-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/"+agent.ID.String()+"/jobs/claim", nil)
	req.Header.Set("X-Agent-Secret", agent.AgentSecret)
	resp, err := h.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("claim status = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode claim: %v", err)
	}
	return out
}

// enqueueRaw stores a job exactly as an older producer (worker scheduler,
// pre-fix api) wrote it, bypassing every api translation.
func (h *agentClaimHarness) enqueueRaw(t *testing.T, jobType storage.JobType, payload map[string]any) uuid.UUID {
	t.Helper()
	if _, err := h.pool.Exec(t.Context(), `DELETE FROM sync_jobs`); err != nil {
		t.Fatalf("clear jobs: %v", err)
	}
	job := &storage.SyncJob{JobType: jobType, Payload: payload}
	if err := h.jobs.Create(t.Context(), job); err != nil {
		t.Fatalf("Create job: %v", err)
	}
	return job.ID
}

// roundTrip gives the JSON shape an agent decodes, so expectations
// compare like with like ([]any, map[string]any, float64).
func roundTrip(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func claimedConfig(t *testing.T, claim map[string]any) map[string]any {
	t.Helper()
	payload, ok := claim["payload"].(map[string]any)
	if !ok {
		t.Fatalf("claim payload missing: %v", claim)
	}
	cfg, ok := payload["target_provider_config"].(map[string]any)
	if !ok {
		t.Fatalf("target_provider_config missing or not an object: %v", payload["target_provider_config"])
	}
	return cfg
}

func TestAgentClaim_DiscoverNowVaultScope_OnlyAgentKeys(t *testing.T) {
	h := bootstrapAgentClaim(t)
	grantIntegrationEdit()

	body := validVaultCreateBody()
	body["scope"] = map[string]string{
		"address":   "https://vault.example.com",
		"mount":     "secret",
		"namespace": "team-alpha",
		"kvPrefix":  "team-alpha/uat",
	}
	body["cluster_name"] = "tenant-a-uat"
	body["discover_enabled"] = true
	resp, raw := doPCJSON(t, h.app, http.MethodPost, "/api/v1/provider-connections", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create connection: %d body=%s", resp.StatusCode, raw)
	}
	connID := decodeEnvelope(t, raw)["id"].(string)

	resp, raw = doPCJSON(t, h.app, http.MethodPost, "/api/v1/provider-connections/"+connID+"/discover-now", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("discover-now: %d body=%s", resp.StatusCode, raw)
	}
	jobID, err := uuid.Parse(decodeEnvelope(t, raw)["job_id"].(string))
	if err != nil {
		t.Fatalf("job_id: %v", err)
	}

	want := map[string]any{"kvMount": "secret", "kvPrefix": "team-alpha/uat"}

	// Stored payload is clean too (enqueue-time translation).
	stored, err := h.jobs.Get(t.Context(), jobID)
	if err != nil {
		t.Fatalf("Get job: %v", err)
	}
	if got := stored.Payload["target_provider_config"]; !reflect.DeepEqual(got, want) {
		t.Errorf("stored target_provider_config = %v, want %v", got, want)
	}

	claim := h.claim(t)
	if claim["id"] != jobID.String() {
		t.Fatalf("claimed job %v, want %s", claim["id"], jobID)
	}
	if got := claimedConfig(t, claim); !reflect.DeepEqual(got, want) {
		t.Errorf("claimed target_provider_config = %v, want %v", got, want)
	}
	payload := claim["payload"].(map[string]any)
	if payload["connection_id"] != connID || payload["target_provider_type"] != "vault" || payload["cluster_name"] != "tenant-a-uat" {
		t.Errorf("discover payload fields changed: %v", payload)
	}
}

func TestAgentClaim_DiscoverNowAWSScope_NoSteeringKeys(t *testing.T) {
	h := bootstrapAgentClaim(t)
	grantIntegrationEdit()

	body := map[string]any{
		"name":        "aws-claim-test",
		"type":        "aws-sm",
		"auth_method": "assume_role",
		"scope": map[string]string{
			"region":  "us-east-1",
			"roleArn": "arn:aws:iam::123456789012:role/sb-agent",
		},
		"cluster_name":              "tenant-a-uat",
		"discover_enabled":          true,
		"discover_interval_seconds": 300,
	}
	resp, raw := doPCJSON(t, h.app, http.MethodPost, "/api/v1/provider-connections", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create connection: %d body=%s", resp.StatusCode, raw)
	}
	connID := decodeEnvelope(t, raw)["id"].(string)
	resp, raw = doPCJSON(t, h.app, http.MethodPost, "/api/v1/provider-connections/"+connID+"/discover-now", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("discover-now: %d body=%s", resp.StatusCode, raw)
	}
	jobID, err := uuid.Parse(decodeEnvelope(t, raw)["job_id"].(string))
	if err != nil {
		t.Fatalf("job_id: %v", err)
	}
	stored, err := h.jobs.Get(t.Context(), jobID)
	if err != nil {
		t.Fatalf("Get job: %v", err)
	}
	if got := stored.Payload["target_provider_config"]; !reflect.DeepEqual(got, map[string]any{}) {
		t.Errorf("stored aws target_provider_config = %v, want {}", got)
	}

	if got := claimedConfig(t, h.claim(t)); len(got) != 0 {
		t.Errorf("claimed aws target_provider_config = %v, want {} (region/roleArn are pinned on the agent)", got)
	}
}

// Jobs already in Postgres when the fix ships, or written by the worker's
// discover scheduler (which copies the connection scope raw), are
// translated when an agent claims them.
func TestAgentClaim_StoredRawPayloads_TranslatedOnClaim(t *testing.T) {
	h := bootstrapAgentClaim(t)

	requestID := uuid.NewString()
	wrapID := uuid.NewString()
	tagFilter := map[string]any{"EnvironmentName": "tenant-a-uat"}

	cases := []struct {
		name       string
		jobType    storage.JobType
		payload    map[string]any
		wantConfig map[string]any
	}{
		{
			name:    "worker discover job with vault scope",
			jobType: storage.JobTypeDiscover,
			payload: map[string]any{
				"connection_id":          uuid.NewString(),
				"target_provider_type":   "vault",
				"target_provider_config": map[string]any{"address": "https://vault.example.com", "mount": "secret"},
				"cluster_name":           "tenant-a-uat",
			},
			wantConfig: map[string]any{"kvMount": "secret"},
		},
		{
			name:    "cross-team patch job with vault scope",
			jobType: storage.JobTypePatch,
			payload: map[string]any{
				"request_id":             requestID,
				"target_provider_type":   "vault",
				"target_provider_config": map[string]any{"address": "https://vault.example.com", "mount": "secret"},
				"target_secret_ref":      "team-alpha/uat/db",
				"target_keys":            []any{"DB_PASSWORD"},
				"target_scope":           map[string]any{},
				"wraps":                  []any{map[string]any{"wrap_id": wrapID, "key_name": "DB_PASSWORD"}},
			},
			wantConfig: map[string]any{"kvMount": "secret"},
		},
		{
			name:    "aws scope keeps only tagFilter",
			jobType: storage.JobTypeDiscover,
			payload: map[string]any{
				"target_provider_type": "aws-sm",
				"target_provider_config": map[string]any{
					"region":    "us-east-1",
					"roleArn":   "arn:aws:iam::123456789012:role/sb-agent",
					"endpoint":  "https://secretsmanager.example.com",
					"tagFilter": tagFilter,
				},
				"cluster_name": "tenant-a-uat",
			},
			wantConfig: map[string]any{"tagFilter": tagFilter},
		},
		{
			name:    "unknown and credential keys are dropped",
			jobType: storage.JobTypeDiscover,
			payload: map[string]any{
				"target_provider_type": "vault",
				"target_provider_config": map[string]any{
					"kvMount":             "secret",
					"authMethod":          "token",
					"token":               "not-a-real-token",
					"kubernetesTokenPath": "/etc/passwd",
					"somethingNew":        "x",
				},
				"cluster_name": "tenant-a-uat",
			},
			wantConfig: map[string]any{"kvMount": "secret"},
		},
		{
			name:    "provider type the agent has no resolver for gets an empty config",
			jobType: storage.JobTypeDiscover,
			payload: map[string]any{
				"target_provider_type":   "gcp-sm",
				"target_provider_config": map[string]any{"projectID": "tenant-a-uat"},
				"cluster_name":           "tenant-a-uat",
			},
			wantConfig: map[string]any{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jobID := h.enqueueRaw(t, tc.jobType, tc.payload)
			claim := h.claim(t)
			if claim["id"] != jobID.String() {
				t.Fatalf("claimed job %v, want %s", claim["id"], jobID)
			}
			if got := claimedConfig(t, claim); !reflect.DeepEqual(got, tc.wantConfig) {
				t.Errorf("claimed target_provider_config = %v, want %v", got, tc.wantConfig)
			}
			// Every other payload field reaches the agent untouched.
			wantRest := roundTrip(t, tc.payload).(map[string]any)
			gotRest := claim["payload"].(map[string]any)
			delete(wantRest, "target_provider_config")
			gotCopy := make(map[string]any, len(gotRest))
			for k, v := range gotRest {
				if k != "target_provider_config" {
					gotCopy[k] = v
				}
			}
			if !reflect.DeepEqual(gotCopy, wantRest) {
				t.Errorf("other payload fields changed:\n got %v\nwant %v", gotCopy, wantRest)
			}
		})
	}
}

func TestAgentClaim_AgentFormatPayload_PassesUnchanged(t *testing.T) {
	h := bootstrapAgentClaim(t)

	cases := map[string]map[string]any{
		"vault read job": {
			"request_id":             uuid.NewString(),
			"target_provider_type":   "vault",
			"target_provider_config": map[string]any{"kvMount": "secret", "kvPrefix": "team-alpha"},
			"target_secret_ref":      "team-alpha/uat/db",
			"target_keys":            []any{"DB_PASSWORD", "DB_USER"},
			"target_scope":           map[string]any{"project_id": uuid.NewString()},
		},
		"aws discover job": {
			"target_provider_type":   "aws-sm",
			"target_provider_config": map[string]any{"tagFilter": map[string]any{"EnvironmentName": "tenant-a-uat"}},
			"label_selector":         map[string]any{"team": "alpha"},
		},
		"empty config": {
			"target_provider_type":   "vault",
			"target_provider_config": map[string]any{},
			"target_secret_ref":      "team-alpha/uat/db",
		},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			h.enqueueRaw(t, storage.JobTypeRead, payload)
			got := h.claim(t)["payload"]
			if want := roundTrip(t, payload); !reflect.DeepEqual(got, want) {
				t.Errorf("payload changed on claim:\n got %v\nwant %v", got, want)
			}
		})
	}
}
