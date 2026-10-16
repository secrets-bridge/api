package services_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// An approved cross-team request writes to the destination provider
// connection. That connection's scope is {address, mount, ...}; the agent
// pins address/namespace from its own env and fails the job if they show
// up in the payload, which left every cross-team request `failed` with
// Vault untouched. The patch job must carry only kvMount/kvPrefix, both in
// sync_jobs and in what the agent gets from POST /agents/:id/jobs/claim.
func TestVerifyCrossTeam_PatchJobCarriesOnlyAgentProviderKeys(t *testing.T) {
	h := buildCrossTeamHarness(t)
	ctx := t.Context()
	// teams are not wiped between runs; a unique slug keeps reruns green.
	in := seedCrossTeamScope(t, h, "ct-agentcfg-"+uuid.NewString()[:8])

	// The real destination connection shape (scopeShapes: vault requires
	// address + mount; namespace and kvPrefix are optional).
	if _, err := h.pool.Exec(ctx,
		`UPDATE provider_connections SET scope = $2::jsonb WHERE id = $1`,
		in.DestinationProviderConnectionID,
		`{"address":"https://vault.example.com","mount":"secret","namespace":"team-alpha","kvPrefix":"team-alpha"}`,
	); err != nil {
		t.Fatalf("set connection scope: %v", err)
	}

	req, err := h.reqSvc.SubmitCrossTeam(ctx, in)
	if err != nil {
		t.Fatalf("SubmitCrossTeam: %v", err)
	}
	if _, err := h.reqSvc.Fill(ctx, services.FillCrossTeamInput{
		RequestID: req.ID, FillerID: "bob@example.com",
		KeyValues: map[string][]byte{"DB_PASSWORD": []byte("a"), "DB_USER": []byte("b")},
	}); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	if _, err := h.reqSvc.VerifyCrossTeam(ctx, services.VerifyCrossTeamInput{
		RequestID: req.ID, ApproverID: "carol@example.com",
		VotedAs: services.VotedAsSource, Decision: storage.ApprovalDecisionApprove,
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got, err := h.requestsR.Get(ctx, req.ID)
	if err != nil {
		t.Fatalf("Get request: %v", err)
	}
	if got.JobID == nil {
		t.Fatal("approved cross_team request has no job_id")
	}

	want := map[string]any{"kvMount": "secret", "kvPrefix": "team-alpha"}

	stored, err := h.jobsR.Get(ctx, *got.JobID)
	if err != nil {
		t.Fatalf("Get job: %v", err)
	}
	if cfg := stored.Payload["target_provider_config"]; !reflect.DeepEqual(cfg, want) {
		t.Errorf("stored target_provider_config = %v, want %v", cfg, want)
	}

	// Claim it the way the agent does: real AgentAuth + claim handler.
	auditRepo := storage.NewAuditEvents(h.pool)
	agentSvc := services.NewAgentService(storage.NewAgents(h.pool), auditRepo, nil)
	agent, err := agentSvc.Mint(ctx, services.MintInput{Name: "ct-agentcfg-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	app := fiber.New()
	app.Group("/api/v1/agents/:id", middleware.AgentAuth(agentSvc)).
		Post("/jobs/claim", handlers.NewJobs(services.NewJobService(h.jobsR, auditRepo)).Claim)

	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/agents/"+agent.ID.String()+"/jobs/claim", nil)
	httpReq.Header.Set("X-Agent-Secret", agent.AgentSecret)
	resp, err := app.Test(httpReq, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("claim status = %d, want 200", resp.StatusCode)
	}
	var claim struct {
		ID      string         `json:"id"`
		JobType string         `json:"job_type"`
		Payload map[string]any `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claim); err != nil {
		t.Fatalf("decode claim: %v", err)
	}
	if claim.ID != got.JobID.String() || claim.JobType != string(storage.JobTypePatch) {
		t.Fatalf("claimed %s/%s, want patch job %s", claim.JobType, claim.ID, got.JobID)
	}
	if cfg := claim.Payload["target_provider_config"]; !reflect.DeepEqual(cfg, want) {
		t.Errorf("claimed target_provider_config = %v, want %v", cfg, want)
	}
	if claim.Payload["target_secret_ref"] != in.DestinationSecretRef {
		t.Errorf("target_secret_ref = %v, want %s", claim.Payload["target_secret_ref"], in.DestinationSecretRef)
	}
	if wraps, ok := claim.Payload["wraps"].([]any); !ok || len(wraps) != 2 {
		t.Errorf("wraps = %v, want the 2 fill wraps", claim.Payload["wraps"])
	}
}
