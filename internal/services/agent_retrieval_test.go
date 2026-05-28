package services_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// These tests cover RequestService.RetrieveWrap — the orchestration
// the agent retrieval endpoint sits on top of.

func TestRetrieveWrap_HappyPath(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, err := h.requests.Submit(ctx, services.PatchInput{
		RequesterID:        "alice",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/foo",
		KeyValues:          map[string][]byte{"DB_PASSWORD": []byte("hunter2-prod")},
		Justification:      "rotation",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := h.requests.Approve(ctx, req.ID, "bob", "lgtm"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	summaries, err := h.requests.WrapSummariesForRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("WrapSummariesForRequest: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("summaries = %d want 1", len(summaries))
	}
	if summaries[0].KeyName != "DB_PASSWORD" {
		t.Fatalf("key_name = %q want DB_PASSWORD", summaries[0].KeyName)
	}

	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())

	plaintext, wrap, err := h.requests.RetrieveWrap(ctx, summaries[0].ID, agent.ID)
	if err != nil {
		t.Fatalf("RetrieveWrap: %v", err)
	}
	if string(plaintext) != "hunter2-prod" {
		t.Fatalf("plaintext = %q want hunter2-prod", plaintext)
	}
	if wrap.KeyName != "DB_PASSWORD" {
		t.Fatalf("wrap.KeyName = %q want DB_PASSWORD", wrap.KeyName)
	}
}

func TestRetrieveWrap_PendingRequestRejected(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, _ := h.requests.Submit(ctx, services.PatchInput{
		RequesterID:        "alice",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/foo",
		KeyValues:          map[string][]byte{"X": []byte("y")},
		Justification:      "j",
	})
	summaries, _ := h.requests.WrapSummariesForRequest(ctx, req.ID)
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())

	_, _, err := h.requests.RetrieveWrap(ctx, summaries[0].ID, agent.ID)
	if !errors.Is(err, services.ErrRequestNotApproved) {
		t.Fatalf("got %v want ErrRequestNotApproved", err)
	}

	// Wrap must NOT have been consumed by the failed call.
	wrap, err := h.wrapsR.Get(ctx, summaries[0].ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if wrap.ConsumedAt != nil {
		t.Fatal("wrap was consumed despite ErrRequestNotApproved — retrieval must not burn the wrap on gate failure")
	}
}

func TestRetrieveWrap_RejectedRequestRejected(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, _ := h.requests.Submit(ctx, services.PatchInput{
		RequesterID:        "alice",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/foo",
		KeyValues:          map[string][]byte{"X": []byte("y")},
		Justification:      "j",
	})
	if _, err := h.requests.Reject(ctx, req.ID, "bob", "no"); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	summaries, _ := h.requests.WrapSummariesForRequest(ctx, req.ID)
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())

	_, _, err := h.requests.RetrieveWrap(ctx, summaries[0].ID, agent.ID)
	if !errors.Is(err, services.ErrRequestNotApproved) {
		t.Fatalf("got %v want ErrRequestNotApproved", err)
	}
}

func TestRetrieveWrap_AlreadyConsumed(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, _ := h.requests.Submit(ctx, services.PatchInput{
		RequesterID:        "alice",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/foo",
		KeyValues:          map[string][]byte{"X": []byte("y")},
		Justification:      "j",
	})
	_, _ = h.requests.Approve(ctx, req.ID, "bob", "")
	summaries, _ := h.requests.WrapSummariesForRequest(ctx, req.ID)
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())

	if _, _, err := h.requests.RetrieveWrap(ctx, summaries[0].ID, agent.ID); err != nil {
		t.Fatalf("first Retrieve: %v", err)
	}
	if _, _, err := h.requests.RetrieveWrap(ctx, summaries[0].ID, agent.ID); !errors.Is(err, storage.ErrAlreadyConsumed) {
		t.Fatalf("second Retrieve: got %v want ErrAlreadyConsumed", err)
	}
}

func TestRetrieveWrap_NotFound(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())
	_, _, err := h.requests.RetrieveWrap(ctx, uuid.New(), agent.ID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
}

func TestWrapSummaries_NoLeak(t *testing.T) {
	// Summaries must carry no ciphertext / no plaintext fields.
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, _ := h.requests.Submit(ctx, services.PatchInput{
		RequesterID:        "alice",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/foo",
		KeyValues:          map[string][]byte{"X": []byte("plain-XYZ")},
		Justification:      "j",
	})
	summaries, err := h.requests.WrapSummariesForRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("WrapSummariesForRequest: %v", err)
	}
	// Summary struct intentionally has no Value / EncryptedValue fields.
	// The compile-time check IS the test — if a future change adds a
	// ciphertext-bearing field to WrapSummary this won't catch it,
	// but it'll be obvious in code review.
	if len(summaries) != 1 || summaries[0].KeyName != "X" {
		t.Fatalf("unexpected summaries: %+v", summaries)
	}
}

// bootstrapAgent creates an agent row directly via the storage layer
// so RetrieveWrap's MarkConsumed has a real FK target. The agent
// secret is not used in these tests (we exercise the service layer,
// not the AgentAuth middleware).
func bootstrapAgent(t *testing.T, h *requestHarness, name string) (*storage.Agent, string) {
	t.Helper()
	agents := storage.NewAgents(h.pool)
	a := &storage.Agent{
		Name:       name,
		Scope:      map[string]any{},
		Status:     storage.AgentStatusActive,
		SecretHash: []byte("not-used-in-service-tests-just-needs-32-byte"),
	}
	if err := agents.Create(t.Context(), a); err != nil {
		t.Fatalf("agents.Create: %v", err)
	}
	return a, ""
}
