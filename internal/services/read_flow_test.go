package services_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// These tests cover the read-flow lifecycle:
//   - SubmitRead creates a read-type request without wraps
//   - Approve enqueues a read job (not a patch job)
//   - WrapByAgent creates wraps tied to the approved request
//   - RetrieveWrapForUser is single-shot + owner-gated + read-type-only

func sampleRead(requester string) services.ReadInput {
	return services.ReadInput{
		RequesterID:        requester,
		ProjectID:          "billing",
		Environment:        "prod",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/billing/prod/db",
		TargetKeys:         []string{"DB_PASSWORD"},
		Justification:      "Auditing key rotation hygiene",
	}
}

func TestSubmitRead_HappyPath_NoWrapsAtSubmit(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, err := h.requests.SubmitRead(ctx, sampleRead("alice"))
	if err != nil {
		t.Fatalf("SubmitRead: %v", err)
	}
	if req.Type != storage.AccessRequestTypeRead {
		t.Fatalf("type = %s want read", req.Type)
	}
	if req.Status != storage.AccessRequestStatusPending {
		t.Fatalf("status = %s want pending", req.Status)
	}

	// CRITICALLY: no wraps exist yet. They're created by the agent
	// post-approval, not at submit time.
	ids, _ := h.wrapsR.ListIDsForRequest(ctx, req.ID)
	if len(ids) != 0 {
		t.Fatalf("submit created wraps: %v — read flow must not", ids)
	}
}

func TestApproveRead_EnqueuesReadJob(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, _ := h.requests.SubmitRead(ctx, sampleRead("alice"))
	if _, err := h.requests.Approve(ctx, req.ID, "bob", ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	reloaded, _ := h.requests.Get(ctx, req.ID)
	if reloaded.JobID == nil {
		t.Fatal("Approve did not enqueue a job")
	}
	job, err := h.jobsR.Get(ctx, *reloaded.JobID)
	if err != nil {
		t.Fatalf("Get job: %v", err)
	}
	if job.JobType != storage.JobTypeRead {
		t.Fatalf("job_type = %s want read", job.JobType)
	}
	// Read job payload must NOT carry a wraps array — there are no
	// pre-existing wraps. The agent creates them post-fetch.
	if _, ok := job.Payload["wraps"]; ok {
		t.Fatal("read job payload should not carry wraps[]")
	}
	// But it must carry target_keys + target_secret_ref so the agent
	// knows what to fetch.
	if got, _ := job.Payload["target_secret_ref"].(string); got != "secret/data/billing/prod/db" {
		t.Fatalf("payload.target_secret_ref = %q", got)
	}
}

func TestWrapByAgent_HappyPath_TiedToRequest(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()
	req, _ := h.requests.SubmitRead(ctx, sampleRead("alice"))
	_, _ = h.requests.Approve(ctx, req.ID, "bob", "")
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())

	wrap, err := h.wraps.WrapByAgent(ctx, agent.ID, services.WrapRequest{
		Plaintext: []byte("hunter2-the-actual-value"),
		RequestID: &req.ID,
		KeyName:   "DB_PASSWORD",
		TTL:       30 * 60 * 1e9, // 30 min as time.Duration nanoseconds
	})
	if err != nil {
		t.Fatalf("WrapByAgent: %v", err)
	}
	if wrap.RequestID == nil || *wrap.RequestID != req.ID {
		t.Fatalf("wrap.RequestID = %v want %v", wrap.RequestID, req.ID)
	}
	if wrap.KeyName != "DB_PASSWORD" {
		t.Fatalf("wrap.KeyName = %q", wrap.KeyName)
	}
}

func TestRetrieveWrapForUser_HappyPath(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()
	req, _ := h.requests.SubmitRead(ctx, sampleRead("alice"))
	_, _ = h.requests.Approve(ctx, req.ID, "bob", "")
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())

	wrap, _ := h.wraps.WrapByAgent(ctx, agent.ID, services.WrapRequest{
		Plaintext: []byte("hunter2-the-actual-value"),
		RequestID: &req.ID,
		KeyName:   "DB_PASSWORD",
		TTL:       30 * 60 * 1e9,
	})

	plaintext, gotWrap, err := h.requests.RetrieveWrapForUser(ctx, req.ID, wrap.ID, "alice")
	if err != nil {
		t.Fatalf("RetrieveWrapForUser: %v", err)
	}
	if string(plaintext) != "hunter2-the-actual-value" {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if gotWrap.KeyName != "DB_PASSWORD" {
		t.Fatalf("KeyName = %q", gotWrap.KeyName)
	}
}

func TestRetrieveWrapForUser_NotRequester(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()
	req, _ := h.requests.SubmitRead(ctx, sampleRead("alice"))
	_, _ = h.requests.Approve(ctx, req.ID, "bob", "")
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())
	wrap, _ := h.wraps.WrapByAgent(ctx, agent.ID, services.WrapRequest{
		Plaintext: []byte("v"), RequestID: &req.ID, KeyName: "K", TTL: 30 * 60 * 1e9,
	})

	_, _, err := h.requests.RetrieveWrapForUser(ctx, req.ID, wrap.ID, "mallory")
	if !errors.Is(err, services.ErrNotRequestOwner) {
		t.Fatalf("got %v want ErrNotRequestOwner", err)
	}

	// Wrap must remain unconsumed when the owner check fails.
	got, _ := h.wrapsR.Get(ctx, wrap.ID)
	if got.ConsumedAt != nil {
		t.Fatal("wrap consumed despite ErrNotRequestOwner — should not have been")
	}
}

func TestRetrieveWrapForUser_PatchRequestRefused(t *testing.T) {
	// The user-bound endpoint must REFUSE to retrieve wraps that
	// belong to a patch request (those flow only through the agent
	// retrieval endpoint).
	h := bootstrapRequests(t)
	ctx := t.Context()
	req, _ := h.requests.Submit(ctx, samplePatch("alice"))
	_, _ = h.requests.Approve(ctx, req.ID, "bob", "")
	summaries, _ := h.requests.WrapSummariesForRequest(ctx, req.ID)

	_, _, err := h.requests.RetrieveWrapForUser(ctx, req.ID, summaries[0].ID, "alice")
	if !errors.Is(err, services.ErrWrongRequest) {
		t.Fatalf("got %v want ErrWrongRequest", err)
	}
}

func TestRetrieveWrapForUser_WrongRequestID(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()
	req1, _ := h.requests.SubmitRead(ctx, sampleRead("alice"))
	req2, _ := h.requests.SubmitRead(ctx, sampleRead("alice"))
	_, _ = h.requests.Approve(ctx, req1.ID, "bob", "")
	_, _ = h.requests.Approve(ctx, req2.ID, "bob", "")
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())
	wrap, _ := h.wraps.WrapByAgent(ctx, agent.ID, services.WrapRequest{
		Plaintext: []byte("v"), RequestID: &req1.ID, KeyName: "K", TTL: 30 * 60 * 1e9,
	})

	// User asks for the wrap claiming it belongs to req2 (the wrong
	// request). Service must refuse — defense against enumeration.
	_, _, err := h.requests.RetrieveWrapForUser(ctx, req2.ID, wrap.ID, "alice")
	if !errors.Is(err, services.ErrWrongRequest) {
		t.Fatalf("got %v want ErrWrongRequest", err)
	}
}

func TestRetrieveWrapForUser_AlreadyConsumed(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()
	req, _ := h.requests.SubmitRead(ctx, sampleRead("alice"))
	_, _ = h.requests.Approve(ctx, req.ID, "bob", "")
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())
	wrap, _ := h.wraps.WrapByAgent(ctx, agent.ID, services.WrapRequest{
		Plaintext: []byte("v"), RequestID: &req.ID, KeyName: "K", TTL: 30 * 60 * 1e9,
	})

	if _, _, err := h.requests.RetrieveWrapForUser(ctx, req.ID, wrap.ID, "alice"); err != nil {
		t.Fatalf("first retrieve: %v", err)
	}
	if _, _, err := h.requests.RetrieveWrapForUser(ctx, req.ID, wrap.ID, "alice"); !errors.Is(err, storage.ErrAlreadyConsumed) {
		t.Fatalf("second retrieve: got %v want ErrAlreadyConsumed", err)
	}
}

func TestRetrieveWrapForUser_NotFound(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()
	req, _ := h.requests.SubmitRead(ctx, sampleRead("alice"))
	_, _ = h.requests.Approve(ctx, req.ID, "bob", "")

	_, _, err := h.requests.RetrieveWrapForUser(ctx, req.ID, uuid.New(), "alice")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
}

func TestSubmitRead_ValidatesRequiredFields(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()
	cases := []struct {
		name string
		in   func() services.ReadInput
	}{
		{"missing requester", func() services.ReadInput {
			r := sampleRead("alice")
			r.RequesterID = ""
			return r
		}},
		{"missing secret ref", func() services.ReadInput {
			r := sampleRead("alice")
			r.TargetSecretRef = ""
			return r
		}},
		{"missing justification", func() services.ReadInput {
			r := sampleRead("alice")
			r.Justification = ""
			return r
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.requests.SubmitRead(ctx, tc.in())
			if !errors.Is(err, services.ErrInvalidInput) {
				t.Fatalf("got %v want ErrInvalidInput", err)
			}
		})
	}
}
