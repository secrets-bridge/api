package services_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// These tests cover the Piece 4a back-edges:
//   - RequestService.Approve enqueues a patch job once the request
//     crosses the workflow's approver threshold
//   - JobService.Complete fires RequestService.OnJobCompleted, which
//     transitions the access_request to executed/failed

func TestApprove_EnqueuesPatchJob(t *testing.T) {
	h := bootstrapRequests(t)
	ctx := t.Context()

	req, err := h.requests.Submit(ctx, services.PatchInput{
		RequesterID:        "alice",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/billing/prod/db",
		KeyValues: map[string][]byte{
			"DB_PASSWORD": []byte("hunter2"),
			"DB_USER":     []byte("billing-svc"),
		},
		Justification: "rotation",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if _, err := h.requests.Approve(ctx, req.ID, "bob", ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Reload the request — job_id should be populated.
	reloaded, err := h.requests.Get(ctx, req.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reloaded.JobID == nil {
		t.Fatal("request.JobID is nil — approve did not enqueue a job")
	}

	job, err := h.jobsR.Get(ctx, *reloaded.JobID)
	if err != nil {
		t.Fatalf("Get job: %v", err)
	}
	if job.JobType != storage.JobTypePatch {
		t.Fatalf("job_type = %s want patch", job.JobType)
	}
	if job.Status != storage.JobStatusQueued {
		t.Fatalf("job.status = %s want queued", job.Status)
	}
	if job.CorrelationID != req.ID {
		t.Fatalf("correlation_id = %s want %s", job.CorrelationID, req.ID)
	}

	// Payload assertions.
	if got, _ := job.Payload["request_id"].(string); got != req.ID.String() {
		t.Fatalf("payload.request_id = %q want %q", got, req.ID)
	}
	if got, _ := job.Payload["target_provider_type"].(string); got != "vault" {
		t.Fatalf("payload.target_provider_type = %q want vault", got)
	}
	wraps, _ := job.Payload["wraps"].([]any)
	if len(wraps) != 2 {
		t.Fatalf("payload.wraps len = %d want 2", len(wraps))
	}
	// Every wrap entry must have wrap_id + key_name; never any value.
	for i, w := range wraps {
		m, ok := w.(map[string]any)
		if !ok {
			t.Fatalf("payload.wraps[%d] not a map: %T", i, w)
		}
		if _, ok := m["wrap_id"].(string); !ok {
			t.Fatalf("payload.wraps[%d].wrap_id missing or not string", i)
		}
		if _, ok := m["key_name"].(string); !ok {
			t.Fatalf("payload.wraps[%d].key_name missing or not string", i)
		}
		if _, leaked := m["value"]; leaked {
			t.Fatalf("payload.wraps[%d] leaks a value field!", i)
		}
	}
}

func TestComplete_PatchSucceeded_TransitionsRequestToExecuted(t *testing.T) {
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

	reloaded, _ := h.requests.Get(ctx, req.ID)
	if reloaded.JobID == nil {
		t.Fatal("no job_id after approve")
	}

	// Claim the job as the agent, then complete.
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())
	claimed, err := h.jobs.Claim(ctx, agent.ID)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if claimed.ID != *reloaded.JobID {
		t.Fatalf("claim returned a different job: %s vs %s", claimed.ID, *reloaded.JobID)
	}

	if err := h.jobs.Complete(ctx, agent.ID, services.CompleteRequest{
		JobID:  claimed.ID,
		Status: storage.JobStatusSucceeded,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	final, _ := h.requests.Get(ctx, req.ID)
	if final.Status != storage.AccessRequestStatusExecuted {
		t.Fatalf("request.status = %s want executed", final.Status)
	}
}

func TestComplete_PatchFailed_TransitionsRequestToFailed(t *testing.T) {
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

	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())
	claimed, err := h.jobs.Claim(ctx, agent.ID)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	if err := h.jobs.Complete(ctx, agent.ID, services.CompleteRequest{
		JobID:  claimed.ID,
		Status: storage.JobStatusFailed,
		Error:  "provider write rejected by CAS",
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	final, _ := h.requests.Get(ctx, req.ID)
	if final.Status != storage.AccessRequestStatusFailed {
		t.Fatalf("request.status = %s want failed", final.Status)
	}
}

func TestApprove_ThresholdNotCrossed_NoJobYet(t *testing.T) {
	// Verify: bob's vote on a 2-approver workflow does NOT enqueue a
	// job — the job only appears when carol's vote crosses the line.
	h := bootstrapRequests(t)
	ctx := t.Context()

	wf := newWorkflow(t, ctx, h, "two-approvers-"+t.Name(), 2, false)
	policyRule(t, ctx, h, "two-approvers-rule-"+t.Name(), wf.ID, 100)

	req, _ := h.requests.Submit(ctx, services.PatchInput{
		RequesterID:        "alice",
		TargetProviderType: "vault",
		TargetSecretRef:    "secret/data/foo",
		KeyValues:          map[string][]byte{"X": []byte("y")},
		Justification:      "j",
	})
	_, _ = h.requests.Approve(ctx, req.ID, "bob", "")

	reloaded, _ := h.requests.Get(ctx, req.ID)
	if reloaded.JobID != nil {
		t.Fatalf("job_id = %v want nil after only 1/2 approvers", reloaded.JobID)
	}
	if reloaded.Status != storage.AccessRequestStatusPending {
		t.Fatalf("status = %s want pending", reloaded.Status)
	}

	_, _ = h.requests.Approve(ctx, req.ID, "carol", "")

	final, _ := h.requests.Get(ctx, req.ID)
	if final.JobID == nil {
		t.Fatal("job_id still nil after threshold crossed")
	}
	if final.Status != storage.AccessRequestStatusApproved {
		t.Fatalf("status = %s want approved", final.Status)
	}
}

func TestComplete_NonPatchJob_DoesNotAffectRequests(t *testing.T) {
	// Sync/discover/verify/delete jobs must not muck with
	// access_request state. Smoke test by enqueueing a sync job
	// manually and asserting the hook is a no-op.
	h := bootstrapRequests(t)
	ctx := t.Context()

	// A bare sync job, no request attached.
	corrID := uuid.New()
	job, err := h.jobs.Enqueue(ctx, services.EnqueueRequest{
		JobType:       storage.JobTypeSync,
		AgentScope:    map[string]any{},
		Payload:       map[string]any{"hello": "world"},
		CorrelationID: corrID,
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	agent, _ := bootstrapAgent(t, h, "agent-"+t.Name())
	if _, err := h.jobs.Claim(ctx, agent.ID); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := h.jobs.Complete(ctx, agent.ID, services.CompleteRequest{
		JobID:  job.ID,
		Status: storage.JobStatusSucceeded,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// Nothing to assert beyond "doesn't panic" — the hook returns
	// early for non-patch job types.
}
