package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// JobService owns the admin-enqueue and agent claim/complete flows.
// JobCompletedHook is fired AFTER a job's terminal Complete succeeds.
// It receives the freshly loaded job row so the hook can branch on
// job_type. The hook runs synchronously inside Complete; errors are
// surfaced to telemetry via the hook's own audit emission — the
// completion itself is durable regardless.
type JobCompletedHook func(ctx context.Context, job *storage.SyncJob)

type JobService struct {
	jobs        storage.SyncJobRepository
	audit       storage.AuditEventRepository
	claimLease  time.Duration
	onCompleted JobCompletedHook
}

// NewJobService binds a JobService to its repositories.
func NewJobService(jobs storage.SyncJobRepository, audit storage.AuditEventRepository) *JobService {
	return &JobService{
		jobs:       jobs,
		audit:      audit,
		claimLease: 30 * time.Second,
	}
}

// OnCompleted installs a hook fired after every terminal Complete
// call. Pass nil to clear. Useful for downstream state machines (e.g.
// RequestService transitioning access_request status when its patch
// job finishes).
func (s *JobService) OnCompleted(hook JobCompletedHook) {
	s.onCompleted = hook
}

// EnqueueRequest is the shape admins post when creating a job. RequestID
// is optional; CorrelationID is generated when omitted.
type EnqueueRequest struct {
	AgentScope    map[string]any
	JobType       storage.JobType
	Payload       map[string]any
	RequestID     *uuid.UUID
	CorrelationID uuid.UUID
}

// Enqueue creates a queued job. Wired today by the admin endpoint;
// later (Step 10) by the approval-workflow on request acceptance.
func (s *JobService) Enqueue(ctx context.Context, req EnqueueRequest) (*storage.SyncJob, error) {
	if req.JobType == "" {
		return nil, errors.New("jobs: JobType is required")
	}
	job := &storage.SyncJob{
		AgentScope:    req.AgentScope,
		JobType:       req.JobType,
		Status:        storage.JobStatusQueued,
		CorrelationID: req.CorrelationID,
		RequestID:     req.RequestID,
		Payload:       req.Payload,
	}
	if err := s.jobs.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("jobs: create: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "admin",
		Action:        "job.enqueue",
		Resource:      "job:" + job.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: job.CorrelationID,
		Metadata: map[string]any{
			"job_type": string(job.JobType),
		},
	})
	return job, nil
}

// Claim hands the oldest queued (or claim-expired) job to agentID with
// a fresh lease. Returns storage.ErrNoJobs when nothing is runnable.
func (s *JobService) Claim(ctx context.Context, agentID uuid.UUID) (*storage.SyncJob, error) {
	job, err := s.jobs.ClaimNext(ctx, agentID, s.claimLease)
	if err != nil {
		if errors.Is(err, storage.ErrNoJobs) {
			return nil, err
		}
		return nil, fmt.Errorf("jobs: claim: %w", err)
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "agent:" + agentID.String(),
		Action:        "job.claim",
		Resource:      "job:" + job.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: job.CorrelationID,
	})
	return job, nil
}

// CompleteRequest captures the agent's outcome submission.
type CompleteRequest struct {
	JobID  uuid.UUID
	Status storage.JobStatus // succeeded | failed
	Error  string
}

// Complete records the agent's outcome. Idempotent on terminal rows
// (returns nil and emits an audit-already-complete event so a re-submit
// is observable). Rejects requests from a non-owning agent with
// storage.ErrUnauthorized.
func (s *JobService) Complete(ctx context.Context, agentID uuid.UUID, req CompleteRequest) error {
	err := s.jobs.Complete(ctx, req.JobID, agentID, req.Status, req.Error)
	switch {
	case errors.Is(err, storage.ErrAlreadyComplete):
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "agent:" + agentID.String(),
			Action:   "job.complete.idempotent",
			Resource: "job:" + req.JobID.String(),
			Status:   storage.AuditStatusSuccess,
		})
		return nil
	case errors.Is(err, storage.ErrUnauthorized):
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "agent:" + agentID.String(),
			Action:   "job.complete",
			Resource: "job:" + req.JobID.String(),
			Status:   storage.AuditStatusDenied,
		})
		return err
	case err != nil:
		return err
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:" + agentID.String(),
		Action:   "job.complete",
		Resource: "job:" + req.JobID.String(),
		Status:   auditStatusFor(req.Status),
		Metadata: map[string]any{
			"job_status": string(req.Status),
		},
	})

	// Fire the post-complete hook (RequestService listens for patch
	// jobs to flip access_request.status). Loading the job row here is
	// cheap and gives the hook the full context it needs without
	// piling more parameters on the public Complete signature.
	if s.onCompleted != nil {
		if job, err := s.jobs.Get(ctx, req.JobID); err == nil {
			s.onCompleted(ctx, job)
		}
	}
	return nil
}

func auditStatusFor(s storage.JobStatus) storage.AuditStatus {
	if s == storage.JobStatusSucceeded {
		return storage.AuditStatusSuccess
	}
	return storage.AuditStatusFailure
}
