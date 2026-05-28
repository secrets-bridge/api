package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Jobs is the HTTP layer over services.JobService.
type Jobs struct {
	svc *services.JobService
}

// NewJobs binds a Jobs handler to its service.
func NewJobs(svc *services.JobService) *Jobs { return &Jobs{svc: svc} }

// EnqueueRequest is the body of POST /api/v1/jobs.
type EnqueueRequest struct {
	AgentScope    map[string]any  `json:"agent_scope,omitempty"`
	JobType       storage.JobType `json:"job_type"`
	Payload       map[string]any  `json:"payload,omitempty"`
	RequestID     *uuid.UUID      `json:"request_id,omitempty"`
	CorrelationID uuid.UUID       `json:"correlation_id,omitempty"`
}

// EnqueueResponse identifies the new row.
type EnqueueResponse struct {
	ID            uuid.UUID `json:"id"`
	CorrelationID uuid.UUID `json:"correlation_id"`
	Status        string    `json:"status"`
}

// Enqueue handles the admin-side job-creation endpoint. Real RBAC lands
// with workflow (#10); the auth stub admits everything for now.
func (h *Jobs) Enqueue(c fiber.Ctx) error {
	var req EnqueueRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	job, err := h.svc.Enqueue(c.Context(), services.EnqueueRequest{
		AgentScope:    req.AgentScope,
		JobType:       req.JobType,
		Payload:       req.Payload,
		RequestID:     req.RequestID,
		CorrelationID: req.CorrelationID,
	})
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(EnqueueResponse{
		ID:            job.ID,
		CorrelationID: job.CorrelationID,
		Status:        string(job.Status),
	})
}

// ClaimResponse is what the agent receives after a successful claim.
type ClaimResponse struct {
	ID             uuid.UUID      `json:"id"`
	JobType        string         `json:"job_type"`
	Payload        map[string]any `json:"payload"`
	CorrelationID  uuid.UUID      `json:"correlation_id"`
	ClaimExpiresAt string         `json:"claim_expires_at"`
}

// Claim returns the next runnable job for the authenticated agent.
// Returns 204 No Content when the queue is empty so the agent can poll
// cheaply (status code distinguishes "no jobs" from "transport error"
// at the HTTP layer).
func (h *Jobs) Claim(c fiber.Ctx) error {
	agentID, ok := middleware.AgentIDFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "agent identity missing in context")
	}

	job, err := h.svc.Claim(c.Context(), agentID)
	switch {
	case errors.Is(err, storage.ErrNoJobs):
		return c.SendStatus(fiber.StatusNoContent)
	case err != nil:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	expires := ""
	if job.ClaimExpiresAt != nil {
		expires = job.ClaimExpiresAt.UTC().Format(rfc3339Nano)
	}
	return c.Status(fiber.StatusOK).JSON(ClaimResponse{
		ID:             job.ID,
		JobType:        string(job.JobType),
		Payload:        job.Payload,
		CorrelationID:  job.CorrelationID,
		ClaimExpiresAt: expires,
	})
}

// CompleteRequest is the body of POST /api/v1/agents/:id/jobs/:job/complete.
type CompleteRequest struct {
	Status storage.JobStatus `json:"status"` // "succeeded" | "failed"
	Error  string            `json:"error,omitempty"`
}

// Complete records the agent's outcome submission.
func (h *Jobs) Complete(c fiber.Ctx) error {
	agentID, ok := middleware.AgentIDFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "agent identity missing in context")
	}
	jobID, err := uuid.Parse(c.Params("job"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid job id")
	}
	var req CompleteRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	err = h.svc.Complete(c.Context(), agentID, services.CompleteRequest{
		JobID:  jobID,
		Status: req.Status,
		Error:  req.Error,
	})
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "job not found")
	case errors.Is(err, storage.ErrUnauthorized):
		// Another agent owns this claim. Generic 409 so an attacker
		// can't tell whether the job exists or just isn't theirs.
		return fiber.NewError(fiber.StatusConflict, "job not owned by this agent")
	case err != nil:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.SendStatus(fiber.StatusNoContent)
}
