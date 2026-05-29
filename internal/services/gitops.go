// Package services — gitops.go: the GitOps Observation service.
//
// Lifecycle:
//
//  1. RequestService transitions an access_request to `executed`
//     after the agent reports the patch/read job done.
//  2. RequestService calls GitOpsService.Start(requestID).
//  3. Start looks up the request's secret_mapping_id (today) or
//     provider_connection_id (future) and fans out one
//     gitops_observations row per configured app mapping.
//  4. The worker repo's poller (separate PR) claims observations
//     via ClaimNextActive, calls argocd.GetApplicationResourceTree,
//     records the snapshot, and transitions to applied /
//     applied_unverified / failed.
//
// This service file owns the api-side surface: Start, Get for the
// user-bound handler, and ProcessOne for the worker's poller (worker
// imports api/pkg/storage and internal/services... no — actually,
// the worker should NOT import internal/services. The polling logic
// lives in the worker. This file owns Start + the read-side methods).
package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// GitOpsService wires the storage + audit edges of the observation
// lifecycle. The actual ArgoCD polling happens in the worker repo.
//
// Default observation timeout (30m) can be overridden via Config.
type GitOpsService struct {
	endpoints    storage.ArgoCDEndpointRepository
	mappings     storage.GitOpsAppMappingRepository
	observations storage.GitOpsObservationRepository
	requests     storage.AccessRequestRepository
	audit        storage.AuditEventRepository
	cfg          GitOpsConfig
}

// GitOpsConfig carries tunables.
type GitOpsConfig struct {
	ObservationTimeout time.Duration // default 30m
}

// NewGitOpsService constructs the service. nil endpoints / mappings /
// observations is permitted only when the integration is disabled
// (e.g. an environment without any ArgoCD endpoint configured).
func NewGitOpsService(
	endpoints storage.ArgoCDEndpointRepository,
	mappings storage.GitOpsAppMappingRepository,
	observations storage.GitOpsObservationRepository,
	requests storage.AccessRequestRepository,
	audit storage.AuditEventRepository,
	cfg GitOpsConfig,
) *GitOpsService {
	if cfg.ObservationTimeout == 0 {
		cfg.ObservationTimeout = 30 * time.Minute
	}
	return &GitOpsService{
		endpoints:    endpoints,
		mappings:     mappings,
		observations: observations,
		requests:     requests,
		audit:        audit,
		cfg:          cfg,
	}
}

// Start fans out gitops_observations rows for the given request.
// Called by RequestService after a successful transition to `executed`.
//
// Behavior:
//   - If the request has no secret_mapping_id (today's read/patch
//     flows can be ad-hoc), no observations are created and the
//     function returns nil. The audit trail still gets a
//     `request.gitops_observation_skipped` event so operators can see
//     why no panel showed up on the request page.
//   - For each configured mapping, one observation row is created in
//     `queued` state with timeout_at = now + ObservationTimeout.
//   - Any per-mapping creation failure is audited but doesn't bubble:
//     other mappings still get their observations.
func (s *GitOpsService) Start(ctx context.Context, request *storage.AccessRequest) error {
	if s == nil || s.observations == nil {
		return nil
	}
	if request == nil {
		return errors.New("services: nil request")
	}
	if request.SecretMappingID == nil {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:         "system",
			Action:        "request.gitops_observation_skipped",
			Resource:      "request:" + request.ID.String(),
			Status:        storage.AuditStatusSuccess,
			CorrelationID: request.ID,
			Metadata:      map[string]any{"reason": "request has no secret_mapping_id"},
		})
		return nil
	}
	mappings, err := s.mappings.ListForSecretMapping(ctx, *request.SecretMappingID)
	if err != nil {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:         "system",
			Action:        "request.gitops_observation_failed",
			Resource:      "request:" + request.ID.String(),
			Status:        storage.AuditStatusFailure,
			CorrelationID: request.ID,
			Metadata:      map[string]any{"error": err.Error()},
		})
		return fmt.Errorf("gitops: list mappings: %w", err)
	}
	if len(mappings) == 0 {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:         "system",
			Action:        "request.gitops_observation_skipped",
			Resource:      "request:" + request.ID.String(),
			Status:        storage.AuditStatusSuccess,
			CorrelationID: request.ID,
			Metadata:      map[string]any{"reason": "no gitops app mappings configured for this secret_mapping"},
		})
		return nil
	}
	timeout := time.Now().Add(s.cfg.ObservationTimeout)
	created := 0
	for _, m := range mappings {
		o := &storage.GitOpsObservation{
			RequestID:            request.ID,
			ArgoCDEndpointID:     m.ArgoCDEndpointID,
			ApplicationName:      m.ApplicationName,
			ApplicationNamespace: m.ApplicationNamespace,
			PollingState:         storage.GitOpsStateQueued,
			TimeoutAt:            &timeout,
		}
		if err := s.observations.Create(ctx, o); err != nil {
			_ = s.audit.Append(ctx, &storage.AuditEvent{
				Actor:         "system",
				Action:        "request.gitops_observation_failed",
				Resource:      "request:" + request.ID.String(),
				Status:        storage.AuditStatusFailure,
				CorrelationID: request.ID,
				Metadata: map[string]any{
					"error":            err.Error(),
					"application_name": m.ApplicationName,
				},
			})
			continue
		}
		created++
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "system",
		Action:        "request.gitops_observation_started",
		Resource:      "request:" + request.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: request.ID,
		Metadata: map[string]any{
			"applications_observed": created,
			"timeout_at":            timeout.UTC().Format(time.RFC3339),
		},
	})
	return nil
}

// ListForRequest returns the observation rows attached to a request,
// shaped for the user-bound handler. Reverse-ordered chronologically
// per application via the storage layer.
func (s *GitOpsService) ListForRequest(ctx context.Context, requestID uuid.UUID) ([]*storage.GitOpsObservation, error) {
	if s == nil || s.observations == nil {
		return nil, nil
	}
	return s.observations.ListForRequest(ctx, requestID)
}
