// Package handlers: gitops_history.go serves the history of the removed
// control-plane Argo CD poller.
//
//	GET /requests/:id/gitops   the request's gitops_observations rows,
//	                           requester only, read-only
//
// The poller and the Argo CD endpoint, discovery and app-mapping routes
// were removed at the Gateway R1 cutover (secrets-bridge/gateway#13).
// Live Argo CD state comes from Gateway evidence only
// (GET /requests/:id/observations). Rows written before the cutover stay
// readable here, each labelled context only (ADR 0001 section 9 step 5):
// they were never linked to the change and are not proof that a secret
// value propagated.
package handlers

import (
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// GitOpsHistoryLabel marks every row of the history route.
const GitOpsHistoryLabel = "history_context_only"

// GitOpsHistory serves the read-only history route.
type GitOpsHistory struct {
	observations storage.GitOpsObservationHistory
	requests     storage.AccessRequestRepository
}

// NewGitOpsHistory wires the handler.
func NewGitOpsHistory(observations storage.GitOpsObservationHistory, requests storage.AccessRequestRepository) *GitOpsHistory {
	return &GitOpsHistory{observations: observations, requests: requests}
}

type gitopsHistoryResponse struct {
	ID                   string `json:"id"`
	ApplicationName      string `json:"application_name"`
	ApplicationNamespace string `json:"application_namespace,omitempty"`
	PollingState         string `json:"polling_state"`
	// Status repeats polling_state for clients that read it under that
	// name.
	Status        string         `json:"status"`
	HistoryStatus string         `json:"history_status"`
	Label         string         `json:"label"`
	History       bool           `json:"history"`
	ObservedState map[string]any `json:"observed_state"`
	LastPolledAt  *string        `json:"last_polled_at,omitempty"`
	PollsCount    int            `json:"polls_count"`
	LastError     string         `json:"last_error,omitempty"`
	TimeoutAt     *string        `json:"timeout_at,omitempty"`
	TerminalAt    *string        `json:"terminal_at,omitempty"`
}

// GetRequestObservations handles GET /requests/:id/gitops.
//
// Authorization: the requester sees their own rows. The acting identity
// is the authenticated session identity, never a caller-supplied
// `user_id` (API-02).
func (h *GitOpsHistory) GetRequestObservations(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request UUID")
	}
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok || userID == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	req, err := h.requests.Get(c.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "request not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, "request lookup failed")
	}
	if req.RequesterID != userID {
		return fiber.NewError(fiber.StatusForbidden, "not the request owner")
	}
	rows, err := h.observations.ListForRequest(c.Context(), id)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "history lookup failed")
	}
	out := make([]gitopsHistoryResponse, 0, len(rows))
	for _, r := range rows {
		out = append(out, gitopsHistoryToResponse(r))
	}
	return c.JSON(out)
}

// gitopsHistoryStatus is how a row reads after the cutover (ADR 0001
// section 9 step 5). applied only ever meant Argo CD was healthy and
// synced; a row the poller never finished is left as not completed.
func gitopsHistoryStatus(s storage.GitOpsObservationState) string {
	switch s {
	case storage.GitOpsStateApplied:
		return "argocd_healthy_synced_context_only"
	case storage.GitOpsStateAppliedUnverified:
		return "timed_out_unverified"
	case storage.GitOpsStateFailed:
		return "failed"
	}
	return "not_completed_poller_removed"
}

func gitopsHistoryToResponse(o *storage.GitOpsObservation) gitopsHistoryResponse {
	out := gitopsHistoryResponse{
		ID:                   o.ID.String(),
		ApplicationName:      o.ApplicationName,
		ApplicationNamespace: o.ApplicationNamespace,
		PollingState:         string(o.PollingState),
		Status:               string(o.PollingState),
		HistoryStatus:        gitopsHistoryStatus(o.PollingState),
		Label:                GitOpsHistoryLabel,
		History:              true,
		ObservedState:        observedStateForClient(o.ObservedState),
		PollsCount:           o.PollsCount,
		LastError:            observationErrorClass(o.LastError),
	}
	fmtTime := func(t *time.Time) *string {
		if t == nil {
			return nil
		}
		s := t.UTC().Format(time.RFC3339)
		return &s
	}
	out.LastPolledAt, out.TimeoutAt, out.TerminalAt = fmtTime(o.LastPolledAt), fmtTime(o.TimeoutAt), fmtTime(o.TerminalAt)
	return out
}

// Rows the poller wrote before it stopped persisting Argo CD free text
// still carry health_message and per-resource message, which can hold
// whatever a controller or probe put there. last_error is raw poller
// text and names the Argo CD base URL. The stored row is left as is;
// only the response is shaped.

// observedStateKeys is the allow-list of observed_state keys a client
// sees. Anything not listed is dropped.
var observedStateKeys = map[string]bool{
	"health_status":   true,
	"sync_status":     true,
	"sync_revision":   true,
	"operation_phase": true,
	"resource_count":  true,
	"resources":       true,
}

// observedResourceKeys is the allow-list for each resources[] entry.
var observedResourceKeys = map[string]bool{
	"group":     true,
	"version":   true,
	"kind":      true,
	"name":      true,
	"namespace": true,
	"status":    true,
	"health":    true,
}

func observedStateForClient(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if !observedStateKeys[k] {
			continue
		}
		if k == "resources" {
			out[k] = observedResourcesForClient(v)
			continue
		}
		out[k] = v
	}
	return out
}

func observedResourcesForClient(v any) []map[string]any {
	items, _ := v.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		r := make(map[string]any, len(m))
		for k, val := range m {
			if observedResourceKeys[k] {
				r[k] = val
			}
		}
		out = append(out, r)
	}
	return out
}

// The error texts the removed client wrapped into the poller's
// last_error. Kept as text so old rows still classify.
const (
	argoErrUnauthorized    = "argocd: unauthorized"
	argoErrForbidden       = "argocd: forbidden"
	argoErrNotFound        = "argocd: not found"
	argoErrRedirectRefused = "argocd: redirect refused"
)

// observationErrorClass maps the poller's raw last_error to a stable
// class. The prefixes are the ones the removed poller wrote.
func observationErrorClass(raw string) string {
	switch {
	case raw == "":
		return ""
	case raw == "endpoint disabled":
		return "endpoint_disabled"
	case strings.HasPrefix(raw, "endpoint lookup:"):
		return "endpoint_unavailable"
	case raw == "no token resolver configured", strings.HasPrefix(raw, "unwrap token:"):
		return "token_unavailable"
	case strings.HasPrefix(raw, "build argocd client:"):
		return "client_config_invalid"
	case strings.HasPrefix(raw, "argocd fetch:"):
		switch {
		case strings.Contains(raw, argoErrUnauthorized):
			return "argocd_unauthorized"
		case strings.Contains(raw, argoErrForbidden):
			return "argocd_forbidden"
		case strings.Contains(raw, argoErrNotFound):
			return "argocd_app_not_found"
		case strings.Contains(raw, argoErrRedirectRefused):
			return "argocd_redirect_refused"
		}
		return "argocd_unreachable"
	}
	return "poll_failed"
}
