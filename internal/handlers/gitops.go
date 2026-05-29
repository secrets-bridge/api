// Package handlers — gitops.go: HTTP layer for the read-only ArgoCD
// integration (BRD §26).
//
// Endpoints:
//
//   Admin (under /api/v1):
//     POST   /argocd-endpoints                 register a new ArgoCD endpoint
//     GET    /argocd-endpoints                 list configured endpoints (no token)
//     GET    /argocd-endpoints/:id             get one endpoint (no token)
//     PUT    /argocd-endpoints/:id/enabled     toggle enabled flag
//     DELETE /argocd-endpoints/:id             soft-delete
//
//     POST   /gitops-app-mappings              create a mapping
//     GET    /gitops-app-mappings              list mappings
//     DELETE /gitops-app-mappings/:id          soft-delete
//
//   User (under /api/v1):
//     GET    /requests/:id/gitops              list observation rows for the
//                                              request (only the requester or
//                                              an admin may read)
package handlers

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// GitOps groups every ArgoCD-integration HTTP route.
type GitOps struct {
	endpoints     *services.ArgoCDEndpointService
	mappings      storage.GitOpsAppMappingRepository
	observations  *services.GitOpsService
	requests      storage.AccessRequestRepository
}

// NewGitOps wires the handler.
func NewGitOps(
	endpoints *services.ArgoCDEndpointService,
	mappings storage.GitOpsAppMappingRepository,
	observations *services.GitOpsService,
	requests storage.AccessRequestRepository,
) *GitOps {
	return &GitOps{
		endpoints:    endpoints,
		mappings:     mappings,
		observations: observations,
		requests:     requests,
	}
}

// --- Admin: argocd_endpoints ---------------------------------------

type createArgoCDEndpointBody struct {
	Name          string  `json:"name"`
	EnvironmentID *string `json:"environment_id,omitempty"`
	BaseURL       string  `json:"base_url"`
	// Token is base64-encoded so binary payloads (rare) work and so
	// the request body shape stays JSON-clean. It's the plaintext
	// ArgoCD account token; the service envelope-encrypts before
	// persisting and never logs it.
	TokenB64      string  `json:"token_b64"`
	TLSCAPEM      string  `json:"tls_ca_pem,omitempty"`
	TLSServerName string  `json:"tls_server_name,omitempty"`
}

type argocdEndpointResponse struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	EnvironmentID *string `json:"environment_id,omitempty"`
	BaseURL       string  `json:"base_url"`
	TLSServerName string  `json:"tls_server_name,omitempty"`
	Enabled       bool    `json:"enabled"`
	LastHealthAt  *string `json:"last_health_at,omitempty"`
	HealthError   string  `json:"health_error,omitempty"`
	KMSKeyID      string  `json:"kms_key_id"`
}

// CreateArgoCDEndpoint handles POST /argocd-endpoints.
func (h *GitOps) CreateArgoCDEndpoint(c fiber.Ctx) error {
	var body createArgoCDEndpointBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.Name == "" || body.BaseURL == "" || body.TokenB64 == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name, base_url, token_b64 required")
	}
	tok, err := base64.StdEncoding.DecodeString(body.TokenB64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "token_b64 is not valid base64")
	}
	var envID *uuid.UUID
	if body.EnvironmentID != nil && *body.EnvironmentID != "" {
		parsed, err := uuid.Parse(*body.EnvironmentID)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid environment_id UUID")
		}
		envID = &parsed
	}
	e, err := h.endpoints.Create(c.Context(), services.CreateArgoCDEndpointInput{
		Name:          body.Name,
		EnvironmentID: envID,
		BaseURL:       body.BaseURL,
		Token:         tok,
		TLSCAPEM:      body.TLSCAPEM,
		TLSServerName: body.TLSServerName,
	})
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(argocdEndpointToResponse(e))
}

// ListArgoCDEndpoints handles GET /argocd-endpoints.
func (h *GitOps) ListArgoCDEndpoints(c fiber.Ctx) error {
	rows, err := h.endpoints.List(c.Context())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	out := make([]argocdEndpointResponse, 0, len(rows))
	for _, r := range rows {
		out = append(out, argocdEndpointToResponse(r))
	}
	return c.JSON(out)
}

// GetArgoCDEndpoint handles GET /argocd-endpoints/:id.
func (h *GitOps) GetArgoCDEndpoint(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	e, err := h.endpoints.Get(c.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "argocd endpoint not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.JSON(argocdEndpointToResponse(e))
}

// SetArgoCDEndpointEnabled handles PUT /argocd-endpoints/:id/enabled.
func (h *GitOps) SetArgoCDEndpointEnabled(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if err := h.endpoints.SetEnabled(c.Context(), id, body.Enabled); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "argocd endpoint not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// DeleteArgoCDEndpoint handles DELETE /argocd-endpoints/:id.
func (h *GitOps) DeleteArgoCDEndpoint(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	if err := h.endpoints.SoftDelete(c.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "argocd endpoint not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func argocdEndpointToResponse(e *storage.ArgoCDEndpoint) argocdEndpointResponse {
	out := argocdEndpointResponse{
		ID:            e.ID.String(),
		Name:          e.Name,
		BaseURL:       e.BaseURL,
		TLSServerName: e.TLSServerName,
		Enabled:       e.Enabled,
		HealthError:   e.LastHealthError,
		KMSKeyID:      e.TokenKMSKeyID,
	}
	if e.EnvironmentID != nil {
		s := e.EnvironmentID.String()
		out.EnvironmentID = &s
	}
	if e.LastHealthAt != nil {
		s := e.LastHealthAt.UTC().Format(time.RFC3339)
		out.LastHealthAt = &s
	}
	return out
}

// --- Admin: gitops_app_mappings ------------------------------------

type createGitOpsMappingBody struct {
	SecretMappingID      *string `json:"secret_mapping_id,omitempty"`
	ProviderConnectionID *string `json:"provider_connection_id,omitempty"`
	ArgoCDEndpointID     string  `json:"argocd_endpoint_id"`
	ApplicationName      string  `json:"application_name"`
	ApplicationNamespace string  `json:"application_namespace,omitempty"`
	ProjectName          string  `json:"project_name,omitempty"`
	ClusterName          string  `json:"cluster_name,omitempty"`
}

type gitopsMappingResponse struct {
	ID                   string  `json:"id"`
	SecretMappingID      *string `json:"secret_mapping_id,omitempty"`
	ProviderConnectionID *string `json:"provider_connection_id,omitempty"`
	ArgoCDEndpointID     string  `json:"argocd_endpoint_id"`
	ApplicationName      string  `json:"application_name"`
	ApplicationNamespace string  `json:"application_namespace,omitempty"`
	ProjectName          string  `json:"project_name,omitempty"`
	ClusterName          string  `json:"cluster_name,omitempty"`
	Enabled              bool    `json:"enabled"`
}

// CreateGitOpsMapping handles POST /gitops-app-mappings.
func (h *GitOps) CreateGitOpsMapping(c fiber.Ctx) error {
	var body createGitOpsMappingBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.ArgoCDEndpointID == "" || body.ApplicationName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "argocd_endpoint_id and application_name required")
	}
	endpointID, err := uuid.Parse(body.ArgoCDEndpointID)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid argocd_endpoint_id UUID")
	}
	m := &storage.GitOpsAppMapping{
		ArgoCDEndpointID:     endpointID,
		ApplicationName:      body.ApplicationName,
		ApplicationNamespace: body.ApplicationNamespace,
		ProjectName:          body.ProjectName,
		ClusterName:          body.ClusterName,
		Enabled:              true,
	}
	if body.SecretMappingID != nil && *body.SecretMappingID != "" {
		v, err := uuid.Parse(*body.SecretMappingID)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid secret_mapping_id UUID")
		}
		m.SecretMappingID = &v
	}
	if body.ProviderConnectionID != nil && *body.ProviderConnectionID != "" {
		v, err := uuid.Parse(*body.ProviderConnectionID)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid provider_connection_id UUID")
		}
		m.ProviderConnectionID = &v
	}
	if (m.SecretMappingID == nil) == (m.ProviderConnectionID == nil) {
		return fiber.NewError(fiber.StatusBadRequest, "exactly one of secret_mapping_id or provider_connection_id required")
	}
	if err := h.mappings.Create(c.Context(), m); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(gitopsMappingToResponse(m))
}

// ListGitOpsMappings handles GET /gitops-app-mappings.
func (h *GitOps) ListGitOpsMappings(c fiber.Ctx) error {
	rows, err := h.mappings.List(c.Context())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	out := make([]gitopsMappingResponse, 0, len(rows))
	for _, r := range rows {
		out = append(out, gitopsMappingToResponse(r))
	}
	return c.JSON(out)
}

// DeleteGitOpsMapping handles DELETE /gitops-app-mappings/:id.
func (h *GitOps) DeleteGitOpsMapping(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	if err := h.mappings.SoftDelete(c.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "gitops mapping not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func gitopsMappingToResponse(m *storage.GitOpsAppMapping) gitopsMappingResponse {
	out := gitopsMappingResponse{
		ID:                   m.ID.String(),
		ArgoCDEndpointID:     m.ArgoCDEndpointID.String(),
		ApplicationName:      m.ApplicationName,
		ApplicationNamespace: m.ApplicationNamespace,
		ProjectName:          m.ProjectName,
		ClusterName:          m.ClusterName,
		Enabled:              m.Enabled,
	}
	if m.SecretMappingID != nil {
		s := m.SecretMappingID.String()
		out.SecretMappingID = &s
	}
	if m.ProviderConnectionID != nil {
		s := m.ProviderConnectionID.String()
		out.ProviderConnectionID = &s
	}
	return out
}

// --- User: request observations ------------------------------------

type observationResponse struct {
	ID                   string         `json:"id"`
	ApplicationName      string         `json:"application_name"`
	ApplicationNamespace string         `json:"application_namespace,omitempty"`
	PollingState         string         `json:"polling_state"`
	ObservedState        map[string]any `json:"observed_state"`
	LastPolledAt         *string        `json:"last_polled_at,omitempty"`
	PollsCount           int            `json:"polls_count"`
	LastError            string         `json:"last_error,omitempty"`
	TimeoutAt            *string        `json:"timeout_at,omitempty"`
	TerminalAt           *string        `json:"terminal_at,omitempty"`
}

// GetRequestObservations handles GET /requests/:id/gitops.
//
// Permission today: requester sees their own; admin sees all. The
// real auth model is the same stub-middleware-and-query-param shape
// the read-flow retrieval uses (handler reads `user_id` query param;
// see RetrieveWrap in requests.go). Real auth lands later.
func (h *GitOps) GetRequestObservations(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request UUID")
	}
	userID := c.Query("user_id")
	if userID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "user_id query parameter required")
	}
	req, err := h.requests.Get(c.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "request not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if req.RequesterID != userID {
		return fiber.NewError(fiber.StatusForbidden, "not the request owner")
	}
	rows, err := h.observations.ListForRequest(c.Context(), id)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	out := make([]observationResponse, 0, len(rows))
	for _, r := range rows {
		out = append(out, observationToResponse(r))
	}
	return c.JSON(out)
}

func observationToResponse(o *storage.GitOpsObservation) observationResponse {
	out := observationResponse{
		ID:                   o.ID.String(),
		ApplicationName:      o.ApplicationName,
		ApplicationNamespace: o.ApplicationNamespace,
		PollingState:         string(o.PollingState),
		ObservedState:        o.ObservedState,
		PollsCount:           o.PollsCount,
		LastError:            o.LastError,
	}
	if o.LastPolledAt != nil {
		s := o.LastPolledAt.UTC().Format(time.RFC3339)
		out.LastPolledAt = &s
	}
	if o.TimeoutAt != nil {
		s := o.TimeoutAt.UTC().Format(time.RFC3339)
		out.TimeoutAt = &s
	}
	if o.TerminalAt != nil {
		s := o.TerminalAt.UTC().Format(time.RFC3339)
		out.TerminalAt = &s
	}
	return out
}
