// Package handlers — secrets.go: discovery HTTP surface.
//
// Two endpoints:
//
//	GET  /api/v1/secrets                       admin list/search
//	POST /api/v1/agents/:id/secrets/bulk       agent upserts a discovery batch
//
// The list endpoint supports K8s-style repeated label selectors:
//
//	GET /api/v1/secrets?label=cluster:prod-eu&label=team:billing
//	  → labels @> '{"cluster":"prod-eu","team":"billing"}'
//
// Plus dimension shorthands (cluster_name, provider, ref_prefix,
// status) and pagination (limit, offset).
package handlers

import (
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Secrets is the HTTP layer over SecretsService.
//
// The catalog endpoint (GET /secrets) is scoped to the caller's
// `secret.list` grants. A grant at empty scope (or with a scope that
// doesn't constrain project_id) yields the admin view; a project_id-
// scoped grant restricts results to that project's bindings. See
// `internal/auth.EffectiveProjectAccess` + the `project_secrets`
// repository (api#43 Slice A) for the join.
type Secrets struct {
	svc            *services.SecretsService
	bindings       storage.ProjectSecretRepository
	scopeResolver  auth.Resolver
}

// NewSecrets binds the handler. `bindings` and `scopeResolver` may be
// nil to keep the legacy "everyone sees everything" behaviour — that
// hatch will be removed once the UI is project-aware.
func NewSecrets(svc *services.SecretsService) *Secrets { return &Secrets{svc: svc} }

// WithProjectScoping wires the multi-tenancy filter. Pass both args
// non-nil from main; passing nil disables scoping (admin-only mode).
func (h *Secrets) WithProjectScoping(b storage.ProjectSecretRepository, r auth.Resolver) *Secrets {
	h.bindings = b
	h.scopeResolver = r
	return h
}

func secretsErr(err error) error {
	switch {
	case errors.Is(err, services.ErrInvalidInput):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "not found")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}

// ---- bulk upsert (agent-side) ----------------------------------------

// BulkUpsertBody is the JSON the agent's DiscoverExecutor POSTs.
type BulkUpsertBody struct {
	ClusterName    string             `json:"cluster_name"`
	ProviderType   string             `json:"provider_type"`
	ProviderConfig map[string]any     `json:"provider_config,omitempty"`
	Items          []BulkUpsertItem   `json:"items"`
}

// BulkUpsertItem is one entry in the batch.
type BulkUpsertItem struct {
	SecretRef       string         `json:"secret_ref"`
	Labels          map[string]any `json:"labels,omitempty"`
	Version         string         `json:"version,omitempty"`
	Checksum        string         `json:"checksum,omitempty"`
	CreatedAtSource *time.Time     `json:"created_at_source,omitempty"`
	UpdatedAtSource *time.Time     `json:"updated_at_source,omitempty"`
}

// BulkUpsertResponse is the JSON returned.
type BulkUpsertResponse struct {
	UpsertedIDs []string `json:"upserted_ids"`
	Count       int      `json:"count"`
}

// BulkUpsert handles POST /api/v1/agents/:id/secrets/bulk.
func (h *Secrets) BulkUpsert(c fiber.Ctx) error {
	agentID, ok := middleware.AgentIDFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "agent identity missing in context")
	}
	var body BulkUpsertBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	items := make([]services.BulkItem, 0, len(body.Items))
	for _, it := range body.Items {
		items = append(items, services.BulkItem{
			SecretRef:       it.SecretRef,
			Labels:          it.Labels,
			Version:         it.Version,
			Checksum:        it.Checksum,
			CreatedAtSource: it.CreatedAtSource,
			UpdatedAtSource: it.UpdatedAtSource,
		})
	}

	res, err := h.svc.Upsert(c.Context(), "agent:"+agentID.String(), services.BulkInput{
		ClusterName:    body.ClusterName,
		ProviderType:   body.ProviderType,
		ProviderConfig: body.ProviderConfig,
		Items:          items,
	})
	if err != nil {
		return secretsErr(err)
	}
	return c.Status(fiber.StatusOK).JSON(BulkUpsertResponse{
		UpsertedIDs: res.UpsertedIDs,
		Count:       res.Count,
	})
}

// ---- list / get (admin-side) -----------------------------------------

// SecretBody is the JSON shape returned to admins.
type SecretBody struct {
	ID              string         `json:"id"`
	ClusterName     string         `json:"cluster_name"`
	ProviderType    string         `json:"provider_type"`
	SecretRef       string         `json:"secret_ref"`
	ProviderConfig  map[string]any `json:"provider_config,omitempty"`
	Labels          map[string]any `json:"labels"`
	Version         string         `json:"version,omitempty"`
	Checksum        string         `json:"checksum,omitempty"`
	CreatedAtSource *time.Time     `json:"created_at_source,omitempty"`
	UpdatedAtSource *time.Time     `json:"updated_at_source,omitempty"`
	Status          string         `json:"status"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
}

// ListResponse wraps the items + total for pagination.
type ListResponse struct {
	Items []SecretBody `json:"items"`
	Total int          `json:"total"`
}

// List handles GET /api/v1/secrets.
//
// Project-scoped catalog: when both `bindings` and `scopeResolver` are
// wired AND the caller is not a global admin for `secret.list`, the
// returned rows are restricted to secrets bound to the caller's
// projects via `project_secrets`. An optional `?project_id=<uuid>`
// narrows further (admin can use this to inspect one project; a
// scoped caller can only narrow within their own access set).
func (h *Secrets) List(c fiber.Ctx) error {
	f := filterFromQuery(c)

	if err := h.applyProjectScope(c, &f); err != nil {
		return err
	}

	rows, err := h.svc.List(c.Context(), f)
	if err != nil {
		return secretsErr(err)
	}
	total, err := h.svc.Count(c.Context(), f)
	if err != nil {
		return secretsErr(err)
	}
	out := make([]SecretBody, 0, len(rows))
	for _, r := range rows {
		out = append(out, secretToBody(r))
	}
	return c.JSON(ListResponse{Items: out, Total: total})
}

// applyProjectScope folds the caller's `secret.list` grants into the
// list filter:
//
//   - bindings or scopeResolver unset → no scoping (legacy behaviour)
//   - identity missing                → 401
//   - global admin                    → no id restriction (unless
//                                       ?project_id= is supplied)
//   - scoped caller                   → restrict to the secrets bound
//                                       to their projects; if a
//                                       ?project_id= is supplied AND
//                                       in their set, narrow further.
//                                       Empty access set → empty
//                                       result (encoded as a non-nil
//                                       empty SecretIDs).
func (h *Secrets) applyProjectScope(c fiber.Ctx, f *storage.SecretsListFilter) error {
	if h.bindings == nil || h.scopeResolver == nil {
		return nil
	}
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}

	access, err := auth.EffectiveProjectAccess(c.Context(), userID, auth.PermSecretList, h.scopeResolver)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	queryProject := c.Query("project_id")
	var queryProjectID *uuid.UUID
	if queryProject != "" {
		u, err := uuid.Parse(queryProject)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "project_id must be a UUID")
		}
		queryProjectID = &u
	}

	if access.IsGlobal {
		if queryProjectID == nil {
			return nil
		}
		ids, err := h.bindings.ListSecretIDsForProjects(c.Context(), []uuid.UUID{*queryProjectID})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		f.SecretIDs = nonNilUUIDs(ids)
		return nil
	}

	// Non-admin caller. They must hold at least one project_id-scoped
	// grant — otherwise they see nothing. A ?project_id= narrows but
	// must stay within their granted set.
	if len(access.ProjectIDs) == 0 {
		f.SecretIDs = []uuid.UUID{}
		return nil
	}
	target := access.ProjectIDs
	if queryProjectID != nil {
		if !containsUUID(access.ProjectIDs, *queryProjectID) {
			return fiber.NewError(fiber.StatusForbidden,
				"project_id is not in caller's accessible projects")
		}
		target = []uuid.UUID{*queryProjectID}
	}
	ids, err := h.bindings.ListSecretIDsForProjects(c.Context(), target)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	f.SecretIDs = nonNilUUIDs(ids)
	return nil
}

func nonNilUUIDs(in []uuid.UUID) []uuid.UUID {
	if in == nil {
		return []uuid.UUID{}
	}
	return in
}

func containsUUID(set []uuid.UUID, target uuid.UUID) bool {
	for _, u := range set {
		if u == target {
			return true
		}
	}
	return false
}

// Get handles GET /api/v1/secrets/:id.
func (h *Secrets) Get(c fiber.Ctx) error {
	id := c.Params("id")
	s, err := h.svc.Get(c.Context(), id)
	if err != nil {
		return secretsErr(err)
	}
	return c.JSON(secretToBody(s))
}

// filterFromQuery builds a SecretsListFilter from the request's query
// string. Repeated `label=key:value` params accumulate into ANDed
// containment predicates.
func filterFromQuery(c fiber.Ctx) storage.SecretsListFilter {
	f := storage.SecretsListFilter{
		ClusterName:     c.Query("cluster_name"),
		ProviderType:    c.Query("provider"),
		SecretRefPrefix: c.Query("ref_prefix"),
		Status:          storage.SecretStatus(c.Query("status")),
		Limit:           queryIntDefault(c, "limit", 100),
		Offset:          queryIntDefault(c, "offset", 0),
	}
	for _, raw := range labelQueryValues(c) {
		k, v, ok := strings.Cut(raw, ":")
		if !ok || k == "" {
			continue
		}
		if f.LabelEquals == nil {
			f.LabelEquals = map[string]string{}
		}
		f.LabelEquals[k] = v
	}
	return f
}

// labelQueryValues returns every `label=...` value. Fiber v3's
// c.Query returns only the first value; Context().QueryArgs() exposes
// the multi-value variant.
func labelQueryValues(c fiber.Ctx) []string {
	out := []string{}
	for k, v := range c.RequestCtx().QueryArgs().All() {
		if string(k) == "label" {
			out = append(out, string(v))
		}
	}
	return out
}

func queryIntDefault(c fiber.Ctx, name string, def int) int {
	v := fiber.Query(c, name, def)
	if v < 0 {
		return 0
	}
	return v
}

func secretToBody(s *storage.Secret) SecretBody {
	return SecretBody{
		ID:              s.ID.String(),
		ClusterName:     s.ClusterName,
		ProviderType:    s.ProviderType,
		SecretRef:       s.SecretRef,
		ProviderConfig:  s.ProviderConfig,
		Labels:          s.Labels,
		Version:         s.Version,
		Checksum:        s.Checksum,
		CreatedAtSource: s.CreatedAtSource,
		UpdatedAtSource: s.UpdatedAtSource,
		Status:          string(s.Status),
		FirstSeenAt:     s.FirstSeenAt,
		LastSeenAt:      s.LastSeenAt,
	}
}
