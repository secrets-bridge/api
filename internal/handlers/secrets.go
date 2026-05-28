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

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Secrets is the HTTP layer over SecretsService.
type Secrets struct {
	svc *services.SecretsService
}

// NewSecrets binds the handler.
func NewSecrets(svc *services.SecretsService) *Secrets { return &Secrets{svc: svc} }

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
func (h *Secrets) List(c fiber.Ctx) error {
	f := filterFromQuery(c)
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
	c.RequestCtx().QueryArgs().VisitAll(func(k, v []byte) {
		if string(k) == "label" {
			out = append(out, string(v))
		}
	})
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
