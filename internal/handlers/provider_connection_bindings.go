// EPIC Q (api#99) Slice Q2 — project-anchored scoped bind / unbind /
// list endpoints. Wires the LOCKED §3 gate chains from Q1 into HTTP,
// with stable {error_code, message, ...} envelopes per §4 and three
// Prometheus counters per §6.
//
// Routing:
//
//   POST   /projects/:projectID/provider-connection-bindings
//   GET    /projects/:projectID/provider-connection-bindings[?environment_id=...]
//   DELETE /projects/:projectID/provider-connection-bindings/:bindingID
//
// Auth path-pinned: every route requires integration.bind scoped to
// (project, env). The existing admin routes on /provider-connections
// stay on integration.edit unchanged. URL hierarchy expresses the
// permission split at the route level so a future PR can't accidentally
// loosen one path while reviewing the other.

package handlers

import (
	"encoding/json"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ---- Prometheus counters (per §6 Q16 lock) ------------------------

var (
	bindingsCreatedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "provider_connection_bindings_created_total",
			Help: "Successful provider connection bindings created, by the actor's permission path and the binding environment's kind.",
		},
		// LOW-CARDINALITY ONLY: NEVER include actor_id, project_id,
		// connection_id, or environment_id labels. Per §6 lock.
		[]string{"permission_used", "env_kind"},
	)
	bindingsDeletedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "provider_connection_bindings_deleted_total",
			Help: "Successful provider connection bindings deleted, by the actor's permission path and the binding environment's kind.",
		},
		[]string{"permission_used", "env_kind"},
	)
	bindingsDeniedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "provider_connection_bindings_denied_total",
			Help: "Provider connection bind / unbind attempts denied, by reason. Fixed reason set per §6 — never carries IDs.",
		},
		[]string{"reason"},
	)
)

// denialReasons is the fixed set §6 locked. Anything outside this
// table is bucketed to "other" to keep cardinality bounded.
const (
	denialOutOfScope               = "out_of_scope"
	denialProdBlocked              = "prod_blocked"
	denialNotSelfServiceBindable   = "not_self_service_bindable"
	denialConnectionDisabled       = "connection_disabled"
	denialConnectionNotFound       = "connection_not_found"
	denialEnvNotInProject          = "env_not_in_project"
	denialBindingExists            = "binding_exists"
	denialBindingNotFound          = "binding_not_found"
)

// denialReasonFor maps a service-layer sentinel to its low-cardinality
// counter reason. Returns empty string when the error doesn't map to
// a known reason (caller skips the counter increment).
func denialReasonFor(err error) string {
	switch {
	case errors.Is(err, services.ErrOutOfScopeBinding):
		return denialOutOfScope
	case errors.Is(err, services.ErrProdBindingNotAllowedForScope):
		return denialProdBlocked
	case errors.Is(err, services.ErrConnectionNotSelfServiceBindable):
		return denialNotSelfServiceBindable
	case errors.Is(err, services.ErrConnectionDisabled):
		return denialConnectionDisabled
	case errors.Is(err, storage.ErrConnectionNotFound):
		return denialConnectionNotFound
	case errors.Is(err, services.ErrEnvironmentNotInProject):
		return denialEnvNotInProject
	case errors.Is(err, storage.ErrBindingExists):
		return denialBindingExists
	case errors.Is(err, storage.ErrBindingNotFound):
		return denialBindingNotFound
	}
	return ""
}

// ---- handler type --------------------------------------------------

// ProjectProviderConnectionBindings owns the project-anchored scoped
// bind / unbind / list routes. Held on a dedicated struct (separate
// from the EPIC P ProviderConnections handler) so the §3 mental model
// "scoped binding is project-ownership work, not platform registry
// administration" is visible at the codebase level.
type ProjectProviderConnectionBindings struct {
	svc *services.ProviderConnectionsService
}

// NewProjectProviderConnectionBindings constructs the handler.
func NewProjectProviderConnectionBindings(svc *services.ProviderConnectionsService) *ProjectProviderConnectionBindings {
	return &ProjectProviderConnectionBindings{svc: svc}
}

// ---- request / response shapes ------------------------------------

type scopedBindBody struct {
	ProviderConnectionID string `json:"provider_connection_id"`
	EnvironmentID        string `json:"environment_id"`
}

// projectBindingProjection mirrors storage.ProjectBindingDetail with
// API-facing JSON tags. Sanitized — no scope, no auth_method, no
// discovery fields, no created_by.
type projectBindingProjection struct {
	ID                   uuid.UUID `json:"id"`
	ProviderConnectionID uuid.UUID `json:"provider_connection_id"`
	ProjectID            uuid.UUID `json:"project_id"`
	EnvironmentID        *string   `json:"environment_id"`
	EnvironmentName      string    `json:"environment_name,omitempty"`
	EnvironmentKind      string    `json:"environment_kind,omitempty"`
	ConnectionName       string    `json:"connection_name"`
	ConnectionType       string    `json:"connection_type"`
	Purpose              string    `json:"purpose"`
	CreatedAt            string    `json:"created_at"`
}

func toProjectBindingProjection(d storage.ProjectBindingDetail) projectBindingProjection {
	var envIDPtr *string
	if d.EnvironmentID != nil {
		s := d.EnvironmentID.String()
		envIDPtr = &s
	}
	return projectBindingProjection{
		ID:                   d.ID,
		ProviderConnectionID: d.ProviderConnectionID,
		ProjectID:            d.ProjectID,
		EnvironmentID:        envIDPtr,
		EnvironmentName:      d.EnvironmentName,
		EnvironmentKind:      string(d.EnvironmentKind),
		ConnectionName:       d.ConnectionName,
		ConnectionType:       string(d.ConnectionType),
		Purpose:              string(d.Purpose),
		CreatedAt:            d.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

// ---- handlers ------------------------------------------------------

// Create handles POST /projects/:projectID/provider-connection-bindings.
// The scoped (gate-chain) path. Auth is integration.bind scoped to
// (projectID, environment_id from body).
func (h *ProjectProviderConnectionBindings) Create(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("projectID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"projectID is malformed", nil)
	}
	var body scopedBindBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"request body is not valid JSON", nil)
	}
	if body.EnvironmentID == "" {
		return stableErr(c, fiber.StatusBadRequest,
			"environment_id_required",
			"scoped binders must supply an environment_id", nil)
	}
	envID, err := uuid.Parse(body.EnvironmentID)
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"environment_id is malformed", nil)
	}
	connID, err := uuid.Parse(body.ProviderConnectionID)
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"provider_connection_id is malformed", nil)
	}

	b, err := h.svc.BindForScopedActor(c.Context(), services.BindForScopedActorInput{
		ConnectionID:  connID,
		ProjectID:     projectID,
		EnvironmentID: envID,
		ActorID:       identityFromCtx(c),
		CorrelationID: uuid.New(),
	})
	if err != nil {
		if reason := denialReasonFor(err); reason != "" {
			bindingsDeniedTotal.WithLabelValues(reason).Inc()
		}
		return mapServiceErr(c, err)
	}

	// Service has already emitted the binding.create audit. Counter:
	// scoped path always = integration.bind; env_kind is non_prod
	// because scoped bind refuses prod at gate 3.
	bindingsCreatedTotal.WithLabelValues(
		string(auth.PermIntegrationBind),
		string(storage.EnvironmentKindNonProd),
	).Inc()

	envIDStr := b.EnvironmentID.String()
	return c.Status(fiber.StatusCreated).JSON(projectBindingProjection{
		ID:                   b.ID,
		ProviderConnectionID: b.ProviderConnectionID,
		ProjectID:            b.ProjectID,
		EnvironmentID:        &envIDStr,
		Purpose:              string(b.Purpose),
		CreatedAt:            b.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
}

// List handles GET /projects/:projectID/provider-connection-bindings.
// Returns the project's bindings joined with environment + connection
// metadata for the SPA's per-project card. Optional ?environment_id
// narrows to env-specific + project-wide for one env.
//
// Auth: integration.bind OR integration.edit. Same projection for
// both — the §5 lock keeps scope / auth_method / discovery fields out
// regardless of permission.
func (h *ProjectProviderConnectionBindings) List(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("projectID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"projectID is malformed", nil)
	}
	var envFilter *uuid.UUID
	if s := c.Query("environment_id"); s != "" {
		envID, err := uuid.Parse(s)
		if err != nil {
			return stableErr(c, fiber.StatusBadRequest, "bad_request",
				"environment_id is malformed", nil)
		}
		envFilter = &envID
	}
	rows, err := h.svc.ListForProject(c.Context(), projectID, envFilter)
	if err != nil {
		return mapServiceErr(c, err)
	}
	out := make([]projectBindingProjection, 0, len(rows))
	for _, r := range rows {
		out = append(out, toProjectBindingProjection(r))
	}
	return c.JSON(out)
}

// Delete handles DELETE /projects/:projectID/provider-connection-bindings/:bindingID.
// Scoped path: integration.bind scoped to the binding's (project, env).
// The §4 correction: if the binding exists under a DIFFERENT project,
// we return binding_not_found, NOT out_of_scope_binding — the latter
// would leak that the binding exists under another project.
func (h *ProjectProviderConnectionBindings) Delete(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("projectID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"projectID is malformed", nil)
	}
	bindingID, err := uuid.Parse(c.Params("bindingID"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"bindingID is malformed", nil)
	}

	if err := h.svc.UnbindForScopedActor(c.Context(), services.UnbindForScopedActorInput{
		BindingID:     bindingID,
		ProjectID:     projectID,
		ActorID:       identityFromCtx(c),
		CorrelationID: uuid.New(),
	}); err != nil {
		if reason := denialReasonFor(err); reason != "" {
			bindingsDeniedTotal.WithLabelValues(reason).Inc()
		}
		return mapServiceErr(c, err)
	}

	// Scoped unbind always succeeds with env_kind=non_prod (gate 3
	// refuses prod on this path; admin prod unbinds go through the
	// existing /provider-connection-bindings/:id route).
	bindingsDeletedTotal.WithLabelValues(
		string(auth.PermIntegrationBind),
		string(storage.EnvironmentKindNonProd),
	).Inc()
	return c.SendStatus(fiber.StatusNoContent)
}
