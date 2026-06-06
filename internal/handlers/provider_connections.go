// Package handlers — provider_connections.go: HTTP layer for the
// provider_connections admin API + developer dropdown (EPIC P / P3).
//
// Endpoints under /api/v1 (with the gating each path uses inline —
// route registration in cmd/api/main.go uses the matching middleware
// for static paths; ListOrDropdown branches on query string + does
// its own auth):
//
//   Admin (integration.edit, global scope):
//     POST   /provider-connections                          create
//     GET    /provider-connections/:id                      get (full projection)
//     PUT    /provider-connections/:id                      update
//     DELETE /provider-connections/:id                      delete
//     POST   /provider-connections/:id/discover-now         enqueue discover
//     POST   /provider-connections/:id/bindings             bind to project/env
//     GET    /provider-connections/:id/bindings             list bindings
//     DELETE /provider-connection-bindings/:binding_id      unbind
//
//   Shared (branches on query string):
//     GET    /provider-connections                          admin list OR dev dropdown
//
// Hard rules:
//   - Response shape is always {error_code, message[, extra…]}.
//   - Dropdown projection is {id, name, type} only — no scope,
//     no auth_method, no discovery fields, no timestamps.
//   - Admin paths require integration.edit; dropdown requires
//     secret.request scoped to the (project, environment) chain.

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ProviderConnections groups the HTTP routes for the provider_connections
// admin + dropdown surface.
type ProviderConnections struct {
	svc      *services.ProviderConnectionsService
	jobs     services.JobEnqueuer
	rdb      *runtime.Client       // for the discover-now per-target lock
	resolver auth.Resolver         // for the shared GET branching
	envs     services.CrossTeamEnvLookup // for ScopeFromEnvironment lookup
}

// NewProviderConnections wires the handler. jobs + rdb are required
// for /discover-now; resolver + envs are required for ListOrDropdown's
// inline auth check.
func NewProviderConnections(
	svc *services.ProviderConnectionsService,
	jobs services.JobEnqueuer,
	rdb *runtime.Client,
	resolver auth.Resolver,
	envs services.CrossTeamEnvLookup,
) *ProviderConnections {
	return &ProviderConnections{
		svc:      svc,
		jobs:     jobs,
		rdb:      rdb,
		resolver: resolver,
		envs:     envs,
	}
}

// ---- wire shapes ---------------------------------------------------

// createBody is the create + update wire shape. Type is ignored on
// update (immutable post-create) but accepted on the wire for
// simplicity; the service Update method preserves the stored Type.
type createBody struct {
	Name                    string            `json:"name"`
	Type                    string            `json:"type"`
	AuthMethod              string            `json:"auth_method"`
	Scope                   map[string]string `json:"scope"`
	ClusterName             string            `json:"cluster_name"`
	Description             string            `json:"description"`
	Status                  string            `json:"status"`
	DiscoverEnabled         bool              `json:"discover_enabled"`
	DiscoverIntervalSeconds int               `json:"discover_interval_seconds"`
}

// adminProjection is the full admin response shape. Echoes every
// column on provider_connections.
type adminProjection struct {
	ID                      uuid.UUID         `json:"id"`
	Name                    string            `json:"name"`
	Type                    string            `json:"type"`
	AuthMethod              string            `json:"auth_method"`
	Scope                   map[string]string `json:"scope"`
	Status                  string            `json:"status"`
	ClusterName             string            `json:"cluster_name,omitempty"`
	Description             string            `json:"description,omitempty"`
	DiscoverEnabled         bool              `json:"discover_enabled"`
	DiscoverIntervalSeconds int               `json:"discover_interval_seconds"`
	LastDiscoverAt          *time.Time        `json:"last_discover_at,omitempty"`
	LastDiscoverStatus      string            `json:"last_discover_status,omitempty"`
	LastDiscoverError       string            `json:"last_discover_error,omitempty"`
	LastDiscoverStartedAt   *time.Time        `json:"last_discover_started_at,omitempty"`
	LastDiscoverFinishedAt  *time.Time        `json:"last_discover_finished_at,omitempty"`
	CreatedAt               time.Time         `json:"created_at"`
	UpdatedAt               time.Time         `json:"updated_at"`
}

// dropdownProjection is the sanitized developer response. NO scope,
// NO auth_method, NO discovery fields, NO timestamps.
type dropdownProjection struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Type string    `json:"type"`
}

func toAdminProjection(pc *storage.ProviderConnection) adminProjection {
	return adminProjection{
		ID:                      pc.ID,
		Name:                    pc.Name,
		Type:                    string(pc.Type),
		AuthMethod:              pc.AuthMethod,
		Scope:                   pc.Scope,
		Status:                  string(pc.Status),
		ClusterName:             pc.ClusterName,
		Description:             pc.Description,
		DiscoverEnabled:         pc.DiscoverEnabled,
		DiscoverIntervalSeconds: pc.DiscoverIntervalSeconds,
		LastDiscoverAt:          pc.LastDiscoverAt,
		LastDiscoverStatus:      pc.LastDiscoverStatus,
		LastDiscoverError:       pc.LastDiscoverError,
		LastDiscoverStartedAt:   pc.LastDiscoverStartedAt,
		LastDiscoverFinishedAt:  pc.LastDiscoverFinishedAt,
		CreatedAt:               pc.CreatedAt,
		UpdatedAt:               pc.UpdatedAt,
	}
}

type bindBody struct {
	ProjectID     string `json:"project_id"`
	EnvironmentID string `json:"environment_id"`
	Purpose       string `json:"purpose"`
}

type bindingProjection struct {
	ID                   uuid.UUID `json:"id"`
	ProjectID            uuid.UUID `json:"project_id"`
	EnvironmentID        *uuid.UUID `json:"environment_id,omitempty"`
	ProviderConnectionID uuid.UUID `json:"provider_connection_id"`
	Purpose              string    `json:"purpose"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	CreatedBy            string    `json:"created_by,omitempty"`
}

func toBindingProjection(b *storage.ProjectProviderConnectionBinding) bindingProjection {
	return bindingProjection{
		ID:                   b.ID,
		ProjectID:            b.ProjectID,
		EnvironmentID:        b.EnvironmentID,
		ProviderConnectionID: b.ProviderConnectionID,
		Purpose:              string(b.Purpose),
		CreatedAt:            b.CreatedAt,
		UpdatedAt:            b.UpdatedAt,
		CreatedBy:            b.CreatedBy,
	}
}

// ---- error envelope ------------------------------------------------

// stableErr writes the §6-locked response shape {error_code, message,
// ...extra} with the given HTTP status. Returns nil so callers
// `return stableErr(...)` is a clean Fiber-idiomatic terminate; the
// JSON body has already been written.
//
// Use this from handlers that have NOTHING ELSE TO DO after calling
// it. For helpers (auth checks) that need to signal "I already wrote
// a response, please stop", use respondedFlag below.
func stableErr(c fiber.Ctx, status int, code, message string, extra map[string]any) error {
	body := map[string]any{
		"error_code": code,
		"message":    message,
	}
	for k, v := range extra {
		body[k] = v
	}
	return c.Status(status).JSON(body)
}

// respondedFlagKey marks the Fiber context locals so an outer handler
// can detect that an inline helper (requireScoped, requirePermission)
// already wrote a response. Callers do:
//
//	if err := h.requireScoped(...); err != nil || responded(c) {
//	    return err
//	}
const respondedFlagKey = "sb:pc:responded"

func markResponded(c fiber.Ctx) { c.Locals(respondedFlagKey, true) }
func responded(c fiber.Ctx) bool {
	v, _ := c.Locals(respondedFlagKey).(bool)
	return v
}

// mapServiceErr translates a service-layer sentinel into the
// {error_code, message, ...} envelope. Returns the Fiber response or
// fiber.NewError when the err is unknown to this map (caller wraps
// it as a 500).
func mapServiceErr(c fiber.Ctx, err error) error {
	// Storage-layer sentinels first.
	switch {
	case errors.Is(err, storage.ErrConnectionNotFound):
		return stableErr(c, fiber.StatusNotFound,
			"connection_not_found",
			"provider connection not found", nil)
	case errors.Is(err, storage.ErrConnectionNameTaken):
		return stableErr(c, fiber.StatusConflict,
			"connection_name_taken",
			"a provider connection with this name already exists", nil)
	case errors.Is(err, storage.ErrConnectionInUse):
		return stableErr(c, fiber.StatusConflict,
			"connection_in_use",
			"provider connection is referenced by bindings or open requests", nil)
	case errors.Is(err, storage.ErrInvalidDiscoverStatus):
		return stableErr(c, fiber.StatusBadRequest,
			"invalid_discover_status",
			"discover status must be success or failure", nil)
	case errors.Is(err, storage.ErrBindingExists):
		return stableErr(c, fiber.StatusConflict,
			"binding_exists",
			"this binding already exists", nil)
	case errors.Is(err, storage.ErrBindingNotFound):
		return stableErr(c, fiber.StatusNotFound,
			"binding_not_found",
			"binding not found", nil)
	}

	// Service-layer ValidationDetail with metadata.
	var d *services.ValidationDetail
	if errors.As(err, &d) {
		switch {
		case errors.Is(d.Err, services.ErrCredentialShapedKey):
			return stableErr(c, fiber.StatusBadRequest,
				"credential_in_scope",
				"scope contains a credential-shaped key",
				map[string]any{"banned_key": d.BannedKey})
		case errors.Is(d.Err, services.ErrSecretShapedValue):
			return stableErr(c, fiber.StatusBadRequest,
				"secret_in_scope",
				"a scope value looks like a credential",
				map[string]any{"field": d.Field})
		case errors.Is(d.Err, services.ErrInvalidProviderURL):
			return stableErr(c, fiber.StatusBadRequest,
				"invalid_provider_url",
				"provider URL is malformed or contains credentials",
				map[string]any{"field": d.Field, "reason": d.Reason})
		case errors.Is(d.Err, services.ErrInvalidRoleArn):
			return stableErr(c, fiber.StatusBadRequest,
				"invalid_role_arn",
				"AWS role ARN is malformed", nil)
		case errors.Is(d.Err, services.ErrDescriptionTooLong):
			return stableErr(c, fiber.StatusBadRequest,
				"description_too_long",
				"description exceeds 500 characters",
				map[string]any{"length": d.Length, "cap": d.Cap})
		case errors.Is(d.Err, services.ErrInvalidScope):
			extra := map[string]any{}
			if len(d.MissingKeys) > 0 {
				extra["missing_keys"] = d.MissingKeys
			}
			if len(d.UnknownKeys) > 0 {
				extra["unknown_keys"] = d.UnknownKeys
			}
			return stableErr(c, fiber.StatusBadRequest,
				"invalid_scope",
				"scope is missing required keys or has unknown keys", extra)
		case errors.Is(d.Err, services.ErrDiscoverRequiresCluster):
			return stableErr(c, fiber.StatusBadRequest,
				"discover_requires_cluster",
				"discover_enabled requires cluster_name", nil)
		case errors.Is(d.Err, services.ErrInvalidDiscoverInterval):
			return stableErr(c, fiber.StatusBadRequest,
				"invalid_discover_interval",
				"discover_interval_seconds must be between 60 and 86400", nil)
		case errors.Is(d.Err, services.ErrInvalidName):
			return stableErr(c, fiber.StatusBadRequest,
				"invalid_name",
				"name must match ^[a-z0-9][a-z0-9-]{0,119}$", nil)
		case errors.Is(d.Err, services.ErrInvalidAuthMethod):
			return stableErr(c, fiber.StatusBadRequest,
				"invalid_auth_method",
				"auth_method is not allowed for this provider type", nil)
		case errors.Is(d.Err, services.ErrInvalidClusterName):
			return stableErr(c, fiber.StatusBadRequest,
				"invalid_cluster_name",
				"cluster_name must match the name regex", nil)
		}
	}

	// Service-layer sentinels that have no detail.
	switch {
	case errors.Is(err, services.ErrConnectionDisabled):
		return stableErr(c, fiber.StatusConflict,
			"connection_disabled",
			"provider connection is disabled", nil)
	case errors.Is(err, services.ErrEnvironmentNotInProject):
		return stableErr(c, fiber.StatusBadRequest,
			"environment_not_in_project",
			"environment does not belong to project", nil)
	}

	// Unknown — caller bubbles as a 500.
	return fiber.NewError(fiber.StatusInternalServerError, err.Error())
}

// ---- admin CRUD ---------------------------------------------------

// Create validates + persists a new provider_connections row.
func (h *ProviderConnections) Create(c fiber.Ctx) error {
	var body createBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"request body is not valid JSON", nil)
	}
	in := services.CreateInput{
		Name:                    body.Name,
		Type:                    storage.ProviderConnectionType(body.Type),
		AuthMethod:              body.AuthMethod,
		Scope:                   body.Scope,
		Status:                  storage.ProviderConnectionStatus(body.Status),
		ClusterName:             body.ClusterName,
		Description:             body.Description,
		DiscoverEnabled:         body.DiscoverEnabled,
		DiscoverIntervalSeconds: body.DiscoverIntervalSeconds,
		ActorID:                 identityFromCtx(c),
		CorrelationID:           uuid.New(),
	}
	row, err := h.svc.Create(c.Context(), in)
	if err != nil {
		return mapServiceErr(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(toAdminProjection(row))
}

// Get returns a single provider_connections row by id (admin only).
func (h *ProviderConnections) Get(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"invalid id", nil)
	}
	row, err := h.svc.Get(c.Context(), id)
	if err != nil {
		return mapServiceErr(c, err)
	}
	return c.JSON(toAdminProjection(row))
}

// Update mutates an existing connection. Type is service-side immutable.
func (h *ProviderConnections) Update(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request", "invalid id", nil)
	}
	var body createBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"request body is not valid JSON", nil)
	}
	in := services.UpdateInput{
		Name:                    body.Name,
		AuthMethod:              body.AuthMethod,
		Scope:                   body.Scope,
		Status:                  storage.ProviderConnectionStatus(body.Status),
		ClusterName:             body.ClusterName,
		Description:             body.Description,
		DiscoverEnabled:         body.DiscoverEnabled,
		DiscoverIntervalSeconds: body.DiscoverIntervalSeconds,
		ActorID:                 identityFromCtx(c),
		CorrelationID:           uuid.New(),
	}
	row, err := h.svc.Update(c.Context(), id, in)
	if err != nil {
		return mapServiceErr(c, err)
	}
	return c.JSON(toAdminProjection(row))
}

// Delete pre-flights the in-use check and persists when both counts
// are zero. 409 connection_in_use response carries the counts so the
// admin UI can render "In use by N bindings + M open requests".
func (h *ProviderConnections) Delete(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request", "invalid id", nil)
	}
	counts, err := h.svc.Delete(c.Context(), id, identityFromCtx(c), uuid.New())
	if err != nil {
		if errors.Is(err, storage.ErrConnectionInUse) {
			return stableErr(c, fiber.StatusConflict,
				"connection_in_use",
				"provider connection is referenced by bindings or open requests",
				map[string]any{
					"bindings_count":      counts.BindingsCount,
					"open_requests_count": counts.OpenRequestsCount,
				})
		}
		return mapServiceErr(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// DiscoverNow enqueues a single discover job out-of-cadence. Refuses
// disabled connections + connections without cluster_name. Uses the
// per-target Redis lock as the rate limit.
func (h *ProviderConnections) DiscoverNow(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request", "invalid id", nil)
	}
	row, err := h.svc.Get(c.Context(), id)
	if err != nil {
		return mapServiceErr(c, err)
	}
	if row.Status == storage.ProviderConnectionStatusDisabled {
		return stableErr(c, fiber.StatusConflict,
			"connection_disabled",
			"provider connection is disabled", nil)
	}
	if row.ClusterName == "" {
		return stableErr(c, fiber.StatusBadRequest,
			"discover_requires_cluster",
			"discover requires cluster_name", nil)
	}

	// Per-target Redis lock — same posture as the worker scheduler.
	// 60-second lease is a soft rate limit; the lock auto-expires.
	lockName := "discover:" + id.String()
	lock, lockErr := h.rdb.AcquireLock(c.Context(), lockName, 60*time.Second)
	if lockErr != nil {
		if errors.Is(lockErr, runtime.ErrLockHeld) {
			return stableErr(c, fiber.StatusConflict,
				"discovery_already_running",
				"a discovery run is already in progress for this connection", nil)
		}
		return mapServiceErr(c, lockErr)
	}
	// Lock is auto-released when the job's lifecycle ends; we don't
	// hold a Go-side reference to release after enqueue.
	_ = lock

	now := time.Now().UTC()
	if err := h.svc.MarkDiscoverStarted(c.Context(), id, now); err != nil {
		return mapServiceErr(c, err)
	}

	corrID := uuid.New()
	payload := map[string]any{
		"connection_id":         id.String(),
		"target_provider_type":  string(row.Type),
		"target_provider_config": row.Scope,
		"cluster_name":          row.ClusterName,
	}
	job, err := h.jobs.Enqueue(c.Context(), services.EnqueueRequest{
		AgentScope:    map[string]any{"cluster": row.ClusterName},
		JobType:       storage.JobTypeDiscover,
		Payload:       payload,
		CorrelationID: corrID,
	})
	if err != nil {
		// Roll back the running flip via finished+failure with a
		// sanitized message.
		_ = h.svc.MarkDiscoverFinished(c.Context(), id,
			storage.DiscoverStatusFailure, "enqueue failed", time.Now().UTC())
		return mapServiceErr(c, err)
	}

	return c.Status(fiber.StatusAccepted).JSON(map[string]any{
		"job_id":         job.ID,
		"correlation_id": corrID,
		"status":         "queued",
	})
}

// ---- bindings -----------------------------------------------------

// CreateBinding adds a project (+ optional env) binding.
func (h *ProviderConnections) CreateBinding(c fiber.Ctx) error {
	connID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request", "invalid id", nil)
	}
	var body bindBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"request body is not valid JSON", nil)
	}
	projectID, perr := uuid.Parse(body.ProjectID)
	if perr != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"project_id is required", nil)
	}
	var envIDPtr *uuid.UUID
	if body.EnvironmentID != "" {
		envID, eerr := uuid.Parse(body.EnvironmentID)
		if eerr != nil {
			return stableErr(c, fiber.StatusBadRequest, "bad_request",
				"environment_id is malformed", nil)
		}
		envIDPtr = &envID
	}
	in := services.BindInput{
		ConnectionID:  connID,
		ProjectID:     projectID,
		EnvironmentID: envIDPtr,
		Purpose:       storage.ProjectProviderConnectionPurpose(body.Purpose),
		ActorID:       identityFromCtx(c),
	}
	b, err := h.svc.Bind(c.Context(), in)
	if err != nil {
		return mapServiceErr(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(toBindingProjection(b))
}

// ListBindings returns every binding referencing the connection.
func (h *ProviderConnections) ListBindings(c fiber.Ctx) error {
	connID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request", "invalid id", nil)
	}
	rows, err := h.svc.ListBindings(c.Context(), connID)
	if err != nil {
		return mapServiceErr(c, err)
	}
	out := make([]bindingProjection, 0, len(rows))
	for _, r := range rows {
		out = append(out, toBindingProjection(r))
	}
	return c.JSON(out)
}

// DeleteBinding removes a binding by its own id.
func (h *ProviderConnections) DeleteBinding(c fiber.Ctx) error {
	bindingID, err := uuid.Parse(c.Params("binding_id"))
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request", "invalid id", nil)
	}
	if err := h.svc.Unbind(c.Context(), bindingID, identityFromCtx(c)); err != nil {
		return mapServiceErr(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ---- shared GET (admin list OR developer dropdown) ----------------

// ListOrDropdown branches on `project_id` query string per §4.B:
//
//   project_id absent + environment_id absent → admin list
//   project_id absent + environment_id present → 400 project_id_required
//   project_id present → dropdown projection (env-specific OR project-wide)
//
// Auth is checked inline because the same URL has two permission
// paths.
func (h *ProviderConnections) ListOrDropdown(c fiber.Ctx) error {
	projectIDStr := c.Query("project_id")
	envIDStr := c.Query("environment_id")

	if projectIDStr == "" {
		if envIDStr != "" {
			return stableErr(c, fiber.StatusBadRequest,
				"project_id_required",
				"environment_id requires project_id", nil)
		}
		// Admin path. Require integration.edit at global scope.
		if err := h.requirePermission(c, auth.PermIntegrationEdit); err != nil || responded(c) {
			return err
		}
		rows, err := h.svc.List(c.Context(),
			storage.ProviderConnectionListFilter{})
		if err != nil {
			return mapServiceErr(c, err)
		}
		out := make([]adminProjection, 0, len(rows))
		for _, r := range rows {
			out = append(out, toAdminProjection(r))
		}
		return c.JSON(out)
	}

	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"project_id is malformed", nil)
	}
	var envID uuid.UUID
	if envIDStr != "" {
		envID, err = uuid.Parse(envIDStr)
		if err != nil {
			return stableErr(c, fiber.StatusBadRequest, "bad_request",
				"environment_id is malformed", nil)
		}
	}

	// Dropdown path. Require secret.request scoped to the
	// (project, environment) chain. Resolve env name when present.
	envName := ""
	if envID != uuid.Nil && h.envs != nil {
		env, err := h.envs.Get(c.Context(), envID)
		if err == nil && env != nil {
			envName = env.Name
		}
	}
	reqScope := map[string]string{
		"project_id": projectID.String(),
	}
	if envName != "" {
		reqScope["environment"] = envName
	}
	if err := h.requireScoped(c, auth.PermSecretRequest, reqScope); err != nil || responded(c) {
		return err
	}

	rows, err := h.svc.ListForProjectEnv(c.Context(), projectID, envID)
	if err != nil {
		return mapServiceErr(c, err)
	}
	out := make([]dropdownProjection, 0, len(rows))
	for _, r := range rows {
		out = append(out, dropdownProjection{ID: r.ID, Name: r.Name, Type: string(r.Type)})
	}
	return c.JSON(out)
}

// requirePermission runs the global-scope check inline. Mirrors
// auth.Require but as a handler-internal call so the shared GET path
// can branch. Calls markResponded(c) before returning any
// not-authorised response so the outer handler short-circuits.
func (h *ProviderConnections) requirePermission(c fiber.Ctx, perm auth.Permission) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		markResponded(c)
		return stableErr(c, fiber.StatusUnauthorized,
			"unauthorized", "authentication required", nil)
	}
	if h.resolver == nil {
		markResponded(c)
		return stableErr(c, fiber.StatusInternalServerError,
			"server_error", "resolver not configured", nil)
	}
	grants, err := h.resolver.Resolve(c.Context(), userID)
	if err != nil {
		markResponded(c)
		return mapServiceErr(c, err)
	}
	for _, g := range grants {
		if g.Permission == string(perm) && len(g.Scope) == 0 {
			return nil
		}
	}
	markResponded(c)
	return stableErr(c, fiber.StatusForbidden,
		"forbidden",
		fmt.Sprintf("missing permission %q (global scope)", perm), nil)
}

// requireScoped runs the per-request scope check inline. Mirrors
// auth.RequireScoped. Same markResponded contract as requirePermission.
func (h *ProviderConnections) requireScoped(c fiber.Ctx, perm auth.Permission, reqScope map[string]string) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		markResponded(c)
		return stableErr(c, fiber.StatusUnauthorized,
			"unauthorized", "authentication required", nil)
	}
	if h.resolver == nil {
		markResponded(c)
		return stableErr(c, fiber.StatusInternalServerError,
			"server_error", "resolver not configured", nil)
	}
	grants, err := h.resolver.Resolve(c.Context(), userID)
	if err != nil {
		markResponded(c)
		return mapServiceErr(c, err)
	}
	for _, g := range grants {
		if g.Permission == string(perm) && scopeCoversInline(g.Scope, reqScope) {
			return nil
		}
	}
	markResponded(c)
	return stableErr(c, fiber.StatusForbidden,
		"out_of_scope_project",
		"caller is out of scope for this project", nil)
}

// scopeCoversInline is a local copy of auth.scopeCovers so the
// inline handler doesn't need to export it from the auth package.
// Empty user scope covers every request.
func scopeCoversInline(user, request map[string]string) bool {
	if len(user) == 0 {
		return true
	}
	for k, v := range user {
		got, ok := request[k]
		if !ok {
			return false
		}
		if k == "secret_ref_prefix" {
			if !strings.HasPrefix(got, v) {
				return false
			}
			continue
		}
		if got != v {
			return false
		}
	}
	return true
}

// identityFromCtx returns the caller's identity string or "admin"
// when not set (e.g. legacy callers during the auth-middleware
// transition).
func identityFromCtx(c fiber.Ctx) string {
	if id, ok := auth.IdentityFromContext(c.Context()); ok && id != "" {
		return id
	}
	return "admin"
}

// silence unused-import noise during incremental editing.
var _ = context.Background
