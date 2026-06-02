// Package handlers — tenancy.go: admin CRUD for the tenancy entities
// projects + environments. These pre-existed in the schema (BRD §17,
// migration 0001) but had no HTTP surface; this handler wires it.
//
// Endpoints mounted under /api/v1 by main:
//
//   POST   /projects                       create project
//   GET    /projects                       list projects
//   GET    /projects/:id                   get project
//   PUT    /projects/:id/status            update status (active|archived)
//   GET    /projects/:id/environments      list a project's environments
//
//   POST   /environments                   create environment under a project
//   GET    /environments                   list every environment (flat)
//   GET    /environments/:id               get environment
//   PUT    /environments/:id               update description + risk_level
//                                          (Slice L1 — kind and name immutable)
//   DELETE /environments/:id               hard-delete environment
//
// Design notes:
//
//   - Projects use a soft-delete model (archive via status flip).
//     Hard-delete cascades to environments via the FK with ON DELETE
//     CASCADE, which would be surprising operationally; archive is
//     safer.
//
//   - Environments DO hard-delete. They're cheap to recreate and
//     don't own downstream rows (the user_roles.scope reference is
//     by-name, not FK).
//
//   - Per-project environment listing is exposed for the UI's
//     Projects detail view; a flat List is exposed for the
//     Integrations form's environment dropdown.
//
//   - Slice L1 added `kind` (non_prod/prod) + `risk_level` (0-4) +
//     `description` to environments. `kind` is the hard safety
//     boundary the PolicyEngine consults (Slice L2). Mutability is
//     deliberately narrow: only description + risk_level can be
//     changed post-create. Operators wanting to flip kind must
//     delete + recreate.
package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Tenancy bundles the projects + environments repositories behind one
// handler so route registration stays compact.
type Tenancy struct {
	projects     storage.ProjectRepository
	environments storage.EnvironmentRepository
}

// NewTenancy wires the handler.
func NewTenancy(p storage.ProjectRepository, e storage.EnvironmentRepository) *Tenancy {
	return &Tenancy{projects: p, environments: e}
}

// --- projects --------------------------------------------------------

type projectBody struct {
	ID          uuid.UUID  `json:"id,omitempty"`
	Name        string     `json:"name"`
	OwnerTeamID string     `json:"owner_team_id,omitempty"`
	TeamID      *uuid.UUID `json:"team_id"`
	Status      string     `json:"status,omitempty"`
	CreatedAt   time.Time  `json:"created_at,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at,omitempty"`
}

func projectToBody(p *storage.Project) projectBody {
	return projectBody{
		ID:          p.ID,
		Name:        p.Name,
		OwnerTeamID: p.OwnerTeamID,
		TeamID:      p.TeamID,
		Status:      string(p.Status),
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

// CreateProject handles POST /projects.
func (h *Tenancy) CreateProject(c fiber.Ctx) error {
	var body projectBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	p := &storage.Project{
		Name:        body.Name,
		OwnerTeamID: body.OwnerTeamID,
		TeamID:      body.TeamID,
		Status:      storage.ProjectStatusActive,
	}
	if body.Status != "" {
		p.Status = storage.ProjectStatus(body.Status)
	}
	if err := h.projects.Create(c.Context(), p); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(projectToBody(p))
}

// SetProjectTeam handles PUT /projects/:id/team — reassigns the
// project's team_id (the typed FK introduced by 0018). Body shape:
// `{"team_id": "<uuid>"}` or `{"team_id": null}` to un-scope.
func (h *Tenancy) SetProjectTeam(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid id")
	}
	var body struct {
		TeamID *uuid.UUID `json:"team_id"`
	}
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if err := h.projects.SetTeam(c.Context(), id, body.TeamID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ListProjects handles GET /projects.
func (h *Tenancy) ListProjects(c fiber.Ctx) error {
	rows, err := h.projects.List(c.Context())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	out := make([]projectBody, 0, len(rows))
	for _, p := range rows {
		out = append(out, projectToBody(p))
	}
	return c.JSON(out)
}

// GetProject handles GET /projects/:id.
func (h *Tenancy) GetProject(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	p, err := h.projects.Get(c.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "project not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.JSON(projectToBody(p))
}

type projectStatusBody struct {
	Status string `json:"status"`
}

// UpdateProjectStatus handles PUT /projects/:id/status.
func (h *Tenancy) UpdateProjectStatus(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	var body projectStatusBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	switch storage.ProjectStatus(body.Status) {
	case storage.ProjectStatusActive, storage.ProjectStatusArchived:
		// ok
	default:
		return fiber.NewError(fiber.StatusBadRequest, "status must be active or archived")
	}
	if err := h.projects.UpdateStatus(c.Context(), id, storage.ProjectStatus(body.Status)); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "project not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ListEnvironmentsForProject handles GET /projects/:id/environments.
func (h *Tenancy) ListEnvironmentsForProject(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	rows, err := h.environments.ListByProject(c.Context(), id)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	out := make([]environmentBody, 0, len(rows))
	for _, e := range rows {
		out = append(out, environmentToBody(e))
	}
	return c.JSON(out)
}

// --- environments ----------------------------------------------------

type environmentBody struct {
	ID          uuid.UUID `json:"id,omitempty"`
	ProjectID   uuid.UUID `json:"project_id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Kind        string    `json:"kind,omitempty"`
	RiskLevel   int       `json:"risk_level,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

func environmentToBody(e *storage.Environment) environmentBody {
	return environmentBody{
		ID: e.ID, ProjectID: e.ProjectID,
		Name: e.Name, Type: string(e.Type),
		Kind:        string(e.Kind),
		RiskLevel:   e.RiskLevel,
		Description: e.Description,
		CreatedAt:   e.CreatedAt, UpdatedAt: e.UpdatedAt,
	}
}

// CreateEnvironment handles POST /environments.
//
// Slice L1: body may include `kind` (non_prod|prod) and `risk_level`
// (0-4) and `description`. When `kind` is omitted, it is derived
// from `type` via storage.DeriveKindFromType. Operators set `kind`
// explicitly when the lifecycle label (`type`) does not match the
// real risk posture (e.g. `type=staging` but the env carries
// customer data, so `kind=prod`).
func (h *Tenancy) CreateEnvironment(c fiber.Ctx) error {
	var body environmentBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.ProjectID == uuid.Nil || body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "project_id and name are required")
	}
	switch storage.EnvironmentType(body.Type) {
	case storage.EnvironmentTypeDev,
		storage.EnvironmentTypeStaging,
		storage.EnvironmentTypeUAT,
		storage.EnvironmentTypeProd,
		storage.EnvironmentTypeOther,
		storage.EnvironmentType(""):
		// ok; empty defaults to "other" in storage
	default:
		return fiber.NewError(fiber.StatusBadRequest, "type must be one of dev|staging|uat|prod|other")
	}
	switch storage.EnvironmentKind(body.Kind) {
	case storage.EnvironmentKindNonProd,
		storage.EnvironmentKindProd,
		storage.EnvironmentKind(""):
		// ok; empty derives from type in storage
	default:
		return fiber.NewError(fiber.StatusBadRequest, "kind must be non_prod or prod")
	}
	if body.RiskLevel < 0 || body.RiskLevel > 4 {
		return fiber.NewError(fiber.StatusBadRequest, "risk_level must be between 0 and 4")
	}
	e := &storage.Environment{
		ProjectID:   body.ProjectID,
		Name:        body.Name,
		Type:        storage.EnvironmentType(body.Type),
		Kind:        storage.EnvironmentKind(body.Kind),
		RiskLevel:   body.RiskLevel,
		Description: body.Description,
	}
	if err := h.environments.Create(c.Context(), e); err != nil {
		if errors.Is(err, storage.ErrDuplicateName) {
			return fiber.NewError(fiber.StatusConflict, "environment with this name already exists in the project")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(environmentToBody(e))
}

// ListEnvironments handles GET /environments. Flat list across all
// projects. Useful for the Integrations form's environment dropdown.
func (h *Tenancy) ListEnvironments(c fiber.Ctx) error {
	rows, err := h.environments.List(c.Context())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	out := make([]environmentBody, 0, len(rows))
	for _, e := range rows {
		out = append(out, environmentToBody(e))
	}
	return c.JSON(out)
}

// GetEnvironment handles GET /environments/:id.
func (h *Tenancy) GetEnvironment(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	e, err := h.environments.Get(c.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "environment not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.JSON(environmentToBody(e))
}

// environmentUpdateBody is the narrow input for UpdateEnvironment.
// Kind and Name are intentionally absent — see storage.EnvironmentRepository
// for why those are immutable. risk_level uses *int so an omitted
// field is distinguishable from a deliberate `0`.
type environmentUpdateBody struct {
	Description *string `json:"description,omitempty"`
	RiskLevel   *int    `json:"risk_level,omitempty"`
}

// UpdateEnvironment handles PUT /environments/:id. Only description
// and risk_level are mutable; kind and name are pinned at creation.
func (h *Tenancy) UpdateEnvironment(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	var body environmentUpdateBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	// Read existing row so unspecified fields preserve their current
	// value. Update touches both columns each call, so any field the
	// caller omits MUST round-trip from the existing row.
	current, err := h.environments.Get(c.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "environment not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	description := current.Description
	if body.Description != nil {
		description = *body.Description
	}
	riskLevel := current.RiskLevel
	if body.RiskLevel != nil {
		if *body.RiskLevel < 0 || *body.RiskLevel > 4 {
			return fiber.NewError(fiber.StatusBadRequest, "risk_level must be between 0 and 4")
		}
		riskLevel = *body.RiskLevel
	}

	if err := h.environments.Update(c.Context(), id, description, riskLevel); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "environment not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	updated, err := h.environments.Get(c.Context(), id)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.JSON(environmentToBody(updated))
}

// DeleteEnvironment handles DELETE /environments/:id.
func (h *Tenancy) DeleteEnvironment(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	if err := h.environments.Delete(c.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "environment not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.SendStatus(fiber.StatusNoContent)
}
