// Package handlers — teams.go: admin CRUD for the team hierarchy.
//
// Endpoints mounted under /api/v1 by main:
//
//	POST   /teams                       create team
//	GET    /teams                       list every team (flat — UI assembles tree)
//	GET    /teams/:id                   get one team
//	PUT    /teams/:id                   update name + description + parent
//	PUT    /teams/:id/status            archive ↔ activate
//	DELETE /teams/:id                   hard-delete (refuses when children exist)
//
//	POST   /teams/:id/members           add a user to the team
//	GET    /teams/:id/members           list members
//	DELETE /teams/:id/members/:user_id  remove a user from the team
//
// Design notes:
//
//   - Teams form an N-level hierarchy via parent_team_id. The handler
//     does not expand the tree server-side; List returns the flat set
//     and the UI builds the tree from parent links. This avoids
//     server-side memoization of a structure the operator may edit
//     frequently.
//
//   - Membership is structural only. Granting a user permissions
//     INSIDE a team subtree goes through the existing user_roles
//     surface (POST /user-roles with scope = {team_id: <uuid>}). This
//     handler does NOT mint role grants.
//
//   - Delete is hard-delete and refuses (409) when children exist.
//     ON DELETE RESTRICT in the schema catches the same case at the
//     SQL layer, so a concurrent insert between handler check and
//     delete still fails safely.
package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Teams bundles the team repository behind one HTTP handler.
type Teams struct {
	teams storage.TeamRepository
}

// NewTeams wires the handler.
func NewTeams(t storage.TeamRepository) *Teams { return &Teams{teams: t} }

// --- request / response shapes --------------------------------------

type teamBody struct {
	ID           uuid.UUID  `json:"id,omitempty"`
	Name         string     `json:"name"`
	ParentTeamID *uuid.UUID `json:"parent_team_id"`
	Status       string     `json:"status,omitempty"`
	Description  string     `json:"description,omitempty"`
	CreatedAt    time.Time  `json:"created_at,omitempty"`
	UpdatedAt    time.Time  `json:"updated_at,omitempty"`
}

func teamToBody(t *storage.Team) teamBody {
	return teamBody{
		ID:           t.ID,
		Name:         t.Name,
		ParentTeamID: t.ParentTeamID,
		Status:       string(t.Status),
		Description:  t.Description,
		CreatedAt:    t.CreatedAt,
		UpdatedAt:    t.UpdatedAt,
	}
}

type teamStatusBody struct {
	Status string `json:"status"`
}

type teamMemberBody struct {
	TeamID    uuid.UUID  `json:"team_id"`
	UserID    uuid.UUID  `json:"user_id"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
}

func memberToBody(m storage.TeamMember) teamMemberBody {
	return teamMemberBody{
		TeamID:    m.TeamID,
		UserID:    m.UserID,
		CreatedAt: m.CreatedAt,
		CreatedBy: m.CreatedBy,
	}
}

type addMemberBody struct {
	UserID uuid.UUID `json:"user_id"`
}

// --- team CRUD -------------------------------------------------------

// Create handles POST /teams.
func (h *Teams) Create(c fiber.Ctx) error {
	var body teamBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	t := &storage.Team{
		Name:         body.Name,
		ParentTeamID: body.ParentTeamID,
		Description:  body.Description,
	}
	if body.Status != "" {
		t.Status = storage.TeamStatus(body.Status)
	}

	if err := h.teams.Create(c.Context(), t); err != nil {
		return mapTeamErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(teamToBody(t))
}

// List handles GET /teams.
func (h *Teams) List(c fiber.Ctx) error {
	all, err := h.teams.List(c.Context())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	out := make([]teamBody, len(all))
	for i, t := range all {
		out[i] = teamToBody(t)
	}
	return c.JSON(out)
}

// Get handles GET /teams/:id.
func (h *Teams) Get(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid id")
	}
	t, err := h.teams.Get(c.Context(), id)
	if err != nil {
		return mapTeamErr(err)
	}
	return c.JSON(teamToBody(t))
}

// Update handles PUT /teams/:id. Body fields: name, description,
// parent_team_id. A nil/empty parent_team_id un-parents to the root.
func (h *Teams) Update(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid id")
	}
	var body teamBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}
	if err := h.teams.Update(c.Context(), id, body.Name, body.Description, body.ParentTeamID); err != nil {
		return mapTeamErr(err)
	}
	t, err := h.teams.Get(c.Context(), id)
	if err != nil {
		return mapTeamErr(err)
	}
	return c.JSON(teamToBody(t))
}

// UpdateStatus handles PUT /teams/:id/status.
func (h *Teams) UpdateStatus(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid id")
	}
	var body teamStatusBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	status := storage.TeamStatus(body.Status)
	if status != storage.TeamStatusActive && status != storage.TeamStatusArchived {
		return fiber.NewError(fiber.StatusBadRequest, "status must be 'active' or 'archived'")
	}
	if err := h.teams.UpdateStatus(c.Context(), id, status); err != nil {
		return mapTeamErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Delete handles DELETE /teams/:id. Refuses with 409 when children
// exist; refuses with 404 when the team doesn't exist.
func (h *Teams) Delete(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid id")
	}
	if err := h.teams.Delete(c.Context(), id); err != nil {
		return mapTeamErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- membership ------------------------------------------------------

// AddMember handles POST /teams/:id/members.
func (h *Teams) AddMember(c fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid team id")
	}
	var body addMemberBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.UserID == uuid.Nil {
		return fiber.NewError(fiber.StatusBadRequest, "user_id is required")
	}

	// Best-effort attribution from the auth-stub context. nil if absent.
	createdBy := callerUUID(c)
	if err := h.teams.AddMember(c.Context(), teamID, body.UserID, createdBy); err != nil {
		return mapTeamErr(err)
	}
	return c.SendStatus(fiber.StatusCreated)
}

// ListMembers handles GET /teams/:id/members.
func (h *Teams) ListMembers(c fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid team id")
	}
	members, err := h.teams.ListMembers(c.Context(), teamID)
	if err != nil {
		return mapTeamErr(err)
	}
	out := make([]teamMemberBody, len(members))
	for i, m := range members {
		out[i] = memberToBody(m)
	}
	return c.JSON(out)
}

// RemoveMember handles DELETE /teams/:id/members/:user_id.
func (h *Teams) RemoveMember(c fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid team id")
	}
	userID, err := uuid.Parse(c.Params("user_id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid user_id")
	}
	if err := h.teams.RemoveMember(c.Context(), teamID, userID); err != nil {
		return mapTeamErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// mapTeamErr maps the storage sentinels to user-facing HTTP errors.
func mapTeamErr(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "not found")
	case errors.Is(err, storage.ErrDuplicateName):
		return fiber.NewError(fiber.StatusConflict, "name already exists at this level")
	case errors.Is(err, storage.ErrCyclicParent):
		return fiber.NewError(fiber.StatusConflict, "parent would create a cycle")
	case errors.Is(err, storage.ErrHasChildren):
		return fiber.NewError(fiber.StatusConflict, "team has children — unparent or delete them first")
	case errors.Is(err, storage.ErrAlreadyMember):
		return fiber.NewError(fiber.StatusConflict, "user is already a member of this team")
	}
	return fiber.NewError(fiber.StatusInternalServerError, err.Error())
}

// callerUUID best-effort reads the actor UUID from the auth context.
// Returns nil when the actor is the legacy stub string ("anonymous") or
// not a valid UUID — attribution stays optional and a missing value is
// stored as NULL rather than failing the request.
func callerUUID(c fiber.Ctx) *uuid.UUID {
	sub, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return nil
	}
	id, err := uuid.Parse(sub)
	if err != nil {
		return nil
	}
	return &id
}
