// Package handlers, user_approvals.go: accounts waiting for an admin's
// approval (api#266).
//
//	GET  /users/pending         the waiting accounts, oldest first, and how many
//	POST /users/:id/approve     {role_id, scope}: grant the role and let the account act
//	POST /users/:id/decline     disable a waiting account
//
// Main gates all three on a global user_role.edit: approving grants a
// role. An account waits while local_users.pending_approval is set;
// until then it may only read /users/me and sign out
// (middleware.RequireApprovedExcept).
package handlers

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// PendingAccounts is what the approval routes need; *storage.LocalUsers
// has it.
type PendingAccounts interface {
	ListPending(ctx context.Context, limit int) ([]*storage.LocalUser, int, error)
	ApprovePending(ctx context.Context, id uuid.UUID, ur *storage.UserRole) error
	DeclinePending(ctx context.Context, id uuid.UUID) error
}

// UserApprovals serves the approval routes.
type UserApprovals struct {
	accounts PendingAccounts
	audit    storage.AuditEventRepository
}

// NewUserApprovals binds the handler. audit may be nil in tests.
func NewUserApprovals(accounts PendingAccounts, audit storage.AuditEventRepository) *UserApprovals {
	return &UserApprovals{accounts: accounts, audit: audit}
}

type pendingAccount struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	WaitingSince string `json:"waiting_since"`
}

type pendingResponse struct {
	Users []pendingAccount `json:"users"`
	// Total counts every waiting account; Users holds at most 100.
	Total int `json:"total"`
}

// ListPending handles GET /users/pending.
func (h *UserApprovals) ListPending(c fiber.Ctx) error {
	found, total, err := h.accounts.ListPending(c.Context(), storage.LocalUserPendingMax)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not list waiting accounts")
	}
	out := pendingResponse{Users: make([]pendingAccount, 0, len(found)), Total: total}
	for _, u := range found {
		out.Users = append(out.Users, pendingAccount{
			ID: u.ID.String(), Email: u.Email, DisplayName: u.DisplayName,
			WaitingSince: u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	return c.JSON(out)
}

// ApproveBody is the body for POST /users/:id/approve.
type ApproveBody struct {
	RoleID uuid.UUID      `json:"role_id"`
	Scope  map[string]any `json:"scope,omitempty"`
}

// Approve handles POST /users/:id/approve. The scope is checked with
// the same rules as POST /user-roles (API-N-06), and the role is granted
// in the same transaction that clears the waiting flag.
func (h *UserApprovals) Approve(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body ApproveBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.RoleID == uuid.Nil {
		return fiber.NewError(fiber.StatusBadRequest, "role_id is required")
	}
	scope, err := auth.NormalizeGrantScope(body.Scope)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	ur := &storage.UserRole{RoleID: body.RoleID, Scope: scope, GrantedBy: sessionActor(c)}
	if err := h.accounts.ApprovePending(c.Context(), id, ur); err != nil {
		return approvalErr(err)
	}
	meta := userRoleAuditMeta(ur)
	auditWrite(c, h.audit, "user.approve", "user:"+id.String(), meta)
	auditWrite(c, h.audit, "user_role.grant", "user_role:"+ur.ID.String(), meta)
	return c.JSON(userRoleToBody(ur))
}

// Decline handles POST /users/:id/decline. Only a waiting account can be
// declined; it is disabled, so its sessions end on their next use.
func (h *UserApprovals) Decline(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	if err := h.accounts.DeclinePending(c.Context(), id); err != nil {
		return approvalErr(err)
	}
	auditWrite(c, h.audit, "user.decline", "user:"+id.String(), map[string]any{"user_id": id.String()})
	return c.SendStatus(fiber.StatusNoContent)
}

func approvalErr(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "user or role not found")
	case errors.Is(err, storage.ErrNotPending):
		return fiber.NewError(fiber.StatusConflict, "user_not_pending")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, "could not update the account")
	}
}
