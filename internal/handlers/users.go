// Package handlers, users.go: the admin user lookup (api#240).
//
//	GET /users?ids=<id>,<id>   the named users (at most 100 ids)
//	GET /users?q=<text>        users whose email or display name
//	                           contains text (2+ characters, 20 results)
//
// Admin pages use it to show names and emails for the raw user ids in
// team members and role assignments, and to pick a user in the grant
// and member forms. Main gates it on user_role.edit or team.edit, the
// permissions that manage those lists. The body carries id, email,
// display name and the disabled flag, nothing else.
package handlers

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// User lookup limits.
const (
	userLookupMaxIDs     = 100
	userSearchMinLength  = 2
	userSearchMaxResults = 20
)

// UserDirectory is what the lookup reads; *storage.LocalUsers has it.
type UserDirectory interface {
	ListByIDs(ctx context.Context, ids []uuid.UUID) ([]*storage.LocalUser, error)
	Search(ctx context.Context, text string, limit int) ([]*storage.LocalUser, error)
}

// Users serves GET /users.
type Users struct {
	dir UserDirectory
}

// NewUsers binds the handler to a user directory.
func NewUsers(dir UserDirectory) *Users { return &Users{dir: dir} }

type userSummary struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Disabled    bool   `json:"disabled"`
}

type userLookupResponse struct {
	Users []userSummary `json:"users"`
}

// Lookup handles GET /users with exactly one of ids or q.
func (h *Users) Lookup(c fiber.Ctx) error {
	ids := strings.TrimSpace(c.Query("ids"))
	q := strings.TrimSpace(c.Query("q"))

	var (
		found []*storage.LocalUser
		err   error
	)
	switch {
	case ids != "" && q != "":
		return fiber.NewError(fiber.StatusBadRequest, "use ids or q, not both")
	case ids != "":
		parts := strings.Split(ids, ",")
		if len(parts) > userLookupMaxIDs {
			return fiber.NewError(fiber.StatusBadRequest, "at most 100 ids per lookup")
		}
		// Ids that aren't UUIDs can't name a user (assignments made
		// before local users existed hold free-form ids), so they are
		// skipped like unknown ones rather than refused.
		uuids := make([]uuid.UUID, 0, len(parts))
		for _, p := range parts {
			if id, perr := uuid.Parse(strings.TrimSpace(p)); perr == nil {
				uuids = append(uuids, id)
			}
		}
		found, err = h.dir.ListByIDs(c.Context(), uuids)
	case q != "":
		if len([]rune(q)) < userSearchMinLength {
			return fiber.NewError(fiber.StatusBadRequest, "q needs at least 2 characters")
		}
		found, err = h.dir.Search(c.Context(), q, userSearchMaxResults)
	default:
		return fiber.NewError(fiber.StatusBadRequest, "ids or q is required")
	}
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not look up users")
	}

	out := userLookupResponse{Users: make([]userSummary, 0, len(found))}
	for _, u := range found {
		out.Users = append(out.Users, userSummary{
			ID: u.ID.String(), Email: u.Email, DisplayName: u.DisplayName, Disabled: u.Disabled,
		})
	}
	return c.JSON(out)
}
