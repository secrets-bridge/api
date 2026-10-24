package auth

// Team-scoped gateway.bind (ADR 0002 C4, api#308; gateway
// docs/design/discovery-contract.md sections 8.2 and 8.4).
//
// gateway.bind counts at two scopes only: global (empty scope) and
// team_id, which covers the team's subtree through TeamScopeResolver. A
// project_id-scoped grant reads as no grant for the catalog and for
// binding (decision S-7), and so does any other scope key.

import (
	"context"
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
)

// GatewayBindScope is the caller's gateway.bind reach. Global is a
// platform admin; otherwise Teams is the union of the granted teams'
// subtrees (empty: no grant). GlobalList is a global gateway.list grant,
// which reads the whole catalog but never binds.
type GatewayBindScope struct {
	Global     bool
	GlobalList bool
	Teams      []uuid.UUID
}

// Any reports whether the scope grants anything.
func (s GatewayBindScope) Any() bool { return s.Global || len(s.Teams) > 0 }

// teamGrant returns the team of a team_id-only scope.
func teamGrant(scope map[string]string) (uuid.UUID, bool) {
	if len(scope) != 1 {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(scope["team_id"])
	return id, err == nil
}

// ResolveGatewayBindScope resolves the caller's gateway.bind scope and
// whether they hold gateway.list globally.
func ResolveGatewayBindScope(ctx context.Context, userID string, r Resolver, tr TeamScopeResolver) (GatewayBindScope, error) {
	var out GatewayBindScope
	if userID == "" || r == nil {
		return out, nil
	}
	grants, err := r.Resolve(ctx, userID)
	if err != nil {
		return out, fmt.Errorf("auth: resolve grants: %w", err)
	}
	seen := map[uuid.UUID]bool{}
	for _, g := range grants {
		switch {
		case g.Permission == string(PermGatewayList) && len(g.Scope) == 0:
			out.GlobalList = true
		case g.Permission != string(PermGatewayBind):
		case len(g.Scope) == 0:
			out.Global = true
		default:
			root, ok := teamGrant(g.Scope)
			if !ok || tr == nil {
				continue
			}
			sub, err := tr.DescendantTeamIDs(ctx, root)
			if err != nil {
				return GatewayBindScope{}, fmt.Errorf("auth: team subtree: %w", err)
			}
			for _, t := range sub {
				if !seen[t] {
					seen[t] = true
					out.Teams = append(out.Teams, t)
				}
			}
		}
	}
	if out.Global {
		out.Teams = nil
	}
	return out, nil
}

// RequireGatewayBind gates a route on gateway.bind held globally or with
// a team_id scope. Any other scope reads as no grant (S-7). The handler
// applies the team filter itself.
func RequireGatewayBind(r Resolver) fiber.Handler {
	if r == nil {
		panic("auth: RequireGatewayBind called with nil Resolver")
	}
	return func(c fiber.Ctx) error {
		userID, ok := IdentityFromContext(c.Context())
		if !ok {
			return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
		}
		grants, err := r.Resolve(c.Context(), userID)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		for _, g := range grants {
			if g.Permission != string(PermGatewayBind) {
				continue
			}
			if _, team := teamGrant(g.Scope); len(g.Scope) == 0 || team {
				return c.Next()
			}
		}
		return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("missing permission %q (global or team scope)", PermGatewayBind))
	}
}

// ErrSelfScopeExpansion: a structure change would bring a team or a
// project under a team where the caller holds a team-scoped gateway.bind
// grant, widening it without any write to user_roles (skills#103 phase
// 1, ADR 0002 C4).
var ErrSelfScopeExpansion = errors.New("auth: self_scope_expansion_not_allowed")

// CheckGatewayBindStructureChange refuses a move that widens one of the
// caller's team-scoped gateway.bind grants: dest (the new parent of a
// team, or the new team of a project) is in the subtree of a team the
// caller holds gateway.bind on, and the moved object was not already
// in that subtree. movedTeam is the team being re-parented, or nil for a
// project move; prevTeam is the project's current team (nil when none),
// unused for a team move. A caller with global gateway.bind widens
// nothing. Narrowest form: only gateway.bind is checked here.
func CheckGatewayBindStructureChange(ctx context.Context, userID string, r Resolver, tr TeamScopeResolver, movedTeam, prevTeam, dest *uuid.UUID) error {
	if dest == nil || r == nil || tr == nil {
		return nil
	}
	grants, err := r.Resolve(ctx, userID)
	if err != nil {
		return fmt.Errorf("auth: resolve grants: %w", err)
	}
	for _, g := range grants {
		if g.Permission == string(PermGatewayBind) && len(g.Scope) == 0 {
			return nil
		}
	}
	for _, g := range grants {
		if g.Permission != string(PermGatewayBind) {
			continue
		}
		root, ok := teamGrant(g.Scope)
		if !ok {
			continue
		}
		sub, err := tr.DescendantTeamIDs(ctx, root)
		if err != nil {
			return fmt.Errorf("auth: team subtree: %w", err)
		}
		in := func(id *uuid.UUID) bool {
			if id == nil {
				return false
			}
			for _, t := range sub {
				if t == *id {
					return true
				}
			}
			return false
		}
		before := prevTeam
		if movedTeam != nil {
			before = movedTeam
		}
		if in(dest) && !in(before) {
			return ErrSelfScopeExpansion
		}
	}
	return nil
}
