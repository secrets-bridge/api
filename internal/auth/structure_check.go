package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrSelfScopeExpansion: a structure change would bring a team or a
// project under a team where the caller holds a team-scoped grant,
// widening it without any write to user_roles (api#192).
var ErrSelfScopeExpansion = errors.New("auth: self_scope_expansion_not_allowed")

// CheckStructureChange refuses a move that widens one of the caller's
// team-scoped grants: dest (the new parent of a team, or the new team
// of a project) is in the subtree of a team the caller holds a grant
// on, and the moved object was not already in that subtree. movedTeam
// is the team being re-parented, or nil for a project move; prevTeam is
// the project's current team (nil when none), unused for a team move. A
// permission the caller also holds globally widens nothing, so it
// doesn't count.
func CheckStructureChange(ctx context.Context, userID string, r Resolver, tr TeamScopeResolver, movedTeam, prevTeam, dest *uuid.UUID) error {
	if dest == nil || r == nil || tr == nil {
		return nil
	}
	grants, err := r.Resolve(ctx, userID)
	if err != nil {
		return fmt.Errorf("auth: resolve grants: %w", err)
	}
	global := map[string]bool{}
	for _, g := range grants {
		if len(g.Scope) == 0 {
			global[g.Permission] = true
		}
	}
	before := prevTeam
	if movedTeam != nil {
		before = movedTeam
	}
	checked := map[uuid.UUID]bool{}
	for _, g := range grants {
		root, err := uuid.Parse(g.Scope[ScopeKeyTeamID])
		if err != nil || global[g.Permission] || checked[root] {
			continue
		}
		checked[root] = true
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
		if in(dest) && !in(before) {
			return ErrSelfScopeExpansion
		}
	}
	return nil
}
