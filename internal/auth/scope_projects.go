package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// ProjectAccess summarises which projects a caller can act on for a
// given permission. It feeds the multi-tenancy gate on GET /secrets
// (Slice B of api#43) and the submit-time enforcement on
// POST /requests/{read,patch} (Slice C).
//
//   IsGlobal == true  → caller holds the permission at empty scope;
//                       admin view, no project filter.
//   IsGlobal == false → caller is tenancy-scoped to ProjectIDs (which
//                       may be empty — then they see no rows).
//
// Project IDs that don't parse as UUIDs are silently dropped. A grant
// with a project_id key that is empty string is treated as global —
// matches the existing scopeCovers convention where an empty value
// inside a scope key is wildcard-like.
type ProjectAccess struct {
	IsGlobal   bool
	ProjectIDs []uuid.UUID
}

// TeamAccess summarises which teams a caller can act on for a given
// permission, with the subtree fully expanded.
//
//   IsGlobal == true → caller holds the permission globally; every
//                      team matches.
//   IsGlobal == false → caller is scoped to TeamIDs (each granted
//                       team_id + all its descendants, deduped).
type TeamAccess struct {
	IsGlobal bool
	TeamIDs  []uuid.UUID
}

// TeamScopeResolver translates a team_id-scoped grant into the
// project_id set the caller can act on. Implementations live in the
// storage layer (DescendantTeamIDs is a recursive CTE on teams;
// ProjectIDsForTeams is a single SELECT … WHERE team_id = ANY).
//
// EffectiveProjectAccess works without a TeamScopeResolver — it just
// ignores team_id-scoped grants in that case. Pass one when team-scoped
// grants need to expand to project-scoped access (production: always).
type TeamScopeResolver interface {
	DescendantTeamIDs(ctx context.Context, root uuid.UUID) ([]uuid.UUID, error)
	ProjectIDsForTeams(ctx context.Context, teamIDs []uuid.UUID) ([]uuid.UUID, error)
}

// EffectiveProjectAccess resolves the caller's grants for `perm` and
// rolls them up into a ProjectAccess summary. When tr is non-nil,
// team_id-scoped grants expand through the team subtree and the matching
// project rows. Pass nil to keep the original (project_id-only)
// semantic — useful in unit tests + during the transition.
//
// Callers should pre-check authentication; if userID is empty, the
// returned ProjectAccess has IsGlobal=false and an empty list (treat
// as "no access").
func EffectiveProjectAccess(ctx context.Context, userID string, perm Permission, r Resolver, tr TeamScopeResolver) (ProjectAccess, error) {
	if userID == "" {
		return ProjectAccess{}, nil
	}
	if r == nil {
		return ProjectAccess{}, fmt.Errorf("auth: EffectiveProjectAccess called with nil Resolver")
	}
	grants, err := r.Resolve(ctx, userID)
	if err != nil {
		return ProjectAccess{}, fmt.Errorf("auth: resolve grants for %q: %w", userID, err)
	}
	pa := ProjectAccess{}
	seen := map[uuid.UUID]struct{}{}
	addProject := func(u uuid.UUID) {
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		pa.ProjectIDs = append(pa.ProjectIDs, u)
	}

	for _, g := range grants {
		if g.Permission != string(perm) {
			continue
		}
		if len(g.Scope) == 0 {
			// Empty scope = global. Doesn't matter what we collected
			// before — global wins.
			return ProjectAccess{IsGlobal: true}, nil
		}

		// Team-scoped: expand via the resolver. The resolver returns
		// the team itself + all descendants in one CTE round-trip, and
		// then maps the team set to project IDs in one SELECT.
		if tid := g.Scope["team_id"]; tid != "" {
			if tr == nil {
				// No TeamScopeResolver wired — silently drop the grant.
				// This lets unit tests use the project-only path and
				// also keeps production fail-safe if main forgets to
				// wire the resolver: callers see less than they should
				// rather than more.
				continue
			}
			rootID, err := uuid.Parse(tid)
			if err != nil {
				continue
			}
			descendants, err := tr.DescendantTeamIDs(ctx, rootID)
			if err != nil {
				return ProjectAccess{}, fmt.Errorf("auth: resolve team subtree for %s: %w", rootID, err)
			}
			projects, err := tr.ProjectIDsForTeams(ctx, descendants)
			if err != nil {
				return ProjectAccess{}, fmt.Errorf("auth: resolve projects for team subtree: %w", err)
			}
			for _, p := range projects {
				addProject(p)
			}
			continue
		}

		pid := g.Scope["project_id"]
		if pid == "" {
			// A non-empty scope without project_id or team_id
			// constrains in some other dimension (env, secret_ref_prefix,
			// …). Treat as "global for project filtering" — submit-time
			// gates still enforce the other dimensions.
			return ProjectAccess{IsGlobal: true}, nil
		}
		u, err := uuid.Parse(pid)
		if err != nil {
			continue
		}
		addProject(u)
	}
	return pa, nil
}

// EffectiveTeamAccess returns the team subtree the caller can act on
// for `perm`. Each team_id-scoped grant is expanded through its
// descendants and deduped across grants. A global grant short-circuits.
// Like EffectiveProjectAccess, tr may be nil — team-scoped grants are
// then ignored.
func EffectiveTeamAccess(ctx context.Context, userID string, perm Permission, r Resolver, tr TeamScopeResolver) (TeamAccess, error) {
	if userID == "" {
		return TeamAccess{}, nil
	}
	if r == nil {
		return TeamAccess{}, fmt.Errorf("auth: EffectiveTeamAccess called with nil Resolver")
	}
	grants, err := r.Resolve(ctx, userID)
	if err != nil {
		return TeamAccess{}, fmt.Errorf("auth: resolve grants for %q: %w", userID, err)
	}
	ta := TeamAccess{}
	seen := map[uuid.UUID]struct{}{}
	for _, g := range grants {
		if g.Permission != string(perm) {
			continue
		}
		if len(g.Scope) == 0 {
			return TeamAccess{IsGlobal: true}, nil
		}
		tid := g.Scope["team_id"]
		if tid == "" {
			continue
		}
		if tr == nil {
			continue
		}
		rootID, err := uuid.Parse(tid)
		if err != nil {
			continue
		}
		descendants, err := tr.DescendantTeamIDs(ctx, rootID)
		if err != nil {
			return TeamAccess{}, fmt.Errorf("auth: resolve team subtree for %s: %w", rootID, err)
		}
		for _, d := range descendants {
			if _, ok := seen[d]; !ok {
				seen[d] = struct{}{}
				ta.TeamIDs = append(ta.TeamIDs, d)
			}
		}
	}
	return ta, nil
}
