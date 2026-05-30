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

// EffectiveProjectAccess resolves the caller's grants for `perm` and
// rolls them up into a ProjectAccess summary.
//
// Callers should pre-check authentication; if userID is empty, the
// returned ProjectAccess has IsGlobal=false and an empty list (treat
// as "no access").
func EffectiveProjectAccess(ctx context.Context, userID string, perm Permission, r Resolver) (ProjectAccess, error) {
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
	for _, g := range grants {
		if g.Permission != string(perm) {
			continue
		}
		if len(g.Scope) == 0 {
			// Empty scope = global. Doesn't matter what we collected
			// before — global wins.
			return ProjectAccess{IsGlobal: true}, nil
		}
		pid := g.Scope["project_id"]
		if pid == "" {
			// A non-empty scope without a project_id constrains in
			// some other dimension (env, secret_ref_prefix, …). Treat
			// as "global for project filtering" — Slice C still
			// enforces the other dimensions at submit time.
			return ProjectAccess{IsGlobal: true}, nil
		}
		u, err := uuid.Parse(pid)
		if err != nil {
			continue
		}
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			pa.ProjectIDs = append(pa.ProjectIDs, u)
		}
	}
	return pa, nil
}
