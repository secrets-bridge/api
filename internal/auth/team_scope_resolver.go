package auth

import (
	"context"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// RepoTeamScopeResolver is the production TeamScopeResolver. It walks
// the team subtree via the storage.TeamRepository's recursive CTE and
// maps team_id → project_id via storage.ProjectRepository.
type RepoTeamScopeResolver struct {
	teams    storage.TeamRepository
	projects storage.ProjectRepository
}

// NewRepoTeamScopeResolver wires the production resolver.
func NewRepoTeamScopeResolver(t storage.TeamRepository, p storage.ProjectRepository) *RepoTeamScopeResolver {
	return &RepoTeamScopeResolver{teams: t, projects: p}
}

// DescendantTeamIDs returns root and every team beneath it.
func (r *RepoTeamScopeResolver) DescendantTeamIDs(ctx context.Context, root uuid.UUID) ([]uuid.UUID, error) {
	return r.teams.DescendantIDs(ctx, root)
}

// ProjectIDsForTeams returns every project whose team_id is in the set.
func (r *RepoTeamScopeResolver) ProjectIDsForTeams(ctx context.Context, teamIDs []uuid.UUID) ([]uuid.UUID, error) {
	return r.projects.IDsForTeams(ctx, teamIDs)
}
