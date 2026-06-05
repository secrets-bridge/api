package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ProviderConnections is a minimal read-side surface for the
// provider_connections table — just enough for the cross-team
// destination-binding existence check today. The full CRUD admin
// API is a future follow-up that replaces the
// SB_DISCOVER_TARGETS_JSON env-driven discover scheduler with a
// DB-backed source of truth.
type ProviderConnections struct {
	pool *Pool
}

// NewProviderConnections binds the repository to a pool.
func NewProviderConnections(pool *Pool) *ProviderConnections {
	return &ProviderConnections{pool: pool}
}

// Exists returns whether a row with the given id is present in
// provider_connections. Used by RequestService.SubmitCrossTeam to
// reject destination_provider_connection_id values that don't map
// to a real row (returns ErrCrossTeamDestinationUnbound at the
// service layer).
func (r *ProviderConnections) Exists(ctx context.Context, id uuid.UUID) (bool, error) {
	const q = `SELECT 1 FROM provider_connections WHERE id = $1`
	var one int
	err := r.pool.QueryRow(ctx, q, id).Scan(&one)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return false, fmt.Errorf("storage: provider_connection exists: %w", err)
}
