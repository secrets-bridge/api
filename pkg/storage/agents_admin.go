package storage

// Agent Onboarding MVP api-2 (api#179) — admin read surface for agents.
// Separate from the certified Get/List/scanAgent path so those stay
// byte-for-byte unchanged; this exposes the onboarding columns + the
// provider-connection name for the admin UI.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AgentAdminRow is the admin projection. It NEVER carries the secret hash,
// public key, or any credential material.
type AgentAdminRow struct {
	ID                     uuid.UUID
	Name                   string
	Status                 AgentStatus
	ProviderConnectionID   *uuid.UUID
	ProviderConnectionName string
	ProviderType           string
	ClusterName            string
	Region                 string
	AgentVersion           string
	Capabilities           []string
	LastSeenAt             *time.Time
	LastStatus             string
	LastError              string
	DisabledAt             *time.Time
	RevokedAt              *time.Time
	RevokedBy              string
	CreatedAt              time.Time
}

// AgentAdminFilter narrows ListAdmin. Empty fields are wildcards.
type AgentAdminFilter struct {
	ProviderConnectionID *uuid.UUID
	Status               string
	ClusterName          string
	ProviderType         string
}

const agentAdminSelect = `
	SELECT a.id, a.name, a.status,
	       a.provider_connection_id, COALESCE(pc.name, ''),
	       COALESCE(a.provider_type, ''), COALESCE(a.cluster_name, ''),
	       COALESCE(a.region, ''), COALESCE(a.agent_version, ''),
	       a.capabilities, a.last_seen_at,
	       COALESCE(a.last_status, ''), COALESCE(a.last_error, ''),
	       a.disabled_at, a.revoked_at, COALESCE(a.revoked_by, ''),
	       a.created_at
	FROM agents a
	LEFT JOIN provider_connections pc ON pc.id = a.provider_connection_id`

// ListAdmin returns agents matching the filter, newest first.
func (r *Agents) ListAdmin(ctx context.Context, f AgentAdminFilter) ([]*AgentAdminRow, error) {
	var where []string
	var args []any
	i := 1
	if f.ProviderConnectionID != nil {
		where = append(where, fmt.Sprintf("a.provider_connection_id = $%d", i))
		args = append(args, *f.ProviderConnectionID)
		i++
	}
	if f.Status != "" {
		where = append(where, fmt.Sprintf("a.status = $%d", i))
		args = append(args, f.Status)
		i++
	}
	if f.ClusterName != "" {
		where = append(where, fmt.Sprintf("a.cluster_name = $%d", i))
		args = append(args, f.ClusterName)
		i++
	}
	if f.ProviderType != "" {
		where = append(where, fmt.Sprintf("a.provider_type = $%d", i))
		args = append(args, f.ProviderType)
		i++
	}
	q := agentAdminSelect
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY a.created_at DESC"

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list admin agents: %w", err)
	}
	defer rows.Close()
	var out []*AgentAdminRow
	for rows.Next() {
		row, err := scanAgentAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// GetAdmin returns one agent's admin projection. ErrNotFound when missing.
func (r *Agents) GetAdmin(ctx context.Context, id uuid.UUID) (*AgentAdminRow, error) {
	row := r.pool.QueryRow(ctx, agentAdminSelect+" WHERE a.id = $1", id)
	out, err := scanAgentAdmin(row)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func scanAgentAdmin(row interface {
	Scan(dest ...any) error
}) (*AgentAdminRow, error) {
	var a AgentAdminRow
	var caps []byte
	err := row.Scan(
		&a.ID, &a.Name, &a.Status,
		&a.ProviderConnectionID, &a.ProviderConnectionName,
		&a.ProviderType, &a.ClusterName, &a.Region, &a.AgentVersion,
		&caps, &a.LastSeenAt,
		&a.LastStatus, &a.LastError,
		&a.DisabledAt, &a.RevokedAt, &a.RevokedBy,
		&a.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan admin agent: %w", err)
	}
	if len(caps) > 0 {
		_ = json.Unmarshal(caps, &a.Capabilities)
	}
	if a.Capabilities == nil {
		a.Capabilities = []string{}
	}
	return &a, nil
}
