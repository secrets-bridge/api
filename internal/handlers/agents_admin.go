package handlers

// Agent Onboarding MVP api-2 (api#179) — admin agent management HTTP layer.
// These routes live OFF the /api/v1/agents/ session-exempt prefix (under
// /admin/agents and /provider-connections/:id/agents) so the global session
// gate applies, and each carries an explicit agent.list / agent.revoke
// permission. Responses NEVER include the secret hash, public key, or any
// credential material.

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// AgentAdminItem is the value-free admin projection of an agent.
type AgentAdminItem struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Status                 string   `json:"status"`
	ProviderConnectionID   *string  `json:"provider_connection_id,omitempty"`
	ProviderConnectionName string   `json:"provider_connection_name,omitempty"`
	ProviderType           string   `json:"provider_type,omitempty"`
	ClusterName            string   `json:"cluster_name,omitempty"`
	Region                 string   `json:"region,omitempty"`
	AgentVersion           string   `json:"agent_version,omitempty"`
	Capabilities           []string `json:"capabilities"`
	LastSeenAt             *string  `json:"last_seen_at,omitempty"`
	LastStatus             string   `json:"last_status,omitempty"`
	RevokedAt              *string  `json:"revoked_at,omitempty"`
	CreatedAt              string   `json:"created_at"`
}

type agentAdminListResponse struct {
	Items []AgentAdminItem `json:"items"`
}

func toAgentAdminItem(r *storage.AgentAdminRow) AgentAdminItem {
	item := AgentAdminItem{
		ID:                     r.ID.String(),
		Name:                   r.Name,
		Status:                 string(r.Status),
		ProviderConnectionName: r.ProviderConnectionName,
		ProviderType:           r.ProviderType,
		ClusterName:            r.ClusterName,
		Region:                 r.Region,
		AgentVersion:           r.AgentVersion,
		Capabilities:           r.Capabilities,
		LastStatus:             r.LastStatus,
		CreatedAt:              r.CreatedAt.UTC().Format(rfc3339Nano),
	}
	if r.ProviderConnectionID != nil {
		s := r.ProviderConnectionID.String()
		item.ProviderConnectionID = &s
	}
	if r.LastSeenAt != nil {
		s := r.LastSeenAt.UTC().Format(rfc3339Nano)
		item.LastSeenAt = &s
	}
	if r.RevokedAt != nil {
		s := r.RevokedAt.UTC().Format(rfc3339Nano)
		item.RevokedAt = &s
	}
	return item
}

// filterFromQuery builds the admin list filter from query params. Returns a
// 400 fiber error when provider_connection_id is present but not a UUID.
func agentFilterFromQuery(c fiber.Ctx) (storage.AgentAdminFilter, error) {
	var f storage.AgentAdminFilter
	if raw := c.Query("provider_connection_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return f, fiber.NewError(fiber.StatusBadRequest, "provider_connection_id must be a UUID")
		}
		f.ProviderConnectionID = &id
	}
	f.Status = c.Query("status")
	f.ClusterName = c.Query("cluster_name")
	f.ProviderType = c.Query("provider_type")
	return f, nil
}

// AdminListAgents handles GET /admin/agents (session + agent.list).
func (h *Agents) AdminListAgents(c fiber.Ctx) error {
	f, err := agentFilterFromQuery(c)
	if err != nil {
		return err
	}
	rows, err := h.svc.ListAgents(c.Context(), f)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not list agents")
	}
	return c.Status(fiber.StatusOK).JSON(agentAdminItemsResponse(rows))
}

// ListAgentsForConnection handles GET /provider-connections/:id/agents
// (session + agent.list) — provider-scoped list for the UI Agents tab.
func (h *Agents) ListAgentsForConnection(c fiber.Ctx) error {
	connID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "provider connection id must be a UUID")
	}
	rows, err := h.svc.ListAgents(c.Context(), storage.AgentAdminFilter{ProviderConnectionID: &connID})
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not list agents")
	}
	return c.Status(fiber.StatusOK).JSON(agentAdminItemsResponse(rows))
}

func agentAdminItemsResponse(rows []*storage.AgentAdminRow) agentAdminListResponse {
	items := make([]AgentAdminItem, 0, len(rows))
	for _, r := range rows {
		items = append(items, toAgentAdminItem(r))
	}
	return agentAdminListResponse{Items: items}
}

// AdminGetAgent handles GET /admin/agents/:id (session + agent.list).
func (h *Agents) AdminGetAgent(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "agent id must be a UUID")
	}
	row, err := h.svc.GetAgent(c.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "agent not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, "could not get agent")
	}
	return c.Status(fiber.StatusOK).JSON(toAgentAdminItem(row))
}

// RevokeEnrollmentToken handles POST /agent-enrollment-tokens/:id/revoke
// (session + agent.mint). Revokes an UNUSED token.
func (h *Agents) RevokeEnrollmentToken(c fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "enrollment token id must be a UUID")
	}
	actor, _ := auth.IdentityFromContext(c.Context())
	var body RevokeAgentRequest
	if len(c.Body()) > 0 {
		_ = c.Bind().JSON(&body)
	}
	if err := h.svc.RevokeEnrollmentToken(c.Context(), id, actor, body.Reason); err != nil {
		switch {
		case errors.Is(err, storage.ErrEnrollmentTokenNotFound):
			// Not found OR already consumed/revoked — collapse to 404 so a
			// caller can't distinguish "never existed" from "already gone".
			return fiber.NewError(fiber.StatusNotFound, "enrollment token not found or not revocable")
		default:
			return fiber.NewError(fiber.StatusInternalServerError, "could not revoke enrollment token")
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}
