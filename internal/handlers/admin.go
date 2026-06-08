// Package handlers — admin.go: HTTP layer for the dynamic
// workflow + policy engine's admin surface.
//
// Endpoints mounted by main on the admin route group (/api/v1):
//
//   Roles
//     POST   /roles                       create
//     GET    /roles                       list
//     GET    /roles/:id                   get
//     PUT    /roles/:id/permissions       replace permission list
//     DELETE /roles/:id                   delete (404 / 409 for system)
//
//   User ↔ Role assignments
//     POST   /user-roles                  grant
//     DELETE /user-roles/:id              revoke
//     GET    /users/:userID/roles         list a user's assignments
//
//   Workflow definitions
//     POST   /workflows                   create
//     GET    /workflows                   list
//     GET    /workflows/:id               get
//     PUT    /workflows/:id               update (except is_default flag)
//     DELETE /workflows/:id               delete (404 / 409 for system)
//
//   Policy rules
//     POST   /policies                    create
//     GET    /policies                    list (priority DESC)
//     GET    /policies/:id                get
//     PUT    /policies/:id                update
//     DELETE /policies/:id                delete (404 / 409 for system)
//
// Authentication is the existing admin-stub middleware; real RBAC
// enforcement lands when the auth design ships (still TBD per BRD).
package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Admin is the HTTP layer over the four admin repositories.
type Admin struct {
	roles     storage.RoleRepository
	userRoles storage.UserRoleRepository
	workflows storage.WorkflowRepository
	policies  storage.PolicyRepository

	// R-follow-up #3 (api#127) — audit emission for admin policy
	// mutations. Optional — when nil, the counter still fires but
	// no audit row is written. Production main always wires this so
	// admin actions are visible in the audit log alongside scoped
	// authoring actions.
	audit storage.AuditEventRepository
}

// NewAdmin constructs an Admin handler bound to its repositories.
func NewAdmin(roles storage.RoleRepository, userRoles storage.UserRoleRepository, workflows storage.WorkflowRepository, policies storage.PolicyRepository) *Admin {
	return &Admin{roles: roles, userRoles: userRoles, workflows: workflows, policies: policies}
}

// WithAudit enables audit emission for admin policy mutations per the
// §4 C2 normalization (policy.create / .update / .delete with
// actor_permission_used: "policy.edit" + scope reflecting the actual
// anchor). When nil, mutations still succeed but no audit event is
// written. Returns the handler so callers can chain.
func (h *Admin) WithAudit(a storage.AuditEventRepository) *Admin {
	h.audit = a
	return h
}

// ---- helpers shared across the four entities -------------------------

func parseID(c fiber.Ctx, paramName string) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Params(paramName))
	if err != nil {
		return uuid.Nil, fiber.NewError(fiber.StatusBadRequest, "invalid "+paramName)
	}
	return id, nil
}

func adminErr(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "not found")
	case errors.Is(err, storage.ErrSystemRow):
		return fiber.NewError(fiber.StatusConflict, "system row cannot be deleted (edit instead)")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}

// ---- roles -----------------------------------------------------------

// RoleBody is the create/get JSON shape.
type RoleBody struct {
	ID          uuid.UUID `json:"id,omitempty"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Permissions []string  `json:"permissions"`
	IsSystem    bool      `json:"is_system,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

func roleToBody(r *storage.Role) RoleBody {
	return RoleBody{
		ID: r.ID, Name: r.Name, Description: r.Description,
		Permissions: r.Permissions, IsSystem: r.IsSystem,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

// CreateRole handles POST /roles.
func (h *Admin) CreateRole(c fiber.Ctx) error {
	var body RoleBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}
	r := &storage.Role{
		Name: body.Name, Description: body.Description,
		Permissions: body.Permissions, // never IsSystem from request — only seed migration sets it
	}
	if err := h.roles.Create(c.Context(), r); err != nil {
		return adminErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(roleToBody(r))
}

// ListRoles handles GET /roles.
func (h *Admin) ListRoles(c fiber.Ctx) error {
	roles, err := h.roles.List(c.Context())
	if err != nil {
		return adminErr(err)
	}
	out := make([]RoleBody, 0, len(roles))
	for _, r := range roles {
		out = append(out, roleToBody(r))
	}
	return c.JSON(out)
}

// GetRole handles GET /roles/:id.
func (h *Admin) GetRole(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	r, err := h.roles.Get(c.Context(), id)
	if err != nil {
		return adminErr(err)
	}
	return c.JSON(roleToBody(r))
}

// UpdateRolePermissionsBody is the body for PUT /roles/:id/permissions.
type UpdateRolePermissionsBody struct {
	Permissions []string `json:"permissions"`
}

// UpdateRolePermissions handles PUT /roles/:id/permissions.
func (h *Admin) UpdateRolePermissions(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body UpdateRolePermissionsBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if err := h.roles.UpdatePermissions(c.Context(), id, body.Permissions); err != nil {
		return adminErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// DeleteRole handles DELETE /roles/:id.
func (h *Admin) DeleteRole(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	if err := h.roles.Delete(c.Context(), id); err != nil {
		return adminErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ---- user_roles ------------------------------------------------------

// GrantUserRoleBody is the body of POST /user-roles.
type GrantUserRoleBody struct {
	UserID    string         `json:"user_id"`
	RoleID    uuid.UUID      `json:"role_id"`
	Scope     map[string]any `json:"scope,omitempty"`
	GrantedBy string         `json:"granted_by,omitempty"`
}

// UserRoleBody is what's returned to clients.
type UserRoleBody struct {
	ID        uuid.UUID      `json:"id"`
	UserID    string         `json:"user_id"`
	RoleID    uuid.UUID      `json:"role_id"`
	Scope     map[string]any `json:"scope,omitempty"`
	GrantedBy string         `json:"granted_by,omitempty"`
	GrantedAt time.Time      `json:"granted_at"`
}

func userRoleToBody(ur *storage.UserRole) UserRoleBody {
	return UserRoleBody{
		ID: ur.ID, UserID: ur.UserID, RoleID: ur.RoleID,
		Scope: ur.Scope, GrantedBy: ur.GrantedBy, GrantedAt: ur.GrantedAt,
	}
}

// GrantUserRole handles POST /user-roles.
func (h *Admin) GrantUserRole(c fiber.Ctx) error {
	var body GrantUserRoleBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.UserID == "" || body.RoleID == uuid.Nil {
		return fiber.NewError(fiber.StatusBadRequest, "user_id and role_id are required")
	}
	ur := &storage.UserRole{
		UserID: body.UserID, RoleID: body.RoleID,
		Scope: body.Scope, GrantedBy: body.GrantedBy,
	}
	if err := h.userRoles.Grant(c.Context(), ur); err != nil {
		return adminErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(userRoleToBody(ur))
}

// RevokeUserRole handles DELETE /user-roles/:id.
func (h *Admin) RevokeUserRole(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	if err := h.userRoles.Revoke(c.Context(), id); err != nil {
		return adminErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ListUserRoles handles GET /users/:userID/roles.
func (h *Admin) ListUserRoles(c fiber.Ctx) error {
	userID := c.Params("userID")
	if userID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "userID is required")
	}
	urs, err := h.userRoles.ListByUser(c.Context(), userID)
	if err != nil {
		return adminErr(err)
	}
	out := make([]UserRoleBody, 0, len(urs))
	for _, ur := range urs {
		out = append(out, userRoleToBody(ur))
	}
	return c.JSON(out)
}

// ListAllUserRoles handles GET /user-roles. Flat list across every
// user — drives the Assignments admin page. Filtering by user or
// role is the caller's job for now; the table is small.
func (h *Admin) ListAllUserRoles(c fiber.Ctx) error {
	urs, err := h.userRoles.List(c.Context())
	if err != nil {
		return adminErr(err)
	}
	out := make([]UserRoleBody, 0, len(urs))
	for _, ur := range urs {
		out = append(out, userRoleToBody(ur))
	}
	return c.JSON(out)
}

// ---- workflow_definitions -------------------------------------------

// WorkflowBody is the request/response JSON shape. TTLs are exposed as
// integer seconds — Helm-friendly and ergonomic over JSON; the storage
// layer translates to Postgres INTERVAL.
type WorkflowBody struct {
	ID                   uuid.UUID  `json:"id,omitempty"`
	Name                 string     `json:"name"`
	Description          string     `json:"description,omitempty"`
	MinApprovers         int        `json:"min_approvers"`
	ApproverRoleID       *uuid.UUID `json:"approver_role_id,omitempty"`
	WrapTTLCreatedSec    int64      `json:"wrap_ttl_created_seconds"`
	WrapTTLApprovedSec   int64      `json:"wrap_ttl_approved_seconds"`
	WrapTTLClaimedSec    int64      `json:"wrap_ttl_claimed_seconds"`
	RequestTTLSec        int64      `json:"request_ttl_seconds"`
	RequireJustification bool       `json:"require_justification"`
	AllowSelfApproval    bool       `json:"allow_self_approval"`
	NotificationChannels []string   `json:"notification_channels"`
	IsDefault            bool       `json:"is_default,omitempty"`
	Enabled              bool       `json:"enabled"`
	IsSystem             bool       `json:"is_system,omitempty"`
	// R-follow-up #1 (api#118) — *bool encodes COALESCE-preserve at
	// the wire layer per §3 safety correction. Omitted JSON field
	// (or explicit `null`) means PRESERVE on Update — critical for
	// rolling deploys where older admin clients don't send the field.
	// Send `true` or `false` to flip the flag explicitly. On Create,
	// nil collapses to false (default-deny).
	ScopedPolicyAuthorable *bool `json:"scoped_policy_authorable,omitempty"`
	CreatedAt              time.Time `json:"created_at,omitempty"`
	UpdatedAt              time.Time `json:"updated_at,omitempty"`
}

func workflowToBody(w *storage.WorkflowDefinition) WorkflowBody {
	spa := w.ScopedPolicyAuthorable
	return WorkflowBody{
		ID: w.ID, Name: w.Name, Description: w.Description,
		MinApprovers: w.MinApprovers, ApproverRoleID: w.ApproverRoleID,
		WrapTTLCreatedSec:    int64(w.WrapTTLCreated.Seconds()),
		WrapTTLApprovedSec:   int64(w.WrapTTLApproved.Seconds()),
		WrapTTLClaimedSec:    int64(w.WrapTTLClaimed.Seconds()),
		RequestTTLSec:        int64(w.RequestTTL.Seconds()),
		RequireJustification: w.RequireJustification,
		AllowSelfApproval:    w.AllowSelfApproval,
		NotificationChannels: w.NotificationChannels,
		IsDefault:            w.IsDefault, Enabled: w.Enabled, IsSystem: w.IsSystem,
		// Always emit the current value on the wire so clients that
		// preserve via copy-then-PUT round-trip correctly.
		ScopedPolicyAuthorable: &spa,
		CreatedAt:              w.CreatedAt, UpdatedAt: w.UpdatedAt,
	}
}

func bodyToWorkflow(b WorkflowBody) *storage.WorkflowDefinition {
	w := &storage.WorkflowDefinition{
		ID: b.ID, Name: b.Name, Description: b.Description,
		MinApprovers: b.MinApprovers, ApproverRoleID: b.ApproverRoleID,
		WrapTTLCreated:       time.Duration(b.WrapTTLCreatedSec) * time.Second,
		WrapTTLApproved:      time.Duration(b.WrapTTLApprovedSec) * time.Second,
		WrapTTLClaimed:       time.Duration(b.WrapTTLClaimedSec) * time.Second,
		RequestTTL:           time.Duration(b.RequestTTLSec) * time.Second,
		RequireJustification: b.RequireJustification,
		AllowSelfApproval:    b.AllowSelfApproval,
		NotificationChannels: b.NotificationChannels,
		IsDefault:            b.IsDefault, Enabled: b.Enabled,
	}
	// R-follow-up #1 (api#118) — explicit field on create collapses
	// nil to false (default-deny). Caller hits the explicit-merge
	// path in UpdateWorkflow for PUT.
	if b.ScopedPolicyAuthorable != nil {
		w.ScopedPolicyAuthorable = *b.ScopedPolicyAuthorable
	}
	return w
}

// CreateWorkflow handles POST /workflows.
func (h *Admin) CreateWorkflow(c fiber.Ctx) error {
	var body WorkflowBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}
	if body.WrapTTLCreatedSec <= 0 || body.WrapTTLApprovedSec <= 0 ||
		body.WrapTTLClaimedSec <= 0 || body.RequestTTLSec <= 0 {
		return fiber.NewError(fiber.StatusBadRequest, "all TTLs must be positive seconds")
	}
	w := bodyToWorkflow(body)
	if err := h.workflows.Create(c.Context(), w); err != nil {
		return adminErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(workflowToBody(w))
}

// ListWorkflows handles GET /workflows.
func (h *Admin) ListWorkflows(c fiber.Ctx) error {
	ws, err := h.workflows.List(c.Context())
	if err != nil {
		return adminErr(err)
	}
	out := make([]WorkflowBody, 0, len(ws))
	for _, w := range ws {
		out = append(out, workflowToBody(w))
	}
	return c.JSON(out)
}

// ListScopedAuthorableWorkflows handles GET /workflows/scoped-policy-
// authorable. Returns enabled AND scoped_policy_authorable=true
// workflows for the EPIC R Slice R3 author drawer (R-follow-up #1).
//
// Auth: bearer + policy.author at any scope. The caller doesn't need
// scoped coverage of any specific project to LIST opted-in workflows;
// they need it to USE one (which the gate chain at POST/PUT
// /projects/:id/policy-rules enforces).
//
// §2 ROUTE-ORDER CORRECTION: this static path MUST be mounted BEFORE
// the dynamic GET /workflows/:id route in main.go. Otherwise some
// routers (including Fiber v3 in some configurations) would interpret
// "scoped-policy-authorable" as the :id parameter.
func (h *Admin) ListScopedAuthorableWorkflows(c fiber.Ctx) error {
	ws, err := h.workflows.ListScopedPolicyAuthorable(c.Context())
	if err != nil {
		return adminErr(err)
	}
	out := make([]WorkflowBody, 0, len(ws))
	for _, w := range ws {
		out = append(out, workflowToBody(w))
	}
	return c.JSON(out)
}

// GetWorkflow handles GET /workflows/:id.
func (h *Admin) GetWorkflow(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	w, err := h.workflows.Get(c.Context(), id)
	if err != nil {
		return adminErr(err)
	}
	return c.JSON(workflowToBody(w))
}

// UpdateWorkflow handles PUT /workflows/:id. is_default flips require
// a separate atomic operation (not in this PR) so they're ignored here.
//
// R-follow-up #1 (api#118) preserve semantic: ScopedPolicyAuthorable
// is *bool on the body. Nil = preserve (Get the existing value, set on
// the patched struct). Explicit true/false = flip. Critical for rolling
// deploys where older admin clients don't yet know about the field —
// without the preserve they'd silently opt out every workflow.
func (h *Admin) UpdateWorkflow(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body WorkflowBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	w := bodyToWorkflow(body)
	w.ID = id
	if body.ScopedPolicyAuthorable == nil {
		// Preserve via Get → merge. Cost: one extra DB round-trip
		// per Update. Acceptable for an admin path.
		existing, err := h.workflows.Get(c.Context(), id)
		if err != nil {
			return adminErr(err)
		}
		w.ScopedPolicyAuthorable = existing.ScopedPolicyAuthorable
	}
	if err := h.workflows.Update(c.Context(), w); err != nil {
		return adminErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// DeleteWorkflow handles DELETE /workflows/:id.
func (h *Admin) DeleteWorkflow(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	if err := h.workflows.Delete(c.Context(), id); err != nil {
		return adminErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ---- policy_rules ---------------------------------------------------

// PolicyBody is the request/response JSON shape.
//
// Slice L2 added the access-decision fields: direct_reveal_allowed,
// requires_mfa, reveal_ttl_seconds. The route-level PolicyEngine
// applies its PROD invariant after Resolve — operators may write
// direct_reveal_allowed=true on a rule that targets a prod env, but
// the engine zeroes it (and writes a `policy.invariant.violated`
// audit row) so the response surface never honours it.
type PolicyBody struct {
	ID                  uuid.UUID      `json:"id,omitempty"`
	Name                string         `json:"name"`
	Selector            map[string]any `json:"selector"`
	WorkflowID          uuid.UUID      `json:"workflow_id"`
	Priority            int            `json:"priority"`
	Enabled             bool           `json:"enabled"`
	IsSystem            bool           `json:"is_system,omitempty"`
	DirectRevealAllowed bool           `json:"direct_reveal_allowed,omitempty"`
	RequiresMFA         bool           `json:"requires_mfa,omitempty"`
	RevealTTLSeconds    int            `json:"reveal_ttl_seconds,omitempty"`

	// R-follow-up #3 (api#127) — anchor fields. Admin can author a
	// rule with EXACTLY ONE of {project_id, team_id} set (or both
	// NULL for platform rules). The DB CHECK constraint
	// policy_rules_one_anchor is the backstop; we validate at the
	// handler so the error envelope is friendly.
	ProjectID *uuid.UUID `json:"project_id,omitempty"`
	TeamID    *uuid.UUID `json:"team_id,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

func policyToBody(p *storage.PolicyRule) PolicyBody {
	return PolicyBody{
		ID: p.ID, Name: p.Name, Selector: p.Selector,
		WorkflowID: p.WorkflowID, Priority: p.Priority,
		Enabled: p.Enabled, IsSystem: p.IsSystem,
		DirectRevealAllowed: p.DirectRevealAllowed,
		RequiresMFA:         p.RequiresMFA,
		RevealTTLSeconds:    p.RevealTTLSeconds,
		ProjectID:           p.ProjectID,
		TeamID:              p.TeamID,
		CreatedAt:           p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

// validatePolicyAnchor enforces the §1 D2 mutually-exclusive anchor
// rule + the §5 C5 server-side team-rule selector safety. The DB
// CHECK constraints from migration 0037 catch most of these
// post-hoc; the handler validation gives a friendly envelope before
// the storage round-trip.
func validatePolicyAnchor(body PolicyBody) error {
	if body.ProjectID != nil && body.TeamID != nil {
		return fiber.NewError(fiber.StatusBadRequest,
			"project_id and team_id cannot both be set (a rule attaches to exactly one anchor)")
	}
	// Platform + project anchors don't carry team-specific selector
	// safety rules (project-anchored rules CAN pin
	// selector.environment_id since they're already tied to one
	// project; platform rules are global). Only team-anchored rules
	// need the §1 C1 safety check.
	if body.TeamID == nil {
		return nil
	}
	sel := body.Selector
	if _, ok := sel["project_id"]; ok {
		return fiber.NewError(fiber.StatusBadRequest,
			"team-anchored rule cannot pin selector.project_id")
	}
	if _, ok := sel["environment_id"]; ok {
		return fiber.NewError(fiber.StatusBadRequest,
			"team-anchored rule cannot pin selector.environment_id")
	}
	if _, ok := sel["team_id"]; ok {
		return fiber.NewError(fiber.StatusBadRequest,
			"team-anchored rule cannot pin selector.team_id (v1 lock)")
	}
	kind, hasKind := sel["environment_kind"]
	if !hasKind {
		return fiber.NewError(fiber.StatusBadRequest,
			"team-anchored rule selector must include environment_kind=non_prod")
	}
	kindStr, ok := kind.(string)
	if !ok || kindStr != "non_prod" {
		return fiber.NewError(fiber.StatusBadRequest,
			"team-anchored rule selector.environment_kind must equal \"non_prod\"")
	}
	return nil
}

// adminPolicyScope returns the counter label value for an admin
// mutation based on the rule's anchor.
func adminPolicyScope(p *storage.PolicyRule) string {
	switch {
	case p.ProjectID != nil:
		return "project"
	case p.TeamID != nil:
		return "team"
	default:
		return "platform"
	}
}

// validatePolicyAccessFields rejects RevealTTLSeconds outside the
// 10..300 range (matching the schema CHECK) when the field is
// non-zero. Zero means "use the schema default 60" so the operator
// can omit the field for default behaviour.
func validatePolicyAccessFields(body PolicyBody) error {
	if body.RevealTTLSeconds != 0 && (body.RevealTTLSeconds < 10 || body.RevealTTLSeconds > 300) {
		return fiber.NewError(fiber.StatusBadRequest, "reveal_ttl_seconds must be between 10 and 300")
	}
	return nil
}

// CreatePolicy handles POST /policies.
func (h *Admin) CreatePolicy(c fiber.Ctx) error {
	var body PolicyBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.Name == "" || body.WorkflowID == uuid.Nil {
		return fiber.NewError(fiber.StatusBadRequest, "name and workflow_id are required")
	}
	if err := validatePolicyAccessFields(body); err != nil {
		return err
	}
	if err := validatePolicyAnchor(body); err != nil {
		return err
	}
	p := &storage.PolicyRule{
		Name:                body.Name,
		Selector:            body.Selector,
		WorkflowID:          body.WorkflowID,
		Priority:            body.Priority,
		Enabled:             body.Enabled,
		DirectRevealAllowed: body.DirectRevealAllowed,
		RequiresMFA:         body.RequiresMFA,
		RevealTTLSeconds:    body.RevealTTLSeconds,
		ProjectID:           body.ProjectID,
		TeamID:              body.TeamID,
	}
	if err := h.policies.Create(c.Context(), p); err != nil {
		return adminErr(err)
	}
	scope := adminPolicyScope(p)
	policyRulesCreatedTotal.WithLabelValues("policy.edit", scope).Inc()
	h.auditAdminPolicy(c, "policy.create", p, scope, nil)
	return c.Status(fiber.StatusCreated).JSON(policyToBody(p))
}

// ListPolicies handles GET /policies.
func (h *Admin) ListPolicies(c fiber.Ctx) error {
	ps, err := h.policies.List(c.Context())
	if err != nil {
		return adminErr(err)
	}
	out := make([]PolicyBody, 0, len(ps))
	for _, p := range ps {
		out = append(out, policyToBody(p))
	}
	return c.JSON(out)
}

// GetPolicy handles GET /policies/:id.
func (h *Admin) GetPolicy(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	p, err := h.policies.Get(c.Context(), id)
	if err != nil {
		return adminErr(err)
	}
	return c.JSON(policyToBody(p))
}

// UpdatePolicy handles PUT /policies/:id.
//
// R-follow-up #3: Update reads the existing row and preserves its
// anchor — `team_id` and `project_id` from the body are IGNORED to
// keep anchor immutability consistent with the storage layer's
// `ErrAnchorImmutable`. Admin who wants to change a rule's anchor
// deletes and re-creates.
func (h *Admin) UpdatePolicy(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body PolicyBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if err := validatePolicyAccessFields(body); err != nil {
		return err
	}
	// Load the existing row so we can preserve the anchor (and run
	// team-rule selector safety if the row is team-anchored, since
	// the body may rewrite selector keys).
	existing, err := h.policies.Get(c.Context(), id)
	if err != nil {
		return adminErr(err)
	}
	// Anchor immutability — apply existing anchor to validation +
	// the patched rule.
	body.ProjectID = existing.ProjectID
	body.TeamID = existing.TeamID
	if err := validatePolicyAnchor(body); err != nil {
		return err
	}
	p := &storage.PolicyRule{
		ID:                  id,
		Name:                body.Name,
		Selector:            body.Selector,
		WorkflowID:          body.WorkflowID,
		Priority:            body.Priority,
		Enabled:             body.Enabled,
		DirectRevealAllowed: body.DirectRevealAllowed,
		RequiresMFA:         body.RequiresMFA,
		RevealTTLSeconds:    body.RevealTTLSeconds,
		ProjectID:           existing.ProjectID,
		TeamID:              existing.TeamID,
	}
	if err := h.policies.Update(c.Context(), p); err != nil {
		return adminErr(err)
	}
	scope := adminPolicyScope(p)
	policyRulesUpdatedTotal.WithLabelValues("policy.edit", scope).Inc()
	h.auditAdminPolicy(c, "policy.update", p, scope, nil)
	return c.SendStatus(fiber.StatusNoContent)
}

// DeletePolicy handles DELETE /policies/:id.
func (h *Admin) DeletePolicy(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	// Load before delete so the counter + audit can record the
	// rule's anchor.
	existing, getErr := h.policies.Get(c.Context(), id)
	if err := h.policies.Delete(c.Context(), id); err != nil {
		return adminErr(err)
	}
	if getErr == nil && existing != nil {
		scope := adminPolicyScope(existing)
		policyRulesDeletedTotal.WithLabelValues("policy.edit", scope).Inc()
		h.auditAdminPolicy(c, "policy.delete", existing, scope, nil)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// auditAdminPolicy emits the normalized policy.create/.update/.delete
// audit event for an admin mutation per §4 C2. Safe no-op when the
// audit repository isn't wired (WithAudit not called). Metadata
// mirrors the scoped paths' shape for cross-cohort triage queries.
func (h *Admin) auditAdminPolicy(c fiber.Ctx, action string, p *storage.PolicyRule, scope string, changedKeys []string) {
	if h.audit == nil {
		return
	}
	keys := make([]string, 0, len(p.Selector))
	for k := range p.Selector {
		keys = append(keys, k)
	}
	projectIDMeta := any(nil)
	if p.ProjectID != nil {
		projectIDMeta = p.ProjectID.String()
	}
	teamIDMeta := any(nil)
	if p.TeamID != nil {
		teamIDMeta = p.TeamID.String()
	}
	meta := map[string]any{
		"policy_rule_id":        p.ID.String(),
		"project_id":            projectIDMeta,
		"team_id":               teamIDMeta,
		"scope":                 scope,
		"priority":              p.Priority,
		"selector_keys":         keys,
		"workflow_id":           p.WorkflowID.String(),
		"actor_permission_used": "policy.edit",
	}
	if len(changedKeys) > 0 {
		meta["changed_keys"] = changedKeys
	}
	actor := identityFromCtx(c)
	if actor == "" {
		actor = "admin"
	}
	_ = h.audit.Append(c.Context(), &storage.AuditEvent{
		Actor:    actor,
		Action:   action,
		Resource: "policy_rule:" + p.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: meta,
	})
}
