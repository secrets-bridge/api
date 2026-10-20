// Package handlers — admin.go: HTTP layer for the dynamic
// workflow + policy engine's admin surface.
//
// Endpoints mounted by main on the admin route group (/api/v1):
//
//   Roles
//     POST   /roles                       create
//     GET    /roles                       list
//     GET    /roles/:id                   get
//     PUT    /roles/:id/permissions       replace permission list (409 when a sign-in
//                                         provider's default role would be widened)
//     DELETE /roles/:id                   delete (404; 409 for system, or a sign-in
//                                         provider's default role)
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
//     DELETE /workflows/:id               delete (404; 409 for system or in use;
//                                         ?delete_policy_rules=true also needs policy.edit)
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
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

	// ssoDefaults makes a widening role edit check, under a lock on the
	// role, that no sign-in provider gives the role to new accounts.
	// Optional; when nil, role edits aren't checked against it.
	ssoDefaults SSODefaultRoles

	// R-follow-up #5 slice 1c (api#135) — history service for the
	// admin PolicyHistory endpoint. nil-safe: when not wired, returns
	// 503. Production main always wires this via WithHistory.
	history *services.PolicyHistoryService
}

// NewAdmin constructs an Admin handler bound to its repositories.
func NewAdmin(roles storage.RoleRepository, userRoles storage.UserRoleRepository, workflows storage.WorkflowRepository, policies storage.PolicyRepository) *Admin {
	return &Admin{roles: roles, userRoles: userRoles, workflows: workflows, policies: policies}
}

// SSODefaultRoles is the slice of the sign-in store the role routes use.
type SSODefaultRoles interface {
	// UpdateRolePermissionsUnlessDefault replaces the permissions unless
	// a provider uses the role as its default (storage.ErrRoleIsSSODefault).
	UpdateRolePermissionsUnlessDefault(ctx context.Context, roleID uuid.UUID, perms []string) error
}

// WithSSODefaultRoles makes PUT /roles/:id/permissions refuse to widen
// a role that a sign-in provider gives to every new account. Returns
// the handler for chaining.
func (h *Admin) WithSSODefaultRoles(d SSODefaultRoles) *Admin {
	h.ssoDefaults = d
	return h
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

// WithHistory wires the policy rule history service for the
// R-follow-up #5 admin PolicyHistory endpoint. Returns the handler so
// callers can chain.
func (h *Admin) WithHistory(history *services.PolicyHistoryService) *Admin {
	h.history = history
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
	case errors.Is(err, storage.ErrRoleInUse):
		return fiber.NewError(fiber.StatusConflict, "role is a sign-in provider's default role; choose another default first")
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
	auditWrite(c, h.audit, "role.create", "role:"+r.ID.String(), map[string]any{
		"role_id":     r.ID.String(),
		"permissions": nonNilStrings(r.Permissions),
	})
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
// The list replaces the role's permissions, so the key is required: a
// body without it used to strip every permission from the role. Send []
// to clear on purpose.
type UpdateRolePermissionsBody struct {
	Permissions []string `json:"permissions"`
}

// UpdateRolePermissions handles PUT /roles/:id/permissions.
func (h *Admin) UpdateRolePermissions(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body struct {
		Permissions *[]string `json:"permissions"`
	}
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.Permissions == nil {
		return fiber.NewError(fiber.StatusBadRequest, "permissions is required (send [] to remove every permission)")
	}
	perms := *body.Permissions
	// Read the current list so the audit records what was added and
	// removed, which is the privilege change a reviewer cares about.
	existing, err := h.roles.Get(c.Context(), id)
	if err != nil {
		return adminErr(err)
	}
	// A sign-in provider's default role goes to every new account with
	// approval off, so it stays within the non-privileged permissions.
	// Sign-in checks the role again too; this says so at edit time. The
	// check and the write share a lock on the role row with provider
	// saves, so the two can't both pass at once.
	if h.ssoDefaults != nil && services.HoldsPrivileged(perms) {
		err = h.ssoDefaults.UpdateRolePermissionsUnlessDefault(c.Context(), id, perms)
	} else {
		err = h.roles.UpdatePermissions(c.Context(), id, perms)
	}
	if errors.Is(err, storage.ErrRoleIsSSODefault) {
		return stableErr(c, fiber.StatusConflict, "role_is_sso_default",
			"a sign-in provider gives this role to new accounts, so it can only hold "+strings.Join(services.NonPrivilegedPermissions, ", "), nil)
	}
	if err != nil {
		return adminErr(err)
	}
	added, removed := stringSetDiff(existing.Permissions, perms)
	auditWrite(c, h.audit, "role.permissions.update", "role:"+id.String(), map[string]any{
		"role_id":             id.String(),
		"permissions_added":   added,
		"permissions_removed": removed,
	})
	return c.SendStatus(fiber.StatusNoContent)
}

// DeleteRole handles DELETE /roles/:id. Deleting a role also drops every
// user_roles row that pointed at it (FK ON DELETE CASCADE).
func (h *Admin) DeleteRole(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	existing, getErr := h.roles.Get(c.Context(), id)
	if err := h.roles.Delete(c.Context(), id); err != nil {
		return adminErr(err)
	}
	meta := map[string]any{"role_id": id.String()}
	if getErr == nil && existing != nil {
		meta["permissions"] = nonNilStrings(existing.Permissions)
	}
	auditWrite(c, h.audit, "role.delete", "role:"+id.String(), meta)
	return c.SendStatus(fiber.StatusNoContent)
}

// ---- user_roles ------------------------------------------------------

// GrantUserRoleBody is the body of POST /user-roles.
//
// GrantedBy is accepted for wire compatibility but IGNORED: provenance is
// the session actor (API-N-05). Trusting it let an admin label a grant
// "system:oidc", the marker the OIDC role reconciler uses to decide which
// rows it owns.
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
	// API-N-06: allowed keys only, non-empty string values, UUIDs where
	// an id is expected. A malformed scope used to collapse to {} at
	// evaluation time and act as a global grant.
	scope, err := auth.NormalizeGrantScope(body.Scope)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	ur := &storage.UserRole{
		UserID: body.UserID, RoleID: body.RoleID,
		Scope: scope, GrantedBy: sessionActor(c),
	}
	if err := h.userRoles.Grant(c.Context(), ur); err != nil {
		return adminErr(err)
	}
	auditWrite(c, h.audit, "user_role.grant", "user_role:"+ur.ID.String(), userRoleAuditMeta(ur))
	return c.Status(fiber.StatusCreated).JSON(userRoleToBody(ur))
}

// userRoleAuditMeta is the ids-and-shape view of an assignment for audit
// metadata: who, which role, and the scope's keys plus its id values.
// Free-text scope values (environment, secret_ref_prefix) stay out.
func userRoleAuditMeta(ur *storage.UserRole) map[string]any {
	meta := map[string]any{
		"user_role_id": ur.ID.String(),
		"user_id":      ur.UserID,
		"role_id":      ur.RoleID.String(),
		"scope_keys":   sortedKeys(ur.Scope),
		"granted_by":   ur.GrantedBy,
	}
	for _, k := range []string{auth.ScopeKeyProjectID, auth.ScopeKeyTeamID} {
		if v, ok := ur.Scope[k].(string); ok {
			meta[k] = v
		}
	}
	return meta
}

// RevokeUserRole handles DELETE /user-roles/:id.
func (h *Admin) RevokeUserRole(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	// Load first so the audit names the user and role that lost access.
	existing, err := h.userRoles.Get(c.Context(), id)
	if err != nil {
		return adminErr(err)
	}
	if err := h.userRoles.Revoke(c.Context(), id); err != nil {
		return adminErr(err)
	}
	auditWrite(c, h.audit, "user_role.revoke", "user_role:"+id.String(), userRoleAuditMeta(existing))
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
	// Cross-team knobs (Slice N1). Before these were on the wire there
	// was no way to set them through the API, and every PUT reset them
	// to the column defaults. Not omitempty: a false security vote must
	// be visible, not inferred from silence. On create, 0 fill_ttl means
	// the 86400s default.
	FillTTLSeconds           int       `json:"fill_ttl_seconds"`
	RequiresSecurityApproval bool      `json:"requires_security_approval"`
	CreatedAt                time.Time `json:"created_at,omitempty"`
	UpdatedAt                time.Time `json:"updated_at,omitempty"`
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
		// Self-approval is never allowed (separation of duties), so the
		// field is always false whatever an older row stored.
		AllowSelfApproval:    false,
		NotificationChannels: w.NotificationChannels,
		IsDefault:            w.IsDefault, Enabled: w.Enabled, IsSystem: w.IsSystem,
		// Always emit the current value on the wire so clients that
		// preserve via copy-then-PUT round-trip correctly.
		ScopedPolicyAuthorable:   &spa,
		FillTTLSeconds:           w.FillTTLSeconds,
		RequiresSecurityApproval: w.RequiresSecurityApproval,
		CreatedAt:                w.CreatedAt, UpdatedAt: w.UpdatedAt,
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
		AllowSelfApproval:    false,
		NotificationChannels: b.NotificationChannels,
		IsDefault:            b.IsDefault, Enabled: b.Enabled,
		FillTTLSeconds:           b.FillTTLSeconds,
		RequiresSecurityApproval: b.RequiresSecurityApproval,
	}
	// R-follow-up #1 (api#118) — explicit field on create collapses
	// nil to false (default-deny). Caller hits the explicit-merge
	// path in UpdateWorkflow for PUT.
	if b.ScopedPolicyAuthorable != nil {
		w.ScopedPolicyAuthorable = *b.ScopedPolicyAuthorable
	}
	return w
}

// selfApprovalRefused answers a workflow that asks for self-approval.
// A requester can never approve their own request, Admin included, so
// there is nothing to configure.
func selfApprovalRefused(c fiber.Ctx) error {
	return stableErr(c, fiber.StatusBadRequest, "self_approval_not_allowed",
		"allow_self_approval is not supported: a requester can never approve their own request", nil)
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
	if body.FillTTLSeconds < 0 {
		return fiber.NewError(fiber.StatusBadRequest, "fill_ttl_seconds must be positive (omit for the default)")
	}
	if body.MinApprovers < 0 {
		return fiber.NewError(fiber.StatusBadRequest, "min_approvers must not be negative")
	}
	if body.AllowSelfApproval {
		return selfApprovalRefused(c)
	}
	w := bodyToWorkflow(body)
	if err := h.workflows.Create(c.Context(), w); err != nil {
		return adminErr(err)
	}
	auditWrite(c, h.audit, "workflow.create", "workflow:"+w.ID.String(), map[string]any{
		"workflow_id": w.ID.String(),
	})
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
// Auth: session + policy.author at any scope. The caller doesn't need
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

// workflowUpdateBody is the PUT /workflows/:id input. Every field is
// optional: absent (or null) keeps the stored value, present applies it,
// including an explicit false or 0. approver_role_id additionally takes
// an explicit null to clear the approver role.
//
// name, is_default and is_system are not updatable here (is_default
// flips need their own atomic operation, name was never written by
// Update) and are ignored if sent.
type workflowUpdateBody struct {
	Description              *string      `json:"description"`
	MinApprovers             *int         `json:"min_approvers"`
	ApproverRoleID           optionalUUID `json:"approver_role_id"`
	WrapTTLCreatedSec        *int64       `json:"wrap_ttl_created_seconds"`
	WrapTTLApprovedSec       *int64       `json:"wrap_ttl_approved_seconds"`
	WrapTTLClaimedSec        *int64       `json:"wrap_ttl_claimed_seconds"`
	RequestTTLSec            *int64       `json:"request_ttl_seconds"`
	RequireJustification     *bool        `json:"require_justification"`
	AllowSelfApproval        *bool        `json:"allow_self_approval"`
	NotificationChannels     *[]string    `json:"notification_channels"`
	Enabled                  *bool        `json:"enabled"`
	ScopedPolicyAuthorable   *bool        `json:"scoped_policy_authorable"`
	FillTTLSeconds           *int         `json:"fill_ttl_seconds"`
	RequiresSecurityApproval *bool        `json:"requires_security_approval"`
}

// UpdateWorkflow handles PUT /workflows/:id as a partial update.
//
// The handler used to build the row from the body alone, so any field a
// client left out was written back as its zero value: TTLs went to 0s,
// approver_role_id was cleared, and requires_security_approval (never on
// the wire) reset to false on every edit, silently dropping the security
// vote on prod cross-team requests. Now the stored row is the base and
// only the keys present in the body change it.
func (h *Admin) UpdateWorkflow(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body workflowUpdateBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	for name, ttl := range map[string]*int64{
		"wrap_ttl_created_seconds":  body.WrapTTLCreatedSec,
		"wrap_ttl_approved_seconds": body.WrapTTLApprovedSec,
		"wrap_ttl_claimed_seconds":  body.WrapTTLClaimedSec,
		"request_ttl_seconds":       body.RequestTTLSec,
	} {
		if ttl != nil && *ttl <= 0 {
			return fiber.NewError(fiber.StatusBadRequest, name+" must be positive seconds")
		}
	}
	if body.MinApprovers != nil && *body.MinApprovers < 0 {
		return fiber.NewError(fiber.StatusBadRequest, "min_approvers must not be negative")
	}
	if body.FillTTLSeconds != nil && *body.FillTTLSeconds <= 0 {
		return fiber.NewError(fiber.StatusBadRequest, "fill_ttl_seconds must be positive")
	}

	existing, err := h.workflows.Get(c.Context(), id)
	if err != nil {
		return adminErr(err)
	}
	w := *existing
	w.NotificationChannels = append([]string(nil), existing.NotificationChannels...)
	if body.Description != nil {
		w.Description = *body.Description
	}
	if body.MinApprovers != nil {
		w.MinApprovers = *body.MinApprovers
	}
	if body.ApproverRoleID.Set {
		w.ApproverRoleID = body.ApproverRoleID.Value
	}
	if body.WrapTTLCreatedSec != nil {
		w.WrapTTLCreated = time.Duration(*body.WrapTTLCreatedSec) * time.Second
	}
	if body.WrapTTLApprovedSec != nil {
		w.WrapTTLApproved = time.Duration(*body.WrapTTLApprovedSec) * time.Second
	}
	if body.WrapTTLClaimedSec != nil {
		w.WrapTTLClaimed = time.Duration(*body.WrapTTLClaimedSec) * time.Second
	}
	if body.RequestTTLSec != nil {
		w.RequestTTL = time.Duration(*body.RequestTTLSec) * time.Second
	}
	if body.RequireJustification != nil {
		w.RequireJustification = *body.RequireJustification
	}
	if body.AllowSelfApproval != nil && *body.AllowSelfApproval {
		return selfApprovalRefused(c)
	}
	// Any save clears a flag an older row still stores; it is ignored
	// either way.
	w.AllowSelfApproval = false
	if body.NotificationChannels != nil {
		w.NotificationChannels = *body.NotificationChannels
	}
	if body.Enabled != nil {
		w.Enabled = *body.Enabled
	}
	if body.ScopedPolicyAuthorable != nil {
		w.ScopedPolicyAuthorable = *body.ScopedPolicyAuthorable
	}
	if body.FillTTLSeconds != nil {
		w.FillTTLSeconds = *body.FillTTLSeconds
	}
	if body.RequiresSecurityApproval != nil {
		w.RequiresSecurityApproval = *body.RequiresSecurityApproval
	}
	if err := h.workflows.Update(c.Context(), &w); err != nil {
		return adminErr(err)
	}
	auditWrite(c, h.audit, "workflow.update", "workflow:"+id.String(), map[string]any{
		"workflow_id":  id.String(),
		"changed_keys": workflowChangedKeys(existing, &w),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

// workflowChangedKeys names the columns workflows.Update rewrote with a
// different value. Names only, no values, matching the
// provider_connection.update convention.
func workflowChangedKeys(before, after *storage.WorkflowDefinition) []string {
	changed := []string{}
	add := func(key string, differs bool) {
		if differs {
			changed = append(changed, key)
		}
	}
	add("description", before.Description != after.Description)
	add("min_approvers", before.MinApprovers != after.MinApprovers)
	add("approver_role_id", uuidPtrMeta(before.ApproverRoleID) != uuidPtrMeta(after.ApproverRoleID))
	add("wrap_ttl_created_seconds", before.WrapTTLCreated != after.WrapTTLCreated)
	add("wrap_ttl_approved_seconds", before.WrapTTLApproved != after.WrapTTLApproved)
	add("wrap_ttl_claimed_seconds", before.WrapTTLClaimed != after.WrapTTLClaimed)
	add("request_ttl_seconds", before.RequestTTL != after.RequestTTL)
	add("require_justification", before.RequireJustification != after.RequireJustification)
	add("allow_self_approval", before.AllowSelfApproval != after.AllowSelfApproval)
	add("notification_channels", !sameStrings(before.NotificationChannels, after.NotificationChannels))
	add("enabled", before.Enabled != after.Enabled)
	add("fill_ttl_seconds", before.FillTTLSeconds != after.FillTTLSeconds)
	add("requires_security_approval", before.RequiresSecurityApproval != after.RequiresSecurityApproval)
	add("scoped_policy_authorable", before.ScopedPolicyAuthorable != after.ScopedPolicyAuthorable)
	return changed
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DeleteWorkflow handles DELETE /workflows/:id.
//
// A workflow that any access request used can't be deleted (the request
// keeps it for its history); disable it instead. Policy rules that route
// to the workflow block the delete too, unless the caller passes
// ?delete_policy_rules=true, which deletes them with it and records a
// policy.delete event for each. Both refusals answer 409
// workflow_in_use with the counts.
func (h *Admin) DeleteWorkflow(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	// With delete_policy_rules=true the rules routing here go too; the
	// route then also requires policy.edit (see main.go).
	deleteRules := DeletesPolicyRules(c)

	usage, err := h.workflows.Delete(c.Context(), id, deleteRules)
	if errors.Is(err, storage.ErrWorkflowInUse) {
		msg := fmt.Sprintf("%d policy rules route to this workflow; repoint or delete them first, or repeat with delete_policy_rules=true",
			len(usage.PolicyRules))
		if usage.Requests > 0 {
			msg = fmt.Sprintf("%d requests used this workflow, so it can't be deleted; disable it instead", usage.Requests)
		}
		return stableErr(c, fiber.StatusConflict, "workflow_in_use", msg, map[string]any{
			"requests_count":     usage.Requests,
			"policy_rules_count": len(usage.PolicyRules),
		})
	}
	if err != nil {
		return adminErr(err)
	}

	// Audit the rules the delete removed, as it returned them: a list
	// read before the transaction can differ if a rule was pointed to or
	// away from this workflow in between.
	deleted := make([]string, 0, len(usage.PolicyRules))
	for _, p := range usage.PolicyRules {
		deleted = append(deleted, p.ID.String())
		scope := adminPolicyScope(p)
		policyRulesDeletedTotal.WithLabelValues("policy.edit", scope).Inc()
		h.auditAdminPolicy(c, "policy.delete", p, scope, nil)
	}
	auditWrite(c, h.audit, "workflow.delete", "workflow:"+id.String(), map[string]any{
		"workflow_id":             id.String(),
		"deleted_policy_rule_ids": deleted,
	})
	return c.SendStatus(fiber.StatusNoContent)
}

// DeletesPolicyRules reports whether a DELETE /workflows/:id asks to
// delete the policy rules that route to the workflow as well.
func DeletesPolicyRules(c fiber.Ctx) bool { return c.Query("delete_policy_rules") == "true" }

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
	// NOT omitempty. `omitempty` on a bool drops `false`, so a rule
	// with direct reveal switched OFF came back with the key absent —
	// indistinguishable from "this field is not supported". An
	// operator confirming that a rule does NOT permit direct reveal
	// needs to see the false, not infer it from silence. Both values
	// were always persisted correctly; only the response hid them.
	DirectRevealAllowed bool           `json:"direct_reveal_allowed"`
	RequiresMFA         bool           `json:"requires_mfa"`
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

// policySelectorEnumReject checks the provider_type / operation selector
// enums (api#139 / api#141) on the admin authoring path. It returns the
// offending field name + the reason detail when a value is invalid, or
// ("", nil) when the selector is clean. The CALLER emits the envelope via
// `return stableErr(...)` so the structured
// `{error_code: "policy_scope_too_broad", reason: "<variant>_invalid"}`
// response (matching the scoped paths, so the SPA's reason-variant toast
// routing works) is the handler's terminal return — stableErr writes the
// body AND returns nil (Fiber c.JSON success), so it must not be used in a
// mid-handler `if err != nil` guard or the later 201 overwrites it.
//
// Kept separate from validatePolicyAnchor (which returns plain fiber
// errors for anchor-shape rules): a selector-enum rejection must carry the
// reason variant, which needs the stableErr envelope.
func policySelectorEnumReject(body PolicyBody) (field string, detail *services.PolicyScopeTooBroadDetail) {
	if d := services.ValidateProviderTypeSelector(body.Selector); d != nil {
		return "provider_type", d
	}
	if d := services.ValidateOperationSelector(body.Selector); d != nil {
		return "operation", d
	}
	return "", nil
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

	// NOTE: the selector-enum checks (provider_type / operation) are NOT
	// here — they live in validatePolicySelectorEnums, which emits the
	// structured {error_code, reason} envelope the scoped paths use (the
	// plain fiber.NewError shape this function returns can't carry the
	// reason variant). Both CreatePolicy and UpdatePolicy call it.

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
	if field, d := policySelectorEnumReject(body); d != nil {
		return stableErr(c, fiber.StatusBadRequest, "policy_scope_too_broad",
			"selector."+field+" is not in the policy selector enum",
			map[string]any{"reason": d.Reason})
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

// policyUpdateBody is the PUT /policies/:id input. Every field is
// optional: absent (or null) keeps the stored value, present applies it,
// including false / 0. project_id and team_id are not accepted (anchors
// are immutable; delete and re-create to move a rule).
type policyUpdateBody struct {
	Name                *string         `json:"name"`
	Selector            *map[string]any `json:"selector"`
	WorkflowID          *uuid.UUID      `json:"workflow_id"`
	Priority            *int            `json:"priority"`
	Enabled             *bool           `json:"enabled"`
	DirectRevealAllowed *bool           `json:"direct_reveal_allowed"`
	RequiresMFA         *bool           `json:"requires_mfa"`
	RevealTTLSeconds    *int            `json:"reveal_ttl_seconds"`
}

// UpdatePolicy handles PUT /policies/:id as a partial update.
//
// The stored rule is the base and only keys present in the body change
// it. The handler used to write the body verbatim, so an omitted key
// reset its column: the selector to {} (match everything), enabled and
// direct_reveal_allowed / requires_mfa to false, priority to 0.
//
// R-follow-up #3: the anchor (project_id / team_id) is preserved from
// the stored row, consistent with storage's ErrAnchorImmutable.
func (h *Admin) UpdatePolicy(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var upd policyUpdateBody
	if err := json.Unmarshal(c.Body(), &upd); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if upd.Name != nil && *upd.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name must not be empty")
	}
	if upd.WorkflowID != nil && *upd.WorkflowID == uuid.Nil {
		return fiber.NewError(fiber.StatusBadRequest, "workflow_id must not be empty")
	}
	existing, err := h.policies.Get(c.Context(), id)
	if err != nil {
		return adminErr(err)
	}
	body := policyToBody(existing)
	if upd.Name != nil {
		body.Name = *upd.Name
	}
	if upd.Selector != nil {
		body.Selector = *upd.Selector
	}
	if upd.WorkflowID != nil {
		body.WorkflowID = *upd.WorkflowID
	}
	if upd.Priority != nil {
		body.Priority = *upd.Priority
	}
	if upd.Enabled != nil {
		body.Enabled = *upd.Enabled
	}
	if upd.DirectRevealAllowed != nil {
		body.DirectRevealAllowed = *upd.DirectRevealAllowed
	}
	if upd.RequiresMFA != nil {
		body.RequiresMFA = *upd.RequiresMFA
	}
	if upd.RevealTTLSeconds != nil {
		body.RevealTTLSeconds = *upd.RevealTTLSeconds
	}
	// Validate the merged rule, the same checks a create runs.
	if err := validatePolicyAccessFields(body); err != nil {
		return err
	}
	if field, d := policySelectorEnumReject(body); d != nil {
		return stableErr(c, fiber.StatusBadRequest, "policy_scope_too_broad",
			"selector."+field+" is not in the policy selector enum",
			map[string]any{"reason": d.Reason})
	}
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
	// R-follow-up #5 slice 1b (api#134) — snapshot extension: add
	// `name` + `enabled` so PolicyHistoryService can diff them
	// without re-reading the rule row from the DB.
	meta := map[string]any{
		"policy_rule_id":        p.ID.String(),
		"project_id":            projectIDMeta,
		"team_id":               teamIDMeta,
		"scope":                 scope,
		"name":                  p.Name,
		"enabled":               p.Enabled,
		"priority":              p.Priority,
		"selector_keys":         keys,
		"workflow_id":           p.WorkflowID.String(),
		"actor_permission_used": "policy.edit",
	}
	if len(changedKeys) > 0 {
		meta["changed_keys"] = changedKeys
	}
	_ = h.audit.Append(c.Context(), &storage.AuditEvent{
		Actor:    auth.AuditActor(c.Context()),
		Action:   action,
		Resource: "policy_rule:" + p.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: meta,
	})
}

// PolicyHistory handles GET /policies/:ruleID/history.
// R-follow-up #5 slice 1c (api#135) — admin history view.
//
// Gate chain per §4 D3 / C2:
//
//  1. Auth — auth.Require(PermPolicyEdit) at the route mount (in main).
//  2. Parse URL params + limit.
//  3. **Existence check FIRST via the audit chain** (NOT policyRepo.Get).
//     If at least one mutation event exists, proceed even when the rule
//     itself was deleted. This is the admin post-delete forensic
//     visibility path per §4 C4. Scoped paths (project / team) lose
//     access at delete; admin retains.
//  4. NO anchor routing — admin sees history for any anchor.
//  5. Service call — policyHistorySvc.ListForRule.
//  6. Counter + audit — policy_rule_history_views_total{scope=<derived>}
//     + audit.read.policy_history event. Scope is derived from the live
//     rule if it still exists; falls back to the most recent event's
//     metadata `scope` field if the rule has been deleted.
func (h *Admin) PolicyHistory(c fiber.Ctx) error {
	if h.history == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable,
			"policy history service not configured")
	}

	ruleID, err := parseID(c, "ruleID")
	if err != nil {
		return err
	}

	limit, err := parseHistoryLimit(c)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	// Load the live rule once (nil when deleted). Passed to the service
	// so a zero-audit rule (e.g. the system match-all seed) still gets a
	// synthesized initial snapshot (M6); reused below for scope.
	var current *storage.PolicyRule
	if rule, getErr := h.policies.Get(c.Context(), ruleID); getErr == nil {
		current = rule
	}

	// Service walks the audit chain regardless of whether the rule
	// exists. Empty result + rule-not-found → 404.
	entries, hasMore, err := h.history.ListForRule(c.Context(), ruleID, current, limit)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// Scope derivation:
	//   1. Live rule (most accurate)
	//   2. Most recent event's snapshot scope (post-delete forensic)
	//   3. Default "platform" for legacy events predating §4 C2
	scope := "platform"
	switch {
	case current != nil:
		scope = scopeForRule(current)
	case len(entries) > 0:
		// Most recent event is entries[len-1] (chain order is ASC).
		if entries[len(entries)-1].Scope != "" {
			scope = entries[len(entries)-1].Scope
		}
	default:
		// No live rule AND no audit events — truly not found.
		return fiber.NewError(fiber.StatusNotFound, "policy rule not found")
	}

	policyRuleHistoryViewsTotal.WithLabelValues(scope).Inc()
	auditReadPolicyHistory(c, h.audit, ruleID, scope, len(entries))

	return c.JSON(policyRuleHistoryResponse{
		RuleID:  ruleID.String(),
		Scope:   scope,
		Entries: toHistoryEntryWires(entries),
		HasMore: hasMore,
		Limit:   limit,
	})
}
