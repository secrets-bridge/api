// Package handlers — cross_team.go: HTTP layer for Slice N3.
//
// Routes mounted by main on /api/v1:
//
//	POST   /requests/cross-team          submit a cross_team request (status=pending_values)
//	POST   /requests/:id/fill            Team B fills values (pending_values → pending_verification)
//	POST   /requests/:id/refuse          Team B refuses (pending_values → refused)
//	POST   /requests/:id/verify          Source / security vote (pending_verification → approved | rejected)
//	GET    /requests/inbox               Team B's pending fill queue
//	GET    /requests/inbox/count         badge count for SPA sidebar
//
// All response shapes are value-free. Fill is the ONE endpoint that
// accepts plaintext bytes, and those flow through WrapService.Wrap
// before touching Postgres / Redis / logs / audit.
package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// CrossTeam is the HTTP layer over the cross-team service methods.
// Holds a TeamScopeResolver so the inbox handlers can compute the
// caller's allowed-team set without round-tripping through
// auth.EffectiveTeamAccess at every call site.
type CrossTeam struct {
	svc       *services.RequestService
	resolver  auth.Resolver
	teamScope auth.TeamScopeResolver
}

// NewCrossTeam binds the handler.
func NewCrossTeam(svc *services.RequestService, resolver auth.Resolver, teamScope auth.TeamScopeResolver) *CrossTeam {
	return &CrossTeam{svc: svc, resolver: resolver, teamScope: teamScope}
}

// --- request / response bodies ----------------------------------------------

// SubmitCrossTeamBody is the JSON the SPA POSTs.
type SubmitCrossTeamBody struct {
	ProjectID                       string   `json:"project_id"`
	Environment                     string   `json:"environment"`
	TargetTeamID                    string   `json:"target_team_id"`
	TargetProjectID                 string   `json:"target_project_id"`
	TargetEnvironmentID             string   `json:"target_environment_id"`
	DestinationProviderConnectionID string   `json:"destination_provider_connection_id"`
	DestinationSecretRef            string   `json:"destination_secret_ref"`
	DestinationKeys                 []string `json:"destination_keys"`
	Justification                   string   `json:"justification"`
}

// FillBody is the JSON Team B POSTs. KeyValues are base64-encoded;
// the service decodes once and feeds the bytes through WrapService.
type FillBody struct {
	KeyValues   map[string]string `json:"key_values"`
	FillComment string            `json:"fill_comment,omitempty"`
}

// RefuseBody is the JSON for refusal.
type RefuseBody struct {
	Reason string `json:"reason"`
}

// VerifyBody is the JSON for a vote. voted_as MUST match the
// permission the caller holds.
type VerifyBody struct {
	VotedAs  string `json:"voted_as"` // "source" | "security"
	Decision string `json:"decision"` // "approve" | "reject"
	Comment  string `json:"comment,omitempty"`
}

// CrossTeamRequestBody is the value-free representation of an
// access_request used in cross_team list responses. Mirrors the
// existing RequestBody shape (no plaintext, no envelopes) plus the
// cross_team-specific fields.
type CrossTeamRequestBody struct {
	ID                              string   `json:"id"`
	RequesterID                     string   `json:"requester_id"`
	Type                            string   `json:"type"`
	Status                          string   `json:"status"`
	Justification                   string   `json:"justification,omitempty"`
	TargetTeamID                    string   `json:"target_team_id,omitempty"`
	TargetProjectID                 string   `json:"target_project_id,omitempty"`
	TargetEnvironmentID             string   `json:"target_environment_id,omitempty"`
	DestinationProviderConnectionID string   `json:"destination_provider_connection_id,omitempty"`
	DestinationSecretRef            string   `json:"destination_secret_ref,omitempty"`
	DestinationKeys                 []string `json:"destination_keys,omitempty"`
	FillExpiresAt                   string   `json:"fill_expires_at,omitempty"`
	FilledAt                        string   `json:"filled_at,omitempty"`
	FilledByUserID                  string   `json:"filled_by_user_id,omitempty"`
	FillComment                     string   `json:"fill_comment,omitempty"`
	RefuseReason                    string   `json:"refuse_reason,omitempty"`
	SecurityApprovalRequired        bool     `json:"security_approval_required"`
	CreatedAt                       string   `json:"created_at"`
	UpdatedAt                       string   `json:"updated_at"`
}

// InboxCountResponse is the SPA badge body.
type InboxCountResponse struct {
	Total int `json:"total"`
}

// --- handlers ---------------------------------------------------------------

// Submit handles POST /api/v1/requests/cross-team.
func (h *CrossTeam) Submit(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	var body SubmitCrossTeamBody
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	targetTeam, err := parseUUIDField(body.TargetTeamID, "target_team_id")
	if err != nil {
		return err
	}
	targetProj, err := parseUUIDField(body.TargetProjectID, "target_project_id")
	if err != nil {
		return err
	}
	targetEnv, err := parseUUIDField(body.TargetEnvironmentID, "target_environment_id")
	if err != nil {
		return err
	}
	destProvConn, err := parseUUIDField(body.DestinationProviderConnectionID, "destination_provider_connection_id")
	if err != nil {
		return err
	}

	req, err := h.svc.SubmitCrossTeam(c.Context(), services.CrossTeamSubmitInput{
		RequesterID:                     userID,
		ProjectID:                       body.ProjectID,
		Environment:                     body.Environment,
		TargetTeamID:                    targetTeam,
		TargetProjectID:                 targetProj,
		TargetEnvironmentID:             targetEnv,
		DestinationProviderConnectionID: destProvConn,
		DestinationSecretRef:            body.DestinationSecretRef,
		DestinationKeys:                 body.DestinationKeys,
		Justification:                   body.Justification,
	})
	if err != nil {
		return crossTeamErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(crossTeamRequestToBody(req))
}

// Fill handles POST /api/v1/requests/:id/fill.
func (h *CrossTeam) Fill(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	reqID, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body FillBody
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	keyValues, err := services.DecodeFillKeyValues(body.KeyValues)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	req, err := h.svc.Fill(c.Context(), services.FillCrossTeamInput{
		RequestID:   reqID,
		FillerID:    userID,
		KeyValues:   keyValues,
		FillComment: body.FillComment,
	})
	if err != nil {
		return crossTeamErr(err)
	}
	return c.Status(fiber.StatusOK).JSON(crossTeamRequestToBody(req))
}

// Refuse handles POST /api/v1/requests/:id/refuse.
func (h *CrossTeam) Refuse(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	reqID, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body RefuseBody
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	req, err := h.svc.Refuse(c.Context(), services.RefuseCrossTeamInput{
		RequestID: reqID,
		UserID:    userID,
		Reason:    body.Reason,
	})
	if err != nil {
		return crossTeamErr(err)
	}
	return c.Status(fiber.StatusOK).JSON(crossTeamRequestToBody(req))
}

// Verify handles POST /api/v1/requests/:id/verify.
func (h *CrossTeam) Verify(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	reqID, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body VerifyBody
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	var decision storage.ApprovalDecision
	switch body.Decision {
	case "approve":
		decision = storage.ApprovalDecisionApprove
	case "reject":
		decision = storage.ApprovalDecisionReject
	default:
		return fiber.NewError(fiber.StatusBadRequest, "decision must be 'approve' or 'reject'")
	}
	resp, err := h.svc.VerifyCrossTeam(c.Context(), services.VerifyCrossTeamInput{
		RequestID:  reqID,
		ApproverID: userID,
		VotedAs:    services.VotedAs(body.VotedAs),
		Decision:   decision,
		Comment:    body.Comment,
	})
	if err != nil {
		return crossTeamErr(err)
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}

// Inbox handles GET /api/v1/requests/inbox.
func (h *CrossTeam) Inbox(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	access, err := auth.EffectiveTeamAccess(c.Context(), userID, auth.PermSecretValueProvide, h.resolver, h.teamScope)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	teamIDs, emptyResult, serr := resolveInboxTeamScope(c, access)
	if serr != nil {
		return serr
	}
	if emptyResult {
		// Global + no team_id filter: no "list every team" query in v1;
		// the SPA passes ?team_id= per team.
		return c.Status(fiber.StatusOK).JSON([]CrossTeamRequestBody{})
	}

	rows, err := h.svc.Inbox(c.Context(), services.InboxInput{Limit: 100, TeamIDs: teamIDs})
	if err != nil {
		return crossTeamErr(err)
	}
	out := make([]CrossTeamRequestBody, 0, len(rows))
	for _, r := range rows {
		out = append(out, crossTeamRequestToBody(r))
	}
	return c.Status(fiber.StatusOK).JSON(out)
}

// InboxCount handles GET /api/v1/requests/inbox/count — SPA badge.
func (h *CrossTeam) InboxCount(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	access, err := auth.EffectiveTeamAccess(c.Context(), userID, auth.PermSecretValueProvide, h.resolver, h.teamScope)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	// api#167: resolve the team scope EXACTLY as Inbox does so the badge
	// count and the list never diverge — an explicit out-of-scope team_id
	// is a 403 here too (was previously ignored → 200 {"total":0}).
	teamIDs, emptyResult, serr := resolveInboxTeamScope(c, access)
	if serr != nil {
		return serr
	}
	if emptyResult {
		return c.Status(fiber.StatusOK).JSON(InboxCountResponse{Total: 0})
	}
	// For v1, count is approximate — we return len(Inbox(allowed)). A
	// dedicated COUNT(*) endpoint can land later if needed.
	rows, err := h.svc.Inbox(c.Context(), services.InboxInput{Limit: 500, TeamIDs: teamIDs})
	if err != nil {
		return crossTeamErr(err)
	}
	return c.Status(fiber.StatusOK).JSON(InboxCountResponse{Total: len(rows)})
}

// --- helpers ---------------------------------------------------------------

// resolveInboxTeamScope maps the caller's effective team access plus an
// optional ?team_id= filter to the team set an inbox list/count query should
// use. Both Inbox and InboxCount call it so the badge count and the list can
// never diverge (api#167): an explicit out-of-scope team_id is a 403 on
// BOTH, a malformed team_id is a 400 on both, and the rows counted are
// exactly the rows listed.
//
// Returns:
//   - teamIDs: the allowed-team filter for services.Inbox. A nil/empty slice
//     is fail-closed at the storage layer (ListInbox returns no rows), so it
//     never leaks another team's inbox.
//   - emptyResult: true only when the caller is global AND passed no team_id.
//     There is no "list every team" query in v1 (the SPA passes ?team_id= per
//     team), so both handlers return an empty result in that case.
//   - err: a *fiber.Error (400 "team_id must be a UUID" or 403
//     "out_of_scope_team") to return verbatim.
func resolveInboxTeamScope(c fiber.Ctx, access auth.TeamAccess) (teamIDs []uuid.UUID, emptyResult bool, err error) {
	tidRaw := c.Query("team_id")
	if tidRaw != "" {
		tid, perr := uuid.Parse(tidRaw)
		if perr != nil {
			return nil, false, fiber.NewError(fiber.StatusBadRequest, "team_id must be a UUID")
		}
		// A tenancy-scoped caller may only filter to a team they cover;
		// a global caller may filter to any team.
		if !access.IsGlobal && !containsUUIDValue(access.TeamIDs, tid) {
			return nil, false, fiber.NewError(fiber.StatusForbidden, "out_of_scope_team")
		}
		return []uuid.UUID{tid}, false, nil
	}
	// No explicit filter.
	if access.IsGlobal {
		return nil, true, nil
	}
	return access.TeamIDs, false, nil
}

func parseUUIDField(raw, name string) (uuid.UUID, error) {
	if raw == "" {
		return uuid.Nil, fiber.NewError(fiber.StatusBadRequest, name+" is required")
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, fiber.NewError(fiber.StatusBadRequest, name+" must be a UUID")
	}
	return id, nil
}

func containsUUIDValue(s []uuid.UUID, target uuid.UUID) bool {
	for _, v := range s {
		if v == target {
			return true
		}
	}
	return false
}

func crossTeamErr(err error) error {
	switch {
	case errors.Is(err, services.ErrInvalidInput):
		return fiber.NewError(fiber.StatusBadRequest, "cross_team_invalid_input")
	case errors.Is(err, services.ErrCrossTeamInvalidTarget):
		return fiber.NewError(fiber.StatusBadRequest, "cross_team_invalid_target")
	case errors.Is(err, services.ErrCrossTeamDestinationUnbound):
		return fiber.NewError(fiber.StatusForbidden, "cross_team_destination_unbound")
	case errors.Is(err, services.ErrCrossTeamKeysEmpty):
		return fiber.NewError(fiber.StatusBadRequest, "cross_team_keys_empty")
	case errors.Is(err, services.ErrKeyNotAllowed):
		return fiber.NewError(fiber.StatusForbidden, "cross_team_key_not_allowed")
	case errors.Is(err, services.ErrCrossTeamMinApproversUnsupported):
		return fiber.NewError(fiber.StatusBadRequest, "cross_team_min_approvers_unsupported")
	case errors.Is(err, services.ErrSeparationOfDuties):
		return fiber.NewError(fiber.StatusForbidden, "separation_of_duties_violated")
	case errors.Is(err, storage.ErrCrossTeamAlreadyFilled):
		return fiber.NewError(fiber.StatusConflict, "cross_team_already_filled")
	case errors.Is(err, storage.ErrFillWindowExpired):
		return fiber.NewError(fiber.StatusConflict, "fill_window_expired")
	case errors.Is(err, storage.ErrCrossTeamStatusInvalidTransition):
		return fiber.NewError(fiber.StatusConflict, "cross_team_status_invalid_transition")
	case errors.Is(err, services.ErrDuplicateVote):
		return fiber.NewError(fiber.StatusConflict, "duplicate_vote")
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "not_found")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}

func crossTeamRequestToBody(r *storage.AccessRequest) CrossTeamRequestBody {
	b := CrossTeamRequestBody{
		ID:                   r.ID.String(),
		RequesterID:          r.RequesterID,
		Type:                 string(r.Type),
		Status:               string(r.Status),
		Justification:        r.Justification,
		DestinationSecretRef: r.DestinationSecretRef,
		DestinationKeys:      r.DestinationKeys,
		FillComment:          r.FillComment,
		RefuseReason:         "",
		FilledByUserID:       r.FilledByUserID,
		CreatedAt:            r.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		UpdatedAt:            r.UpdatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if r.TargetTeamID != nil {
		b.TargetTeamID = r.TargetTeamID.String()
	}
	if r.TargetProjectID != nil {
		b.TargetProjectID = r.TargetProjectID.String()
	}
	if r.TargetEnvironmentID != nil {
		b.TargetEnvironmentID = r.TargetEnvironmentID.String()
	}
	if r.DestinationProviderConnectionID != nil {
		b.DestinationProviderConnectionID = r.DestinationProviderConnectionID.String()
	}
	if r.FillExpiresAt != nil {
		b.FillExpiresAt = r.FillExpiresAt.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if r.FilledAt != nil {
		b.FilledAt = r.FilledAt.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if r.SnapRequiresSecurityApproval != nil {
		b.SecurityApprovalRequired = *r.SnapRequiresSecurityApproval
	}
	return b
}
