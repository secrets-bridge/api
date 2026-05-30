// Package handlers — requests.go: HTTP layer for the patch-request
// lifecycle.
//
// Endpoints mounted by main on /api/v1:
//
//	POST   /requests                  submit a patch request
//	GET    /requests                  list (filter: requester_id, status)
//	GET    /requests/:id              get one request + its approvals
//	POST   /requests/:id/approve      cast an approve vote
//	POST   /requests/:id/reject       cast a reject vote with reason
//	POST   /requests/:id/cancel       requester withdraws
//
// The wire format never returns secret values. The submit endpoint
// accepts them once (over TLS), wraps them, and immediately discards
// the plaintext.
package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Requests is the HTTP layer over RequestService.
//
// When the multi-tenancy gate is wired (via WithTenancyGate), POST
// /requests and POST /requests/read pre-flight every submission
// against project_secrets: the caller must hold secret.request at a
// scope covering the body's project_id, AND the secret_ref must be
// bound to that project, AND every requested key must be in the
// binding's allowed_keys (when allowed_keys is non-null), AND the
// requested op (read|patch) must be in allowed_ops. See api#43 Slice C.
type Requests struct {
	svc       *services.RequestService
	bindings  storage.ProjectSecretRepository
	secrets   storage.SecretRepository
	resolver  auth.Resolver
}

// NewRequests binds a handler to its service.
func NewRequests(svc *services.RequestService) *Requests { return &Requests{svc: svc} }

// WithTenancyGate wires the multi-tenancy gate. Pass non-nil values
// for all three; passing nil for any disables the gate (preserves
// legacy "any authenticated caller can submit any request" mode).
func (h *Requests) WithTenancyGate(b storage.ProjectSecretRepository, s storage.SecretRepository, r auth.Resolver) *Requests {
	h.bindings = b
	h.secrets = s
	h.resolver = r
	return h
}

func requestErr(err error) error {
	switch {
	case errors.Is(err, services.ErrInvalidInput):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, services.ErrSelfApprovalDenied):
		return fiber.NewError(fiber.StatusForbidden, "requester cannot approve own request")
	case errors.Is(err, services.ErrDuplicateVote):
		return fiber.NewError(fiber.StatusConflict, "approver has already voted on this request")
	case errors.Is(err, services.ErrRequestNotPending):
		return fiber.NewError(fiber.StatusConflict, "request is not pending")
	case errors.Is(err, services.ErrNotRequester):
		return fiber.NewError(fiber.StatusForbidden, "only the original requester can cancel")
	case errors.Is(err, services.ErrNoDefaultWorkflow):
		return fiber.NewError(fiber.StatusInternalServerError, "no policy matched and no default workflow exists")
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "request not found")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}

// ---- submit ----------------------------------------------------------

// SubmitRequestBody is the JSON sent by the UI.
//
// KeyValues carries one plaintext per key; the server wraps each one
// before it touches Postgres. The handler clears the map before
// returning so the plaintext doesn't outlive the request goroutine.
type SubmitRequestBody struct {
	RequesterID          string            `json:"requester_id"`
	ProjectID            string            `json:"project_id,omitempty"`
	Environment          string            `json:"environment,omitempty"`
	TargetProviderType   string            `json:"target_provider_type"`
	TargetProviderConfig map[string]any    `json:"target_provider_config,omitempty"`
	TargetSecretRef      string            `json:"target_secret_ref"`
	KeyValues            map[string]string `json:"key_values"`
	Justification        string            `json:"justification"`
}

// Submit handles POST /requests.
func (h *Requests) Submit(c fiber.Ctx) error {
	var body SubmitRequestBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if len(body.KeyValues) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "key_values must contain at least one entry")
	}

	kv := make(map[string][]byte, len(body.KeyValues))
	for k, v := range body.KeyValues {
		if strings.TrimSpace(k) == "" {
			return fiber.NewError(fiber.StatusBadRequest, "key_values keys must be non-empty")
		}
		kv[k] = []byte(v)
	}
	// Best-effort drop the strings from the body map.
	for k := range body.KeyValues {
		delete(body.KeyValues, k)
	}

	keysForCheck := make([]string, 0, len(kv))
	for k := range kv {
		keysForCheck = append(keysForCheck, k)
	}
	if err := h.checkTenancy(c, body.ProjectID, body.TargetProviderType, body.TargetSecretRef, keysForCheck, storage.OpPatch); err != nil {
		return err
	}

	req, err := h.svc.Submit(c.Context(), services.PatchInput{
		RequesterID:          body.RequesterID,
		ProjectID:            body.ProjectID,
		Environment:          body.Environment,
		TargetProviderType:   body.TargetProviderType,
		TargetProviderConfig: body.TargetProviderConfig,
		TargetSecretRef:      body.TargetSecretRef,
		KeyValues:            kv,
		Justification:        body.Justification,
	})
	if err != nil {
		return requestErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(requestToBody(req))
}

// ---- list / get ------------------------------------------------------

// List handles GET /requests.
func (h *Requests) List(c fiber.Ctx) error {
	f := storage.AccessRequestListFilter{
		RequesterID: c.Query("requester_id"),
		Status:      storage.AccessRequestStatus(c.Query("status")),
	}
	rows, err := h.svc.List(c.Context(), f)
	if err != nil {
		return requestErr(err)
	}
	out := make([]RequestBody, 0, len(rows))
	for _, r := range rows {
		out = append(out, requestToBody(r))
	}
	return c.JSON(out)
}

// Get handles GET /requests/:id and includes its approvals inline.
func (h *Requests) Get(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	req, err := h.svc.Get(c.Context(), id)
	if err != nil {
		return requestErr(err)
	}
	approvals, err := h.svc.Approvals(c.Context(), id)
	if err != nil {
		return requestErr(err)
	}
	body := requestToBody(req)
	body.Approvals = make([]ApprovalBody, 0, len(approvals))
	for _, a := range approvals {
		body.Approvals = append(body.Approvals, approvalToBody(a))
	}
	return c.JSON(body)
}

// ---- approve / reject / cancel ---------------------------------------

// DecisionBody is the small body for approve/reject.
type DecisionBody struct {
	ApproverID string `json:"approver_id"`
	Comment    string `json:"comment,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// Approve handles POST /requests/:id/approve.
func (h *Requests) Approve(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body DecisionBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	req, err := h.svc.Approve(c.Context(), id, body.ApproverID, body.Comment)
	if err != nil {
		return requestErr(err)
	}
	return c.JSON(requestToBody(req))
}

// Reject handles POST /requests/:id/reject.
func (h *Requests) Reject(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body DecisionBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	req, err := h.svc.Reject(c.Context(), id, body.ApproverID, body.Reason)
	if err != nil {
		return requestErr(err)
	}
	return c.JSON(requestToBody(req))
}

// CancelBody is the body for POST /requests/:id/cancel.
type CancelBody struct {
	ActorID string `json:"actor_id"`
}

// ---- read flow -------------------------------------------------------

// SubmitReadRequestBody is the JSON sent by the UI when a user wants
// to VIEW one or more keys from a provider secret. No values are sent —
// the agent will fetch them after approval.
type SubmitReadRequestBody struct {
	RequesterID          string         `json:"requester_id"`
	ProjectID            string         `json:"project_id,omitempty"`
	Environment          string         `json:"environment,omitempty"`
	TargetProviderType   string         `json:"target_provider_type"`
	TargetProviderConfig map[string]any `json:"target_provider_config,omitempty"`
	TargetSecretRef      string         `json:"target_secret_ref"`
	TargetKeys           []string       `json:"target_keys,omitempty"`
	Justification        string         `json:"justification"`
}

// SubmitRead handles POST /requests/read.
func (h *Requests) SubmitRead(c fiber.Ctx) error {
	var body SubmitReadRequestBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if err := h.checkTenancy(c, body.ProjectID, body.TargetProviderType, body.TargetSecretRef, body.TargetKeys, storage.OpRead); err != nil {
		return err
	}
	req, err := h.svc.SubmitRead(c.Context(), services.ReadInput{
		RequesterID:          body.RequesterID,
		ProjectID:            body.ProjectID,
		Environment:          body.Environment,
		TargetProviderType:   body.TargetProviderType,
		TargetProviderConfig: body.TargetProviderConfig,
		TargetSecretRef:      body.TargetSecretRef,
		TargetKeys:           body.TargetKeys,
		Justification:        body.Justification,
	})
	if err != nil {
		return requestErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(requestToBody(req))
}

// RetrieveWrapBody is the JSON returned to the requesting user when
// retrieving a wrap created by the agent during a read flow.
type RetrieveWrapBody struct {
	WrapID      string `json:"wrap_id"`
	RequestID   string `json:"request_id"`
	KeyName     string `json:"key_name,omitempty"`
	Value       string `json:"value"` // base64-encoded plaintext
	ByteLength  int    `json:"byte_length"`
	ContentHash string `json:"content_hash"`
	Algorithm   string `json:"algorithm"`
}

// RetrieveWrapForUserQuery holds the user identifier the handler needs
// to authorize the retrieval. Today the user identity comes from a
// `user_id` query string param — real auth integration replaces this
// with a middleware-stashed identity later.
type RetrieveWrapForUserQuery struct {
	UserID string `json:"user_id"`
}

// RetrieveWrap handles GET /api/v1/requests/:id/wraps/:wrap_id.
//
// Authorization (today): user identity comes from the `user_id` query
// param. When the auth design lands this swaps to a middleware-stashed
// identity, but the service-layer check (requester == userID) remains
// the load-bearing rule.
func (h *Requests) RetrieveWrap(c fiber.Ctx) error {
	reqID, err := parseID(c, "id")
	if err != nil {
		return err
	}
	wrapID, err := parseID(c, "wrap_id")
	if err != nil {
		return err
	}
	userID := c.Query("user_id")
	if userID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "user_id query param required (until auth middleware lands)")
	}

	plaintext, wrap, err := h.svc.RetrieveWrapForUser(c.Context(), reqID, wrapID, userID)
	if err != nil {
		return retrieveUserWrapErr(err)
	}
	defer zero(plaintext)

	return c.Status(fiber.StatusOK).JSON(RetrieveWrapBody{
		WrapID:      wrap.ID.String(),
		RequestID:   reqID.String(),
		KeyName:     wrap.KeyName,
		Value:       base64.StdEncoding.EncodeToString(plaintext),
		ByteLength:  wrap.ByteLength,
		ContentHash: hex.EncodeToString(wrap.ContentHash),
		Algorithm:   wrap.Algorithm,
	})
}

func retrieveUserWrapErr(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound), errors.Is(err, services.ErrWrongRequest):
		return fiber.NewError(fiber.StatusNotFound, "wrap not found")
	case errors.Is(err, storage.ErrAlreadyConsumed):
		return fiber.NewError(fiber.StatusGone, "wrap already consumed")
	case errors.Is(err, storage.ErrExpired):
		return fiber.NewError(fiber.StatusGone, "wrap expired")
	case errors.Is(err, services.ErrRequestNotApproved):
		return fiber.NewError(fiber.StatusConflict, "request not retrievable in current state")
	case errors.Is(err, services.ErrNotRequestOwner):
		return fiber.NewError(fiber.StatusForbidden, "only the original requester may retrieve")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}

// WrapSummaryBody is the value-free metadata view returned by the
// wrap-summaries endpoint. Lets the UI render the Wraps card on the
// request detail page (one row per key with a ready/consumed pill)
// without ever fetching plaintext until the user explicitly clicks
// Reveal — which goes through the existing single-shot RetrieveWrap
// path. NEVER carries plaintext.
type WrapSummaryBody struct {
	ID        string `json:"id"`
	KeyName   string `json:"key_name,omitempty"`
	Consumed  bool   `json:"consumed"`
	ExpiresAt string `json:"expires_at"`
}

// ListWraps handles GET /api/v1/requests/:id/wraps and returns the
// value-free wrap summaries for the request. Lets the requester see
// which keys have wraps issued (and whether each is already consumed)
// without revealing any plaintext.
//
// Authorization (today): consistent with RetrieveWrap, the user
// identity comes from the `user_id` query param. The service layer's
// ownership check (requester == userID) gates the response.
func (h *Requests) ListWraps(c fiber.Ctx) error {
	reqID, err := parseID(c, "id")
	if err != nil {
		return err
	}
	userID := c.Query("user_id")
	if userID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "user_id query param required (until auth middleware lands)")
	}

	req, err := h.svc.Get(c.Context(), reqID)
	if err != nil {
		return requestErr(err)
	}
	if req.RequesterID != userID {
		return fiber.NewError(fiber.StatusForbidden, "only the original requester may list wraps")
	}

	summaries, err := h.svc.WrapSummariesForRequest(c.Context(), reqID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	out := make([]WrapSummaryBody, 0, len(summaries))
	for _, s := range summaries {
		out = append(out, WrapSummaryBody{
			ID:        s.ID.String(),
			KeyName:   s.KeyName,
			Consumed:  s.Consumed,
			ExpiresAt: s.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	return c.JSON(out)
}

// ---- end read flow ---------------------------------------------------

// Cancel handles POST /requests/:id/cancel.
func (h *Requests) Cancel(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body CancelBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	req, err := h.svc.Cancel(c.Context(), id, body.ActorID)
	if err != nil {
		return requestErr(err)
	}
	return c.JSON(requestToBody(req))
}

// ---- wire shapes -----------------------------------------------------

// RequestBody is the JSON we return for an access_request. Notice it
// carries the target-key NAMES but NEVER any plaintext values.
type RequestBody struct {
	ID                   string         `json:"id"`
	RequesterID          string         `json:"requester_id"`
	Type                 string         `json:"type"`
	Justification        string         `json:"justification"`
	Status               string         `json:"status"`
	WorkflowID           string         `json:"workflow_id,omitempty"`
	TargetProviderType   string         `json:"target_provider_type,omitempty"`
	TargetProviderConfig map[string]any `json:"target_provider_config,omitempty"`
	TargetSecretRef      string         `json:"target_secret_ref,omitempty"`
	TargetKeys           []string       `json:"target_keys,omitempty"`
	TargetScope          map[string]any `json:"target_scope,omitempty"`
	JobID                string         `json:"job_id,omitempty"`
	RejectReason         string         `json:"reject_reason,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	Approvals            []ApprovalBody `json:"approvals,omitempty"`
}

// ApprovalBody is the JSON shape for one approval row.
type ApprovalBody struct {
	ID         string    `json:"id"`
	ApproverID string    `json:"approver_id"`
	Decision   string    `json:"decision"`
	Comment    string    `json:"comment,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

func requestToBody(r *storage.AccessRequest) RequestBody {
	body := RequestBody{
		ID:                   r.ID.String(),
		RequesterID:          r.RequesterID,
		Type:                 string(r.Type),
		Justification:        r.Justification,
		Status:               string(r.Status),
		TargetProviderType:   r.TargetProviderType,
		TargetProviderConfig: r.TargetProviderConfig,
		TargetSecretRef:      r.TargetSecretRef,
		TargetKeys:           r.TargetKeys,
		TargetScope:          r.TargetScope,
		RejectReason:         r.RejectReason,
		CreatedAt:            r.CreatedAt,
		UpdatedAt:            r.UpdatedAt,
	}
	if r.WorkflowID != nil {
		body.WorkflowID = r.WorkflowID.String()
	}
	if r.JobID != nil {
		body.JobID = r.JobID.String()
	}
	return body
}

func approvalToBody(a *storage.Approval) ApprovalBody {
	return ApprovalBody{
		ID:         a.ID.String(),
		ApproverID: a.ApproverID,
		Decision:   string(a.Decision),
		Comment:    a.Comment,
		CreatedAt:  a.CreatedAt,
	}
}

// checkTenancy is the multi-tenancy gate on POST /requests +
// /requests/read. Returns nil when scoping isn't wired (legacy mode)
// or when the request is in-scope; otherwise returns a fiber error
// with the right status code + a generic message. The audit trail
// records the specifics via the request lifecycle's existing audit
// events; this handler stays terse on purpose.
//
// `op` is one of storage.OpRead / storage.OpPatch.
//
// Resolution model:
//   - identity missing                 → 401
//   - body.project_id missing/invalid  → 400
//   - caller scoped but project_id not in their access set → 403
//   - secret_ref not bound to project_id                    → 403
//   - any requested key not in binding.allowed_keys         → 403
//   - op not in binding.allowed_ops                         → 403
//   - happy path                                            → nil
func (h *Requests) checkTenancy(c fiber.Ctx, projectIDRaw, providerType, secretRef string, requestedKeys []string, op string) error {
	if h.bindings == nil || h.secrets == nil || h.resolver == nil {
		return nil
	}
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	if projectIDRaw == "" {
		return fiber.NewError(fiber.StatusBadRequest, "project_id is required")
	}
	projectID, err := uuid.Parse(projectIDRaw)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "project_id must be a UUID")
	}

	// Step 1: caller has secret.request at a scope covering this project?
	access, err := auth.EffectiveProjectAccess(c.Context(), userID, auth.PermSecretRequest, h.resolver)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if !access.IsGlobal {
		if !containsUUID(access.ProjectIDs, projectID) {
			return fiber.NewError(fiber.StatusForbidden, "out_of_scope_project")
		}
	}

	// Step 2: find a binding for (project, provider_type, secret_ref).
	//
	// The catalog row identity is (cluster_name, provider_type, secret_ref);
	// the same ref can exist on multiple clusters. Look up every match
	// and accept the first row that has a binding to this project.
	secrets, err := h.secrets.ListByRef(c.Context(), providerType, secretRef)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if len(secrets) == 0 {
		return fiber.NewError(fiber.StatusForbidden, "out_of_scope_project")
	}
	var binding *storage.ProjectSecret
	for _, s := range secrets {
		b, err := h.bindings.Get(c.Context(), projectID, s.ID)
		if err == nil {
			binding = b
			break
		}
		if !errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
	}
	if binding == nil {
		return fiber.NewError(fiber.StatusForbidden, "out_of_scope_project")
	}

	// Step 3: requested op allowed?
	if !containsString(binding.AllowedOps, op) {
		return fiber.NewError(fiber.StatusForbidden, "out_of_scope_op")
	}

	// Step 4: every requested key in allowed_keys (when non-null)?
	if binding.AllowedKeys != nil {
		for _, k := range requestedKeys {
			if !containsString(binding.AllowedKeys, k) {
				return fiber.NewError(fiber.StatusForbidden, "out_of_scope_key")
			}
		}
	}
	return nil
}

func containsString(set []string, target string) bool {
	for _, s := range set {
		if s == target {
			return true
		}
	}
	return false
}
