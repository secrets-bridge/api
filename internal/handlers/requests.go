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
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Requests is the HTTP layer over RequestService.
type Requests struct {
	svc *services.RequestService
}

// NewRequests binds a handler to its service.
func NewRequests(svc *services.RequestService) *Requests { return &Requests{svc: svc} }

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
