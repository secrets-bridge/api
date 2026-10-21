package handlers

// Gateway observation HTTP layer (api#294).
//
// Machine routes (X-Gateway-Secret through middleware.GatewayAuth, under
// the session-exempt /api/v1/gateways/:id group), matching the Gateway
// client on gateway main (internal/client):
//
//	E4 POST /gateways/:id/tasks/claim                 200 task, 204 idle
//	E5 POST /gateways/:id/tasks/:task_id/lease        200 {lease_expires_at}
//	E6 POST /gateways/:id/tasks/:task_id/release      204
//	E7 POST /gateways/:id/tasks/:task_id/result       200 accepted or duplicate
//
// Errors are {"error": "<code>"} from a closed list; no error body echoes
// request content.
//
// Admin routes (session gate, gateway.* permission, fresh second factor
// on writes, wired in cmd/api): Gateway enable and disable, a Gateway's
// tasks, and an environment's observation source. The request page
// reads its evidence through Requests.Observations.

import (
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// WithObservations wires the observation service for E4 to E7 and the
// observation admin routes.
func (h *Gateways) WithObservations(obs *services.GatewayObservationService) *Gateways {
	h.obs = obs
	return h
}

func taskPathID(c fiber.Ctx) (uuid.UUID, bool) {
	raw := c.Params("task_id")
	id, err := uuid.Parse(raw)
	if err != nil || id.String() != raw {
		return uuid.Nil, false
	}
	return id, true
}

// observationError maps a service error to the closed wire codes the
// Gateway client knows (internal/client/errors.go).
func observationError(c fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, services.ErrObservationInvalidRequest):
		return gwError(c, fiber.StatusBadRequest, "invalid_request")
	case errors.Is(err, services.ErrObservationGatewayNotLive):
		return gwError(c, fiber.StatusUnauthorized, "unauthorized")
	case errors.Is(err, services.ErrObservationNotFound):
		return gwError(c, fiber.StatusNotFound, "not_found")
	case errors.Is(err, services.ErrObservationAttemptSuperseded):
		return gwError(c, fiber.StatusConflict, "attempt_superseded")
	case errors.Is(err, services.ErrObservationLeaseExpired):
		return gwError(c, fiber.StatusConflict, "lease_expired")
	case errors.Is(err, services.ErrObservationTaskClosed):
		return gwError(c, fiber.StatusConflict, "task_closed")
	case errors.Is(err, services.ErrObservationResultConflict):
		return gwError(c, fiber.StatusConflict, "result_conflict")
	case errors.Is(err, services.ErrObservationContractUnsupported):
		return gwError(c, fiber.StatusConflict, "contract_version_unsupported")
	case errors.Is(err, services.ErrObservationSchema):
		return gwError(c, fiber.StatusUnprocessableEntity, "schema_violation")
	case errors.Is(err, services.ErrObservationOutOfWindow):
		return gwError(c, fiber.StatusUnprocessableEntity, "evidence_out_of_window")
	}
	return err
}

type claimRequest struct {
	ReplicaID string `json:"replica_id"`
	MaxTasks  int    `json:"max_tasks"`
}

// Claim handles POST /api/v1/gateways/:id/tasks/claim (E4).
func (h *Gateways) Claim(c fiber.Ctx) error {
	id, err := authenticatedGateway(c)
	if err != nil {
		return err
	}
	var req claimRequest
	if err := decodeStrict(c.Body(), &req); err != nil {
		return gwError(c, fiber.StatusBadRequest, "invalid_request")
	}
	task, err := h.obs.Claim(c.Context(), id, services.ObservationClaimInput{ReplicaID: req.ReplicaID, MaxTasks: req.MaxTasks})
	retry := strconv.Itoa(int(h.obs.Config().ClaimRetryAfter / time.Second))
	switch {
	case errors.Is(err, services.ErrObservationNoTask):
		c.Set(fiber.HeaderRetryAfter, retry)
		return c.SendStatus(fiber.StatusNoContent)
	case errors.Is(err, services.ErrObservationAtCapacity):
		c.Set(fiber.HeaderRetryAfter, retry)
		return gwError(c, fiber.StatusTooManyRequests, "inflight_limit")
	case err != nil:
		return observationError(c, err)
	}
	return c.JSON(task)
}

type attemptRequest struct {
	ReplicaID string `json:"replica_id"`
	AttemptID string `json:"attempt_id"`
}

type releaseRequest struct {
	ReplicaID string `json:"replica_id"`
	AttemptID string `json:"attempt_id"`
	Reason    string `json:"reason"`
}

// RenewLease handles POST /api/v1/gateways/:id/tasks/:task_id/lease (E5).
func (h *Gateways) RenewLease(c fiber.Ctx) error {
	id, err := authenticatedGateway(c)
	if err != nil {
		return err
	}
	taskID, ok := taskPathID(c)
	if !ok {
		return gwError(c, fiber.StatusNotFound, "not_found")
	}
	var req attemptRequest
	if err := decodeStrict(c.Body(), &req); err != nil {
		return gwError(c, fiber.StatusBadRequest, "invalid_request")
	}
	exp, err := h.obs.Renew(c.Context(), id, taskID, services.ObservationAttemptInput{ReplicaID: req.ReplicaID, AttemptID: req.AttemptID})
	if err != nil {
		return observationError(c, err)
	}
	return c.JSON(fiber.Map{"lease_expires_at": exp.UTC().Format(time.RFC3339Nano)})
}

// Release handles POST /api/v1/gateways/:id/tasks/:task_id/release (E6).
func (h *Gateways) Release(c fiber.Ctx) error {
	id, err := authenticatedGateway(c)
	if err != nil {
		return err
	}
	taskID, ok := taskPathID(c)
	if !ok {
		return gwError(c, fiber.StatusNotFound, "not_found")
	}
	var req releaseRequest
	if err := decodeStrict(c.Body(), &req); err != nil {
		return gwError(c, fiber.StatusBadRequest, "invalid_request")
	}
	if err := h.obs.Release(c.Context(), id, taskID, services.ObservationAttemptInput{
		ReplicaID: req.ReplicaID, AttemptID: req.AttemptID, Reason: req.Reason,
	}); err != nil {
		return observationError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Result handles POST /api/v1/gateways/:id/tasks/:task_id/result (E7).
// The body is passed through unparsed: the service checks ids, replay,
// fence, schema, scope and window in order, inside one transaction.
func (h *Gateways) Result(c fiber.Ctx) error {
	id, err := authenticatedGateway(c)
	if err != nil {
		return err
	}
	taskID, ok := taskPathID(c)
	if !ok {
		return gwError(c, fiber.StatusNotFound, "not_found")
	}
	body := append([]byte(nil), c.Body()...)
	res, err := h.obs.SubmitResult(c.Context(), id, taskID, body)
	if err != nil {
		return observationError(c, err)
	}
	return c.JSON(res)
}

// ---- admin ----------------------------------------------------------------

type setEnabledRequest struct {
	Enabled *bool `json:"enabled"`
}

// AdminSetEnabled handles PUT /admin/gateways/:id/enabled (gateway.revoke,
// fresh MFA). Disabling refuses the Gateway's next call with 401 and
// moves its leased tasks back to queued; enabling undoes it.
func (h *Gateways) AdminSetEnabled(c fiber.Ctx) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	var req setEnabledRequest
	if err := decodeStrict(c.Body(), &req); err != nil || req.Enabled == nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid_request")
	}
	g, err := h.svc.SetEnabled(c.Context(), id, *req.Enabled, actor)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "gateway_not_found")
	case errors.Is(err, services.ErrCredentialCacheUnconfirmed) && *req.Enabled:
		// Enabled in the database; a stale tombstone may refuse the
		// Gateway until the background retry clears it.
		return cacheUnconfirmed(c, "enabled_cache_unconfirmed")
	case errors.Is(err, services.ErrCredentialCacheUnconfirmed):
		return cacheUnconfirmed(c, "revoked_cache_unconfirmed")
	case errors.Is(err, storage.ErrGatewayStatusConflict):
		return fiber.NewError(fiber.StatusConflict, "gateway_revoked")
	case err != nil:
		return err
	}
	return c.JSON(toGatewayView(g))
}

type observationTaskView struct {
	ID              string                            `json:"id"`
	RequestID       string                            `json:"request_id"`
	GatewayID       string                            `json:"gateway_id"`
	GatewayName     string                            `json:"gateway_name,omitempty"`
	BindingID       string                            `json:"binding_id"`
	EnvironmentID   string                            `json:"environment_id"`
	CorrelationID   string                            `json:"correlation_id"`
	ConnectorRefs   []storage.ObservationConnectorRef `json:"connector_refs"`
	ExpectedStages  []string                          `json:"expected_stages"`
	State           string                            `json:"state"`
	Verdict         string                            `json:"verdict"`
	VerdictReason   string                            `json:"verdict_reason,omitempty"`
	VersionSource   string                            `json:"version_source"`
	AttemptCount    int                               `json:"attempt_count"`
	FailureCount    int                               `json:"failure_count"`
	LeasedReplicaID *string                           `json:"leased_replica_id,omitempty"`
	LeaseExpiresAt  *string                           `json:"lease_expires_at,omitempty"`
	NotBefore       string                            `json:"not_before"`
	DeadlineAt      string                            `json:"deadline_at"`
	ExecutedAt      string                            `json:"executed_at"`
	LastResultAt    *string                           `json:"last_result_at,omitempty"`
	CreatedAt       string                            `json:"created_at"`
	TerminalAt      *string                           `json:"terminal_at,omitempty"`
}

func toObservationTaskView(t *storage.ObservationTask) observationTaskView {
	return observationTaskView{
		ID: t.ID.String(), RequestID: t.RequestID.String(), GatewayID: t.GatewayID.String(), GatewayName: t.GatewayName,
		BindingID: t.BindingID.String(), EnvironmentID: t.EnvironmentID.String(), CorrelationID: t.CorrelationID.String(),
		ConnectorRefs: t.ConnectorRefs, ExpectedStages: t.ExpectedStages, State: string(t.State), Verdict: string(t.Verdict),
		VerdictReason: t.VerdictReason, VersionSource: t.VersionSource, AttemptCount: t.AttemptCount,
		FailureCount: t.FailureCount, LeasedReplicaID: uuidPtr(t.LeasedReplicaID), LeaseExpiresAt: timePtr(t.LeaseExpiresAt),
		NotBefore: t.NotBefore.UTC().Format(time.RFC3339), DeadlineAt: t.DeadlineAt.UTC().Format(time.RFC3339),
		ExecutedAt: t.ExecutedAt.UTC().Format(time.RFC3339), LastResultAt: timePtr(t.LastResultAt),
		CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339), TerminalAt: timePtr(t.TerminalAt),
	}
}

// AdminTasks handles GET /admin/gateways/:id/tasks (gateway.list),
// optionally ?state= and ?limit=.
func (h *Gateways) AdminTasks(c fiber.Ctx) error {
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	limit := 100
	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			return fiber.NewError(fiber.StatusBadRequest, "invalid_limit")
		}
		limit = n
	}
	tasks, err := h.obs.GatewayTasks(c.Context(), id, c.Query("state"), limit)
	if errors.Is(err, services.ErrObservationInvalidRequest) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid_state")
	}
	if err != nil {
		return err
	}
	// counts covers every task of the Gateway per state, not only the
	// returned page or the ?state= filter (api#298).
	counts, err := h.obs.GatewayTaskCounts(c.Context(), id)
	if err != nil {
		return err
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	items := make([]observationTaskView, 0, len(tasks))
	for _, t := range tasks {
		items = append(items, toObservationTaskView(t))
	}
	return c.JSON(fiber.Map{"items": items, "counts": counts, "total": total})
}

// AdminGetObservationSource handles GET
// /admin/environments/:id/observation-source (gateway.list; the PUT stays
// on gateway.bind).
func (h *Gateways) AdminGetObservationSource(c fiber.Ctx) error {
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	src, err := h.obs.EnvironmentSource(c.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "environment_not_found")
	}
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"environment_id": id.String(), "observation_source": string(src)})
}

type observationSourceRequest struct {
	ObservationSource string `json:"observation_source"`
}

// AdminSetObservationSource handles PUT
// /admin/environments/:id/observation-source (gateway.bind, fresh MFA).
func (h *Gateways) AdminSetObservationSource(c fiber.Ctx) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	var req observationSourceRequest
	if err := decodeStrict(c.Body(), &req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid_request")
	}
	src := storage.ObservationSource(req.ObservationSource)
	out, err := h.obs.SetObservationSource(c.Context(), id, src, actor)
	switch {
	case errors.Is(err, services.ErrObservationSourceRetired):
		return fiber.NewError(fiber.StatusBadRequest, "source_retired")
	case errors.Is(err, services.ErrObservationInvalidSource):
		return fiber.NewError(fiber.StatusBadRequest, "invalid_observation_source")
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "environment_not_found")
	case err != nil:
		return err
	}
	return c.JSON(fiber.Map{
		"environment_id": id.String(), "observation_source": string(src),
		"previous_observation_source": string(out.Previous), "tasks_cancelled": len(out.Cancelled),
	})
}

// ---- request page -------------------------------------------------------------

// WithObservations wires the Gateway evidence read for the request page.
func (h *Requests) WithObservations(obs *services.GatewayObservationService) *Requests {
	h.obs = obs
	return h
}

type requestObservationTaskBody struct {
	TaskID         string                     `json:"task_id"`
	GatewayID      string                     `json:"gateway_id"`
	GatewayName    string                     `json:"gateway_name"`
	State          string                     `json:"state"`
	Verdict        string                     `json:"verdict"`
	VerdictReason  string                     `json:"verdict_reason,omitempty"`
	ExpectedStages []string                   `json:"expected_stages"`
	VersionSource  string                     `json:"version_source"`
	AttemptCount   int                        `json:"attempt_count"`
	DeadlineAt     string                     `json:"deadline_at"`
	CreatedAt      string                     `json:"created_at"`
	TerminalAt     *string                    `json:"terminal_at,omitempty"`
	Stages         []services.EvidenceDisplay `json:"stages"`
	// TimedOutAtRead is true when the task is shown as timed out because
	// its deadline passed and the deadline sweeper has not closed the row
	// yet (api#297). The read does not write.
	TimedOutAtRead bool `json:"timed_out_at_read,omitempty"`
}

// Observations handles GET /requests/:id/observations: the request's
// Gateway tasks and their latest accepted evidence per stage, behind the
// same read check as GET /requests/:id. Every stage line is labelled as
// observed operational state; Argo CD lines always carry
// argocd_health_not_proof. Resource namespaces and names are not shown
// (admin display only).
func (h *Requests) Observations(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	req, err := h.svc.Get(c.Context(), id)
	if err != nil {
		return requestErr(err)
	}
	if err := h.authorizeRequestRead(c, req); err != nil {
		return err
	}
	if h.obs == nil {
		return c.JSON(fiber.Map{"observation_source": nil, "rollup": services.ObservationRollupNone, "label": services.ObservationLabel, "tasks": []any{}})
	}
	v, err := h.obs.RequestObservations(c.Context(), req)
	if err != nil {
		return err
	}
	tasks := make([]requestObservationTaskBody, 0, len(v.Tasks))
	for _, t := range v.Tasks {
		b := requestObservationTaskBody{
			TaskID: t.ID.String(), GatewayID: t.GatewayID.String(), GatewayName: t.GatewayName,
			State: string(t.State), Verdict: string(t.Verdict), VerdictReason: t.VerdictReason,
			ExpectedStages: t.ExpectedStages, VersionSource: t.VersionSource, AttemptCount: t.AttemptCount,
			DeadlineAt: t.DeadlineAt.UTC().Format(time.RFC3339), CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339),
			TerminalAt: timePtr(t.TerminalAt), TimedOutAtRead: v.TimedOutAtRead[t.ID], Stages: []services.EvidenceDisplay{},
		}
		for _, e := range v.Evidence[t.ID] {
			b.Stages = append(b.Stages, services.DisplayEvidence(e, t.ConnectorRefs))
		}
		tasks = append(tasks, b)
	}
	return c.JSON(fiber.Map{
		"observation_source": string(v.Source), "rollup": v.Rollup, "label": services.ObservationLabel, "tasks": tasks,
	})
}
