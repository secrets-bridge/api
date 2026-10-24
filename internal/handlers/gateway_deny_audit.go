package handlers

import (
	"errors"
	"log/slog"
	"regexp"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Denied Gateway admin writes (api#312, ADR 0002 section 5: allow and
// deny outcomes are audited). AuditGatewayDenied wraps a write route in
// front of its permission and step-up guards, so one place sees every
// refusal: a missing or scoped grant (403), a stale second factor (401
// step_up_required), no factor enrolled (412) and the rules the handler
// checks (400, 404, 409). A refused call writes one audit row with
// status denied, the route's action and a closed error_kind. A 2xx or
// a 5xx writes nothing here: the service audits a success itself, and a
// server error is not a decision.
//
// The metadata carries the UUID path parameters only (gateway_id,
// connector_id, binding_id), each parsed as a UUID. Nothing from the
// body is read, so a target id, a namespace, a name or a secret
// reference the caller is not allowed to see never reaches the row.

// gatewayDenyErrorKindRe is a closed machine code, as the handlers
// answer them.
var gatewayDenyErrorKindRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// GatewayDenyPathIDs maps a UUID route parameter to its audit metadata
// key.
type GatewayDenyPathIDs map[string]string

// AuditGatewayDenied returns the middleware for action. ids names the
// UUID route parameters to record.
func AuditGatewayDenied(repo storage.AuditEventRepository, action string, ids GatewayDenyPathIDs) fiber.Handler {
	return func(c fiber.Ctx) error {
		err := c.Next()
		status := c.Response().StatusCode()
		msg := ""
		var fe *fiber.Error
		if errors.As(err, &fe) {
			status, msg = fe.Code, fe.Message
		} else if err != nil {
			return err // not a decision: the error handler answers 500
		}
		if repo == nil || status < 400 || status > 499 {
			return err
		}
		meta := map[string]any{"error_kind": gatewayDenyErrorKind(status, msg)}
		resource := "gateway"
		for param, key := range ids {
			if id, perr := uuid.Parse(c.Params(param)); perr == nil {
				meta[key] = id.String()
				if key == "gateway_id" {
					resource = "gateway:" + id.String()
				}
			}
		}
		evt := &storage.AuditEvent{
			Actor: auth.AuditActor(c.Context()), Action: action, Resource: resource,
			Status: storage.AuditStatusDenied, CorrelationID: uuid.New(), Metadata: meta,
		}
		if aerr := repo.Append(c.Context(), evt); aerr != nil {
			slog.WarnContext(c.Context(), "audit append failed", "action", action, "err", aerr)
		}
		return err
	}
}

// gatewayDenyErrorKind is the handler's closed code when it sent one
// (step_up_required, target_not_advertised, ...), else a code for the
// status. A permission refusal's text names the permission, so it maps
// to permission_denied.
func gatewayDenyErrorKind(status int, msg string) string {
	switch {
	case status == fiber.StatusForbidden:
		return "permission_denied"
	case gatewayDenyErrorKindRe.MatchString(msg):
		return msg
	case status == fiber.StatusUnauthorized:
		return "unauthenticated"
	case status == fiber.StatusNotFound:
		return "not_found"
	case status == fiber.StatusConflict:
		return "conflict"
	}
	return "invalid_request"
}

// Gateway write routes whose refusals are audited, with their path ids.
var (
	GatewayDenyApprove = GatewayDenyPathIDs{"id": "gateway_id", "cid": "connector_id"}
	GatewayDenyConfirm = GatewayDenyPathIDs{"id": "gateway_id", "cid": "connector_id"}
	GatewayDenyBind    = GatewayDenyPathIDs{}
	GatewayDenyDelete  = GatewayDenyPathIDs{"id": "binding_id"}
)
