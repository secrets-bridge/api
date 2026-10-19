package storage

import (
	"encoding/json"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/secrets-bridge/api/pkg/sanitize"
)

// Audit metadata allowlist (api#263).
//
// Callers are expected to put metadata only, never values, into an
// audit event, but nothing checked that at the point where the row is
// written, and the audit table is append-only: whatever lands there
// stays. SanitizeAuditMetadata is that check. It runs on every write
// (Append, AppendTx and the platform-settings insert) and keeps a key
// only when it is on the list below and its value has the shape the
// list allows. It does not rely on spotting secrets: an unknown key is
// dropped whatever it holds, free-text error strings never persist, and
// the credential patterns are a second check on the few name fields.
//
// What is dropped is named (never shown) in `_dropped_keys` (unknown
// key) and `_rejected_keys` (known key, value of the wrong shape), and
// logged with the action and key name, so a missing entry shows up in
// tests and logs instead of silently losing metadata.

type auditMetaKind int

const (
	metaID               auditMetaKind = iota // UUID, prefix:UUID, ARN or other opaque id
	metaToken                                 // enum, code, permission, algorithm
	metaName                                  // a name a person or system chose: bounded, printable, no credentials
	metaEmail                                 // an email address
	metaNumber                                // JSON number
	metaBool                                  // JSON bool
	metaScalar                                // number, bool or token
	metaTime                                  // RFC 3339 timestamp
	metaDigest                                // hex or base64 digest or fingerprint
	metaIDList                                // list of metaID
	metaTokenList                             // list of metaToken
	metaNameList                              // list of metaName
	metaNameListOrScalar                      // list of metaName, or number/bool/token
	metaObject                                // nested map, its keys checked against this table
	metaErrorText                             // free-text error: never stored, logged sanitized instead
)

// auditMetaKeys is the allowlist: every key an audit event may carry,
// and the shape of its value. A new key goes here in the same change
// that starts writing it.
var auditMetaKeys = map[string]auditMetaKind{
	// ids
	"aaguid": metaID, "agent_id": metaID, "attempted_environment_id": metaID, "attempted_project_id": metaID,
	"attempted_team_id": metaID, "attempted_workflow_id": metaID, "binding_id": metaID, "connection_id": metaID,
	"default_role_id": metaID, "enrollment_token_id": metaID, "environment": metaID, "environment_id": metaID,
	"filled_by": metaID, "job_id": metaID, "kms_key_id": metaID, "new_parent_team_id": metaID,
	"observation_id": metaID, "old_parent_team_id": metaID, "parent_team_id": metaID,
	"parent_team_id_after": metaID, "parent_team_id_before": metaID, "policy_rule_id": metaID,
	"previous_environment_id": metaID, "project_id": metaID, "provider_connection_id": metaID,
	"provider_id": metaID, "request_id": metaID, "requester_id": metaID, "role_id": metaID, "rule_id": metaID,
	"session_id": metaID, "target_environment_id": metaID, "target_project_id": metaID, "target_team_id": metaID,
	"team_id": metaID, "team_id_after": metaID, "team_id_before": metaID, "user_id": metaID,
	"workflow_id": metaID, "wrap_id": metaID, "secret_id": metaID, "user_role_id": metaID, "granted_by": metaID,

	// enums and codes
	"actor_permission_attempted": metaToken, "actor_permission_used": metaToken, "algorithm": metaToken,
	"attempted_action": metaToken, "decision": metaToken, "env_kind": metaToken, "environment_kind": metaToken,
	"error_kind": metaToken, "expected_provider_type": metaToken, "factor": metaToken, "job_status": metaToken,
	"job_type": metaToken, "kind": metaToken, "kind_after": metaToken, "kind_before": metaToken,
	"path": metaToken, "phase": metaToken, "prior_lane": metaToken, "provider_type": metaToken,
	"public_key_algorithm": metaToken, "purpose": metaToken, "refusal_reason": metaToken,
	"request_type": metaToken, "risk_level_before": metaToken, "role": metaToken, "scope": metaToken,
	"severity": metaToken, "state": metaToken, "status": metaToken, "sweeper": metaToken, "target": metaToken,
	"target_provider_type": metaToken, "triggered_by": metaToken, "type": metaToken, "voted_as": metaToken,

	// names
	"acr": metaName, "agent_version": metaName, "application_name": metaName, "base_url": metaName,
	"client_id": metaName, "cluster_name": metaName, "destination_secret_ref": metaName,
	"display_name": metaName, "email": metaEmail, "email_at_link": metaEmail, "environment_name": metaName,
	"expected_cluster_name": metaName, "ip": metaName, "iss": metaName, "key": metaName, "label": metaName,
	"name": metaName, "project_filter": metaName, "public_url": metaName, "reason": metaName, "sub": metaName, "target_secret_ref": metaName,
	"user_agent": metaName,

	// numbers
	"affected_project_count": metaNumber, "app_count": metaNumber, "applications_observed": metaNumber,
	"approves": metaNumber, "bindings_count_at_delete": metaNumber, "byte_length": metaNumber, "count": metaNumber,
	"dropped_count": metaNumber, "duration_seconds": metaNumber, "email_length": metaNumber,
	"entry_count": metaNumber, "failed_login_count": metaNumber, "fill_ttl_seconds": metaNumber,
	"height": metaNumber, "key_count": metaNumber, "min_approvers": metaNumber,
	"open_requests_count_at_delete": metaNumber, "request_ttl_seconds": metaNumber, "required": metaNumber,
	"requests_swept": metaNumber, "rollup_window_seconds": metaNumber, "sessions_swept": metaNumber,
	"skipped_locked": metaNumber, "source_votes": metaNumber, "source_votes_needed": metaNumber,
	"stale_after_seconds": metaNumber, "team_policy_rule_count": metaNumber, "threshold": metaNumber,
	"ttl_seconds": metaNumber, "pending_cap": metaNumber, "undeclared_count": metaNumber, "width": metaNumber, "wrap_count": metaNumber,
	"wrap_errors": metaNumber, "wraps_already_closed": metaNumber, "priority": metaNumber,
	"wraps_expired": metaNumber, "wraps_self_healed": metaNumber,

	// bools
	"became_approved": metaBool, "client_secret_set": metaBool,
	"discover_enabled": metaBool, "enabled": metaBool, "has_comment": metaBool, "has_error": metaBool,
	"has_reason": metaBool, "require_approval": metaBool, "requires_security_approval": metaBool,
	"security_approval_required": metaBool, "security_vote_present": metaBool, "self_heal_failed": metaBool,
	"self_service_bindable": metaBool, "transitioned": metaBool, "all_keys": metaBool, "locked": metaBool,

	// number, bool or token
	"enqueued": metaScalar, "failed": metaScalar, "flipped": metaScalar, "new_value": metaScalar,
	"old_value": metaScalar, "succeeded": metaScalar,
	"added": metaNameListOrScalar, "deleted": metaNameListOrScalar, "revoked": metaNameListOrScalar,

	// times
	"at": metaTime, "deadline": metaTime, "expires_at": metaTime, "idle_expires_at": metaTime,
	"locked_until": metaTime, "timeout_at": metaTime,

	// digests and fingerprints (content_hash is the value digest tracked in skills#68)
	"content_hash": metaDigest, "public_key_sha": metaDigest, "sha256": metaDigest,

	// lists
	"deleted_policy_rule_ids": metaIDList,
	"allowed_ops":             metaTokenList, "amr": metaTokenList, "permissions": metaTokenList, "permissions_added": metaTokenList,
	"permissions_removed": metaTokenList,
	"allowed_domains":     metaNameList, "allowed_keys": metaNameList, "capabilities": metaNameList,
	"changed_keys": metaNameList, "configured_map_keys": metaNameList, "groups": metaNameList,
	"key_names": metaNameList, "selector_keys": metaNameList, "scope_keys": metaNameList,

	// nested before/after values, checked against this table
	"new": metaObject, "old": metaObject,

	// free-text errors: never stored
	"error": metaErrorText, "sessions_revoke_err": metaErrorText, "wrap_refresh_errors": metaErrorText,
}

const (
	auditMetaMaxName     = 256
	auditMetaMaxList     = 200
	auditMetaMaxDepth    = 2
	auditMetaErrorMarker = "omitted"
)

var (
	auditMetaIDRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._/@+-]{0,255}$`)
	auditMetaTokenRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._/@+-]{0,127}$`)
	auditMetaTimeRe   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(Z|[+-][0-9]{2}:[0-9]{2})$`)
	auditMetaDigestRe = regexp.MustCompile(`^[A-Za-z0-9+/=_:-]{8,160}$`)
	auditMetaKeyRe    = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	auditMetaEmailRe  = regexp.MustCompile(`^[^\s@]{1,64}@[^\s@]{1,253}$`)
)

// SanitizeAuditMetadata returns the metadata that may be written to the
// audit table for action. It never returns nil and never modifies meta.
func SanitizeAuditMetadata(action string, meta map[string]any) map[string]any {
	out := map[string]any{}
	if len(meta) == 0 {
		return out
	}
	// Normalise to JSON types (string, float64, bool, nil, []any,
	// map[string]any) so the checks see what would be stored.
	raw, err := json.Marshal(meta)
	if err != nil {
		slog.Warn("audit metadata dropped: not JSON", "action", action)
		out["_dropped_keys"] = []string{"*"}
		return out
	}
	var norm map[string]any
	if err := json.Unmarshal(raw, &norm); err != nil {
		slog.Warn("audit metadata dropped: not a JSON object", "action", action)
		out["_dropped_keys"] = []string{"*"}
		return out
	}
	var dropped, rejected []string
	sanitizeAuditMap(action, norm, out, &dropped, &rejected, 0)
	if len(dropped) > 0 {
		out["_dropped_keys"] = dropped
	}
	if len(rejected) > 0 {
		out["_rejected_keys"] = rejected
	}
	return out
}

func sanitizeAuditMap(action string, in, out map[string]any, dropped, rejected *[]string, depth int) {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := in[k]
		kind, known := auditMetaKeys[k]
		if !known {
			*dropped = append(*dropped, auditMetaKeyName(k))
			slog.Warn("audit metadata key dropped", "action", action, "key", auditMetaKeyName(k), "reason", "unknown_key")
			continue
		}
		if kind == metaErrorText {
			if v == nil || v == "" {
				continue
			}
			// The detail goes to the log, scrubbed, never to the
			// append-only audit row.
			switch x := v.(type) {
			case string:
				slog.Warn("audit error detail", "action", action, "key", k, "error", sanitize.LogError(x))
			case []any:
				for _, e := range x {
					if s, ok := e.(string); ok {
						slog.Warn("audit error detail", "action", action, "key", k, "error", sanitize.LogError(s))
					}
				}
			}
			out[k] = auditMetaErrorMarker
			continue
		}
		if kind == metaObject {
			obj, ok := v.(map[string]any)
			if v == nil {
				out[k] = nil
				continue
			}
			if !ok || depth >= auditMetaMaxDepth {
				*rejected = append(*rejected, k)
				slog.Warn("audit metadata key dropped", "action", action, "key", k, "reason", "bad_value")
				continue
			}
			nested := map[string]any{}
			sanitizeAuditMap(action, obj, nested, dropped, rejected, depth+1)
			out[k] = nested
			continue
		}
		if !auditMetaValueOK(kind, v) {
			*rejected = append(*rejected, k)
			slog.Warn("audit metadata key dropped", "action", action, "key", k, "reason", "bad_value")
			continue
		}
		out[k] = v
	}
}

// auditMetaKeyName is how a dropped key is named in the row and the log:
// as itself when it looks like one of ours, otherwise as a placeholder,
// so a key built from data can't carry that data through.
func auditMetaKeyName(k string) string {
	if auditMetaKeyRe.MatchString(k) {
		return k
	}
	return "<invalid_key>"
}

func auditMetaValueOK(kind auditMetaKind, v any) bool {
	if v == nil {
		return true
	}
	switch kind {
	case metaID:
		s, ok := v.(string)
		return ok && (s == "" || auditMetaIDRe.MatchString(s))
	case metaToken:
		s, ok := v.(string)
		return ok && (s == "" || auditMetaTokenRe.MatchString(s))
	case metaName:
		s, ok := v.(string)
		return ok && auditMetaNameOK(s)
	case metaEmail:
		s, ok := v.(string)
		return ok && (s == "" || (auditMetaEmailRe.MatchString(s) && auditMetaNameOK(s)))
	case metaNumber:
		_, ok := v.(float64)
		return ok
	case metaBool:
		_, ok := v.(bool)
		return ok
	case metaScalar:
		switch x := v.(type) {
		case float64, bool:
			return true
		case string:
			return auditMetaTokenRe.MatchString(x)
		}
		return false
	case metaTime:
		s, ok := v.(string)
		return ok && (s == "" || auditMetaTimeRe.MatchString(s))
	case metaDigest:
		s, ok := v.(string)
		return ok && (s == "" || auditMetaDigestRe.MatchString(s))
	case metaNameListOrScalar:
		if _, isList := v.([]any); isList {
			return auditMetaValueOK(metaNameList, v)
		}
		return auditMetaValueOK(metaScalar, v)
	case metaIDList, metaTokenList, metaNameList:
		list, ok := v.([]any)
		if !ok || len(list) > auditMetaMaxList {
			return false
		}
		elem := map[auditMetaKind]auditMetaKind{metaIDList: metaID, metaTokenList: metaToken, metaNameList: metaName}[kind]
		for _, e := range list {
			if e == nil || !auditMetaValueOK(elem, e) {
				return false
			}
		}
		return true
	}
	return false
}

// auditMetaNameOK accepts a bounded, printable, single-line string with
// no credential-shaped substring.
func auditMetaNameOK(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > auditMetaMaxName || !utf8.ValidString(s) {
		return false
	}
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) }) >= 0 {
		return false
	}
	return !sanitize.HasCredential(s)
}
