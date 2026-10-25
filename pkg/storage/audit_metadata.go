package storage

import (
	"encoding/json"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
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
// the credential patterns are a second check on every string value
// (names, ids, tokens, digests and scalar strings alike), and URLs lose
// their user info, query and fragment.
//
// What is dropped is named (never shown) in `_dropped_keys` (unknown
// key) and `_rejected_keys` (known key, value of the wrong shape or
// credential-shaped), by its path for a nested key ("new.display_name"),
// logged with the action and key name, and counted (AuditMetadataDrops),
// so a missing entry shows up in tests and logs instead of silently
// losing metadata.

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
	metaURL                                   // absolute URL: user info, query and fragment are stripped
	metaErrorText                             // free-text error: never stored, logged sanitized instead
)

// auditMetaKeys is the allowlist: every key an audit event may carry,
// and the shape of its value. A new key goes here in the same change
// that starts writing it.
var auditMetaKeys = map[string]auditMetaKind{
	// ids
	"aaguid": metaID, "agent_id": metaID, "attempted_environment_id": metaID, "attempted_project_id": metaID,
	"attempted_team_id": metaID, "attempted_workflow_id": metaID, "binding_id": metaID, "connection_id": metaID,
	"default_role_id": metaID, "enrollment_token_id": metaID, "environment_id": metaID,
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
	"request_type": metaToken, "scope": metaToken,
	"severity": metaToken, "state": metaToken, "status": metaToken, "sweeper": metaToken, "target": metaToken,
	"target_provider_type": metaToken, "triggered_by": metaToken, "type": metaToken, "voted_as": metaToken,

	// names
	"acr": metaName, "agent_version": metaName, "application_name": metaName, "base_url": metaURL,
	"client_id": metaName, "cluster_name": metaName, "destination_secret_ref": metaName,
	"display_name": metaName, "email": metaEmail, "environment": metaName, "role": metaName, "email_at_link": metaEmail, "environment_name": metaName,
	"expected_cluster_name": metaName, "ip": metaName, "iss": metaName, "key": metaName, "label": metaName,
	"name": metaName, "project_filter": metaName, "public_url": metaURL, "reason": metaName, "sub": metaName, "target_secret_ref": metaName,
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
	"ttl_seconds": metaNumber, "pending_cap": metaNumber, "risk_level": metaNumber, "risk_level_before": metaNumber, "window_minutes": metaNumber, "undeclared_count": metaNumber, "width": metaNumber, "wrap_count": metaNumber,
	"wrap_errors": metaNumber, "wraps_already_closed": metaNumber, "priority": metaNumber,
	"wraps_expired": metaNumber, "wraps_self_healed": metaNumber,

	// bools
	"became_approved": metaBool, "first_in_window": metaBool, "client_secret_set": metaBool,
	"discover_enabled": metaBool, "enabled": metaBool, "has_comment": metaBool, "has_error": metaBool,
	"has_reason": metaBool, "require_approval": metaBool, "requires_security_approval": metaBool,
	"security_approval_required": metaBool, "security_vote_present": metaBool, "self_heal_failed": metaBool,
	"self_service_bindable": metaBool, "transitioned": metaBool, "all_keys": metaBool, "locked": metaBool,

	// number, bool or token
	"enqueued": metaScalar, "failed": metaScalar, "flipped": metaScalar, "succeeded": metaScalar,
	// platform settings: the only setting (platform_reserved_priority)
	// is an integer, so a string here is never a legitimate value.
	"new_value": metaNumber, "old_value": metaNumber,
	"added": metaNameListOrScalar, "deleted": metaNameListOrScalar, "revoked": metaNameListOrScalar,

	// times
	"at": metaTime, "deadline": metaTime, "first": metaTime, "last": metaTime, "window_start": metaTime, "expires_at": metaTime, "idle_expires_at": metaTime,
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

	// gateway registry (api#293): ids, enums, digests and counts only
	"gateway_id": metaID, "replica_id": metaID, "connector_id": metaID, "argocd_connector_id": metaID,
	"argocd_target_id": metaToken, "expected_stages": metaTokenList, "catalog_version": metaDigest,
	"connector_count": metaNumber, "target_count": metaNumber, "targets_stale": metaNumber,
	"connectors_missing": metaNumber, "max_replicas": metaNumber, "max_inflight_tasks": metaNumber,
	"enrollment_tokens_revoked": metaNumber, "observation_timeout_seconds": metaNumber,
	// target identity pin (api#312): scoped one-way digests, never a uid
	"identity_digest_before": metaDigest, "identity_digest_after": metaDigest,
	"bindings_suspended": metaNumber, "bindings_resumed": metaNumber,
	// what marked the target identity_changed (api#314): catalog or gateway_reported
	"trigger": metaToken,
	// Argo CD discovery (api#308): one-way scope digests, ids and counts
	// only, never an AppProject, namespace or Application name
	"scope_digest": metaDigest, "scope_digest_before": metaDigest, "scope_digest_after": metaDigest,
	"adopted": metaBool, "app_project_count_before": metaNumber,

	// gateway observation queue (api#294): ids, enums, digests and counts only
	"task_id": metaID, "attempt_id": metaID, "previous_attempt_id": metaID, "superseding_task_id": metaID,
	"attempt_count": metaNumber, "failure_count": metaNumber, "tasks_cancelled": metaNumber, "tasks_requeued": metaNumber,
	"version_source": metaToken, "release_reason": metaToken, "attempt_status": metaToken, "task_state": metaToken,
	"verdict": metaToken, "verdict_reason": metaToken, "stage": metaToken, "reported_outcome": metaToken,
	"cp_outcome": metaToken, "next": metaToken, "observation_source": metaToken,
	"observation_source_before": metaToken, "observation_source_after": metaToken,
	"stages": metaTokenList, "outcomes": metaTokenList, "linkages": metaTokenList,

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

// Reasons a key is dropped or rejected, as logged and counted.
const (
	AuditDropUnknownKey = "unknown_key" // not on the allowlist
	AuditDropBadValue   = "bad_value"   // on the list, value of the wrong shape
	AuditDropCredential = "credential"  // on the list, value carries a credential shape
	AuditDropNotJSON    = "not_json"    // the whole map could not be encoded
)

// AuditMetadataDrop is one (action, key, reason) that SanitizeAuditMetadata
// dropped or rejected. Key is the path of the key ("new.display_name").
type AuditMetadataDrop struct {
	Action string
	Key    string
	Reason string
}

// auditDropMaxEntries bounds the counter map: an unknown key name can
// come from data, so past this many distinct entries the rest are
// counted under one overflow entry.
const auditDropMaxEntries = 1024

var auditDrops = struct {
	sync.Mutex
	n map[AuditMetadataDrop]int
}{n: map[AuditMetadataDrop]int{}}

func countAuditDrop(action, key, reason string) {
	d := AuditMetadataDrop{Action: action, Key: key, Reason: reason}
	auditDrops.Lock()
	defer auditDrops.Unlock()
	if _, seen := auditDrops.n[d]; !seen && len(auditDrops.n) >= auditDropMaxEntries {
		d = AuditMetadataDrop{Action: "<overflow>", Key: "<overflow>", Reason: reason}
	}
	auditDrops.n[d]++
}

// AuditMetadataDrops returns how many times each (action, key, reason)
// was dropped or rejected since the process started or the last
// ResetAuditMetadataDrops. Tests use it to assert that real writers
// lose nothing, without reading the log.
func AuditMetadataDrops() map[AuditMetadataDrop]int {
	auditDrops.Lock()
	defer auditDrops.Unlock()
	out := make(map[AuditMetadataDrop]int, len(auditDrops.n))
	for k, v := range auditDrops.n {
		out[k] = v
	}
	return out
}

// ResetAuditMetadataDrops clears the counts.
func ResetAuditMetadataDrops() {
	auditDrops.Lock()
	defer auditDrops.Unlock()
	auditDrops.n = map[AuditMetadataDrop]int{}
}

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
		countAuditDrop(action, "*", AuditDropNotJSON)
		out["_dropped_keys"] = []string{"*"}
		return out
	}
	var norm map[string]any
	if err := json.Unmarshal(raw, &norm); err != nil {
		slog.Warn("audit metadata dropped: not a JSON object", "action", action)
		countAuditDrop(action, "*", AuditDropNotJSON)
		out["_dropped_keys"] = []string{"*"}
		return out
	}
	s := auditSanitizer{action: action}
	s.sanitizeMap(norm, out, "", 0)
	if len(s.dropped) > 0 {
		out["_dropped_keys"] = s.dropped
	}
	if len(s.rejected) > 0 {
		out["_rejected_keys"] = s.rejected
	}
	return out
}

type auditSanitizer struct {
	action            string
	dropped, rejected []string
}

func (s *auditSanitizer) drop(path string) {
	s.dropped = append(s.dropped, path)
	slog.Warn("audit metadata key dropped", "action", s.action, "key", path, "reason", AuditDropUnknownKey)
	countAuditDrop(s.action, path, AuditDropUnknownKey)
}

func (s *auditSanitizer) reject(path, reason string) {
	s.rejected = append(s.rejected, path)
	slog.Warn("audit metadata key dropped", "action", s.action, "key", path, "reason", reason)
	countAuditDrop(s.action, path, reason)
}

func (s *auditSanitizer) sanitizeMap(in, out map[string]any, prefix string, depth int) {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := in[k]
		path := prefix + auditMetaKeyName(k)
		kind, known := auditMetaKeys[k]
		if !known {
			s.drop(path)
			continue
		}
		switch kind {
		case metaErrorText:
			if v == nil || v == "" {
				continue
			}
			// The detail goes to the log, scrubbed, never to the
			// append-only audit row.
			switch x := v.(type) {
			case string:
				slog.Warn("audit error detail", "action", s.action, "key", path, "error", sanitize.LogError(x))
			case []any:
				for _, e := range x {
					if str, ok := e.(string); ok {
						slog.Warn("audit error detail", "action", s.action, "key", path, "error", sanitize.LogError(str))
					}
				}
			}
			out[k] = auditMetaErrorMarker
		case metaObject:
			if v == nil {
				out[k] = nil
				continue
			}
			obj, ok := v.(map[string]any)
			if !ok || depth >= auditMetaMaxDepth {
				s.reject(path, AuditDropBadValue)
				continue
			}
			nested := map[string]any{}
			s.sanitizeMap(obj, nested, path+".", depth+1)
			out[k] = nested
		case metaURL:
			clean, reason := auditMetaURL(v)
			if reason != "" {
				s.reject(path, reason)
				continue
			}
			out[k] = clean
		default:
			if auditMetaHasCredential(v) {
				s.reject(path, AuditDropCredential)
				continue
			}
			if !auditMetaValueOK(kind, v) {
				s.reject(path, AuditDropBadValue)
				continue
			}
			out[k] = v
		}
	}
}

// auditMetaHasCredential runs the credential patterns over every string
// in a value, whatever its kind: an id, token, digest or scalar string
// can carry a token just as well as a name can.
func auditMetaHasCredential(v any) bool {
	switch x := v.(type) {
	case string:
		return sanitize.HasCredential(x)
	case []any:
		for _, e := range x {
			if auditMetaHasCredential(e) {
				return true
			}
		}
	}
	return false
}

// auditMetaURL keeps an absolute URL as scheme://host/path: user info,
// a query and a fragment can carry a password or a token, so they are
// stripped. A value that is not an absolute URL is rejected.
func auditMetaURL(v any) (any, string) {
	if v == nil {
		return nil, ""
	}
	raw, ok := v.(string)
	if !ok {
		return nil, AuditDropBadValue
	}
	if raw == "" {
		return "", ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return nil, AuditDropBadValue
	}
	clean := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}).String()
	if !auditMetaNameOK(clean) {
		if sanitize.HasCredential(clean) {
			return nil, AuditDropCredential
		}
		return nil, AuditDropBadValue
	}
	return clean, ""
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
