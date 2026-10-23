package services

// Wire form of the Gateway observation contract v1 (api#294):
// the ObservationTask the CP hands out on claim (E4) and the
// EvidenceResult it accepts (E7). The rules mirror
// schemas/evidence-result.schema.json and
// schemas/observation-task.schema.json on gateway main, and the
// Gateway's own internal/contract validators, field for field:
//
//   - every object is closed: an unknown field anywhere is a schema
//     violation, so a value, a hash of a value, a manifest, a URL, a log
//     line or an error message has no field to travel in;
//   - every string is an enum, an id, a timestamp or a tightly patterned
//     Kubernetes or Argo CD identifier;
//   - the conditional rules of the schema (refused results, error
//     stages, observed linkage, the Argo CD variant) are checked too.
//
// Errors name the failing field and rule, never its content.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Contract constants (gateway internal/contract).
const (
	ObservationTaskSchemaVersion   = "gateway.observation-task/v1"
	ObservationResultSchemaVersion = "gateway.evidence-result/v1"
	observationContractVersion     = "1"

	// ObservationResultMaxBytes is the E7 body cap (413 above).
	ObservationResultMaxBytes = 64 << 10

	obsMaxStages         = 32
	obsMaxCaveats        = 20
	obsMaxNonNeg         = 1000000000
	obsMaxClockOffsetMS  = 86400000
	obsMaxTimestampLen   = 40
	obsMaxDNSSubdomain   = 253
	obsMaxGatewayVersion = 64
)

// Observation stages.
const (
	StageESOSync         = "eso_sync"
	StageWorkloadRollout = "workload_rollout"
	StageArgoCDContext   = "argocd_context"
)

// Stage outcomes.
const (
	OutcomeObserved      = "observed"
	OutcomeNotObserved   = "not_observed"
	OutcomeNotApplicable = "not_applicable"
	OutcomeUnverifiable  = "unverifiable"
	OutcomeFailed        = "failed"
	OutcomeError         = "error"
)

// Caveat values the CP itself sets or checks.
const (
	CaveatArgoCDHealthNotProof = "argocd_health_not_proof"
	CaveatClockSkewSuspected   = "clock_skew_suspected"
)

// ErrObservationSchema is a body that breaks the closed v1 schema
// (422 schema_violation).
var ErrObservationSchema = errors.New("services: evidence result schema violation")

func obsViolation(field, rule string) error {
	return fmt.Errorf("%w: %s %s", ErrObservationSchema, field, rule)
}

var (
	obsUUIDRe         = gatewayUUIDRe
	obsLocalIDRe      = gatewayLocalIDRe
	obsDNSSubdomainRe = gatewayDNSSubdomainRe
	obsVersionRe      = gatewayVersionRe
	obsK8sRVRe        = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)
	obsConditionRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
	obsSyncedRVRe     = regexp.MustCompile(`^[0-9A-Za-z-]{1,128}$`)
	obsRevisionRe     = regexp.MustCompile(`^[0-9]{1,12}$`)
	obsSyncRevisionRe = regexp.MustCompile(`^[0-9A-Za-z._+:-]{1,128}$`)
	// obsSecretRefRe is secretRef.name (observation-task schema); the
	// "://" refusal is checked separately (RE2 has no lookahead).
	obsSecretRefRe = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]+$`)
	// obsIdentityDigestRe is resource.identity_digest: "d-" and 26
	// lower-case base32 characters, a one-way digest of the connector id
	// and the object's uid computed inside the customer boundary (ADR
	// 0002 C3). The CP cannot recover the uid from it.
	obsIdentityDigestRe = regexp.MustCompile(`^d-[a-z2-7]{26}$`)
)

var (
	obsAllOutcomes = []string{OutcomeObserved, OutcomeNotObserved, OutcomeNotApplicable, OutcomeUnverifiable, OutcomeFailed, OutcomeError}
	obsAllCaveats  = []string{
		"argocd_health_not_proof", "eso_status_has_no_provider_version", "provider_version_missing",
		"temporal_inference_only", "refresh_before_change", "refresh_time_within_skew", "remote_ref_not_checked",
		"remote_ref_mismatch", "remote_version_pinned_other", "multiple_externalsecrets_for_target",
		"data_from_extract_or_find", "rollout_not_triggered_by_change", "reload_mechanism_unknown",
		"rollout_in_progress", "generation_not_observed", "argocd_operation_unrelated",
		"argocd_app_has_multiple_sources", "clock_skew_suspected", "observed_before_not_before",
		"resource_deleted_during_observation", "refresh_interval_exceeds_deadline", "volume_refresh_not_observable",
		"subpath_mount_not_refreshed", "rollout_paused", "zero_replicas", "replicaset_reused",
	}
	obsAllErrorCodes = []string{
		"connector_unreachable", "connector_timeout", "connector_unauthorized", "connector_forbidden",
		"resource_not_found", "api_version_not_served", "response_too_large", "rate_limited",
		"tls_verification_failed", "internal", "target_identity_changed",
	}
	obsRefusalReasons = []string{
		"unknown_connector", "unbound_target", "stage_not_supported_by_connector", "scope_mismatch",
		"schema_violation", "unsupported_schema_version", "deadline_passed",
	}
	obsConditionStatuses = []string{"True", "False", "Unknown"}
)

type obsStageRules struct {
	api               string
	outcomes          []string
	confidences       []string
	linkages          []string
	kind              string
	connectorKind     string
	apiVersions       []string
	observedNeedsLink bool
	mustCaveat        string
	// digestIdentity: the resource carries identity_digest and never the
	// raw uid. Other stages may not carry identity_digest.
	digestIdentity bool
}

var obsRulesByStage = map[string]obsStageRules{
	StageESOSync: {
		api: "kubernetes", outcomes: obsAllOutcomes, confidences: []string{"high", "medium", "low", "none"},
		linkages: []string{"version_pinned", "time_ordered", "none"}, kind: "ExternalSecret", connectorKind: GatewayKindESO,
		apiVersions: []string{"external-secrets.io/v1", "external-secrets.io/v1beta1"}, observedNeedsLink: true,
	},
	StageWorkloadRollout: {
		api: "kubernetes", outcomes: obsAllOutcomes, confidences: []string{"high", "medium", "low", "none"},
		linkages: []string{"time_ordered", "none"}, kind: "Deployment", connectorKind: GatewayKindRollout,
		apiVersions: []string{"apps/v1"}, observedNeedsLink: true,
	},
	StageArgoCDContext: {
		api: "argocd", outcomes: []string{OutcomeObserved, OutcomeNotObserved, OutcomeUnverifiable, OutcomeError},
		confidences: []string{"low", "none"}, linkages: []string{"none"}, kind: "Application", connectorKind: GatewayKindArgoCD,
		apiVersions: []string{"argoproj.io/v1alpha1"}, mustCaveat: CaveatArgoCDHealthNotProof, digestIdentity: true,
	},
}

// ---- EvidenceResult --------------------------------------------------------

// EvidenceResult is a decoded, validated E7 body.
type EvidenceResult struct {
	SchemaVersion  string           `json:"schema_version"`
	TaskID         string           `json:"task_id"`
	AttemptID      string           `json:"attempt_id"`
	GatewayID      string           `json:"gateway_id"`
	ReplicaID      string           `json:"replica_id"`
	GatewayVersion string           `json:"gateway_version"`
	StartedAt      string           `json:"started_at"`
	FinishedAt     string           `json:"finished_at"`
	AttemptStatus  string           `json:"attempt_status"`
	RefusalReason  string           `json:"refusal_reason,omitempty"`
	Stages         *[]StageEvidence `json:"stages"`
	Clock          *EvidenceClock   `json:"clock"`

	started  time.Time
	finished time.Time
}

// EvidenceClock is the measured offsets, Gateway clock minus peer clock.
type EvidenceClock struct {
	CPOffsetMS        *int64 `json:"cp_offset_ms"`
	APIServerOffsetMS *int64 `json:"apiserver_offset_ms,omitempty"`
}

// StageEvidence is one stage observation of a result. Facts holds the
// raw facts object, decoded per stage by validate.
type StageEvidence struct {
	Stage      string            `json:"stage"`
	Source     *EvidenceSource   `json:"source"`
	ObservedAt string            `json:"observed_at"`
	Resource   *EvidenceResource `json:"resource,omitempty"`
	Outcome    string            `json:"outcome"`
	Confidence string            `json:"confidence"`
	Caveats    *[]string         `json:"caveats"`
	Linkage    string            `json:"linkage"`
	ErrorCode  string            `json:"error_code,omitempty"`
	Facts      json.RawMessage   `json:"facts,omitempty"`

	observedAt time.Time
	argocd     *ArgoCDFacts
	eso        *ESOFacts
	rollout    *RolloutFacts
}

// EvidenceSource names the local connector and target a stage was read
// through.
type EvidenceSource struct {
	ConnectorID string `json:"connector_id"`
	TargetID    string `json:"target_id"`
	API         string `json:"api"`
}

// EvidenceResource is the identity of the object read. Namespace and
// name are the values the Gateway advertised for the target; they are
// for admin display only and are not shown on the request page.
type EvidenceResource struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
	// IdentityDigest is the scoped identity digest an Argo CD stage
	// carries instead of the raw uid.
	IdentityDigest  string `json:"identity_digest,omitempty"`
	ResourceVersion string `json:"resource_version,omitempty"`
	Generation      *int64 `json:"generation,omitempty"`
}

// ArgoCDFacts is copied from Application .status. Context only.
type ArgoCDFacts struct {
	SyncStatus          string `json:"sync_status"`
	HealthStatus        string `json:"health_status"`
	SyncRevision        string `json:"sync_revision,omitempty"`
	OperationPhase      string `json:"operation_phase,omitempty"`
	OperationStartedAt  string `json:"operation_started_at,omitempty"`
	OperationFinishedAt string `json:"operation_finished_at,omitempty"`
	ReconciledAt        string `json:"reconciled_at,omitempty"`
}

// ESOFacts is copied from ExternalSecret .status and .spec.
type ESOFacts struct {
	ReadyStatus               string `json:"ready_status"`
	ReadyReason               string `json:"ready_reason,omitempty"`
	ReadyLastTransitionTime   string `json:"ready_last_transition_time,omitempty"`
	RefreshTime               string `json:"refresh_time,omitempty"`
	SyncedResourceVersion     string `json:"synced_resource_version,omitempty"`
	ObservedGenerationMatches *bool  `json:"observed_generation_matches,omitempty"`
	RefreshIntervalSeconds    *int64 `json:"refresh_interval_seconds,omitempty"`
	RemoteRefMatch            string `json:"remote_ref_match,omitempty"`
	RemoteVersionPin          string `json:"remote_version_pin,omitempty"`
	TargetSecretName          string `json:"target_secret_name,omitempty"`
}

// RolloutFacts is copied from Deployment metadata, spec scalars and
// status, and from owned ReplicaSet metadata.
type RolloutFacts struct {
	Generation                *int64 `json:"generation"`
	ObservedGeneration        *int64 `json:"observed_generation"`
	SpecReplicas              *int64 `json:"spec_replicas"`
	Paused                    *bool  `json:"paused,omitempty"`
	ProgressDeadlineSeconds   *int64 `json:"progress_deadline_seconds,omitempty"`
	Replicas                  *int64 `json:"replicas,omitempty"`
	UpdatedReplicas           *int64 `json:"updated_replicas,omitempty"`
	ReadyReplicas             *int64 `json:"ready_replicas,omitempty"`
	AvailableReplicas         *int64 `json:"available_replicas,omitempty"`
	UnavailableReplicas       *int64 `json:"unavailable_replicas,omitempty"`
	ProgressingStatus         string `json:"progressing_status,omitempty"`
	ProgressingReason         string `json:"progressing_reason,omitempty"`
	AvailableStatus           string `json:"available_status,omitempty"`
	DeploymentRevision        string `json:"deployment_revision,omitempty"`
	NewestReplicaSetCreatedAt string `json:"newest_replicaset_created_at,omitempty"`
	RolloutTrigger            string `json:"rollout_trigger,omitempty"`
	ReloadMechanism           string `json:"reload_mechanism,omitempty"`
	ConsumptionMode           string `json:"consumption_mode,omitempty"`
}

// evidenceIDs is the lenient first read of an E7 body: just the ids, to
// compare with the path before anything else is looked at.
type evidenceIDs struct {
	TaskID    string `json:"task_id"`
	AttemptID string `json:"attempt_id"`
	GatewayID string `json:"gateway_id"`
}

// decodeStrictJSON decodes exactly one JSON value into v with unknown
// fields refused. The decoder error can quote input, so it is replaced.
func decodeStrictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("unknown field, wrong type or malformed JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// requireKeys checks that the object in data has every key in keys, so
// a required field that is absent is told apart from a zero value.
func requireKeys(field string, data []byte, keys ...string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil || m == nil {
		return obsViolation(field, "is not an object")
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return obsViolation(field+"."+k, "is required")
		}
	}
	return nil
}

func obsTime(s string) (time.Time, bool) {
	if s == "" || len(s) > obsMaxTimestampLen {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func optObsTime(s string) bool {
	if s == "" {
		return true
	}
	_, ok := obsTime(s)
	return ok
}

func optEnum(v string, allowed ...string) bool { return v == "" || slices.Contains(allowed, v) }

func nonNeg(p *int64) bool { return p == nil || (*p >= 0 && *p <= obsMaxNonNeg) }

// ---- exact-key pre-pass -------------------------------------------------------

// keySet is the set of keys allowed in one JSON object of the contract,
// with the key sets of the nested objects. encoding/json matches keys
// case-insensitively and keeps the last of duplicate keys, so a
// "closed" struct decode alone would take "Facts" for "facts" or let a
// second "facts" replace the first. checkKeys walks the tokens first and
// refuses both.
type keySet struct {
	// fields maps each allowed key to the key set of its value; a nil
	// value is a scalar or an array of scalars (no object allowed).
	fields map[string]*keySet
	// items is the key set of the objects in an array value.
	items *keySet
	// any allows every key (duplicates are still refused).
	any bool
}

func keys(names ...string) map[string]*keySet {
	m := make(map[string]*keySet, len(names))
	for _, n := range names {
		m[n] = nil
	}
	return m
}

var (
	anyKeys = func() *keySet { k := &keySet{any: true}; k.items = k; return k }()

	evidenceKeySet = func() *keySet {
		facts := keys(
			// argocdFacts
			"sync_status", "health_status", "sync_revision", "operation_phase", "operation_started_at",
			"operation_finished_at", "reconciled_at",
			// esoFacts
			"ready_status", "ready_reason", "ready_last_transition_time", "refresh_time", "synced_resource_version",
			"observed_generation_matches", "refresh_interval_seconds", "remote_ref_match", "remote_version_pin",
			"target_secret_name",
			// rolloutFacts
			"generation", "observed_generation", "spec_replicas", "paused", "progress_deadline_seconds", "replicas",
			"updated_replicas", "ready_replicas", "available_replicas", "unavailable_replicas", "progressing_status",
			"progressing_reason", "available_status", "deployment_revision", "newest_replicaset_created_at",
			"rollout_trigger", "reload_mechanism", "consumption_mode",
		)
		stage := keys("stage", "observed_at", "outcome", "confidence", "caveats", "linkage", "error_code")
		stage["source"] = &keySet{fields: keys("connector_id", "target_id", "api")}
		stage["resource"] = &keySet{fields: keys("api_version", "kind", "namespace", "name", "uid", "identity_digest", "resource_version", "generation")}
		stage["facts"] = &keySet{fields: facts}
		root := keys("schema_version", "task_id", "attempt_id", "gateway_id", "replica_id", "gateway_version",
			"started_at", "finished_at", "attempt_status", "refusal_reason")
		root["stages"] = &keySet{items: &keySet{fields: stage}}
		root["clock"] = &keySet{fields: keys("cp_offset_ms", "apiserver_offset_ms")}
		return &keySet{fields: root}
	}()
)

// errDuplicateKey marks a duplicate-key refusal.
var errDuplicateKey = errors.New("duplicate key")

// checkKeys refuses a body with a duplicate key in any object, or a key
// that is not exactly (case included) one the contract allows there.
// Errors name the rule, never the key or a value.
func checkKeys(data []byte, ks *keySet) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkKeys(dec, ks, "body"); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return obsViolation("body", "has trailing data")
	}
	return nil
}

func walkKeys(dec *json.Decoder, ks *keySet, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return obsViolation(path, "is not valid JSON")
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return obsViolation(path, "is not valid JSON")
			}
			k, _ := kt.(string)
			if seen[k] {
				return fmt.Errorf("%w: %s has a duplicate key: %w", ErrObservationSchema, path, errDuplicateKey)
			}
			seen[k] = true
			var child *keySet
			switch {
			case ks != nil && ks.any:
				child = ks
			case ks == nil || ks.fields == nil:
				return obsViolation(path, "must not be an object")
			default:
				c, known := ks.fields[k]
				if !known {
					return obsViolation(path, "has an unknown field")
				}
				child = c
			}
			if err := walkKeys(dec, child, path+".field"); err != nil {
				return err
			}
		}
	case '[':
		var items *keySet
		if ks != nil {
			items = ks.items
		}
		for dec.More() {
			if err := walkKeys(dec, items, path+"[]"); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return obsViolation(path, "is not valid JSON")
	}
	return nil
}

// DecodeEvidenceResult strictly decodes and validates an E7 body against
// the closed v1 schema. Errors wrap ErrObservationSchema and name a
// field, never a value.
func DecodeEvidenceResult(data []byte) (*EvidenceResult, error) {
	if len(data) > ObservationResultMaxBytes {
		return nil, obsViolation("body", "is over the size limit")
	}
	if err := checkKeys(data, evidenceKeySet); err != nil {
		return nil, err
	}
	if err := requireKeys("result", data, "schema_version", "task_id", "attempt_id", "gateway_id", "replica_id",
		"gateway_version", "started_at", "finished_at", "attempt_status", "stages", "clock"); err != nil {
		return nil, err
	}
	var r EvidenceResult
	if err := decodeStrictJSON(data, &r); err != nil {
		return nil, obsViolation("result", err.Error())
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	// Per-stage required keys (absent versus zero).
	var raw struct {
		Stages []json.RawMessage `json:"stages"`
	}
	_ = json.Unmarshal(data, &raw)
	for i, st := range raw.Stages {
		if err := requireKeys(fmt.Sprintf("stages[%d]", i), st, "stage", "source", "observed_at", "outcome",
			"confidence", "caveats", "linkage"); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

func (r *EvidenceResult) validate() error {
	var ok bool
	switch {
	case r.SchemaVersion != ObservationResultSchemaVersion:
		return obsViolation("schema_version", "is not "+ObservationResultSchemaVersion)
	case !obsUUIDRe.MatchString(r.TaskID):
		return obsViolation("task_id", "must be a uuid")
	case !obsUUIDRe.MatchString(r.AttemptID):
		return obsViolation("attempt_id", "must be a uuid")
	case !obsUUIDRe.MatchString(r.GatewayID):
		return obsViolation("gateway_id", "must be a uuid")
	case !obsUUIDRe.MatchString(r.ReplicaID):
		return obsViolation("replica_id", "must be a uuid")
	case len(r.GatewayVersion) > obsMaxGatewayVersion || !obsVersionRe.MatchString(r.GatewayVersion):
		return obsViolation("gateway_version", "does not match the version pattern")
	}
	if r.started, ok = obsTime(r.StartedAt); !ok {
		return obsViolation("started_at", "must be a timestamp")
	}
	if r.finished, ok = obsTime(r.FinishedAt); !ok {
		return obsViolation("finished_at", "must be a timestamp")
	}
	switch {
	case r.Stages == nil:
		return obsViolation("stages", "is required")
	case len(*r.Stages) > obsMaxStages:
		return obsViolation("stages", "has too many entries")
	case r.Clock == nil || r.Clock.CPOffsetMS == nil:
		return obsViolation("clock.cp_offset_ms", "is required")
	case *r.Clock.CPOffsetMS < -obsMaxClockOffsetMS || *r.Clock.CPOffsetMS > obsMaxClockOffsetMS:
		return obsViolation("clock.cp_offset_ms", "is out of range")
	case r.Clock.APIServerOffsetMS != nil &&
		(*r.Clock.APIServerOffsetMS < -obsMaxClockOffsetMS || *r.Clock.APIServerOffsetMS > obsMaxClockOffsetMS):
		return obsViolation("clock.apiserver_offset_ms", "is out of range")
	}
	switch r.AttemptStatus {
	case "refused":
		if !slices.Contains(obsRefusalReasons, r.RefusalReason) {
			return obsViolation("refusal_reason", "is required and must be a v1 reason when refused")
		}
		if len(*r.Stages) != 0 {
			return obsViolation("stages", "must be empty when refused")
		}
		return nil
	case "completed", "partial":
		if r.RefusalReason != "" {
			return obsViolation("refusal_reason", "is only allowed when refused")
		}
		if len(*r.Stages) == 0 {
			return obsViolation("stages", "must not be empty unless refused")
		}
	default:
		return obsViolation("attempt_status", "is not a v1 status")
	}
	seen := map[string]bool{}
	for i := range *r.Stages {
		s := &(*r.Stages)[i]
		if err := s.validate(); err != nil {
			return fmt.Errorf("stages[%d]: %w", i, err)
		}
		if seen[s.Stage] {
			return obsViolation("stages", "has more than one entry for a stage")
		}
		seen[s.Stage] = true
	}
	return nil
}

func (s *StageEvidence) validate() error {
	rules, ok := obsRulesByStage[s.Stage]
	if !ok {
		return obsViolation("stage", "is not a v1 stage")
	}
	switch {
	case s.Source == nil:
		return obsViolation("source", "is required")
	case !obsLocalIDRe.MatchString(s.Source.ConnectorID):
		return obsViolation("source.connector_id", "must be a local id")
	case !obsLocalIDRe.MatchString(s.Source.TargetID):
		return obsViolation("source.target_id", "must be a local id")
	case s.Source.API != rules.api:
		return obsViolation("source.api", "does not match the stage")
	case !slices.Contains(rules.outcomes, s.Outcome):
		return obsViolation("outcome", "is not allowed for this stage")
	case !slices.Contains(rules.confidences, s.Confidence):
		return obsViolation("confidence", "is not allowed for this stage")
	case !slices.Contains(rules.linkages, s.Linkage):
		return obsViolation("linkage", "is not allowed for this stage")
	case s.Caveats == nil:
		return obsViolation("caveats", "is required")
	case len(*s.Caveats) > obsMaxCaveats:
		return obsViolation("caveats", "has too many entries")
	case rules.observedNeedsLink && s.Outcome == OutcomeObserved && s.Linkage == "none":
		return obsViolation("linkage", "must not be none when observed")
	}
	at, ok := obsTime(s.ObservedAt)
	if !ok {
		return obsViolation("observed_at", "must be a timestamp")
	}
	s.observedAt = at
	hasMust := rules.mustCaveat == ""
	seen := map[string]bool{}
	for _, c := range *s.Caveats {
		if !slices.Contains(obsAllCaveats, c) {
			return obsViolation("caveats", "has a value outside the v1 enum")
		}
		if seen[c] {
			return obsViolation("caveats", "has duplicates")
		}
		seen[c] = true
		hasMust = hasMust || c == rules.mustCaveat
	}
	if !hasMust {
		return obsViolation("caveats", "must contain "+rules.mustCaveat)
	}
	if s.Resource != nil {
		if err := s.Resource.validate(rules); err != nil {
			return err
		}
	}
	hasFacts := len(s.Facts) > 0 && !bytes.Equal(bytes.TrimSpace(s.Facts), []byte("null"))
	if s.Outcome == OutcomeError {
		switch {
		case !slices.Contains(obsAllErrorCodes, s.ErrorCode):
			return obsViolation("error_code", "is required and must be a v1 code when outcome is error")
		case s.Confidence != "none":
			return obsViolation("confidence", "must be none when outcome is error")
		case hasFacts:
			return obsViolation("facts", "must be absent when outcome is error")
		}
		return nil
	}
	switch {
	case s.ErrorCode != "":
		return obsViolation("error_code", "is only allowed when outcome is error")
	case s.Resource == nil:
		return obsViolation("resource", "is required unless outcome is error")
	case !hasFacts:
		return obsViolation("facts", "is required unless outcome is error")
	}
	return s.decodeFacts()
}

func (r *EvidenceResource) validate(rules obsStageRules) error {
	switch {
	case !slices.Contains(rules.apiVersions, r.APIVersion):
		return obsViolation("resource.api_version", "is not allowed for this stage")
	case r.Kind != rules.kind:
		return obsViolation("resource.kind", "is not allowed for this stage")
	case !obsLocalIDRe.MatchString(r.Namespace):
		return obsViolation("resource.namespace", "must be a namespace name")
	case len(r.Name) > obsMaxDNSSubdomain || !obsDNSSubdomainRe.MatchString(r.Name):
		return obsViolation("resource.name", "must be an object name")
	case r.UID != "" && !obsUUIDRe.MatchString(r.UID):
		return obsViolation("resource.uid", "must be a uuid")
	case rules.digestIdentity && r.UID != "":
		return obsViolation("resource.uid", "is not allowed for this stage; send identity_digest")
	case !rules.digestIdentity && r.IdentityDigest != "":
		return obsViolation("resource.identity_digest", "is not allowed for this stage")
	case r.IdentityDigest != "" && !obsIdentityDigestRe.MatchString(r.IdentityDigest):
		return obsViolation("resource.identity_digest", "does not match the pattern")
	case r.ResourceVersion != "" && !obsK8sRVRe.MatchString(r.ResourceVersion):
		return obsViolation("resource.resource_version", "does not match the pattern")
	case !nonNeg(r.Generation):
		return obsViolation("resource.generation", "is out of range")
	}
	return nil
}

func (s *StageEvidence) decodeFacts() error {
	switch s.Stage {
	case StageArgoCDContext:
		if err := requireKeys("facts", s.Facts, "sync_status", "health_status"); err != nil {
			return err
		}
		var f ArgoCDFacts
		if err := decodeStrictJSON(s.Facts, &f); err != nil {
			return obsViolation("facts", err.Error())
		}
		switch {
		case !slices.Contains([]string{"Synced", "OutOfSync", "Unknown"}, f.SyncStatus):
			return obsViolation("facts.sync_status", "is not a v1 value")
		case !slices.Contains([]string{"Healthy", "Progressing", "Degraded", "Suspended", "Missing", "Unknown"}, f.HealthStatus):
			return obsViolation("facts.health_status", "is not a v1 value")
		case f.SyncRevision != "" && !obsSyncRevisionRe.MatchString(f.SyncRevision):
			return obsViolation("facts.sync_revision", "does not match the pattern")
		case !optEnum(f.OperationPhase, "Running", "Succeeded", "Failed", "Error", "Terminating"):
			return obsViolation("facts.operation_phase", "is not a v1 value")
		case !optObsTime(f.OperationStartedAt), !optObsTime(f.OperationFinishedAt), !optObsTime(f.ReconciledAt):
			return obsViolation("facts", "has an invalid timestamp")
		}
		s.argocd = &f
	case StageESOSync:
		if err := requireKeys("facts", s.Facts, "ready_status"); err != nil {
			return err
		}
		var f ESOFacts
		if err := decodeStrictJSON(s.Facts, &f); err != nil {
			return obsViolation("facts", err.Error())
		}
		switch {
		case !slices.Contains(obsConditionStatuses, f.ReadyStatus):
			return obsViolation("facts.ready_status", "must be a condition status")
		case f.ReadyReason != "" && !obsConditionRe.MatchString(f.ReadyReason):
			return obsViolation("facts.ready_reason", "must be a condition reason")
		case !optObsTime(f.ReadyLastTransitionTime), !optObsTime(f.RefreshTime):
			return obsViolation("facts", "has an invalid timestamp")
		case f.SyncedResourceVersion != "" && !obsSyncedRVRe.MatchString(f.SyncedResourceVersion):
			return obsViolation("facts.synced_resource_version", "does not match the pattern")
		case !nonNeg(f.RefreshIntervalSeconds):
			return obsViolation("facts.refresh_interval_seconds", "is out of range")
		case !optEnum(f.RemoteRefMatch, "match", "mismatch", "not_checked", "extract_or_find"):
			return obsViolation("facts.remote_ref_match", "is not a v1 value")
		case !optEnum(f.RemoteVersionPin, "none", "matches_expected", "other_version"):
			return obsViolation("facts.remote_version_pin", "is not a v1 value")
		case f.TargetSecretName != "" && (len(f.TargetSecretName) > obsMaxDNSSubdomain || !obsDNSSubdomainRe.MatchString(f.TargetSecretName)):
			return obsViolation("facts.target_secret_name", "must be an object name")
		}
		s.eso = &f
	case StageWorkloadRollout:
		if err := requireKeys("facts", s.Facts, "generation", "observed_generation", "spec_replicas"); err != nil {
			return err
		}
		var f RolloutFacts
		if err := decodeStrictJSON(s.Facts, &f); err != nil {
			return obsViolation("facts", err.Error())
		}
		switch {
		case f.Generation == nil || f.ObservedGeneration == nil || f.SpecReplicas == nil:
			return obsViolation("facts", "is missing a required count")
		case !nonNeg(f.Generation), !nonNeg(f.ObservedGeneration), !nonNeg(f.SpecReplicas),
			!nonNeg(f.ProgressDeadlineSeconds), !nonNeg(f.Replicas), !nonNeg(f.UpdatedReplicas),
			!nonNeg(f.ReadyReplicas), !nonNeg(f.AvailableReplicas), !nonNeg(f.UnavailableReplicas):
			return obsViolation("facts", "has a count out of range")
		case !optEnum(f.ProgressingStatus, obsConditionStatuses...), !optEnum(f.AvailableStatus, obsConditionStatuses...):
			return obsViolation("facts", "has an invalid condition status")
		case f.ProgressingReason != "" && !obsConditionRe.MatchString(f.ProgressingReason):
			return obsViolation("facts.progressing_reason", "must be a condition reason")
		case f.DeploymentRevision != "" && !obsRevisionRe.MatchString(f.DeploymentRevision):
			return obsViolation("facts.deployment_revision", "must be a revision number")
		case !optObsTime(f.NewestReplicaSetCreatedAt):
			return obsViolation("facts.newest_replicaset_created_at", "must be a timestamp")
		case !optEnum(f.RolloutTrigger, "pod_template_annotation_after_change", "pod_template_annotation_before_change",
			"replicaset_created_after_change", "replicaset_revision_bumped_after_change", "no_rollout_since_change", "not_checked"):
			return obsViolation("facts.rollout_trigger", "is not a v1 value")
		case !optEnum(f.ReloadMechanism, "reloader_annotation", "checksum_annotation", "none_detected", "not_checked"):
			return obsViolation("facts.reload_mechanism", "is not a v1 value")
		case !optEnum(f.ConsumptionMode, "env", "volume", "subpath_volume", "mixed", "not_referenced", "unknown"):
			return obsViolation("facts.consumption_mode", "is not a v1 value")
		}
		s.rollout = &f
	}
	return nil
}

// stageBody is the validated stage object as stored in
// observation_evidence.body: re-encoded from the typed structs, so only
// schema fields reach the database.
func (s *StageEvidence) stageBody() (json.RawMessage, error) {
	type body struct {
		Stage      string            `json:"stage"`
		Source     *EvidenceSource   `json:"source"`
		ObservedAt string            `json:"observed_at"`
		Resource   *EvidenceResource `json:"resource,omitempty"`
		Outcome    string            `json:"outcome"`
		Confidence string            `json:"confidence"`
		Caveats    []string          `json:"caveats"`
		Linkage    string            `json:"linkage"`
		ErrorCode  string            `json:"error_code,omitempty"`
		Facts      any               `json:"facts,omitempty"`
	}
	b := body{
		Stage: s.Stage, Source: s.Source, ObservedAt: s.ObservedAt, Resource: s.Resource, Outcome: s.Outcome,
		Confidence: s.Confidence, Caveats: *s.Caveats, Linkage: s.Linkage, ErrorCode: s.ErrorCode,
	}
	switch {
	case s.argocd != nil:
		b.Facts = s.argocd
	case s.eso != nil:
		b.Facts = s.eso
	case s.rollout != nil:
		b.Facts = s.rollout
	}
	raw, err := json.Marshal(b)
	return json.RawMessage(raw), err
}

// ---- RFC 8785 canonical JSON and digest -------------------------------------

// ResultDigest is SHA-256 over the RFC 8785 (JCS) canonical JSON of an
// E7 body: object keys sorted by UTF-16 code units, no insignificant
// whitespace, numbers in their shortest round-trip form, strings with
// the minimal escapes. Two bodies that differ only in key order or
// whitespace have the same digest.
func ResultDigest(data []byte) ([]byte, error) {
	c, err := canonicalize(data)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(c))
	return sum[:], nil
}

// canonicalize returns the RFC 8785 form of one JSON value. A duplicate
// key has no canonical form (RFC 8785 section 3.1) and is an
// ErrObservationSchema error.
func canonicalize(data []byte) (string, error) {
	if err := checkKeys(data, anyKeys); err != nil {
		if errors.Is(err, errDuplicateKey) {
			return "", err
		}
		return "", errors.New("services: result is not JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", errors.New("services: result is not JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", errors.New("services: result has trailing data")
	}
	var b strings.Builder
	if err := canonicalJSON(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func canonicalJSON(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case json.Number:
		s, err := canonicalNumber(x)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case string:
		canonicalString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonicalJSON(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			canonicalString(b, k)
			b.WriteByte(':')
			if err := canonicalJSON(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return errors.New("services: unexpected JSON value")
	}
	return nil
}

func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// canonicalNumber is the ECMAScript Number serialization RFC 8785 uses:
// integers below 1e21 in plain digits, everything else in the shortest
// round-trip form with an exponent like 1e+21.
func canonicalNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		return "", errors.New("services: number out of range")
	}
	if f == 0 {
		return "0", nil
	}
	abs := f
	if abs < 0 {
		abs = -abs
	}
	if abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(s, "e")
	sign := exp[0]
	exp = strings.TrimLeft(exp[1:], "0")
	if sign == '+' {
		return mant + "e+" + exp, nil
	}
	return mant + "e-" + exp, nil
}

func canonicalString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// validTaskSecretRef reports whether a provider secret reference can be
// put in an ObservationTask (secretRef.name in the task schema).
func validTaskSecretRef(s string) bool {
	return len(s) >= 1 && len(s) <= 512 && !strings.Contains(s, "://") && obsSecretRefRe.MatchString(s)
}
