package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// TestResultDigest_RFC8785 checks the canonical form the E7 idempotency
// digest is computed over: key order and whitespace do not matter,
// numbers and strings use the RFC 8785 serialization.
func TestResultDigest_RFC8785(t *testing.T) {
	a, err := ResultDigest([]byte(`{"b":[1,{"y":2,"x":"A\n"}],"a":true,"€":null,"c":10.0}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ResultDigest([]byte(" { \"c\" : 1e1, \"€\":null , \"a\":true,\"b\":[ 1 , {\"x\":\"A\\n\",\"y\":2.0}] } "))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("same value, different digest: %x %x", a, b)
	}
	c, _ := ResultDigest([]byte(`{"a":true,"b":[1,{"x":"A\n","y":3}],"c":10,"€":null}`))
	if bytes.Equal(a, c) {
		t.Fatal("different values share a digest")
	}

	cases := map[string]string{
		`{"b":1,"a":2}`:                         `{"a":2,"b":1}`,
		`[1e21,1e-7,0.000001,-0,100,1.5e2]`:     `[1e+21,1e-7,0.000001,0,100,150]`,
		`"é\u001f\"\\\/\t"`:                     `"é\u001f\"\\/\t"`,
		`{"€":1,"😀":2,"z":3}`:                   `{"z":3,"€":1,"😀":2}`,
		`{"a":{"d":[],"c":{}},"A":"x"}`:         `{"A":"x","a":{"c":{},"d":[]}}`,
		`{"𐀀":1,"￿":2}`:                         `{"𐀀":1,"￿":2}`,
		"{\"\uFB33\":1,\"\U00010000\":2}":       "{\"\U00010000\":2,\"\uFB33\":1}",
		`{"x":1.0000000000000002,"y":5e-324}`:   `{"x":1.0000000000000002,"y":5e-324}`,
		`{"x":123456789012345680000}`:           `{"x":123456789012345680000}`,
		`{"x":0.1,"y":-1.25e-10,"z":999999e15}`: `{"x":0.1,"y":-1.25e-10,"z":999999000000000000000}`,
	}
	for in, want := range cases {
		got, err := canonicalize([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Errorf("canonicalize(%s) = %s; want %s", in, got, want)
		}
	}
	if _, err := ResultDigest([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestCanonicalNumber(t *testing.T) {
	for in, want := range map[string]string{
		"1e21": "1e+21", "1e-7": "1e-7", "0.000001": "0.000001", "-0": "0", "150": "150", "1.5": "1.5",
		"123456789012345678901": "123456789012345680000", "5e-324": "5e-324", "-1.25e-10": "-1.25e-10",
	} {
		got, err := canonicalNumber(jsonNumber(in))
		if err != nil || got != want {
			t.Errorf("canonicalNumber(%s) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// TestComputeVerdict_ArgoCDIsContextOnly: Release 1 tasks expect only
// argocd_context. Healthy and Synced observed is never verified; it ends
// unverified with reason context_only. Not final stays pending. No stage
// ever yields a failed verdict.
func TestComputeVerdict_ArgoCDIsContextOnly(t *testing.T) {
	exp := []string{StageArgoCDContext}
	st := func(o string) map[string]storage.ObservationStageState {
		return map[string]storage.ObservationStageState{StageArgoCDContext: {Outcome: o}}
	}
	for _, tc := range []struct {
		outcome, source string
		final           bool
		verdict         storage.ObservationVerdict
		reason          string
	}{
		{OutcomeObserved, "none", true, storage.ObservationVerdictUnverified, storage.ObservationReasonContextOnly},
		{OutcomeObserved, "agent_reported", true, storage.ObservationVerdictUnverified, storage.ObservationReasonContextOnly},
		{OutcomeUnverifiable, "none", true, storage.ObservationVerdictUnverified, storage.ObservationReasonNoStageObserved},
		{OutcomeNotObserved, "none", false, storage.ObservationVerdictPending, ""},
		{OutcomeError, "none", false, storage.ObservationVerdictPending, ""},
		{"", "none", false, storage.ObservationVerdictPending, ""},
	} {
		final, v, r := computeVerdict(exp, st(tc.outcome), tc.source)
		if final != tc.final || v != tc.verdict || r != tc.reason {
			t.Errorf("argocd %q (%s) = %v %s %s; want %v %s %s", tc.outcome, tc.source, final, v, r, tc.final, tc.verdict, tc.reason)
		}
		if v == storage.ObservationVerdictVerified {
			t.Errorf("argocd %q produced verified", tc.outcome)
		}
	}
	// Later releases: eso_sync observed plus a reported version is
	// verified; without the version partially_observed; a failed stage is
	// unverified, failure_observed.
	two := []string{StageESOSync, StageArgoCDContext}
	if _, v, _ := computeVerdict(two, map[string]storage.ObservationStageState{
		StageESOSync: {Outcome: OutcomeObserved}, StageArgoCDContext: {Outcome: OutcomeObserved},
	}, "agent_reported"); v != storage.ObservationVerdictVerified {
		t.Errorf("eso observed with a version = %s; want verified", v)
	}
	if _, v, r := computeVerdict(two, map[string]storage.ObservationStageState{
		StageESOSync: {Outcome: OutcomeObserved}, StageArgoCDContext: {Outcome: OutcomeUnverifiable},
	}, "none"); v != storage.ObservationVerdictPartiallyObserved || r != storage.ObservationReasonNoProviderVersion {
		t.Errorf("eso observed without a version = %s %s", v, r)
	}
	if _, v, r := computeVerdict(two, map[string]storage.ObservationStageState{
		StageESOSync: {Outcome: OutcomeFailed}, StageArgoCDContext: {Outcome: OutcomeObserved},
	}, "agent_reported"); v != storage.ObservationVerdictUnverified || r != storage.ObservationReasonFailureObserved {
		t.Errorf("eso failed = %s %s", v, r)
	}
}

func TestRollupVerdict(t *testing.T) {
	mk := func(vs ...storage.ObservationVerdict) []*storage.ObservationTask {
		out := make([]*storage.ObservationTask, 0, len(vs))
		for _, v := range vs {
			out = append(out, &storage.ObservationTask{Verdict: v})
		}
		return out
	}
	P, V, PO, U, T := storage.ObservationVerdictPending, storage.ObservationVerdictVerified,
		storage.ObservationVerdictPartiallyObserved, storage.ObservationVerdictUnverified, storage.ObservationVerdictTimedOut
	for _, tc := range []struct {
		in   []*storage.ObservationTask
		want string
	}{
		{nil, "none"},
		{mk(P, V), "pending"},
		{mk(V, V), "verified"},
		{mk(V, U), "partially_observed"},
		{mk(PO, T), "partially_observed"},
		{mk(T, T), "timed_out"},
		{mk(T, U), "unverified"},
		{mk(U), "unverified"},
	} {
		if got := RollupVerdict(tc.in); got != tc.want {
			t.Errorf("rollup = %s; want %s", got, tc.want)
		}
	}
}

// TestCPOutcome_ArgoCD: the CP recomputes argocd_context from facts.
// Healthy and Synced reconciled after the write plus skew is observed;
// before it, or Progressing, or an operation Failed, or a suspected
// clock skew, is not_observed. Unverifiable and error stand.
func TestCPOutcome_ArgoCD(t *testing.T) {
	bound := time.Date(2026, 10, 20, 10, 0, 5, 0, time.UTC)
	mk := func(outcome, health, sync, phase, reconciled string) *StageEvidence {
		return &StageEvidence{Stage: StageArgoCDContext, Outcome: outcome, argocd: &ArgoCDFacts{
			HealthStatus: health, SyncStatus: sync, OperationPhase: phase, ReconciledAt: reconciled,
		}}
	}
	after, before := "2026-10-20T10:00:06Z", "2026-10-20T10:00:05Z"
	for _, tc := range []struct {
		st   *StageEvidence
		skew bool
		want string
	}{
		{mk(OutcomeObserved, "Healthy", "Synced", "", after), false, OutcomeObserved},
		{mk(OutcomeNotObserved, "Healthy", "Synced", "Succeeded", after), false, OutcomeObserved},
		{mk(OutcomeObserved, "Healthy", "Synced", "", before), false, OutcomeNotObserved},
		{mk(OutcomeObserved, "Healthy", "Synced", "", ""), false, OutcomeNotObserved},
		{mk(OutcomeObserved, "Progressing", "Synced", "", after), false, OutcomeNotObserved},
		{mk(OutcomeObserved, "Healthy", "OutOfSync", "", after), false, OutcomeNotObserved},
		{mk(OutcomeObserved, "Healthy", "Synced", "Failed", after), false, OutcomeNotObserved},
		{mk(OutcomeObserved, "Healthy", "Synced", "", after), true, OutcomeNotObserved},
		{mk(OutcomeUnverifiable, "Unknown", "Unknown", "", ""), false, OutcomeUnverifiable},
		{&StageEvidence{Stage: StageArgoCDContext, Outcome: OutcomeError}, false, OutcomeError},
	} {
		if got := cpOutcome(tc.st, bound, tc.skew); got != tc.want {
			t.Errorf("%+v skew=%v = %s; want %s", tc.st.argocd, tc.skew, got, tc.want)
		}
	}
}

// TestDecodeEvidenceResult_GatewayShape decodes a body exactly as the
// Gateway's contract package marshals one (field order, omitempty
// fields absent, apiserver offset absent for Argo CD).
func TestDecodeEvidenceResult_GatewayShape(t *testing.T) {
	body := `{"schema_version":"gateway.evidence-result/v1","task_id":"0b6f2a4e-3c1d-4e5f-8a9b-0c1d2e3f4a5b",` +
		`"attempt_id":"c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f","gateway_id":"1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9",` +
		`"replica_id":"7f3c9e2a-1b2c-4d5e-8f90-123456789abc","gateway_version":"0.1.0",` +
		`"started_at":"2026-10-18T10:00:01.123456789Z","finished_at":"2026-10-18T10:00:02Z","attempt_status":"completed",` +
		`"stages":[{"stage":"argocd_context","source":{"connector_id":"argocd-main","target_id":"payments-api","api":"argocd"},` +
		`"observed_at":"2026-10-18T10:00:02Z","resource":{"api_version":"argoproj.io/v1alpha1","kind":"Application","namespace":"argocd","name":"payments-api"},` +
		`"outcome":"observed","confidence":"low","caveats":["argocd_health_not_proof"],"linkage":"none",` +
		`"facts":{"sync_status":"Synced","health_status":"Healthy","sync_revision":"4f2a9c1","reconciled_at":"2026-10-18T10:00:00Z"}}],` +
		`"clock":{"cp_offset_ms":-12}}`
	r, err := DecodeEvidenceResult([]byte(body))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(*r.Stages) != 1 || (*r.Stages)[0].argocd.HealthStatus != "Healthy" {
		t.Fatalf("decoded = %+v", r)
	}
	refused := `{"schema_version":"gateway.evidence-result/v1","task_id":"0b6f2a4e-3c1d-4e5f-8a9b-0c1d2e3f4a5b",` +
		`"attempt_id":"c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f","gateway_id":"1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9",` +
		`"replica_id":"7f3c9e2a-1b2c-4d5e-8f90-123456789abc","gateway_version":"0.1.0",` +
		`"started_at":"2026-10-18T10:00:01Z","finished_at":"2026-10-18T10:00:01Z","attempt_status":"refused",` +
		`"refusal_reason":"unknown_connector","stages":[],"clock":{"cp_offset_ms":0}}`
	if _, err := DecodeEvidenceResult([]byte(refused)); err != nil {
		t.Fatalf("refused result: %v", err)
	}
	// Errors name a field, never the content.
	bad := strings.Replace(body, `"health_status":"Healthy"`, `"health_status":"hunter2"`, 1)
	_, err = DecodeEvidenceResult([]byte(bad))
	if !errors.Is(err, ErrObservationSchema) || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("bad enum = %v", err)
	}
	extra := strings.Replace(body, `"linkage":"none"`, `"linkage":"none","value":"hunter2"`, 1)
	_, err = DecodeEvidenceResult([]byte(extra))
	if !errors.Is(err, ErrObservationSchema) || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("unknown field = %v", err)
	}
}

func TestRescheduleBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{1: 15 * time.Second, 2: 30 * time.Second, 3: 60 * time.Second, 4: 120 * time.Second, 9: 120 * time.Second} {
		if got := rescheduleBackoff(n); got != want {
			t.Errorf("backoff(%d) = %v; want %v", n, got, want)
		}
	}
}

func TestDeadlineFor(t *testing.T) {
	ten := 600
	b := &storage.ObservableBinding{ObservationTimeoutS: 1800, ArgoCDTargetID: "payments-api"}
	if d := deadlineFor(b); d != 30*time.Minute {
		t.Fatalf("default deadline = %v; want 30m", d)
	}
	b.ObservationTimeoutS = 60
	b.ArgoCDTargets = []storage.GatewayTarget{{TargetID: "payments-api", RefreshIntervalSeconds: &ten, ProgressDeadlineSeconds: &ten}}
	if d := deadlineFor(b); d != 25*time.Minute {
		t.Fatalf("interval deadline = %v; want 25m", d)
	}
	big := 100000
	b.ArgoCDTargets[0].RefreshIntervalSeconds = &big
	if d := deadlineFor(b); d != 24*time.Hour {
		t.Fatalf("capped deadline = %v; want 24h", d)
	}
}

func jsonNumber(s string) json.Number { return json.Number(s) }

// TestCanonicalize_RefusesDuplicateKeys: RFC 8785 has no canonical form
// for an object with a duplicate key, at any depth.
func TestCanonicalize_RefusesDuplicateKeys(t *testing.T) {
	for _, in := range []string{`{"a":1,"a":2}`, `{"x":[{"b":1,"b":1}]}`, `{"o":{"k":{},"k":{}}}`} {
		if _, err := canonicalize([]byte(in)); !errors.Is(err, ErrObservationSchema) {
			t.Errorf("canonicalize(%s) = %v; want a schema error", in, err)
		}
	}
	if _, err := canonicalize([]byte(`{"a":1,"A":2}`)); err != nil {
		t.Errorf("keys differing in case are distinct for RFC 8785: %v", err)
	}
}

// TestTimedOutAtRead: an open task at or past its deadline is shown as
// done / timed_out with the reason the sweeper would write, on a copy;
// the input is not changed. Closed or not yet due tasks pass through.
func TestTimedOutAtRead(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	attempt := uuid.New()
	for _, tc := range []struct {
		name        string
		state       storage.ObservationTaskState
		deadline    time.Time
		unavailable bool
		want        bool
		reason      string
	}{
		{"queued overdue, gateway offline", storage.ObservationTaskQueued, now.Add(-time.Second), true, true, storage.ObservationReasonGatewayUnavailable},
		{"leased overdue, gateway seen", storage.ObservationTaskLeased, now.Add(-time.Second), false, true, storage.ObservationReasonDeadlineReached},
		{"deadline exactly now", storage.ObservationTaskQueued, now, false, true, storage.ObservationReasonDeadlineReached},
		{"not yet due", storage.ObservationTaskLeased, now.Add(time.Second), true, false, ""},
		{"already done", storage.ObservationTaskDone, now.Add(-time.Hour), true, false, ""},
		{"dead", storage.ObservationTaskDead, now.Add(-time.Hour), false, false, ""},
		{"cancelled", storage.ObservationTaskCancelled, now.Add(-time.Hour), false, false, ""},
	} {
		in := &storage.ObservationTask{
			State: tc.state, Verdict: storage.ObservationVerdictPending, DeadlineAt: tc.deadline,
			GatewayUnavailable: tc.unavailable, CurrentAttemptID: &attempt,
		}
		got, ok := timedOutAtRead(in, now)
		if ok != tc.want {
			t.Fatalf("%s: ok = %v; want %v", tc.name, ok, tc.want)
		}
		if !ok {
			if got != in {
				t.Fatalf("%s: a task that is not overdue must pass through", tc.name)
			}
			continue
		}
		if got == in || in.State != tc.state || in.Verdict != storage.ObservationVerdictPending || in.CurrentAttemptID == nil {
			t.Fatalf("%s: the input task was changed", tc.name)
		}
		if got.State != storage.ObservationTaskDone || got.Verdict != storage.ObservationVerdictTimedOut ||
			got.VerdictReason != tc.reason || got.TerminalAt == nil || !got.TerminalAt.Equal(tc.deadline) || got.CurrentAttemptID != nil {
			t.Fatalf("%s: view = %s %s %q terminal %v attempt %v", tc.name, got.State, got.Verdict, got.VerdictReason, got.TerminalAt, got.CurrentAttemptID)
		}
	}
}
