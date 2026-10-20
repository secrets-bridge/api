package main

// Parity between the retired control-plane Argo CD poller and the
// Gateway evidence path (secrets-bridge/gateway#13, cutover step 1).
//
// The poller stored, per mapped application, an observed_state snapshot
// with health_status, sync_status, sync_revision and operation_phase
// (worker gitops_poller, read back through GET /requests/:id/gitops).
// These tests show that for a bound target the Gateway path exposes each
// of those facts on the request page, per bound application, under the
// same names, and that every line is labelled operational state rather
// than proof that the secret propagated.

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// pollerFacts are the Argo CD facts the retired poller recorded on a
// request, by the key it stored them under in observed_state.
var pollerFacts = []string{"health_status", "sync_status", "sync_revision", "operation_phase"}

// parityApp is what Argo CD reports for one application in the test.
type parityApp struct {
	outcome string
	facts   map[string]any
}

func TestLive_Observation_ParityWithRetiredPoller(t *testing.T) {
	f := newObsFixture(t)
	// A second application bound to the same secret: the poller kept one
	// row per mapped app, the Gateway path keeps one task per binding.
	f.bind(t, f.gw.GatewayID, f.connID, f.env, f.secret, "orders-api")

	reqID, _ := f.executeOn(t, f.env, f.secret)
	if n := len(f.taskRows(t, reqID)); n != 2 {
		t.Fatalf("tasks = %d; want one per bound application (2)", n)
	}
	f.makeClaimable(t, reqID)

	apps := map[string]parityApp{
		"payments-api": {outcome: "observed", facts: map[string]any{
			"sync_status": "Synced", "health_status": "Healthy", "sync_revision": "4f2a9c1", "operation_phase": "Succeeded",
		}},
		"orders-api": {outcome: "not_observed", facts: map[string]any{
			"sync_status": "OutOfSync", "health_status": "Progressing", "sync_revision": "9b1e07d", "operation_phase": "Running",
		}},
	}
	for range 2 {
		// Each replica holds one task at a time, so a fresh replica per claim.
		replica := uuid.NewString()
		code, task := f.claim(t, replica)
		if code != http.StatusOK {
			t.Fatalf("claim = %d", code)
		}
		app, ok := apps[task.ConnectorRefs[0].TargetID]
		if !ok {
			t.Fatalf("claimed a task for %q, not a bound application", task.ConnectorRefs[0].TargetID)
		}
		res := argoResult(task, f.gw.GatewayID, replica)
		st := stage0(res)
		st["outcome"] = app.outcome
		facts := st["facts"].(map[string]any)
		for k, v := range app.facts {
			facts[k] = v
		}
		if code, body := f.post(t, task.TaskID, res); code != http.StatusOK {
			t.Fatalf("result for %s = %d %s", task.ConnectorRefs[0].TargetID, code, body)
		}
	}

	ev, body := f.requestEvidence(t, reqID)
	if ev.ObservationSource != "gateway" || ev.Label != "observed_operational_state" {
		t.Fatalf("request evidence source %q label %q; want gateway, observed_operational_state: %s",
			ev.ObservationSource, ev.Label, body)
	}
	if len(ev.Tasks) != len(apps) {
		t.Fatalf("request evidence has %d tasks; want %d: %s", len(ev.Tasks), len(apps), body)
	}
	seen := map[string]bool{}
	for _, tk := range ev.Tasks {
		if len(tk.Stages) != 1 {
			t.Fatalf("task %s has %d stage lines; want 1: %s", tk.TaskID, len(tk.Stages), body)
		}
		st := tk.Stages[0]
		app, ok := apps[st.TargetID]
		if !ok || st.Stage != "argocd_context" || st.ConnectorID != "argocd-main" {
			t.Fatalf("stage line %+v is not an argocd_context line for a bound application", st)
		}
		seen[st.TargetID] = true
		for _, k := range pollerFacts {
			if st.Facts[k] != app.facts[k] {
				t.Fatalf("%s: %s = %v; the poller showed %v and the Gateway path must too: %s",
					st.TargetID, k, st.Facts[k], app.facts[k], body)
			}
		}
		if st.Label != "observed_operational_state" || !contains(st.Caveats, "argocd_health_not_proof") {
			t.Fatalf("%s: label %q caveats %v; want operational state with argocd_health_not_proof", st.TargetID, st.Label, st.Caveats)
		}
		if st.ObservedAt.IsZero() || st.GatewayID != f.gw.GatewayID {
			t.Fatalf("%s: observed_at %v gateway %q; want the observation time and the reporting Gateway", st.TargetID, st.ObservedAt, st.GatewayID)
		}
		// Healthy and Synced made the poller call a row applied. Here it
		// is context only, never a verified propagation.
		if tk.Verdict == "verified" {
			t.Fatalf("%s: verdict verified from Argo CD facts alone", st.TargetID)
		}
	}
	for target := range apps {
		if !seen[target] {
			t.Fatalf("no stage line for bound application %s: %s", target, body)
		}
	}
	if ev.Rollup == "verified" {
		t.Fatalf("rollup verified from Argo CD facts alone: %s", body)
	}
}
