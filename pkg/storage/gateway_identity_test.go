package storage

import (
	"strings"
	"testing"
)

// The target identity pin of mergeTargets (api#312), without a
// database. The live tests in cmd/api drive the same rules through the
// E3 route.

var (
	pinA = "d-" + strings.Repeat("a", 26)
	pinB = "d-" + strings.Repeat("b", 26)
)

func advertise(id string) []GatewayTarget {
	return []GatewayTarget{{TargetID: "payments-api", Name: "payments-api", IdentityAdvertised: id}}
}

func TestMergeTargets_FirstIdentityIsPinned(t *testing.T) {
	got, changes := mergeTargets(advertise(""), advertise(pinA))
	if len(changes) != 0 {
		t.Fatalf("changes = %+v; a first pin is not a change", changes)
	}
	if g := got[0]; g.IdentityDigest != pinA || g.IdentityStatus != GatewayTargetIdentityPinned || g.IdentityAdvertised != pinA {
		t.Fatalf("target = %+v; want pinned to the first identity", g)
	}
}

func TestMergeTargets_SameIdentityIsANoOp(t *testing.T) {
	prev, _ := mergeTargets(nil, advertise(pinA))
	got, changes := mergeTargets(prev, advertise(pinA))
	if len(changes) != 0 || got[0] != prev[0] {
		t.Fatalf("same identity again: target %+v -> %+v, changes %+v; want no change", prev[0], got[0], changes)
	}
}

func TestMergeTargets_AbsentIdentityNeverClearsThePin(t *testing.T) {
	prev, _ := mergeTargets(nil, advertise(pinA))
	got, changes := mergeTargets(prev, advertise(""))
	if len(changes) != 0 || got[0].IdentityDigest != pinA || got[0].IdentityStatus != GatewayTargetIdentityPinned {
		t.Fatalf("absent identity: target %+v, changes %+v; want the pin kept", got[0], changes)
	}
	// Nor does it clear identity_changed.
	changed, _ := mergeTargets(prev, advertise(pinB))
	got, changes = mergeTargets(changed, advertise(""))
	if len(changes) != 0 || !got[0].Suspended() || got[0].IdentityDigest != pinA {
		t.Fatalf("absent identity while changed: target %+v, changes %+v; want still identity_changed", got[0], changes)
	}
	// A target that leaves the catalog (stale) keeps its pin too.
	got, _ = mergeTargets(prev, nil)
	if !got[0].Stale || got[0].IdentityDigest != pinA {
		t.Fatalf("stale target = %+v; want the pin kept", got[0])
	}
}

func TestMergeTargets_DifferentIdentitySuspends(t *testing.T) {
	prev, _ := mergeTargets(nil, advertise(pinA))
	got, changes := mergeTargets(prev, advertise(pinB))
	if len(changes) != 1 || changes[0].Old != pinA || changes[0].New != pinB || changes[0].TargetID != "payments-api" {
		t.Fatalf("changes = %+v; want one change from the pin to the new identity", changes)
	}
	if g := got[0]; !g.Suspended() || g.IdentityDigest != pinA || g.IdentityAdvertised != pinB {
		t.Fatalf("target = %+v; want identity_changed with the old pin kept", g)
	}
	// The same new identity again is not a second change.
	again, changes := mergeTargets(got, advertise(pinB))
	if len(changes) != 0 || !again[0].Suspended() {
		t.Fatalf("same new identity again: changes %+v, target %+v; want no new change, still suspended", changes, again[0])
	}
	// The old pin again does not lift the suspension: only a re-confirm does.
	back, changes := mergeTargets(again, advertise(pinA))
	if len(changes) != 0 || !back[0].Suspended() {
		t.Fatalf("old pin again: changes %+v, target %+v; want still identity_changed", changes, back[0])
	}
}

// The gateway_reported change (api#314).

func TestReportIdentityChanged_MarksAPinnedTargetOnce(t *testing.T) {
	targets, _ := mergeTargets(nil, advertise(pinA))
	ch, ok := reportIdentityChanged(targets, "payments-api")
	if !ok || ch.Old != pinA || ch.New != pinA || ch.TargetID != "payments-api" {
		t.Fatalf("change = %+v %v; want one change from the pin to the pin", ch, ok)
	}
	if g := targets[0]; !g.Suspended() || g.IdentityDigest != pinA || g.IdentityChangeTrigger != GatewayIdentityTriggerReported {
		t.Fatalf("target = %+v; want identity_changed, gateway_reported, pin kept", g)
	}
	if _, ok := reportIdentityChanged(targets, "payments-api"); ok {
		t.Fatal("a second report of the same change was reported again")
	}
}

func TestReportIdentityChanged_NeedsALivePin(t *testing.T) {
	unpinned := advertise("")
	if _, ok := reportIdentityChanged(unpinned, "payments-api"); ok || unpinned[0].IdentityStatus != "" {
		t.Fatalf("unpinned target was marked: %+v", unpinned[0])
	}
	pinned, _ := mergeTargets(nil, advertise(pinA))
	if _, ok := reportIdentityChanged(pinned, "other"); ok {
		t.Fatal("an unknown target was marked")
	}
	stale, _ := mergeTargets(pinned, nil)
	if _, ok := reportIdentityChanged(stale, "payments-api"); ok || stale[0].Suspended() {
		t.Fatalf("stale target was marked: %+v", stale[0])
	}
	changed, _ := mergeTargets(pinned, advertise(pinB))
	if _, ok := reportIdentityChanged(changed, "payments-api"); ok || changed[0].IdentityChangeTrigger != "" {
		t.Fatalf("catalog change was re-reported: %+v", changed[0])
	}
}

func TestMergeTargets_CatalogChangeClearsReportedTrigger(t *testing.T) {
	targets, _ := mergeTargets(nil, advertise(pinA))
	reportIdentityChanged(targets, "payments-api")
	same, changes := mergeTargets(targets, advertise(pinA))
	if len(changes) != 0 || same[0].IdentityChangeTrigger != GatewayIdentityTriggerReported {
		t.Fatalf("pin again: changes %+v target %+v; want no change, trigger kept", changes, same[0])
	}
	got, changes := mergeTargets(same, advertise(pinB))
	if len(changes) != 1 || got[0].IdentityChangeTrigger != "" || got[0].IdentityAdvertised != pinB || !got[0].Suspended() {
		t.Fatalf("new identity: changes %+v target %+v; want a catalog change, no trigger", changes, got[0])
	}
}

func TestConfirmable_PinAgainOnlyForReported(t *testing.T) {
	pinned, _ := mergeTargets(nil, advertise(pinA))
	if err := confirmable(pinned[0]); err != ErrGatewayTargetIdentityNotChanged {
		t.Fatalf("pinned target: %v; want not changed", err)
	}
	reverted, _ := mergeTargets(pinned, advertise(pinB))
	reverted, _ = mergeTargets(reverted, advertise(pinA))
	if err := confirmable(reverted[0]); err != ErrGatewayTargetIdentityNotChanged {
		t.Fatalf("catalog change back to the pin: %v; want not changed", err)
	}
	reported, _ := mergeTargets(nil, advertise(pinA))
	reportIdentityChanged(reported, "payments-api")
	if err := confirmable(reported[0]); err != nil {
		t.Fatalf("gateway_reported change: %v; want confirmable", err)
	}
	changed, _ := mergeTargets(pinned, advertise(pinB))
	if err := confirmable(changed[0]); err != nil {
		t.Fatalf("catalog change: %v; want confirmable", err)
	}
}
