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
