package services

import "testing"

// The known answer from the gateway contract (testdata/discovery-kat.json,
// section 2.2): projects given unsorted, discovery on, names mode.
func TestGatewayScopeDigest_KnownAnswer(t *testing.T) {
	const (
		endpoint = "sha256:9508006565bb8a9beb9bb68e3984a5350e7e0320f55945cad5aeddbdd71115ce"
		want     = "sha256:bf4357a6ba9936070285b4ac00d9d32ba1ad29922757fbd7556dc9f08c2784a7"
	)
	if got := GatewayScopeDigest(endpoint, []string{"team-b-apps", "team-a-apps"}, true, "names"); got != want {
		t.Fatalf("scope digest = %s; want %s", got, want)
	}
	for _, other := range []string{
		GatewayScopeDigest(endpoint, []string{"team-a-apps"}, true, "names"),
		GatewayScopeDigest(endpoint, []string{"team-b-apps", "team-a-apps"}, false, "names"),
		GatewayScopeDigest("sha256:"+endpoint[7:70]+"f", []string{"team-b-apps", "team-a-apps"}, true, "names"),
	} {
		if other == want {
			t.Fatal("a different scope input gave the same digest")
		}
	}
}
