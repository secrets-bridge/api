package services

import "testing"

// Bind rule 4 is an allowlist: anything not listed stays platform-only.
func TestTeamBindableEnvironment(t *testing.T) {
	for _, tc := range []struct {
		envType, kind string
		want          bool
	}{
		{"dev", "non_prod", true},
		{"staging", "non_prod", true},
		{"uat", "non_prod", true},
		{"prod", "non_prod", false},
		{"other", "non_prod", false},
		{"staging", "prod", false},
		{"dev", "prod", false},
		{"sandbox", "non_prod", false},
		{"", "non_prod", false},
		{"dev", "", false},
	} {
		if got := teamBindableEnvironment(tc.envType, tc.kind); got != tc.want {
			t.Errorf("teamBindableEnvironment(%q, %q) = %v; want %v", tc.envType, tc.kind, got, tc.want)
		}
	}
}
