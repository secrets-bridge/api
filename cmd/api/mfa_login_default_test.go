package main

import (
	"strings"
	"testing"
)

// SB_REQUIRE_MFA_AT_LOGIN is on by default unless SB_ENV=dev
// (skills#105), and an explicit setting wins in both directions.
func TestRequireMFAAtLogin_DefaultPerEnv(t *testing.T) {
	cases := []struct {
		name, env, flag string
		want            bool
	}{
		{"SB_ENV unset (production)", "", "", true},
		{"production", ModeProduction, "", true},
		{"dev", ModeDev, "", false},
		{"production, explicitly off", ModeProduction, "false", false},
		{"dev, explicitly on", ModeDev, "true", true},
		{"production, explicitly on", ModeProduction, "true", true},
		{"production, unparseable value keeps the default", ModeProduction, "maybe", true},
		{"production, 0", ModeProduction, "0", false},
		{"production, no", ModeProduction, "no", false},
		{"dev, explicitly off", ModeDev, "false", false},
		{"dev, unparseable value keeps the default", ModeDev, "on", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// An empty value counts as unset for both settings.
			t.Setenv("SB_ENV", tc.env)
			t.Setenv("SB_REQUIRE_MFA_AT_LOGIN", tc.flag)
			if got := loadConfig().RequireMFAAtLogin; got != tc.want {
				t.Fatalf("RequireMFAAtLogin = %v, want %v", got, tc.want)
			}
		})
	}
}

// The boot warnings name the setting, never its value: one for a value
// that isn't a boolean, one for the gate being off outside dev.
func TestMFAAtLoginWarnings(t *testing.T) {
	cases := []struct {
		name, env, flag string
		want            []string // substrings, one per warning, in order
	}{
		{"production default", ModeProduction, "", nil},
		{"dev default", ModeDev, "", nil},
		{"production, off", ModeProduction, "false", []string{"login-time MFA is OFF"}},
		{"production, not a boolean", ModeProduction, "enabled-please", []string{"not a boolean", "login-time MFA is on"}},
		{"dev, not a boolean", ModeDev, "switched-on", []string{"not a boolean", "login-time MFA is off"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_ENV", tc.env)
			t.Setenv("SB_REQUIRE_MFA_AT_LOGIN", tc.flag)
			got := mfaAtLoginWarnings(loadConfig())
			if tc.want == nil {
				if len(got) != 0 {
					t.Fatalf("warnings = %q, want none", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("warnings = %q, want exactly one", got)
			}
			for _, sub := range tc.want {
				if !strings.Contains(got[0], sub) {
					t.Fatalf("warning %q does not say %q", got[0], sub)
				}
			}
			// The invalid values above are distinctive, so this can't
			// match by accident.
			if strings.Contains(tc.flag, "-") && strings.Contains(got[0], tc.flag) {
				t.Fatalf("warning %q echoes the value", got[0])
			}
		})
	}
}
