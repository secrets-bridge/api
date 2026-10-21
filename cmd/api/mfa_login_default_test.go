package main

import "testing"

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
