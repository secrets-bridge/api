package main

import (
	"net/http"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// api#266, the OIDC callback: an account waiting for approval signs in
// and gets a limited session, but no grants from the IdP's groups. Once
// approved, the same sign-in syncs them, so the check below isn't
// vacuous.
func TestLoginSecurity_PendingAccountGetsNoGroupGrants(t *testing.T) {
	h := newLoginHarness(t, func(c *Config) {
		c.OIDCGroupClaim = "groups"
		c.OIDCGroupMap = map[string]string{"sb-devs": "developer"}
	})
	ctx := h.t.Context()
	user := h.createUser("wes@example.com", "wes-correct-pw", bcrypt.MinCost)
	if _, err := h.pool.Exec(ctx, `UPDATE local_users SET pending_approval = TRUE WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("mark pending: %v", err)
	}
	claims := verifiedClaims("wes-sub", "wes@example.com")
	claims["groups"] = []string{"sb-devs"}
	oidcGrants := func() int {
		return h.count(`SELECT count(*) FROM user_roles WHERE user_id = $1 AND granted_by = 'system:oidc'`, user.ID.String())
	}

	resp := h.oidcLogin("/", claims)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("oidc login while waiting: status %d, want 302", resp.StatusCode)
	}
	session := findCookie(resp, loginTestSessionKey)
	if st, _ := h.me(session, ""); st != http.StatusOK {
		t.Fatalf("/users/me while waiting = %d, want 200", st)
	}
	req, _ := http.NewRequest(http.MethodGet, h.apiURL+"/api/v1/users/me/projects", nil)
	req.AddCookie(session)
	if resp := h.do(req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the waiting account's session reached /users/me/projects (status %d), want 403", resp.StatusCode)
	}
	if n := oidcGrants(); n != 0 {
		t.Fatalf("a waiting account got %d grants from IdP groups, want 0", n)
	}
	if n := h.count(`SELECT count(*) FROM audit_events WHERE action = 'auth.oidc.reconcile_skipped' AND resource = $1`,
		"user:"+user.ID.String()); n != 1 {
		t.Fatalf("auth.oidc.reconcile_skipped events = %d, want 1", n)
	}

	if _, err := h.pool.Exec(ctx, `UPDATE local_users SET pending_approval = FALSE WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if resp := h.oidcLogin("/", claims); resp.StatusCode != http.StatusFound {
		t.Fatalf("oidc login after approval: status %d, want 302", resp.StatusCode)
	}
	if n := oidcGrants(); n != 1 {
		t.Fatalf("grants from IdP groups after approval = %d, want 1", n)
	}
}
