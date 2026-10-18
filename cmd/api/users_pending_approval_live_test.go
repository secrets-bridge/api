package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestLive_PendingApproval drives the real router (api#266). An account
// waiting for approval reads /users/me and signs out, and nothing else.
// Only a global user_role.edit lists, approves or declines waiting
// accounts. Approve validates the scope like POST /user-roles and grants
// the role in the same step; decline only touches waiting accounts.
func TestLive_PendingApproval(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()

	role := uuid.New()
	if _, err := l.pool.Exec(ctx,
		`INSERT INTO roles (id, name, permissions, is_system) VALUES ($1, 'it-requester', '["secret.request"]'::jsonb, false)`,
		role); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	waitingAs := func(email string) (uuid.UUID, map[string]string) {
		t.Helper()
		id := uuid.New()
		cookie := l.sessionFor(t, id, email)
		if _, err := l.pool.Exec(ctx, `UPDATE local_users SET pending_approval = TRUE WHERE id = $1`, id); err != nil {
			t.Fatalf("mark pending: %v", err)
		}
		return id, map[string]string{"Cookie": cookie}
	}
	admin := l.grantUser(t, []string{"user_role.edit"}, `{}`)
	teamScoped := l.grantUser(t, []string{"user_role.edit"}, `{"team_id":"`+uuid.NewString()+`"}`)
	teamEditor := l.grantUser(t, []string{"team.edit"}, `{}`)

	waiting, as := waitingAs("waiting@example.com")

	t.Run("a waiting account reads /users/me and nothing else", func(t *testing.T) {
		code, body := l.callAs(t, http.MethodGet, "/api/v1/users/me", as, nil)
		if code != http.StatusOK || !strings.Contains(string(body), `"pending_approval":true`) {
			t.Fatalf("/users/me = %d %s; want 200 with pending_approval true", code, body)
		}
		for _, path := range []string{"/api/v1/users/me/projects", "/api/v1/policies", "/api/v1/requests"} {
			code, body := l.callAs(t, http.MethodGet, path, as, nil)
			if code != http.StatusForbidden || !strings.Contains(string(body), "account_pending_approval") {
				t.Errorf("GET %s = %d %s; want 403 account_pending_approval", path, code, body)
			}
		}
	})

	t.Run("only a global user_role.edit lists waiting accounts", func(t *testing.T) {
		code, body := l.call(t, http.MethodGet, "/api/v1/users/pending", admin, nil)
		if code != http.StatusOK || !strings.Contains(string(body), waiting.String()) {
			t.Fatalf("pending list as admin = %d %s", code, body)
		}
		for who, user := range map[string]string{"team-scoped user_role.edit": teamScoped, "team.edit": teamEditor} {
			if code, body := l.call(t, http.MethodGet, "/api/v1/users/pending", user, nil); code != http.StatusForbidden {
				t.Errorf("pending list as %s = %d %s; want 403", who, code, body)
			}
		}
	})

	approve := "/api/v1/users/" + waiting.String() + "/approve"
	stillWaiting := func(t *testing.T) {
		t.Helper()
		if code, _ := l.callAs(t, http.MethodGet, "/api/v1/users/me/projects", as, nil); code != http.StatusForbidden {
			t.Fatalf("account no longer waiting (status %d)", code)
		}
	}

	t.Run("a team-scoped user_role.edit can't approve", func(t *testing.T) {
		if code, body := l.call(t, http.MethodPost, approve, teamScoped, map[string]any{"role_id": role}); code != http.StatusForbidden {
			t.Fatalf("approve as team-scoped = %d %s; want 403", code, body)
		}
		stillWaiting(t)
	})

	t.Run("a malformed scope is refused and the account keeps waiting", func(t *testing.T) {
		code, body := l.call(t, http.MethodPost, approve, admin, map[string]any{
			"role_id": role, "scope": map[string]any{"project_id": "not-a-uuid"},
		})
		if code != http.StatusBadRequest {
			t.Fatalf("approve with a bad scope = %d %s; want 400", code, body)
		}
		stillWaiting(t)
	})

	t.Run("approve grants the role and lets the account act", func(t *testing.T) {
		if code, body := l.call(t, http.MethodPost, approve, admin, map[string]any{"role_id": role}); code != http.StatusOK {
			t.Fatalf("approve = %d %s", code, body)
		}
		if code, body := l.callAs(t, http.MethodGet, "/api/v1/users/me/projects", as, nil); code != http.StatusOK {
			t.Fatalf("approved account /users/me/projects = %d %s; want 200", code, body)
		}
		code, body := l.callAs(t, http.MethodGet, "/api/v1/users/me", as, nil)
		if code != http.StatusOK || !strings.Contains(string(body), `"pending_approval":false`) || !strings.Contains(string(body), "secret.request") {
			t.Fatalf("approved /users/me = %d %s; want the role's permission and pending_approval false", code, body)
		}
		ap := l.requireOneAudit(t, "user.approve", admin)
		if ap.Metadata["role_id"] != role.String() || ap.Metadata["user_id"] != waiting.String() {
			t.Errorf("user.approve metadata = %v", ap.Metadata)
		}
	})

	t.Run("decline never touches an active account", func(t *testing.T) {
		code, body := l.call(t, http.MethodPost, "/api/v1/users/"+waiting.String()+"/decline", admin, nil)
		if code != http.StatusConflict {
			t.Fatalf("decline an approved account = %d %s; want 409", code, body)
		}
		if code, _ := l.callAs(t, http.MethodGet, "/api/v1/users/me", as, nil); code != http.StatusOK {
			t.Fatalf("a refused decline still ended the account's session (status %d)", code)
		}
	})

	t.Run("decline disables a waiting account and ends its session", func(t *testing.T) {
		declined, das := waitingAs("declined@example.com")
		if code, body := l.call(t, http.MethodPost, "/api/v1/users/"+declined.String()+"/decline", admin, nil); code != http.StatusNoContent {
			t.Fatalf("decline = %d %s", code, body)
		}
		if code, _ := l.callAs(t, http.MethodGet, "/api/v1/users/me", das, nil); code != http.StatusUnauthorized {
			t.Fatalf("declined account /users/me = %d; want 401", code)
		}
		l.requireOneAudit(t, "user.decline", admin)
	})

	t.Run("a waiting account can sign out", func(t *testing.T) {
		_, oas := waitingAs("leaving@example.com")
		if code, body := l.callAs(t, http.MethodPost, "/api/v1/auth/logout", oas, nil); code == http.StatusForbidden {
			t.Fatalf("sign-out for a waiting account = %d %s", code, body)
		}
	})
}
