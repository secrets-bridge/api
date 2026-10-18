package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// api#240: GET /users resolves user ids to names and emails, and
// searches them, for holders of user_role.edit or team.edit.
func TestLive_UserLookup(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()

	seed := func(email, name string) string {
		t.Helper()
		id := uuid.New()
		if _, err := l.pool.Exec(ctx,
			`INSERT INTO local_users (id, email, password_hash, display_name) VALUES ($1, $2, '\x00', $3)`,
			id, email, name); err != nil {
			t.Fatalf("seed %s: %v", email, err)
		}
		return id.String()
	}
	alice := seed("alice@example.com", "Alice Ng")
	seed("bob@example.com", "Bob Ode")
	underscore := seed("under_score@example.com", "U S")
	seed("underxscore@example.com", "U X")

	teamEditor := l.grantUser(t, []string{"team.edit"}, `{}`)
	grantEditor := l.grantUser(t, []string{"user_role.edit"}, `{}`)
	other := l.grantUser(t, []string{"audit.read"}, `{}`)

	lookup := func(user, query string) (int, []map[string]any, string) {
		t.Helper()
		code, body := l.call(t, http.MethodGet, "/api/v1/users?"+query, user, nil)
		var res struct {
			Users []map[string]any `json:"users"`
		}
		_ = json.Unmarshal(body, &res)
		return code, res.Users, string(body)
	}
	emails := func(users []map[string]any) string {
		var out []string
		for _, u := range users {
			out = append(out, u["email"].(string))
		}
		return strings.Join(out, ",")
	}

	// Gate: authenticated, and one of the two permissions.
	if code, _, body := lookup("", "q=alice"); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d %s; want 401", code, body)
	}
	if code, _, body := lookup(other, "q=alice"); code != http.StatusForbidden {
		t.Errorf("without user_role.edit or team.edit = %d %s; want 403", code, body)
	}
	// A team- or project-scoped grant of either permission must not open
	// the directory: the users aren't tenancy-scoped, so only a global
	// grant counts. The 403 body must carry no user data.
	scopedTeam := l.grantUser(t, []string{"team.edit"}, `{"team_id":"`+uuid.NewString()+`"}`)
	scopedGrant := l.grantUser(t, []string{"user_role.edit"}, `{"project_id":"`+uuid.NewString()+`"}`)
	for name, u := range map[string]string{"scoped team.edit": scopedTeam, "scoped user_role.edit": scopedGrant} {
		for _, q := range []string{"q=alice", "ids=" + alice} {
			code, users, body := lookup(u, q)
			if code != http.StatusForbidden || len(users) != 0 || strings.Contains(body, "@example.com") {
				t.Errorf("%s ?%s = %d %s; want 403 with no user data", name, q[:min(len(q), 8)], code, body)
			}
		}
	}

	// ids: unknown and non-UUID ids are skipped; only four fields.
	ids := url.QueryEscape(alice + "," + uuid.NewString() + ",alice-legacy-id")
	code, users, body := lookup(teamEditor, "ids="+ids)
	if code != http.StatusOK || emails(users) != "alice@example.com" {
		t.Fatalf("ids lookup = %d %s; want alice only", code, body)
	}
	for k := range users[0] {
		if k != "id" && k != "email" && k != "display_name" && k != "disabled" {
			t.Errorf("lookup returns %q; want only id, email, display_name and disabled", k)
		}
	}
	if users[0]["id"] != alice || users[0]["display_name"] != "Alice Ng" {
		t.Errorf("alice = %v", users[0])
	}

	// q: case-insensitive on email and display name; _ matches literally.
	for _, tc := range []struct{ q, want string }{
		{"ALICE", "alice@example.com"},
		{"ode", "bob@example.com"},
		{"r_s", "under_score@example.com"},
	} {
		code, users, body := lookup(grantEditor, "q="+url.QueryEscape(tc.q))
		if code != http.StatusOK || emails(users) != tc.want {
			t.Errorf("q=%s = %d %s; want %s", tc.q, code, body, tc.want)
		}
	}
	if code, users, _ := lookup(grantEditor, "q=r_s"); code == http.StatusOK && len(users) == 1 && users[0]["id"] != underscore {
		t.Errorf("q=r_s matched %v", users[0])
	}

	// Bad parameters.
	many := make([]string, 101)
	for i := range many {
		many[i] = uuid.NewString()
	}
	for _, q := range []string{"", "q=a", "ids=" + alice + "&q=alice", "ids=" + strings.Join(many, ",")} {
		if code, _, body := lookup(teamEditor, q); code != http.StatusBadRequest {
			t.Errorf("?%s = %d %s; want 400", q[:min(len(q), 40)], code, body)
		}
	}
}
