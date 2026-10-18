package auth_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	. "github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
)

func TestRequireWhen_GuardsOnlyMatchingRequests(t *testing.T) {
	deletesRules := func(c fiber.Ctx) bool { return c.Query("delete_policy_rules") == "true" }
	cases := []struct {
		name   string
		grants []Grant
		path   string
		want   int
	}{
		{"plain delete, no extra permission", nil, "/", 204},
		{"with the option, no policy.edit", nil, "/?delete_policy_rules=true", 403},
		{"with the option, team-scoped policy.edit", []Grant{{Permission: string(PermPolicyEdit), Scope: map[string]string{"team_id": "t1"}}}, "/?delete_policy_rules=true", 403},
		{"with the option, global policy.edit", []Grant{{Permission: string(PermPolicyEdit)}}, "/?delete_policy_rules=true", 204},
		{"option set to something else", nil, "/?delete_policy_rules=1", 204},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			app.Use(func(c fiber.Ctx) error {
				c.SetContext(context.WithValue(c.Context(), middleware.CtxKeyActor, "u1"))
				return c.Next()
			})
			reached := false
			app.Delete("/", RequireWhen(deletesRules, Require(PermPolicyEdit, fixedResolver(tc.grants))), func(c fiber.Ctx) error {
				reached = true
				return c.SendStatus(204)
			})
			resp, err := app.Test(httptest.NewRequest("DELETE", tc.path, nil))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d; want %d", resp.StatusCode, tc.want)
			}
			if reached != (tc.want == 204) {
				t.Fatalf("handler reached = %v with status %d", reached, resp.StatusCode)
			}
		})
	}
}
