package auth_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	. "github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
)

type fixedResolver []Grant

func (f fixedResolver) Resolve(context.Context, string) ([]Grant, error) { return f, nil }

func TestRequireAnyOfGlobal_OnlyGlobalGrantsPass(t *testing.T) {
	cases := []struct {
		name   string
		grants []Grant
		want   int
	}{
		{"global first perm", []Grant{{Permission: string(PermUserRoleEdit)}}, 200},
		{"global second perm", []Grant{{Permission: string(PermTeamEdit)}}, 200},
		{"team-scoped", []Grant{{Permission: string(PermTeamEdit), Scope: map[string]string{"team_id": "t1"}}}, 403},
		{"project-scoped", []Grant{{Permission: string(PermUserRoleEdit), Scope: map[string]string{"project_id": "p1"}}}, 403},
		{"other perm global", []Grant{{Permission: string(PermAuditRead)}}, 403},
		{"no grants", nil, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			app.Use(func(c fiber.Ctx) error {
				c.SetContext(context.WithValue(c.Context(), middleware.CtxKeyActor, "u1"))
				return c.Next()
			})
			app.Get("/", RequireAnyOfGlobal(fixedResolver(tc.grants), PermUserRoleEdit, PermTeamEdit), func(c fiber.Ctx) error {
				return c.SendStatus(200)
			})
			resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d; want %d", resp.StatusCode, tc.want)
			}
		})
	}
}
