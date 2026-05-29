// Auth handler — exposes the local-admin login endpoint behind
// /api/v1/auth/login. Stays minimal on purpose: the OIDC swap
// (api#26) replaces it. The shape is what the UI consumes today.

package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/services"
)

// Auth is the HTTP-side wrapper around AuthService.
type Auth struct {
	svc *services.AuthService
}

func NewAuth(svc *services.AuthService) *Auth { return &Auth{svc: svc} }

// LoginBody is the inbound JSON shape. `password` is value-bearing —
// the handler hands it straight to the service which zeroes the slice
// after bcrypt verification.
type LoginBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse is the outbound shape. The UI persists the token in
// memory only (see ui src/auth/AuthContext.tsx); never localStorage.
type LoginResponse struct {
	Token     string       `json:"token"`
	ExpiresAt string       `json:"expires_at"`
	User      LoginRespUser `json:"user"`
}

// LoginRespUser is the value-free projection returned alongside the
// token.
type LoginRespUser struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// Login handles POST /api/v1/auth/login. Public route — no auth
// middleware in front. Generic 401 on every failure shape; the audit
// log carries the specific error kind so triage stays possible
// without disclosing it on the wire.
func (h *Auth) Login(c fiber.Ctx) error {
	var body LoginBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	password := []byte(body.Password)
	body.Password = "" // best-effort drop the original string ref

	result, err := h.svc.Login(c.Context(), body.Email, password)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(LoginResponse{
		Token:     result.Token,
		ExpiresAt: result.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		User: LoginRespUser{
			ID:          result.User.ID.String(),
			Email:       result.User.Email,
			DisplayName: result.User.DisplayName,
		},
	})
}
