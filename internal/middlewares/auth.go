package middlewares

import (
	"context"
	"errors"
	"net/http"

	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

type UserIDKey string

const (
	UserKey UserIDKey = "user_id"
)

type AuthMiddlewares struct {
	repo *repository.Queries
}

func NewAuthMiddlewares(repo *repository.Queries) *AuthMiddlewares {
	return &AuthMiddlewares{repo: repo}
}

func (m *AuthMiddlewares) AuthMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auser, err := auth.GetActiveSession(c.Request(), m.repo)
			if err != nil {
				if errors.Is(err, http.ErrNoCookie) || errors.Is(err, pgx.ErrNoRows) {
					if c.Request().Header.Get("HX-Request") == "true" {
						c.Response().Header().Set("HX-Redirect", "/auth")
						return c.NoContent(http.StatusUnauthorized)
					}
					return c.Redirect(http.StatusSeeOther, "/auth")
				}
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{
					Error:       helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "session error", Message: err.Error()},
					Box:         enums.Boxes.TOAST_TR,
					Persistance: "5000",
				}, nil)
			}

			log.Debugf("Authenticated user: %s", auser.Username)
			ctx := context.WithValue(c.Request().Context(), UserKey, auser.ID)
			c.SetRequest(c.Request().WithContext(ctx))
			return next(c)
		}
	}
}

func (m *AuthMiddlewares) IsDeveloperRoleMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, err := auth.GetActiveSession(c.Request(), m.repo)
			if err != nil || user == nil {
				return c.Redirect(http.StatusSeeOther, "/")
			}
			if user.Role != "DEVELOPER" {
				return c.Redirect(http.StatusSeeOther, "/")
			}
			return next(c)
		}
	}
}

func (m *AuthMiddlewares) IsAdminRoleMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, err := auth.GetActiveSession(c.Request(), m.repo)
			if err != nil || user == nil {
				return c.Redirect(http.StatusSeeOther, "/")
			}
			if user.Role == enums.Roles.USER.String() {
				return c.Redirect(http.StatusSeeOther, "/")
			}
			return next(c)
		}
	}
}
