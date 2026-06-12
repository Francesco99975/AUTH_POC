package middlewares

import (
	"context"
	"net/http"

	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

type UserIDKey string

const (
	UserKey UserIDKey = "user_id"
)

func AuthMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auser, authenticated := auth.GetSessionUser(c.Request())
			if !authenticated {
				if c.Request().Header.Get("HX-Request") == "true" {
					c.Response().Header().Set("HX-Redirect", "/auth")
					return c.NoContent(http.StatusUnauthorized)
				}
				return c.Redirect(http.StatusSeeOther, "/auth")
			}

			log.Debugf("Authenticated user: %s", auser.Username)

			ctx := context.WithValue(c.Request().Context(), UserKey, auser.ID)

			c.SetRequest(c.Request().WithContext(ctx))
			return next(c)
		}
	}
}

func IsDeveloperRoleMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, _ := auth.GetSessionUser(c.Request())
			if user.Role != "DEVELOPER" {
				return c.Redirect(http.StatusSeeOther, "/")
			}
			return next(c)
		}
	}
}

func IsAdminRoleMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, _ := auth.GetSessionUser(c.Request())
			if user.Role == enums.Roles.USER.String() {
				return c.Redirect(http.StatusSeeOther, "/")
			}
			return next(c)
		}
	}
}
