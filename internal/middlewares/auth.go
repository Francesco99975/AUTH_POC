package middlewares

import (
	"context"
	"net/http"

	"github.com/Francesco99975/authpoc/internal/auth"
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
			userID, _, authenticated := auth.GetSessionUserID(c.Request())
			if !authenticated {
				return c.Redirect(http.StatusSeeOther, "/auth")
			}

			log.Debugf("Authenticated user: %s", userID)

			ctx := context.WithValue(c.Request().Context(), UserKey, userID)

			c.SetRequest(c.Request().WithContext(ctx))
			return next(c)
		}
	}
}

func IsDeveloperRoleMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			_, role, _ := auth.GetSessionUserID(c.Request())
			if role != "DEVELOPER" {
				return c.Redirect(http.StatusSeeOther, "/")
			}
			return next(c)
		}
	}
}

func IsAdminRoleMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			_, role, _ := auth.GetSessionUserID(c.Request())
			if role != "ADMIN" {
				return c.Redirect(http.StatusSeeOther, "/")
			}
			return next(c)
		}
	}
}
