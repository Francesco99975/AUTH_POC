package main

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Francesco99975/authpoc/cmd/boot"
	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"

	"github.com/Francesco99975/authpoc/internal/controllers"
	"github.com/Francesco99975/authpoc/internal/middlewares"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/views"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func createRouter(ctx context.Context) *echo.Echo {
	e := echo.New()
	e.Use(middleware.RequestLogger())
	e.Use(middleware.RemoveTrailingSlash())
	e.Use(session.Middleware(auth.SessionStore))
	e.Use(middlewares.RateLimiter())
	// Apply Gzip middleware, but skip it for /metrics
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
		Skipper: func(c echo.Context) bool {
			return c.Path() == "/metrics" // Skip compression for /metrics
		},
	}))
	e.Use(middlewares.MonitoringMiddleware())
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()), middlewares.MetricsAccessMiddleware())
	e.GET("/healthcheck", func(c echo.Context) error {
		time.Sleep(5 * time.Second)
		return c.JSON(http.StatusOK, "OK")
	})
	e.POST("/csp-violation-report", func(c echo.Context) error {
		log.Warnf("CSP Violation Report: %s", c.Request().RequestURI)
		return c.NoContent(http.StatusOK)
	})

	e.GET("/sw.js", func(c echo.Context) error {
		c.Response().Header().Set("Content-Type", "application/javascript")
		c.Response().Header().Set("Cache-Control", "no-cache")
		return c.File("./static/sw.js")
	})

	e.Static("/assets", "./static")
	e.GET("/assets/dist/*", func(c echo.Context) error {
		c.Response().Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return c.File(filepath.Join("./static/dist", c.Param("*")))
	})

	web := e.Group("")

	web.Use(middlewares.SecurityHeaders())

	if boot.Environment.GoEnv == enums.Environments.DEVELOPMENT {
		log.Infof("Running in %s mode", boot.Environment.GoEnv)
		e.Logger.SetLevel(log.DEBUG)
		log.SetLevel(log.DEBUG)

		log.Debugf("Environment variables: %v", boot.Environment)

	}

	if boot.Environment.GoEnv == enums.Environments.PRODUCTION {
		log.Infof("Running in %s mode", boot.Environment.GoEnv)
		e.Logger.SetLevel(log.INFO)
		log.SetLevel(log.INFO)

	}

	web.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup:    "form:_csrf,header:X-CSRF-Token",
		CookieName:     "csrf_token",
		CookiePath:     "/",
		CookieHTTPOnly: true,
		CookieSecure:   boot.Environment.GoEnv == enums.Environments.PRODUCTION,
		CookieSameSite: http.SameSiteLaxMode,
		Skipper: func(c echo.Context) bool {
			// Skip CSRF for the /webhook route
			return c.Path() == "/webhook"

		},
		ErrorHandler: func(err error, c echo.Context) error {
			// Log or customize the 403 response
			log.Errorf("CSRF protection failed: %v", err)
			return c.String(http.StatusForbidden, "CSRF protection failed: "+err.Error())
		},
	}))

	web.GET("/", controllers.Index())
	web.GET("/auth", controllers.Auth())
	web.POST("auth/2fa/check", controllers.SessionLoginTwoFACheck())
	web.GET("/dashboard", controllers.Dashboard(), middlewares.AuthMiddleware())
	web.GET("/settings", controllers.Settings(), middlewares.AuthMiddleware())
	web.GET("/settings/profile", controllers.Profile(), middlewares.AuthMiddleware())
	web.PATCH("/settings/profile", controllers.UpdateUsernameOrEmail(), middlewares.AuthMiddleware())
	web.GET("/settings/security", controllers.Security(), middlewares.AuthMiddleware())
	web.PATCH("/settings/password", controllers.UpdateUserPassword(), middlewares.AuthMiddleware())
	web.GET("/settings/account", controllers.Account(), middlewares.AuthMiddleware())
	web.POST("/settings/account/activate", controllers.ActivateUser(), middlewares.AuthMiddleware())
	web.DELETE("/settings/account/deactivate", controllers.DeactivateUser(), middlewares.AuthMiddleware())
	web.DELETE("/settings/account/delete", controllers.PermanentlyDeleteUser(), middlewares.AuthMiddleware())
	web.DELETE("/settings/2fa/cancel", controllers.CancelTwoFA(), middlewares.AuthMiddleware())
	web.POST("/settings/2fa/setup", controllers.InitTwoFA(), middlewares.AuthMiddleware())
	web.POST("/settings/2fa/verify", controllers.VerifyTwoFA(), middlewares.AuthMiddleware())
	web.POST("/settings/2fa/complete", controllers.FinalizeTwoFA(), middlewares.AuthMiddleware())
	web.PATCH("/settings/2fa/disable", controllers.DisableTwoFA(), middlewares.AuthMiddleware())
	// web.GET("/settings/users", )
	web.POST("/signup", controllers.SessionSignup())
	web.POST("/verification/manual", controllers.ManualEmailVerification())
	web.GET("/verification/:token", controllers.EmailVerification())
	web.POST("/verification/resend", controllers.ResendEmailVerification())
	web.POST("/login", controllers.SessionLogin())
	web.POST("/logout", controllers.SessionLogout())
	web.GET("/reset", controllers.ResetPage())
	web.GET("/reset/:token", controllers.ResetPageExpress())
	web.POST("/reset/check", controllers.ResetCheck())
	web.POST("/reset/confirm", controllers.ResetUserPassword())
	web.POST("/reset/resend", controllers.ResendReset())

	e.HTTPErrorHandler = serverErrorHandler

	return e
}

func serverErrorHandler(err error, c echo.Context) {
	// Default to internal server error (500)
	code := http.StatusInternalServerError
	var message any = "Internal Server Error"

	// Check if it's an echo.HTTPError
	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
		message = he.Message
	}

	// Check the Accept header to decide the response format
	if strings.Contains(c.Request().Header.Get("Accept"), "application/json") {
		// Respond with JSON if the client prefers JSON
		_ = c.JSON(code, map[string]any{
			"error":   true,
			"message": message,
			"status":  code,
		})
	} else {
		// Prepare data for rendering the error page (HTML)
		data := models.GetDefaultSite("Error")

		html := helpers.MustRenderHTML(views.Error(data, fmt.Sprintf("%d", code), message.(string)))

		// Respond with HTML (default) if the client prefers HTML
		_ = c.Blob(code, "text/html; charset=utf-8", html)
	}
}
