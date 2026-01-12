package middlewares

import (
	"net/http"
	"strings"
	"time"

	"github.com/Francesco99975/authpoc/cmd/boot"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// rateLimiter returns a configured middleware.RateLimiter
func RateLimiter() echo.MiddlewareFunc {
	// Config per environment
	var config middleware.RateLimiterConfig

	if boot.Environment.GoEnv == enums.Environments.DEVELOPMENT {
		// DEV: Generous limits (for testing)
		config = middleware.RateLimiterConfig{
			Skipper: middleware.DefaultSkipper,
			Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
				Rate:      100, // 100 req/sec
				Burst:     200,
				ExpiresIn: 1 * time.Minute,
			}),
			IdentifierExtractor: func(c echo.Context) (string, error) {
				return c.RealIP(), nil
			},
			ErrorHandler: func(c echo.Context, err error) error {
				if strings.Contains(c.Request().Header.Get("Accept"), "application/json") {
					return c.JSON(http.StatusTooManyRequests, map[string]string{
						"error": "Too many requests (dev mode)",
					})
				} else {
					return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusTooManyRequests, Message: "Too many requests (dev mode)", UserMessage: "Too many requests (dev mode)"}, nil)
				}
			},
			DenyHandler: func(c echo.Context, identifier string, err error) error {
				c.Response().Header().Set("Retry-After", "60")
				if strings.Contains(c.Request().Header.Get("Accept"), "application/json") {
					return c.JSON(http.StatusTooManyRequests, map[string]string{
						"error": "Rate limit exceeded. Try again later.",
					})
				} else {
					return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusTooManyRequests, Message: "Rate limit exceeded. Try again later. (dev mode)", UserMessage: "Rate limit exceeded. Try again later. (dev mode)"}, nil)
				}
			},
		}
	} else {
		// PROD: Strict, secure limits
		config = middleware.RateLimiterConfig{
			Skipper: middleware.DefaultSkipper,
			Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
				Rate:      50, // 10 req/sec per IP
				Burst:     80,
				ExpiresIn: 3 * time.Minute,
			}),
			IdentifierExtractor: func(c echo.Context) (string, error) {
				// Use RealIP (respects X-Forwarded-For in prod)
				return c.RealIP(), nil
			},
			ErrorHandler: func(c echo.Context, err error) error {
				if strings.Contains(c.Request().Header.Get("Accept"), "application/json") {
					return c.JSON(http.StatusTooManyRequests, map[string]string{
						"error": "Too many requests",
					})
				} else {
					return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusTooManyRequests, Message: "Too many requests"}, nil)
				}

			},
			DenyHandler: func(c echo.Context, identifier string, err error) error {
				c.Response().Header().Set("Retry-After", "180")
				if strings.Contains(c.Request().Header.Get("Accept"), "application/json") {
					return c.JSON(http.StatusTooManyRequests, map[string]string{
						"error":   "Rate limit exceeded",
						"retryIn": "180",
					})
				} else {
					return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusTooManyRequests, Message: "Rate limit exceeded. Try again later."}, nil)
				}
			},
		}
	}

	return middleware.RateLimiterWithConfig(config)
}
