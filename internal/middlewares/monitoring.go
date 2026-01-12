package middlewares

import (
	"net"
	"net/http"
	"strings"
	"time"

	"fmt"
	"slices"

	"github.com/Francesco99975/authpoc/cmd/boot"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/monitoring"
	"github.com/labstack/echo/v4"
)

// MonitoringMiddleware tracks request metrics and exposes them for Prometheus
func MonitoringMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			path := c.Path()
			method := c.Request().Method

			// Proceed with the request
			err := next(c)

			// Calculate duration
			duration := time.Since(start).Seconds()
			status := c.Response().Status

			// Sanitize path for metrics (e.g., convert dynamic routes like /user/:id to /user/{id})
			if strings.Contains(path, ":") {
				path = strings.ReplaceAll(path, ":", "{") + "}"
			}

			// Record metrics
			monitoring.IncreaseHTTPRequestCount(method, path, status)
			monitoring.RecordHTTPRequestDuration(method, path, status, duration)

			return err
		}
	}
}

func MetricsAccessMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth := c.Request().Header.Get("Authorization")
			if auth == "" {
				return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusForbidden, Message: "Forbidden Access Attempt to Metrics without Authorization header", UserMessage: "Resource is not accessible"}, nil)
			}

			realIP := c.RealIP()
			var ipStr string
			var err error
			if !strings.Contains(realIP, ":") {
				ipStr = realIP
			} else {
				ipStr, _, err = net.SplitHostPort(c.RealIP())
				if err != nil {
					return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusForbidden, Message: fmt.Sprintf("Forbidden Access Attempt to Metrics with invalid IP address at splitting host <-- %v", err.Error()), UserMessage: "Resource is not accessible"}, nil)
				}
			}

			sourceIP := net.ParseIP(ipStr)
			if sourceIP == nil {
				return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusForbidden, Message: "Forbidden Access Attempt to Metrics with invalid source IP address", UserMessage: "Resource is not accessible"}, nil)
			}

			ips, err := net.LookupHost(boot.Environment.Prometheus)
			if err != nil {
				return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: fmt.Sprintf("Error resolving Prometheus IP address (%v) <-- %v", boot.Environment.Prometheus, err.Error()), UserMessage: "Server is not accessible to find this resource"}, nil)
			}

			allowed := slices.Contains(ips, sourceIP.String())

			if !allowed {
				return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusForbidden, Message: fmt.Sprintf("Forbidden Access Attempt to Metrics with invalid source IP address (%v)", sourceIP), UserMessage: "Resource is not accessible"}, nil)
			}

			return next(c)
		}
	}
}
