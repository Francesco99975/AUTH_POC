package httperr

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/monitoring"
	"github.com/Francesco99975/authpoc/internal/tools"
	"github.com/Francesco99975/authpoc/views/components"
	"github.com/labstack/echo/v4"
)

// errorDescriptor holds the user-facing Why and How-to-remedy for a given HTTP status code.
type errorDescriptor struct {
	why    string
	remedy string
}

// JSONErrorResponse is the structured error body returned by HandleJSON.
// Errors is omitted when empty — most errors are single-message.
// RequestID is omitted when absent so it does not appear on handlers that
// don't carry one.
type JSONErrorResponse struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// clientMessages maps 4xx status codes to user-facing error context.
var clientMessages = map[int]errorDescriptor{
	http.StatusBadRequest: {
		why:    "the request contained invalid or malformed data",
		remedy: "check your request parameters and try again",
	},
	http.StatusUnauthorized: {
		why:    "authentication is required to perform this action",
		remedy: "provide valid credentials and try again",
	},
	http.StatusForbidden: {
		why:    "you do not have permission to perform this action",
		remedy: "contact an administrator if you believe this is an error",
	},
	http.StatusNotFound: {
		why:    "the requested resource could not be found",
		remedy: "verify the resource identifier and try again",
	},
	http.StatusMethodNotAllowed: {
		why:    "this HTTP method is not permitted for the requested resource",
		remedy: "consult the API documentation for the correct method",
	},
	http.StatusConflict: {
		why:    "a conflict occurred with the current state of the resource",
		remedy: "resolve the conflict and retry the request",
	},
	http.StatusUnprocessableEntity: {
		why:    "the provided data failed validation",
		remedy: "review the field constraints and correct the data before retrying",
	},
	http.StatusTooManyRequests: {
		why:    "the allowed request rate has been exceeded",
		remedy: "wait before retrying or contact support to adjust your rate limit",
	},
}

// serverMessages maps 5xx status codes to user-facing error context.
var serverMessages = map[int]errorDescriptor{
	http.StatusInternalServerError: {
		why:    "an unexpected error occurred on the server",
		remedy: "try again later or contact support if the problem persists",
	},
	http.StatusNotImplemented: {
		why:    "the requested operation is not supported by the server",
		remedy: "consult the API documentation or contact support",
	},
	http.StatusBadGateway: {
		why:    "an upstream service returned an invalid response",
		remedy: "try again in a few moments",
	},
	http.StatusServiceUnavailable: {
		why:    "the service is temporarily unavailable",
		remedy: "try again in a few moments",
	},
	http.StatusGatewayTimeout: {
		why:    "an upstream service did not respond in time",
		remedy: "try again later or contact support if the problem persists",
	},
}

// defaultClientMessage is the fallback for unmapped 4xx codes.
var defaultClientMessage = errorDescriptor{
	why:    "an unexpected client error occurred",
	remedy: "check your request and try again",
}

// defaultServerMessage is the fallback for unmapped 5xx codes.
var defaultServerMessage = errorDescriptor{
	why:    "an unexpected server error occurred",
	remedy: "try again later or contact support if the problem persists",
}

// HttpErrorMessage handles structured, consistent error reporting for a controller action.
// The what, origin, and requestID fields are constant for the lifetime of the handler
// invocation and are attached to every log entry produced by this instance.
type HttpErrorMessage struct {
	what      string // the operation being performed, e.g. "creating post"
	origin    string // the handler function name, e.g. "CreatePost"
	requestID string // the request ID for log correlation, e.g. from X-Request-ID
}

// New creates an HttpErrorMessage for a given controller action.
//
//   - what:      the operation being performed (e.g. "creating post")
//   - origin:    the handler function name (e.g. "CreatePost")
//   - requestID: the request-scoped ID for correlating log lines (e.g. from X-Request-ID)
func New(what, origin, requestID string) *HttpErrorMessage {
	return &HttpErrorMessage{
		what:      what,
		origin:    origin,
		requestID: requestID,
	}
}

// Handle logs the internal error with structured fields and dispatches a
// user-facing error response via displayerrorDescriptor.
//
// Log severity is derived from the status code class:
//   - 4xx → Warn  (expected client mistakes, not actionable for the server)
//   - 5xx → Error (server-side failures, actionable for on-call)
//
// The HTTP status code is used to resolve the Why and How-to-remedy components.
// Together with the instance's What, these are composed into a single coherent
// message following the What / Why / How pattern.
func (h *HttpErrorMessage) Handle(w http.ResponseWriter, code int, err error) error {
	monitoring.RecordError(fmt.Sprintf("%d", code))
	h.log(code, err)

	descriptor := h.resolve(code)

	message := fmt.Sprintf(
		"An error occurred while %s, caused by %s. To remedy, %s.",
		h.what, descriptor.why, descriptor.remedy,
	)

	tools.SetToastTrigger(w, enums.ErrorToast, message)

	w.WriteHeader(code)

	return err
}

func (h *HttpErrorMessage) HandleOnForm(w http.ResponseWriter, code int, err error, box enums.Box, persistance *time.Duration) error {
	var prs string
	if persistance != nil {
		prs = strconv.FormatInt(persistance.Milliseconds(), 10)
	}

	monitoring.RecordError(fmt.Sprintf("%d", code))
	h.log(code, err)

	descriptor := h.resolve(code)

	message := fmt.Sprintf(
		"An error occurred while %s, caused by %s. To remedy, %s.",
		h.what, descriptor.why, descriptor.remedy,
	)

	htmlBytes := helpers.MustRenderHTML(components.ErrorMsg(message, box, prs))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, internal_error := w.Write(htmlBytes)
	if internal_error != nil {
		h.log(http.StatusInternalServerError, err)
		return internal_error
	}

	return err
}

// HandleJSON is for API handlers. It logs the error and writes a structured
// JSON error body. The errors parameter is optional — pass nil for single-message
// errors, or a slice of validation messages for 422 responses.
//
// Usage:
//
//	return errMsg.HandleJSON(w, http.StatusUnprocessableEntity, err, []string{"title is required", "content is required"})
//	return errMsg.HandleJSON(w, http.StatusInternalServerError, err, nil)
func (h *HttpErrorMessage) HandleJSON(w http.ResponseWriter, code int, err error) error {
	monitoring.RecordError(fmt.Sprintf("%d", code))
	h.log(code, err)

	ce := h.resolve(code)
	message := fmt.Sprintf(
		"An error occurred while %s: %s. To remedy, %s.",
		h.what, ce.why, ce.remedy,
	)

	resp := JSONErrorResponse{
		Code:      code,
		Message:   message,
		RequestID: h.requestID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	internal_error := json.NewEncoder(w).Encode(resp)
	if internal_error != nil {
		h.log(http.StatusInternalServerError, err)
		return internal_error
	}
	return err
}

// HandlePage is for navigational handlers. It logs the error and returns an
// echo.HTTPError which Echo's serverErrorHandler catches to render the
// appropriate error page or JSON response based on the Accept header.
//
// Usage:
//
//	return errMsg.HandlePage(http.StatusNotFound, fmt.Errorf("post %d not found", id))
func (h *HttpErrorMessage) HandleEchoPage(code int, err error) error {
	monitoring.RecordError(fmt.Sprintf("%d", code))
	h.log(code, err)
	return echo.NewHTTPError(code)
}

// resolve looks up the errorDescriptor for the given status code, falling back to
// the appropriate default based on whether the code is a 4xx or 5xx.
func (h *HttpErrorMessage) resolve(code int) errorDescriptor {
	if code >= 500 {
		if descriptor, ok := serverMessages[code]; ok {
			return descriptor
		}
		return defaultServerMessage
	}

	if descriptor, ok := clientMessages[code]; ok {
		return descriptor
	}
	return defaultClientMessage
}

// log emits a structured log entry at the appropriate severity level.
// Every entry carries action, origin, request_id, status, and error as
// discrete fields for easy filtering and correlation.
func (h *HttpErrorMessage) log(code int, err error) {
	attrs := []any{
		"action", h.what,
		"origin", h.origin,
		"request_id", h.requestID,
		"status", code,
		"error", err,
	}

	if code >= 500 {
		slog.Error("server error", attrs...)
	} else {
		slog.Warn("client error", attrs...)
	}
}
