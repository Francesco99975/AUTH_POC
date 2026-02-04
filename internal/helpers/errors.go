package helpers

import (
	"fmt"

	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/monitoring"
	"github.com/Francesco99975/authpoc/views"
	"github.com/Francesco99975/authpoc/views/components"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

type GenericError struct {
	Code        int      `json:"code"`
	Message     string   `json:"message"`
	UserMessage string   `json:"userMessage"`
	Errors      []string `json:"errors"`
}

type ErrorMessage struct {
	Error       GenericError `json:"error"`
	Box         enums.Box    `json:"box"`
	Persistance string       `json:"persistence"`
}

func (ge *GenericError) Stringify() string {
	return fmt.Sprintf("[%d] %s <-- %v", ge.Code, ge.Message, ge.Errors)
}

func SendReturnedGenericJSONError(c echo.Context, err GenericError, r *Reporter) error {
	monitoring.RecordError(fmt.Sprintf("%d", err.Code))
	log.Error(err.Stringify())

	if r != nil {
		_ = r.Report(SeverityLevels.ERROR, err.Stringify())
	}

	return c.JSON(err.Code, models.JSONErrorResponse{Code: err.Code, Message: err.UserMessage, Errors: err.Errors})
}

func SendReturnedGenericHTMLError(c echo.Context, err GenericError, r *Reporter) error {
	monitoring.RecordError(fmt.Sprintf("%d", err.Code))
	log.Error(err.Stringify())

	if r != nil {
		_ = r.Report(SeverityLevels.ERROR, err.Stringify())
	}

	html := MustRenderHTML(views.Error(models.GetDefaultSite("Error", c.Request()), fmt.Sprintf("%d", err.Code), err.UserMessage))

	return c.Blob(err.Code, "text/html", html)
}

func SendReturnedHTMLErrorMessage(c echo.Context, err ErrorMessage, r *Reporter) error {
	monitoring.RecordError(fmt.Sprintf("%d", err.Error.Code))
	log.Error(err.Error.Stringify())

	if r != nil {
		_ = r.Report(SeverityLevels.ERROR, err.Error.Stringify())
	}

	html := MustRenderHTML(components.ErrorMsg(err.Error.UserMessage, err.Box, err.Persistance))

	return c.Blob(err.Error.Code, "text/html", html)
}
