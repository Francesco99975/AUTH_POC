package controllers

import (
	"net/http"

	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/views"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
)

func Index() echo.HandlerFunc {
	return func(c echo.Context) error {

		_, _, authenticated := auth.GetSessionUserID(c.Request())

		if authenticated {
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}

		return c.Redirect(http.StatusSeeOther, "/auth")

	}
}

func Auth() echo.HandlerFunc {
	return func(c echo.Context) error {
		_, _, authenticated := auth.GetSessionUserID(c.Request())
		if authenticated {
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}

		data := models.GetDefaultSite("Authentication")

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		html := helpers.MustRenderHTML(views.Index(data))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func Dashboard() echo.HandlerFunc {
	return func(c echo.Context) error {
		userIDStr, _, authenticated := auth.GetSessionUserID(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		data := models.GetDefaultSite("Dashboard")

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		ctx := c.Request().Context()
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := repo.GetUserByID(ctx, userID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		html := helpers.MustRenderHTML(views.Dashboard(data, user.Username, user.Email))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}
