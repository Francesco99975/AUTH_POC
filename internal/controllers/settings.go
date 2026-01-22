package controllers

import (
	"net/http"
	"strings"

	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/views"
	"github.com/Francesco99975/authpoc/views/components"
	"github.com/Francesco99975/authpoc/views/layouts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
)

func Settings() echo.HandlerFunc {
	return func(c echo.Context) error {

		data := models.GetDefaultSite("Settings")

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)
		UserUUID, err := uuid.Parse(c.Get("user_id").(string))

		user, err := repo.GetUserByID(ctx, UserUUID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		tabProps := layouts.TabLayoutProps{
			Site:      data,
			Tabs:      layouts.DefaultTabs(),
			ActiveTab: "profile",
		}

		profileProps := components.ProfileProps{
			Username:      user.Username,
			Email:         user.Email,
			EmailVerified: user.IsEmailVerified,
			Initials:      strings.Split(user.Username, "")[0],
			UserID:        user.ID.String(),
			Role:          user.Role,
			Created:       user.CreatedAt.Time.Format("2006-01-02"),
			LastLogin:     user.LastLogin.Time.Format("2006-01-02"),
			CSRF:          c.Get("csrf").(string),
		}

		html := helpers.MustRenderHTML(views.Settings(data, tabProps, profileProps))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}
