package controllers

import (
	"net/http"
	"strings"

	"github.com/Francesco99975/authpoc/internal/auth"
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

		userID, _, authenticated := auth.GetSessionUserID(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		user, err := repo.GetUserByID(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		tabProps := layouts.TabLayoutProps{
			Site:      data,
			Tabs:      layouts.Tabs(user.Role),
			ActiveTab: "profile",
		}

		profileProps := components.ProfileProps{
			Username:      user.Username,
			Email:         user.Email,
			EmailVerified: user.IsEmailVerified,
			Initials:      strings.Split(user.Username, "")[0],
			UserID:        user.ID.String(),
			Role:          user.Role,
			Created:       user.CreatedAt.Time.Format("January 2, 2006"),
			LastLogin:     user.LastLogin.Time.Format("January 2, 2006"),
			CSRF:          c.Get("csrf").(string),
		}

		html := helpers.MustRenderHTML(views.Settings(data, tabProps, profileProps))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func Profile() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		userID, _, authenticated := auth.GetSessionUserID(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		user, err := repo.GetUserByID(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		props := components.ProfileProps{
			Username:      user.Username,
			Email:         user.Email,
			EmailVerified: user.IsEmailVerified,
			Initials:      strings.Split(user.Username, "")[0],
			UserID:        user.ID.String(),
			Role:          user.Role,
			Created:       user.CreatedAt.Time.Format("January 2, 2006"),
			LastLogin:     user.LastLogin.Time.Format("January 2, 2006"),
			CSRF:          c.Get("csrf").(string),
		}

		html := helpers.MustRenderHTML(components.SettingsProfileTab(props))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func Security() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		userID, _, authenticated := auth.GetSessionUserID(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		user, err := repo.GetUserByID(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		props := components.SecurityProps{
			TwoFAEnabled: user.TwofaEnabled,
			CSRF:         c.Get("csrf").(string),
		}

		html := helpers.MustRenderHTML(components.SettingsSecurityTab(props))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func Account() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		userID, _, authenticated := auth.GetSessionUserID(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		user, err := repo.GetUserByID(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		props := components.AccountProps{
			IsActive: user.IsActive,
			CSRF:     c.Get("csrf").(string),
		}

		html := helpers.MustRenderHTML(components.SettingsAccountTab(props))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

// func Users() echo.HandlerFunc {
// 	return func(c echo.Context) error {
// 		ctx := c.Request().Context()
// 		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
// 		if err != nil {
// 			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
// 		}
// 		defer database.HandleTransaction(ctx, tx, &err)
// 		repo := repository.New(tx)

// 		userID, _, authenticated := auth.GetSessionUserID(c.Request())
// 		if !authenticated {
// 			return c.Redirect(http.StatusSeeOther, "/auth")
// 		}

// 		userUUID, err := uuid.Parse(userID)
// 		if err != nil {
// 			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
// 		}

// 		user, err := repo.GetUserByID(ctx, userUUID)
// 		if err != nil {
// 			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
// 		}

// 		props := components.UsersProps{

// 			CSRF:         c.Get("csrf").(string),
// 		}

// 		html := helpers.MustRenderHTML(components.SettingsUsersTab(props))

// 		return c.Blob(http.StatusOK, "text/html", html)
// 	}
// }
