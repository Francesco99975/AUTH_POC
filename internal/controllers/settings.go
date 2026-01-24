package controllers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/views"
	"github.com/Francesco99975/authpoc/views/components"
	"github.com/Francesco99975/authpoc/views/layouts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
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

func UpdateUsernameOrEmail() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.ChangeUsernameOrEmail

		if err := c.Bind(&payload); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "invalid data sent", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		userID, _, authenticated := auth.GetSessionUserID(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		updatedUser, err := repo.UpdateUserUsernameOrEmail(ctx, repository.UpdateUserUsernameOrEmailParams{Username: payload.Username, Email: payload.Email, ID: userUUID})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not update username or email", Message: fmt.Errorf("could not update username or email: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.ChangeUserDetailsForm(updatedUser.Username, updatedUser.Email, updatedUser.IsEmailVerified, csrf))
		html = append(html, helpers.MustRenderHTML(components.SuccessMsg("User Updated!"))...)

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

func UpdateUserPassword() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.ChangePasswordRequest

		if err := c.Bind(&payload); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "invalid data sent", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		log.Debugf("Change password payload: %v", payload)

		err := payload.Validate(1)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: err.Error(), Message: fmt.Errorf("invalid form data on validate: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		userID, _, authenticated := auth.GetSessionUserID(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		user, err := repo.GetUserByID(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("unable to find user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if !helpers.CheckPasswordHash(payload.CurrentPassword, user.PasswordHash) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "invalid password", Message: fmt.Errorf("invalid password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		hashedPassword, err := helpers.HashPassword(payload.NewPassword)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "unexpected Error Occurred while trying to reset password", Message: fmt.Errorf("unable to hash password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.UpdateUserPassword(ctx, repository.UpdateUserPasswordParams{
			ID:           userUUID,
			PasswordHash: hashedPassword,
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "unexpected Error Occurred while trying to reset password", Message: fmt.Errorf("unable to update user password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.ChangePasswordForm(csrf))
		html = append(html, helpers.MustRenderHTML(components.SuccessMsg("User Password Updated!"))...)

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
