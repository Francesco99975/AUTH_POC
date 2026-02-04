package controllers

import (
	"fmt"
	"net/http"

	"strings"
	"time"

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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/pquerna/otp/totp"
)

func Settings() echo.HandlerFunc {
	return func(c echo.Context) error {

		data := models.GetDefaultSite("Settings", c.Request())

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, authenticated := auth.GetSessionUser(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(auser.ID)
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

		auser, authenticated := auth.GetSessionUser(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(auser.ID)
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

func UpdateUsername() echo.HandlerFunc {
	return func(c echo.Context) error {
		username := c.FormValue("username")

		if username == "" {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "invalid data sent", Message: "invalid form data"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		username = strings.ToLower(username)

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, authenticated := auth.GetSessionUser(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(user.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		_, err = repo.UpdateUserUsername(ctx, repository.UpdateUserUsernameParams{Username: username, ID: userUUID})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not update username or email", Message: fmt.Errorf("could not update username or email: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		html := helpers.MustRenderHTML(components.SuccessMsg("User Updated!"))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func UpdateEmail() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.ChangeEmail

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

		user, authenticated := auth.GetSessionUser(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(user.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if payload.Email == user.Email {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "email did not change", Message: "email did not change"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		token, err := helpers.GenerateBase62Token(8)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to generate token", Message: fmt.Errorf("failed to generate token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		_, err = repo.CreateEmailVerification(ctx, repository.CreateEmailVerificationParams{ID: uuid.New(), UserID: userUUID, Token: token, Email: payload.Email, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Duration(30 * time.Minute)), Valid: true}})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to generate token", Message: fmt.Errorf("failed to generate token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		helpers.ResendEmailVerificationTemplate(payload.Email, token)

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.EmailVerification(payload.Email, csrf, "/verification/update"))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func UpdateManualEmailVerification() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.VerifyEmailRequest
		err := c.Bind(&payload)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid input", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = payload.Validate()
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: err.Error(), Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		verification, err := repo.GetEmailVerificationByToken(ctx, payload.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to get email verification", Message: fmt.Errorf("failed to get email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if verification.ExpiresAt.Time.Before(time.Now()) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "token expired", Message: fmt.Errorf("token expired: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.VerifyUserEmail(ctx, verification.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to verify email", Message: fmt.Errorf("failed to verify email: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.MarkEmailVerificationUsed(ctx, verification.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, Message: fmt.Sprintf("failed to mark email verification used: %v", err), UserMessage: "failed to verify email"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		user, err := repo.UpdateUserEmail(ctx, repository.UpdateUserEmailParams{
			Email: verification.Email,
			ID:    verification.UserID,
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, Message: fmt.Sprintf("failed to mark get user: %v", err), UserMessage: "failed to get user"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.ChangeUserEmailForm(user.Email, user.IsEmailVerified, csrf))

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

		auser, authenticated := auth.GetSessionUser(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(auser.ID)
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
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, authenticated := auth.GetSessionUser(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(auser.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		hash, err := repo.GetPasswordHash(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("unable to find user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if !helpers.CheckPasswordHash(payload.CurrentPassword, hash) {
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

		html := helpers.MustRenderHTML(components.SuccessMsg("User Password Updated!"))

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

		auser, authenticated := auth.GetSessionUser(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(auser.ID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		user, err := repo.GetUserByID(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		props := components.AccountProps{
			IsActive:     user.IsActive,
			TwoFAEnabled: user.TwofaEnabled,
			UserEmail:    user.Email,
			CSRF:         c.Get("csrf").(string),
		}

		html := helpers.MustRenderHTML(components.SettingsAccountTab(props))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func DeactivateUser() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, authenticated := auth.GetSessionUser(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(auser.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.DeactivateUser(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not deactivate user", Message: fmt.Errorf("could not deactivate user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.AccountStatusCard(false, true))
		html = append(html, helpers.MustRenderHTML(components.DeactivateSection(false, csrf, true))...)

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func ActivateUser() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, authenticated := auth.GetSessionUser(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(auser.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.ReactivateUser(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not reactivate user", Message: fmt.Errorf("could not reactivate user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.AccountStatusCard(true, true))
		html = append(html, helpers.MustRenderHTML(components.DeactivateSection(true, csrf, true))...)

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func PermanentlyDeleteUser() echo.HandlerFunc {
	return func(c echo.Context) error {
		password := c.FormValue("password")
		otp := c.FormValue("otp")

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, authenticated := auth.GetSessionUser(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(auser.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if auser.TwoFAEnabled {
			secrets, err := repo.GetUser2FASecret(ctx, userUUID)
			if err != nil {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("user not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
			}

			if !helpers.CheckPasswordHash(password, secrets.PasswordHash) {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "invalid credentials", Message: fmt.Errorf("invalid credentials: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
			}

			if !totp.Validate(otp, *secrets.TwofaSecret) {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "unauthorized: invalid code", Message: "totp validation failed"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
			}
		} else {
			hash, err := repo.GetPasswordHash(ctx, userUUID)
			if err != nil {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("user not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
			}

			if !helpers.CheckPasswordHash(password, hash) {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "invalid credentials", Message: fmt.Errorf("invalid credentials: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
			}
		}

		if err := auth.ClearSession(c.Response(), c.Request()); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to logout", Message: fmt.Errorf("failed to clear session: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.DeleteUser(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not delete user", Message: fmt.Errorf("could not delete user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		c.Response().Header().Set("HX-Redirect", "/")
		return c.NoContent(http.StatusOK)
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

// 		userID, _, authenticated := auth.GetSessionUser(c.Request())
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
