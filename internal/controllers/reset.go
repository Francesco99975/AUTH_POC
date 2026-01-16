package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/views"
	"github.com/Francesco99975/authpoc/views/components"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
)

func ResetPage() echo.HandlerFunc {
	return func(c echo.Context) error {
		data := models.GetDefaultSite("Reset Password")

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		html := helpers.MustRenderHTML(views.PasswordReset(data))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func ResetPageExpress() echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Param("token")
		data := models.GetDefaultSite("Reset Password")

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		html := helpers.MustRenderHTML(views.PasswordResetExpress(data, token))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func ResetCheck() echo.HandlerFunc {
	return func(c echo.Context) error {
		email := c.FormValue("email")

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could Not Check Users", Message: fmt.Errorf("Failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := repo.GetUserByEmail(ctx, email)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "User not found with this email", Message: fmt.Errorf("User not found during reset password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if user == nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "User not found with this email", Message: fmt.Errorf("User not found during reset password, because user is nil: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if !user.IsEmailVerified {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusForbidden, UserMessage: "This user does not have a verified email", Message: "user does not have a verified email: %v"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		token, err := helpers.GenerateBase62Token(12)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "An Unexpected error occurred while trying to resert password", Message: fmt.Errorf("Error During Token generation for password reset: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		passwordReset, err := repo.CreatePasswordReset(ctx, repository.CreatePasswordResetParams{
			ID:        uuid.New(),
			UserID:    user.ID,
			Token:     token,
			ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Minute * 30), Valid: true},
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "An Unexpected error occurred while trying to resert password", Message: fmt.Errorf("password reset entry was not created: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		helpers.ResendPasswordResetTemplate(user.Email, passwordReset.Token)

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.CheckEmailCard(user.Email, csrf))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func ResendReset() echo.HandlerFunc {
	return func(c echo.Context) error {
		email := c.FormValue("email")

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could Not Check Users", Message: fmt.Errorf("Failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := repo.GetUserByEmail(ctx, email)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "User not found with this email", Message: fmt.Errorf("User not found during reset password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if user == nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "User not found with this email", Message: fmt.Errorf("User not found during reset password, because user is nil: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if !user.IsEmailVerified {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusForbidden, UserMessage: "This user does not have a verified email", Message: "user does not have a verified email: %v"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.DeletePasswordResetByUserID(ctx, user.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "An Unexpected error occurred while trying to resert password", Message: fmt.Errorf("Error During old token deletion: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		token, err := helpers.GenerateBase62Token(12)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "An Unexpected error occurred while trying to resert password", Message: fmt.Errorf("Error During Token generation for password reset: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		passwordReset, err := repo.CreatePasswordReset(ctx, repository.CreatePasswordResetParams{
			ID:        uuid.New(),
			UserID:    user.ID,
			Token:     token,
			ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Minute * 30), Valid: true},
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "An Unexpected error occurred while trying to resert password", Message: fmt.Errorf("password reset entry was not created: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		helpers.ResendPasswordResetTemplate(user.Email, passwordReset.Token)

		html := helpers.MustRenderHTML(components.SuccessMsg("Email Resent with new token"))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func ResetUserPassword() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.ResetPasswordRequest
		err := c.Bind(&payload)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "Invalid Data Sent", Message: fmt.Errorf("Invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = payload.Validate(1)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "Invalid Data Sent", Message: fmt.Errorf("Invalid form data on validate: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Unexpected Error Occurred while trying to reset password", Message: fmt.Errorf("Unable to get transaction from db: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		passwordReset, err := repo.GetPasswordResetByToken(ctx, payload.Token)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "Token not found for this user", Message: fmt.Errorf("Unable to find password reset token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if passwordReset.ExpiresAt.Time.Before(time.Now()) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusPreconditionFailed, UserMessage: "Password reset token has expired", Message: fmt.Errorf("Password reset token has expired: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if passwordReset.Used {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusConflict, UserMessage: "Password reset token has already been used", Message: fmt.Errorf("Password reset token has already been used: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		user, err := repo.GetUserByID(ctx, passwordReset.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "User not found", Message: fmt.Errorf("Unable to find user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if user == nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "User not found", Message: fmt.Errorf("Unable to find user since its nil: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if !user.IsEmailVerified {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusPreconditionFailed, UserMessage: "User email is not verified", Message: fmt.Errorf("User email is not verified: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		hashedPassword, err := helpers.HashPassword(payload.Password)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Unexpected Error Occurred while trying to reset password", Message: fmt.Errorf("Unable to hash password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.UpdateUserPassword(ctx, repository.UpdateUserPasswordParams{
			ID:           user.ID,
			PasswordHash: hashedPassword,
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Unexpected Error Occurred while trying to reset password", Message: fmt.Errorf("Unable to update user password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.MarkPasswordResetUsed(ctx, passwordReset.Token)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Unexpected Error Occurred while trying to reset password", Message: fmt.Errorf("Unable to mark password reset as used: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.CleanupExpiredPasswordResets(ctx)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Unexpected Error Occurred while trying to reset password", Message: fmt.Errorf("Unable to cleanup expired password resets: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		html := helpers.MustRenderHTML(components.ResetSuccessCard())

		return c.Blob(http.StatusOK, "text/html", html)

	}
}
