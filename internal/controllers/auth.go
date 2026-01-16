package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/views/components"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

func SessionSignup() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.SignupRequest
		err := c.Bind(&payload)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid input", Message: fmt.Errorf("Invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		log.Debugf("Signup payload: %v", payload)

		err = payload.ValidateAndNormalize(1)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: err.Error(), Message: fmt.Errorf("Invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		log.Debugf("Normalized signup payload: %v", payload)

		ctx := c.Request().Context()

		hashedPassword, err := helpers.HashPassword(payload.Password)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to hash password", Message: fmt.Errorf("Failed to hash password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		log.Debugf("Hashed password: %v", hashedPassword)

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to open database on signup", Message: fmt.Errorf("Failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		newUser, err := repo.CreateUser(ctx, repository.CreateUserParams{ID: uuid.New(), Role: "USER", Username: payload.Username, Email: payload.Email, PasswordHash: hashedPassword})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to create user", Message: fmt.Errorf("Failed to create user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		log.Debugf("New user: %v", newUser)

		token, err := helpers.GenerateBase62Token(8)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to generate token", Message: fmt.Errorf("Failed to generate token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		log.Debugf("Generated token: %v", token)

		ev, err := repo.CreateEmailVerification(ctx, repository.CreateEmailVerificationParams{ID: uuid.New(), UserID: newUser.ID, Token: token, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Duration(30 * time.Minute)), Valid: true}})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to Create email verification", Message: fmt.Errorf("Failed to Create email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		helpers.ResendEmailVerificationTemplate(newUser.Email, ev.Token)

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.EmailVerification(payload.Email, csrf))

		return c.Blob(http.StatusCreated, "text/html", html)
	}
}

func ResendEmailVerification() echo.HandlerFunc {
	return func(c echo.Context) error {
		email := c.FormValue("email")

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to open database on signup", Message: fmt.Errorf("Failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := repo.GetUserByEmail(ctx, email)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "User not found", Message: fmt.Errorf("User not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if user.IsEmailVerified {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusConflict, UserMessage: "User is already verified", Message: fmt.Errorf("User is already verified: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.DeleteEmailVerificationByUserID(ctx, user.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to delete old email verification", Message: fmt.Errorf("Failed to delete old email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		token, err := helpers.GenerateBase62Token(8)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to generate token", Message: fmt.Errorf("Failed to generate token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		log.Debugf("Generated token: %v", token)

		ev, err := repo.CreateEmailVerification(ctx, repository.CreateEmailVerificationParams{ID: uuid.New(), UserID: user.ID, Token: token, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Duration(30 * time.Minute)), Valid: true}})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to Create email verification", Message: fmt.Errorf("Failed to Create email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		helpers.ResendEmailVerificationTemplate(user.Email, ev.Token)

		html := helpers.MustRenderHTML(components.SuccessMsg("Verification Email Resent"))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func EmailVerification() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.VerifyEmailRequest = models.VerifyEmailRequest{Token: c.Param("token")}

		err := payload.Validate()
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: err.Error(), Message: fmt.Errorf("Invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to open database on signup", Message: fmt.Errorf("Failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		verification, err := repo.GetEmailVerificationByToken(ctx, payload.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to get email verification", Message: fmt.Errorf("Failed to get email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if verification.ExpiresAt.Time.Before(time.Now()) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "Token expired", Message: fmt.Errorf("Token expired: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.VerifyUserEmail(ctx, verification.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to verify email", Message: fmt.Errorf("Failed to verify email: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.MarkEmailVerificationUsed(ctx, verification.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, Message: fmt.Sprintf("Failed to mark email verification used: %v", err), UserMessage: "Failed to verify email"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		return c.Redirect(http.StatusSeeOther, "/")
	}
}

func ManualEmailVerification() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.VerifyEmailRequest
		err := c.Bind(&payload)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid input", Message: fmt.Errorf("Invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = payload.Validate()
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: err.Error(), Message: fmt.Errorf("Invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to open database on signup", Message: fmt.Errorf("Failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		verification, err := repo.GetEmailVerificationByToken(ctx, payload.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to get email verification", Message: fmt.Errorf("Failed to get email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if verification.ExpiresAt.Time.Before(time.Now()) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "Token expired", Message: fmt.Errorf("Token expired: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.VerifyUserEmail(ctx, verification.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to verify email", Message: fmt.Errorf("Failed to verify email: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.MarkEmailVerificationUsed(ctx, verification.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, Message: fmt.Sprintf("Failed to mark email verification used: %v", err), UserMessage: "Failed to verify email"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		html := helpers.MustRenderHTML(components.InfoDisplay("Succcess", "Email Verified! Try to Signin"))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func SessionLogin() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.LoginRequest
		err := c.Bind(&payload)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid input", Message: fmt.Errorf("Invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		log.Debugf("Login payload: %v", payload)

		err = payload.Validate()
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: err.Error(), Message: fmt.Errorf("Invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to open database on login", Message: fmt.Errorf("Failed to open database on login: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := repo.GetUserByEmailOrUsername(ctx, payload.EmailOrUsername)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("User not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if !user.IsEmailVerified {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "email not verified", Message: fmt.Errorf("Email not verified: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if !helpers.CheckPasswordHash(payload.Password, user.PasswordHash) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "invalid credentials", Message: fmt.Errorf("Invalid credentials: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if err := auth.SetSessionUser(c.Response(), c.Request(), user.ID.String(), user.Role, payload.Remeber == "on"); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to set session", Message: fmt.Errorf("Failed to set session: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		_ = repo.UpdateUserLastLogin(ctx, user.ID)

		c.Response().Header().Set("HX-Redirect", "/dashboard")
		return c.NoContent(http.StatusOK)
	}
}

func SessionLogout() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := auth.ClearSession(c.Response(), c.Request()); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Failed to logout", Message: fmt.Errorf("Failed to logout: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		c.Response().Header().Set("HX-Redirect", "/")
		return c.NoContent(http.StatusOK)
	}
}
