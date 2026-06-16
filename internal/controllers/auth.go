package controllers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image/png"

	"net/http"
	"time"

	"github.com/Francesco99975/authpoc/cmd/boot"
	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/internal/tools"
	"github.com/Francesco99975/authpoc/views"
	"github.com/Francesco99975/authpoc/views/components"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/blake2b"
)

func SessionSignup() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.SignupRequest
		err := c.Bind(&payload)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid input", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		log.Debugf("Signup payload: %v", payload)

		err = payload.ValidateAndNormalize(1)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: err.Error(), Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		log.Debugf("Normalized signup payload: %v", payload)

		ctx := c.Request().Context()

		hashedPassword, err := helpers.HashPassword(payload.Password)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to hash password", Message: fmt.Errorf("failed to hash password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		log.Debugf("Hashed password: %v", hashedPassword)

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		existsEmail, err := repo.ExistsUserWithEmail(ctx, payload.Email)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could not Create account at thius moment", Message: fmt.Errorf("failed to check if user exists by email: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if existsEmail {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusConflict, UserMessage: "An account with this email already exists", Message: fmt.Errorf("email exists: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		existsUsername, err := repo.ExistsUserWithUsername(ctx, payload.Username)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could not Create account at thius moment", Message: fmt.Errorf("failed to check if user exists by username: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if existsUsername {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusConflict, UserMessage: "An account with this username already exists", Message: fmt.Errorf("username exists: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		var newUser *repository.CreateUserRow

		_, err = helpers.GenerateProofUUIDV7(database.IsPKCollision("users_pkey"), func(id uuid.UUID) error {
			var insert_err error
			newUser, insert_err = repo.CreateUser(ctx, repository.CreateUserParams{ID: id, Role: enums.Roles.USER.String(), Username: payload.Username, Email: payload.Email, PasswordHash: hashedPassword})
			return insert_err
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to create user", Message: fmt.Errorf("failed to create user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		log.Debugf("New user: %v", newUser)

		token, err := helpers.GenerateBase62Token(8)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to generate token", Message: fmt.Errorf("failed to generate token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		log.Debugf("Generated token: %v", token)

		var ev *repository.CreateEmailVerificationRow

		_, err = helpers.GenerateProofUUIDV4(database.IsPKCollision("email_verifications_pkey"), func(id uuid.UUID) error {
			var insert_err error
			ev, insert_err = repo.CreateEmailVerification(ctx, repository.CreateEmailVerificationParams{ID: uuid.New(), UserID: newUser.ID, Token: token, Email: newUser.Email, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Duration(30 * time.Minute)), Valid: true}})
			return insert_err
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to Create email verification", Message: fmt.Errorf("failed to Create email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		helpers.ResendEmailVerificationTemplate(newUser.Email, ev.Token)

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.EmailVerification(payload.Email, csrf, "/verification/manual"))

		return c.Blob(http.StatusCreated, "text/html", html)
	}
}

func ResendEmailVerification() echo.HandlerFunc {
	return func(c echo.Context) error {
		email := c.FormValue("email")

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := repo.GetUserByEmail(ctx, email)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("user not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if user.IsEmailVerified {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusConflict, UserMessage: "user is already verified", Message: fmt.Errorf("user is already verified: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = repo.DeleteEmailVerificationByUserID(ctx, user.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to delete old email verification", Message: fmt.Errorf("failed to delete old email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		token, err := helpers.GenerateBase62Token(8)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to generate token", Message: fmt.Errorf("failed to generate token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		log.Debugf("Generated token: %v", token)

		var ev *repository.CreateEmailVerificationRow

		_, err = helpers.GenerateProofUUIDV4(database.IsPKCollision("email_verifications_pkey"), func(id uuid.UUID) error {
			var insert_err error
			ev, insert_err = repo.CreateEmailVerification(ctx, repository.CreateEmailVerificationParams{ID: uuid.New(), UserID: user.ID, Token: token, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Duration(30 * time.Minute)), Valid: true}})
			return insert_err
		})

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to Create email verification", Message: fmt.Errorf("failed to Create email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		helpers.ResendEmailVerificationTemplate(user.Email, ev.Token)

		tools.SetToastTrigger(c.Response(), enums.InfoToast, "Resent email verification")
		return c.NoContent(http.StatusAccepted)

	}
}

func EmailVerification() echo.HandlerFunc {
	return func(c echo.Context) error {
		payload := models.VerifyEmailRequest{Token: c.Param("token")}

		err := payload.Validate()
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: err.Error(), Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		verification, err := repo.GetEmailVerificationByToken(ctx, payload.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to get email verification", Message: fmt.Errorf("failed to get email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if verification.ExpiresAt.Time.Before(time.Now()) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "token expired", Message: fmt.Errorf("token expired: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = repo.VerifyUserEmail(ctx, verification.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to verify email", Message: fmt.Errorf("failed to verify email: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = repo.MarkEmailVerificationUsed(ctx, verification.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, Message: fmt.Sprintf("failed to mark email verification used: %v", err), UserMessage: "failed to verify email"}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		return c.Redirect(http.StatusSeeOther, "/")
	}
}

func ManualEmailVerification() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.VerifyEmailRequest
		err := c.Bind(&payload)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid input", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = payload.Validate()
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: err.Error(), Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		verification, err := repo.GetEmailVerificationByToken(ctx, payload.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to get email verification", Message: fmt.Errorf("failed to get email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if verification.ExpiresAt.Time.Before(time.Now()) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "token expired", Message: fmt.Errorf("token expired: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = repo.VerifyUserEmail(ctx, verification.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to verify email", Message: fmt.Errorf("failed to verify email: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = repo.MarkEmailVerificationUsed(ctx, verification.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, Message: fmt.Sprintf("failed to mark email verification used: %v", err), UserMessage: "failed to verify email"}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		c.Response().Header().Set("HX-Redirect", "/auth")
		return c.NoContent(http.StatusOK)
	}
}

func SessionLogin() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.LoginRequest
		err := c.Bind(&payload)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid input", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		log.Debugf("Login payload: %v", payload)

		err = payload.Validate()
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: err.Error(), Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on login", Message: fmt.Errorf("failed to open database on login: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		user, err := repo.GetUserByEmailOrUsername(ctx, payload.EmailOrUsername)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("user not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if !user.IsEmailVerified && user.Role != string(enums.Roles.DEVELOPER) {
			token, err := helpers.GenerateBase62Token(8)
			if err != nil {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to generate token", Message: fmt.Errorf("failed to generate token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
			}
			log.Debugf("Generated token: %v", token)

			var ev *repository.CreateEmailVerificationRow

			_, err = helpers.GenerateProofUUIDV4(database.IsPKCollision("email_verifications_pkey"), func(id uuid.UUID) error {
				var insert_err error
				ev, insert_err = repo.CreateEmailVerification(ctx, repository.CreateEmailVerificationParams{ID: uuid.New(), UserID: user.ID, Token: token, Email: user.Email, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Duration(30 * time.Minute)), Valid: true}})
				return insert_err
			})

			if err != nil {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to Create email verification", Message: fmt.Errorf("failed to Create email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
			}

			helpers.ResendEmailVerificationTemplate(user.Email, ev.Token)

			csrf := c.Get("csrf").(string)

			html := helpers.MustRenderHTML(components.EmailVerification(user.Email, csrf, "/verification/manual"))

			return c.Blob(http.StatusCreated, "text/html", html)
		}

		if !helpers.CheckPasswordHash(payload.Password, user.PasswordHash) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "invalid credentials", Message: fmt.Errorf("invalid credentials: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if user.Role == string(enums.Roles.DEVELOPER) && !user.IsEmailVerified {
			csrf := c.Get("csrf").(string)

			html := helpers.MustRenderHTML(components.DevResetCard(csrf, user.ID.String()))

			return c.Blob(http.StatusOK, "text/html", html)
		}

		if user.TwofaEnabled {
			csrf := c.Get("csrf").(string)

			challengeID, err := helpers.GenerateProofUUIDV4(database.IsPKCollision("pending_auth_challenges_pkey"), func(u uuid.UUID) error {
				_, err = repo.CreatePendingAuthChallenge(ctx, repository.CreatePendingAuthChallengeParams{
					ID:         u,
					UserID:     user.ID,
					Mode:       enums.TwofaModes.CHALLENGE.String(),
					Secret:     nil,
					RememberMe: payload.Remeber == "on",
					ExpiresAt: pgtype.Timestamptz{
						Time:  time.Now().Add(time.Duration(time.Minute * 10)),
						Valid: true,
					},
				})

				return err
			})

			if err != nil {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to generate temp jwt token", Message: fmt.Errorf("failed to generate temp jwt token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
			}

			html := helpers.MustRenderHTML(components.TwoFACheck(challengeID.String(), csrf))

			return c.Blob(http.StatusOK, "text/html", html)
		}

		if _, err = helpers.GenerateProofUUIDV7(database.IsPKCollision("sessions_pkey"), func(id uuid.UUID) error {
			err = auth.CreateSession(c.Response(), c.Request(), repo, id, user.ID, payload.Remeber == "on")
			return err
		}); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to set session", Message: fmt.Errorf("failed to set session: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		// if err := auth.SetSessionUser(c.Response(), c.Request(), auser, payload.Remeber == "on"); err != nil {
		// 	return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to set session", Message: fmt.Errorf("failed to set session: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		// }

		_ = repo.UpdateUserLastLogin(ctx, user.ID)

		c.Response().Header().Set("HX-Redirect", "/dashboard")
		return c.NoContent(http.StatusOK)
	}
}

func SessionLoginTwoFACheck() echo.HandlerFunc {
	return func(c echo.Context) error {
		challengeID := c.FormValue("token")
		otp := c.FormValue("otp")

		if otp == "" || challengeID == "" {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid data sent", Message: "invalid form data"}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		challengeUUID, err := uuid.Parse(challengeID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		challenge, err := repo.GetPendingAuthChallenge(ctx, challengeUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "challenge not found", Message: fmt.Errorf("challenge not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		secrets, err := repo.GetUser2FASecret(ctx, challenge.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("user not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		key, err := helpers.ParseBase64Key(boot.Environment.TwoFAKey)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "invalid key", Message: fmt.Errorf("invalid key: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		decriptedTwofaSecret, err := helpers.Decrypt(*secrets.TwofaSecret, key)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "invalid key", Message: fmt.Errorf("invalid key: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if !totp.Validate(otp, string(decriptedTwofaSecret)) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "unauthorized: invalid code", Message: "totp validation failed"}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if _, err = helpers.GenerateProofUUIDV7(database.IsPKCollision("sessions_pkey"), func(id uuid.UUID) error {
			err = auth.CreateSession(c.Response(), c.Request(), repo, id, challenge.UserID, challenge.RememberMe)
			return err
		}); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to set session", Message: fmt.Errorf("failed to set session: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		// if err := auth.SetSessionUser(c.Response(), c.Request(), auth.AuthenticatedSessionUser{
		// 	ID:       challenge.UserID.String(),
		// 	Username: secrets.Username,
		// 	Email:    secrets.Email,
		// 	Role:     secrets.Role,
		// }, challenge.RememberMe); err != nil {
		// 	return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to set session", Message: fmt.Errorf("failed to set session: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		// }

		err = repo.UpdateUserLastLogin(ctx, challenge.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not update user last login", Message: fmt.Errorf("could not update user last login: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = repo.DeletePendingAuthChallenge(ctx, challengeUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not delete pending auth challenge", Message: fmt.Errorf("could not delete pending auth challenge: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		c.Response().Header().Set("HX-Redirect", "/dashboard")
		return c.NoContent(http.StatusOK)
	}
}

func TwoFAResetForm() echo.HandlerFunc {
	return func(c echo.Context) error {
		data := models.GetDefaultSite("Reset TOPT", c.Request())

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		challengeID := c.QueryParam("token")

		html := helpers.MustRenderHTML(views.TwoFAReset(data, challengeID))
		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func TwoFAReset() echo.HandlerFunc {
	return func(c echo.Context) error {
		challengeID := c.FormValue("token")
		code := c.FormValue("reset_code")

		if code == "" || challengeID == "" {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid data sent", Message: "invalid form data"}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		challengeUUID, err := uuid.Parse(challengeID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		challenge, err := repo.GetPendingAuthChallenge(ctx, challengeUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "challenge not found", Message: fmt.Errorf("challenge not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		count, err := repo.CountUnusedBackupCodesForUser(ctx, challenge.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if count <= 0 {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusConflict, UserMessage: "No more backup codes available", Message: fmt.Errorf("no more backup codes available: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		h, err := blake2b.New512(nil)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{
				Error: helpers.GenericError{
					Code:        http.StatusConflict,
					UserMessage: "Code has already been used",
					Message:     "code has already been used",
				},
				Box: enums.Boxes.TOAST_TR, Persistance: "5000",
			}, nil)
		}
		h.Write([]byte(code))
		codeHash := hex.EncodeToString(h.Sum(nil))

		backupCode, err := repo.GetBackupCodeByHash(ctx, string(codeHash))
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "incorrect code, try another one", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if backupCode.Used {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusConflict, UserMessage: "Code has already been used", Message: fmt.Errorf("code has already been used: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		user, err := repo.GetUserByID(ctx, challenge.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not get user", Message: fmt.Errorf("could not get user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      models.GetDefaultSite("", c.Request()).AppName,
			AccountName: user.Email,
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not generate code", Message: fmt.Errorf("could not generate code: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		encryptionKey, err := helpers.ParseBase64Key(boot.Environment.TwoFAKey)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "invalid key", Message: fmt.Errorf("invalid key: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		encryptedTwofaSecret, err := helpers.Encrypt([]byte(key.Secret()), encryptionKey)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not encrypt twofa secret", Message: fmt.Errorf("could not encrypt twofa secret: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		_, err = repo.PromoteChallengeToRegistration(ctx, repository.PromoteChallengeToRegistrationParams{
			ID:     challengeUUID,
			Secret: &encryptedTwofaSecret,
		})

		image, err := key.Image(200, 200)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not generate qr code", Message: fmt.Errorf("could not generate qr code: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		var buf bytes.Buffer
		if err := png.Encode(&buf, image); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not generate qr code", Message: fmt.Errorf("could not generate qr code: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		pngBytes := buf.Bytes()
		base64Str := base64.StdEncoding.EncodeToString(pngBytes)
		qr_code := fmt.Sprintf("data:image/png;base64,%s", base64Str)

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.TwoFAQRCodeResetCard(components.TwoFAResetProps{
			QRCodeDataURL: qr_code,
			Secret:        key.Secret(),
			CSRF:          csrf,
			Token:         challengeID,
			BackupCodeID:  backupCode.ID.String(),
		}))

		return c.Blob(http.StatusAccepted, "text/html", html)
	}
}

func TwoFACancelReset() echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set("HX-Redirect", "/auth")
		return c.NoContent(http.StatusOK)
	}
}

func TwoFAVerifyReset() echo.HandlerFunc {
	return func(c echo.Context) error {
		challengeID := c.FormValue("token")
		otp := c.FormValue("otp")
		code := c.FormValue("code")

		if challengeID == "" || otp == "" || code == "" {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid data sent", Message: "invalid form data"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		challengeUUID, err := uuid.Parse(challengeID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		codeUUID, err := uuid.Parse(code)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse temp jwt token", Message: fmt.Errorf("could not parse temp jwt token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		challenge, err := repo.GetPendingAuthChallenge(ctx, challengeUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "challenge not found", Message: fmt.Errorf("challenge not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		key, err := helpers.ParseBase64Key(boot.Environment.TwoFAKey)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "invalid key", Message: fmt.Errorf("invalid key: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		encrypted_totp_secret := challenge.Secret

		totp_secret, err := helpers.Decrypt(*encrypted_totp_secret, key)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not decrypt totp secret", Message: fmt.Errorf("could not decrypt totp secret: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if !totp.Validate(otp, string(totp_secret)) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "unauthorized", Message: "totp validation failed"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.EnableUser2FA(ctx, repository.EnableUser2FAParams{
			TwofaSecret: encrypted_totp_secret,
			ID:          challenge.UserID,
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not enable 2fa", Message: fmt.Errorf("could not enable 2fa: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.MarkBackupCodeUsed(ctx, codeUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not mark backup code used", Message: fmt.Errorf("could not mark backup code used: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.DeletePendingAuthChallenge(ctx, challengeUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not delete pending auth challenge", Message: fmt.Errorf("could not delete pending auth challenge: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		c.Response().Header().Set("HX-Redirect", "/auth")
		return c.NoContent(http.StatusOK)
	}
}

func TwoFARestoreForm() echo.HandlerFunc {
	return func(c echo.Context) error {
		data := models.GetDefaultSite("Restore Account", c.Request())

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		challengeID := c.QueryParam("token")

		challengeUUID, err := uuid.Parse(challengeID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		code, err := helpers.GenerateBase62Token(8)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to generate token", Message: fmt.Errorf("failed to generate token: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		log.Debugf("Generated code: %v", code)

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		challenge, err := repo.GetPendingAuthChallenge(ctx, challengeUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "challenge not found", Message: fmt.Errorf("challenge not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		user, err := repo.GetUserByID(ctx, challenge.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("user not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		var ev *repository.CreateEmailVerificationRow

		_, err = helpers.GenerateProofUUIDV4(database.IsPKCollision("email_verifications_pkey"), func(id uuid.UUID) error {
			var insert_err error
			ev, insert_err = repo.CreateEmailVerification(ctx, repository.CreateEmailVerificationParams{ID: uuid.New(), UserID: user.ID, Token: code, Email: user.Email, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Duration(30 * time.Minute)), Valid: true}})
			return insert_err
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to Create email verification", Message: fmt.Errorf("failed to Create email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		helpers.ResendEmailVerificationTemplate(user.Email, ev.Token)
		html := helpers.MustRenderHTML(views.TwoFARestore(data))
		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func TwoFARestore() echo.HandlerFunc {
	return func(c echo.Context) error {
		resetCode := c.FormValue("reset_code")
		if resetCode == "" {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "reset code is required", Message: "reset code is required"}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		verification, err := repo.GetEmailVerificationByToken(ctx, resetCode)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to get email verification", Message: fmt.Errorf("failed to get email verification: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		if verification.ExpiresAt.Time.Before(time.Now()) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "token expired", Message: fmt.Errorf("token expired: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = repo.VerifyUserEmail(ctx, verification.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to verify email", Message: fmt.Errorf("failed to verify email: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = repo.MarkEmailVerificationUsed(ctx, verification.Token)

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, Message: fmt.Sprintf("failed to mark email verification used: %v", err), UserMessage: "failed to verify email"}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = repo.DeleteUserBackupCodes(ctx, verification.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, Message: fmt.Sprintf("failed to delete user backup codes: %v", err), UserMessage: "failed to verify email"}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		err = repo.DisableUser2FA(ctx, verification.UserID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, Message: fmt.Sprintf("failed to disable user 2FA: %v", err), UserMessage: "failed to verify email"}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		c.Response().Header().Set("HX-Redirect", "/auth")
		return c.NoContent(http.StatusOK)

	}
}

func SessionLogout() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)
		if err := auth.RevokeCurrentSession(c.Response(), c.Request(), repo); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to logout", Message: fmt.Errorf("failed to logout: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}

		// if err := auth.ClearSession(c.Response(), c.Request()); err != nil {
		// 	return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to logout", Message: fmt.Errorf("failed to logout: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		// }
		c.Response().Header().Set("HX-Redirect", "/")
		return c.NoContent(http.StatusOK)
	}
}
