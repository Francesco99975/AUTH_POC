package controllers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/http"
	"slices"
	"strings"

	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/views/components"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
)

func CancelTwoFA() echo.HandlerFunc {
	return func(c echo.Context) error {
		_ = auth.ClearSessionUserTempTOTP(c.Response(), c.Request())

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
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
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("user not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		csrf := c.Get("csrf").(string)
		html := helpers.MustRenderHTML(components.TwoFactorCard(user.TwofaEnabled, csrf))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func InitTwoFA() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
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
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("user not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      models.GetDefaultSite("").AppName,
			AccountName: user.Username,
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not generate code", Message: fmt.Errorf("could not generate code: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		auth.SetSessionUserTempTOTP(c.Response(), c.Request(), key.Secret())

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

		html := helpers.MustRenderHTML(components.TwoFAQRCodeCard(components.TwoFASetupProps{
			QRCodeDataURL: qr_code,
			Secret:        key.Secret(),
			CSRF:          csrf,
		}))

		return c.Blob(http.StatusAccepted, "text/html", html)

	}
}

func VerifyTwoFA() echo.HandlerFunc {
	return func(c echo.Context) error {
		otp := c.FormValue("otp")

		if otp == "" {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid data sent", Message: "invalid form data"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		userID, _, authenticated := auth.GetSessionUserID(c.Request())
		if !authenticated {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		totp_secret, ok := auth.GetSessionUserTempTOTP(c.Request())
		if !ok {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not verify", Message: "secret not found"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if !totp.Validate(otp, totp_secret) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "unauthorized", Message: "totp validation failed"}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.EnableUser2FA(ctx, repository.EnableUser2FAParams{
			TwofaSecret: &totp_secret,
			ID:          userUUID,
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not enable 2fa", Message: fmt.Errorf("could not enable 2fa: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		recovery_backup_codes, err := helpers.GenerateBackupCodes(10)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not generate backup codes", Message: fmt.Errorf("could not generate backup codes: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.CreateBackupCodes(ctx, repository.CreateBackupCodesParams{
			Column1: recovery_backup_codes.IDs,
			Column2: slices.Repeat([]uuid.UUID{userUUID}, len(recovery_backup_codes.IDs)),
			Column3: recovery_backup_codes.Hashed,
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not store backup codes", Message: fmt.Errorf("could not store backup codes: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.TwoFARecoverySecretCard(strings.Join(recovery_backup_codes.Plain, ","), csrf))

		return c.Blob(http.StatusAccepted, "text/html", html)
	}
}

func FinalizeTwoFA() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
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
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "user not found", Message: fmt.Errorf("user not found: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		csrf := c.Get("csrf").(string)
		html := helpers.MustRenderHTML(components.TwoFactorCard(user.TwofaEnabled, csrf))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}
