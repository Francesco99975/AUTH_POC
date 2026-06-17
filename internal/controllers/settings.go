package controllers

import (
	"fmt"
	"net/http"
	"strconv"

	"strings"
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
	"github.com/Francesco99975/authpoc/views/layouts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/pquerna/otp/totp"
)

func Settings(tab string) echo.HandlerFunc {
	return func(c echo.Context) error {

		if tab == "" {
			return c.Redirect(http.StatusSeeOther, "/settings/profile")
		}

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

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
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
			ActiveTab: tab,
		}

		switch tab {
		case "profile":
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

			html := helpers.MustRenderHTML(views.SettingsProfile(data, tabProps, profileProps))

			return c.Blob(http.StatusOK, "text/html", html)
		case "security":

			sessions, err := repo.GetActiveSessionsByUser(ctx, userUUID)
			if err != nil {
				return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
			}

			log.Debugf("sessions: %v", sessions)

			sessionsInfo := helpers.MapSlice(sessions, func(session *repository.Session) components.SessionInfo {
				return components.SessionInfo{
					Device:    helpers.GetUaDeviceType(*session.UserAgent),
					Browser:   helpers.GetUaBrowser(*session.UserAgent),
					OS:        helpers.GetUaOS(*session.UserAgent),
					LastUsed:  session.LastActivityAt.Time.Format(time.RFC850),
					Expires:   session.ExpiresAt.Time.Format(time.RFC850),
					IsCurrent: session.ID == auser.SessionID,
					SessionID: session.ID.String(),
				}
			})

			log.Debugf("sessionsInfo: %v", sessionsInfo)

			securityProps := components.SecurityProps{
				TwoFAEnabled: user.TwofaEnabled,
				Sessions:     sessionsInfo,
				CSRF:         c.Get("csrf").(string),
			}

			html := helpers.MustRenderHTML(views.SettingsSecurity(data, tabProps, securityProps))

			return c.Blob(http.StatusOK, "text/html", html)
		case "account":
			accountProps := components.AccountProps{
				IsActive:     user.IsActive,
				TwoFAEnabled: user.TwofaEnabled,
				UserEmail:    user.Email,
				CSRF:         c.Get("csrf").(string),
			}

			html := helpers.MustRenderHTML(views.SettingsAccount(data, tabProps, accountProps))

			return c.Blob(http.StatusOK, "text/html", html)
		case "users":
			totalUsers, err := repo.GetUsersCount(ctx)
			if err != nil {
				return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
			}

			rawUsers, err := repo.SearchUsers(ctx, repository.SearchUsersParams{
				Column1: "",
				Column2: "",
				Limit:   int32(boot.Environment.PaginationWindow),
				Column4: 1,
			})
			if err != nil {
				return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
			}

			filteredUsers := helpers.FilteredSlice(rawUsers, func(user *repository.SearchUsersRow) bool {
				return auser.ID != user.ID.String() &&
					(auser.Role == enums.Roles.DEVELOPER.String() ||
						user.Role != enums.Roles.DEVELOPER.String())
			})

			totalUsers = totalUsers - int64(len(rawUsers)-len(filteredUsers))

			users := helpers.MapSlice(filteredUsers, func(user *repository.SearchUsersRow) components.UserInfo {

				status := "Active"
				if !user.IsActive {
					status = "Inactive"
				}
				return components.UserInfo{
					ID:        user.ID.String(),
					Username:  user.Username,
					Email:     user.Email,
					Verified:  user.IsEmailVerified,
					Initials:  strings.Split(user.Username, "")[0],
					Role:      user.Role,
					Status:    status,
					TwoFA:     user.TwofaEnabled,
					LastLogin: user.LastLogin.Time.Format(time.RFC3339),
					Gradient:  "primary",
					CanEdit:   auth.CanManageUser(enums.Role(auser.Role), enums.ActEdit, enums.Role(user.Role)),
					CanDelete: auth.CanManageUser(enums.Role(auser.Role), enums.ActDelete, enums.Role(user.Role)),
				}
			})

			usersProps := components.UsersProps{
				Users:      users,
				TotalUsers: int(totalUsers),
				Viewer:     enums.Role(auser.Role),
				Page:       1,
				PerPage:    boot.Environment.PaginationWindow,
				CSRF:       c.Get("csrf").(string),
			}

			html := helpers.MustRenderHTML(views.SettingsUsers(data, tabProps, usersProps))

			return c.Blob(http.StatusOK, "text/html", html)

		default:
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

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

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
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

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(auser.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		_, err = repo.UpdateUserUsername(ctx, repository.UpdateUserUsernameParams{Username: username, ID: userUUID})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not update username or email", Message: fmt.Errorf("could not update username or email: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		tools.SetToastTrigger(c.Response(), enums.SuccessToast, "Successfully updated username")
		return c.NoContent(http.StatusAccepted)
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
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		exists, err := repo.ExistsUserWithEmail(ctx, payload.Email)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could not change email", Message: fmt.Errorf("unable to check if email exists: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if exists {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusConflict, UserMessage: "Another user already has this email", Message: fmt.Errorf("email already exists: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		user, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if user == nil {
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

		tools.SetToastTrigger(c.Response(), enums.WarningToast, "Email needs to be verified")
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

		tools.SetToastTrigger(c.Response(), enums.SuccessToast, "Email updated successfully")
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

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
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

		sessions, err := repo.GetActiveSessionsByUser(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		log.Debugf("sessions: %v", sessions)

		sessionsInfo := helpers.MapSlice(sessions, func(session *repository.Session) components.SessionInfo {
			device := helpers.GetUaDeviceType(*session.UserAgent)

			return components.SessionInfo{
				Device:    device,
				LastUsed:  session.LastActivityAt.Time.Format(time.RFC850),
				IsCurrent: session.ID == auser.SessionID,
				SessionID: session.ID.String(),
			}
		})

		log.Debugf("sessionsInfo: %v", sessionsInfo)

		props := components.SecurityProps{
			TwoFAEnabled: user.TwofaEnabled,
			Sessions:     sessionsInfo,
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

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
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

		tools.SetToastTrigger(c.Response(), enums.SuccessToast, "Successfully updated user password")
		return c.NoContent(http.StatusAccepted)

	}
}

func RevokeSession() echo.HandlerFunc {
	return func(c echo.Context) error {
		sessionID := c.Param("id")

		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to get transaction: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		sessionUUID, err := uuid.Parse(sessionID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to parse session ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.RevokeSession(ctx, sessionUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "database error occurred", Message: fmt.Errorf("unable to revoke session: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		return c.NoContent(http.StatusOK)
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

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
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

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
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

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
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

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
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

			encryptionKey, err := helpers.ParseBase64Key(boot.Environment.TwoFAKey)
			if err != nil {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not parse twofa key", Message: fmt.Errorf("could not parse twofa key: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
			}

			totp_secret, err := helpers.Decrypt(*secrets.TwofaSecret, encryptionKey)
			if err != nil {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not decrypt twofa secret", Message: fmt.Errorf("could not decrypt twofa secret: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
			}

			if !totp.Validate(otp, string(totp_secret)) {
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

		if err := auth.RevokeCurrentSession(c.Response(), c.Request(), repo); err != nil {
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

func Users() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		totalUsers, err := repo.GetUsersCount(ctx)
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		rawUsers, err := repo.GetUsers(ctx, repository.GetUsersParams{
			Limit:  int32(boot.Environment.PaginationWindow),
			Offset: 0,
		})
		if err != nil {
			return helpers.SendReturnedGenericHTMLError(c, helpers.GenericError{Code: http.StatusInternalServerError, Message: err.Error(), UserMessage: "Resource is not accessible"}, nil)
		}

		filteredUsers := helpers.FilteredSlice(rawUsers, func(user *repository.GetUsersRow) bool {
			return auser.ID != user.ID.String() &&
				(auser.Role == enums.Roles.DEVELOPER.String() ||
					user.Role != enums.Roles.DEVELOPER.String())
		})

		totalUsers = totalUsers - int64(len(rawUsers)-len(filteredUsers))

		users := helpers.MapSlice(filteredUsers, func(user *repository.GetUsersRow) components.UserInfo {

			status := "Active"
			if !user.IsActive {
				status = "Inactive"
			}
			return components.UserInfo{
				ID:        user.ID.String(),
				Username:  user.Username,
				Email:     user.Email,
				Verified:  user.IsEmailVerified,
				Initials:  strings.Split(user.Username, "")[0],
				Role:      user.Role,
				Status:    status,
				TwoFA:     user.TwofaEnabled,
				LastLogin: user.LastLogin.Time.Format(time.RFC3339),
				Gradient:  "primary",
				CanEdit:   auth.CanManageUser(enums.Role(auser.Role), enums.ActEdit, enums.Role(user.Role)),
				CanDelete: auth.CanManageUser(enums.Role(auser.Role), enums.ActDelete, enums.Role(user.Role)),
			}
		})

		props := components.UsersProps{
			Users:      users,
			TotalUsers: int(totalUsers),
			Viewer:     enums.Role(auser.Role),
			Page:       1,
			PerPage:    boot.Environment.PaginationWindow,
			CSRF:       c.Get("csrf").(string),
		}

		html := helpers.MustRenderHTML(components.SettingsUsersTab(props))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func GetUser() echo.HandlerFunc {
	return func(c echo.Context) error {
		id := c.Param("id")
		userID, err := uuid.Parse(id)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Invalid ID", Message: fmt.Errorf("invalid ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		user, err := repo.GetUserByID(ctx, userID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "User not found", Message: fmt.Errorf("unable to get user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		status := "Active"
		if !user.IsActive {
			status = "Inactive"
		}
		userInfo := components.UserInfo{
			ID:        user.ID.String(),
			Username:  user.Username,
			Email:     user.Email,
			Verified:  user.IsEmailVerified,
			Initials:  strings.Split(user.Username, "")[0],
			Role:      user.Role,
			Status:    status,
			TwoFA:     user.TwofaEnabled,
			LastLogin: user.LastLogin.Time.Format(time.RFC3339),
			Gradient:  "primary",
			CanEdit:   auth.CanManageUser(enums.Role(auser.Role), enums.ActEdit, enums.Role(user.Role)),
			CanDelete: auth.CanManageUser(enums.Role(auser.Role), enums.ActDelete, enums.Role(user.Role)),
		}

		data := models.GetDefaultSite(fmt.Sprintf("User: %s", user.Username), c.Request())

		data.Nonce = c.Get("nonce").(string)
		data.CSRF = c.Get("csrf").(string)

		html := helpers.MustRenderHTML(views.UserDetails(data, userInfo))

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func CreateUser() echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload models.CreateNewUser

		if err := c.Bind(&payload); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid data sent", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err := payload.Validate(0)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid data sent", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		if auser.Role == enums.Roles.USER.String() {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		if auser.Role == enums.Roles.ADMIN.String() && payload.Role == enums.Roles.DEVELOPER.String() {
			tools.SetToastTrigger(c.Response(), enums.WarningToast, "You are not allowed to create a DEVELOPER user")
			return c.NoContent(http.StatusBadRequest)
		}

		hashedPassword, err := helpers.HashPassword(payload.Password)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could not create User", Message: fmt.Errorf("unable to hash password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		var createdUser *repository.CreateUserRow

		_, err = helpers.GenerateProofUUIDV7(database.IsPKCollision("users_pkey"), func(id uuid.UUID) error {
			var insert_err error
			createdUser, insert_err = repo.CreateUser(ctx, repository.CreateUserParams{
				ID:           id,
				Username:     payload.Username,
				Email:        payload.Email,
				Role:         payload.Role,
				PasswordHash: hashedPassword,
			})
			return insert_err
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could not create User", Message: fmt.Errorf("unable to generate UUID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		var userStatus string = "Inactive"
		if createdUser.IsActive {
			userStatus = "Active"
		}

		userInfo := components.UserInfo{
			ID:        createdUser.ID.String(),
			Username:  createdUser.Username,
			Email:     createdUser.Email,
			Verified:  createdUser.IsEmailVerified,
			Initials:  strings.Split(createdUser.Username, "")[0],
			Role:      createdUser.Role,
			Status:    userStatus,
			TwoFA:     createdUser.TwofaEnabled,
			Gradient:  "primary",
			CanEdit:   auth.CanManageUser(enums.Role(auser.Role), enums.ActEdit, enums.Role(payload.Role)),
			CanDelete: auth.CanManageUser(enums.Role(auser.Role), enums.ActDelete, enums.Role(payload.Role)),
		}

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.SettingsUserItem(userInfo, csrf))

		tools.SetToastTrigger(c.Response(), enums.SuccessToast, "User created successfully")

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func UpdateUser() echo.HandlerFunc {
	return func(c echo.Context) error {
		id := c.Param("id")

		userUUID, err := uuid.Parse(id)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid data sent", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		var payload models.UpdateUserRequest

		if err := c.Bind(&payload); err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid data sent", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = payload.Validate(0)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusBadRequest, UserMessage: "invalid data sent", Message: fmt.Errorf("invalid form data: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		if auser.Role == enums.Roles.USER.String() {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		if auser.Role == enums.Roles.ADMIN.String() && payload.Role == enums.Roles.DEVELOPER.String() {
			tools.SetToastTrigger(c.Response(), enums.WarningToast, "You are not allowed to update a DEVELOPER user")
			return c.NoContent(http.StatusBadRequest)
		}

		isActive := payload.Active == "on"

		var updatedUser *repository.UpdateUserRow
		if payload.Password != "" {
			hashedPassword, err := helpers.HashPassword(payload.Password)
			if err != nil {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could not create User", Message: fmt.Errorf("unable to hash password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
			}

			updatedUser, err = repo.UpdateUser(ctx, repository.UpdateUserParams{
				ID:       userUUID,
				Username: payload.Username,
				Role:     payload.Role,
				Email:    payload.Email,
				IsActive: isActive,
				Column6:  hashedPassword,
			})
			if err != nil {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could not create User", Message: fmt.Errorf("unable to create user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
			}

		} else {
			updatedUser, err = repo.UpdateUser(ctx, repository.UpdateUserParams{
				ID:       userUUID,
				Username: payload.Username,
				Role:     payload.Role,
				Email:    payload.Email,
				IsActive: isActive,
			})
			if err != nil {
				return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could not update User", Message: fmt.Errorf("unable to update user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
			}
		}

		var userStatus string = "Inactive"
		if updatedUser.IsActive {
			userStatus = "Active"
		}

		userInfo := components.UserInfo{
			ID:        updatedUser.ID.String(),
			Username:  updatedUser.Username,
			Email:     updatedUser.Email,
			Verified:  updatedUser.IsEmailVerified,
			Initials:  strings.Split(updatedUser.Username, "")[0],
			Role:      updatedUser.Role,
			Status:    userStatus,
			TwoFA:     updatedUser.TwofaEnabled,
			Gradient:  "primary",
			CanEdit:   auth.CanManageUser(enums.Role(auser.Role), enums.ActEdit, enums.Role(payload.Role)),
			CanDelete: auth.CanManageUser(enums.Role(auser.Role), enums.ActDelete, enums.Role(payload.Role)),
		}

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.SettingsUserItem(userInfo, csrf))

		tools.SetToastTrigger(c.Response(), enums.SuccessToast, "User updated successfully")

		return c.Blob(http.StatusOK, "text/html", html)

	}
}

func ReactivateUserAsAdmin() echo.HandlerFunc {
	return func(c echo.Context) error {
		userID := c.Param("id")

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.ReactivateUser(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not reactivate user", Message: fmt.Errorf("could not reactivate user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		user, err := repo.GetUserByID(ctx, userUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "could not reactivate user", Message: fmt.Errorf("could not reactivate user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		tools.SetToastTrigger(c.Response(), enums.SuccessToast, "User reactivated successfully")

		userInfo := components.UserInfo{
			ID:        user.ID.String(),
			Username:  user.Username,
			Email:     user.Email,
			Verified:  user.IsEmailVerified,
			Initials:  strings.Split(user.Username, "")[0],
			Role:      user.Role,
			Status:    "Active",
			TwoFA:     user.TwofaEnabled,
			Gradient:  "primary",
			CanEdit:   auth.CanManageUser(enums.Role(auser.Role), enums.ActEdit, enums.Role(user.Role)),
			CanDelete: auth.CanManageUser(enums.Role(auser.Role), enums.ActDelete, enums.Role(user.Role)),
			LastLogin: user.LastLogin.Time.Format(time.RFC822Z),
		}

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.SettingsUserItem(userInfo, csrf))

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func SearchUsers() echo.HandlerFunc {
	return func(c echo.Context) error {
		search := c.QueryParam("search")
		role := c.QueryParam("role_filter")
		pageStr := c.QueryParam("page")
		var page int

		page, err := strconv.Atoi(pageStr)
		if err != nil {
			page = 1
		}

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		rawUsers, err := repo.SearchUsers(ctx, repository.SearchUsersParams{
			Column1: search,
			Column2: role,
			Limit:   int32(boot.Environment.PaginationWindow),
			Column4: page,
		})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "search error", Message: fmt.Errorf("unable to get users: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		filteredUsers := helpers.FilteredSlice(rawUsers, func(user *repository.SearchUsersRow) bool {
			return auser.ID != user.ID.String() &&
				(auser.Role == enums.Roles.DEVELOPER.String() ||
					user.Role != enums.Roles.DEVELOPER.String())
		})

		totalUsers, err := repo.GetUserCountBySearch(ctx, repository.GetUserCountBySearchParams{
			Column1: search,
			Column2: role,
		})

		totalUsers = totalUsers - int64(len(rawUsers)-len(filteredUsers))

		users := helpers.MapSlice(filteredUsers, func(user *repository.SearchUsersRow) components.UserInfo {

			status := "Active"
			if !user.IsActive {
				status = "Inactive"
			}
			return components.UserInfo{
				ID:        user.ID.String(),
				Username:  user.Username,
				Email:     user.Email,
				Verified:  user.IsEmailVerified,
				Initials:  strings.Split(user.Username, "")[0],
				Role:      user.Role,
				Status:    status,
				TwoFA:     user.TwofaEnabled,
				LastLogin: user.LastLogin.Time.Format(time.RFC3339),
				Gradient:  "primary",
				CanEdit:   auth.CanManageUser(enums.Role(auser.Role), enums.ActEdit, enums.Role(user.Role)),
				CanDelete: auth.CanManageUser(enums.Role(auser.Role), enums.ActDelete, enums.Role(user.Role)),
			}
		})

		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "No users found", Message: fmt.Errorf("unable to get users: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		csrf := c.Get("csrf").(string)

		html := helpers.MustRenderHTML(components.UserList(users, csrf))
		html = append(html, helpers.MustRenderHTML(components.UsersPagination(int(totalUsers), page, boot.Environment.PaginationWindow, true))...)

		return c.Blob(http.StatusOK, "text/html", html)
	}
}

func DeleteUser() echo.HandlerFunc {
	return func(c echo.Context) error {
		password := c.FormValue("password")

		ctx := c.Request().Context()

		tx, err := database.Pool().BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		defer database.HandleTransaction(ctx, tx, &err)
		repo := repository.New(tx)

		auser, err := auth.GetActiveSession(c.Request(), repo)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "failed to open database on signup", Message: fmt.Errorf("failed to open database on signup: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "5000"}, nil)
		}
		if auser == nil {
			return c.Redirect(http.StatusSeeOther, "/auth")
		}

		auserUUID, err := uuid.Parse(auser.ID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "could not parse ID", Message: fmt.Errorf("could not parse ID: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		hash, err := repo.GetPasswordHash(ctx, auserUUID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusNotFound, UserMessage: "admin not found", Message: fmt.Errorf("unable to find auser password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		if !helpers.CheckPasswordHash(password, hash) {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusUnauthorized, UserMessage: "invalid password", Message: fmt.Errorf("invalid auser password: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		id := c.Param("id")
		userID, err := uuid.Parse(id)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could not delete user", Message: fmt.Errorf("could not parse ID to delete user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		err = repo.DeleteUser(ctx, userID)
		if err != nil {
			return helpers.SendReturnedHTMLErrorMessage(c, helpers.ErrorMessage{Error: helpers.GenericError{Code: http.StatusInternalServerError, UserMessage: "Could not delete user", Message: fmt.Errorf("could not delete user: %v", err).Error()}, Box: enums.Boxes.TOAST_TR, Persistance: "3000"}, nil)
		}

		tools.SetToastTrigger(c.Response(), enums.SuccessToast, "Successfully deleted user")
		return c.NoContent(http.StatusCreated)
	}
}
