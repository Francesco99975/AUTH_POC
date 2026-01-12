package models

import (
	"errors"
	"strings"

	"github.com/Francesco99975/authpoc/cmd/boot"
	"github.com/Francesco99975/authpoc/internal/enums"
)

type SignupRequest struct {
	Email    string `form:"email"`
	Username string `form:"username"`
	Password string `form:"password"`
	Confirm  string `form:"confirm"`
}

func (r SignupRequest) ValidateAndNormalize(passwordSecurityLevel int) error {
	r.Email = strings.ToLower(strings.ReplaceAll(r.Email, " ", ""))
	r.Username = strings.ReplaceAll(r.Username, " ", "")
	r.Password = strings.ReplaceAll(r.Password, " ", "")
	r.Confirm = strings.ReplaceAll(r.Confirm, " ", "")

	if r.Email == "" {
		return errors.New("email is required")
	}
	if r.Username == "" {
		return errors.New("username is required")
	}
	if r.Password == "" {
		return errors.New("password is required")
	}

	if r.Password != r.Confirm {
		return errors.New("passwords do not match")
	}

	if len(r.Username) < 3 || len(r.Username) > 21 {
		return errors.New("username must be at least 3 characters and no more than 21 characters")
	}

	if boot.Environment.GoEnv == enums.Environments.PRODUCTION {
		if !strings.Contains(r.Email, "@") {
			return errors.New("invalid email")
		}

		switch passwordSecurityLevel {
		case 0:
			if len(r.Password) < 8 {
				return errors.New("password must be at least 8 characters")
			}
		case 1:
			if len(r.Password) < 8 {
				return errors.New("password must be at least 12 characters")
			}

			if !strings.ContainsAny(r.Password, "0123456789") {
				return errors.New("password must contain at least one number")
			}
		case 2:
			if len(r.Password) < 12 {
				return errors.New("password must be at least 16 characters")
			}

			if !strings.ContainsAny(r.Password, "0123456789") {
				return errors.New("password must contain at least one number")
			}

			if !strings.ContainsAny(r.Password, "!@#$%") {
				return errors.New("password must contain at least one special character: !@#$%")
			}
		}
	}
	return nil

}

type LoginRequest struct {
	EmailOrUsername string `form:"eou"`
	Password        string `form:"password"`
	Remeber         string `form:"remember"`
}

func (r LoginRequest) Validate() error {
	if r.EmailOrUsername == "" {
		return errors.New("email or username is required")
	}
	if r.Password == "" {
		return errors.New("password is required")
	}
	return nil
}

type VerifyEmailRequest struct {
	Token string `form:"token"`
}

func (r VerifyEmailRequest) Validate() error {
	if r.Token == "" {
		return errors.New("token is required")
	}
	return nil
}
