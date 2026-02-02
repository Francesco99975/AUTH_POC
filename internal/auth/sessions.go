package auth

import (
	"encoding/base64"
	"log"
	"net/http"

	"github.com/Francesco99975/authpoc/cmd/boot"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/gorilla/sessions"
)

var SessionStore *sessions.CookieStore

func InitSessionStore() {
	log.Print("Initializing SessionStore...")
	authKey, err := base64.StdEncoding.DecodeString(boot.Environment.SessionAuthKey)
	if err != nil {
		log.Fatal("Invalid SESSION_AUTH_KEY:", err)
	}

	encKey, err := base64.StdEncoding.DecodeString(boot.Environment.SessionEncryptionKey)
	if err != nil {
		log.Fatal("Invalid SESSION_ENCRYPTION_KEY:", err)
	}

	// Validate AES key length
	switch len(encKey) {
	case 16, 24, 32:
		// ok
	default:
		log.Fatalf("SESSION_ENCRYPTION_KEY decoded length must be 16, 24, or 32 bytes, got %d", len(encKey))
	}

	SessionStore = sessions.NewCookieStore(authKey, encKey)
}
func getSessionOptions(remember bool) *sessions.Options {
	sameSite := http.SameSiteDefaultMode
	maxAge := 86400 * 7 // One Week
	if remember {
		maxAge = maxAge * 52 // One Year
	}

	if boot.Environment.GoEnv == enums.Environments.DEVELOPMENT {
		sameSite = http.SameSiteDefaultMode

		if remember {
			maxAge = 0 // Infinite
		} else {
			maxAge = 86400 / 24 / 60 * 5 // 5 minutes
		}

	}

	return &sessions.Options{
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   boot.Environment.GoEnv != enums.Environments.DEVELOPMENT,
		Domain:   boot.Environment.Host,
		SameSite: sameSite,
	}

}

type AuthenticatedSessionUser struct {
	ID           string
	Username     string
	Email        string
	Role         string
	IsActive     bool
	TwoFAEnabled bool
	Remember     bool
}

func SetSessionUser(w http.ResponseWriter, r *http.Request, user AuthenticatedSessionUser, remember bool) error {
	session, err := SessionStore.Get(r, "session")
	if err != nil {
		return err
	}
	session.Values["user_id"] = user.ID
	session.Values["username"] = user.Username
	session.Values["email"] = user.Email
	session.Values["role"] = user.Role
	session.Values["is_active"] = user.IsActive
	session.Values["twofa_enabled"] = user.TwoFAEnabled
	session.Values["authenticated"] = true
	session.Options = getSessionOptions(remember)
	return session.Save(r, w)
}

func GetSessionUser(r *http.Request) (AuthenticatedSessionUser, bool) {
	session, _ := SessionStore.Get(r, "session")
	userID, ok_id := session.Values["user_id"].(string)
	if !ok_id {
		log.Printf("No user_id in session: %v", session.Values)
	}
	username, ok_username := session.Values["username"].(string)
	if !ok_username {
		log.Printf("No username in session: %v", session.Values)
	}
	email, ok_email := session.Values["email"].(string)
	if !ok_email {
		log.Printf("No email in session: %v", session.Values)
	}
	role, ok_role := session.Values["role"].(string)
	if !ok_role {
		log.Printf("No role in session: %v", session.Values)
	}
	is_active, ok_active := session.Values["is_active"].(bool)
	if !ok_active {
		log.Printf("No is_active in session: %v", session.Values)
	}
	twofa_enabled, ok_twofa_enabled := session.Values["twofa_enabled"].(bool)
	if !ok_twofa_enabled {
		log.Printf("No twofa_enabled in session: %v", session.Values)
	}
	authenticated := session.Values["authenticated"] == true

	user := AuthenticatedSessionUser{
		ID:           userID,
		Username:     username,
		Email:        email,
		Role:         role,
		IsActive:     is_active,
		TwoFAEnabled: twofa_enabled,
		Remember:     session.Options.MaxAge == 0,
	}

	return user, ok_id && ok_username && ok_email && ok_role && ok_active && ok_twofa_enabled && authenticated
}

func ClearSession(w http.ResponseWriter, r *http.Request) error {
	session, err := SessionStore.Get(r, "session")
	if err != nil {
		return err
	}
	session.Options.MaxAge = -1 // Delete cookie
	return session.Save(r, w)
}

func SetSessionUserTempTOTP(w http.ResponseWriter, r *http.Request, key string) error {
	session, err := SessionStore.Get(r, "session")
	if err != nil {
		return err
	}
	session.Values["totp"] = key
	return session.Save(r, w)
}

func GetSessionUserTempTOTP(r *http.Request) (string, bool) {
	session, _ := SessionStore.Get(r, "session")
	key, ok := session.Values["totp"].(string)
	return key, ok
}

func ClearSessionUserTempTOTP(w http.ResponseWriter, r *http.Request) error {
	session, err := SessionStore.Get(r, "session")
	if err != nil {
		return err
	}
	delete(session.Values, "totp")
	return session.Save(r, w)
}
