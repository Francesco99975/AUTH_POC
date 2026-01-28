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

// Helper functions
func SetSessionUser(w http.ResponseWriter, r *http.Request, userID string, role string, remember bool) error {
	session, err := SessionStore.Get(r, "session")
	if err != nil {
		return err
	}
	session.Values["user_id"] = userID
	session.Values["role"] = role
	session.Values["authenticated"] = true
	session.Options = getSessionOptions(remember)
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

func ClearSession(w http.ResponseWriter, r *http.Request) error {
	session, err := SessionStore.Get(r, "session")
	if err != nil {
		return err
	}
	session.Options.MaxAge = -1 // Delete cookie
	return session.Save(r, w)
}

func GetSessionUserID(r *http.Request) (string, string, bool) {
	session, _ := SessionStore.Get(r, "session")
	userID, ok := session.Values["user_id"].(string)
	role, ok_role := session.Values["role"].(string)
	authenticated := session.Values["authenticated"] == true
	return userID, role, ok && ok_role && authenticated
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
