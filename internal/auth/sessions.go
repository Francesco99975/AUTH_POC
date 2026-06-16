package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/Francesco99975/authpoc/cmd/boot"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/blake2b"
)

type AuthenticatedSessionUser struct {
	ID           string
	Username     string
	Email        string
	Role         string
	IsActive     bool
	TwoFAEnabled bool
	Remember     bool
}

// Server Side DB Stored SESSIONS

const sessionCookieName = "sid"

func generateSessionToken() (token string, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	token = base64.URLEncoding.EncodeToString(b)

	h, err := blake2b.New512(nil)
	if err != nil {
		return
	}
	h.Write([]byte(token))
	hash = hex.EncodeToString(h.Sum(nil))
	return
}

func sessionMaxAge(remember bool) int {
	if boot.Environment.GoEnv == enums.Environments.DEVELOPMENT {
		if remember {
			return 0 // session-only in dev
		}
		return 5 * 60 // 5 min
	}
	if remember {
		return 86400 * 7 * 52 // 1 year
	}
	return 86400 * 7 // 1 week
}

func CreateSession(w http.ResponseWriter, r *http.Request, repo *repository.Queries, id uuid.UUID, userID uuid.UUID, remember bool) error {
	token, hash, err := generateSessionToken()
	if err != nil {
		return err
	}

	maxAge := sessionMaxAge(remember)

	var expiresAt time.Time
	if maxAge == 0 {
		expiresAt = time.Now().Add(24 * time.Hour)
	} else {
		expiresAt = time.Now().Add(time.Duration(maxAge) * time.Second)
	}

	userAgent := r.UserAgent()

	_, err = repo.CreateUserSession(r.Context(), repository.CreateUserSessionParams{
		ID:               id,
		UserID:           userID,
		SessionTokenHash: hash,
		IpAddress:        &r.RemoteAddr,
		UserAgent:        &userAgent,
		RememberMe:       remember,
		ExpiresAt: pgtype.Timestamptz{
			Time:  expiresAt,
			Valid: true,
		},
	})
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token, // raw token, never the hash
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   boot.Environment.GoEnv != enums.Environments.DEVELOPMENT,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func GetActiveSession(r *http.Request, repo *repository.Queries) (*AuthenticatedSessionUser, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}

	sum, err := blake2b.New512(nil)
	if err != nil {
		return nil, err
	}
	sum.Write([]byte(cookie.Value))
	hash := hex.EncodeToString(sum.Sum(nil))

	row, err := repo.GetActiveSession(r.Context(), hash)
	if err != nil {
		return nil, err
	}

	return &AuthenticatedSessionUser{
		ID:           row.UserID.String(),
		Username:     row.Username,
		Email:        row.Email,
		Role:         row.Role,
		IsActive:     row.IsActive,
		TwoFAEnabled: row.TwofaEnabled,
		Remember:     row.RememberMe,
	}, nil
}

func TouchSession(r *http.Request, repo *repository.Queries, sessionID uuid.UUID, lastActivity time.Time) {
	go func() {
		if time.Since(lastActivity) > 5*time.Minute {
			_ = repo.TouchSession(r.Context(), sessionID)
		}
	}()
}

func RevokeSessionByID(r *http.Request, repo *repository.Queries, sessionID uuid.UUID) error {
	return repo.RevokeSession(r.Context(), sessionID)
}

func RevokeCurrentSession(w http.ResponseWriter, r *http.Request, repo *repository.Queries) error {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil // already gone
	}

	h, err := blake2b.New512(nil)
	if err != nil {
		return err
	}
	h.Write([]byte(cookie.Value))
	hash := hex.EncodeToString(h.Sum(nil))

	if err := repo.RevokeSessionByHash(r.Context(), hash); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   boot.Environment.GoEnv != enums.Environments.DEVELOPMENT,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func RevokeAllSessions(w http.ResponseWriter, r *http.Request, repo *repository.Queries, userID uuid.UUID) error {
	if err := repo.RevokeAllUserSessions(r.Context(), userID); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   boot.Environment.GoEnv != enums.Environments.DEVELOPMENT,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func RevokeOtherSessions(r *http.Request, repo *repository.Queries, userID uuid.UUID, currentSessionID uuid.UUID) error {
	return repo.RevokeAllUserSessionsExcept(r.Context(), repository.RevokeAllUserSessionsExceptParams{
		UserID: userID,
		ID:     currentSessionID,
	})
}

// var SessionStore *sessions.CookieStore

// func InitSessionStore() {
// 	log.Print("Initializing SessionStore...")
// 	authKey, err := base64.StdEncoding.DecodeString(boot.Environment.SessionAuthKey)
// 	if err != nil {
// 		log.Fatal("Invalid SESSION_AUTH_KEY:", err)
// 	}

// 	encKey, err := base64.StdEncoding.DecodeString(boot.Environment.SessionEncryptionKey)
// 	if err != nil {
// 		log.Fatal("Invalid SESSION_ENCRYPTION_KEY:", err)
// 	}

// 	// Validate AES key length
// 	switch len(encKey) {
// 	case 16, 24, 32:
// 		// ok
// 	default:
// 		log.Fatalf("SESSION_ENCRYPTION_KEY decoded length must be 16, 24, or 32 bytes, got %d", len(encKey))
// 	}

// 	SessionStore = sessions.NewCookieStore(authKey, encKey)
// }
// func getSessionOptions(remember bool) *sessions.Options {
// 	domain := ""
// 	sameSite := http.SameSiteLaxMode
// 	maxAge := 86400 * 7 // One Week
// 	if remember {
// 		maxAge = maxAge * 52 // One Year
// 	}

// 	if boot.Environment.GoEnv == enums.Environments.DEVELOPMENT {

// 		if remember {
// 			maxAge = 0 //Session Only (Closing browser deletes session)
// 		} else {
// 			maxAge = 86400 / 24 / 60 * 5 // 5 minutes
// 		}

// 	}

// 	return &sessions.Options{
// 		Path:     "/",
// 		MaxAge:   maxAge,
// 		HttpOnly: true,
// 		Secure:   boot.Environment.GoEnv != enums.Environments.DEVELOPMENT,
// 		Domain:   domain,
// 		SameSite: sameSite,
// 	}

// }

// func SetSessionUser(w http.ResponseWriter, r *http.Request, user AuthenticatedSessionUser, remember bool) error {
// 	session, err := SessionStore.Get(r, "session")
// 	if err != nil {
// 		return err
// 	}
// 	session.Values["user_id"] = user.ID
// 	session.Values["username"] = user.Username
// 	session.Values["email"] = user.Email
// 	session.Values["role"] = user.Role
// 	session.Values["is_active"] = user.IsActive
// 	session.Values["twofa_enabled"] = user.TwoFAEnabled
// 	session.Values["authenticated"] = true
// 	session.Options = getSessionOptions(remember)
// 	return session.Save(r, w)
// }

// func GetSessionUser(r *http.Request) (AuthenticatedSessionUser, bool) {
// 	session, _ := SessionStore.Get(r, "session")
// 	userID, ok_id := session.Values["user_id"].(string)
// 	if !ok_id {
// 		log.Printf("No user_id in session: %v", session.Values)
// 	}
// 	username, ok_username := session.Values["username"].(string)
// 	if !ok_username {
// 		log.Printf("No username in session: %v", session.Values)
// 	}
// 	email, ok_email := session.Values["email"].(string)
// 	if !ok_email {
// 		log.Printf("No email in session: %v", session.Values)
// 	}
// 	role, ok_role := session.Values["role"].(string)
// 	if !ok_role {
// 		log.Printf("No role in session: %v", session.Values)
// 	}
// 	is_active, ok_active := session.Values["is_active"].(bool)
// 	if !ok_active {
// 		log.Printf("No is_active in session: %v", session.Values)
// 	}
// 	twofa_enabled, ok_twofa_enabled := session.Values["twofa_enabled"].(bool)
// 	if !ok_twofa_enabled {
// 		log.Printf("No twofa_enabled in session: %v", session.Values)
// 	}
// 	authenticated := session.Values["authenticated"] == true

// 	user := AuthenticatedSessionUser{
// 		ID:           userID,
// 		Username:     username,
// 		Email:        email,
// 		Role:         role,
// 		IsActive:     is_active,
// 		TwoFAEnabled: twofa_enabled,
// 		Remember:     session.Options.MaxAge == 0,
// 	}

// 	return user, ok_id && ok_username && ok_email && ok_role && ok_active && ok_twofa_enabled && authenticated
// }

// func ClearSession(w http.ResponseWriter, r *http.Request) error {
// 	session, err := SessionStore.Get(r, "session")
// 	if err != nil {
// 		return err
// 	}
// 	session.Options.MaxAge = -1 // Delete cookie
// 	session.Options.Path = "/"
// 	return session.Save(r, w)
// }
