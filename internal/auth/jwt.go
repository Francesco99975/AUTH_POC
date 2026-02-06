package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Francesco99975/authpoc/cmd/boot"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/gommon/log"
)

// Claims for the interim 2FA token
type InterimClaims struct {
	UserID       string `json:"uid"`
	Username     string `json:"un"`
	Email        string `json:"em"`
	Role         string `json:"role"`
	IsActive     bool   `json:"ia"`
	TwoFAEnabled bool   `json:"2fa"`
	Remember     bool   `json:"remember"`
	jwt.RegisteredClaims
}

// GenerateEncryptedToken creates a short-lived encrypted token
func GenerateEncryptedToken(user AuthenticatedSessionUser, duration time.Duration) (string, error) {
	claims := InterimClaims{
		UserID:       user.ID,
		Username:     user.Username,
		Email:        user.Email,
		Role:         user.Role,
		IsActive:     user.IsActive,
		TwoFAEnabled: user.TwoFAEnabled,
		Remember:     user.Remember,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			// Optional: add jti (unique id) if you want to track/revoke
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(boot.Environment.JWTSecret))
	if err != nil {
		return "", err
	}

	encryptKey, err := base64.StdEncoding.DecodeString(boot.Environment.JWTTokenEncryptionKey)
	if err != nil {
		return "", err
	}

	log.Infof("Encrypting token with key: %s", encryptKey)
	log.Infof("Encryption Key len: %d", len(encryptKey))

	if len(encryptKey) != 32 {
		return "", errors.New("invalid encryption key length")
	}

	// Now encrypt the signed JWT string
	ciphertext, err := encryptAESGCM([]byte(signed), encryptKey)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// ValidateAndDecryptToken decrypts → verifies signature & expiration → returns claims
func ValidateAndDecryptToken(tokenStr string) (*AuthenticatedSessionUser, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid token on decode: %v", err)
	}

	encryptKey, err := base64.StdEncoding.DecodeString(boot.Environment.JWTTokenEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key on decode: %v", err)
	}

	if len(encryptKey) != 32 {
		return nil, errors.New("invalid encryption key length")
	}

	plaintext, err := decryptAESGCM(ciphertext, encryptKey)
	if err != nil {
		return nil, fmt.Errorf("invalid token on decrypt: %v", err)
	}

	token, err := jwt.ParseWithClaims(string(plaintext), &InterimClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(boot.Environment.JWTSecret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token on parse: %v", err)
	}

	if claims, ok := token.Claims.(*InterimClaims); ok && token.Valid {
		return &AuthenticatedSessionUser{ID: claims.UserID, Username: claims.Username, Email: claims.Email, Role: claims.Role, IsActive: claims.IsActive, TwoFAEnabled: claims.TwoFAEnabled, Remember: claims.Remember}, nil
	}

	return nil, errors.New("invalid token")
}

// AES-256-GCM helpers (nonce-prepended format: nonce || ciphertext || tag)

func encryptAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) < 12 { // minimal nonce size
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ct, nil)
}
