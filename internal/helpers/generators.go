package helpers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func GenerateUniqueID() uint {
	u := uuid.New()
	hash := sha256.Sum256(u[:])
	return uint(binary.BigEndian.Uint64(hash[:8]))
}

const charset = "abcdefghkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ123456789%$#@"

func GenerateBase62Token(length int) (string, error) {
	token := make([]byte, length)
	max := big.NewInt(int64(len(charset)))

	for i := range length {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		token[i] = charset[n.Int64()]
	}

	return string(token), nil
}

type BackupCodes struct {
	IDs    []uuid.UUID
	Plain  []string
	Hashed []string
}

// GenerateBackupCodes creates 8–10 secure backup codes
func GenerateBackupCodes(count int) (*BackupCodes, error) {
	if count < 5 || count > 12 {
		return nil, fmt.Errorf("recommended count is 8-10, got %d", count)
	}

	ids := make([]uuid.UUID, count)
	codes_plain := make([]string, count)
	codes_hashes := make([]string, count)

	for i := range count {
		// 10 chars = ~59.8 bits entropy (very strong for one-time use)
		plain, err := generateSecureCode(10)
		if err != nil {
			return nil, err
		}

		// Hash it for storage (bcrypt default cost=10 is fine; 12–14 for more security)
		hashed, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}

		ids[i] = uuid.New()
		codes_plain[i] = plain
		codes_hashes[i] = string(hashed)

	}

	return &BackupCodes{ids, codes_plain, codes_hashes}, nil
}

// generateSecureCode creates a random uppercase + digits string
func generateSecureCode(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)

	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Map random bytes to charset
	for i := range bytes {
		bytes[i] = charset[bytes[i]%byte(len(charset))]
	}

	return string(bytes), nil
}

// pretty-print for display (e.g., "ABCD-EFGH-IJKL")
func FormatCode(code string) string {
	var parts []string
	for i := 0; i < len(code); i += 4 {
		end := min(i+4, len(code))
		parts = append(parts, code[i:end])
	}
	return strings.Join(parts, "-")
}
