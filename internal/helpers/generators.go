package helpers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/google/uuid"
)

func GenerateUniqueID() uint {
	u := uuid.New()
	hash := sha256.Sum256(u[:])
	return uint(binary.BigEndian.Uint64(hash[:8]))
}

const charset = "abcdefghkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ123456789"

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
