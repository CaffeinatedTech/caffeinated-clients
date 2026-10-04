package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// NewToken returns a 256-bit random token, URL-safe and unpadded.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewCSRFToken is a session CSRF token; same construction as a session token.
func NewCSRFToken() (string, error) {
	return NewToken()
}

// HashToken is the value stored in the database. Raw session tokens are never
// persisted, so a leaked database cannot be replayed as a live session.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
