// Package token provides secure random token generation and verification.
// It is used for refresh tokens, but can be used for password reset tokens,
// email verification tokens and other scenarios requiring secure random tokens
// with hashed storage.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// tokenLength is the byte length of tokens.
const tokenLength = 32 // 32 bytes = 256 bits

// Manager handles secure token generation and verification.
type Manager interface {
	Generate() (string, error)
	Hash(token string) (string, error)
}

// tokenManager implements the Manager interace.
type tokenManager struct {
	tokenLength int
}

// New creates a new token manager.
func New() Manager {
	return &tokenManager{
		tokenLength: tokenLength,
	}
}

// Generate creates a secure random token.
func (m *tokenManager) Generate() (string, error) {
	b := make([]byte, m.tokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Hash generates a SHA-256 hash of a given token.
// TODO: This was refactored form using SHA-256 instead of bcrypt because
// refresh tokens need deterministic hashing (so they can be looked up in the database),
// and bcrypt generates different hashes each time due to being randomlly salted.
func (m *tokenManager) Hash(token string) (string, error) {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:]), nil
}
