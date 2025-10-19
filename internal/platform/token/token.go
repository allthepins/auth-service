// Package token provides secure random token generation and verification.
// It is used for refresh tokens, but can be used for password reset tokens,
// email verification tokens and other scenarios requiring secure random tokens
// with hashed storage.
package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// tokenLength is the byte length of tokens.
const tokenLength = 32 // 32 bytes = 256 bits
// bcryptCost is the number of bcrypt hashing rounds
const bcryptCost = 11 // 1 more than default cost

// Manager handles secure token generation and verification.
type Manager interface {
	Generate() (string, error)
	Hash(token string) (string, error)
	Verify(token, hash string) error
}

// tokenManager implements the Manager interace.
type tokenManager struct {
	tokenLength int
	bcryptCost  int
}

// New creates a new token manager.
func New() Manager {
	return &tokenManager{
		tokenLength: tokenLength,
		bcryptCost:  bcryptCost,
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

// Hash generates a bcrypt hash of a given token.
func (m *tokenManager) Hash(token string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(token), m.bcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// Verify checks if a token matches its hash.
func (m *tokenManager) Verify(token, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return errors.New("token does not match")
		}
		return err
	}

	return nil
}
