// Package jwt provides JSON Web Token generation and validation for access tokens.
package jwt

import (
	"errors"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Auth is the interface for JWT authentication operations.
type Auth interface {
	GenerateToken(userID string) (string, error)
	ValidateToken(tokenString string) (string, error)
}

// jwtAuth implements the Auth interface.
type jwtAuth struct {
	secret      []byte
	issuer      string
	audience    string
	tokenExpiry time.Duration
}

// New creates a new instance of jwtAuth.
func New(secret, issuer, audience string, expiryMinutes int) (Auth, error) {
	if secret == "" {
		return nil, errors.New("jwt secret cannot be empty")
	}

	return &jwtAuth{
		secret:      []byte(secret),
		issuer:      issuer,
		audience:    audience,
		tokenExpiry: time.Minute * time.Duration(expiryMinutes),
	}, nil
}

// GenerateToken creates a new JWT access token for a given user ID.
func (j *jwtAuth) GenerateToken(userId string) (string, error) {
	claims := &jwtv5.RegisteredClaims{
		Issuer:    j.issuer,
		Audience:  jwtv5.ClaimStrings{j.audience},
		Subject:   userId,
		IssuedAt:  jwtv5.NewNumericDate(time.Now()),
		ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(j.tokenExpiry)),
	}

	// TODO: Determine most suitable signing algorithm.
	// Take into account speed, token size and security implications.
	// Should be assymetric if external services validate tokens as well.
	// Choosing HMAC for now, for speed and simplicity.
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(j.secret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// ValidateToken parses and validates a token string, returning the user ID (subject).
func (j *jwtAuth) ValidateToken(tokenString string) (string, error) {
	var claims jwtv5.RegisteredClaims

	token, err := jwtv5.ParseWithClaims(
		tokenString,
		&claims,
		func(token *jwtv5.Token) (any, error) {
			// Ensure the signing method is what we expect
			if _, ok := token.Method.(*jwtv5.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}

			return j.secret, nil
		},
	)

	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", errors.New("invalid token")
	}

	return claims.Subject, nil
}
