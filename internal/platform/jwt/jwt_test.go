package jwt_test

import (
	"testing"

	"github.com/allthepins/auth-service/internal/platform/jwt"
)

const (
	testSecret   = "secret-key-for-testing"
	testIssuer   = "test-service"
	testAudience = "test-audience"
)

func TestNew(t *testing.T) {
	t.Run("should return error for empty secret", func(t *testing.T) {
		_, err := jwt.New("", testIssuer, testAudience, 15)
		if err == nil {
			t.Fatal("expected an error for empty secret, but got nil")
		}
	})

	t.Run("should return auth instance for valid secret", func(t *testing.T) {
		auth, err := jwt.New(testSecret, testIssuer, testAudience, 15)
		if err != nil {
			t.Fatalf("expected no error, but got: %v", err)
		}
		if auth == nil {
			t.Fatal("expected auth instance to be non-nil")
		}
	})
}

func TestGenerateAndValidateToken(t *testing.T) {
	auth, _ := jwt.New(testSecret, testIssuer, testAudience, 15)
	userID := "user-123"

	t.Run("should generate and validate a token successfully", func(t *testing.T) {
		tokenString, err := auth.GenerateToken(userID)
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		if tokenString == "" {
			t.Fatal("generated token string is empty")
		}

		validatedUserID, err := auth.ValidateToken(tokenString)
		if err != nil {
			t.Fatalf("failed to validate token: %v", err)
		}
		if validatedUserID != userID {
			t.Errorf("expected user ID %q, but got %q", userID, validatedUserID)
		}
	})
}

func TestValidateToken_Expired(t *testing.T) {
	// Create an auth instance where tokens expire instantly (-1 minute)
	auth, _ := jwt.New(testSecret, testIssuer, testAudience, -1)
	userID := "user-123"

	expiredToken, err := auth.GenerateToken(userID)
	if err != nil {
		t.Fatalf("dailed to generate expired token: %v", err)
	}

	_, err = auth.ValidateToken(expiredToken)
	if err == nil {
		t.Fatalf("expected an error for an expired token, but got nil")
	}
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	auth1, _ := jwt.New("secret-one", testIssuer, testAudience, 15)
	auth2, _ := jwt.New("secret-two", testIssuer, testAudience, 15)
	userID := "user-123"

	// Generate a token with the 1st secret
	tokenString, err := auth1.GenerateToken(userID)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Attempt to validate using the 2nd secret
	_, err = auth2.ValidateToken(tokenString)
	if err == nil {
		t.Fatal("expected an error for invalid signature, but got nil")
	}
}
