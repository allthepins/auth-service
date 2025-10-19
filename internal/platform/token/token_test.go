package token_test

import (
	"testing"

	"github.com/allthepins/auth-service/internal/platform/token"
)

func TestGenerate(t *testing.T) {
	manager := token.New()

	t.Run("generates non-empty token", func(t *testing.T) {
		tok, err := manager.Generate()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}
		if tok == "" {
			t.Fatal("generated token is empty")
		}
	})

	t.Run("generates unique tokens", func(t *testing.T) {
		tok1, err := manager.Generate()
		if err != nil {
			t.Fatalf("failed to generate first token: %v", err)
		}

		tok2, err := manager.Generate()
		if err != nil {
			t.Fatalf("failed to generate second token: %v", err)
		}

		if tok1 == tok2 {
			t.Fatal("generated tokens are not unique")
		}
	})
}

func TestHashAndVerify(t *testing.T) {
	manager := token.New()

	t.Run("hash and verify valid token", func(t *testing.T) {
		tok, err := manager.Generate()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		hash, err := manager.Hash(tok)
		if err != nil {
			t.Fatalf("failed to hash token: %v", err)
		}

		if hash == "" {
			t.Fatal("generated hash is empty")
		}

		if hash == tok {
			t.Fatal("hash should not equal original token")
		}

		err = manager.Verify(tok, hash)
		if err != nil {
			t.Fatalf("failed to verify token: %v", err)
		}
	})

	t.Run("verify fails with wrong token", func(t *testing.T) {
		tok, _ := manager.Generate()
		hash, _ := manager.Hash(tok)

		wrongTok, _ := manager.Generate()

		err := manager.Verify(wrongTok, hash)
		if err == nil {
			t.Fatal("expected verification to fail with wrong token")
		}
	})

	t.Run("verify fails with invalid hash", func(t *testing.T) {
		tok, _ := manager.Generate()

		err := manager.Verify(tok, "invalid-hash")
		if err == nil {
			t.Fatal("expected verification to fail with invalid hash")
		}
	})
}
