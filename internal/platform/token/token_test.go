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

func TestHash(t *testing.T) {
	manager := token.New()

	t.Run("hash is deterministic", func(t *testing.T) {
		tok, err := manager.Generate()
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		hash1, err := manager.Hash(tok)
		if err != nil {
			t.Fatalf("failed to hash token: %v", err)
		}

		hash2, err := manager.Hash(tok)
		if err != nil {
			t.Fatalf("failed to hash token second time: %v", err)
		}

		if hash1 != hash2 {
			t.Fatal("hash is not deterministic")
		}
	})

	t.Run("different tokens produce different hashes", func(t *testing.T) {
		tok1, _ := manager.Generate()
		tok2, _ := manager.Generate()

		hash1, err := manager.Hash(tok1)
		if err != nil {
			t.Fatalf("failed to hash first token: %v", err)
		}

		hash2, err := manager.Hash(tok2)
		if err != nil {
			t.Fatalf("failed to hash second token: %v", err)
		}

		if hash1 == hash2 {
			t.Fatal("different tokens should produce different hashes")
		}
	})

	t.Run("hash is non-empty", func(t *testing.T) {
		tok, _ := manager.Generate()

		hash, err := manager.Hash(tok)
		if err != nil {
			t.Fatalf("failed to hash token: %v", err)
		}

		if hash == "" {
			t.Fatal("hash is empty")
		}
	})

	t.Run("hash is different from token", func(t *testing.T) {
		tok, _ := manager.Generate()

		hash, err := manager.Hash(tok)
		if err != nil {
			t.Fatalf("failed to hash token: %v", err)
		}

		if hash == tok {
			t.Fatal("hash should not equal original token")
		}
	})
}
