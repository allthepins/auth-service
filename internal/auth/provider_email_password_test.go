package auth_test

import (
	"encoding/json"
	"testing"

	"github.com/allthepins/auth-service/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestEmailPasswordProvider_Name(t *testing.T) {
	provider := auth.NewEmailPasswordProvider()
	assert.Equal(t, "email_password", provider.Name())
}

func TestEmailPasswordProvider_ValidateCredentials(t *testing.T) {
	provider := auth.NewEmailPasswordProvider()

	tests := []struct {
		name        string
		credentials map[string]any
		wantErr     bool
		errContains string
	}{
		{
			name: "valid credentials",
			credentials: map[string]any{
				"email":    "test@example.com",
				"password": "SecurePass123!",
			},
			wantErr: false,
		},
		{
			name: "missing email",
			credentials: map[string]any{
				"password": "SecurePass123!",
			},
			wantErr:     true,
			errContains: "email is required",
		},
		{
			name: "missing password",
			credentials: map[string]any{
				"email": "test@example.com",
			},
			wantErr:     true,
			errContains: "password is required",
		},
		{
			name: "invalid email format",
			credentials: map[string]any{
				"email":    "invalid email",
				"password": "SecurePass123!",
			},
			wantErr:     true,
			errContains: "invalid email",
		},
		{
			name: "weak password",
			credentials: map[string]any{
				"email":    "test@example.com",
				"password": "weak",
			},
			wantErr:     true,
			errContains: "password must be at least",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := provider.ValidateCredentials(tt.credentials)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEmailPasswordProvider_PrepareCredentials(t *testing.T) {
	provider := auth.NewEmailPasswordProvider()

	t.Run("successful preparation", func(t *testing.T) {
		credentials := map[string]any{
			"email":    "Test@Example.Com",
			"password": "SecurePass123!",
		}

		data, err := provider.PrepareCredentials(credentials)
		require.NoError(t, err)
		assert.NotNil(t, data)

		// Unmarshal and verify
		var stored map[string]string
		err = json.Unmarshal(data, &stored)
		require.NoError(t, err)

		// Email should be normalized to lowercase
		assert.Equal(t, "test@example.com", stored["email"])

		// Password should be hashed
		assert.NotEqual(t, "SecurePass123!", stored["password_hash"])
		err = bcrypt.CompareHashAndPassword([]byte(stored["password_hash"]), []byte("SecurePass123!"))
		assert.NoError(t, err)
	})

	t.Run("missing email", func(t *testing.T) {
		credentials := map[string]any{
			"password": "SecurePass123!",
		}

		data, err := provider.PrepareCredentials(credentials)
		require.Error(t, err)
		assert.Nil(t, data)
		assert.Contains(t, err.Error(), "email is required")
	})
}

func TestEmailPasswordProvider_VerifyCredentials(t *testing.T) {
	provider := auth.NewEmailPasswordProvider()

	// Prepare valid stored credentials
	validCreds := map[string]any{
		"email":    "test@example.com",
		"password": "SecurePass123!",
	}
	storedData, err := provider.PrepareCredentials(validCreds)
	require.NoError(t, err)

	tests := []struct {
		name        string
		provided    map[string]any
		stored      []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "valid credentials",
			provided: map[string]any{
				"email":    "test@example.com",
				"password": "SecurePass123!",
			},
			stored:  storedData,
			wantErr: false,
		},
		{
			name: "valid credentials with different case email",
			provided: map[string]any{
				"email":    "Test@Example.Com",
				"password": "SecurePass123!",
			},
			stored:  storedData,
			wantErr: false,
		},
		{
			name: "wrong password",
			provided: map[string]any{
				"email":    "test@example.com",
				"password": "WrongPassword123!",
			},
			stored:      storedData,
			wantErr:     true,
			errContains: "invalid password",
		},
		{
			name: "wrong email",
			provided: map[string]any{
				"email":    "wrong@example.com",
				"password": "SecurePass123!",
			},
			stored:      storedData,
			wantErr:     true,
			errContains: "email mismatch",
		},
		{
			name: "invalid stored data",
			provided: map[string]any{
				"email":    "test@example.com",
				"password": "SecurePass123!",
			},
			stored:      []byte("invalid json"),
			wantErr:     true,
			errContains: "failed to unmarshal",
		},
		{
			name: "missing email in provided",
			provided: map[string]any{
				"password": "SecurePass123!",
			},
			stored:      storedData,
			wantErr:     true,
			errContains: "email is required",
		},
		{
			name: "missing password in provided",
			provided: map[string]any{
				"email": "test@example.com",
			},
			stored:      storedData,
			wantErr:     true,
			errContains: "password is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := provider.VerifyCredentials(tt.provided, tt.stored)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEmailPasswordProvider_GetIdentifier(t *testing.T) {
	provider := auth.NewEmailPasswordProvider()

	t.Run("valid email", func(t *testing.T) {
		credentials := map[string]any{
			"email": "Test@Example.Com",
		}

		identifier, err := provider.GetIdentifier(credentials)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", identifier)
	})

	t.Run("missing email", func(t *testing.T) {
		credentials := map[string]any{}

		identifier, err := provider.GetIdentifier(credentials)
		require.Error(t, err)
		assert.Empty(t, identifier)
		assert.Contains(t, err.Error(), "email is required")
	})

	t.Run("empty email", func(t *testing.T) {
		credentials := map[string]any{
			"email": "",
		}

		identifier, err := provider.GetIdentifier(credentials)
		require.Error(t, err)
		assert.Empty(t, identifier)
		assert.Contains(t, err.Error(), "email is required")
	})
}
