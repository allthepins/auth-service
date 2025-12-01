package middleware_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/allthepins/auth-service/internal/api/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockJWT mocks the JWT Auth interface
type mockJWT struct {
	mock.Mock
}

func (m *mockJWT) GenerateToken(userID string) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}

func (m *mockJWT) ValidateToken(tokenString string) (string, error) {
	args := m.Called(tokenString)
	return args.String(0), args.Error(1)
}

// testHandler is a simple handler that writes the user ID from context
func testHandler(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID != "" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(userID))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("no user ID in context"))
	}
}

func TestAuth_ValidToken(t *testing.T) {
	jwtMock := new(mockJWT)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	expectedUserID := "user-123"
	validToken := "valid-token"

	jwtMock.On("ValidateToken", validToken).Return(expectedUserID, nil)

	authMiddleware := middleware.Auth(jwtMock, logger)
	handler := authMiddleware(http.HandlerFunc(testHandler))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedUserID, w.Body.String())
	jwtMock.AssertExpectations(t)
}

func TestAuth_MissingAuthorizationHeader(t *testing.T) {
	jwtMock := new(mockJWT)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	authMiddleware := middleware.Auth(jwtMock, logger)
	handler := authMiddleware(http.HandlerFunc(testHandler))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
	jwtMock.AssertNotCalled(t, "ValidateToken")
}

func TestAuth_InvalidAuthorizationFormat(t *testing.T) {
	jwtMock := new(mockJWT)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	authMiddleware := middleware.Auth(jwtMock, logger)
	handler := authMiddleware(http.HandlerFunc(testHandler))

	testCases := []struct {
		name       string
		authHeader string
	}{
		{"missing Bearer prefix", "just-a-token"},
		{"empty token", "Bearer"},
		{"wrong scheme", "Basic dXNlcjpwYXNz"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", tc.authHeader)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Contains(t, w.Body.String(), "Invalid authorization header format")
		})
	}

	jwtMock.AssertNotCalled(t, "ValidateToken")
}

func TestAuth_InvalidToken(t *testing.T) {
	jwtMock := new(mockJWT)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	invalidToken := "invalid-token"
	jwtMock.On("ValidateToken", invalidToken).Return("", assert.AnError)

	authMiddleware := middleware.Auth(jwtMock, logger)
	handler := authMiddleware(http.HandlerFunc(testHandler))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+invalidToken)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired token")
	jwtMock.AssertExpectations(t)
}

func TestGetUserID(t *testing.T) {
	t.Run("empty context", func(t *testing.T) {
		ctx := context.Background()
		userID := middleware.GetUserID(ctx)
		assert.Empty(t, userID)
	})

	t.Run("with user ID", func(t *testing.T) {
		jwtMock := new(mockJWT)
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

		expectedUserID := "test-user"
		validToken := "token"

		jwtMock.On("ValidateToken", validToken).Return(expectedUserID, nil)

		authMiddleware := middleware.Auth(jwtMock, logger)

		var extractedUserID string
		handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedUserID = middleware.GetUserID(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, expectedUserID, extractedUserID)
	})
}
