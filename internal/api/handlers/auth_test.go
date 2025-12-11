package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/allthepins/auth-service/internal/api/handlers"
	"github.com/allthepins/auth-service/internal/api/middleware"
	"github.com/allthepins/auth-service/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockAuthService mocks the handlers.AuthService interface
type mockAuthService struct {
	mock.Mock
}

func (m *mockAuthService) Register(ctx context.Context, req auth.RegisterRequest) (*auth.AuthResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthResponse), args.Error(1)
}

func (m *mockAuthService) Login(ctx context.Context, req auth.LoginRequest) (*auth.AuthResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthResponse), args.Error(1)
}

func (m *mockAuthService) Refresh(ctx context.Context, refreshToken string) (*auth.AuthResponse, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthResponse), args.Error(1)
}

func (m *mockAuthService) Logout(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
	return args.Error(0)
}

func (m *mockAuthService) ListUserSessions(ctx context.Context, userID string) ([]auth.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]auth.Session), args.Error(1)
}

func (m *mockAuthService) RevokeSession(ctx context.Context, userID, sessionID string) error {
	args := m.Called(ctx, userID, sessionID)
	return args.Error(0)
}

func TestAuthHandler_Register(t *testing.T) {
	tests := []struct {
		name          string
		requestBody   any
		mockSetup     func(*mockAuthService)
		wantStatus    int
		wantErrorCode string // Expected error code in response
		checkResponse func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "successful registration",
			requestBody: map[string]any{
				"provider": "email_password",
				"credentials": map[string]string{
					"email":    "test@example.com",
					"password": "SecurePass123!",
				},
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Register", mock.Anything, mock.MatchedBy(func(req auth.RegisterRequest) bool {
					return req.Provider == "email_password"
				})).Return(&auth.AuthResponse{
					AccessToken:  "mock-access-token",
					RefreshToken: "mock-refresh-token",
					User: auth.User{
						ID:    "user-123",
						Roles: []string{"user"},
					},
				}, nil)
			},
			wantStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp auth.AuthResponse
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.Equal(t, "mock-access-token", resp.AccessToken)
				assert.Equal(t, "mock-refresh-token", resp.RefreshToken)
				assert.Equal(t, "user-123", resp.User.ID)
				assert.Equal(t, []string{"user"}, resp.User.Roles)
			},
		},
		{
			name:          "invalid JSON body",
			requestBody:   `{invalid json}`,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "BAD_REQUEST",
		},
		{
			name: "missing provider",
			requestBody: map[string]any{
				"credentials": map[string]string{
					"email":    "test@example.com",
					"password": "SecurePass123!",
				},
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Register", mock.Anything, mock.Anything).
					Return(nil, auth.ErrInvalidProvider)
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "INVALID_PROVIDER",
		},
		{
			name: "user already exists",
			requestBody: map[string]any{
				"provider": "email_password",
				"credentials": map[string]string{
					"email":    "existing@example.com",
					"password": "SecurePass123!",
				},
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Register", mock.Anything, mock.Anything).
					Return(nil, auth.ErrUserExists)
			},
			wantStatus:    http.StatusConflict,
			wantErrorCode: "USER_EXISTS",
		},
		{
			name: "invalid credentials",
			requestBody: map[string]any{
				"provider": "email_password",
				"credentials": map[string]string{
					"email":    "invalid-email",
					"password": "weak",
				},
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Register", mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("%w: password must be at least 8 characters", auth.ErrInvalidInput))
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "INVALID_INPUT",
		},
		{
			name: "internal server error",
			requestBody: map[string]any{
				"provider": "email_password",
				"credentials": map[string]string{
					"email":    "test@example.com",
					"password": "SecurePass123!",
				},
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Register", mock.Anything, mock.Anything).
					Return(nil, errors.New("database connection failed"))
			},
			wantStatus:    http.StatusInternalServerError,
			wantErrorCode: "INTERNAL_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := new(mockAuthService)
			if tt.mockSetup != nil {
				tt.mockSetup(mockService)
			}

			logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			handler := handlers.NewAuthHandler(mockService, logger)

			// Create request
			var body []byte
			switch v := tt.requestBody.(type) {
			case string:
				body = []byte(v)
			default:
				body, _ = json.Marshal(v)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Execute
			handler.Register(w, req)

			// Assert status code
			assert.Equal(t, tt.wantStatus, w.Code)

			// Assert error code if specified
			if tt.wantErrorCode != "" {
				var errResp struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}
				err := json.Unmarshal(w.Body.Bytes(), &errResp)
				require.NoError(t, err)
				assert.Equal(t, tt.wantErrorCode, errResp.Code)
			}

			// Run custom response checks
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}

			// Verify mock expectations
			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_Login(t *testing.T) {
	tests := []struct {
		name          string
		requestBody   any
		mockSetup     func(*mockAuthService)
		wantStatus    int
		wantErrorCode string
		checkResponse func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "successful login",
			requestBody: map[string]any{
				"provider": "email_password",
				"credentials": map[string]string{
					"email":    "test@example.com",
					"password": "SecurePass123!",
				},
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Login", mock.Anything, mock.Anything).
					Return(&auth.AuthResponse{
						AccessToken:  "access-token",
						RefreshToken: "refresh-token",
						User: auth.User{
							ID:    "user-123",
							Roles: []string{"user"},
						},
					}, nil)
			},
			wantStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var resp auth.AuthResponse
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp.AccessToken)
				assert.NotEmpty(t, resp.RefreshToken)
			},
		},
		{
			name: "invalid credentials",
			requestBody: map[string]any{
				"provider": "email_password",
				"credentials": map[string]string{
					"email":    "test@example.com",
					"password": "WrongPassword",
				},
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Login", mock.Anything, mock.Anything).
					Return(nil, auth.ErrInvalidCredentials)
			},
			wantStatus:    http.StatusUnauthorized,
			wantErrorCode: "INVALID_CREDENTIALS",
		},
		{
			name: "user not found",
			requestBody: map[string]any{
				"provider": "email_password",
				"credentials": map[string]string{
					"email":    "nonexistent@example.com",
					"password": "SecurePass123!",
				},
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Login", mock.Anything, mock.Anything).
					Return(nil, auth.ErrUserNotFound)
			},
			wantStatus:    http.StatusUnauthorized,
			wantErrorCode: "INVALID_CREDENTIALS", // Intentionally obscure "user not found"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(mockAuthService)
			if tt.mockSetup != nil {
				tt.mockSetup(mockService)
			}

			logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			handler := handlers.NewAuthHandler(mockService, logger)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.Login(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantErrorCode != "" {
				var errResp struct {
					Code string `json:"code"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &errResp)
				assert.Equal(t, tt.wantErrorCode, errResp.Code)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_Refresh(t *testing.T) {
	tests := []struct {
		name          string
		requestBody   any
		mockSetup     func(*mockAuthService)
		wantStatus    int
		wantErrorCode string
	}{
		{
			name: "successful refresh",
			requestBody: map[string]any{
				"refreshToken": "valid-refresh-token",
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Refresh", mock.Anything, "valid-refresh-token").
					Return(&auth.AuthResponse{
						AccessToken:  "new-access-token",
						RefreshToken: "new-refresh-token",
						User:         auth.User{ID: "user-123"},
					}, nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "invalid refresh token",
			requestBody: map[string]any{
				"refreshToken": "invalid-token",
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Refresh", mock.Anything, "invalid-token").
					Return(nil, auth.ErrInvalidToken)
			},
			wantStatus:    http.StatusUnauthorized,
			wantErrorCode: "INVALID_TOKEN",
		},
		{
			name:          "missing refresh token",
			requestBody:   map[string]any{},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(mockAuthService)
			if tt.mockSetup != nil {
				tt.mockSetup(mockService)
			}

			logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			handler := handlers.NewAuthHandler(mockService, logger)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(body))
			w := httptest.NewRecorder()

			handler.Refresh(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantErrorCode != "" {
				var errResp struct {
					Code string `json:"code"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &errResp)
				assert.Equal(t, tt.wantErrorCode, errResp.Code)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_Logout(t *testing.T) {
	tests := []struct {
		name          string
		requestBody   any
		mockSetup     func(*mockAuthService)
		wantStatus    int
		wantErrorCode string
	}{
		{
			name: "successful logout",
			requestBody: map[string]any{
				"refreshToken": "valid-token",
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Logout", mock.Anything, "valid-token").
					Return(nil)
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name: "invalid token",
			requestBody: map[string]any{
				"refreshToken": "invalid-token",
			},
			mockSetup: func(m *mockAuthService) {
				m.On("Logout", mock.Anything, "invalid-token").
					Return(auth.ErrInvalidToken)
			},
			wantStatus:    http.StatusUnauthorized,
			wantErrorCode: "INVALID_TOKEN",
		},
		{
			name:          "missing refresh token",
			requestBody:   map[string]any{},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(mockAuthService)
			if tt.mockSetup != nil {
				tt.mockSetup(mockService)
			}

			logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			handler := handlers.NewAuthHandler(mockService, logger)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(body))
			w := httptest.NewRecorder()

			handler.Logout(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantErrorCode != "" {
				var errResp struct {
					Code string `json:"code"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &errResp)
				assert.Equal(t, tt.wantErrorCode, errResp.Code)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_ListSessions(t *testing.T) {
	tests := []struct {
		name          string
		userID        string // From JWT middleware context
		mockSetup     func(*mockAuthService)
		wantStatus    int
		wantErrorCode string
		checkResponse func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:   "successful list sessions",
			userID: "user-123",
			mockSetup: func(m *mockAuthService) {
				sessions := []auth.Session{
					{
						ID:           "session-1",
						ClientIP:     "192.168.1.*",
						LastUsedAt:   time.Now().Add(-1 * time.Hour),
						SessionStart: time.Now().Add(-24 * time.Hour),
						ExpiresAt:    time.Now().Add(29 * 24 * time.Hour),
					},
					{
						ID:           "session-2",
						ClientIP:     "10.0.0.*",
						LastUsedAt:   time.Now().Add(-5 * time.Minute),
						SessionStart: time.Now().Add(-2 * time.Hour),
						ExpiresAt:    time.Now().Add(29 * 24 * time.Hour),
					},
				}
				m.On("ListUserSessions", mock.Anything, "user-123").
					Return(sessions, nil)
			},
			wantStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var sessions []auth.Session
				err := json.Unmarshal(w.Body.Bytes(), &sessions)
				require.NoError(t, err)
				assert.Len(t, sessions, 2)
				assert.Equal(t, "session-1", sessions[0].ID)
				assert.Equal(t, "192.168.1.*", sessions[0].ClientIP)
			},
		},
		{
			name:   "empty session list",
			userID: "user-456",
			mockSetup: func(m *mockAuthService) {
				m.On("ListUserSessions", mock.Anything, "user-456").
					Return([]auth.Session{}, nil)
			},
			wantStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var sessions []auth.Session
				err := json.Unmarshal(w.Body.Bytes(), &sessions)
				require.NoError(t, err)
				assert.Len(t, sessions, 0)
			},
		},
		{
			name:   "user not found",
			userID: "nonexistent-user",
			mockSetup: func(m *mockAuthService) {
				m.On("ListUserSessions", mock.Anything, "nonexistent-user").
					Return(nil, auth.ErrUserNotFound)
			},
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "USER_NOT_FOUND",
		},
		{
			name:   "database error",
			userID: "user-789",
			mockSetup: func(m *mockAuthService) {
				m.On("ListUserSessions", mock.Anything, "user-789").
					Return(nil, errors.New("database connection failed"))
			},
			wantStatus:    http.StatusInternalServerError,
			wantErrorCode: "INTERNAL_ERROR",
		},
		{
			name:          "missing user ID from context",
			userID:        "", // Simulates missing auth middleware
			wantStatus:    http.StatusUnauthorized,
			wantErrorCode: "UNAUTHORIZED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(mockAuthService)
			if tt.mockSetup != nil {
				tt.mockSetup(mockService)
			}

			logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			handler := handlers.NewAuthHandler(mockService, logger)

			req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)

			// Add user ID to context
			if tt.userID != "" {
				req = req.WithContext(middleware.SetUserIDForTesting(req.Context(), tt.userID))
			}

			w := httptest.NewRecorder()
			handler.ListSessions(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantErrorCode != "" {
				var errResp struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}
				err := json.Unmarshal(w.Body.Bytes(), &errResp)
				require.NoError(t, err)
				assert.Equal(t, tt.wantErrorCode, errResp.Code)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_RevokeSession(t *testing.T) {
	tests := []struct {
		name          string
		userID        string // From JWT middleware context
		sessionID     string // From URL path parameter
		mockSetup     func(*mockAuthService)
		wantStatus    int
		wantErrorCode string
	}{
		{
			name:      "successful revoke",
			userID:    "user-123",
			sessionID: "session-456",
			mockSetup: func(m *mockAuthService) {
				m.On("RevokeSession", mock.Anything, "user-123", "session-456").
					Return(nil)
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:      "session not found",
			userID:    "user-123",
			sessionID: "nonexistent-session",
			mockSetup: func(m *mockAuthService) {
				m.On("RevokeSession", mock.Anything, "user-123", "nonexistent-session").
					Return(auth.ErrSessionNotFound)
			},
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "SESSION_NOT_FOUND",
		},
		{
			name:      "session belongs to different user",
			userID:    "user-123",
			sessionID: "other-user-session",
			mockSetup: func(m *mockAuthService) {
				m.On("RevokeSession", mock.Anything, "user-123", "other-user-session").
					Return(auth.ErrSessionNotFound) // Security: return not found
			},
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "SESSION_NOT_FOUND",
		},
		{
			name:      "invalid session ID format",
			userID:    "user-123",
			sessionID: "invalid-uuid",
			mockSetup: func(m *mockAuthService) {
				m.On("RevokeSession", mock.Anything, "user-123", "invalid-uuid").
					Return(fmt.Errorf("invalid session ID format"))
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "BAD_REQUEST",
		},
		{
			name:      "database error",
			userID:    "user-123",
			sessionID: "session-456",
			mockSetup: func(m *mockAuthService) {
				m.On("RevokeSession", mock.Anything, "user-123", "session-456").
					Return(errors.New("database connection failed"))
			},
			wantStatus:    http.StatusInternalServerError,
			wantErrorCode: "INTERNAL_ERROR",
		},
		{
			name:          "missing user ID from context",
			userID:        "", // Simulate missing auth middleware
			sessionID:     "session-456",
			wantStatus:    http.StatusUnauthorized,
			wantErrorCode: "UNAUTHORIZED",
		},
		{
			name:          "missing session ID from path",
			userID:        "user-123",
			sessionID:     "", // Empty session ID
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(mockAuthService)
			if tt.mockSetup != nil {
				tt.mockSetup(mockService)
			}

			logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			handler := handlers.NewAuthHandler(mockService, logger)

			req := httptest.NewRequest(
				http.MethodDelete,
				fmt.Sprintf("/auth/sessions/%s", tt.sessionID),
				nil,
			)

			// Add user ID to context
			if tt.userID != "" {
				req = req.WithContext(middleware.SetUserIDForTesting(req.Context(), tt.userID))
			}

			// Add session ID to chi URL params
			if tt.sessionID != "" {
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("sessionId", tt.sessionID)
				req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			}

			w := httptest.NewRecorder()
			handler.RevokeSession(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantErrorCode != "" {
				var errResp struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}
				err := json.Unmarshal(w.Body.Bytes(), &errResp)
				require.NoError(t, err)
				assert.Equal(t, tt.wantErrorCode, errResp.Code)
			}

			mockService.AssertExpectations(t)
		})
	}
}
