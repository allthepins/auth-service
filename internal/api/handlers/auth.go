// Package handlers provides HTTP request handlers for API endpoints.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/allthepins/auth-service/internal/api/middleware"
	"github.com/allthepins/auth-service/internal/api/response"
	"github.com/allthepins/auth-service/internal/auth"
	"github.com/go-chi/chi/v5"
)

// AuthService defines the interface for authentication operations.
// (Defined this interface to allow the handler to also work with mocks for tests).
type AuthService interface {
	Register(ctx context.Context, req auth.RegisterRequest) (*auth.AuthResponse, error)
	Login(ctx context.Context, req auth.LoginRequest) (*auth.AuthResponse, error)
	Refresh(ctx context.Context, refreshToken string) (*auth.AuthResponse, error)
	Logout(ctx context.Context, refreshToken string) error
	ListUserSessions(ctx context.Context, userID string) ([]auth.Session, error)
	RevokeSession(ctx context.Context, userID, sessionID string) error
}

// AuthHandler handles authentication-related HTTP requests.
type AuthHandler struct {
	service AuthService
	logger  *slog.Logger
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(service AuthService, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		service: service,
		logger:  logger,
	}
}

// RegisterRequest represents the registration request payload.
type RegisterRequest struct {
	Provider    string         `json:"provider"`
	Credentials map[string]any `json:"credentials"`
}

// LoginRequest represents the login request payload.
type LoginRequest struct {
	Provider    string         `json:"provider"`
	Credentials map[string]any `json:"credentials"`
}

// RefreshRequest represents the token refresh request payload.
type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// Register handles user registration.
// POST /auth/register
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err := response.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body"); err != nil {
			h.logger.Error("failed to write error response", "error", err)
		}
		return
	}

	resp, err := h.service.Register(r.Context(), auth.RegisterRequest{
		Provider:    req.Provider,
		Credentials: req.Credentials,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	if err := response.JSON(w, http.StatusCreated, resp); err != nil {
		h.logger.Error("failed tp write response", "error", err)
	}
}

// Login handles user authentication.
// POST /auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err := response.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body"); err != nil {
			h.logger.Error("failed to write error response", "error", err)
		}
		return
	}

	resp, err := h.service.Login(r.Context(), auth.LoginRequest{
		Provider:    req.Provider,
		Credentials: req.Credentials,
	})

	if err != nil {
		h.handleError(w, err)
		return
	}

	if err := response.JSON(w, http.StatusOK, resp); err != nil {
		h.logger.Error("failed to write response", "error", err)
	}
}

// Refresh handles token refresh.
// POST /auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err := response.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body"); err != nil {
			h.logger.Error("failed to write error response", "error", err)
		}
		return
	}

	if req.RefreshToken == "" {
		if err := response.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Refresh token is required"); err != nil {
			h.logger.Error("failed to write error response", "error", err)
		}
		return
	}

	resp, err := h.service.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		h.handleError(w, err)
		return
	}

	if err := response.JSON(w, http.StatusOK, resp); err != nil {
		h.logger.Error("failed to write response", "error", err)
	}
}

// Logout handles user logout.
// POST /auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err := response.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body"); err != nil {
			h.logger.Error("failed to write error response", "error", err)
		}
		return
	}

	if req.RefreshToken == "" {
		if err := response.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Refresh token is required"); err != nil {
			h.logger.Error("failed to write error response", "error", err)
		}
		return
	}

	err := h.service.Logout(r.Context(), req.RefreshToken)
	if err != nil {
		h.handleError(w, err)
		return
	}

	// 204 No Content for successful logout
	w.WriteHeader(http.StatusNoContent)
}

// ListSessions handles listing user sessions.
// GET /auth/sessions
func (h *AuthHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		if err := response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "User ID not found in context"); err != nil {
			h.logger.Error("failed to write error response", "error", err)
		}
		return
	}

	sessions, err := h.service.ListUserSessions(r.Context(), userID)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			if err = response.Error(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found"); err != nil {
				h.logger.Error("failed to write error response", "error", err)
			}
			return
		}

		h.handleError(w, err)
		return
	}

	if err := response.JSON(w, http.StatusOK, sessions); err != nil {
		h.logger.Error("failed to write response", "error", err)
	}
}

// RevokeSession handles revoking a specific session.
// DELETE /auth/sessions/{sessionId}
func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		if err := response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "User ID not found in context"); err != nil {
			h.logger.Error("failed to write error response", "error", err)
		}
		return
	}

	sessionID := chi.URLParam(r, "sessionId")
	if sessionID == "" {
		if err := response.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Session ID is required"); err != nil {
			h.logger.Error("failed to write error response", "error", err)
		}
		return
	}

	err := h.service.RevokeSession(r.Context(), userID, sessionID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleError maps service errors to appropriate HTTP responses.
func (h *AuthHandler) handleError(w http.ResponseWriter, err error) {
	var respErr error

	switch {
	case errors.Is(err, auth.ErrUserExists):
		respErr = response.Error(w, http.StatusConflict, "USER_EXISTS", "An account with this identifier already exists")
	case errors.Is(err, auth.ErrUserNotFound):
		respErr = response.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid credentials")
	case errors.Is(err, auth.ErrInvalidCredentials):
		respErr = response.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid credentials")
	case errors.Is(err, auth.ErrInvalidProvider):
		respErr = response.Error(w, http.StatusBadRequest, "INVALID_PROVIDER", "Invalid authentication provider")
	case errors.Is(err, auth.ErrInvalidInput):
		respErr = response.Error(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
	case errors.Is(err, auth.ErrInvalidToken):
		respErr = response.Error(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired token")
	case errors.Is(err, auth.ErrSessionNotFound):
		respErr = response.Error(w, http.StatusNotFound, "SESSION_NOT_FOUND", "Session not found")
	case strings.Contains(err.Error(), "invalid session ID"):
		respErr = response.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid session ID format")
	default:
		h.logger.Error("unexpected error", "error", err)
		respErr = response.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred")
	}

	if respErr != nil {
		h.logger.Error("failed to write error response", "error", respErr)
	}
}
