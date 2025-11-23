// Package handlers provides HTTP request handlers for API endpoints.
package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/allthepins/auth-service/internal/api/response"
	"github.com/allthepins/auth-service/internal/auth"
)

// AuthHandler handles authentication-related HTTP requests.
type AuthHandler struct {
	service *auth.Service
	logger  *slog.Logger
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(service *auth.Service, logger *slog.Logger) *AuthHandler {
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
	default:
		h.logger.Error("unexpected error", "error", err)
		respErr = response.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred")
	}

	if respErr != nil {
		h.logger.Error("failed to write error response", "error", respErr)
	}
}
