// Package middleware provides HTTP middleware for the API server.
package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/allthepins/auth-service/internal/api/response"
	"github.com/allthepins/auth-service/internal/platform/jwt"
)

// contextKey is a custom type for context keys to avoid key collisions.
type contextKey string

const userIDKey contextKey = "user_id"

// Auth returns a middleware that validates JWT tokens and adds user ID to context.
func Auth(jwtAuth jwt.Auth, logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				if err := response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authorization header required"); err != nil {
					logger.Error("failed to write error response", "error", err)
				}
				return
			}

			// Check for Bearer token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				if err := response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid authorization header format"); err != nil {
					logger.Error("failed to write error response", "error", err)
				}
				return
			}

			token := parts[1]

			// validate token
			userID, err := jwtAuth.ValidateToken(token)
			if err != nil {
				logger.Warn("invalid token", "error", err)
				if err := response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or expired token"); err != nil {
					logger.Error("failed to write error response", "error", err)
				}
				return
			}

			// add user ID to the context
			ctx := context.WithValue(r.Context(), userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID extracts the user ID from the request context.
func GetUserID(ctx context.Context) string {
	if userID, ok := ctx.Value(userIDKey).(string); ok {
		return userID
	}
	return ""
}
