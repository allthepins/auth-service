package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/allthepins/auth-service/internal/api/handlers"
	"github.com/allthepins/auth-service/internal/auth"
	"github.com/allthepins/auth-service/internal/database"
	"github.com/allthepins/auth-service/internal/platform/jwt"
	"github.com/allthepins/auth-service/internal/platform/logger"
	"github.com/allthepins/auth-service/internal/platform/token"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestAuthHandlerIntegration tests handlers with real database using testcontainers
func TestAuthHandlerIntegration(t *testing.T) {
	// Skip if running in short mode
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()

	// Start PostgreSQL container
	t.Log("Starting PostgreSQL container...")
	postgresContainer, err := postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "failed to start postgres container")

	// Container will be automatically terminated when test completes
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(postgresContainer); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	})

	// Get connection string from container
	connString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "failed to get connection string")

	t.Logf("Test database URL: %s", connString)

	// Run migrations
	t.Log("Running migrations...")
	require.NoError(t, runMigrations(t, ctx, connString))

	// Connect to database
	dbPool, err := pgxpool.New(ctx, connString)
	require.NoError(t, err, "failed to connect to test database")
	defer dbPool.Close()

	// Setup auth service with real dependencies
	authService := setupAuthService(t, dbPool)

	// Setup handler and router
	log := logger.New("test-service")
	handler := handlers.NewAuthHandler(authService, log)
	r := setupRouter(handler)

	// Run test suites
	t.Run("complete authentication flow", func(t *testing.T) {
		testCompleteAuthFlow(t, r)
	})

	t.Run("concurrent registrations", func(t *testing.T) {
		testConcurrentRegistrations(t, r)
	})
}

// runMigrations runs database migrations inline.
// TODO Look into alternative to inline if queries grow.
func runMigrations(t *testing.T, ctx context.Context, connString string) error {
	t.Helper()

	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer func() {
		if err := conn.Close(ctx); err != nil {
			t.Logf("WARNING: failed to close migration connection: %v", err)
		}
	}()

	// Run migrations
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS "auth.users" (
			id UUID PRIMARY KEY,
			roles TEXT[] NOT NULL DEFAULT '{}',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS "auth.identities" (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL REFERENCES "auth.users"(id) ON DELETE CASCADE,
			provider TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			credentials JSONB,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(provider, provider_id)
		)`,
		`CREATE TABLE IF NOT EXISTS "auth.refresh_tokens" (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL REFERENCES "auth.users"(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(token_hash)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_active
		 ON "auth.refresh_tokens"(user_id)
		 WHERE revoked_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash
		 ON "auth.refresh_tokens"(token_hash)
		 WHERE revoked_at IS NULL`,
	}

	for _, migration := range migrations {
		if _, err := conn.Exec(ctx, migration); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	return nil
}

// setupAuthService creates auth service with real dependencies.
func setupAuthService(t *testing.T, pool *pgxpool.Pool) *auth.Service {
	t.Helper()

	jwtAuth, err := jwt.New(
		"test-secret-key-for-testing-only",
		"test-issuer",
		"test-audience",
		15,
	)
	require.NoError(t, err)

	tokenManager := token.New()
	queries := &queryAdapter{database.New(pool)}
	log := logger.New("test-service")

	service, err := auth.NewService(auth.Config{
		Conn:               pool,
		Querier:            queries,
		JWT:                jwtAuth,
		TokenManager:       tokenManager,
		Logger:             log,
		RefreshTokenExpiry: 30 * 24 * time.Hour,
	})
	require.NoError(t, err)

	return service
}

// queryAdapter adapts database.Queries to auth.Querier interface.
type queryAdapter struct {
	*database.Queries
}

func (qa *queryAdapter) WithTx(tx pgx.Tx) database.Querier {
	return &queryAdapter{qa.Queries.WithTx(tx)}
}

// setupRouter creates a chi router with all routes.
func setupRouter(handler *handlers.AuthHandler) *chi.Mux {
	r := chi.NewRouter()

	r.Post("/auth/register", handler.Register)
	r.Post("/auth/login", handler.Login)
	r.Post("/auth/refresh", handler.Refresh)
	r.Post("/auth/logout", handler.Logout)

	return r
}

// testCompleteAuthFlow tests the complete authentication workflow.
func testCompleteAuthFlow(t *testing.T, r *chi.Mux) {
	email := fmt.Sprintf("integration-test-%d@example.com", time.Now().UnixNano())
	password := "SecurePass123!"

	// Step 1: Register a new user
	t.Log("Step 1: Registering new user...")
	registerReq := map[string]any{
		"provider": "email_password",
		"credentials": map[string]string{
			"email":    email,
			"password": password,
		},
	}
	registerBody, _ := json.Marshal(registerReq)
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewReader(registerBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code, "registration should succeed")

	var registerResp auth.AuthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &registerResp))
	assert.NotEmpty(t, registerResp.AccessToken)
	assert.NotEmpty(t, registerResp.RefreshToken)
	assert.NotEmpty(t, registerResp.User.ID)
	assert.Equal(t, []string{"user"}, registerResp.User.Roles)

	userID := registerResp.User.ID
	firstRefreshToken := registerResp.RefreshToken

	// Step 2: Attempt duplicate registration (should fail)
	t.Log("Step 2: Testing duplicate registration...")
	req = httptest.NewRequest("POST", "/auth/register", bytes.NewReader(registerBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code, "duplicate registration should fail")

	// Step 3: Login with correct credentials
	t.Log("Step 3: Logging in with correct credentials...")
	loginReq := map[string]any{
		"provider": "email_password",
		"credentials": map[string]string{
			"email":    email,
			"password": password,
		},
	}
	loginBody, _ := json.Marshal(loginReq)
	req = httptest.NewRequest("POST", "/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "login should succeed")

	var loginResp auth.AuthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &loginResp))
	assert.Equal(t, userID, loginResp.User.ID, "should be same user")
	assert.NotEmpty(t, loginResp.AccessToken)
	assert.NotEmpty(t, loginResp.RefreshToken)

	// Step 4: Login with wrong password (should fail)
	t.Log("Step 4: Testing login with wrong password...")
	wrongLoginReq := map[string]any{
		"provider": "email_password",
		"credentials": map[string]string{
			"email":    email,
			"password": "WrongPassword123!",
		},
	}
	wrongLoginBody, _ := json.Marshal(wrongLoginReq)
	req = httptest.NewRequest("POST", "/auth/login", bytes.NewReader(wrongLoginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "wrong password should fail")

	// Step 5: Refresh tokens
	t.Log("Step 5: Refreshing tokens...")
	refreshReq := map[string]string{
		"refreshToken": firstRefreshToken,
	}
	refreshBody, _ := json.Marshal(refreshReq)
	req = httptest.NewRequest("POST", "/auth/refresh", bytes.NewReader(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "token refresh should succeed")

	var refreshResp auth.AuthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refreshResp))
	assert.NotEmpty(t, refreshResp.AccessToken)
	assert.NotEmpty(t, refreshResp.RefreshToken)
	assert.NotEqual(t, firstRefreshToken, refreshResp.RefreshToken, "refresh token should rotate")

	secondRefreshToken := refreshResp.RefreshToken

	// Step 6: Try to use old refresh token (should fail - token rotation)
	t.Log("Step 6: Testing token rotation (old token should be invalid)...")
	req = httptest.NewRequest("POST", "/auth/refresh", bytes.NewReader(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "old refresh token should be invalid")

	// Step 7: Logout
	t.Log("Step 7: Logging out...")
	logoutReq := map[string]string{
		"refreshToken": secondRefreshToken,
	}
	logoutBody, _ := json.Marshal(logoutReq)
	req = httptest.NewRequest("POST", "/auth/logout", bytes.NewReader(logoutBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code, "logout should succeed")

	// Step 8: Try to use logged-out token (should fail)
	t.Log("Step 8: Testing logged-out token...")
	req = httptest.NewRequest("POST", "/auth/refresh", bytes.NewReader(logoutBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "logged-out token should be invalid")

	t.Log("✅ Complete authentication flow test passed!")
}

// testConcurrentRegistrations tests concurrent registration handling.
func testConcurrentRegistrations(t *testing.T, r *chi.Mux) {
	email := fmt.Sprintf("concurrent-test-%d@example.com", time.Now().UnixNano())
	password := "SecurePass123!"

	numRequests := 5
	results := make([]int, numRequests)
	var wg sync.WaitGroup

	t.Logf("Launching %d concurrent registration requests...", numRequests)

	// Launch concurrent requests
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			registerReq := map[string]any{
				"provider": "email_password",
				"credentials": map[string]string{
					"email":    email,
					"password": password,
				},
			}
			body, _ := json.Marshal(registerReq)

			req := httptest.NewRequest("POST", "/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)
			results[index] = w.Code
		}(i)
	}

	wg.Wait()

	// Count successes and conflicts
	var successes, conflicts int
	for _, code := range results {
		switch code {
		case http.StatusCreated:
			successes++
		case http.StatusConflict:
			conflicts++
		}
	}

	t.Logf("Results: %d successes, %d conflicts", successes, conflicts)

	// Exactly one should succeed, rest should be conflicts
	assert.Equal(t, 1, successes, "exactly one registration should succeed")
	assert.Equal(t, numRequests-1, conflicts, "remaining registrations should conflict")

	t.Log("✅ Concurrent registration test passed!")
}
