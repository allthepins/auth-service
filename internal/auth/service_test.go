package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/allthepins/auth-service/internal/api/middleware"
	"github.com/allthepins/auth-service/internal/auth"
	"github.com/allthepins/auth-service/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// contextWithMetadata creates a context with request metadata for testing.
func contextWithMetadata(clientIP string) context.Context {
	metadata := &middleware.RequestMetadata{ClientIP: clientIP}
	return context.WithValue(context.Background(), middleware.RequestMetadataKey, metadata)
}

// mockTxBeginner mocks the transaction beginner interface
type mockTxBeginner struct {
	mock.Mock
}

func (m *mockTxBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(pgx.Tx), args.Error(1)
}

// mockTx mocks a pgx transaction
type mockTx struct {
	mock.Mock
}

func (m *mockTx) Commit(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockTx) Rollback(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Unused methods required by the pgx.Tx interface
func (m *mockTx) Begin(ctx context.Context) (pgx.Tx, error)                 { return nil, nil }
func (m *mockTx) BeginFunc(ctx context.Context, f func(pgx.Tx) error) error { return nil }
func (m *mockTx) Conn() *pgx.Conn                                           { return nil }
func (m *mockTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, nil
}
func (m *mockTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (m *mockTx) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (m *mockTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, nil
}
func (m *mockTx) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }
func (m *mockTx) QueryRow(context.Context, string, ...any) pgx.Row        { return nil }
func (m *mockTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults  { return nil }

// mockQuerier mocks the auth.Querier interface
type mockQuerier struct {
	mock.Mock
}

func (m *mockQuerier) CreateUser(ctx context.Context, arg database.CreateUserParams) (database.AuthUser, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(database.AuthUser), args.Error(1)
}

func (m *mockQuerier) CreateIdentity(ctx context.Context, arg database.CreateIdentityParams) (database.AuthIdentity, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(database.AuthIdentity), args.Error(1)
}

func (m *mockQuerier) GetIdentityByProvider(ctx context.Context, arg database.GetIdentityByProviderParams) (database.AuthIdentity, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(database.AuthIdentity), args.Error(1)
}

func (m *mockQuerier) GetUserByID(ctx context.Context, id uuid.UUID) (database.AuthUser, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(database.AuthUser), args.Error(1)
}

func (m *mockQuerier) WithTx(tx pgx.Tx) database.Querier {
	args := m.Called(tx)
	return args.Get(0).(database.Querier)
}

func (m *mockQuerier) CreateRefreshToken(ctx context.Context, arg database.CreateRefreshTokenParams) (database.AuthRefreshToken, error) {
	args := m.Called(ctx, arg)
	return args.Get(0).(database.AuthRefreshToken), args.Error(1)
}

func (m *mockQuerier) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (database.AuthRefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	return args.Get(0).(database.AuthRefreshToken), args.Error(1)
}

func (m *mockQuerier) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash)
	return args.Error(0)
}

func (m *mockQuerier) RevokeAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *mockQuerier) ListUserRefreshTokens(ctx context.Context, userID uuid.UUID) ([]database.AuthRefreshToken, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]database.AuthRefreshToken), args.Error(1)
}

func (m *mockQuerier) RevokeUserSession(ctx context.Context, arg database.RevokeUserSessionParams) error {
	args := m.Called(ctx, arg)
	return args.Error(0)
}

// mockJWT mocks JWT operations
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

// mockTokenManager mocks token operations
type mockTokenManager struct {
	mock.Mock
}

func (m *mockTokenManager) Generate() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *mockTokenManager) Hash(token string) (string, error) {
	args := m.Called(token)
	return args.String(0), args.Error(1)
}

// mockIPCrypt mocks IP encryption operations
type mockIPCrypt struct {
	mock.Mock
}

func (m *mockIPCrypt) Encrypt(ip string) (string, error) {
	args := m.Called(ip)
	return args.String(0), args.Error(1)
}

func (m *mockIPCrypt) Decrypt(encrypted string) (string, error) {
	args := m.Called(encrypted)
	return args.String(0), args.Error(1)
}

func TestNewService(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})

		require.NoError(t, err)
		assert.NotNil(t, service)
	})

	t.Run("missing connection", func(t *testing.T) {
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "database connection is required")
	})

	t.Run("missing querier", func(t *testing.T) {
		conn := &mockTxBeginner{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "querier is required")
	})

	t.Run("missing JWT service", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "JWT service is required")
	})

	t.Run("missing logger", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("missing token manager", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "token manager is required")
	})

	t.Run("missing IP encryptor", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "IP encryptor is required")
	})

	t.Run("missing refresh token expiry", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:         conn,
			Querier:      querier,
			JWT:          jwtMock,
			TokenManager: tokenMgr,
			IPCrypt:      ipCrypt,
			Logger:       logger,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "refresh token expiry is required")
	})
}

func TestService_Register(t *testing.T) {
	t.Run("successful registration", func(t *testing.T) {
		ctx := contextWithMetadata("192.168.1.100")

		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		txQuerier := &mockQuerier{}
		tx := &mockTx{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		userID := uuid.New()
		user := database.AuthUser{
			ID:    userID,
			Roles: []string{"user"},
		}
		identity := database.AuthIdentity{
			ID:         uuid.New(),
			UserID:     userID,
			Provider:   "email_password",
			ProviderID: "test@example.com",
		}

		// Mock: Check identity doesn't exist
		querier.On("GetIdentityByProvider", ctx, database.GetIdentityByProviderParams{
			Provider:   "email_password",
			ProviderID: "test@example.com",
		}).Return(database.AuthIdentity{}, pgx.ErrNoRows)

		// Mock: Begin transaction
		conn.On("Begin", ctx).Return(tx, nil)

		// Mock: WithTx returns transaction-aware queries
		querier.On("WithTx", tx).Return(txQuerier)

		// Mock: CreateUser in transaction
		txQuerier.On("CreateUser", ctx, mock.MatchedBy(func(arg database.CreateUserParams) bool {
			return len(arg.Roles) == 1 && arg.Roles[0] == "user"
		})).Return(user, nil)

		// Mock: CreateIdentity in transaction
		txQuerier.On("CreateIdentity", ctx, mock.MatchedBy(func(arg database.CreateIdentityParams) bool {
			return arg.UserID == userID && arg.Provider == "email_password"
		})).Return(identity, nil)

		// Mock: Commit transaction
		tx.On("Commit", ctx).Return(nil)

		// Mock: JWT generation
		jwtMock.On("GenerateToken", userID.String()).Return("test-token", nil)

		// Mock: IP encryption
		ipCrypt.On("Encrypt", "192.168.1.100").Return("encrypted-ip", nil)

		// Mock: Generate refresh token
		tokenMgr.On("Generate").Return("mock-refresh-token", nil)

		// Mock: Hash refresh token
		tokenMgr.On("Hash", "mock-refresh-token").Return("mock-refresh-hash", nil)

		// Mock: Create refresh token in DB
		querier.On("CreateRefreshToken", ctx, mock.MatchedBy(func(arg database.CreateRefreshTokenParams) bool {
			return arg.UserID == userID && arg.TokenHash == "mock-refresh-hash"
		})).Return(database.AuthRefreshToken{
			ID:        uuid.New(),
			UserID:    userID,
			TokenHash: "mock-refresh-hash",
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		}, nil)

		req := auth.RegisterRequest{
			Provider: "email_password",
			Credentials: map[string]any{
				"email":    "test@example.com",
				"password": "SecurePass123!",
			},
		}

		resp, err := service.Register(ctx, req)

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "test-token", resp.AccessToken)
		assert.Equal(t, "mock-refresh-token", resp.RefreshToken)
		assert.Equal(t, userID.String(), resp.User.ID)
		assert.Equal(t, []string{"user"}, resp.User.Roles)

		conn.AssertExpectations(t)
		querier.AssertExpectations(t)
		txQuerier.AssertExpectations(t)
		tx.AssertExpectations(t)
		jwtMock.AssertExpectations(t)
		tokenMgr.AssertExpectations(t)
		ipCrypt.AssertExpectations(t)
	})

	t.Run("assigns default user role", func(t *testing.T) {
		ctx := contextWithMetadata("192.168.1.100")

		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		txQuerier := &mockQuerier{}
		tx := &mockTx{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		userID := uuid.New()
		user := database.AuthUser{
			ID:    userID,
			Roles: []string{"user"},
		}

		querier.On("GetIdentityByProvider", ctx, mock.Anything).Return(database.AuthIdentity{}, pgx.ErrNoRows)
		conn.On("Begin", ctx).Return(tx, nil)
		querier.On("WithTx", tx).Return(txQuerier)

		// Verify that CreateUser is called with exactly ["user"]
		txQuerier.On("CreateUser", ctx, mock.MatchedBy(func(arg database.CreateUserParams) bool {
			if len(arg.Roles) != 1 {
				return false
			}
			return arg.Roles[0] == "user"
		})).Return(user, nil)

		txQuerier.On("CreateIdentity", ctx, mock.Anything).Return(database.AuthIdentity{}, nil)
		tx.On("Commit", ctx).Return(nil)
		jwtMock.On("GenerateToken", userID.String()).Return("test-token", nil)

		ipCrypt.On("Encrypt", "192.168.1.100").Return("encrypted-ip", nil)
		tokenMgr.On("Generate").Return("mock-refresh-token", nil)
		tokenMgr.On("Hash", "mock-refresh-token").Return("mock-refresh-hash", nil)
		querier.On("CreateRefreshToken", ctx, mock.Anything).Return(database.AuthRefreshToken{}, nil)

		req := auth.RegisterRequest{
			Provider: "email_password",
			Credentials: map[string]any{
				"email":    "test@example.com",
				"password": "SecurePass123!",
			},
		}

		resp, err := service.Register(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, []string{"user"}, resp.User.Roles)

		txQuerier.AssertExpectations(t)
	})

	t.Run("user already exists", func(t *testing.T) {
		ctx := context.Background()

		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		existingIdentity := database.AuthIdentity{
			ID:         uuid.New(),
			UserID:     uuid.New(),
			Provider:   "email_password",
			ProviderID: "test@example.com",
		}

		querier.On("GetIdentityByProvider", ctx, database.GetIdentityByProviderParams{
			Provider:   "email_password",
			ProviderID: "test@example.com",
		}).Return(existingIdentity, nil)

		req := auth.RegisterRequest{
			Provider: "email_password",
			Credentials: map[string]any{
				"email":    "test@example.com",
				"password": "SecurePass123!",
			},
		}

		resp, err := service.Register(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, auth.ErrUserExists, err)

		querier.AssertExpectations(t)
	})

	t.Run("invalid provider", func(t *testing.T) {
		ctx := context.Background()

		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		req := auth.RegisterRequest{
			Provider: "invalid_provider",
			Credentials: map[string]any{
				"email": "test@example.com",
			},
		}

		resp, err := service.Register(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, auth.ErrInvalidProvider, err)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		ctx := context.Background()

		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		req := auth.RegisterRequest{
			Provider: "email_password",
			Credentials: map[string]any{
				"email":    "invalid-email",
				"password": "weak",
			},
		}

		resp, err := service.Register(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.True(t, errors.Is(err, auth.ErrInvalidInput))
	})
}

func TestService_Login(t *testing.T) {
	t.Run("invalid provider", func(t *testing.T) {
		ctx := context.Background()

		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		req := auth.LoginRequest{
			Provider: "invalid_provider",
			Credentials: map[string]any{
				"email": "test@example.com",
			},
		}

		resp, err := service.Login(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, auth.ErrInvalidProvider, err)
	})

	t.Run("user not found", func(t *testing.T) {
		ctx := context.Background()

		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		querier.On("GetIdentityByProvider", ctx, database.GetIdentityByProviderParams{
			Provider:   "email_password",
			ProviderID: "nonexistent@example.com",
		}).Return(database.AuthIdentity{}, pgx.ErrNoRows)

		req := auth.LoginRequest{
			Provider: "email_password",
			Credentials: map[string]any{
				"email":    "nonexistent@example.com",
				"password": "SecurePass123!",
			},
		}

		resp, err := service.Login(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, auth.ErrUserNotFound, err)

		querier.AssertExpectations(t)
	})
}

func TestService_GetUserByID(t *testing.T) {
	ctx := context.Background()

	t.Run("valid user ID", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		userID := uuid.New()
		expectedUser := database.AuthUser{
			ID:    userID,
			Roles: []string{"user", "admin"},
		}

		querier.On("GetUserByID", ctx, userID).Return(expectedUser, nil)

		user, err := service.GetUserByID(ctx, userID.String())

		require.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, expectedUser.ID, user.ID)
		assert.Equal(t, expectedUser.Roles, user.Roles)

		querier.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		userID := uuid.New()

		querier.On("GetUserByID", ctx, userID).Return(database.AuthUser{}, pgx.ErrNoRows)

		user, err := service.GetUserByID(ctx, userID.String())

		require.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, auth.ErrUserNotFound, err)

		querier.AssertExpectations(t)
	})

	t.Run("invalid user ID format", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		user, err := service.GetUserByID(ctx, "invalid-uuid")

		require.Error(t, err)
		assert.Nil(t, user)
		assert.Contains(t, err.Error(), "invalid user ID")
	})
}

func TestService_Refresh(t *testing.T) {
	t.Run("successful token refresh", func(t *testing.T) {
		ctx := contextWithMetadata("192.168.1.100")

		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		userID := uuid.New()
		user := database.AuthUser{
			ID:    userID,
			Roles: []string{"user"},
		}

		oldTokenHash := "old-token-hash"
		sessionStartTime := time.Now().Add(-24 * time.Hour)

		// Create metadata with session_start_time
		metadata := map[string]any{
			"encrypted_ip":       "old-encrypted-ip",
			"session_start_time": sessionStartTime.Format(time.RFC3339),
		}
		metadataBytes, _ := json.Marshal(metadata)

		storedToken := database.AuthRefreshToken{
			ID:        uuid.New(),
			UserID:    userID,
			TokenHash: oldTokenHash,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			Metadata:  metadataBytes,
		}

		// Mock: Hash the provided token
		tokenMgr.On("Hash", "old-refresh-token").Return(oldTokenHash, nil)

		// Mock: Get stored token
		querier.On("GetRefreshTokenByHash", ctx, oldTokenHash).Return(storedToken, nil)

		// Mock: Revoke old token
		querier.On("RevokeRefreshToken", ctx, oldTokenHash).Return(nil)

		// Mock: Get user
		querier.On("GetUserByID", ctx, userID).Return(user, nil)

		// Mock: Generate new access token
		jwtMock.On("GenerateToken", userID.String()).Return("new-access-token", nil)

		// Mock: IP encryption for new token
		ipCrypt.On("Encrypt", "192.168.1.100").Return("new-encrypted-ip", nil)

		// Mock: Generate new refresh token
		tokenMgr.On("Generate").Return("new-refresh-token", nil)
		tokenMgr.On("Hash", "new-refresh-token").Return("new-token-hash", nil)
		querier.On("CreateRefreshToken", ctx, mock.Anything).Return(database.AuthRefreshToken{}, nil)

		resp, err := service.Refresh(ctx, "old-refresh-token")

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "new-access-token", resp.AccessToken)
		assert.Equal(t, "new-refresh-token", resp.RefreshToken)
		assert.Equal(t, userID.String(), resp.User.ID)

		querier.AssertExpectations(t)
		tokenMgr.AssertExpectations(t)
		jwtMock.AssertExpectations(t)
		ipCrypt.AssertExpectations(t)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		ctx := context.Background()

		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		tokenMgr.On("Hash", "invalid-token").Return("invalid-hash", nil)
		querier.On("GetRefreshTokenByHash", ctx, "invalid-hash").Return(database.AuthRefreshToken{}, pgx.ErrNoRows)

		resp, err := service.Refresh(ctx, "invalid-token")

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, auth.ErrInvalidToken, err)

		querier.AssertExpectations(t)
		tokenMgr.AssertExpectations(t)
	})

	t.Run("expired refresh token", func(t *testing.T) {
		ctx := context.Background()

		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		userID := uuid.New()
		tokenHash := "expired-token-hash"
		expiredToken := database.AuthRefreshToken{
			ID:        uuid.New(),
			UserID:    userID,
			TokenHash: tokenHash,
			ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired yesterday
		}

		tokenMgr.On("Hash", "expired-refresh-token").Return(tokenHash, nil)
		querier.On("GetRefreshTokenByHash", ctx, tokenHash).Return(expiredToken, nil)

		resp, err := service.Refresh(ctx, "expired-refresh-token")

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, auth.ErrInvalidToken, err)

		querier.AssertExpectations(t)
		tokenMgr.AssertExpectations(t)
	})
}

func TestService_Logout(t *testing.T) {
	ctx := context.Background()

	t.Run("successful logout", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		tokenHash := "token-hash"

		tokenMgr.On("Hash", "refresh-token").Return(tokenHash, nil)
		querier.On("RevokeRefreshToken", ctx, tokenHash).Return(nil)

		err = service.Logout(ctx, "refresh-token")

		require.NoError(t, err)

		querier.AssertExpectations(t)
		tokenMgr.AssertExpectations(t)
	})

	t.Run("logout with invalid token", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		tokenMgr.On("Hash", "invalid-token").Return("", errors.New("hash error"))

		err = service.Logout(ctx, "invalid-token")

		require.Error(t, err)
		assert.Equal(t, auth.ErrInvalidToken, err)

		tokenMgr.AssertExpectations(t)
	})
}

func TestService_ListUserSessions(t *testing.T) {
	ctx := context.Background()

	t.Run("successful list with multiple sessions", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		userID := uuid.New()
		// truncate so second precision since RFC3339 doesn't preserve nanoseconds
		now := time.Now().UTC().Truncate(time.Second)
		sessionStart := now.Add(-48 * time.Hour).Truncate(time.Second)

		// Create metadata for tokens
		metadata1 := map[string]any{
			"encrypted_ip":       "encrypted-ip-1",
			"session_start_time": sessionStart.Format(time.RFC3339),
		}
		metadata1Bytes, _ := json.Marshal(metadata1)

		metadata2 := map[string]any{
			"encrypted_ip":       "encrypted-ip-2",
			"session_start_time": sessionStart.Add(1 * time.Hour).Format(time.RFC3339),
		}
		metadata2Bytes, _ := json.Marshal(metadata2)

		tokens := []database.AuthRefreshToken{
			{
				ID:         uuid.New(),
				UserID:     userID,
				TokenHash:  "hash1",
				ExpiresAt:  now.Add(24 * time.Hour),
				Metadata:   metadata1Bytes,
				LastUsedAt: &now,
				CreatedAt:  sessionStart,
			},
			{
				ID:         uuid.New(),
				UserID:     userID,
				TokenHash:  "hash2",
				ExpiresAt:  now.Add(48 * time.Hour),
				Metadata:   metadata2Bytes,
				LastUsedAt: &now,
				CreatedAt:  sessionStart.Add(1 * time.Hour),
			},
		}

		querier.On("ListUserRefreshTokens", ctx, userID).Return(tokens, nil)
		ipCrypt.On("Decrypt", "encrypted-ip-1").Return("192.168.1.100", nil)
		ipCrypt.On("Decrypt", "encrypted-ip-2").Return("10.0.0.50", nil)

		sessions, err := service.ListUserSessions(ctx, userID.String())

		require.NoError(t, err)
		assert.Len(t, sessions, 2)

		// Check first session
		assert.Equal(t, tokens[0].ID.String(), sessions[0].ID)
		assert.Equal(t, "192.168.1.*", sessions[0].ClientIP) // Masked
		assert.Equal(t, now, sessions[0].LastUsedAt)
		assert.Equal(t, sessionStart, sessions[0].SessionStart)
		assert.Equal(t, tokens[0].ExpiresAt, sessions[0].ExpiresAt)

		// Check second session
		assert.Equal(t, tokens[1].ID.String(), sessions[1].ID)
		assert.Equal(t, "10.0.0.*", sessions[1].ClientIP) // Masked

		querier.AssertExpectations(t)
		ipCrypt.AssertExpectations(t)
	})

	t.Run("no active sessions", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		userID := uuid.New()

		querier.On("ListUserRefreshTokens", ctx, userID).Return([]database.AuthRefreshToken{}, nil)

		sessions, err := service.ListUserSessions(ctx, userID.String())

		require.NoError(t, err)
		assert.Empty(t, sessions)

		querier.AssertExpectations(t)
	})

	t.Run("invalid user ID", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		sessions, err := service.ListUserSessions(ctx, "invalid-uuid")

		require.Error(t, err)
		assert.Nil(t, sessions)
		assert.Contains(t, err.Error(), "invalid user ID")
	})
}

func TestService_RevokeSession(t *testing.T) {
	ctx := context.Background()

	t.Run("successful revocation", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		userID := uuid.New()
		sessionID := uuid.New()

		querier.On("RevokeUserSession", ctx, database.RevokeUserSessionParams{
			ID:     sessionID,
			UserID: userID,
		}).Return(nil)

		err = service.RevokeSession(ctx, userID.String(), sessionID.String())

		require.NoError(t, err)
		querier.AssertExpectations(t)
	})

	t.Run("invalid user ID", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		sessionID := uuid.New()

		err = service.RevokeSession(ctx, "invalid-uuid", sessionID.String())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user ID")
	})

	t.Run("invalid session ID", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		tokenMgr := &mockTokenManager{}
		ipCrypt := &mockIPCrypt{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:               conn,
			Querier:            querier,
			JWT:                jwtMock,
			TokenManager:       tokenMgr,
			IPCrypt:            ipCrypt,
			Logger:             logger,
			RefreshTokenExpiry: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)

		userID := uuid.New()

		err = service.RevokeSession(ctx, userID.String(), "invalid-uuid")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session ID")
	})
}
