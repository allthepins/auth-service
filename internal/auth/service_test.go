package auth_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/allthepins/auth-service/internal/auth"
	"github.com/allthepins/auth-service/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

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

func TestNewService(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
		})

		require.NoError(t, err)
		assert.NotNil(t, service)
	})

	t.Run("missing connection", func(t *testing.T) {
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "database connection is required")
	})

	t.Run("missing querier", func(t *testing.T) {
		conn := &mockTxBeginner{}
		jwtMock := &mockJWT{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:   conn,
			JWT:    jwtMock,
			Logger: logger,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "querier is required")
	})

	t.Run("missing JWT service", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			Logger:  logger,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "JWT service is required")
	})

	t.Run("missing logger", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
		})

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

func TestService_Register(t *testing.T) {
	ctx := context.Background()

	t.Run("successful registration", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		txQuerier := &mockQuerier{}
		tx := &mockTx{}
		jwtMock := &mockJWT{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
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
		assert.Equal(t, userID.String(), resp.UserID)
		assert.Equal(t, []string{"user"}, resp.Roles)

		conn.AssertExpectations(t)
		querier.AssertExpectations(t)
		txQuerier.AssertExpectations(t)
		tx.AssertExpectations(t)
		jwtMock.AssertExpectations(t)
	})

	t.Run("user already exists", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
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
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
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
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
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
	ctx := context.Background()

	t.Run("invalid provider", func(t *testing.T) {
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
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
		conn := &mockTxBeginner{}
		querier := &mockQuerier{}
		jwtMock := &mockJWT{}
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
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
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
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
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
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
		logger := slog.Default()

		service, err := auth.NewService(auth.Config{
			Conn:    conn,
			Querier: querier,
			JWT:     jwtMock,
			Logger:  logger,
		})
		require.NoError(t, err)

		user, err := service.GetUserByID(ctx, "invalid-uuid")

		require.Error(t, err)
		assert.Nil(t, user)
		assert.Contains(t, err.Error(), "invalid user ID")
	})
}
