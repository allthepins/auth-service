package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/allthepins/auth-service/internal/api/handlers"
	"github.com/allthepins/auth-service/internal/api/middleware"
	"github.com/allthepins/auth-service/internal/auth"
	"github.com/allthepins/auth-service/internal/config"
	"github.com/allthepins/auth-service/internal/database"
	"github.com/allthepins/auth-service/internal/platform/ipcrypt"
	"github.com/allthepins/auth-service/internal/platform/jwt"
	"github.com/allthepins/auth-service/internal/platform/logger"
	"github.com/allthepins/auth-service/internal/platform/token"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httplog/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Init logger
	log := logger.New("auth-service")
	log.Info("starting auth-service", "port", cfg.Server.Port)

	// Init DB connection
	dbPool, err := pgxpool.New(context.Background(), cfg.Database.URL)
	if err != nil {
		log.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	// Verify DB connection
	if err := dbPool.Ping(context.Background()); err != nil {
		log.Error("failed to ping database", "error", err)
		os.Exit(1)
	}
	log.Info("established database connection")

	// Init JWT service
	jwtAuth, err := jwt.New(
		cfg.JWT.Secret,
		cfg.JWT.Issuer,
		cfg.JWT.Audience,
		cfg.JWT.ExpiryMinutes,
	)
	if err != nil {
		log.Error("failed to initialize JWT service", "error", err)
		os.Exit(1)
	}

	// Init token manager
	tokenManager := token.New()

	// Init IP encryptor
	ipEncryptor, err := ipcrypt.New(cfg.Auth.IPCryptKey)
	if err != nil {
		log.Error("failed to initialize IP encryptor", "error", err)
		os.Exit(1)
	}

	// Init DB queries
	// NOTE: database.Queries.WithTx returns *Queries, but auth.Querier expects
	// WithTx to return database.Querier. This thin adapter bridges the gap.
	// TODO: Consider refactoring auth.Querier interface to avoid needing this wrapper.
	queries := &queryAdapter{database.New(dbPool)}

	// Init auth service
	authService, err := auth.NewService(auth.Config{
		Conn:               dbPool,
		Querier:            queries,
		JWT:                jwtAuth,
		TokenManager:       tokenManager,
		IPCrypt:            ipEncryptor,
		Logger:             log,
		RefreshTokenExpiry: cfg.Auth.RefreshTokenExpiry,
	})
	if err != nil {
		log.Error("failed to initialize auth service", "error", err)
		os.Exit(1)
	}

	// Init handlers
	authHandler := handlers.NewAuthHandler(authService, log)

	// Setup router
	r := chi.NewRouter()

	// CORS middleware
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.Server.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Global middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.ExtractRequestMetadata)
	r.Use(httplog.RequestLogger(log, &httplog.Options{
		Level:         slog.LevelInfo,
		Schema:        httplog.SchemaOTEL,
		RecoverPanics: true,
	}))

	// Health check endpoint
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Public routes
	r.Post("/auth/register", authHandler.Register)
	r.Post("/auth/login", authHandler.Login)
	r.Post("/auth/refresh", authHandler.Refresh)
	r.Post("/auth/logout", authHandler.Logout)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.Auth(jwtAuth, log))
		r.Get("/auth/sessions", authHandler.ListSessions)
		r.Delete("/auth/sessions/{sessionId}", authHandler.RevokeSession)
	})

	// Start server
	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	log.Info("server listening", "address", addr, "allowed_origins", cfg.Server.AllowedOrigins)

	if err := http.ListenAndServe(addr, r); err != nil {
		log.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// queryAdapter is a thin wrapper around database.Queries that satisfies auth.Querier.
// We need it because sqlc generates WithTx returning *Queries, but auth.Querier
// expects WithTx to return the database.Querier interface.
type queryAdapter struct {
	*database.Queries
}

func (qa *queryAdapter) WithTx(tx pgx.Tx) database.Querier {
	return &queryAdapter{qa.Queries.WithTx(tx)}
}
