// Package testhelpers provides common utilities for integration and E2E tests.
package testhelpers

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// findProjectRoot walks up the directory tree to find the project root.
// It specifically looks for go.mod (as it should be in the project root).
// NOTE: Added this because running a single package test was breaking.
// e.g. `go test ./internal/api/handlers` would fail due to the migration dir
// being then wrongly deemed to be 'internal/api/handlers/internal/database/migrations/',
// rather than 'internal/database/migrations/'.
func findProjectRoot(t *testing.T) (string, error) {
	t.Helper()

	// Start from the current working dir
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	// Walk up until we find go.mod
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			// go.mod found, so this is the project root
			return dir, nil
		}

		// Move up one
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding go.mod
			return "", fmt.Errorf("could not find go.mod (project root)")
		}
		dir = parent
	}
}

// RunGooseMigrations applies all Goose migrations from the project's migration
// directory to a test database.
func RunGooseMigrations(t *testing.T, connString string) error {
	t.Helper()

	// Open db connection
	db, err := sql.Open("pgx", connString)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	defer func() {
		_ = db.Close()
	}()

	// Verify connection works
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	projectRoot, err := findProjectRoot(t)
	if err != nil {
		return fmt.Errorf("failed to find project root: %w", err)
	}
	migrationDir := filepath.Join(projectRoot, "internal", "database", "migrations")

	// Run migrations
	if err := goose.Up(db, migrationDir); err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	t.Log("All Goose migrations applied successfully")
	return nil
}
