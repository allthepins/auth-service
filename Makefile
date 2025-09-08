# Load environment variables from the .env file for use in this Makefile
include .env
export

# Define the database connection string from the .env file
DATABASE_URL := $(shell grep '^DATABASE_URL=' .env | sed 's/^DATABASE_URL=//; s/^"//; s/"$$//')

.PHONY: help up down build logs migrate-up migrate-down migrate-create sqlc run test lint tidy clean

help: ## Show help message
	@echo "Usage: make <target>"
	@echo ""
	@echo "Available targets:"
	@awk -F':|##' '/^[a-zA-Z_-]+:.*##/ { \
		printf "\033[36m%-20s\033[0m %s\n", $$1, $$3 \
	}' $(MAKEFILE_LIST)

# ==============================================================================
# Docker Management
# ==============================================================================

up: ## Start all services in the background using Docker Compose
	@echo "Starting Docker containers..."
	@docker compose up -d --build

down: ## Stop and remove all services defined in Docker Compose
	@echo "Stopping Docker containers..."
	@docker compose down

# ==============================================================================
# Database Migrations (Goose)
# ==============================================================================

migrate-up: ## Apply all pending Goose migrations inside Docker
	@docker run --rm \
		--network auth_service_default \
		--env-file .env \
		-v $$PWD:/app \
		-w /app \
		golang:1.24.5-alpine \
		sh -c "go install github.com/pressly/goose/v3/cmd/goose@latest && goose -dir internal/database/migrations postgres \"$$DATABASE_URL\" up"

migrate-down: ## Roll back the last Goose migration inside Docker
	@docker run --rm \
		--network auth_service_default \
		--env-file .env \
		-v $$PWD:/app \
		-w /app \
		golang:1.24.5-alpine \
		sh -c "go install github.com/pressly/goose/v3/cmd/goose@latest && goose -dir internal/database/migrations postgres \"$$DATABASE_URL\" down"

# ==============================================================================
# Go Development
# ==============================================================================

run: ## Run the API service locally (outside of Docker)
	@echo "Running the Go application..."
	@go run ./cmd/api

test: ## Run all Go tests
	@echo "Running tests..."
	@go test -v ./...

tidy: ## Tidy the go.mod and go.sum files
	@echo "Tidying modules..."
	@go mod tidy

clean: ## Remove the compiled application binary
	@echo "Cleaning up..."
	@rm -f auth-service
