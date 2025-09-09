# Auth Service

A token-based authentication service for managing user identity, authentication and sessions for web and mobile clients.

***

## Getting started

### Prerequisites

* Go 1.24+
* Docker
* [Goose](https://github.com/pressly/goose)
* [sqlc](https://sqlc.dev/)

### Local setup

1. **Configure environment variables:**
  ```sh
  cp .env.example .env
  ```
  Review and update the vars in the `.env` file with your values.

2. **Start the services:**
  ```sh
  make up
  ```
  This builds the go container and starts the API and Postgres services.

3. **Run database migrations:**
  ```sh
  make migrate-up
  ```

The API service should now be running ans accessible at `http://localhost:8080`.

*** 

## Makefile usage

A `Makefile` provides shortcuts for running (some) tasks.

Run `make help` for a descriptive list of what's available.

***

## Development roadmap

### Phase 1: MVP

#### Scaffolding and environment
- [x] Initialize Go project and initial directory structure.
- [x] Configure Docker Compose with go and postgres services.

#### Database
- [x] Implement initial schema migrations (`users`, `identities`) with `goose`.
- [x] Configure `sqlc` and generate initial queriers.

#### Core logic & platform
- [ ] Implement structured logger (use `slog`).
- [ ] Implement RSA-based JWT platform (`RS256` so the public key can later be shared for decentralized JWT validation).
- [ ] Implement `auth.Service` for email/password registration and login.
- [ ] Add unit tests for the `auth.Service`.

#### API endpoints
- [ ] Implement public handlers for `/auth/register` and `/auth/login`.
- [ ] Wire up all components in `main.go`.
- [ ] Add unit tests for the API handlers.

### Phase 2: Security & core features

#### Middleware
- [ ] Implement centralized middleware for request logging.
- [ ] Implement `Authenticate` middleware for JWT validation.
- [ ] Implement panic recovery middleware.
- [ ] Add unit tests for all middleware.

#### Session lifecycle
- [ ] Add `refresh_tokens` table migration.
- [ ] Implement refresh token rotation logic in the `auth.Service`.
- [ ] Implement the `POST /auth/refresh` and `POST /auth/logout` endpoints.

#### Session management
- [ ] Add `metadata` column to `refresh_tokens` table.
- [ ] Implement service logic for listing and revoking sessions.
- [ ] Implement the protected `GET /auth/sessions` and `DELETE /auth/sessions/{id}` endpoints.

### Phase 3: Feature expansion

#### Additional providers
- [ ] Add `otp_requests` table.
- [ ] Implement `username` and `email-otp` provider logic.
- [ ] Implement third-party provider logic (e.g. google).
- [ ] Refactor handlers to support polymorphic provider payloads.

#### Token validation endpoints
- [ ] Implement `/.well-known/jwks.json` endpoint (for public keys used to sign JWTs).
- [ ] Implement `/auth/validate` endpoint.

#### Account recovery
- [ ] Add `password_reset_tokens` table.
- [ ] Implement `ForgotPassword` and `ResetPassword` service logic.
- [ ] Implement the `POST /forgot-password` and `POST /reset-password` endpoints.

#### Polish
- [ ] Implement structured configuration from environment variables.
- [ ] Write comprehensive integration tests for all API flows.
- [ ] Revisit and finalize documentation and `Makefile` scripts.
