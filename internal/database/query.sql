-- name: CreateUser :one
INSERT INTO "auth.users" (id, roles)
VALUES ($1, $2)
RETURNING *;

-- name: CreateIdentity :one
INSERT INTO "auth.identities" (id, user_id, provider, provider_id, credentials)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetIdentityByProvider :one
SELECT * FROM "auth.identities"
WHERE provider = $1 AND provider_id = $2
LIMIT 1;

-- name: GetUserByID :one
SELECT * FROM "auth.users"
WHERE id = $1
LIMIT 1;

-- name: CreateRefreshToken :one
INSERT INTO "auth.refresh_tokens" (id, user_id, token_hash, expires_at, last_used_at, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM "auth.refresh_tokens"
WHERE token_hash = $1 AND revoked_at IS NULL
LIMIT 1;

-- name: RevokeRefreshToken :exec
UPDATE "auth.refresh_tokens"
SET revoked_at = NOW()
where token_hash = $1;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE "auth.refresh_tokens"
SET revoked_at = NOW()
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: ListUserRefreshTokens :many
SELECT * FROM "auth.refresh_tokens"
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY last_used_at DESC;

-- name: RevokeUserSession :exec
UPDATE "auth.refresh_tokens"
SET revoked_at = NOW()
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;
