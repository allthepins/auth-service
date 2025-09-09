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
