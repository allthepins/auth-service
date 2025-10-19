-- +goose Up
-- +goose StatementBegin
CREATE TABLE "auth.refresh_tokens" (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES "auth.users"(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(token_hash)
);

-- Index for finding active tokens by user
CREATE INDEX idx_refresh_tokens_user_active
ON "auth.refresh_tokens"(user_id)
WHERE revoked_at IS NULL;

-- Index for token lookup
CREATE INDEX idx_refresh_tokens_hash
ON "auth.refresh_tokens"(token_hash)
WHERE revoked_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE "auth.refresh_tokens";
-- +goose StatementEnd
