-- +goose Up
-- +goose StatementBegin
ALTER TABLE "auth.refresh_tokens" 
ADD COLUMN last_used_at TIMESTAMPTZ,
ADD COLUMN metadata JSONB DEFAULT '{}';

-- Index for querying by last_used_at
CREATE INDEX idx_refresh_tokens_last_used 
ON "auth.refresh_tokens"(last_used_at) 
WHERE revoked_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_refresh_tokens_last_used;

ALTER TABLE "auth.refresh_tokens" 
DROP COLUMN IF EXISTS metadata,
DROP COLUMN IF EXISTS last_used_at;
-- +goose StatementEnd
