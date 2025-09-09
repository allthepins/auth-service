-- +goose Up
-- +goose StatementBegin
CREATE TABLE "auth.users" (
    id UUID PRIMARY KEY,
    roles TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE "auth.identities" (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES "auth.users"(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    credentials JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE "auth.identities";
DROP TABLE "auth.users";
-- +goose StatementEnd
