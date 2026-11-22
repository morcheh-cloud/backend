-- +goose Up
-- Personal access tokens: "morche_" + 40 base62 characters, shown once; only
-- the SHA-256 is kept. A token acts as its user (same grants, same blocking).
CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text NOT NULL,
    -- The first 8 characters after "morche_", to tell tokens apart.
    prefix       text NOT NULL,
    token_hash   bytea NOT NULL UNIQUE,
    read_only    boolean NOT NULL DEFAULT false,
    expires_at   timestamptz,
    last_used_at timestamptz,
    last_used_ip text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX api_tokens_user_idx ON api_tokens (user_id, created_at DESC);

-- +goose Down
DROP TABLE api_tokens;
