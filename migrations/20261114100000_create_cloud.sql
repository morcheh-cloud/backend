-- +goose Up
-- Cloud provider accounts (an API key each). Servers live at the provider
-- and are read live; only the key, its last check and a few counts are kept.
-- allow_changes = false keeps an account view-only: no power or rename.
CREATE TABLE cloud_accounts (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    provider        text NOT NULL CHECK (provider IN ('arvan')),
    name            text NOT NULL,
    api_key_enc     bytea NOT NULL,
    key_hint        text NOT NULL DEFAULT '',
    description     text NOT NULL DEFAULT '',
    favorite        boolean NOT NULL DEFAULT false,
    allow_changes   boolean NOT NULL DEFAULT false,
    status          text NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('unknown', 'online', 'unreachable', 'auth_failed', 'tls_error', 'blocked', 'error')),
    status_message  text NOT NULL DEFAULT '',
    server_count    integer NOT NULL DEFAULT 0,
    running_count   integer NOT NULL DEFAULT 0,
    latency_ms      integer,
    last_checked_at timestamptz,
    last_online_at  timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX cloud_accounts_name_key ON cloud_accounts (workspace_id, lower(name));

-- +goose Down
DROP TABLE cloud_accounts;
