-- +goose Up
-- Authoritative DNS servers (Technitium) Morcheh talks to through their API.
-- Zones and records live on those servers; only the connection is kept here.
CREATE TABLE dns_servers (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name            text NOT NULL,
    url             text NOT NULL,
    token_enc       bytea NOT NULL,
    tls_skip_verify boolean NOT NULL DEFAULT false,
    allow_internal  boolean NOT NULL DEFAULT false,
    description     text NOT NULL DEFAULT '',
    favorite        boolean NOT NULL DEFAULT false,
    status          text NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('unknown', 'online', 'unreachable', 'auth_failed', 'tls_error', 'blocked', 'error')),
    status_message  text NOT NULL DEFAULT '',
    version         text NOT NULL DEFAULT '',
    server_domain   text NOT NULL DEFAULT '',
    zone_count      integer NOT NULL DEFAULT 0,
    latency_ms      integer,
    last_checked_at timestamptz,
    last_online_at  timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX dns_servers_name_key ON dns_servers (workspace_id, lower(name));

-- +goose Down
DROP TABLE dns_servers;
