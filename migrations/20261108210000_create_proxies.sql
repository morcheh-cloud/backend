-- +goose Up
-- A reverse proxy Morcheh manages on one of the panel's servers, over SSH.
-- kind picks the driver (nginx first; Caddy, Traefik… later).
CREATE TABLE proxies (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    server_id       uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('nginx')),
    status          text NOT NULL DEFAULT 'unknown' CHECK (status IN (
        'unknown', 'online', 'stopped', 'not_installed', 'not_set_up',
        'config_error', 'unreachable', 'error')),
    status_message  text NOT NULL DEFAULT '',
    version         text NOT NULL DEFAULT '',
    host_problems   int NOT NULL DEFAULT 0,
    last_checked_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (server_id, kind)
);

-- A site the proxy serves: the kind-neutral model in config, rendered by the
-- driver into its own files.
CREATE TABLE proxy_hosts (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    proxy_id        uuid NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
    domains         text[] NOT NULL,
    enabled         boolean NOT NULL DEFAULT true,
    config          jsonb NOT NULL,
    note            text NOT NULL DEFAULT '',
    created_by_name text NOT NULL DEFAULT '',
    updated_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX proxy_hosts_proxy_idx ON proxy_hosts (proxy_id);

-- What changed, with every host as it was afterwards, so any point can be
-- put back.
CREATE TABLE proxy_changes (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    proxy_id   uuid NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
    user_id    uuid REFERENCES users (id) ON DELETE SET NULL,
    user_name  text NOT NULL DEFAULT '',
    summary    text NOT NULL,
    hosts      jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX proxy_changes_proxy_idx ON proxy_changes (proxy_id, created_at DESC);

-- +goose Down
DROP TABLE proxy_changes;
DROP TABLE proxy_hosts;
DROP TABLE proxies;
