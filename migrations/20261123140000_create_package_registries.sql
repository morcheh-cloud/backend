-- +goose Up

-- A package registry Morche deployed on one of the workspace's servers
-- (Harbor for container images, Verdaccio for npm), set up and managed
-- through the registry's own API or its files.
CREATE TABLE package_registries (
    id                 uuid PRIMARY KEY DEFAULT uuidv7(),
    server_id          uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    kind               text NOT NULL CHECK (kind IN ('harbor', 'verdaccio')),
    name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    note               text NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
    -- The compose project it runs as, and its folder on the server.
    project            text NOT NULL,
    dir                text NOT NULL,
    -- The port it listens on, on the server's loopback (127.0.0.1).
    port               integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    -- The name clients use (registry.example.com), '' = only the port.
    domain             text NOT NULL DEFAULT '',
    https              boolean NOT NULL DEFAULT false,
    version            text NOT NULL DEFAULT '',
    admin_user         text NOT NULL DEFAULT 'admin',
    admin_secret_enc   bytea,
    -- The reverse proxy site and the Containers registry login made for it.
    proxy_host_id      uuid REFERENCES proxy_hosts (id) ON DELETE SET NULL,
    docker_registry_id uuid REFERENCES docker_registries (id) ON DELETE SET NULL,
    -- Kind settings (mirror, scanner, read access, private scopes…).
    settings           jsonb NOT NULL DEFAULT '{}',
    -- deploying | ready | failed | removing
    state              text NOT NULL DEFAULT 'deploying' CHECK (state IN ('deploying', 'ready', 'failed', 'removing')),
    -- What the last health check saw: unknown | online | degraded | down
    health             text NOT NULL DEFAULT 'unknown',
    problem            text NOT NULL DEFAULT '',
    job_id             uuid,
    usage_bytes        bigint NOT NULL DEFAULT 0,
    items              integer NOT NULL DEFAULT 0,
    checked_at         timestamptz,
    created_by_name    text NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- Harbor's containers have fixed names: one per server.
CREATE UNIQUE INDEX package_registries_harbor_key ON package_registries (server_id) WHERE kind = 'harbor';
CREATE UNIQUE INDEX package_registries_project_key ON package_registries (server_id, project);

-- +goose Down
DROP TABLE package_registries;
