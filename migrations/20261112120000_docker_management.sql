-- +goose Up

-- Container management beyond what the engine itself keeps: registries to
-- pull from, compose templates, per-workspace settings, and what Morche
-- learned about each server's images (newer versions, known vulnerabilities).

-- A registry login for a workspace. Used for pulls, update checks and
-- compose projects on every server of the workspace.
CREATE TABLE docker_registries (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    -- The registry's host as image names spell it: docker.io, ghcr.io,
    -- registry.example.com:5000.
    address      text NOT NULL CHECK (length(address) BETWEEN 1 AND 255),
    username     text NOT NULL DEFAULT '' CHECK (length(username) <= 255),
    password_enc bytea,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX docker_registries_address_key ON docker_registries (workspace_id, lower(address));

-- A compose file a workspace keeps to start new projects from. Built-in
-- templates live in the code.
CREATE TABLE docker_templates (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    category        text NOT NULL DEFAULT '' CHECK (length(category) <= 50),
    compose         text NOT NULL CHECK (length(compose) BETWEEN 1 AND 200000),
    env             text NOT NULL DEFAULT '' CHECK (length(env) <= 50000),
    created_by_name text NOT NULL DEFAULT '',
    updated_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX docker_templates_name_key ON docker_templates (workspace_id, lower(name));

CREATE TABLE docker_settings (
    workspace_id  uuid PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
    -- Where new compose projects go on a server (one folder per project).
    projects_dir  text NOT NULL DEFAULT '/opt/morche/projects',
    -- Look for newer images once a day on every server with Docker.
    update_check  boolean NOT NULL DEFAULT true,
    -- The image that scans for vulnerabilities when the server has no trivy.
    scanner_image text NOT NULL DEFAULT 'aquasec/trivy:latest',
    -- Docker events kept back in the event log, in hours (the engine keeps
    -- them in memory only; this just bounds what is asked for).
    events_hours  int NOT NULL DEFAULT 24 CHECK (events_hours BETWEEN 1 AND 720),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- What the registry has for an image a server runs, last time Morche asked.
CREATE TABLE docker_image_updates (
    server_id     uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    -- The reference as containers name it: nginx:1.27, ghcr.io/org/app.
    image         text NOT NULL,
    local_digest  text NOT NULL DEFAULT '',
    remote_digest text NOT NULL DEFAULT '',
    -- current | available | error | local (built here, no registry copy)
    state         text NOT NULL,
    error         text NOT NULL DEFAULT '',
    checked_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, image)
);

-- The newest vulnerability scan of an image on a server.
CREATE TABLE docker_image_scans (
    server_id  uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    image_id   text NOT NULL,
    image      text NOT NULL DEFAULT '',
    critical   int NOT NULL DEFAULT 0,
    high       int NOT NULL DEFAULT 0,
    medium     int NOT NULL DEFAULT 0,
    low        int NOT NULL DEFAULT 0,
    unknown    int NOT NULL DEFAULT 0,
    fixable    int NOT NULL DEFAULT 0,
    -- The findings, worst first (capped).
    findings   jsonb NOT NULL DEFAULT '[]',
    scanner    text NOT NULL DEFAULT '',
    error      text NOT NULL DEFAULT '',
    scanned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, image_id)
);

-- +goose Down
DROP TABLE docker_image_scans;
DROP TABLE docker_image_updates;
DROP TABLE docker_settings;
DROP TABLE docker_templates;
DROP TABLE docker_registries;
