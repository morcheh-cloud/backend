-- +goose Up
-- Compose projects Morche keeps track of outside the workspace's projects
-- folder: found by a scan of the server's disk, added by path, or seen once
-- through their containers (so they stay listed after `down`). `hidden` =
-- the person chose to forget it; a scan then leaves it out.
CREATE TABLE docker_project_places (
    server_id     uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    project       text NOT NULL,
    dir           text NOT NULL,
    files         text[] NOT NULL DEFAULT '{}',
    source        text NOT NULL CHECK (source IN ('scan', 'added', 'containers')),
    hidden        boolean NOT NULL DEFAULT false,
    added_by_name text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, project)
);

-- The last look for compose files on a server's disk.
CREATE TABLE docker_project_scans (
    server_id  uuid PRIMARY KEY REFERENCES servers (id) ON DELETE CASCADE,
    scanned_at timestamptz NOT NULL DEFAULT now(),
    took_ms    integer NOT NULL DEFAULT 0,
    items      jsonb NOT NULL DEFAULT '[]',
    truncated  boolean NOT NULL DEFAULT false,
    error      text NOT NULL DEFAULT ''
);

-- +goose Down
DROP TABLE docker_project_scans;
DROP TABLE docker_project_places;
