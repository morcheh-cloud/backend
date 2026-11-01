-- +goose Up

-- Folders nest freely (parent_id); a server sits in at most one folder.
CREATE TABLE folders (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    parent_id  uuid REFERENCES folders (id) ON DELETE SET NULL,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Sibling folders can't share a name (case-insensitive); top level included.
CREATE UNIQUE INDEX folders_parent_name_key ON folders (parent_id, lower(name)) NULLS NOT DISTINCT;

-- Servers reachable over SSH. Secrets are AES-GCM sealed by the API
-- (internal/secrets) and never leave it. os_* and status are filled in by
-- connection checks.
CREATE TABLE servers (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    folder_id        uuid REFERENCES folders (id) ON DELETE SET NULL,
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    host             text NOT NULL,
    port             integer NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
    username         text NOT NULL,
    auth_method      text NOT NULL CHECK (auth_method IN ('password', 'private_key')),
    password_enc     bytea,
    private_key_enc  bytea,
    passphrase_enc   bytea,
    -- Trust on first use: the key seen on the first successful check, in
    -- authorized_keys format. A later mismatch fails the check.
    host_key         text NOT NULL DEFAULT '',
    description      text NOT NULL DEFAULT '',
    tags             text[] NOT NULL DEFAULT '{}',
    favorite         boolean NOT NULL DEFAULT false,
    status           text NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('unknown', 'online', 'unreachable', 'auth_failed', 'host_key_mismatch', 'error')),
    status_message   text NOT NULL DEFAULT '',
    latency_ms       integer,
    os_family        text NOT NULL DEFAULT '',
    os_id            text NOT NULL DEFAULT '',
    os_name          text NOT NULL DEFAULT '',
    os_version       text NOT NULL DEFAULT '',
    kernel           text NOT NULL DEFAULT '',
    arch             text NOT NULL DEFAULT '',
    hostname         text NOT NULL DEFAULT '',
    last_checked_at  timestamptz,
    last_seen_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX servers_name_key ON servers (lower(name));
CREATE INDEX servers_folder_id_idx ON servers (folder_id);
CREATE INDEX servers_tags_idx ON servers USING gin (tags);

-- +goose Down
DROP TABLE servers;
DROP TABLE folders;
