-- +goose Up

-- Remote storages (S3-compatible, FTP/FTPS, SFTP, WebDAV). Secrets are
-- AES-GCM sealed by the API (internal/secrets) and never leave it.
CREATE TABLE storages (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    protocol        text NOT NULL CHECK (protocol IN ('s3', 'ftp', 'sftp', 'webdav')),
    -- Preset the form was filled from (aws, minio, r2, nextcloud…); display only.
    provider        text NOT NULL DEFAULT '',
    -- S3: endpoint (URL or host); WebDAV: URL; FTP/SFTP: host name.
    host            text NOT NULL,
    port            integer NOT NULL DEFAULT 0 CHECK (port BETWEEN 0 AND 65535),
    -- S3: access key; others: user name (empty FTP user = anonymous).
    username        text NOT NULL DEFAULT '',
    auth_method     text NOT NULL DEFAULT 'password' CHECK (auth_method IN ('password', 'private_key')),
    -- S3: secret key; others: password.
    secret_enc      bytea,
    private_key_enc bytea,
    passphrase_enc  bytea,
    bucket          text NOT NULL DEFAULT '',
    region          text NOT NULL DEFAULT '',
    path_style      boolean NOT NULL DEFAULT false,
    -- FTP: none, explicit, implicit.
    tls             text NOT NULL DEFAULT 'none' CHECK (tls IN ('none', 'explicit', 'implicit')),
    insecure_tls    boolean NOT NULL DEFAULT false,
    -- SFTP trust on first use, as for servers.
    host_key        text NOT NULL DEFAULT '',
    -- Folder (or bucket/prefix) the browser is jailed in; '' = login folder.
    root_path       text NOT NULL DEFAULT '',
    read_only       boolean NOT NULL DEFAULT false,
    description     text NOT NULL DEFAULT '',
    favorite        boolean NOT NULL DEFAULT false,
    status          text NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('unknown', 'online', 'unreachable', 'auth_failed', 'host_key_mismatch', 'error')),
    status_message  text NOT NULL DEFAULT '',
    detail          text NOT NULL DEFAULT '',
    latency_ms      integer,
    last_checked_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX storages_name_key ON storages (lower(name));

-- +goose Down
DROP TABLE storages;
