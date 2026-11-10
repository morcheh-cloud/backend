-- +goose Up
-- Where alerts go: one row per destination (an email list, a Telegram or Bale
-- chat, a webhook…). config holds the plain settings, secrets_enc the sealed
-- JSON of the secret ones (bot token, SMTP password, webhook signing key).
CREATE TABLE notification_channels (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name            text NOT NULL,
    kind            text NOT NULL CHECK (kind IN (
        'email', 'telegram', 'bale', 'webhook', 'slack', 'discord', 'ntfy',
        'gotify', 'mattermost', 'teams', 'pushover')),
    config          jsonb NOT NULL DEFAULT '{}',
    secrets_enc     bytea,
    enabled         boolean NOT NULL DEFAULT true,
    -- Added to every new monitor of the workspace.
    is_default      boolean NOT NULL DEFAULT false,
    allow_internal  boolean NOT NULL DEFAULT false,
    last_sent_at    timestamptz,
    last_error      text NOT NULL DEFAULT '',
    last_error_at   timestamptz,
    created_by_name text NOT NULL DEFAULT '',
    updated_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, name)
);

-- What Morcheh watches. config is the kind's own settings (URL and
-- assertions, host and port…); secrets_enc the sealed secret ones.
CREATE TABLE monitors (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id     uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name             text NOT NULL,
    kind             text NOT NULL,
    config           jsonb NOT NULL DEFAULT '{}',
    secrets_enc      bytea,
    description      text NOT NULL DEFAULT '',
    tags             text[] NOT NULL DEFAULT '{}',
    -- Checked from a panel server over SSH instead of from Morcheh itself.
    via_server_id    uuid REFERENCES servers (id) ON DELETE SET NULL,
    -- The resource it watches, for links ("Monitor this").
    server_id        uuid REFERENCES servers (id) ON DELETE SET NULL,
    interval_seconds int NOT NULL DEFAULT 60 CHECK (interval_seconds BETWEEN 10 AND 86400),
    retry_seconds    int NOT NULL DEFAULT 20 CHECK (retry_seconds BETWEEN 5 AND 86400),
    timeout_seconds  int NOT NULL DEFAULT 10 CHECK (timeout_seconds BETWEEN 1 AND 120),
    -- Failed checks in a row before it counts as down.
    retries          int NOT NULL DEFAULT 1 CHECK (retries BETWEEN 0 AND 20),
    -- While down, notify again every this many checks (0 = once).
    resend_every     int NOT NULL DEFAULT 0 CHECK (resend_every BETWEEN 0 AND 10000),
    notify_degraded  boolean NOT NULL DEFAULT true,
    allow_internal   boolean NOT NULL DEFAULT false,
    paused           boolean NOT NULL DEFAULT false,
    push_token       text UNIQUE,
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'up', 'degraded', 'down')),
    status_message   text NOT NULL DEFAULT '',
    status_since     timestamptz NOT NULL DEFAULT now(),
    fail_count       int NOT NULL DEFAULT 0,
    down_checks      int NOT NULL DEFAULT 0,
    last_latency_ms  int,
    last_checked_at  timestamptz,
    next_check_at    timestamptz NOT NULL DEFAULT now(),
    cert_expires_at  timestamptz,
    created_by_name  text NOT NULL DEFAULT '',
    updated_by_name  text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, name)
);

CREATE INDEX monitors_due_idx ON monitors (next_check_at) WHERE NOT paused;
CREATE INDEX monitors_server_idx ON monitors (server_id);

CREATE TABLE monitor_channels (
    monitor_id uuid NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    channel_id uuid NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    PRIMARY KEY (monitor_id, channel_id)
);

CREATE INDEX monitor_channels_channel_idx ON monitor_channels (channel_id);

-- Every check, kept MONITOR_HISTORY (14 days by default).
CREATE TABLE monitor_checks (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    monitor_id  uuid NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    status      text NOT NULL CHECK (status IN ('up', 'degraded', 'down')),
    latency_ms  int,
    code        text NOT NULL DEFAULT '',
    message     text NOT NULL DEFAULT ''
);

CREATE INDEX monitor_checks_monitor_idx ON monitor_checks (monitor_id, at DESC);
CREATE INDEX monitor_checks_at_idx ON monitor_checks (at);

-- One row per monitor per UTC day, kept forever: long-range uptime.
CREATE TABLE monitor_days (
    monitor_id     uuid NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    day            date NOT NULL,
    checks         int NOT NULL DEFAULT 0,
    up             int NOT NULL DEFAULT 0,
    degraded       int NOT NULL DEFAULT 0,
    down           int NOT NULL DEFAULT 0,
    latency_sum    bigint NOT NULL DEFAULT 0,
    latency_count  int NOT NULL DEFAULT 0,
    latency_max    int NOT NULL DEFAULT 0,
    PRIMARY KEY (monitor_id, day)
);

-- Status changes, kept forever.
CREATE TABLE monitor_events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    monitor_id  uuid NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    from_status text NOT NULL,
    to_status   text NOT NULL,
    message     text NOT NULL DEFAULT ''
);

CREATE INDEX monitor_events_monitor_idx ON monitor_events (monitor_id, at DESC);

-- A stretch of downtime: opened when a monitor goes down, resolved when it
-- comes back.
CREATE TABLE monitor_incidents (
    id                   uuid PRIMARY KEY DEFAULT uuidv7(),
    monitor_id           uuid NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    started_at           timestamptz NOT NULL DEFAULT now(),
    resolved_at          timestamptz,
    cause                text NOT NULL DEFAULT '',
    acknowledged_at      timestamptz,
    acknowledged_by_name text NOT NULL DEFAULT '',
    note                 text NOT NULL DEFAULT ''
);

CREATE INDEX monitor_incidents_monitor_idx ON monitor_incidents (monitor_id, started_at DESC);
CREATE UNIQUE INDEX monitor_incidents_open_idx ON monitor_incidents (monitor_id) WHERE resolved_at IS NULL;

-- What was sent where, for a channel's history and a monitor's alerts.
CREATE TABLE notification_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    channel_id  uuid NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    monitor_id  uuid REFERENCES monitors (id) ON DELETE SET NULL,
    at          timestamptz NOT NULL DEFAULT now(),
    title       text NOT NULL,
    ok          boolean NOT NULL,
    error       text NOT NULL DEFAULT ''
);

CREATE INDEX notification_log_channel_idx ON notification_log (channel_id, at DESC);

-- +goose Down
DROP TABLE notification_log;
DROP TABLE monitor_incidents;
DROP TABLE monitor_events;
DROP TABLE monitor_days;
DROP TABLE monitor_checks;
DROP TABLE monitor_channels;
DROP TABLE monitors;
DROP TABLE notification_channels;
