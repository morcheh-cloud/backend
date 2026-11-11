-- +goose Up
-- Every filesystem of a sample (mount, used, total), for per-disk charts.
ALTER TABLE server_samples ADD COLUMN disks jsonb NOT NULL DEFAULT '[]';

-- Alert rules on server metrics: "CPU above 90% for 10 minutes on servers
-- tagged web". Checked against every resource sample (and, for "offline",
-- every connection check); a rule fires per server.
CREATE TABLE alert_rules (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name            text NOT NULL,
    enabled         boolean NOT NULL DEFAULT true,
    metric          text NOT NULL CHECK (metric IN (
        'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline')),
    op              text NOT NULL DEFAULT 'above' CHECK (op IN ('above', 'below')),
    threshold       float8 NOT NULL DEFAULT 0,
    -- disk only: one mount point; '' = the fullest one.
    mount           text NOT NULL DEFAULT '',
    for_minutes     int NOT NULL DEFAULT 5 CHECK (for_minutes >= 0),
    severity        text NOT NULL DEFAULT 'warning' CHECK (severity IN ('warning', 'critical')),
    scope           text NOT NULL DEFAULT 'all' CHECK (scope IN ('all', 'servers', 'tags')),
    server_ids      uuid[] NOT NULL DEFAULT '{}',
    tags            text[] NOT NULL DEFAULT '{}',
    -- Remind while it keeps firing; 0 = once.
    repeat_minutes  int NOT NULL DEFAULT 0 CHECK (repeat_minutes >= 0),
    notify_resolved boolean NOT NULL DEFAULT true,
    created_by_name text NOT NULL DEFAULT '',
    updated_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX alert_rules_workspace_idx ON alert_rules (workspace_id);

CREATE TABLE alert_rule_channels (
    rule_id    uuid NOT NULL REFERENCES alert_rules (id) ON DELETE CASCADE,
    channel_id uuid NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, channel_id)
);

-- Where a rule stands on each server: breach_since = the condition has held
-- since then; firing_since = it lasted long enough and was sent.
CREATE TABLE alert_states (
    rule_id      uuid NOT NULL REFERENCES alert_rules (id) ON DELETE CASCADE,
    server_id    uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    breach_since timestamptz,
    firing_since timestamptz,
    last_sent_at timestamptz,
    value        float8 NOT NULL DEFAULT 0,
    detail       text NOT NULL DEFAULT '',
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, server_id)
);

CREATE INDEX alert_states_firing_idx ON alert_states (rule_id) WHERE firing_since IS NOT NULL;

-- History: when a rule fired and resolved on a server. Names are copied so
-- the history reads the same after either is gone.
CREATE TABLE alert_events (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    rule_id      uuid REFERENCES alert_rules (id) ON DELETE SET NULL,
    server_id    uuid REFERENCES servers (id) ON DELETE SET NULL,
    rule_name    text NOT NULL,
    server_name  text NOT NULL,
    metric       text NOT NULL,
    severity     text NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('fired', 'resolved')),
    value        float8 NOT NULL DEFAULT 0,
    threshold    float8 NOT NULL DEFAULT 0,
    detail       text NOT NULL DEFAULT '',
    lasted_secs  bigint NOT NULL DEFAULT 0,
    at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX alert_events_workspace_idx ON alert_events (workspace_id, at DESC);
CREATE INDEX alert_events_server_idx ON alert_events (server_id, at DESC);

ALTER TABLE notification_log ADD COLUMN rule_id uuid REFERENCES alert_rules (id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE notification_log DROP COLUMN rule_id;
DROP TABLE alert_events;
DROP TABLE alert_states;
DROP TABLE alert_rule_channels;
DROP TABLE alert_rules;
ALTER TABLE server_samples DROP COLUMN disks;
