-- +goose Up
-- More to alert on: failed systemd services on servers, and databases that
-- can't be reached or whose health turned critical.
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health'));
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_scope_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_scope_check CHECK (scope IN (
    'all', 'servers', 'tags', 'databases'));
-- service only: one unit; '' = any failed service.
ALTER TABLE alert_rules ADD COLUMN unit text NOT NULL DEFAULT '';
-- scope databases.
ALTER TABLE alert_rules ADD COLUMN database_ids uuid[] NOT NULL DEFAULT '{}';

-- A state is now on a server or a database (no foreign key: lists skip the
-- ones whose target is gone).
ALTER TABLE alert_states DROP CONSTRAINT alert_states_server_id_fkey;
ALTER TABLE alert_states RENAME COLUMN server_id TO target_id;
ALTER TABLE alert_states ADD COLUMN target_kind text NOT NULL DEFAULT 'server'
    CHECK (target_kind IN ('server', 'database'));

ALTER TABLE alert_events ADD COLUMN database_id uuid REFERENCES databases (id) ON DELETE SET NULL;
-- Fired while muted: recorded, not sent.
ALTER TABLE alert_events ADD COLUMN muted boolean NOT NULL DEFAULT false;
CREATE INDEX alert_events_database_idx ON alert_events (database_id, at DESC);

-- Quiet time (maintenance): while a mute is on, matching alerts are recorded
-- but not sent. rule_id NULL = every rule; target_id NULL = everywhere.
CREATE TABLE alert_mutes (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    rule_id         uuid REFERENCES alert_rules (id) ON DELETE CASCADE,
    target_id       uuid,
    target_kind     text NOT NULL DEFAULT '' CHECK (target_kind IN ('', 'server', 'database')),
    target_name     text NOT NULL DEFAULT '',
    starts_at       timestamptz NOT NULL DEFAULT now(),
    until           timestamptz NOT NULL,
    note            text NOT NULL DEFAULT '',
    created_by_name text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (until > starts_at)
);

CREATE INDEX alert_mutes_workspace_idx ON alert_mutes (workspace_id, until);

-- +goose Down
DROP TABLE alert_mutes;
DROP INDEX alert_events_database_idx;
ALTER TABLE alert_events DROP COLUMN muted;
ALTER TABLE alert_events DROP COLUMN database_id;
DELETE FROM alert_states WHERE target_kind <> 'server' OR target_id NOT IN (SELECT id FROM servers);
ALTER TABLE alert_states DROP COLUMN target_kind;
ALTER TABLE alert_states RENAME COLUMN target_id TO server_id;
ALTER TABLE alert_states ADD CONSTRAINT alert_states_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE;
DELETE FROM alert_rules WHERE metric IN ('service', 'db_down', 'db_health') OR scope = 'databases';
ALTER TABLE alert_rules DROP COLUMN database_ids;
ALTER TABLE alert_rules DROP COLUMN unit;
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_scope_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_scope_check CHECK (scope IN ('all', 'servers', 'tags'));
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline'));
