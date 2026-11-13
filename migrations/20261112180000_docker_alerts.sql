-- +goose Up
-- Alert rules on containers: a container down, unhealthy, restarting over
-- and over, using too much CPU or memory, or the engine itself stopped.
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health',
    'container_down', 'container_unhealthy', 'container_restarts', 'container_cpu',
    'container_memory', 'docker_engine'));
-- Container rules only: a compose project and/or a container name (* matches
-- anything); '' = every one.
ALTER TABLE alert_rules ADD COLUMN project text NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN container text NOT NULL DEFAULT '';

-- A compose project's name and description as people see them in the panel
-- (the project name itself is compose's and can't change).
CREATE TABLE docker_project_meta (
    server_id       uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    project         text NOT NULL,
    title           text NOT NULL DEFAULT '',
    note            text NOT NULL DEFAULT '',
    updated_by_name text NOT NULL DEFAULT '',
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, project)
);

-- +goose Down
DROP TABLE docker_project_meta;
DELETE FROM alert_rules WHERE metric IN ('container_down', 'container_unhealthy',
    'container_restarts', 'container_cpu', 'container_memory', 'docker_engine');
ALTER TABLE alert_rules DROP COLUMN container;
ALTER TABLE alert_rules DROP COLUMN project;
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health'));
