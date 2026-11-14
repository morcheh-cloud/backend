-- +goose Up
-- Proxmox VE clusters Morche talks to through their API (an API token).
-- Machines, nodes and storage live on the cluster and are read live; only
-- the connection, its last check and a few counts are kept here.
CREATE TABLE pve_clusters (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id    uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name            text NOT NULL,
    url             text NOT NULL,
    token_id        text NOT NULL,
    secret_enc      bytea NOT NULL,
    fingerprint     text NOT NULL DEFAULT '',
    tls_skip_verify boolean NOT NULL DEFAULT false,
    allow_internal  boolean NOT NULL DEFAULT false,
    description     text NOT NULL DEFAULT '',
    favorite        boolean NOT NULL DEFAULT false,
    status          text NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('unknown', 'online', 'unreachable', 'auth_failed', 'tls_error', 'blocked', 'error')),
    status_message  text NOT NULL DEFAULT '',
    version         text NOT NULL DEFAULT '',
    cluster_name    text NOT NULL DEFAULT '',
    node_count      integer NOT NULL DEFAULT 0,
    nodes_online    integer NOT NULL DEFAULT 0,
    guest_count     integer NOT NULL DEFAULT 0,
    running_count   integer NOT NULL DEFAULT 0,
    latency_ms      integer,
    last_checked_at timestamptz,
    last_online_at  timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX pve_clusters_name_key ON pve_clusters (workspace_id, lower(name));

-- A machine on a cluster that is also a server in Morche: the server's page
-- shows where it runs, with power and console.
CREATE TABLE pve_vm_links (
    cluster_id uuid NOT NULL REFERENCES pve_clusters (id) ON DELETE CASCADE,
    vmid       integer NOT NULL,
    server_id  uuid NOT NULL UNIQUE REFERENCES servers (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cluster_id, vmid)
);

-- Alert rules on clusters: a node down, a storage filling up, a machine that
-- stopped without Morche stopping it.
ALTER TABLE alert_rules ADD COLUMN cluster_ids uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health',
    'container_down', 'container_unhealthy', 'container_restarts', 'container_cpu',
    'container_memory', 'docker_engine', 'container_vulns_critical', 'container_vulns_high',
    'pve_node_down', 'pve_storage_full', 'pve_vm_stopped'));
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_scope_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_scope_check
    CHECK (scope IN ('all', 'servers', 'tags', 'databases', 'clusters'));
ALTER TABLE alert_states DROP CONSTRAINT alert_states_target_kind_check;
ALTER TABLE alert_states ADD CONSTRAINT alert_states_target_kind_check
    CHECK (target_kind IN ('server', 'database', 'pve'));
ALTER TABLE alert_mutes DROP CONSTRAINT alert_mutes_target_kind_check;
ALTER TABLE alert_mutes ADD CONSTRAINT alert_mutes_target_kind_check
    CHECK (target_kind IN ('', 'server', 'database', 'pve'));
ALTER TABLE alert_events ADD COLUMN cluster_id uuid REFERENCES pve_clusters (id) ON DELETE SET NULL;

-- Scheduled backups and snapshots of machines.
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup', 'software-update', 'package-upgrade', 'docker-update', 'docker-volume-backup', 'docker-prune', 'pve-backup', 'pve-snapshot'));

-- +goose Down
DELETE FROM schedules WHERE action IN ('pve-backup', 'pve-snapshot');
ALTER TABLE schedules DROP CONSTRAINT schedules_action_check;
ALTER TABLE schedules ADD CONSTRAINT schedules_action_check
    CHECK (action IN ('sync', 'script', 'ansible', 'service', 'reboot', 'fetch', 'archive', 'verify-backup', 'software-update', 'package-upgrade', 'docker-update', 'docker-volume-backup', 'docker-prune'));
ALTER TABLE alert_events DROP COLUMN cluster_id;
DELETE FROM alert_mutes WHERE target_kind = 'pve';
ALTER TABLE alert_mutes DROP CONSTRAINT alert_mutes_target_kind_check;
ALTER TABLE alert_mutes ADD CONSTRAINT alert_mutes_target_kind_check
    CHECK (target_kind IN ('', 'server', 'database'));
DELETE FROM alert_states WHERE target_kind = 'pve';
ALTER TABLE alert_states DROP CONSTRAINT alert_states_target_kind_check;
ALTER TABLE alert_states ADD CONSTRAINT alert_states_target_kind_check
    CHECK (target_kind IN ('server', 'database'));
DELETE FROM alert_rules WHERE metric LIKE 'pve\_%' OR scope = 'clusters';
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_scope_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_scope_check
    CHECK (scope IN ('all', 'servers', 'tags', 'databases'));
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health',
    'container_down', 'container_unhealthy', 'container_restarts', 'container_cpu',
    'container_memory', 'docker_engine', 'container_vulns_critical', 'container_vulns_high'));
ALTER TABLE alert_rules DROP COLUMN cluster_ids;
DROP TABLE pve_vm_links;
DROP TABLE pve_clusters;
