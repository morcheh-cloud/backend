-- +goose Up
-- An alert rule on tunnels: one that servers (or anything else) go through
-- keeps failing.
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health',
    'db_disk', 'db_connections', 'db_memory', 'db_latency', 'db_replication_lag', 'db_backup_age',
    'container_down', 'container_unhealthy', 'container_restarts', 'container_cpu',
    'container_memory', 'docker_engine', 'container_vulns_critical', 'container_vulns_high',
    'pve_node_down', 'pve_storage_full', 'pve_vm_stopped', 'tunnel_down'));
ALTER TABLE alert_states DROP CONSTRAINT alert_states_target_kind_check;
ALTER TABLE alert_states ADD CONSTRAINT alert_states_target_kind_check
    CHECK (target_kind IN ('server', 'database', 'pve', 'tunnel'));
ALTER TABLE alert_mutes DROP CONSTRAINT alert_mutes_target_kind_check;
ALTER TABLE alert_mutes ADD CONSTRAINT alert_mutes_target_kind_check
    CHECK (target_kind IN ('', 'server', 'database', 'pve', 'tunnel'));
ALTER TABLE alert_events ADD COLUMN tunnel_id uuid REFERENCES tunnels (id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE alert_events DROP COLUMN tunnel_id;
DELETE FROM alert_mutes WHERE target_kind = 'tunnel';
ALTER TABLE alert_mutes DROP CONSTRAINT alert_mutes_target_kind_check;
ALTER TABLE alert_mutes ADD CONSTRAINT alert_mutes_target_kind_check
    CHECK (target_kind IN ('', 'server', 'database', 'pve'));
DELETE FROM alert_states WHERE target_kind = 'tunnel';
ALTER TABLE alert_states DROP CONSTRAINT alert_states_target_kind_check;
ALTER TABLE alert_states ADD CONSTRAINT alert_states_target_kind_check
    CHECK (target_kind IN ('server', 'database', 'pve'));
DELETE FROM alert_rules WHERE metric = 'tunnel_down';
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health',
    'db_disk', 'db_connections', 'db_memory', 'db_latency', 'db_replication_lag', 'db_backup_age',
    'container_down', 'container_unhealthy', 'container_restarts', 'container_cpu',
    'container_memory', 'docker_engine', 'container_vulns_critical', 'container_vulns_high',
    'pve_node_down', 'pve_storage_full', 'pve_vm_stopped'));
