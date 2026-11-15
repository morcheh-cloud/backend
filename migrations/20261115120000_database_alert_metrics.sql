-- +goose Up
-- Alert rules on a database's own numbers: disk, connections, Redis memory,
-- response time, replication lag and the age of its last backup.
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health',
    'db_disk', 'db_connections', 'db_memory', 'db_latency', 'db_replication_lag', 'db_backup_age',
    'container_down', 'container_unhealthy', 'container_restarts', 'container_cpu',
    'container_memory', 'docker_engine', 'container_vulns_critical', 'container_vulns_high',
    'pve_node_down', 'pve_storage_full', 'pve_vm_stopped'));

-- +goose Down
DELETE FROM alert_rules WHERE metric IN
    ('db_disk', 'db_connections', 'db_memory', 'db_latency', 'db_replication_lag', 'db_backup_age');
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health',
    'container_down', 'container_unhealthy', 'container_restarts', 'container_cpu',
    'container_memory', 'docker_engine', 'container_vulns_critical', 'container_vulns_high',
    'pve_node_down', 'pve_storage_full', 'pve_vm_stopped'));
