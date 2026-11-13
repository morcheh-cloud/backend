-- +goose Up
-- Alert rules on the known vulnerabilities in a container's image (from the
-- last Trivy scan): critical only, or high and worse.
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health',
    'container_down', 'container_unhealthy', 'container_restarts', 'container_cpu',
    'container_memory', 'docker_engine', 'container_vulns_critical', 'container_vulns_high'));

-- +goose Down
DELETE FROM alert_rules WHERE metric IN ('container_vulns_critical', 'container_vulns_high');
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'cpu', 'iowait', 'load', 'memory', 'swap', 'disk', 'net_rx', 'net_tx', 'offline',
    'service', 'db_down', 'db_health',
    'container_down', 'container_unhealthy', 'container_restarts', 'container_cpu',
    'container_memory', 'docker_engine'));
