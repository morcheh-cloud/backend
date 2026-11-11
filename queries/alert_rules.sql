-- name: ListAlertRules :many
SELECT * FROM alert_rules
WHERE (@see_all::bool OR workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id')::uuid)
ORDER BY lower(name), id;

-- name: GetAlertRule :one
SELECT * FROM alert_rules WHERE id = $1;

-- name: GetAlertRuleWorkspace :one
SELECT workspace_id FROM alert_rules WHERE id = $1;

-- name: CreateAlertRule :one
INSERT INTO alert_rules (
    workspace_id, name, enabled, metric, op, threshold, mount, for_minutes, severity,
    scope, server_ids, tags, repeat_minutes, notify_resolved, created_by_name, updated_by_name
) VALUES (
    @workspace_id, @name, @enabled, @metric, @op, @threshold, @mount, @for_minutes, @severity,
    @scope, @server_ids, @tags, @repeat_minutes, @notify_resolved, @created_by_name, @created_by_name
)
RETURNING *;

-- name: UpdateAlertRule :one
UPDATE alert_rules SET
    name = @name, enabled = @enabled, metric = @metric, op = @op, threshold = @threshold,
    mount = @mount, for_minutes = @for_minutes, severity = @severity, scope = @scope,
    server_ids = @server_ids, tags = @tags, repeat_minutes = @repeat_minutes,
    notify_resolved = @notify_resolved, updated_by_name = @updated_by_name, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetAlertRuleEnabled :one
UPDATE alert_rules SET enabled = @enabled, updated_by_name = @updated_by_name, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteAlertRule :exec
DELETE FROM alert_rules WHERE id = $1;

-- name: ListAlertRuleChannels :many
SELECT rule_id, channel_id FROM alert_rule_channels
WHERE rule_id = ANY (@ids::uuid[]);

-- name: ClearAlertRuleChannels :exec
DELETE FROM alert_rule_channels WHERE rule_id = $1;

-- name: AddAlertRuleChannel :exec
INSERT INTO alert_rule_channels (rule_id, channel_id) VALUES (@rule_id, @channel_id)
ON CONFLICT DO NOTHING;

-- name: AlertRuleChannelsToNotify :many
SELECT c.* FROM notification_channels c
JOIN alert_rule_channels rc ON rc.channel_id = c.id
WHERE rc.rule_id = $1 AND c.enabled;

-- name: CountChannelRules :many
SELECT channel_id, count(*)::int AS rules
FROM alert_rule_channels
WHERE channel_id = ANY (@ids::uuid[])
GROUP BY channel_id;

-- name: AlertRulesForServer :many
-- The enabled rules of a server's workspace that cover it.
SELECT * FROM alert_rules
WHERE enabled AND workspace_id = @workspace_id
  AND (scope = 'all'
    OR (scope = 'servers' AND @server_id::uuid = ANY (server_ids))
    OR (scope = 'tags' AND tags && @tags::text[]));

-- name: GetAlertState :one
SELECT * FROM alert_states WHERE rule_id = @rule_id AND server_id = @server_id;

-- name: UpsertAlertState :exec
INSERT INTO alert_states (rule_id, server_id, breach_since, firing_since, last_sent_at, value, detail, updated_at)
VALUES (@rule_id, @server_id, sqlc.narg('breach_since'), sqlc.narg('firing_since'), sqlc.narg('last_sent_at'), @value, @detail, now())
ON CONFLICT (rule_id, server_id) DO UPDATE SET
    breach_since = excluded.breach_since, firing_since = excluded.firing_since,
    last_sent_at = excluded.last_sent_at, value = excluded.value, detail = excluded.detail,
    updated_at = now();

-- name: DeleteAlertStates :exec
DELETE FROM alert_states WHERE rule_id = $1;

-- name: ListAlertStates :many
-- Where the given rules stand on each server they've seen.
SELECT st.*, s.name AS server_name
FROM alert_states st
JOIN servers s ON s.id = st.server_id
WHERE st.rule_id = ANY (@ids::uuid[])
ORDER BY st.firing_since NULLS LAST, s.name;

-- name: InsertAlertEvent :exec
INSERT INTO alert_events (
    workspace_id, rule_id, server_id, rule_name, server_name, metric, severity, kind,
    value, threshold, detail, lasted_secs, at
) VALUES (
    @workspace_id, @rule_id, @server_id, @rule_name, @server_name, @metric, @severity, @kind,
    @value, @threshold, @detail, @lasted_secs, @at
);

-- name: ListAlertEvents :many
SELECT * FROM alert_events
WHERE (@see_all::bool OR workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id')::uuid)
  AND (sqlc.narg('server_id')::uuid IS NULL OR server_id = sqlc.narg('server_id')::uuid)
  AND (sqlc.narg('rule_id')::uuid IS NULL OR rule_id = sqlc.narg('rule_id')::uuid)
ORDER BY at DESC, id DESC
LIMIT @lim;

-- name: PruneAlertEvents :execrows
DELETE FROM alert_events WHERE at < @before::timestamptz;
