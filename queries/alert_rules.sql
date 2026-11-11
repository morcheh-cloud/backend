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
    workspace_id, name, enabled, metric, op, threshold, mount, unit, for_minutes, severity,
    scope, server_ids, database_ids, tags, repeat_minutes, notify_resolved, created_by_name, updated_by_name
) VALUES (
    @workspace_id, @name, @enabled, @metric, @op, @threshold, @mount, @unit, @for_minutes, @severity,
    @scope, @server_ids, @database_ids, @tags, @repeat_minutes, @notify_resolved, @created_by_name, @created_by_name
)
RETURNING *;

-- name: UpdateAlertRule :one
UPDATE alert_rules SET
    name = @name, enabled = @enabled, metric = @metric, op = @op, threshold = @threshold,
    mount = @mount, unit = @unit, for_minutes = @for_minutes, severity = @severity, scope = @scope,
    server_ids = @server_ids, database_ids = @database_ids, tags = @tags, repeat_minutes = @repeat_minutes,
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
-- The enabled server rules of a server's workspace that cover it.
SELECT * FROM alert_rules
WHERE enabled AND workspace_id = @workspace_id
  AND metric NOT IN ('db_down', 'db_health')
  AND (scope = 'all'
    OR (scope = 'servers' AND @server_id::uuid = ANY (server_ids))
    OR (scope = 'tags' AND tags && @tags::text[]));

-- name: AlertRulesForDatabase :many
-- The enabled database rules of a database's workspace that cover it.
SELECT * FROM alert_rules
WHERE enabled AND workspace_id = @workspace_id
  AND metric IN ('db_down', 'db_health')
  AND (scope = 'all' OR (scope = 'databases' AND @database_id::uuid = ANY (database_ids)));

-- name: GetAlertState :one
SELECT * FROM alert_states WHERE rule_id = @rule_id AND target_id = @target_id;

-- name: UpsertAlertState :exec
INSERT INTO alert_states (rule_id, target_id, target_kind, breach_since, firing_since, last_sent_at, value, detail, updated_at)
VALUES (@rule_id, @target_id, @target_kind, sqlc.narg('breach_since'), sqlc.narg('firing_since'), sqlc.narg('last_sent_at'), @value, @detail, now())
ON CONFLICT (rule_id, target_id) DO UPDATE SET
    breach_since = excluded.breach_since, firing_since = excluded.firing_since,
    last_sent_at = excluded.last_sent_at, value = excluded.value, detail = excluded.detail,
    updated_at = now();

-- name: DeleteAlertStates :exec
DELETE FROM alert_states WHERE rule_id = $1;

-- name: ListAlertStates :many
-- Where the given rules stand on each server or database they've seen.
SELECT st.*, coalesce(s.name, d.name)::text AS target_name
FROM alert_states st
LEFT JOIN servers s ON st.target_kind = 'server' AND s.id = st.target_id
LEFT JOIN databases d ON st.target_kind = 'database' AND d.id = st.target_id
WHERE st.rule_id = ANY (@ids::uuid[]) AND (s.id IS NOT NULL OR d.id IS NOT NULL)
ORDER BY st.firing_since NULLS LAST, coalesce(s.name, d.name);

-- name: InsertAlertEvent :exec
INSERT INTO alert_events (
    workspace_id, rule_id, server_id, database_id, rule_name, server_name, metric, severity, kind,
    value, threshold, detail, lasted_secs, muted, at
) VALUES (
    @workspace_id, @rule_id, sqlc.narg('server_id'), sqlc.narg('database_id'), @rule_name, @server_name, @metric, @severity, @kind,
    @value, @threshold, @detail, @lasted_secs, @muted, @at
);

-- name: ListAlertEvents :many
SELECT * FROM alert_events
WHERE (@see_all::bool OR workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id')::uuid)
  AND (sqlc.narg('server_id')::uuid IS NULL OR server_id = sqlc.narg('server_id')::uuid)
  AND (sqlc.narg('database_id')::uuid IS NULL OR database_id = sqlc.narg('database_id')::uuid)
  AND (sqlc.narg('rule_id')::uuid IS NULL OR rule_id = sqlc.narg('rule_id')::uuid)
ORDER BY at DESC, id DESC
LIMIT @lim;

-- name: PruneAlertEvents :execrows
DELETE FROM alert_events WHERE at < @before::timestamptz;

-- name: ListAlertMutes :many
-- Mutes that are on now or start later.
SELECT m.*, coalesce(r.name, '')::text AS rule_name
FROM alert_mutes m
LEFT JOIN alert_rules r ON r.id = m.rule_id
WHERE m.until > now()
  AND (@see_all::bool OR m.workspace_id = ANY (@workspace_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR m.workspace_id = sqlc.narg('workspace_id')::uuid)
ORDER BY m.starts_at, m.until;

-- name: GetAlertMute :one
SELECT * FROM alert_mutes WHERE id = $1;

-- name: CreateAlertMute :one
INSERT INTO alert_mutes (workspace_id, rule_id, target_id, target_kind, target_name, starts_at, until, note, created_by_name)
VALUES (@workspace_id, sqlc.narg('rule_id'), sqlc.narg('target_id'), @target_kind, @target_name, @starts_at, @until, @note, @created_by_name)
RETURNING *;

-- name: EndAlertMute :one
-- Ends a mute now (one that hasn't started yet goes away).
UPDATE alert_mutes SET until = greatest(now(), starts_at + interval '1 second')
WHERE id = $1
RETURNING *;

-- name: DeleteAlertMute :exec
DELETE FROM alert_mutes WHERE id = $1;

-- name: AlertMuted :one
-- Whether a mute covers this rule on this target right now.
SELECT exists (
    SELECT 1 FROM alert_mutes
    WHERE workspace_id = @workspace_id AND starts_at <= now() AND until > now()
      AND (rule_id IS NULL OR rule_id = @rule_id)
      AND (target_id IS NULL OR target_id = @target_id)
)::bool;

-- name: PruneAlertMutes :execrows
DELETE FROM alert_mutes WHERE until < @before::timestamptz;
