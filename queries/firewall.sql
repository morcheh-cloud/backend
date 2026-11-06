-- name: AddFirewallChange :one
INSERT INTO firewall_changes (server_id, user_id, user_name, summary, backend, status, state_before, added, removed, snapshot)
VALUES (@server_id, @user_id, @user_name, @summary, @backend, @status, @state_before, @added, @removed, @snapshot)
RETURNING id;

-- name: ListFirewallChanges :many
SELECT id, user_name, summary, backend, status, added, removed, (snapshot IS NOT NULL)::boolean AS restorable, created_at
FROM firewall_changes
WHERE server_id = @server_id
ORDER BY created_at DESC, id DESC;

-- name: GetFirewallChange :one
SELECT * FROM firewall_changes WHERE id = @id AND server_id = @server_id;

-- name: SettleFirewallChanges :exec
UPDATE firewall_changes SET status = @status WHERE server_id = @server_id AND status = 'pending';

-- name: PruneFirewallChanges :exec
DELETE FROM firewall_changes AS old
WHERE old.server_id = @server_id AND old.id NOT IN (
    SELECT recent.id FROM firewall_changes AS recent
    WHERE recent.server_id = @server_id
    ORDER BY recent.created_at DESC, recent.id DESC
    LIMIT @keep
);
