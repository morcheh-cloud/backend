-- ---- Sync with what Morche manages ----

-- name: SyncAssetSources :many
-- Adds a linked asset for each server, database, storage… of the workspace
-- that has none yet and refreshes the facts of the rest. inserted = new.
INSERT INTO assets (workspace_id, kind, name, source_kind, source_ref, facts, last_seen_at, created_by_name, updated_by_name)
SELECT s.workspace_id, s.kind, left(s.name, 200), s.kind, s.ref, s.facts, now(), 'Morche', 'Morche'
FROM asset_sources s WHERE s.workspace_id = @workspace_id
ON CONFLICT (workspace_id, source_kind, source_ref) WHERE source_kind <> ''
DO UPDATE SET name = EXCLUDED.name, facts = EXCLUDED.facts, last_seen_at = now(), source_gone = false
RETURNING id, (xmax = 0)::bool AS inserted, source_gone;

-- name: MarkGoneAssets :many
-- Linked assets whose source was removed from Morche (or moved to another
-- workspace) are kept, for their history, and flagged.
UPDATE assets a SET source_gone = true
WHERE a.workspace_id = @workspace_id AND a.source_kind <> '' AND NOT a.source_gone
  AND NOT EXISTS (SELECT 1 FROM asset_sources s
                  WHERE s.workspace_id = a.workspace_id AND s.kind = a.source_kind AND s.ref = a.source_ref)
RETURNING id;

-- name: SyncAssetRelations :exec
INSERT INTO asset_relations (workspace_id, from_id, to_id, kind, origin)
SELECT DISTINCT @workspace_id::uuid, a.id, b.id, l.kind, 'discovered'
FROM asset_source_links l
JOIN assets a ON a.workspace_id = @workspace_id AND a.source_kind = l.from_kind AND a.source_ref = l.from_ref
JOIN assets b ON b.workspace_id = @workspace_id AND b.source_kind = l.to_kind AND b.source_ref = l.to_ref
WHERE a.id <> b.id
ON CONFLICT (from_id, to_id, kind) DO NOTHING;

-- name: PruneAssetRelations :exec
DELETE FROM asset_relations r
WHERE r.workspace_id = @workspace_id AND r.origin = 'discovered'
  AND NOT EXISTS (
    SELECT 1 FROM asset_source_links l
    JOIN assets a ON a.workspace_id = r.workspace_id AND a.source_kind = l.from_kind AND a.source_ref = l.from_ref
    JOIN assets b ON b.workspace_id = r.workspace_id AND b.source_kind = l.to_kind AND b.source_ref = l.to_ref
    WHERE a.id = r.from_id AND b.id = r.to_id AND l.kind = r.kind);

-- ---- Assets ----

-- name: ListAssets :many
SELECT sqlc.embed(a),
    coalesce(nullif(ou.full_name, ''), ou.username, '')::text AS owner_user_name,
    coalesce(ou.status, '')::text AS owner_user_status,
    coalesce(og.name, '')::text AS owner_group_name,
    coalesce(nullif(du.full_name, ''), du.username, '')::text AS deputy_user_name,
    coalesce(nullif(au.full_name, ''), au.username, '')::text AS assigned_user_name,
    (a.license_key_enc IS NOT NULL)::bool AS has_license_key
FROM assets a
LEFT JOIN users ou ON ou.id = a.owner_user_id
LEFT JOIN user_groups og ON og.id = a.owner_group_id
LEFT JOIN users du ON du.id = a.deputy_user_id
LEFT JOIN users au ON au.id = a.assigned_user_id
WHERE a.workspace_id = @workspace_id
ORDER BY a.name, a.id;

-- name: GetAsset :one
SELECT sqlc.embed(a),
    coalesce(nullif(ou.full_name, ''), ou.username, '')::text AS owner_user_name,
    coalesce(ou.status, '')::text AS owner_user_status,
    coalesce(og.name, '')::text AS owner_group_name,
    coalesce(nullif(du.full_name, ''), du.username, '')::text AS deputy_user_name,
    coalesce(nullif(au.full_name, ''), au.username, '')::text AS assigned_user_name,
    (a.license_key_enc IS NOT NULL)::bool AS has_license_key
FROM assets a
LEFT JOIN users ou ON ou.id = a.owner_user_id
LEFT JOIN user_groups og ON og.id = a.owner_group_id
LEFT JOIN users du ON du.id = a.deputy_user_id
LEFT JOIN users au ON au.id = a.assigned_user_id
WHERE a.id = @id;

-- name: GetAssetWorkspace :one
SELECT workspace_id FROM assets WHERE id = @id;

-- name: CountAssets :one
SELECT count(*)::int FROM assets WHERE workspace_id = @workspace_id;

-- name: CreateAsset :one
INSERT INTO assets (
    workspace_id, kind, category, name, description,
    owner_user_id, owner_group_id, deputy_user_id, assigned_user_id,
    environment, criticality, classification, lifecycle, tags,
    vendor, model, serial_number, asset_tag, location,
    cost_cents, currency, billing, cost_center,
    purchased_on, warranty_until, expires_on, auto_renew, seats, seats_used,
    license_key_enc, links, fields, notes, channel_ids, review_days,
    created_by_name, updated_by_name
) VALUES (
    @workspace_id, @kind, @category, @name, @description,
    sqlc.narg('owner_user_id'), sqlc.narg('owner_group_id'), sqlc.narg('deputy_user_id'), sqlc.narg('assigned_user_id'),
    @environment, @criticality, @classification, @lifecycle, @tags,
    @vendor, @model, @serial_number, @asset_tag, @location,
    sqlc.narg('cost_cents'), @currency, @billing, @cost_center,
    @purchased_on, @warranty_until, @expires_on, @auto_renew, sqlc.narg('seats'), sqlc.narg('seats_used'),
    sqlc.narg('license_key_enc'), @links, @fields, @notes, @channel_ids, @review_days,
    @created_by_name, @created_by_name
) RETURNING id;

-- name: UpdateAsset :exec
-- kind and name of a linked asset come from its source: the handler sends
-- the stored ones back.
UPDATE assets SET
    kind = @kind, category = @category, name = @name, description = @description,
    owner_user_id = sqlc.narg('owner_user_id'), owner_group_id = sqlc.narg('owner_group_id'),
    deputy_user_id = sqlc.narg('deputy_user_id'), assigned_user_id = sqlc.narg('assigned_user_id'),
    environment = @environment, criticality = @criticality, classification = @classification,
    lifecycle = @lifecycle, tags = @tags,
    vendor = @vendor, model = @model, serial_number = @serial_number, asset_tag = @asset_tag, location = @location,
    cost_cents = sqlc.narg('cost_cents'), currency = @currency, billing = @billing, cost_center = @cost_center,
    purchased_on = @purchased_on, warranty_until = @warranty_until, expires_on = @expires_on,
    auto_renew = @auto_renew, seats = sqlc.narg('seats'), seats_used = sqlc.narg('seats_used'),
    links = @links, fields = @fields, notes = @notes, channel_ids = @channel_ids, review_days = @review_days,
    updated_by_name = @updated_by_name, updated_at = now()
WHERE id = @id;

-- name: SetAssetLicenseKey :exec
UPDATE assets SET license_key_enc = sqlc.narg('license_key_enc'), updated_at = now() WHERE id = @id;

-- name: GetAssetLicenseKey :one
SELECT license_key_enc FROM assets WHERE id = @id;

-- name: ReviewAsset :exec
UPDATE assets SET reviewed_at = now(), reviewed_by_name = @reviewed_by_name WHERE id = @id;

-- name: DeleteAsset :execrows
DELETE FROM assets WHERE id = @id;

-- ---- Relations ----

-- name: ListWorkspaceAssetRelations :many
SELECT * FROM asset_relations WHERE workspace_id = @workspace_id ORDER BY created_at, id;

-- name: CreateAssetRelation :one
INSERT INTO asset_relations (workspace_id, from_id, to_id, kind, note, origin)
VALUES (@workspace_id, @from_id, @to_id, @kind, @note, 'manual')
ON CONFLICT (from_id, to_id, kind) DO UPDATE SET note = EXCLUDED.note, origin = 'manual'
RETURNING *;

-- name: GetAssetRelation :one
SELECT * FROM asset_relations WHERE id = @id AND (from_id = @asset_id OR to_id = @asset_id);

-- name: DeleteAssetRelation :execrows
DELETE FROM asset_relations WHERE id = @id AND (from_id = @asset_id OR to_id = @asset_id);

-- ---- History ----

-- name: AddAssetEvent :exec
INSERT INTO asset_events (asset_id, by_name, action, changes) VALUES (@asset_id, @by_name, @action, @changes);

-- name: ListAssetEvents :many
SELECT * FROM asset_events WHERE asset_id = @asset_id ORDER BY at DESC, id DESC LIMIT @lim;

-- ---- Owner rules ----

-- name: ListAssetOwnerRules :many
SELECT r.*,
    coalesce(nullif(ou.full_name, ''), ou.username, '')::text AS owner_user_name,
    coalesce(og.name, '')::text AS owner_group_name,
    coalesce(nullif(du.full_name, ''), du.username, '')::text AS deputy_user_name
FROM asset_owner_rules r
LEFT JOIN users ou ON ou.id = r.owner_user_id
LEFT JOIN user_groups og ON og.id = r.owner_group_id
LEFT JOIN users du ON du.id = r.deputy_user_id
WHERE r.workspace_id = @workspace_id ORDER BY r.position, r.created_at;

-- name: DeleteAssetOwnerRules :exec
DELETE FROM asset_owner_rules WHERE workspace_id = @workspace_id;

-- name: CreateAssetOwnerRule :exec
INSERT INTO asset_owner_rules (workspace_id, position, name, kinds, tags, environments, name_pattern, owner_user_id, owner_group_id, deputy_user_id)
VALUES (@workspace_id, @position, @name, @kinds, @tags, @environments, @name_pattern, sqlc.narg('owner_user_id'), sqlc.narg('owner_group_id'), sqlc.narg('deputy_user_id'));

-- ---- People who can own things ----

-- name: ListAssetPeople :many
SELECT id, username, coalesce(nullif(full_name, ''), username)::text AS name, email, status
FROM users WHERE status IN ('active', 'blocked') ORDER BY name;

-- name: ListAssetGroups :many
SELECT g.id, g.name, (SELECT count(*) FROM group_members m WHERE m.group_id = g.id)::int AS members
FROM user_groups g ORDER BY g.name;

-- name: GroupMemberIDs :many
SELECT user_id FROM group_members WHERE group_id = @group_id;

-- ---- Settings ----

-- name: GetAssetSettings :one
SELECT * FROM asset_settings WHERE workspace_id = @workspace_id;

-- name: UpsertAssetSettings :one
INSERT INTO asset_settings (workspace_id, auto_discover, discover_hours, remind_days, channel_ids, notify_owners)
VALUES (@workspace_id, @auto_discover, @discover_hours, @remind_days, @channel_ids, @notify_owners)
ON CONFLICT (workspace_id) DO UPDATE SET
    auto_discover = EXCLUDED.auto_discover, discover_hours = EXCLUDED.discover_hours,
    remind_days = EXCLUDED.remind_days, channel_ids = EXCLUDED.channel_ids,
    notify_owners = EXCLUDED.notify_owners, updated_at = now()
RETURNING *;

-- name: TouchAssetDiscovery :exec
INSERT INTO asset_settings (workspace_id, last_discovery_at) VALUES (@workspace_id, now())
ON CONFLICT (workspace_id) DO UPDATE SET last_discovery_at = now();

-- name: AssetWorkspacesDueForDiscovery :many
-- Workspaces with servers or clusters whose discovery is on and due; a
-- workspace without settings uses the defaults (on, every 24 hours).
SELECT w.id FROM workspaces w
LEFT JOIN asset_settings s ON s.workspace_id = w.id
WHERE coalesce(s.auto_discover, true)
  AND (s.last_discovery_at IS NULL OR s.last_discovery_at < now() - make_interval(hours => coalesce(s.discover_hours, 24)))
  AND (EXISTS (SELECT 1 FROM servers v WHERE v.workspace_id = w.id)
       OR EXISTS (SELECT 1 FROM pve_clusters c WHERE c.workspace_id = w.id)
       OR EXISTS (SELECT 1 FROM cloud_accounts c WHERE c.workspace_id = w.id)
       OR EXISTS (SELECT 1 FROM dns_servers d WHERE d.workspace_id = w.id));

-- ---- Discovery ----

-- name: ListAssetDiscoveries :many
SELECT d.*, coalesce(s.name, '')::text AS server_name
FROM asset_discoveries d LEFT JOIN servers s ON s.id = d.server_id
WHERE d.workspace_id = @workspace_id
ORDER BY (d.state = 'new') DESC, d.gone, d.first_seen DESC, d.id;

-- name: UpsertAssetDiscovery :exec
INSERT INTO asset_discoveries (workspace_id, key, kind, title, detail, source, server_id, data)
VALUES (@workspace_id, @key, @kind, @title, @detail, @source, sqlc.narg('server_id'), @data)
ON CONFLICT (workspace_id, key) DO UPDATE SET
    kind = EXCLUDED.kind, title = EXCLUDED.title, detail = EXCLUDED.detail, source = EXCLUDED.source,
    server_id = EXCLUDED.server_id, data = EXCLUDED.data, last_seen = now(), gone = false;

-- name: MarkGoneAssetDiscoveries :exec
-- What a source that answered no longer shows is gone; a source that failed
-- this time keeps its findings as they were.
UPDATE asset_discoveries SET gone = true
WHERE workspace_id = @workspace_id AND source = ANY (@sources::text[]) AND last_seen < @since AND NOT gone;

-- name: ResolveAssetDiscoveries :exec
-- Findings now managed by Morche (their key was added to a section) count
-- as accepted.
UPDATE asset_discoveries SET state = 'accepted', gone = true
WHERE workspace_id = @workspace_id AND key = ANY (@keys::text[]) AND state = 'new';

-- name: SetAssetDiscoveryState :exec
UPDATE asset_discoveries SET state = @state WHERE workspace_id = @workspace_id AND id = ANY (@ids::uuid[]);

-- name: GetAssetDiscovery :one
SELECT * FROM asset_discoveries WHERE workspace_id = @workspace_id AND id = @id;

-- name: SetAssetDiscoveryAsset :exec
UPDATE asset_discoveries SET state = 'accepted', asset_id = @asset_id WHERE id = @id;

-- name: DiscoveryServers :many
SELECT id, name, host, status, os_name FROM servers WHERE workspace_id = @workspace_id ORDER BY name;

-- name: DiscoveryDatabases :many
SELECT id, name, engine, mode, server_id, host, port, container FROM databases WHERE workspace_id = @workspace_id;

-- name: DiscoveryServerHosts :many
-- Every address a server of the workspace answers on, for matching.
SELECT id, host, hostname FROM servers WHERE workspace_id = @workspace_id;

-- name: DiscoveryPVEClusters :many
SELECT * FROM pve_clusters WHERE workspace_id = @workspace_id;

-- name: DiscoveryCloudAccounts :many
SELECT * FROM cloud_accounts WHERE workspace_id = @workspace_id;

-- name: DiscoveryDNSServers :many
SELECT * FROM dns_servers WHERE workspace_id = @workspace_id;

-- name: DiscoveryPVELinks :many
SELECT cluster_id, vmid FROM pve_vm_links l JOIN pve_clusters c ON c.id = l.cluster_id WHERE c.workspace_id = @workspace_id;

-- ---- Reminders and owner alerts ----

-- name: ListAssetsForReminders :many
SELECT a.id, a.workspace_id, a.name, a.kind, a.purchased_on, a.warranty_until, a.expires_on, a.facts,
    a.review_days, a.reviewed_at, a.created_at, a.channel_ids, a.reminded, a.lifecycle, a.auto_renew
FROM assets a
WHERE a.lifecycle <> 'retired' AND NOT a.source_gone
  AND (a.warranty_until <> '' OR a.expires_on <> '' OR a.review_days > 0 OR a.facts ? 'cert_expires_at');

-- name: SetAssetReminded :exec
UPDATE assets SET reminded = @reminded WHERE id = @id;

-- name: AssetChannelsForSource :many
-- The channels an asset's owners asked to hear about it on.
SELECT c.* FROM notification_channels c
JOIN assets a ON c.id = ANY (a.channel_ids)
WHERE a.source_kind = @source_kind AND a.source_ref = @source_ref AND c.enabled AND c.workspace_id = a.workspace_id
  AND coalesce((SELECT s.notify_owners FROM asset_settings s WHERE s.workspace_id = a.workspace_id), true);

-- name: AssetReminderChannels :many
SELECT * FROM notification_channels
WHERE workspace_id = @workspace_id AND enabled AND (id = ANY (@ids::uuid[]) OR (cardinality(@ids::uuid[]) = 0 AND is_default));
