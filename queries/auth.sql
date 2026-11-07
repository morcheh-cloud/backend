-- name: CountUsers :one
SELECT count(*)::int FROM users;

-- name: CountActiveAdmins :one
SELECT count(*)::int FROM users WHERE role = 'admin' AND status = 'active';

-- name: LockAuth :exec
-- Serializes first-run setup and last-admin checks for the transaction.
SELECT pg_advisory_xact_lock(7264001);

-- name: CreateUser :one
INSERT INTO users (username, email, first_name, full_name, password_hash, role, status, must_change_password)
VALUES (@username, @email, @first_name, @full_name, @password_hash, @role, @status, @must_change_password)
RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE lower(username) = lower(@username::text);

-- name: ListUsers :many
SELECT * FROM users
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('q')::text IS NULL
       OR username ILIKE '%' || sqlc.narg('q')::text || '%'
       OR email ILIKE '%' || sqlc.narg('q')::text || '%'
       OR full_name ILIKE '%' || sqlc.narg('q')::text || '%'
       OR first_name ILIKE '%' || sqlc.narg('q')::text || '%')
ORDER BY status = 'pending' DESC, lower(full_name), id;

-- name: UserStatusCounts :many
SELECT status AS value, count(*)::int AS count FROM users GROUP BY status;

-- name: UpdateUserProfile :one
UPDATE users SET email = @email, first_name = @first_name, full_name = @full_name, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetUserRole :one
UPDATE users SET role = @role, updated_at = now() WHERE id = @id RETURNING *;

-- name: SetUserStatus :one
UPDATE users SET status = @status, updated_at = now() WHERE id = @id RETURNING *;

-- name: SetUserPassword :one
UPDATE users SET password_hash = @password_hash, must_change_password = @must_change_password, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetUsername :one
UPDATE users SET username = @username, updated_at = now() WHERE id = @id RETURNING *;

-- name: TouchUserLogin :exec
UPDATE users SET last_login_at = now() WHERE id = $1;

-- name: DeleteUser :execrows
DELETE FROM users WHERE id = $1;

-- ---- Sessions ----

-- name: CreateSession :one
INSERT INTO sessions (user_id, token_hash, remember, user_agent, ip, expires_at)
VALUES (@user_id, @token_hash, @remember, @user_agent, @ip, @expires_at)
RETURNING *;

-- name: GetSessionByHash :one
SELECT sqlc.embed(s), sqlc.embed(u)
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1 AND s.expires_at > now();

-- name: GetSessionUser :one
-- For re-checking a session someone is still connected with.
SELECT sqlc.embed(u)
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.id = $1 AND s.expires_at > now();

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = now() WHERE id = $1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = $1;

-- name: DeleteOtherUserSessions :exec
DELETE FROM sessions WHERE user_id = @user_id AND id <> @keep;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at <= now();

-- name: CountUserSessions :one
SELECT count(*)::int FROM sessions WHERE user_id = $1 AND expires_at > now();

-- ---- Settings ----

-- name: GetSettings :one
SELECT * FROM app_settings WHERE id;

-- name: SetRegistrationOpen :one
UPDATE app_settings SET registration_open = @registration_open, updated_at = now() WHERE id RETURNING *;

-- ---- Groups ----

-- name: ListGroups :many
SELECT g.*, count(m.user_id)::int AS member_count
FROM user_groups g
LEFT JOIN group_members m ON m.group_id = g.id
GROUP BY g.id
ORDER BY lower(g.name);

-- name: GetGroup :one
SELECT * FROM user_groups WHERE id = $1;

-- name: CreateGroup :one
INSERT INTO user_groups (name, description) VALUES (@name, @description) RETURNING *;

-- name: UpdateGroup :one
UPDATE user_groups SET name = @name, description = @description, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteGroup :execrows
DELETE FROM user_groups WHERE id = $1;

-- name: ListGroupMembers :many
SELECT user_id FROM group_members WHERE group_id = $1;

-- name: ListAllGroupMembers :many
SELECT group_id, user_id FROM group_members;

-- name: ClearGroupMembers :exec
DELETE FROM group_members WHERE group_id = $1;

-- name: AddGroupMembers :exec
INSERT INTO group_members (group_id, user_id)
SELECT @group_id, unnest(@user_ids::uuid[])
ON CONFLICT DO NOTHING;

-- name: SetUserGroups :exec
-- Replaces the groups of one user (approving someone, editing them).
WITH removed AS (
    DELETE FROM group_members WHERE group_members.user_id = @user_id AND group_id <> ALL (@group_ids::uuid[])
)
INSERT INTO group_members (group_id, user_id)
SELECT unnest(@group_ids::uuid[]), @user_id
ON CONFLICT DO NOTHING;

-- ---- Workspaces ----

-- name: ListWorkspaces :many
SELECT w.*,
       (SELECT count(*) FROM servers s WHERE s.workspace_id = w.id)::int AS server_count,
       (SELECT count(*) FROM storages t WHERE t.workspace_id = w.id)::int AS storage_count,
       (SELECT count(*) FROM apps a WHERE a.workspace_id = w.id)::int AS app_count,
       l.updated_at AS logo_updated_at
FROM workspaces w
LEFT JOIN workspace_logos l ON l.workspace_id = w.id
ORDER BY lower(w.name);

-- name: GetWorkspace :one
SELECT * FROM workspaces WHERE id = $1;

-- name: CreateWorkspace :one
INSERT INTO workspaces (name, description, color, logo_kind, logo_icon)
VALUES (@name, @description, @color, @logo_kind, @logo_icon)
RETURNING *;

-- name: UpdateWorkspace :one
UPDATE workspaces SET name = @name, description = @description, color = @color,
    logo_kind = @logo_kind, logo_icon = @logo_icon, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: GetWorkspaceLogo :one
SELECT * FROM workspace_logos WHERE workspace_id = $1;

-- name: GetWorkspaceLogoStamp :one
SELECT updated_at FROM workspace_logos WHERE workspace_id = $1;

-- name: PutWorkspaceLogo :exec
INSERT INTO workspace_logos (workspace_id, content_type, data)
VALUES (@workspace_id, @content_type, @data)
ON CONFLICT (workspace_id) DO UPDATE
SET content_type = EXCLUDED.content_type, data = EXCLUDED.data, updated_at = now();

-- name: DeleteWorkspaceLogo :exec
DELETE FROM workspace_logos WHERE workspace_id = $1;

-- name: SetWorkspaceLogoKind :one
UPDATE workspaces SET logo_kind = @logo_kind, updated_at = now() WHERE id = @id RETURNING *;

-- name: DeleteWorkspace :execrows
DELETE FROM workspaces WHERE id = $1;

-- name: CountWorkspaces :one
SELECT count(*)::int FROM workspaces;

-- name: CountWorkspaceResources :one
SELECT (SELECT count(*) FROM servers s WHERE s.workspace_id = $1)::int AS servers,
       (SELECT count(*) FROM storages t WHERE t.workspace_id = $1)::int AS storages,
       (SELECT count(*) FROM databases d WHERE d.workspace_id = $1)::int AS databases,
       (SELECT count(*) FROM apps a WHERE a.workspace_id = $1)::int AS apps;

-- name: MoveServersToWorkspace :execrows
-- Folders belong to one workspace, so moved servers leave theirs.
UPDATE servers SET workspace_id = @workspace_id, folder_id = NULL, updated_at = now()
WHERE id = ANY (@ids::uuid[]) AND workspace_id <> @workspace_id;

-- name: MoveStoragesToWorkspace :execrows
UPDATE storages SET workspace_id = @workspace_id, updated_at = now()
WHERE id = ANY (@ids::uuid[]) AND workspace_id <> @workspace_id;

-- name: MoveAppsToWorkspace :execrows
-- Categories belong to one workspace, so moved services leave theirs.
UPDATE apps SET workspace_id = @workspace_id, category_id = NULL, updated_at = now()
WHERE id = ANY (@ids::uuid[]) AND workspace_id <> @workspace_id;

-- name: GetServerWorkspace :one
SELECT workspace_id FROM servers WHERE id = $1;

-- name: GetStorageWorkspace :one
SELECT workspace_id FROM storages WHERE id = $1;

-- name: GetAppWorkspace :one
SELECT workspace_id FROM apps WHERE id = $1;

-- name: ListServerWorkspaces :many
SELECT id, workspace_id FROM servers WHERE id = ANY (@ids::uuid[]);

-- name: ListStorageWorkspaces :many
SELECT id, workspace_id FROM storages WHERE id = ANY (@ids::uuid[]);

-- name: ListAppWorkspaces :many
SELECT id, workspace_id FROM apps WHERE id = ANY (@ids::uuid[]);

-- name: ListWorkspaceServers :many
-- The light list for an access page: never the sealed credentials.
SELECT id, name, host FROM servers WHERE workspace_id = $1 ORDER BY lower(name);

-- name: ListWorkspaceStorages :many
SELECT id, name, protocol FROM storages WHERE workspace_id = $1 ORDER BY lower(name);

-- name: ListWorkspaceApps :many
SELECT id, name, address FROM apps WHERE workspace_id = $1 ORDER BY lower(name);

-- ---- Grants ----

-- name: ListUserGrants :many
-- Every grant that applies to a user, directly or through a group.
SELECT g.*
FROM access_grants g
WHERE g.user_id = @user_id
   OR g.group_id IN (SELECT m.group_id FROM group_members m WHERE m.user_id = @user_id);

-- name: ListGrants :many
-- Filters combine with AND. Joins give the names a screen shows.
SELECT g.*,
       u.username, u.full_name, u.status AS user_status, ug.name AS group_name,
       w.name AS workspace_name, s.name AS server_name, t.name AS storage_name,
       a.name AS app_name
FROM access_grants g
LEFT JOIN users u ON u.id = g.user_id
LEFT JOIN user_groups ug ON ug.id = g.group_id
LEFT JOIN workspaces w ON w.id = g.workspace_id
LEFT JOIN servers s ON s.id = g.server_id
LEFT JOIN storages t ON t.id = g.storage_id
LEFT JOIN apps a ON a.id = g.app_id
WHERE (sqlc.narg('user_id')::uuid IS NULL OR g.user_id = sqlc.narg('user_id')::uuid)
  AND (sqlc.narg('group_id')::uuid IS NULL OR g.group_id = sqlc.narg('group_id')::uuid)
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR g.workspace_id = sqlc.narg('workspace_id')::uuid)
  AND (sqlc.narg('server_id')::uuid IS NULL OR g.server_id = sqlc.narg('server_id')::uuid)
  AND (sqlc.narg('storage_id')::uuid IS NULL OR g.storage_id = sqlc.narg('storage_id')::uuid)
  AND (sqlc.narg('app_id')::uuid IS NULL OR g.app_id = sqlc.narg('app_id')::uuid)
ORDER BY g.created_at, g.id;

-- name: GetGrant :one
SELECT * FROM access_grants WHERE id = $1;

-- name: FindGrant :one
SELECT * FROM access_grants
WHERE user_id IS NOT DISTINCT FROM sqlc.narg('user_id')::uuid
  AND group_id IS NOT DISTINCT FROM sqlc.narg('group_id')::uuid
  AND workspace_id IS NOT DISTINCT FROM sqlc.narg('workspace_id')::uuid
  AND server_id IS NOT DISTINCT FROM sqlc.narg('server_id')::uuid
  AND storage_id IS NOT DISTINCT FROM sqlc.narg('storage_id')::uuid
  AND app_id IS NOT DISTINCT FROM sqlc.narg('app_id')::uuid;

-- name: UpsertGrant :one
INSERT INTO access_grants (user_id, group_id, workspace_id, server_id, storage_id, app_id, level, can_create)
VALUES (sqlc.narg('user_id'), sqlc.narg('group_id'), sqlc.narg('workspace_id'), sqlc.narg('server_id'), sqlc.narg('storage_id'), sqlc.narg('app_id'), @level, @can_create)
ON CONFLICT (user_id, group_id, workspace_id, server_id, storage_id, app_id)
DO UPDATE SET level = EXCLUDED.level, can_create = EXCLUDED.can_create, updated_at = now()
RETURNING *;

-- name: DeleteGrant :execrows
DELETE FROM access_grants WHERE id = $1;

-- name: ListPrincipalUsers :many
-- People an owner can give access to.
SELECT id, username, full_name FROM users WHERE status = 'active' ORDER BY lower(full_name), id;
