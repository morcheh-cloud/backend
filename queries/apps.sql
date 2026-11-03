-- name: ListApps :many
-- Category order first (uncategorized last), then the order inside it.
-- pattern is an ILIKE pattern over name, address and note; '' = everything.
SELECT a.* FROM apps a
LEFT JOIN app_categories c ON c.id = a.category_id
WHERE (@see_all::bool OR a.workspace_id = ANY (@workspace_ids::uuid[]) OR a.id = ANY (@app_ids::uuid[]))
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR a.workspace_id = sqlc.narg('workspace_id')::uuid)
  AND (@pattern::text = '' OR a.name ILIKE @pattern OR a.address ILIKE @pattern OR a.note ILIKE @pattern)
ORDER BY c.position NULLS LAST, lower(c.name), a.position, lower(a.name);

-- name: GetApp :one
SELECT * FROM apps WHERE id = $1;

-- name: CreateApp :one
INSERT INTO apps (
    workspace_id, category_id, name, address, note, color, critical, position,
    logo_kind, logo_icon
) VALUES (
    @workspace_id, sqlc.narg('category_id'), @name, @address, @note, @color,
    @critical, @position, @logo_kind, @logo_icon
)
RETURNING *;

-- name: UpdateApp :one
UPDATE apps SET
    category_id = sqlc.narg('category_id'),
    name = @name,
    address = @address,
    note = @note,
    color = @color,
    critical = @critical,
    position = @position,
    logo_kind = @logo_kind,
    logo_icon = @logo_icon,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: NextAppPosition :one
-- Where a service lands at the end of its category (or of the uncategorized).
SELECT COALESCE(MAX(position) + 1, 0)::int FROM apps
WHERE workspace_id = @workspace_id
  AND category_id IS NOT DISTINCT FROM sqlc.narg('category_id')::uuid;

-- name: DeleteApp :execrows
DELETE FROM apps WHERE id = $1;

-- name: ListAppAccounts :many
SELECT * FROM app_accounts WHERE app_id = ANY (@app_ids::uuid[])
ORDER BY app_id, position;

-- name: CreateAppAccount :one
INSERT INTO app_accounts (app_id, label, username, password_enc, position)
VALUES (@app_id, @label, @username, sqlc.narg('password_enc'), @position)
RETURNING *;

-- name: UpdateAppAccount :one
UPDATE app_accounts SET
    label = @label,
    username = @username,
    password_enc = sqlc.narg('password_enc'),
    position = @position
WHERE id = @id AND app_id = @app_id
RETURNING *;

-- name: DeleteAppAccountsExcept :exec
DELETE FROM app_accounts WHERE app_id = @app_id AND NOT (id = ANY (@keep::uuid[]));

-- name: ListAppLogoStamps :many
SELECT app_id, source, updated_at FROM app_logos WHERE app_id = ANY (@app_ids::uuid[]);

-- name: DeleteAppLogo :exec
DELETE FROM app_logos WHERE app_id = @app_id AND source = @source;

-- name: GetAppCategory :one
SELECT * FROM app_categories WHERE id = $1;

-- name: ListAppCategories :many
SELECT * FROM app_categories WHERE workspace_id = ANY (@workspace_ids::uuid[])
ORDER BY workspace_id, position, lower(name);

-- name: CreateAppCategory :one
-- New categories go last.
INSERT INTO app_categories (workspace_id, name, color, position)
VALUES (@workspace_id, @name, @color,
    (SELECT COALESCE(MAX(position) + 1, 0)::int FROM app_categories WHERE workspace_id = @workspace_id))
RETURNING *;

-- name: UpdateAppCategory :one
UPDATE app_categories SET name = @name, color = @color, updated_at = now()
WHERE id = @id AND workspace_id = @workspace_id
RETURNING *;

-- name: DeleteAppCategory :execrows
DELETE FROM app_categories WHERE id = @id AND workspace_id = @workspace_id;

-- name: SetAppCategoryPosition :exec
UPDATE app_categories SET position = @position
WHERE id = @id AND workspace_id = @workspace_id;

-- name: SetAppPlace :exec
-- A service of another workspace (or one already removed) is left alone.
UPDATE apps SET category_id = sqlc.narg('category_id'), position = @position
WHERE id = @id AND workspace_id = @workspace_id;

-- name: GetAppAccount :one
SELECT * FROM app_accounts WHERE id = $1 AND app_id = $2;

-- name: CreateAppSecretView :exec
INSERT INTO app_secret_views (app_id, account_id, account_label, user_id, user_name, ip)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAppSecretViews :many
SELECT * FROM app_secret_views WHERE app_id = $1 ORDER BY created_at DESC LIMIT 200;
