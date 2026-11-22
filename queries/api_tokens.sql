-- ---- API tokens ----

-- name: CreateApiToken :one
INSERT INTO api_tokens (user_id, name, prefix, token_hash, read_only, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetApiTokenByHash :one
-- A token that is still good, with its user.
SELECT sqlc.embed(t), sqlc.embed(u)
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.token_hash = $1 AND (t.expires_at IS NULL OR t.expires_at > now());

-- name: GetApiTokenUser :one
-- For re-checking a token a stream is still open with.
SELECT sqlc.embed(u)
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.id = $1 AND (t.expires_at IS NULL OR t.expires_at > now());

-- name: TouchApiToken :exec
UPDATE api_tokens SET last_used_at = now(), last_used_ip = $2 WHERE id = $1;

-- name: ListUserApiTokens :many
SELECT * FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC;

-- name: CountUserApiTokens :one
SELECT count(*) FROM api_tokens WHERE user_id = $1;

-- name: GetApiToken :one
SELECT * FROM api_tokens WHERE id = $1;

-- name: DeleteUserApiToken :execrows
DELETE FROM api_tokens WHERE id = $1 AND user_id = $2;

-- name: DeleteApiToken :execrows
DELETE FROM api_tokens WHERE id = $1;
