-- ---- Sign-in log ----

-- name: RecordSignIn :one
INSERT INTO sign_ins (
    user_id, username, ip, network, user_agent, kind, reason, new_address,
    session_id, by_user_id, by_name
) VALUES (
    sqlc.narg('user_id'), @username, @ip, @network, @user_agent, @kind, @reason,
    @new_address, sqlc.narg('session_id'), sqlc.narg('by_user_id'), @by_name
)
RETURNING *;

-- name: ListSignIns :many
-- Newest first, paged by (at, id) from the last row of the previous page.
SELECT sqlc.embed(l), (s.id IS NOT NULL)::bool AS session_open
FROM sign_ins l
LEFT JOIN sessions s ON s.id = l.session_id AND s.expires_at > now()
WHERE (sqlc.narg('user_id')::uuid IS NULL OR l.user_id = sqlc.narg('user_id')::uuid)
  AND (cardinality(@kinds::text[]) = 0 OR l.kind = ANY (@kinds::text[]))
  AND (NOT @new_only::bool OR l.new_address)
  AND (@q::text = '' OR l.username ILIKE '%' || @q || '%' OR l.ip ILIKE @q || '%')
  AND (sqlc.narg('since')::timestamptz IS NULL OR l.at >= sqlc.narg('since')::timestamptz)
  AND (sqlc.narg('before_at')::timestamptz IS NULL
       OR (l.at, l.id) < (sqlc.narg('before_at')::timestamptz, sqlc.narg('before_id')::uuid))
ORDER BY l.at DESC, l.id DESC
LIMIT @lim;

-- name: GetSignIn :one
SELECT * FROM sign_ins WHERE id = $1;

-- name: KnownNetwork :one
-- Has this person signed in from this network before (in what's kept)?
SELECT EXISTS (
    SELECT 1 FROM sign_ins
    WHERE user_id = @user_id AND kind = 'signed_in' AND network = @network
)::bool;

-- name: HasSignedIn :one
SELECT EXISTS (
    SELECT 1 FROM sign_ins WHERE user_id = $1 AND kind = 'signed_in'
)::bool;

-- name: PendingSignInAlerts :many
-- New-address sign-ins nobody has answered yet, for the person's other devices.
SELECT sqlc.embed(l), (s.id IS NOT NULL)::bool AS session_open
FROM sign_ins l
LEFT JOIN sessions s ON s.id = l.session_id AND s.expires_at > now()
WHERE l.user_id = @user_id AND l.kind = 'signed_in' AND l.new_address
  AND l.answer = '' AND l.at > now() - interval '14 days'
  AND l.session_id IS DISTINCT FROM sqlc.narg('current')::uuid
ORDER BY l.at DESC
LIMIT 5;

-- name: AnswerSignIn :one
UPDATE sign_ins SET answer = @answer, answered_at = now()
WHERE id = @id AND user_id = @user_id AND kind = 'signed_in'
RETURNING *;

-- name: DeleteOldSignIns :exec
DELETE FROM sign_ins WHERE at < now() - make_interval(days => @days::int);
