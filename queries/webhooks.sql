-- ---- Outgoing webhooks ----

-- name: CreateWebhook :one
INSERT INTO webhooks (workspace_id, name, url, events, secret_enc, headers_enc, enabled, include_muted, allow_internal, created_by, created_by_name)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: UpdateWebhook :one
UPDATE webhooks SET name = $2, url = $3, events = $4, headers_enc = $5, enabled = $6,
    include_muted = $7, allow_internal = $8, updated_at = now()
WHERE id = $1
RETURNING *;

-- name: SetWebhookSecret :one
UPDATE webhooks SET secret_enc = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: GetWebhook :one
SELECT * FROM webhooks WHERE id = $1;

-- name: GetWebhookWorkspace :one
SELECT workspace_id FROM webhooks WHERE id = $1;

-- name: ListWebhooks :many
SELECT * FROM webhooks WHERE workspace_id = $1 ORDER BY name, created_at;

-- name: ListEnabledWebhooks :many
-- The webhooks an event of this workspace may go to.
SELECT * FROM webhooks WHERE workspace_id = $1 AND enabled;

-- name: DeleteWebhook :exec
DELETE FROM webhooks WHERE id = $1;

-- name: NoteWebhookAttempt :exec
-- How the latest attempt went.
UPDATE webhooks SET last_status = sqlc.arg(status)::text, last_delivery_at = now(),
    failing_since = CASE WHEN sqlc.arg(status)::text = 'delivered' THEN NULL
                         ELSE coalesce(failing_since, now()) END
WHERE id = sqlc.arg(id);

-- ---- Deliveries ----

-- name: InsertWebhookDelivery :one
INSERT INTO webhook_deliveries (webhook_id, event_id, event_type, body, next_try_at, redelivery_of)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ClaimDueWebhookDeliveries :many
-- Takes due deliveries for a while (lease_until), so two loops never send the
-- same one and one stuck by a crash is tried again after the lease.
UPDATE webhook_deliveries SET next_try_at = sqlc.arg(lease_until)::timestamptz
WHERE id IN (
    SELECT d.id FROM webhook_deliveries d
    WHERE d.status = 'pending' AND d.next_try_at <= now()
    ORDER BY d.next_try_at
    LIMIT sqlc.arg(max_rows)::int
    FOR UPDATE SKIP LOCKED
)
RETURNING *;

-- name: FinishWebhookAttempt :one
UPDATE webhook_deliveries SET attempt = $2, status = $3, http_status = $4, response = $5,
    duration_ms = $6, error = $7, next_try_at = $8, updated_at = now()
WHERE id = $1
RETURNING *;

-- name: GetWebhookDelivery :one
SELECT * FROM webhook_deliveries WHERE id = $1;

-- name: GetWebhookDeliveryWorkspace :one
SELECT w.workspace_id FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id WHERE d.id = $1;

-- name: ListWebhookDeliveries :many
SELECT * FROM webhook_deliveries
WHERE webhook_id = $1 AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountWebhookDeliveries :one
SELECT count(*) FROM webhook_deliveries
WHERE webhook_id = $1 AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text);

-- name: PruneWebhookDeliveries :execrows
-- Older than the cut-off, or past the newest keep of their webhook.
DELETE FROM webhook_deliveries d
WHERE d.status <> 'pending' AND (d.created_at < sqlc.arg(before)::timestamptz OR d.id IN (
    SELECT x.id FROM (
        SELECT id, row_number() OVER (PARTITION BY webhook_id ORDER BY created_at DESC) AS n
        FROM webhook_deliveries
    ) x WHERE x.n > sqlc.arg(keep)::int
));
