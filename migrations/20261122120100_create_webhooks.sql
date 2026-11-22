-- +goose Up
-- Outgoing webhooks: events of a workspace POSTed to a URL, signed.
CREATE TABLE webhooks (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id     uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name             text NOT NULL,
    url              text NOT NULL,
    -- Event types to send; empty = all of them.
    events           text[] NOT NULL DEFAULT '{}',
    -- Sealed signing secret and sealed extra headers (JSON object).
    secret_enc       bytea,
    headers_enc      bytea,
    enabled          boolean NOT NULL DEFAULT true,
    -- Send muted alert events too (they carry data.muted = true).
    include_muted    boolean NOT NULL DEFAULT false,
    -- A private or loopback address; only a system admin can turn it on.
    allow_internal   boolean NOT NULL DEFAULT false,
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name  text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    -- delivered | failed: how the last attempt went ('' = never sent).
    last_status      text NOT NULL DEFAULT '',
    last_delivery_at timestamptz,
    -- Since when every attempt has failed (NULL = the last one worked).
    failing_since    timestamptz
);

CREATE INDEX webhooks_workspace_idx ON webhooks (workspace_id);

-- One event to one webhook. A failed attempt with tries left stays pending
-- with next_try_at set; the dispatcher's loop picks it up (survives restarts).
CREATE TABLE webhook_deliveries (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    webhook_id  uuid NOT NULL REFERENCES webhooks (id) ON DELETE CASCADE,
    event_id    uuid NOT NULL,
    event_type  text NOT NULL,
    -- The JSON body sent (the same on every attempt).
    body        text NOT NULL,
    attempt     integer NOT NULL DEFAULT 0,
    status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed')),
    http_status integer,
    -- The start of the answer (≤ 4 KB).
    response    text NOT NULL DEFAULT '',
    duration_ms integer NOT NULL DEFAULT 0,
    error       text NOT NULL DEFAULT '',
    next_try_at timestamptz,
    -- Redelivered from this delivery.
    redelivery_of uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX webhook_deliveries_hook_idx ON webhook_deliveries (webhook_id, created_at DESC);
CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries (next_try_at) WHERE status = 'pending';

-- +goose Down
DROP TABLE webhook_deliveries;
DROP TABLE webhooks;
