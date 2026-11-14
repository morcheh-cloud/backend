-- +goose Up
-- A proxy whose container runs a proxy manager (Nginx Proxy Manager…) that
-- writes nginx's config itself: Morche only reads it, never writes there.
ALTER TABLE proxies ADD COLUMN manager text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE proxies DROP COLUMN manager;
