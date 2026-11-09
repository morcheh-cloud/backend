-- +goose Up
-- A proxy runs on the server itself (host) or in a container there: then
-- every command goes through `docker|podman exec`, and container names it.
ALTER TABLE proxies ADD COLUMN runtime text NOT NULL DEFAULT 'host'
    CHECK (runtime IN ('host', 'docker', 'podman'));
ALTER TABLE proxies ADD COLUMN container text NOT NULL DEFAULT '';
ALTER TABLE proxies ADD CONSTRAINT proxies_container_check
    CHECK ((runtime = 'host') = (container = ''));
ALTER TABLE proxies DROP CONSTRAINT proxies_server_id_kind_key;
ALTER TABLE proxies ADD CONSTRAINT proxies_server_id_kind_container_key
    UNIQUE (server_id, kind, container);

-- +goose Down
ALTER TABLE proxies DROP CONSTRAINT proxies_server_id_kind_container_key;
DELETE FROM proxies WHERE runtime <> 'host';
ALTER TABLE proxies ADD CONSTRAINT proxies_server_id_kind_key UNIQUE (server_id, kind);
ALTER TABLE proxies DROP CONSTRAINT proxies_container_check;
ALTER TABLE proxies DROP COLUMN container;
ALTER TABLE proxies DROP COLUMN runtime;
