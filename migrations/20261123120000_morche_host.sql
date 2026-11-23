-- +goose Up

-- The machine Morche itself runs on, added by MANAGE_HOST (or from the
-- panel). It starts with a key Morche made for itself and waits for someone
-- to sign in once ('needs_login') or to put that key on it by hand.
ALTER TABLE servers DROP CONSTRAINT servers_status_check;
ALTER TABLE servers ADD CONSTRAINT servers_status_check CHECK (status IN (
    'unknown', 'online', 'unreachable', 'auth_failed', 'host_key_mismatch', 'error', 'needs_login'));
ALTER TABLE servers
    ADD COLUMN morche_host boolean NOT NULL DEFAULT false,
    -- authorized_keys line of the key Morche made for this server; '' = none.
    ADD COLUMN setup_public_key text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX servers_morche_host_key ON servers (morche_host) WHERE morche_host;

-- Set once MANAGE_HOST has added it, so a deleted one doesn't come back.
ALTER TABLE app_settings ADD COLUMN morche_host_added_at timestamptz;

-- +goose Down
ALTER TABLE app_settings DROP COLUMN morche_host_added_at;
DROP INDEX servers_morche_host_key;
ALTER TABLE servers DROP COLUMN setup_public_key, DROP COLUMN morche_host;
UPDATE servers SET status = 'auth_failed' WHERE status = 'needs_login';
ALTER TABLE servers DROP CONSTRAINT servers_status_check;
ALTER TABLE servers ADD CONSTRAINT servers_status_check CHECK (status IN (
    'unknown', 'online', 'unreachable', 'auth_failed', 'host_key_mismatch', 'error'));
