-- +goose Up
-- A DNS connection is a Technitium server or an ArvanCloud CDN account (its
-- domains are the zones). allow_changes = Morche may write; an ArvanCloud
-- account starts read only.
ALTER TABLE dns_servers
    ADD COLUMN kind text NOT NULL DEFAULT 'technitium' CHECK (kind IN ('technitium', 'arvan')),
    ADD COLUMN allow_changes boolean NOT NULL DEFAULT true;

-- +goose Down
ALTER TABLE dns_servers DROP COLUMN allow_changes, DROP COLUMN kind;
