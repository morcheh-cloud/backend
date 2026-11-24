-- +goose Up
-- Ways to reach servers Morche can't reach directly: an SSH jump host, a
-- SOCKS5/HTTP proxy or a VPN (WireGuard, OpenVPN, openconnect, SSTP). config
-- holds the settings, secrets_enc the sealed passwords/keys/.ovpn file. A
-- tunnel opens on first use; status is what it last did.
CREATE TABLE tunnels (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id      uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name              text NOT NULL,
    kind              text NOT NULL
        CHECK (kind IN ('jump', 'socks5', 'http', 'wireguard', 'openvpn', 'openconnect', 'sstp')),
    config            jsonb NOT NULL DEFAULT '{}',
    secrets_enc       bytea,
    description       text NOT NULL DEFAULT '',
    status            text NOT NULL DEFAULT 'idle'
        CHECK (status IN ('idle', 'connecting', 'connected', 'failed')),
    status_message    text NOT NULL DEFAULT '',
    address           text NOT NULL DEFAULT '',
    status_at         timestamptz,
    last_connected_at timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX tunnels_name_key ON tunnels (workspace_id, lower(name));

-- The tunnel a server is reached through; NULL = directly.
ALTER TABLE servers ADD COLUMN tunnel_id uuid REFERENCES tunnels (id) ON DELETE SET NULL;
CREATE INDEX servers_tunnel_id_idx ON servers (tunnel_id) WHERE tunnel_id IS NOT NULL;

-- +goose Down
ALTER TABLE servers DROP COLUMN tunnel_id;
DROP TABLE tunnels;
