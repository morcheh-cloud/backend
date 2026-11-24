-- +goose Up
-- Direct databases, Proxmox clusters, monitors (their "from Morche"
-- location) and storages can be reached through a tunnel too.
ALTER TABLE databases ADD COLUMN tunnel_id uuid REFERENCES tunnels (id) ON DELETE SET NULL;
ALTER TABLE pve_clusters ADD COLUMN tunnel_id uuid REFERENCES tunnels (id) ON DELETE SET NULL;
ALTER TABLE monitors ADD COLUMN tunnel_id uuid REFERENCES tunnels (id) ON DELETE SET NULL;
ALTER TABLE storages ADD COLUMN tunnel_id uuid REFERENCES tunnels (id) ON DELETE SET NULL;
CREATE INDEX databases_tunnel_id_idx ON databases (tunnel_id) WHERE tunnel_id IS NOT NULL;
CREATE INDEX pve_clusters_tunnel_id_idx ON pve_clusters (tunnel_id) WHERE tunnel_id IS NOT NULL;
CREATE INDEX monitors_tunnel_id_idx ON monitors (tunnel_id) WHERE tunnel_id IS NOT NULL;
CREATE INDEX storages_tunnel_id_idx ON storages (tunnel_id) WHERE tunnel_id IS NOT NULL;

-- +goose Down
ALTER TABLE storages DROP COLUMN tunnel_id;
ALTER TABLE monitors DROP COLUMN tunnel_id;
ALTER TABLE pve_clusters DROP COLUMN tunnel_id;
ALTER TABLE databases DROP COLUMN tunnel_id;
