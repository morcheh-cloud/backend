-- +goose Up

-- The asset inventory: one row per thing the organisation owns or pays for.
-- Things Morche already manages (servers, databases, storages…) get a linked
-- row kept in step by the sync (source_kind + source_ref); everything else
-- (hardware, licences, domains, subscriptions…) is entered by hand. The row
-- holds what Morche can't know: who owns it, how critical it is, what it
-- costs, when it expires.
CREATE TABLE assets (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id        uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    kind                text NOT NULL CHECK (length(kind) BETWEEN 1 AND 40),
    category            text NOT NULL DEFAULT '' CHECK (length(category) <= 60),
    name                text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description         text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    -- Linked rows: what it mirrors. '' = entered by hand.
    source_kind         text NOT NULL DEFAULT '',
    source_ref          text NOT NULL DEFAULT '',
    source_gone         boolean NOT NULL DEFAULT false,
    facts               jsonb NOT NULL DEFAULT '{}',
    last_seen_at        timestamptz,
    -- Ownership. It grants no access.
    owner_user_id       uuid REFERENCES users (id) ON DELETE SET NULL,
    owner_group_id      uuid REFERENCES user_groups (id) ON DELETE SET NULL,
    deputy_user_id      uuid REFERENCES users (id) ON DELETE SET NULL,
    assigned_user_id    uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Classification.
    environment         text NOT NULL DEFAULT '' CHECK (environment IN ('', 'production', 'staging', 'development', 'test')),
    criticality         smallint NOT NULL DEFAULT 0 CHECK (criticality BETWEEN 0 AND 4),
    classification      text NOT NULL DEFAULT '' CHECK (classification IN ('', 'public', 'internal', 'confidential', 'restricted')),
    lifecycle           text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('planned', 'active', 'maintenance', 'deprecated', 'retired')),
    tags                text[] NOT NULL DEFAULT '{}',
    -- Purchase, hardware and licence details.
    vendor              text NOT NULL DEFAULT '' CHECK (length(vendor) <= 200),
    model               text NOT NULL DEFAULT '' CHECK (length(model) <= 200),
    serial_number       text NOT NULL DEFAULT '' CHECK (length(serial_number) <= 200),
    asset_tag           text NOT NULL DEFAULT '' CHECK (length(asset_tag) <= 100),
    location            text NOT NULL DEFAULT '' CHECK (length(location) <= 200),
    cost_cents          bigint CHECK (cost_cents >= 0),
    currency            text NOT NULL DEFAULT '' CHECK (length(currency) <= 8),
    billing             text NOT NULL DEFAULT '' CHECK (billing IN ('', 'once', 'monthly', 'yearly')),
    cost_center         text NOT NULL DEFAULT '' CHECK (length(cost_center) <= 100),
    -- Dates as YYYY-MM-DD ('' = not set).
    purchased_on        text NOT NULL DEFAULT '' CHECK (purchased_on = '' OR purchased_on ~ '^\d{4}-\d{2}-\d{2}$'),
    warranty_until      text NOT NULL DEFAULT '' CHECK (warranty_until = '' OR warranty_until ~ '^\d{4}-\d{2}-\d{2}$'),
    expires_on          text NOT NULL DEFAULT '' CHECK (expires_on = '' OR expires_on ~ '^\d{4}-\d{2}-\d{2}$'),
    auto_renew          boolean NOT NULL DEFAULT false,
    seats               integer CHECK (seats >= 0),
    seats_used          integer CHECK (seats_used >= 0),
    license_key_enc     bytea,
    links               jsonb NOT NULL DEFAULT '[]',
    fields              jsonb NOT NULL DEFAULT '{}',
    notes               text NOT NULL DEFAULT '' CHECK (length(notes) <= 20000),
    -- Where reminders and owner alerts go, on top of the workspace defaults.
    channel_ids         uuid[] NOT NULL DEFAULT '{}',
    -- Periodic review: the owner confirms it's still theirs and still needed.
    review_days         integer NOT NULL DEFAULT 0 CHECK (review_days BETWEEN 0 AND 3650),
    reviewed_at         timestamptz,
    reviewed_by_name    text NOT NULL DEFAULT '',
    -- Last reminder sent per date field, so each is sent once per threshold.
    reminded            jsonb NOT NULL DEFAULT '{}',
    created_by_name     text NOT NULL DEFAULT '',
    updated_by_name     text NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX assets_source_idx ON assets (workspace_id, source_kind, source_ref) WHERE source_kind <> '';
CREATE INDEX assets_workspace_idx ON assets (workspace_id, kind);
CREATE INDEX assets_owner_idx ON assets (owner_user_id);

-- How assets depend on each other: a website runs on a proxy, an app uses a
-- database, a database backs up to a storage. Discovered ones are rebuilt by
-- the sync; manual ones are the team's.
CREATE TABLE asset_relations (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    from_id      uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    to_id        uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('runs_on', 'uses', 'depends_on', 'stored_in', 'backs_up_to', 'points_to', 'connects_to', 'part_of', 'licensed_for', 'assigned_to')),
    note         text NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    origin       text NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual', 'discovered')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (from_id <> to_id),
    UNIQUE (from_id, to_id, kind)
);

CREATE INDEX asset_relations_to_idx ON asset_relations (to_id);
CREATE INDEX asset_relations_ws_idx ON asset_relations (workspace_id);

-- Every change to an asset, for the audit trail.
CREATE TABLE asset_events (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    asset_id   uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    at         timestamptz NOT NULL DEFAULT now(),
    by_name    text NOT NULL DEFAULT '',
    action     text NOT NULL,
    changes    jsonb NOT NULL DEFAULT '[]'
);

CREATE INDEX asset_events_asset_idx ON asset_events (asset_id, at DESC);

-- Owner rules: an asset with no owner of its own takes the first rule that
-- matches it.
CREATE TABLE asset_owner_rules (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id   uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    position       integer NOT NULL DEFAULT 0,
    name           text NOT NULL DEFAULT '' CHECK (length(name) <= 100),
    kinds          text[] NOT NULL DEFAULT '{}',
    tags           text[] NOT NULL DEFAULT '{}',
    environments   text[] NOT NULL DEFAULT '{}',
    name_pattern   text NOT NULL DEFAULT '' CHECK (length(name_pattern) <= 200),
    owner_user_id  uuid REFERENCES users (id) ON DELETE SET NULL,
    owner_group_id uuid REFERENCES user_groups (id) ON DELETE SET NULL,
    deputy_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX asset_owner_rules_ws_idx ON asset_owner_rules (workspace_id, position);

-- What discovery found that isn't in the inventory yet.
CREATE TABLE asset_discoveries (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    key          text NOT NULL,
    kind         text NOT NULL,
    title        text NOT NULL,
    detail       text NOT NULL DEFAULT '',
    source       text NOT NULL DEFAULT '',
    server_id    uuid REFERENCES servers (id) ON DELETE CASCADE,
    data         jsonb NOT NULL DEFAULT '{}',
    state        text NOT NULL DEFAULT 'new' CHECK (state IN ('new', 'accepted', 'ignored')),
    asset_id     uuid REFERENCES assets (id) ON DELETE SET NULL,
    gone         boolean NOT NULL DEFAULT false,
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, key)
);

-- Per workspace settings.
CREATE TABLE asset_settings (
    workspace_id      uuid PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
    auto_discover     boolean NOT NULL DEFAULT true,
    discover_hours    integer NOT NULL DEFAULT 24 CHECK (discover_hours BETWEEN 1 AND 720),
    remind_days       integer[] NOT NULL DEFAULT '{30,7,1}',
    channel_ids       uuid[] NOT NULL DEFAULT '{}',
    notify_owners     boolean NOT NULL DEFAULT true,
    last_discovery_at timestamptz,
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- What Morche already manages, as assets. The sync upserts these into
-- assets; facts are what the inventory shows without opening the source.
CREATE VIEW asset_sources AS
SELECT s.workspace_id, 'server'::text AS kind, s.id::text AS ref, s.name,
    jsonb_build_object(
        'status', s.status, 'host', s.host, 'hostname', s.hostname,
        'os_id', s.os_id, 'os_name', s.os_name, 'os_version', s.os_version,
        'arch', s.arch, 'kernel', s.kernel, 'tags', to_jsonb(s.tags),
        'monitors', (SELECT count(*) FROM monitors m WHERE m.server_id = s.id OR m.config->>'host' = s.host)
    ) AS facts
FROM servers s
UNION ALL
SELECT d.workspace_id, 'database', d.id::text, d.name,
    jsonb_build_object(
        'status', CASE WHEN d.paused THEN 'paused' ELSE d.status END,
        'engine', d.engine, 'version', d.version, 'host', d.host, 'port', d.port,
        'server_id', d.server_id, 'size_bytes', d.size_bytes, 'health', d.health,
        'backups', (SELECT count(*) FROM database_backup_plans p WHERE p.database_id = d.id AND p.enabled)
    )
FROM databases d
UNION ALL
SELECT st.workspace_id, 'storage', st.id::text, st.name,
    jsonb_build_object('status', st.status, 'protocol', st.protocol, 'provider', st.provider,
        'host', st.host, 'bucket', st.bucket)
FROM storages st
UNION ALL
SELECT n.workspace_id, 'dns_server', n.id::text, n.name,
    jsonb_build_object('status', n.status, 'url', n.url, 'version', n.version, 'zones', n.zone_count)
FROM dns_servers n
UNION ALL
SELECT s.workspace_id, 'proxy', p.id::text,
    s.name || CASE WHEN p.container <> '' THEN ' · ' || p.container ELSE '' END || ' (' || p.kind || ')',
    jsonb_build_object('status', p.status, 'proxy_kind', p.kind, 'version', p.version,
        'server_id', p.server_id, 'server_name', s.name, 'container', p.container)
FROM proxies p JOIN servers s ON s.id = p.server_id
UNION ALL
SELECT s.workspace_id, 'website', h.id::text,
    CASE WHEN h.config->>'type' = 'stream' THEN 'Port ' || coalesce(h.config->>'port', '?') || ' on ' || s.name
         ELSE coalesce(h.domains[1], 'Site on ' || s.name) END,
    jsonb_build_object('status', CASE WHEN h.enabled THEN 'on' ELSE 'off' END,
        'domains', to_jsonb(h.domains), 'site_type', h.config->>'type',
        'upstream', h.config->>'upstream', 'proxy_id', p.id, 'server_id', s.id, 'server_name', s.name,
        'monitors', (SELECT count(*) FROM monitors m WHERE EXISTS (
            SELECT 1 FROM unnest(h.domains) dm WHERE dm <> '' AND m.config->>'url' ILIKE '%://' || dm || '%')),
        'cert_expires_at', (SELECT min(m.cert_expires_at) FROM monitors m WHERE EXISTS (
            SELECT 1 FROM unnest(h.domains) dm WHERE dm <> '' AND m.config->>'url' ILIKE '%://' || dm || '%')))
FROM proxy_hosts h JOIN proxies p ON p.id = h.proxy_id JOIN servers s ON s.id = p.server_id
UNION ALL
SELECT c.workspace_id, 'vm_cluster', c.id::text, c.name,
    jsonb_build_object('status', c.status, 'url', c.url, 'version', c.version,
        'nodes', c.node_count, 'guests', c.guest_count, 'running', c.running_count)
FROM pve_clusters c
UNION ALL
SELECT a.workspace_id, 'cloud_account', a.id::text, a.name,
    jsonb_build_object('status', a.status, 'provider', a.provider, 'servers', a.server_count, 'running', a.running_count)
FROM cloud_accounts a
UNION ALL
SELECT ap.workspace_id, 'web_service', ap.id::text, ap.name,
    jsonb_build_object('address', ap.address, 'critical', ap.critical,
        'monitors', (SELECT count(*) FROM monitors m WHERE ap.address <> '' AND m.config->>'url' ILIKE '%' || regexp_replace(ap.address, '^[a-z]+://', '') || '%'))
FROM apps ap
UNION ALL
SELECT s.workspace_id, 'compose_project', ps.server_id::text || '/' || ps.project,
    coalesce(nullif(pm.title, ''), ps.project) || ' on ' || s.name,
    jsonb_build_object('status', CASE WHEN ps.total = 0 THEN 'off' WHEN ps.running = ps.total AND ps.unhealthy = 0 THEN 'on' ELSE 'warning' END,
        'project', ps.project, 'server_id', ps.server_id, 'server_name', s.name,
        'running', ps.running, 'total', ps.total)
FROM (SELECT DISTINCT ON (server_id, project) server_id, project, running, total, unhealthy
      FROM docker_project_stats WHERE at > now() - interval '2 days'
      ORDER BY server_id, project, at DESC) ps
JOIN servers s ON s.id = ps.server_id
LEFT JOIN docker_project_meta pm ON pm.server_id = ps.server_id AND pm.project = ps.project
UNION ALL
SELECT si.workspace_id, 'application', si.id::text, si.name || ' on ' || s.name,
    jsonb_build_object('status', si.status, 'version', si.version, 'latest', si.latest,
        'update_available', si.update_available, 'recipe', si.recipe_id,
        'server_id', si.server_id, 'server_name', s.name)
FROM software_installs si JOIN servers s ON s.id = si.server_id;

-- Relations Morche can see between the sources above.
CREATE VIEW asset_source_links AS
-- A server runs on a Proxmox cluster.
SELECT 'server'::text AS from_kind, l.server_id::text AS from_ref, 'vm_cluster'::text AS to_kind, l.cluster_id::text AS to_ref, 'runs_on'::text AS kind
FROM pve_vm_links l
UNION ALL
SELECT 'database', d.id::text, 'server', d.server_id::text, 'runs_on'
FROM databases d WHERE d.server_id IS NOT NULL
UNION ALL
SELECT 'proxy', p.id::text, 'server', p.server_id::text, 'runs_on'
FROM proxies p
UNION ALL
SELECT 'website', h.id::text, 'proxy', h.proxy_id::text, 'runs_on'
FROM proxy_hosts h
-- A site forwarding to another panel server depends on it.
UNION ALL
SELECT DISTINCT 'website', h.id::text, 'server', s.id::text, 'depends_on'
FROM proxy_hosts h
JOIN proxies p ON p.id = h.proxy_id
JOIN servers ps ON ps.id = p.server_id
JOIN servers s ON s.workspace_id = ps.workspace_id AND s.id <> p.server_id AND s.host <> ''
    AND regexp_replace(coalesce(h.config->>'upstream', ''), '^[a-z]+://([^/:]+).*$', '\1') = s.host
UNION ALL
SELECT 'compose_project', ps.server_id::text || '/' || ps.project, 'server', ps.server_id::text, 'runs_on'
FROM (SELECT DISTINCT server_id, project FROM docker_project_stats WHERE at > now() - interval '2 days') ps
UNION ALL
SELECT 'application', si.id::text, 'server', si.server_id::text, 'runs_on'
FROM software_installs si
UNION ALL
SELECT DISTINCT 'database', p.database_id::text, 'storage', ps.storage_id::text, 'backs_up_to'
FROM database_backup_plans p JOIN database_backup_plan_storages ps ON ps.plan_id = p.id
-- A web service whose address is a panel site depends on that site.
UNION ALL
SELECT DISTINCT 'web_service', ap.id::text, 'website', h.id::text, 'depends_on'
FROM apps ap
JOIN proxy_hosts h ON ap.address <> '' AND EXISTS (
    SELECT 1 FROM unnest(h.domains) dm
    WHERE dm <> '' AND regexp_replace(ap.address, '^[a-z]+://([^/:]+).*$', '\1') = dm);

-- +goose Down
DROP VIEW asset_source_links;
DROP VIEW asset_sources;
DROP TABLE asset_settings;
DROP TABLE asset_discoveries;
DROP TABLE asset_owner_rules;
DROP TABLE asset_events;
DROP TABLE asset_relations;
DROP TABLE assets;
