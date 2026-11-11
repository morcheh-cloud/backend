-- +goose Up

-- Who may reach the panel, and where sign-in alerts go.
ALTER TABLE app_settings
    -- Off: any address. On: only the addresses and ranges in ip_allowlist.
    ADD COLUMN ip_allowlist_enabled boolean NOT NULL DEFAULT false,
    -- [{"address": "203.0.113.0/24", "note": "Office"}]
    ADD COLUMN ip_allowlist jsonb NOT NULL DEFAULT '[]',
    -- Notification channels (any workspace) that hear about sign-ins.
    ADD COLUMN sign_in_channels uuid[] NOT NULL DEFAULT '{}',
    ADD COLUMN alert_new_address boolean NOT NULL DEFAULT true,
    ADD COLUMN alert_failed_sign_ins boolean NOT NULL DEFAULT true;

-- Every sign-in, failed attempt, sign-out and ended session. Rows outlive the
-- user and the session they name, so neither is a foreign key that cascades.
CREATE TABLE sign_ins (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    at          timestamptz NOT NULL DEFAULT now(),
    user_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    -- As typed for a failed attempt; the account's name otherwise.
    username    text NOT NULL DEFAULT '',
    ip          text NOT NULL DEFAULT '',
    -- The address's network (/24 or /64): what "a new address" compares.
    network     text NOT NULL DEFAULT '',
    user_agent  text NOT NULL DEFAULT '',
    kind        text NOT NULL CHECK (kind IN ('signed_in', 'failed', 'signed_out', 'ended')),
    -- failed: wrong_password, unknown_user, blocked_account, address_not_allowed
    -- signed_out: '' or everywhere; ended: by_self, by_admin
    reason      text NOT NULL DEFAULT '',
    new_address boolean NOT NULL DEFAULT false,
    session_id  uuid,
    -- Who ended the session, for kind ended.
    by_user_id  uuid REFERENCES users (id) ON DELETE SET NULL,
    by_name     text NOT NULL DEFAULT '',
    -- The owner's answer to "was this you?": '', me, not_me.
    answer      text NOT NULL DEFAULT '' CHECK (answer IN ('', 'me', 'not_me')),
    answered_at timestamptz
);

CREATE INDEX sign_ins_at_idx ON sign_ins (at DESC);
CREATE INDEX sign_ins_user_idx ON sign_ins (user_id, at DESC);
CREATE INDEX sign_ins_network_idx ON sign_ins (user_id, network) WHERE kind = 'signed_in';
CREATE INDEX sign_ins_pending_idx ON sign_ins (user_id) WHERE new_address AND answer = '';

-- +goose Down

DROP TABLE sign_ins;
ALTER TABLE app_settings
    DROP COLUMN ip_allowlist_enabled,
    DROP COLUMN ip_allowlist,
    DROP COLUMN sign_in_channels,
    DROP COLUMN alert_new_address,
    DROP COLUMN alert_failed_sign_ins;
