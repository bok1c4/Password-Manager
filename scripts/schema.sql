-- Base schema for a FRESH Password Manager install.
-- The app's startup migration only ADDS the enc_version column; it does not
-- create these base tables, so run this once against a new database:
--   psql "host=localhost dbname=pwmgr user=pwmgr" -f scripts/schema.sql
-- (In the Docker setup this is auto-applied via docker-entrypoint-initdb.d.)
-- Migration v2 (devices/password_keys founding registration + backfill) exists
-- in the app but only runs via `pwmgr migrate` or PWMGR_MIGRATE_V2=1 — never
-- on normal startup.

CREATE TABLE IF NOT EXISTS passwords (
    id          bigserial PRIMARY KEY,
    password    text        NOT NULL,   -- v1: base64(IV||AES-256-CBC); v2: "v2:"||base64(nonce||GCM||tag)
    aes_key     bytea       NOT NULL,   -- the 32-byte AES key, GPG-armored to the recipient
    note        text        NOT NULL,   -- human label
    created_at  timestamptz NOT NULL DEFAULT now(),
    enc_version smallint    NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_public_keys (
    public_key  text,
    fingerprint text,
    username    text
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    int PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

-- Registered devices ("device usernames" + their public keys). Populated by
-- `pwmgr migrate` (founding device) and `pwmgr device add`.
CREATE TABLE IF NOT EXISTS devices (
    id           bigserial PRIMARY KEY,
    name         text   UNIQUE NOT NULL,          -- e.g. "arch-laptop"
    fingerprint  char(40) UNIQUE NOT NULL,        -- full GPG fingerprint
    public_key   text   NOT NULL,                 -- armored public key
    status       text   NOT NULL DEFAULT 'active',-- 'active' | 'revoked'
    enrolled_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);

-- Access matrix: one GPG-wrapped AES key per (entry, device).
CREATE TABLE IF NOT EXISTS password_keys (
    password_id  bigint NOT NULL REFERENCES passwords(id) ON DELETE CASCADE,
    device_id    bigint NOT NULL REFERENCES devices(id),
    wrapped_key  bytea  NOT NULL,                 -- GPG(K -> that device)
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (password_id, device_id)
);
