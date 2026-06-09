-- Base schema for a FRESH Password Manager install.
-- The app's startup migration only ADDS the enc_version column; it does not
-- create these base tables, so run this once against a new database:
--   psql "host=localhost dbname=pwmgr user=pwmgr" -f scripts/schema.sql
-- (In the Docker setup this is auto-applied via docker-entrypoint-initdb.d.)

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
