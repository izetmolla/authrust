-- Schema shared by the authrust examples.
--
-- authrust reads and writes two tables whose names are configurable through
-- `Config::user_table_name` and `Config::session_table_name`. Only the columns
-- below are touched; add your own alongside them.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    roles   jsonb NOT NULL DEFAULT '[]'::jsonb,
    content jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS sessions (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid REFERENCES users (id) ON DELETE CASCADE,
    "type"     text NOT NULL DEFAULT 'sign_in',
    ip_address text,
    user_agent text,
    method     text NOT NULL DEFAULT 'credentials',
    account    jsonb,
    expires_at timestamptz,
    is_deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);

-- The demo user both examples resolve every sign-in to.
INSERT INTO users (id, roles)
VALUES ('00000000-0000-0000-0000-000000000001', '["admin:rw"]'::jsonb)
ON CONFLICT (id) DO NOTHING;
