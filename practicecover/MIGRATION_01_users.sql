-- ============================================================
-- STEP 1: Users Table
-- Run this in your Supabase SQL Editor
-- ============================================================

-- The main users table (for login accounts)
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user',   -- 'user' or 'admin'
  active        BOOLEAN NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- The sessions table (used automatically by the app to keep you logged in)
CREATE TABLE IF NOT EXISTS user_sessions (
  sid    VARCHAR    NOT NULL COLLATE "default",
  sess   JSON       NOT NULL,
  expire TIMESTAMP(6) NOT NULL,
  CONSTRAINT session_pkey PRIMARY KEY (sid)
);
CREATE INDEX IF NOT EXISTS IDX_session_expire ON user_sessions (expire);

-- ============================================================
-- CREATE YOUR FIRST ADMIN USER
-- Replace the values below with your own name, email and a
-- bcrypt hash of your chosen password.
--
-- To generate a bcrypt hash, visit:
--   https://bcrypt-generator.com
-- Enter your password, set rounds to 12, click Generate.
-- Paste the result (starting with $2b$12$...) in place of
-- the placeholder below.
-- ============================================================

INSERT INTO users (id, name, email, password_hash, role, active)
VALUES (
  gen_random_uuid()::text,
  'Your Name',
  'your@email.com',
  '$2b$12$REPLACE_THIS_WITH_YOUR_BCRYPT_HASH',
  'admin',
  true
)
ON CONFLICT (email) DO NOTHING;
