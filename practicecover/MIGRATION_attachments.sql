-- ── Step 1: Create the attachments table ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS attachments (
  id           TEXT PRIMARY KEY,
  entity_type  TEXT NOT NULL,          -- 'job', 'customer', or 'trade'
  entity_id    TEXT NOT NULL,
  file_name    TEXT NOT NULL,
  file_size    BIGINT,
  mime_type    TEXT,
  storage_path TEXT NOT NULL,          -- path inside Supabase Storage bucket
  public_url   TEXT NOT NULL,          -- full public URL for download
  uploaded_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attachments_entity ON attachments(entity_type, entity_id);

-- ── Step 2: Create the Supabase Storage bucket ────────────────────────────────
-- Run this in the Supabase Dashboard → Storage → New Bucket:
--   Name: attachments
--   Public: YES (so files can be downloaded via public URL)
--
-- Or run via SQL (Supabase Storage API):
-- INSERT INTO storage.buckets (id, name, public) VALUES ('attachments', 'attachments', true)
-- ON CONFLICT (id) DO NOTHING;

-- ── Step 3: Add environment variables to Render ───────────────────────────────
-- In your Render service → Environment, add:
--   SUPABASE_URL            = https://xxxx.supabase.co   (your project URL)
--   SUPABASE_SERVICE_KEY    = your service_role secret key (NOT anon key)
--   SUPABASE_STORAGE_BUCKET = attachments
