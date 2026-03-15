-- Run this in your Supabase SQL editor to add the tasks table

CREATE TABLE IF NOT EXISTS tasks (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  description   TEXT NOT NULL,
  target_date   DATE NOT NULL,
  assigned_to   UUID REFERENCES users(id) ON DELETE SET NULL,
  assigned_by   UUID REFERENCES users(id) ON DELETE SET NULL,
  customer_id   UUID REFERENCES customers(id) ON DELETE SET NULL,
  job_id        UUID REFERENCES jobs(id) ON DELETE SET NULL,
  status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','complete')),
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tasks_assigned_to ON tasks(assigned_to);
CREATE INDEX IF NOT EXISTS idx_tasks_target_date ON tasks(target_date);
