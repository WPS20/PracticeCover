-- Add trade_id (subcontractor link) to tasks
ALTER TABLE tasks
  ADD COLUMN IF NOT EXISTS trade_id TEXT REFERENCES trades(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_tasks_trade_id ON tasks(trade_id);

-- Add compliance fields to attachments
ALTER TABLE attachments
  ADD COLUMN IF NOT EXISTS is_compliance  BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS expiry_date    DATE;
