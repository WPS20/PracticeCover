-- Purchase Orders
CREATE TABLE IF NOT EXISTS purchase_orders (
  id            TEXT PRIMARY KEY,
  po_number     TEXT NOT NULL,
  job_id        TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  trade_id      TEXT NOT NULL REFERENCES trades(id) ON DELETE RESTRICT,
  status        TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','sent','acknowledged','cancelled')),
  issue_date    DATE NOT NULL DEFAULT CURRENT_DATE,
  instructions  TEXT,
  notes         TEXT,
  created_by    TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- PO line items
CREATE TABLE IF NOT EXISTS po_items (
  id          TEXT PRIMARY KEY,
  po_id       TEXT NOT NULL REFERENCES purchase_orders(id) ON DELETE CASCADE,
  description TEXT NOT NULL,
  quantity    NUMERIC(10,2) NOT NULL DEFAULT 1,
  unit_cost   NUMERIC(12,2) NOT NULL DEFAULT 0,
  vat_rate    NUMERIC(5,2) NOT NULL DEFAULT 20,  -- 0, 5, or 20
  sort_order  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_po_job_id   ON purchase_orders(job_id);
CREATE INDEX IF NOT EXISTS idx_po_trade_id ON purchase_orders(trade_id);
CREATE INDEX IF NOT EXISTS idx_po_items_po ON po_items(po_id);
