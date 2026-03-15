-- Invoices table
CREATE TABLE IF NOT EXISTS invoices (
  id              TEXT PRIMARY KEY,
  invoice_number  TEXT NOT NULL,
  job_id          TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  customer_id     TEXT REFERENCES customers(id) ON DELETE SET NULL,
  status          TEXT NOT NULL DEFAULT 'draft'
                  CHECK (status IN ('draft','sent','paid','overdue','cancelled')),
  invoice_date    DATE NOT NULL DEFAULT CURRENT_DATE,
  payment_due     DATE NOT NULL DEFAULT CURRENT_DATE,
  date_paid       DATE,
  notes           TEXT,
  created_by      TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Invoice line items
CREATE TABLE IF NOT EXISTS invoice_items (
  id          TEXT PRIMARY KEY,
  invoice_id  TEXT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  description TEXT NOT NULL,
  quantity    NUMERIC(10,2) NOT NULL DEFAULT 1,
  unit_cost   NUMERIC(12,2) NOT NULL DEFAULT 0,
  vat_rate    NUMERIC(5,2)  NOT NULL DEFAULT 20,
  sort_order  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_invoices_job_id      ON invoices(job_id);
CREATE INDEX IF NOT EXISTS idx_invoices_customer_id  ON invoices(customer_id);
CREATE INDEX IF NOT EXISTS idx_invoice_items_inv     ON invoice_items(invoice_id);
