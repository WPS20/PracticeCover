-- Run this in your Supabase SQL editor to add the new job fields

ALTER TABLE jobs
  ADD COLUMN IF NOT EXISTS deadline_for_completion DATE,
  ADD COLUMN IF NOT EXISTS date_work_completed DATE,
  ADD COLUMN IF NOT EXISTS invoice_number TEXT,
  ADD COLUMN IF NOT EXISTS price_quoted_excl_vat NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS price_quoted_incl_vat NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS compliance_standard TEXT,
  ADD COLUMN IF NOT EXISTS po_sent_subcontractor DATE,
  ADD COLUMN IF NOT EXISTS chased_subcontractor DATE,
  ADD COLUMN IF NOT EXISTS proposed_date_tenant DATE,
  ADD COLUMN IF NOT EXISTS booked_adc DATE,
  ADD COLUMN IF NOT EXISTS booked_subcontractor DATE,
  ADD COLUMN IF NOT EXISTS tenant_not_responding DATE,
  ADD COLUMN IF NOT EXISTS on_hold DATE,
  ADD COLUMN IF NOT EXISTS rejected_cancelled DATE,
  ADD COLUMN IF NOT EXISTS po_chased_date DATE;
