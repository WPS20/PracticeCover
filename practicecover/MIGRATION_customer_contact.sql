-- Add contact_name and contact_mobile columns to customers table
ALTER TABLE customers
  ADD COLUMN IF NOT EXISTS contact_name   TEXT,
  ADD COLUMN IF NOT EXISTS contact_mobile TEXT;
