-- ============================================================
-- STEP 2: Customers (Practices) Table
-- Run this in your Supabase SQL Editor AFTER Step 1
-- ============================================================

CREATE TABLE IF NOT EXISTS customers (
  id                   TEXT PRIMARY KEY,
  -- Core contact fields
  type                 TEXT,                        -- e.g. 'gp_practice', 'dental_practice'
  name                 TEXT NOT NULL,               -- Full Name of the person
  email                TEXT,
  phone                TEXT,
  contact_name         TEXT,                        -- Name of Contact
  contact_mobile       TEXT,                        -- Mobile Number
  -- PracticeCover specific fields
  practice_name        TEXT,                        -- Name of the practice
  status               TEXT DEFAULT 'active',       -- active / inactive / prospect / lapsed
  ern_number           TEXT,                        -- Employer Reference Number
  ern_exempt           TEXT DEFAULT 'no',           -- yes / no
  year_established     INTEGER,                     -- Year the business was established
  num_subsidiaries     INTEGER DEFAULT 0,           -- Number of subsidiaries
  -- Correspondence address
  corr_address_line1   TEXT,
  corr_address_line2   TEXT,
  corr_city            TEXT,
  corr_county          TEXT,
  corr_country         TEXT DEFAULT 'United Kingdom',
  corr_postcode        TEXT,
  -- Business classification
  business_description TEXT,                        -- e.g. 'GP Practice/Surgery'
  entity_type          TEXT,                        -- e.g. 'Limited', 'Sole Trader'
  -- Timestamp
  created_at           TIMESTAMPTZ DEFAULT NOW()
);
