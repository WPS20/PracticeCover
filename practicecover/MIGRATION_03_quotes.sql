-- ============================================================
-- STEP 3: Quotes Table
-- Run this in your Supabase SQL Editor AFTER Steps 1 and 2
-- ============================================================

CREATE TABLE IF NOT EXISTS quotes (
  id                    TEXT PRIMARY KEY,
  quote_ref             TEXT UNIQUE,
  customer_id           TEXT REFERENCES customers(id) ON DELETE SET NULL,                    -- e.g. QT-0001
  status                TEXT DEFAULT 'draft',           -- draft / quoted / accepted / declined / bound
  created_by            TEXT REFERENCES users(id),
  created_at            TIMESTAMPTZ DEFAULT NOW(),
  updated_at            TIMESTAMPTZ DEFAULT NOW(),

  -- Step 1: Client Details & Correspondence Address
  renewal_date          DATE,
  quote_type            TEXT,                           -- Renewal / New Business / MTA / Cancellation
  previous_insurer      TEXT,
  full_name             TEXT,
  contact_name          TEXT,
  telephone             TEXT,
  mobile                TEXT,
  email                 TEXT,
  addr_name             TEXT,
  addr_line1            TEXT,
  addr_line2            TEXT,
  addr_town             TEXT,
  addr_county           TEXT,
  addr_country          TEXT DEFAULT 'United Kingdom',
  addr_postcode         TEXT,

  -- Step 2: Declarations
  none_of_below         TEXT DEFAULT 'Yes',
  decl1                 TEXT DEFAULT 'No',             -- criminal convictions
  decl2                 TEXT DEFAULT 'No',             -- bankruptcy
  decl3                 TEXT DEFAULT 'No',             -- CCJ / voluntary arrangement
  decl4                 TEXT DEFAULT 'No',             -- insurance refused/cancelled
  decl5                 TEXT DEFAULT 'No',             -- losses in last 5 years
  decl6                 TEXT DEFAULT 'No',             -- circumstances giving rise to claim
  years_since_last_claim TEXT DEFAULT '0',
  claims                JSONB DEFAULT '[]',            -- array of claim objects

  -- Step 3: Cover Choice - Physical Items
  day_one_cover         TEXT DEFAULT '0',              -- 0 / 20 / 30
  excess                TEXT DEFAULT '£200',           -- £200 / £500 / £1,000
  fidelity              TEXT DEFAULT '£0',             -- £0 / £10,000 / ... / £50,000

  -- Step 4: Cover Choice Continued (Employee Personal Accident)
  dir_units             INTEGER DEFAULT 0,
  dir_fulltime          INTEGER DEFAULT 0,
  dir_parttime          INTEGER DEFAULT 0,
  emp_units             INTEGER DEFAULT 0,
  emp_fulltime          INTEGER DEFAULT 0,
  emp_parttime          INTEGER DEFAULT 0,

  -- Step 5: Business Interruption
  bi_cover_type         TEXT,                          -- Loss of Income / Increased Expenses
  bi_annual_sum_insured NUMERIC(14,2) DEFAULT 0,
  bi_cover_period       TEXT DEFAULT '24',             -- months
  bi_book_debt_cover    NUMERIC(14,2) DEFAULT 10000,

  -- Step 6: Public & Products Liability
  indemnity_limit       TEXT DEFAULT '£5,000,000',
  offsite_clinics       INTEGER DEFAULT 0,
  terrorism_cover       TEXT DEFAULT 'No',
  material_damage       TEXT,
  non_selection_rule    TEXT,
  terrorism_postcode    TEXT,
  anticipated_turnover  NUMERIC(14,2) DEFAULT 0,

  -- Step 7: Premises Details
  num_premises          INTEGER DEFAULT 1,
  country               TEXT DEFAULT 'UK',             -- Not on Cover / UK / Channel Islands / Isle of Man
  premises              JSONB DEFAULT '[]',             -- array of per-premises detail objects

  -- Final pricing
  premium               NUMERIC(10,2),
  valid_until           DATE
);

-- Index for fast lookups
CREATE INDEX IF NOT EXISTS idx_quotes_status      ON quotes(status);
CREATE INDEX IF NOT EXISTS idx_quotes_quote_type  ON quotes(quote_type);
CREATE INDEX IF NOT EXISTS idx_quotes_created_at  ON quotes(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_quotes_created_by  ON quotes(created_by);
