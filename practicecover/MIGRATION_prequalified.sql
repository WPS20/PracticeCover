-- Add 'prequalified' as a valid status option for subcontractors.
-- The trades table status column has no CHECK constraint so no ALTER needed.
-- This migration just documents the new status value for reference.

-- Optional: if you previously added a CHECK constraint manually, run:
-- ALTER TABLE trades DROP CONSTRAINT IF EXISTS trades_status_check;
-- ALTER TABLE trades ADD CONSTRAINT trades_status_check
--   CHECK (status IN ('active', 'inactive', 'prequalified'));

-- No action required if the column is plain TEXT (the default).
SELECT 'Prequalified status requires no schema change - trades.status is TEXT' AS info;
