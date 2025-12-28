-- Add full_value column to IOC table for storing complete long values
-- This allows unlimited-length command lines, base64 PowerShell, etc.
-- The indexed 'value' field remains truncated for performance

ALTER TABLE iocs ADD COLUMN IF NOT EXISTS full_value TEXT;

COMMENT ON COLUMN iocs.full_value IS 'Complete untruncated value for long IOCs (command lines, base64, etc.)';

