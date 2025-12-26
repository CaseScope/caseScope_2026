-- Migration: Add file_hash column to case_file table for deduplication
-- Date: 2025-12-26
-- Purpose: Enable per-case file deduplication by SHA256 hash

-- Add file_hash column (SHA256 = 64 hex characters)
ALTER TABLE case_file 
ADD COLUMN IF NOT EXISTS file_hash VARCHAR(64);

-- Create index for fast duplicate lookups
CREATE INDEX IF NOT EXISTS idx_case_file_hash ON case_file(case_id, file_hash);

-- Add comment for documentation
COMMENT ON COLUMN case_file.file_hash IS 'SHA256 hash of file contents for deduplication (per-case)';

