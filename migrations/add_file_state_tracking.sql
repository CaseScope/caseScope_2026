-- Migration: Add File State Tracking System (v2.2.0)
-- 
-- Adds comprehensive boolean flags and state tracking for file processing
-- Replaces fragile status string parsing with explicit phase completion flags
-- 
-- Author: System
-- Date: 2025-12-18

-- Add new boolean flags for phase tracking
ALTER TABLE case_file ADD COLUMN is_new BOOLEAN DEFAULT TRUE;
ALTER TABLE case_file ADD COLUMN sigma_hunted BOOLEAN DEFAULT FALSE;
ALTER TABLE case_file ADD COLUMN ioc_hunted BOOLEAN DEFAULT FALSE;
ALTER TABLE case_file ADD COLUMN known_good BOOLEAN DEFAULT FALSE;
ALTER TABLE case_file ADD COLUMN known_noise BOOLEAN DEFAULT FALSE;
ALTER TABLE case_file ADD COLUMN failed BOOLEAN DEFAULT FALSE;

-- Add state tracking fields
ALTER TABLE case_file ADD COLUMN file_state VARCHAR(50) DEFAULT 'New';
ALTER TABLE case_file ADD COLUMN previous_state VARCHAR(50) DEFAULT NULL;

-- Create indexes for common queries
CREATE INDEX idx_case_file_is_new ON case_file(is_new);
CREATE INDEX idx_case_file_sigma_hunted ON case_file(sigma_hunted);
CREATE INDEX idx_case_file_ioc_hunted ON case_file(ioc_hunted);
CREATE INDEX idx_case_file_known_good ON case_file(known_good);
CREATE INDEX idx_case_file_known_noise ON case_file(known_noise);
CREATE INDEX idx_case_file_failed ON case_file(failed);
CREATE INDEX idx_case_file_file_state ON case_file(file_state);

-- Migrate existing data from indexing_status to new flags
-- NOTE: This is a best-effort migration based on status strings

-- Mark files as not new if they've been indexed
UPDATE case_file SET is_new = FALSE WHERE is_indexed = TRUE;

-- Mark completed files
UPDATE case_file 
SET is_new = FALSE,
    sigma_hunted = TRUE,
    ioc_hunted = TRUE,
    known_good = TRUE,
    known_noise = TRUE,
    file_state = 'Completed'
WHERE indexing_status = 'Completed' 
  AND is_hidden = FALSE 
  AND is_deleted = FALSE;

-- Mark failed files
UPDATE case_file 
SET failed = TRUE,
    file_state = 'Failed'
WHERE indexing_status LIKE 'Failed%';

-- Mark files in various processing states
UPDATE case_file SET file_state = 'Indexing' WHERE indexing_status = 'Indexing';
UPDATE case_file SET file_state = 'SIGMA Testing' WHERE indexing_status = 'SIGMA Testing';
UPDATE case_file SET file_state = 'IOC Hunting' WHERE indexing_status = 'IOC Hunting';
UPDATE case_file SET file_state = 'Queued' WHERE indexing_status = 'Queued';

-- Mark indexed files that have passed indexing
UPDATE case_file 
SET is_new = FALSE,
    file_state = 'Indexed'
WHERE indexing_status IN ('Indexed', 'IOC Complete', 'SIGMA Checked')
  AND is_indexed = TRUE
  AND failed = FALSE;

-- Mark hidden files (0 events)
UPDATE case_file 
SET file_state = 'Hidden'
WHERE is_hidden = TRUE 
  AND event_count = 0
  AND is_deleted = FALSE;

-- Mark files that completed IOC hunting
UPDATE case_file 
SET ioc_hunted = TRUE
WHERE indexing_status IN ('IOC Complete', 'Completed', 'SIGMA Checked');

-- Mark files that completed SIGMA (EVTX only)
UPDATE case_file 
SET sigma_hunted = TRUE
WHERE (indexing_status IN ('SIGMA Checked', 'IOC Complete', 'Completed') 
       OR indexing_status = 'Completed')
  AND LOWER(original_filename) LIKE '%.evtx';

-- Add comment for documentation
COMMENT ON COLUMN case_file.is_new IS 'TRUE if file is newly uploaded and not yet indexed';
COMMENT ON COLUMN case_file.sigma_hunted IS 'TRUE if SIGMA detection has completed (EVTX files only)';
COMMENT ON COLUMN case_file.ioc_hunted IS 'TRUE if IOC hunting has completed';
COMMENT ON COLUMN case_file.known_good IS 'TRUE if known-good filtering has completed';
COMMENT ON COLUMN case_file.known_noise IS 'TRUE if known-noise filtering has completed';
COMMENT ON COLUMN case_file.failed IS 'TRUE if file failed at any processing step';
COMMENT ON COLUMN case_file.file_state IS 'Current processing state for UI display';
COMMENT ON COLUMN case_file.previous_state IS 'State before re-operation (for restoration after partial operations)';

