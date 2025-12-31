-- PHASE 1: Database Migrations for File Upload Redesign
-- NEW_FILE_UPLOAD.ND Implementation

-- =============================================================================
-- 1. ADD parser_type COLUMN TO case_file TABLE
-- =============================================================================
-- Parser type field (evtx, edr, firewall, iis, sysmon, json, xml, csv, etc.)
-- Auto-determined by parser used, WITHOUT '_parser' suffix

ALTER TABLE case_file 
ADD COLUMN IF NOT EXISTS parser_type VARCHAR(50);

-- Add index for filtering
CREATE INDEX IF NOT EXISTS idx_case_file_parser_type ON case_file(parser_type);

COMMENT ON COLUMN case_file.parser_type IS 'Parser used to process file (evtx, edr, firewall, iis, etc.) - auto-determined, without _parser suffix';

-- =============================================================================
-- 2. DROP parent_file_id COLUMN AND RELATED CONSTRAINTS
-- =============================================================================
-- Drop foreign key constraint
ALTER TABLE case_file DROP CONSTRAINT IF EXISTS fk_parent_file;

-- Drop index
DROP INDEX IF EXISTS idx_case_file_parent;

-- Drop the column
ALTER TABLE case_file DROP COLUMN IF EXISTS parent_file_id;

-- Drop event_sigma_hits foreign key if it references parent_file_id  
-- (Check if this constraint exists and references case_file properly)
-- The event_sigma_hits table has file_id which should reference case_file(id)
-- No changes needed there since we're only removing parent_file_id

-- =============================================================================
-- 3. UPDATE FILE STATUSES (New status definitions)
-- =============================================================================
-- FILE STATUSES (status column):
-- - New: File before ANY index processing is done
-- - ParseFail: Unable to parse and index file (still moved to storage, not hidden)
-- - ZeroEvents: File parsed but contains no events
-- - Error: Some other error happened with file
-- - Partial: Not all events indexed successfully
-- - Indexed: All events indexed successfully

-- Note: Existing statuses will be migrated as part of code updates
-- No schema changes needed, just documentation

-- =============================================================================
-- 4. CREATE ingestion_progress TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS ingestion_progress (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    current_step VARCHAR(50),
    total_files INTEGER DEFAULT 0,
    processed_files INTEGER DEFAULT 0,
    failed_files INTEGER DEFAULT 0,
    last_file_processed VARCHAR(500),
    error_message TEXT,
    can_resume BOOLEAN DEFAULT TRUE,
    completed_at TIMESTAMP,
    
    CONSTRAINT chk_status CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'aborted')),
    CONSTRAINT chk_step CHECK (current_step IN ('staging', 'hashing', 'indexing', 'moving', 'cleanup', NULL))
);

-- Add indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_ingestion_progress_case_id ON ingestion_progress(case_id);
CREATE INDEX IF NOT EXISTS idx_ingestion_progress_status ON ingestion_progress(status);
CREATE INDEX IF NOT EXISTS idx_ingestion_progress_started_at ON ingestion_progress(started_at DESC);

-- Grant permissions
GRANT ALL ON ingestion_progress TO casescope;
GRANT USAGE, SELECT ON SEQUENCE ingestion_progress_id_seq TO casescope;

COMMENT ON TABLE ingestion_progress IS 'Tracks file ingestion progress for resumable uploads';
COMMENT ON COLUMN ingestion_progress.status IS 'pending, in_progress, completed, failed, aborted';
COMMENT ON COLUMN ingestion_progress.current_step IS 'staging, hashing, indexing, moving, cleanup';
COMMENT ON COLUMN ingestion_progress.can_resume IS 'Whether ingestion can be resumed after interruption';

-- =============================================================================
-- MIGRATION COMPLETE
-- =============================================================================

-- Log the migration
INSERT INTO audit_log (timestamp, user_id, username, action, resource_type, details, status)
VALUES (
    NOW(),
    NULL,
    'system',
    'phase1_database_migration',
    'system',
    '{"phase": "PHASE 1", "changes": ["added_parser_type_column", "dropped_parent_file_id", "created_ingestion_progress_table"], "migration_file": "phase1_file_upload_redesign.sql"}',
    'success'
);

-- Verify migration
DO $$
DECLARE
    parser_type_exists BOOLEAN;
    parent_file_id_exists BOOLEAN;
    ingestion_progress_exists BOOLEAN;
BEGIN
    -- Check parser_type column
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name='case_file' AND column_name='parser_type'
    ) INTO parser_type_exists;
    
    -- Check parent_file_id column (should NOT exist)
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name='case_file' AND column_name='parent_file_id'
    ) INTO parent_file_id_exists;
    
    -- Check ingestion_progress table
    SELECT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name='ingestion_progress'
    ) INTO ingestion_progress_exists;
    
    RAISE NOTICE '=== Migration Verification ===';
    RAISE NOTICE 'parser_type column exists: %', parser_type_exists;
    RAISE NOTICE 'parent_file_id column exists (should be false): %', parent_file_id_exists;
    RAISE NOTICE 'ingestion_progress table exists: %', ingestion_progress_exists;
    
    IF parser_type_exists AND NOT parent_file_id_exists AND ingestion_progress_exists THEN
        RAISE NOTICE '✓ PHASE 1 MIGRATION SUCCESSFUL';
    ELSE
        RAISE WARNING '✗ PHASE 1 MIGRATION INCOMPLETE - Check errors above';
    END IF;
END $$;

