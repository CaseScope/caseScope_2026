-- ============================================================================
-- CaseScope v2.4.0 - Global IOC Hunt Tables (PostgreSQL)
-- ============================================================================
-- Migration: Add tables for global IOC hunting feature
-- Date: 2025-12-21
-- Description: Creates tables for tracking global IOC hunt jobs and matches
--              separate from per-file IOC matching during indexing
-- ============================================================================

-- Create IOC Hunt Job table
CREATE TABLE IF NOT EXISTS ioc_hunt_job (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL,
    task_id VARCHAR(255) NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    progress INTEGER NOT NULL DEFAULT 0,
    
    -- IOC-centric metrics
    total_iocs INTEGER NOT NULL DEFAULT 0,
    processed_iocs INTEGER NOT NULL DEFAULT 0,
    match_count INTEGER NOT NULL DEFAULT 0,
    
    message TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    created_by INTEGER NULL,
    
    -- Foreign keys
    CONSTRAINT fk_hunt_job_case FOREIGN KEY (case_id) REFERENCES "case"(id) ON DELETE CASCADE,
    CONSTRAINT fk_hunt_job_user FOREIGN KEY (created_by) REFERENCES "user"(id) ON DELETE SET NULL
);

-- Create indexes for ioc_hunt_job
CREATE INDEX IF NOT EXISTS idx_hunt_job_case_id ON ioc_hunt_job(case_id);
CREATE INDEX IF NOT EXISTS idx_hunt_job_task_id ON ioc_hunt_job(task_id);
CREATE INDEX IF NOT EXISTS idx_hunt_job_status ON ioc_hunt_job(status);
CREATE INDEX IF NOT EXISTS idx_hunt_job_created_at ON ioc_hunt_job(created_at);

-- Create IOC Hunt Match table
CREATE TABLE IF NOT EXISTS ioc_hunt_match (
    id SERIAL PRIMARY KEY,
    job_id INTEGER NOT NULL,
    case_id INTEGER NOT NULL,
    ioc_id INTEGER NOT NULL,
    
    -- Event location
    event_id VARCHAR(255) NULL,
    event_index VARCHAR(255) NULL,
    
    -- Match details
    matched_value TEXT NULL,
    event_data TEXT NULL,
    
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign keys
    CONSTRAINT fk_hunt_match_job FOREIGN KEY (job_id) REFERENCES ioc_hunt_job(id) ON DELETE CASCADE,
    CONSTRAINT fk_hunt_match_case FOREIGN KEY (case_id) REFERENCES "case"(id) ON DELETE CASCADE,
    CONSTRAINT fk_hunt_match_ioc FOREIGN KEY (ioc_id) REFERENCES ioc(id) ON DELETE CASCADE
);

-- Create indexes for ioc_hunt_match
CREATE INDEX IF NOT EXISTS idx_hunt_match_job_id ON ioc_hunt_match(job_id);
CREATE INDEX IF NOT EXISTS idx_hunt_match_case_id ON ioc_hunt_match(case_id);
CREATE INDEX IF NOT EXISTS idx_hunt_match_ioc_id ON ioc_hunt_match(ioc_id);
CREATE INDEX IF NOT EXISTS idx_hunt_match_event_id ON ioc_hunt_match(event_id);
CREATE INDEX IF NOT EXISTS idx_hunt_match_created_at ON ioc_hunt_match(created_at);
CREATE INDEX IF NOT EXISTS idx_hunt_match_job_ioc ON ioc_hunt_match(job_id, ioc_id);
CREATE INDEX IF NOT EXISTS idx_hunt_match_case_event ON ioc_hunt_match(case_id, event_id);

-- ============================================================================
-- Migration Notes
-- ============================================================================
-- 1. These tables are separate from the existing ioc_match table
-- 2. ioc_match: Used for per-file IOC matching during indexing (has file_id)
-- 3. ioc_hunt_match: Used for global on-demand hunts (no file_id, has job_id)
-- 4. Both tables track IOC matches but serve different purposes
-- 5. Global hunts do NOT update has_ioc flag in OpenSearch (file processing does)
-- ============================================================================

-- Grant permissions to casescope user
GRANT ALL PRIVILEGES ON TABLE ioc_hunt_job TO casescope;
GRANT ALL PRIVILEGES ON TABLE ioc_hunt_match TO casescope;
GRANT USAGE, SELECT ON SEQUENCE ioc_hunt_job_id_seq TO casescope;
GRANT USAGE, SELECT ON SEQUENCE ioc_hunt_match_id_seq TO casescope;

-- Verify tables were created
SELECT 'IOC Hunt tables created successfully' AS status;
SELECT COUNT(*) AS ioc_hunt_job_count FROM ioc_hunt_job;
SELECT COUNT(*) AS ioc_hunt_match_count FROM ioc_hunt_match;
