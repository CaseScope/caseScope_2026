-- ============================================================================
-- CaseScope v2.4.0 - Global IOC Hunt Tables
-- ============================================================================
-- Migration: Add tables for global IOC hunting feature
-- Date: 2025-12-21
-- Description: Creates tables for tracking global IOC hunt jobs and matches
--              separate from per-file IOC matching during indexing
-- ============================================================================

-- Create IOC Hunt Job table
CREATE TABLE IF NOT EXISTS ioc_hunt_job (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    task_id VARCHAR(255) NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    progress INT NOT NULL DEFAULT 0,
    
    -- IOC-centric metrics
    total_iocs INT NOT NULL DEFAULT 0,
    processed_iocs INT NOT NULL DEFAULT 0,
    match_count INT NOT NULL DEFAULT 0,
    
    message TEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME NULL,
    created_by INT NULL,
    
    -- Foreign keys
    FOREIGN KEY (case_id) REFERENCES `case`(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES user(id) ON DELETE SET NULL,
    
    -- Indexes for performance
    INDEX idx_case_id (case_id),
    INDEX idx_task_id (task_id),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create IOC Hunt Match table
CREATE TABLE IF NOT EXISTS ioc_hunt_match (
    id INT AUTO_INCREMENT PRIMARY KEY,
    job_id INT NOT NULL,
    case_id INT NOT NULL,
    ioc_id INT NOT NULL,
    
    -- Event location
    event_id VARCHAR(255) NULL,
    event_index VARCHAR(255) NULL,
    
    -- Match details
    matched_value TEXT NULL,
    event_data TEXT NULL,
    
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign keys
    FOREIGN KEY (job_id) REFERENCES ioc_hunt_job(id) ON DELETE CASCADE,
    FOREIGN KEY (case_id) REFERENCES `case`(id) ON DELETE CASCADE,
    FOREIGN KEY (ioc_id) REFERENCES ioc(id) ON DELETE CASCADE,
    
    -- Indexes for performance
    INDEX idx_job_id (job_id),
    INDEX idx_case_id (case_id),
    INDEX idx_ioc_id (ioc_id),
    INDEX idx_event_id (event_id),
    INDEX idx_created_at (created_at),
    INDEX idx_hunt_job_ioc (job_id, ioc_id),
    INDEX idx_hunt_case_event (case_id, event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Migration Notes
-- ============================================================================
-- 1. These tables are separate from the existing ioc_match table
-- 2. ioc_match: Used for per-file IOC matching during indexing (has file_id)
-- 3. ioc_hunt_match: Used for global on-demand hunts (no file_id, has job_id)
-- 4. Both tables track IOC matches but serve different purposes
-- 5. Global hunts do NOT update has_ioc flag in OpenSearch (file processing does)
-- ============================================================================

-- Verify tables were created
SELECT 'IOC Hunt tables created successfully' AS status;
SELECT COUNT(*) AS ioc_hunt_job_count FROM ioc_hunt_job;
SELECT COUNT(*) AS ioc_hunt_match_count FROM ioc_hunt_match;
