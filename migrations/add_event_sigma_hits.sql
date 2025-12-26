-- Migration: Add event_sigma_hits table for Sigma rule detection tracking
-- Created: 2025-12-25
-- Description: Tracks which events match which Sigma rules during hunts

-- Create event_sigma_hits table
CREATE TABLE IF NOT EXISTS event_sigma_hits (
    id SERIAL PRIMARY KEY,
    
    -- Case association
    case_id INTEGER NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
    
    -- Event identification (links to OpenSearch document)
    opensearch_doc_id VARCHAR(255) NOT NULL,
    event_record_id BIGINT,
    event_id VARCHAR(255),
    event_timestamp TIMESTAMP,
    computer VARCHAR(255),
    
    -- File that was scanned
    file_id INTEGER REFERENCES case_file(id) ON DELETE SET NULL,
    
    -- Sigma rule information
    sigma_rule_id VARCHAR(500) NOT NULL,  -- e.g., "proc_creation_win_susp_powershell"
    rule_title TEXT,
    rule_level VARCHAR(50),  -- critical, high, medium, low, informational
    mitre_tags TEXT,  -- comma-separated MITRE ATT&CK tags
    
    -- Match details
    matched_field VARCHAR(255),  -- which field contained the match
    confidence VARCHAR(20) DEFAULT 'high',  -- high, medium, low
    
    -- Detection metadata
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    detected_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    
    -- Indexes for efficient queries
    CONSTRAINT unique_event_sigma UNIQUE (opensearch_doc_id, sigma_rule_id)
);

-- Index for case-based queries
CREATE INDEX IF NOT EXISTS idx_event_sigma_hits_case ON event_sigma_hits(case_id);

-- Index for event lookups (most common query)
CREATE INDEX IF NOT EXISTS idx_event_sigma_hits_event ON event_sigma_hits(opensearch_doc_id);

-- Index for rule queries
CREATE INDEX IF NOT EXISTS idx_event_sigma_hits_rule ON event_sigma_hits(sigma_rule_id);

-- Index for severity filtering
CREATE INDEX IF NOT EXISTS idx_event_sigma_hits_level ON event_sigma_hits(rule_level);

-- Index for file-based queries
CREATE INDEX IF NOT EXISTS idx_event_sigma_hits_file ON event_sigma_hits(file_id);

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_event_sigma_hits_detected ON event_sigma_hits(detected_at);

-- Index for MITRE tag searches
CREATE INDEX IF NOT EXISTS idx_event_sigma_hits_mitre ON event_sigma_hits(mitre_tags);

-- Composite index for search results (most common join)
CREATE INDEX IF NOT EXISTS idx_event_sigma_hits_case_event ON event_sigma_hits(case_id, opensearch_doc_id);

COMMENT ON TABLE event_sigma_hits IS 'Tracks Sigma rule matches for events during hunting operations';
COMMENT ON COLUMN event_sigma_hits.opensearch_doc_id IS 'OpenSearch document ID (_id field)';
COMMENT ON COLUMN event_sigma_hits.sigma_rule_id IS 'Sigma rule identifier from YAML filename';
COMMENT ON COLUMN event_sigma_hits.rule_level IS 'Severity: critical, high, medium, low, informational';
COMMENT ON COLUMN event_sigma_hits.mitre_tags IS 'Comma-separated MITRE ATT&CK technique IDs';

