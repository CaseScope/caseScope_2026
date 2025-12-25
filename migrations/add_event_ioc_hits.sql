-- Event IOC Hits Table
-- Tracks which events contain which IOCs for fast lookup and reporting

CREATE TABLE IF NOT EXISTS event_ioc_hits (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
    
    -- Event identification
    opensearch_doc_id VARCHAR(255) NOT NULL,
    event_record_id BIGINT,
    event_id VARCHAR(255),
    event_timestamp TIMESTAMP,
    computer VARCHAR(255),
    
    -- IOC information
    ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    ioc_value VARCHAR(1000) NOT NULL,
    ioc_type VARCHAR(50),
    ioc_category VARCHAR(50),
    threat_level VARCHAR(20),
    
    -- Match details
    matched_in_field VARCHAR(255),
    match_context TEXT,
    confidence VARCHAR(20) DEFAULT 'high',
    
    -- Metadata
    detected_at TIMESTAMP DEFAULT NOW(),
    detected_by INTEGER REFERENCES "user"(id),
    
    -- Prevent duplicate entries
    CONSTRAINT unique_event_ioc UNIQUE (opensearch_doc_id, ioc_id)
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_event_ioc_case ON event_ioc_hits(case_id);
CREATE INDEX IF NOT EXISTS idx_event_ioc_ioc ON event_ioc_hits(ioc_id);
CREATE INDEX IF NOT EXISTS idx_event_ioc_event ON event_ioc_hits(opensearch_doc_id);
CREATE INDEX IF NOT EXISTS idx_event_ioc_timestamp ON event_ioc_hits(detected_at);
CREATE INDEX IF NOT EXISTS idx_event_ioc_threat ON event_ioc_hits(threat_level);
CREATE INDEX IF NOT EXISTS idx_event_ioc_type ON event_ioc_hits(ioc_type);

