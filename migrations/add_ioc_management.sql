-- ============================================================================
-- IOC Management Database Schema
-- Created: 2025-12-24
-- Description: Comprehensive IOC tracking system for CaseScope
-- ============================================================================

-- Drop existing tables if they exist (for clean migration)
DROP TABLE IF EXISTS ioc_relationships CASCADE;
DROP TABLE IF EXISTS ioc_tags CASCADE;
DROP TABLE IF EXISTS ioc_enrichment CASCADE;
DROP TABLE IF EXISTS iocs CASCADE;
DROP TYPE IF EXISTS ioc_type_enum CASCADE;
DROP TYPE IF EXISTS ioc_category_enum CASCADE;
DROP TYPE IF EXISTS threat_level_enum CASCADE;
DROP TYPE IF EXISTS ioc_source_enum CASCADE;

-- ============================================================================
-- ENUMS: Define allowed values
-- ============================================================================

CREATE TYPE ioc_category_enum AS ENUM (
    'network',
    'file',
    'host',
    'identity',
    'vulnerability',
    'cloud',
    'mobile'
);

CREATE TYPE ioc_type_enum AS ENUM (
    -- Network Indicators
    'ipv4',
    'ipv6',
    'domain',
    'fqdn',
    'url',
    'uri_path',
    'email_address',
    'email_subject',
    'user_agent',
    'ja3_hash',
    'ja3s_hash',
    'jarm_hash',
    'ssl_cert_hash',
    'ssl_cert_serial',
    
    -- File Indicators
    'md5',
    'sha1',
    'sha256',
    'sha512',
    'ssdeep',
    'imphash',
    'tlsh',
    'filename',
    'filepath',
    'filesize',
    'filetype',
    
    -- Host Indicators
    'registry_key',
    'registry_value',
    'mutex',
    'named_pipe',
    'service_name',
    'scheduled_task',
    'process_name',
    'command_line',
    'parent_child_process',
    'wmi_subscription',
    
    -- Identity / Account
    'username',
    'sid',
    'email_sender',
    'bitcoin_address',
    'ethereum_address',
    'monero_address',
    
    -- Vulnerability / Exploit
    'cve_id',
    'exploit_kit',
    'malware_family',
    'mitre_attack_id',
    'yara_rule',
    'sigma_rule_id',
    
    -- Cloud / SaaS
    'aws_account_id',
    's3_bucket',
    'azure_tenant_id',
    'oauth_app_id',
    'api_key',
    
    -- Mobile
    'app_package_name',
    'apk_hash',
    'ios_bundle_id',
    'imei'
);

CREATE TYPE threat_level_enum AS ENUM (
    'info',
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE ioc_source_enum AS ENUM (
    'manual',
    'ai_extraction',
    'event_extraction',
    'file_analysis',
    'threat_feed',
    'osint',
    'import'
);

-- ============================================================================
-- MAIN IOC TABLE
-- ============================================================================

CREATE TABLE iocs (
    id SERIAL PRIMARY KEY,
    
    -- Core IOC Data
    type ioc_type_enum NOT NULL,
    value TEXT NOT NULL,
    category ioc_category_enum NOT NULL,
    
    -- Classification
    confidence SMALLINT CHECK (confidence >= 0 AND confidence <= 100),
    threat_level threat_level_enum DEFAULT 'info',
    is_whitelisted BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Temporal Data
    first_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    times_seen INTEGER DEFAULT 1 CHECK (times_seen >= 0),
    expires_at TIMESTAMP WITHOUT TIME ZONE,
    
    -- Source & Attribution
    source ioc_source_enum DEFAULT 'manual',
    source_reference TEXT,  -- URL, feed name, case event ID, etc.
    description TEXT,
    analyst_notes TEXT,
    
    -- Relationships
    case_id INTEGER REFERENCES "case"(id) ON DELETE CASCADE,
    parent_ioc_id INTEGER REFERENCES iocs(id) ON DELETE SET NULL,
    
    -- Metadata (flexible JSON for type-specific fields)
    metadata JSONB DEFAULT '{}',
    
    -- Enrichment Data (threat intel, geolocation, etc.)
    enrichment JSONB DEFAULT '{}',
    
    -- Audit
    created_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    updated_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    UNIQUE(type, value, case_id)  -- Prevent duplicate IOCs per case
);

-- ============================================================================
-- IOC TAGS TABLE (Many-to-Many)
-- ============================================================================

CREATE TABLE ioc_tags (
    id SERIAL PRIMARY KEY,
    ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    tag VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ioc_id, tag)
);

-- ============================================================================
-- IOC RELATIONSHIPS TABLE (Link related IOCs)
-- ============================================================================

CREATE TABLE ioc_relationships (
    id SERIAL PRIMARY KEY,
    source_ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    target_ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    relationship_type VARCHAR(50) NOT NULL,  -- 'resolves_to', 'downloads', 'communicates_with', 'drops', 'executes', etc.
    confidence SMALLINT CHECK (confidence >= 0 AND confidence <= 100),
    notes TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_ioc_id, target_ioc_id, relationship_type)
);

-- ============================================================================
-- IOC ENRICHMENT LOG (Track enrichment attempts)
-- ============================================================================

CREATE TABLE ioc_enrichment (
    id SERIAL PRIMARY KEY,
    ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    enrichment_source VARCHAR(100) NOT NULL,  -- 'virustotal', 'abuseipdb', 'shodan', etc.
    enrichment_data JSONB,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    enriched_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- INDEXES: Performance optimization
-- ============================================================================

-- Core lookup indexes
CREATE INDEX idx_iocs_type ON iocs(type);
CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_iocs_type_value ON iocs(type, value);
CREATE INDEX idx_iocs_category ON iocs(category);
CREATE INDEX idx_iocs_threat_level ON iocs(threat_level);

-- Filter indexes
CREATE INDEX idx_iocs_is_active ON iocs(is_active);
CREATE INDEX idx_iocs_is_whitelisted ON iocs(is_whitelisted);
CREATE INDEX idx_iocs_confidence ON iocs(confidence);

-- Temporal indexes
CREATE INDEX idx_iocs_first_seen ON iocs(first_seen);
CREATE INDEX idx_iocs_last_seen ON iocs(last_seen);
CREATE INDEX idx_iocs_expires_at ON iocs(expires_at) WHERE expires_at IS NOT NULL;

-- Relationship indexes
CREATE INDEX idx_iocs_case_id ON iocs(case_id);
CREATE INDEX idx_iocs_parent_ioc_id ON iocs(parent_ioc_id);
CREATE INDEX idx_iocs_source ON iocs(source);

-- Audit indexes
CREATE INDEX idx_iocs_created_by ON iocs(created_by);
CREATE INDEX idx_iocs_created_at ON iocs(created_at);

-- JSONB indexes (GIN for flexible querying)
CREATE INDEX idx_iocs_metadata ON iocs USING GIN (metadata);
CREATE INDEX idx_iocs_enrichment ON iocs USING GIN (enrichment);

-- Tag indexes
CREATE INDEX idx_ioc_tags_ioc_id ON ioc_tags(ioc_id);
CREATE INDEX idx_ioc_tags_tag ON ioc_tags(tag);

-- Relationship indexes
CREATE INDEX idx_ioc_relationships_source ON ioc_relationships(source_ioc_id);
CREATE INDEX idx_ioc_relationships_target ON ioc_relationships(target_ioc_id);
CREATE INDEX idx_ioc_relationships_type ON ioc_relationships(relationship_type);

-- Enrichment indexes
CREATE INDEX idx_ioc_enrichment_ioc_id ON ioc_enrichment(ioc_id);
CREATE INDEX idx_ioc_enrichment_source ON ioc_enrichment(enrichment_source);

-- ============================================================================
-- TRIGGERS: Auto-update timestamps
-- ============================================================================

CREATE OR REPLACE FUNCTION update_iocs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_iocs_updated_at
    BEFORE UPDATE ON iocs
    FOR EACH ROW
    EXECUTE FUNCTION update_iocs_updated_at();

-- ============================================================================
-- FUNCTIONS: Helper functions for IOC management
-- ============================================================================

-- Function to increment times_seen and update last_seen
CREATE OR REPLACE FUNCTION increment_ioc_sighting(
    p_type ioc_type_enum,
    p_value TEXT,
    p_case_id INTEGER
)
RETURNS INTEGER AS $$
DECLARE
    v_ioc_id INTEGER;
BEGIN
    UPDATE iocs
    SET times_seen = times_seen + 1,
        last_seen = CURRENT_TIMESTAMP
    WHERE type = p_type
      AND value = p_value
      AND case_id = p_case_id
    RETURNING id INTO v_ioc_id;
    
    RETURN v_ioc_id;
END;
$$ LANGUAGE plpgsql;

-- Function to get IOC statistics
CREATE OR REPLACE FUNCTION get_ioc_stats()
RETURNS TABLE(
    total_iocs BIGINT,
    active_iocs BIGINT,
    critical_iocs BIGINT,
    by_category JSONB,
    by_threat_level JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        COUNT(*)::BIGINT AS total_iocs,
        COUNT(*) FILTER (WHERE is_active = TRUE)::BIGINT AS active_iocs,
        COUNT(*) FILTER (WHERE threat_level = 'critical')::BIGINT AS critical_iocs,
        jsonb_object_agg(category, cnt) AS by_category,
        jsonb_object_agg(threat_level, tl_cnt) AS by_threat_level
    FROM (
        SELECT
            category,
            COUNT(*) AS cnt
        FROM iocs
        GROUP BY category
    ) cat
    CROSS JOIN (
        SELECT
            threat_level,
            COUNT(*) AS tl_cnt
        FROM iocs
        GROUP BY threat_level
    ) tl;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PERMISSIONS: Grant access to casescope user
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON iocs TO casescope;
GRANT SELECT, INSERT, UPDATE, DELETE ON ioc_tags TO casescope;
GRANT SELECT, INSERT, UPDATE, DELETE ON ioc_relationships TO casescope;
GRANT SELECT, INSERT, UPDATE, DELETE ON ioc_enrichment TO casescope;

GRANT USAGE, SELECT ON SEQUENCE iocs_id_seq TO casescope;
GRANT USAGE, SELECT ON SEQUENCE ioc_tags_id_seq TO casescope;
GRANT USAGE, SELECT ON SEQUENCE ioc_relationships_id_seq TO casescope;
GRANT USAGE, SELECT ON SEQUENCE ioc_enrichment_id_seq TO casescope;

GRANT EXECUTE ON FUNCTION increment_ioc_sighting TO casescope;
GRANT EXECUTE ON FUNCTION get_ioc_stats TO casescope;

-- ============================================================================
-- SAMPLE DATA: Example IOCs (optional, for testing)
-- ============================================================================

-- Uncomment to insert sample data:
/*
INSERT INTO iocs (type, value, category, threat_level, source, description) VALUES
    ('ipv4', '192.168.1.100', 'network', 'high', 'manual', 'Known C2 server'),
    ('domain', 'malicious-site.com', 'network', 'critical', 'threat_feed', 'Active phishing domain'),
    ('md5', 'd41d8cd98f00b204e9800998ecf8427e', 'file', 'medium', 'file_analysis', 'Suspicious executable'),
    ('cve_id', 'CVE-2024-12345', 'vulnerability', 'critical', 'osint', 'Critical RCE vulnerability');
*/

-- ============================================================================
-- COMMENTS: Document the schema
-- ============================================================================

COMMENT ON TABLE iocs IS 'Comprehensive IOC tracking system for threat intelligence';
COMMENT ON COLUMN iocs.metadata IS 'Type-specific fields (e.g., geolocation for IPs, WHOIS for domains)';
COMMENT ON COLUMN iocs.enrichment IS 'External threat intel data (VirusTotal, AbuseIPDB, etc.)';
COMMENT ON COLUMN iocs.expires_at IS 'Optional expiration for time-limited indicators';
COMMENT ON COLUMN iocs.parent_ioc_id IS 'Link to parent IOC (e.g., URL -> Domain -> IP hierarchy)';

COMMENT ON TABLE ioc_relationships IS 'Track relationships between IOCs (e.g., domain resolves to IP)';
COMMENT ON TABLE ioc_tags IS 'Flexible tagging system for IOCs (e.g., "apt29", "ransomware", "false_positive")';
COMMENT ON TABLE ioc_enrichment IS 'Log of enrichment attempts from external sources';

-- ============================================================================
-- END OF MIGRATION
-- ============================================================================

