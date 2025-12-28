-- Noise Filters Migration
-- Adds tables for filtering known good software/tools to reduce noise in event searches
-- Created: 2025-12-28

-- Create noise_filter_categories table
CREATE TABLE IF NOT EXISTS noise_filter_categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_noise_filter_categories_enabled ON noise_filter_categories(is_enabled);

-- Create noise_filter_rules table
CREATE TABLE IF NOT EXISTS noise_filter_rules (
    id SERIAL PRIMARY KEY,
    category_id INTEGER REFERENCES noise_filter_categories(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    filter_type VARCHAR(50) NOT NULL, -- 'process_name', 'file_path', 'command_line', 'hash', 'guid', 'network_connection'
    pattern VARCHAR(1000) NOT NULL, -- The pattern to match (can be exact, wildcard, or regex)
    match_mode VARCHAR(20) DEFAULT 'contains', -- 'exact', 'contains', 'starts_with', 'ends_with', 'regex', 'wildcard'
    is_case_sensitive BOOLEAN DEFAULT FALSE,
    is_enabled BOOLEAN DEFAULT TRUE,
    is_system_default BOOLEAN DEFAULT FALSE, -- True for built-in defaults, False for user-added
    priority INTEGER DEFAULT 100, -- Lower number = higher priority
    created_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    updated_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_noise_filter_rules_category ON noise_filter_rules(category_id);
CREATE INDEX idx_noise_filter_rules_enabled ON noise_filter_rules(is_enabled);
CREATE INDEX idx_noise_filter_rules_type ON noise_filter_rules(filter_type);
CREATE INDEX idx_noise_filter_rules_priority ON noise_filter_rules(priority);
CREATE INDEX idx_noise_filter_rules_system ON noise_filter_rules(is_system_default);

-- Create noise_filter_stats table to track how many events were filtered
CREATE TABLE IF NOT EXISTS noise_filter_stats (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER REFERENCES noise_filter_rules(id) ON DELETE CASCADE,
    case_id INTEGER REFERENCES "case"(id) ON DELETE CASCADE,
    events_filtered INTEGER DEFAULT 0,
    last_matched TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_noise_filter_stats_rule ON noise_filter_stats(rule_id);
CREATE INDEX idx_noise_filter_stats_case ON noise_filter_stats(case_id);
CREATE INDEX idx_noise_filter_stats_last_matched ON noise_filter_stats(last_matched);

-- Insert default categories
INSERT INTO noise_filter_categories (name, description, is_enabled) VALUES
    ('RMM Tools', 'Remote Monitoring and Management tools used by IT administrators', TRUE),
    ('EDR/MDR Platforms', 'Endpoint Detection and Response and Managed Detection and Response platforms', TRUE),
    ('Remote Access Tools', 'Legitimate remote access and support tools', TRUE),
    ('Backup Software', 'Backup and recovery software', TRUE),
    ('System Software', 'Known good system software and utilities', TRUE),
    ('Monitoring Tools', 'System monitoring and performance tools', TRUE)
ON CONFLICT (name) DO NOTHING;

-- Insert default RMM tool filters
WITH rmm_category AS (SELECT id FROM noise_filter_categories WHERE name = 'RMM Tools' LIMIT 1)
INSERT INTO noise_filter_rules (category_id, name, description, filter_type, pattern, match_mode, is_enabled, is_system_default, priority)
SELECT 
    rmm_category.id,
    'ConnectWise Automate',
    'ConnectWise Automate (formerly LabTech) RMM platform',
    'process_name',
    'labtech',
    'contains',
    TRUE,
    TRUE,
    100
FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'ConnectWise Control', 'ConnectWise Control (formerly ScreenConnect)', 'process_name', 'screenconnect', 'contains', TRUE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'Datto RMM', 'Datto RMM (formerly Autotask Endpoint Management)', 'process_name', 'datto', 'contains', TRUE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'Kaseya VSA', 'Kaseya Virtual System Administrator', 'process_name', 'kaseya', 'contains', TRUE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'N-able N-central', 'N-able N-central (formerly SolarWinds N-central)', 'process_name', 'n-central', 'contains', TRUE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'NinjaRMM', 'NinjaOne RMM platform', 'process_name', 'ninjarmm', 'contains', TRUE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'Atera', 'Atera RMM platform', 'process_name', 'atera', 'contains', TRUE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'Syncro', 'Syncro RMM platform', 'process_name', 'syncro', 'contains', TRUE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'Level', 'Level (formerly Pulseway) RMM', 'process_name', 'pulseway', 'contains', TRUE, TRUE, 100 FROM rmm_category;

-- Insert default EDR/MDR filters
WITH edr_category AS (SELECT id FROM noise_filter_categories WHERE name = 'EDR/MDR Platforms' LIMIT 1)
INSERT INTO noise_filter_rules (category_id, name, description, filter_type, pattern, match_mode, is_enabled, is_system_default, priority)
SELECT 
    edr_category.id,
    'BlackPoint Cyber MDR',
    'BlackPoint Cyber Managed Detection and Response',
    'process_name',
    'blackpoint',
    'contains',
    TRUE,
    TRUE,
    100
FROM edr_category
UNION ALL
SELECT edr_category.id, 'Huntress EDR', 'Huntress Managed EDR', 'process_name', 'huntress', 'contains', TRUE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'SentinelOne', 'SentinelOne EDR platform', 'process_name', 'sentinel', 'contains', TRUE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'CrowdStrike Falcon', 'CrowdStrike Falcon EDR', 'process_name', 'crowdstrike', 'contains', TRUE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'Microsoft Defender', 'Microsoft Defender for Endpoint', 'process_name', 'msmpeng', 'contains', TRUE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'Carbon Black', 'VMware Carbon Black EDR', 'process_name', 'carbonblack', 'contains', TRUE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'Cylance', 'BlackBerry Cylance EDR', 'process_name', 'cylance', 'contains', TRUE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'Sophos', 'Sophos Endpoint Protection', 'process_name', 'sophos', 'contains', TRUE, TRUE, 100 FROM edr_category;

-- Insert default Remote Access Tool filters
WITH remote_category AS (SELECT id FROM noise_filter_categories WHERE name = 'Remote Access Tools' LIMIT 1)
INSERT INTO noise_filter_rules (category_id, name, description, filter_type, pattern, match_mode, is_enabled, is_system_default, priority)
SELECT 
    remote_category.id,
    'TeamViewer',
    'TeamViewer remote access',
    'process_name',
    'teamviewer',
    'contains',
    TRUE,
    TRUE,
    100
FROM remote_category
UNION ALL
SELECT remote_category.id, 'AnyDesk', 'AnyDesk remote access', 'process_name', 'anydesk', 'contains', TRUE, TRUE, 100 FROM remote_category
UNION ALL
SELECT remote_category.id, 'LogMeIn', 'LogMeIn remote access', 'process_name', 'logmein', 'contains', TRUE, TRUE, 100 FROM remote_category
UNION ALL
SELECT remote_category.id, 'GoToMyPC', 'GoTo remote access tools', 'process_name', 'gotomypc', 'contains', TRUE, TRUE, 100 FROM remote_category
UNION ALL
SELECT remote_category.id, 'Splashtop', 'Splashtop remote access', 'process_name', 'splashtop', 'contains', TRUE, TRUE, 100 FROM remote_category
UNION ALL
SELECT remote_category.id, 'Chrome Remote Desktop', 'Google Chrome Remote Desktop', 'process_name', 'remoting_host', 'contains', TRUE, TRUE, 100 FROM remote_category
UNION ALL
SELECT remote_category.id, 'Windows RDP', 'Microsoft Remote Desktop Protocol', 'process_name', 'mstsc', 'contains', TRUE, TRUE, 100 FROM remote_category;

-- Grant permissions to casescope user
GRANT ALL PRIVILEGES ON noise_filter_categories TO casescope;
GRANT ALL PRIVILEGES ON noise_filter_rules TO casescope;
GRANT ALL PRIVILEGES ON noise_filter_stats TO casescope;
GRANT USAGE, SELECT ON SEQUENCE noise_filter_categories_id_seq TO casescope;
GRANT USAGE, SELECT ON SEQUENCE noise_filter_rules_id_seq TO casescope;
GRANT USAGE, SELECT ON SEQUENCE noise_filter_stats_id_seq TO casescope;

