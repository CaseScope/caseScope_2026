-- Noise Filters Migration - Enhanced
-- Adds tables for filtering known good software/tools to reduce noise in event searches
-- Updated: 2025-12-28 - Added more defaults, comma-separated patterns, AND logic support
-- Created: 2025-12-28

-- Create noise_filter_categories table
CREATE TABLE IF NOT EXISTS noise_filter_categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    is_enabled BOOLEAN DEFAULT FALSE,  -- Default to disabled
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_noise_filter_categories_enabled ON noise_filter_categories(is_enabled);

-- Create noise_filter_rules table
CREATE TABLE IF NOT EXISTS noise_filter_rules (
    id SERIAL PRIMARY KEY,
    category_id INTEGER REFERENCES noise_filter_categories(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    filter_type VARCHAR(50) NOT NULL, -- 'process_name', 'file_path', 'command_line', 'hash', 'guid', 'network_connection'
    pattern VARCHAR(1000) NOT NULL, -- Comma-separated patterns for OR logic, use && for AND logic
    match_mode VARCHAR(20) DEFAULT 'contains', -- 'exact', 'contains', 'starts_with', 'ends_with', 'regex', 'wildcard'
    is_case_sensitive BOOLEAN DEFAULT FALSE,
    is_enabled BOOLEAN DEFAULT FALSE,  -- Default to disabled
    is_system_default BOOLEAN DEFAULT FALSE, -- True for built-in defaults, False for user-added
    priority INTEGER DEFAULT 100, -- Lower number = higher priority
    created_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    updated_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_noise_filter_rules_category ON noise_filter_rules(category_id);
CREATE INDEX IF NOT EXISTS idx_noise_filter_rules_enabled ON noise_filter_rules(is_enabled);
CREATE INDEX IF NOT EXISTS idx_noise_filter_rules_type ON noise_filter_rules(filter_type);
CREATE INDEX IF NOT EXISTS idx_noise_filter_rules_priority ON noise_filter_rules(priority);
CREATE INDEX IF NOT EXISTS idx_noise_filter_rules_system ON noise_filter_rules(is_system_default);

-- Create noise_filter_stats table to track how many events were filtered
CREATE TABLE IF NOT EXISTS noise_filter_stats (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER REFERENCES noise_filter_rules(id) ON DELETE CASCADE,
    case_id INTEGER REFERENCES "case"(id) ON DELETE CASCADE,
    events_filtered INTEGER DEFAULT 0,
    last_matched TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_noise_filter_stats_rule ON noise_filter_stats(rule_id);
CREATE INDEX IF NOT EXISTS idx_noise_filter_stats_case ON noise_filter_stats(case_id);
CREATE INDEX IF NOT EXISTS idx_noise_filter_stats_last_matched ON noise_filter_stats(last_matched);

-- Insert default categories (all disabled by default)
INSERT INTO noise_filter_categories (name, description, is_enabled) VALUES
    ('RMM Tools', 'Remote Monitoring and Management tools used by IT administrators', FALSE),
    ('EDR/MDR Platforms', 'Endpoint Detection and Response and Managed Detection and Response platforms', FALSE),
    ('Remote Access Tools', 'Legitimate remote access and support tools', FALSE),
    ('Backup Software', 'Backup and recovery software', FALSE),
    ('System Software', 'Known good system software and utilities', FALSE),
    ('Monitoring Tools', 'System monitoring and performance tools', FALSE)
ON CONFLICT (name) DO NOTHING;

-- Insert default RMM tool filters (all disabled by default)
WITH rmm_category AS (SELECT id FROM noise_filter_categories WHERE name = 'RMM Tools' LIMIT 1)
INSERT INTO noise_filter_rules (category_id, name, description, filter_type, pattern, match_mode, is_enabled, is_system_default, priority)
SELECT 
    rmm_category.id,
    'ConnectWise Automate',
    'ConnectWise Automate (formerly LabTech) RMM platform',
    'process_name',
    'labtech,ltsvc,lttray',
    'contains',
    FALSE,
    TRUE,
    100
FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'ConnectWise Control', 'ConnectWise Control (formerly ScreenConnect)', 'process_name', 'screenconnect,connectwisecontrol', 'contains', FALSE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'Datto RMM', 'Datto RMM (formerly Autotask Endpoint Management)', 'process_name', 'datto,dattoagent,dattobackup', 'contains', FALSE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'Kaseya VSA', 'Kaseya Virtual System Administrator', 'process_name', 'kaseya,agentmon', 'contains', FALSE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'N-able N-central', 'N-able N-central (formerly SolarWinds N-central)', 'process_name', 'n-central,n-able,solarwinds', 'contains', FALSE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'NinjaRMM', 'NinjaOne RMM platform', 'process_name', 'ninjarmm,ninjaone', 'contains', FALSE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'Atera', 'Atera RMM platform', 'process_name', 'atera,ateraagent', 'contains', FALSE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'Syncro', 'Syncro RMM platform', 'process_name', 'syncro', 'contains', FALSE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'Level (Pulseway)', 'Level (formerly Pulseway) RMM', 'process_name', 'pulseway,level', 'contains', FALSE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'MeshCentral', 'MeshCentral remote management', 'process_name', 'meshcentral,meshagent', 'contains', FALSE, TRUE, 100 FROM rmm_category
UNION ALL
SELECT rmm_category.id, 'TacticalRMM', 'TacticalRMM open source RMM', 'process_name', 'tacticalrmm,tacticalagent', 'contains', FALSE, TRUE, 100 FROM rmm_category;

-- Insert default EDR/MDR filters
WITH edr_category AS (SELECT id FROM noise_filter_categories WHERE name = 'EDR/MDR Platforms' LIMIT 1)
INSERT INTO noise_filter_rules (category_id, name, description, filter_type, pattern, match_mode, is_enabled, is_system_default, priority)
SELECT 
    edr_category.id,
    'BlackPoint Cyber MDR',
    'BlackPoint Cyber Managed Detection and Response',
    'process_name',
    'blackpoint,bpagent',
    'contains',
    FALSE,
    TRUE,
    100
FROM edr_category
UNION ALL
SELECT edr_category.id, 'Huntress EDR', 'Huntress Managed EDR', 'process_name', 'huntress,huntressagent', 'contains', FALSE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'SentinelOne', 'SentinelOne EDR platform', 'process_name', 'sentinel,sentinelagent,sentinelone', 'contains', FALSE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'CrowdStrike Falcon', 'CrowdStrike Falcon EDR', 'process_name', 'crowdstrike,csagent,csfalcon', 'contains', FALSE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'Microsoft Defender', 'Microsoft Defender for Endpoint', 'process_name', 'msmpeng,mssense,defender', 'contains', FALSE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'Carbon Black', 'VMware Carbon Black EDR', 'process_name', 'carbonblack,cb', 'contains', FALSE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'Cylance', 'BlackBerry Cylance EDR', 'process_name', 'cylance,cylancesvc', 'contains', FALSE, TRUE, 100 FROM edr_category
UNION ALL
SELECT edr_category.id, 'Sophos', 'Sophos Endpoint Protection', 'process_name', 'sophos,savservice', 'contains', FALSE, TRUE, 100 FROM edr_category;

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
    FALSE,
    TRUE,
    100
FROM remote_category
UNION ALL
SELECT remote_category.id, 'AnyDesk', 'AnyDesk remote access', 'process_name', 'anydesk', 'contains', FALSE, TRUE, 100 FROM remote_category
UNION ALL
SELECT remote_category.id, 'LogMeIn', 'LogMeIn remote access', 'process_name', 'logmein', 'contains', FALSE, TRUE, 100 FROM remote_category
UNION ALL
SELECT remote_category.id, 'GoToMyPC', 'GoTo remote access tools', 'process_name', 'gotomypc,gotoassist', 'contains', FALSE, TRUE, 100 FROM remote_category
UNION ALL
SELECT remote_category.id, 'Splashtop', 'Splashtop remote access', 'process_name', 'splashtop', 'contains', FALSE, TRUE, 100 FROM remote_category
UNION ALL
SELECT remote_category.id, 'Chrome Remote Desktop', 'Google Chrome Remote Desktop', 'process_name', 'remoting_host,chromeremotedesktop', 'contains', FALSE, TRUE, 100 FROM remote_category
UNION ALL
SELECT remote_category.id, 'Windows RDP', 'Microsoft Remote Desktop Protocol', 'process_name', 'mstsc,rdp', 'contains', FALSE, TRUE, 100 FROM remote_category;

-- Insert default Backup Software filters
WITH backup_category AS (SELECT id FROM noise_filter_categories WHERE name = 'Backup Software' LIMIT 1)
INSERT INTO noise_filter_rules (category_id, name, description, filter_type, pattern, match_mode, is_enabled, is_system_default, priority)
SELECT 
    backup_category.id,
    'Veeam Backup',
    'Veeam Backup & Replication',
    'process_name',
    'veeam,veeamagent,veeambackup',
    'contains',
    FALSE,
    TRUE,
    100
FROM backup_category
UNION ALL
SELECT backup_category.id, 'Datto Backup', 'Datto SIRIS Backup', 'process_name', 'dattobackup,dattocontinuity', 'contains', FALSE, TRUE, 100 FROM backup_category
UNION ALL
SELECT backup_category.id, 'StorageCraft', 'StorageCraft ShadowProtect', 'process_name', 'storagecraft,shadowprotect,spxservice', 'contains', FALSE, TRUE, 100 FROM backup_category;

-- Grant permissions to casescope user
GRANT ALL PRIVILEGES ON noise_filter_categories TO casescope;
GRANT ALL PRIVILEGES ON noise_filter_rules TO casescope;
GRANT ALL PRIVILEGES ON noise_filter_stats TO casescope;
GRANT USAGE, SELECT ON SEQUENCE noise_filter_categories_id_seq TO casescope;
GRANT USAGE, SELECT ON SEQUENCE noise_filter_rules_id_seq TO casescope;
GRANT USAGE, SELECT ON SEQUENCE noise_filter_stats_id_seq TO casescope;

