-- Add table for SIGMA rule management
-- Tracks which SIGMA rules are enabled/disabled

CREATE TABLE IF NOT EXISTS sigma_rules (
    id SERIAL PRIMARY KEY,
    rule_path VARCHAR(512) NOT NULL UNIQUE,  -- Relative path from rules/sigma/rules/
    rule_id VARCHAR(255),  -- UUID from rule file
    rule_title VARCHAR(512),  -- Title from rule file
    rule_level VARCHAR(50),  -- critical, high, medium, low
    rule_status VARCHAR(50),  -- Status from rule file
    rule_category VARCHAR(255),  -- e.g., 'windows/process_creation'
    logsource JSONB,  -- Logsource information from rule
    mitre_tags TEXT,  -- Comma-separated MITRE ATT&CK tags
    is_enabled BOOLEAN DEFAULT true,  -- Whether the rule is enabled
    source_folder VARCHAR(255) DEFAULT 'rules',  -- rules, rules-emerging-threats, rules-threat-hunting, etc.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_synced TIMESTAMP  -- Last time rules were synced from disk
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_sigma_rules_enabled ON sigma_rules(is_enabled);
CREATE INDEX IF NOT EXISTS idx_sigma_rules_source_folder ON sigma_rules(source_folder);
CREATE INDEX IF NOT EXISTS idx_sigma_rules_category ON sigma_rules(rule_category);
CREATE INDEX IF NOT EXISTS idx_sigma_rules_level ON sigma_rules(rule_level);

-- Add trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_sigma_rules_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_sigma_rules_updated_at BEFORE UPDATE
    ON sigma_rules FOR EACH ROW EXECUTE PROCEDURE update_sigma_rules_updated_at();

-- Grant permissions to casescope user
GRANT ALL PRIVILEGES ON TABLE sigma_rules TO casescope;
GRANT USAGE, SELECT ON SEQUENCE sigma_rules_id_seq TO casescope;
GRANT EXECUTE ON FUNCTION update_sigma_rules_updated_at() TO casescope;

