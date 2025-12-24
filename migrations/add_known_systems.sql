-- Migration: Add Known Systems Table
-- Date: 2025-12-24
-- Description: Adds known_systems table to track systems/devices in investigations
-- Database: PostgreSQL

-- Create known_systems table
CREATE TABLE IF NOT EXISTS known_systems (
    id SERIAL PRIMARY KEY,
    
    -- Core System Data
    hostname VARCHAR(255),
    domain_name VARCHAR(255),
    ip_address VARCHAR(45),  -- Supports IPv4 and IPv6
    
    -- Classification
    compromised VARCHAR(20) DEFAULT 'unknown' NOT NULL,  -- yes, no, unknown
    source VARCHAR(50) DEFAULT 'manual' NOT NULL,  -- manual, logs
    system_type VARCHAR(50) NOT NULL,  -- workstation, server, router, switch, printer, wap, other, threat_actor
    
    -- Additional Details
    description TEXT,
    analyst_notes TEXT,
    
    -- Relationships
    case_id INTEGER NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
    
    -- Audit
    created_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    updated_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_known_systems_hostname ON known_systems(hostname);
CREATE INDEX IF NOT EXISTS idx_known_systems_domain_name ON known_systems(domain_name);
CREATE INDEX IF NOT EXISTS idx_known_systems_ip_address ON known_systems(ip_address);
CREATE INDEX IF NOT EXISTS idx_known_systems_compromised ON known_systems(compromised);
CREATE INDEX IF NOT EXISTS idx_known_systems_source ON known_systems(source);
CREATE INDEX IF NOT EXISTS idx_known_systems_system_type ON known_systems(system_type);
CREATE INDEX IF NOT EXISTS idx_known_systems_case_id ON known_systems(case_id);
CREATE INDEX IF NOT EXISTS idx_known_systems_created_at ON known_systems(created_at);

-- Grant permissions to casescope user
GRANT ALL PRIVILEGES ON TABLE known_systems TO casescope;
GRANT USAGE, SELECT ON SEQUENCE known_systems_id_seq TO casescope;

