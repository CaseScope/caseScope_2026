-- Migration: Add Known Users table
-- Date: 2025-12-24
-- Description: Track user accounts involved in investigations
-- Database: PostgreSQL

CREATE TABLE IF NOT EXISTS known_users (
    id SERIAL PRIMARY KEY,
    
    -- Core User Data
    username VARCHAR(255) NOT NULL,
    domain_name VARCHAR(255),
    sid VARCHAR(255),
    
    -- Classification
    compromised VARCHAR(20) DEFAULT 'no' CHECK(compromised IN ('yes', 'no')),
    user_type VARCHAR(50) DEFAULT 'unknown' CHECK(user_type IN ('domain', 'local', 'unknown')),
    source VARCHAR(50) DEFAULT 'manual',
    
    -- Additional Details
    description TEXT,
    analyst_notes TEXT,
    
    -- Relationships
    case_id INTEGER NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
    
    -- Audit
    created_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    updated_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_known_users_username ON known_users(username);
CREATE INDEX IF NOT EXISTS idx_known_users_domain_name ON known_users(domain_name);
CREATE INDEX IF NOT EXISTS idx_known_users_sid ON known_users(sid);
CREATE INDEX IF NOT EXISTS idx_known_users_compromised ON known_users(compromised);
CREATE INDEX IF NOT EXISTS idx_known_users_user_type ON known_users(user_type);
CREATE INDEX IF NOT EXISTS idx_known_users_source ON known_users(source);
CREATE INDEX IF NOT EXISTS idx_known_users_case_id ON known_users(case_id);
CREATE INDEX IF NOT EXISTS idx_known_users_created_at ON known_users(created_at);

