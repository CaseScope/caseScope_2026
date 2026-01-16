-- ============================================
-- CaseScope ClickHouse Schema
-- Events table for forensic artifact storage
-- ============================================

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS casescope;

-- Switch to database
USE casescope;

-- Drop existing table if rebuilding (comment out in production)
-- DROP TABLE IF EXISTS events;

-- Main events table
CREATE TABLE IF NOT EXISTS events (
    -- ==========================================
    -- PARTITION & PRIMARY KEY FIELDS
    -- ==========================================
    case_id           UInt32,                                    -- PostgreSQL case.id (not UUID)
    artifact_type     LowCardinality(String),                    -- evtx, prefetch, registry, lnk, etc.
    timestamp         DateTime64(3),                             -- Original event timestamp (forensic integrity)
    timestamp_utc     DateTime64(3),                             -- Normalized UTC timestamp for sorting/filtering
    timestamp_source_tz LowCardinality(String) DEFAULT 'UTC',    -- Source timezone assumption (IANA identifier)
    
    -- ==========================================
    -- SOURCE TRACKING
    -- ==========================================
    source_file       LowCardinality(String),                    -- Original filename
    source_path       String,                                    -- Full path in staging
    source_host       LowCardinality(String),                    -- Hostname extracted from artifact
    case_file_id      Nullable(UInt32),                          -- FK to PostgreSQL case_files.id
    
    -- ==========================================
    -- COMMON EVENT FIELDS
    -- ==========================================
    event_id          LowCardinality(Nullable(String)),          -- Windows Event ID or equivalent
    channel           LowCardinality(Nullable(String)),          -- EVTX channel (Security, System, etc.)
    provider          LowCardinality(Nullable(String)),          -- Event provider name
    record_id         Nullable(UInt64),                          -- EVTX record ID
    level             LowCardinality(Nullable(String)),          -- Event level (info, warning, error)
    
    -- ==========================================
    -- NORMALIZED DFIR FIELDS
    -- ==========================================
    -- Actor/User
    username          Nullable(String),
    domain            LowCardinality(Nullable(String)),
    sid               Nullable(String),
    logon_type        Nullable(UInt8),
    logon_id          Nullable(String),                            -- Target logon ID for session correlation
    
    -- Logon Details (from EVTX EventData)
    remote_host       Nullable(String),                            -- EvtxECmd RemoteHost (IP/hostname of source)
    workstation_name  Nullable(String),                            -- Source workstation name
    auth_package      LowCardinality(Nullable(String)),            -- NTLM, Kerberos, Negotiate, etc.
    logon_process     LowCardinality(Nullable(String)),            -- Logon process name (Advapi, User32, etc.)
    elevated_token    LowCardinality(Nullable(String)),            -- Elevated token indicator
    
    -- Process
    process_name      Nullable(String),
    process_path      Nullable(String),
    process_id        Nullable(UInt32),
    parent_process    Nullable(String),
    parent_pid        Nullable(UInt32),
    command_line      Nullable(String),
    thread_id         Nullable(UInt32),                            -- Thread ID from System
    executable_info   Nullable(String),                            -- EvtxECmd ExecutableInfo (Maps-normalized)
    
    -- EvtxECmd Maps Payload Summary
    payload_data1     Nullable(String),                            -- Maps-extracted field 1
    payload_data2     Nullable(String),                            -- Maps-extracted field 2
    payload_data3     Nullable(String),                            -- Maps-extracted field 3
    payload_data4     Nullable(String),                            -- Maps-extracted field 4
    payload_data5     Nullable(String),                            -- Maps-extracted field 5
    payload_data6     Nullable(String),                            -- Maps-extracted field 6
    
    -- File
    target_path       Nullable(String),
    file_hash_md5     Nullable(String),
    file_hash_sha1    Nullable(String),
    file_hash_sha256  Nullable(String),
    file_size         Nullable(UInt64),
    
    -- Network
    src_ip            Nullable(IPv4),
    dst_ip            Nullable(IPv4),
    src_port          Nullable(UInt16),
    dst_port          Nullable(UInt16),
    
    -- Registry (for registry artifacts)
    reg_key           Nullable(String),
    reg_value         Nullable(String),
    reg_data          Nullable(String),
    
    -- ==========================================
    -- HAYABUSA DETECTION FIELDS
    -- ==========================================
    rule_title        Nullable(String),                          -- Detection rule name
    rule_level        LowCardinality(Nullable(String)),          -- info, low, med, high, crit
    rule_file         Nullable(String),                          -- Path to rule file
    mitre_tactics     Array(LowCardinality(String)) DEFAULT [],  -- MITRE tactics
    mitre_tags        Array(LowCardinality(String)) DEFAULT [],  -- MITRE technique IDs
    
    -- ==========================================
    -- FLEXIBLE DATA STORAGE
    -- ==========================================
    raw_json          String CODEC(ZSTD(3)),                     -- Original parsed data as JSON
    search_blob       String CODEC(ZSTD(1)),                     -- Flattened text for full-text search
    extra_fields      String CODEC(ZSTD(3)) DEFAULT '{}',        -- Additional fields as JSON
    
    -- ==========================================
    -- METADATA
    -- ==========================================
    indexed_at        DateTime64(3) DEFAULT now64(3),
    parser_version    LowCardinality(String) DEFAULT '',
    
    -- ==========================================
    -- INDEXES FOR SEARCH PERFORMANCE
    -- ==========================================
    -- N-gram index for substring matching (LIKE '%term%')
    INDEX idx_search_ngram search_blob 
        TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
    
    -- Token bloom filter for whole-word matching
    INDEX idx_search_token search_blob 
        TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    
    -- Bloom filters for common filter fields
    INDEX idx_event_id event_id 
        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_username username 
        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_process process_name 
        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_rule_level rule_level 
        TYPE bloom_filter(0.01) GRANULARITY 4,
    
    -- Command line n-gram for partial matching
    INDEX idx_cmdline command_line 
        TYPE ngrambf_v1(4, 256, 2, 0) GRANULARITY 4,
    
    -- File path token index
    INDEX idx_path target_path 
        TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4,
    
    -- IP address set indexes
    INDEX idx_src_ip src_ip 
        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_dst_ip dst_ip 
        TYPE bloom_filter(0.01) GRANULARITY 4,
    
    -- MITRE tags array index
    INDEX idx_mitre mitre_tags 
        TYPE bloom_filter(0.01) GRANULARITY 4,
    
    -- New field indexes for session/logon analysis
    INDEX idx_logon_id logon_id 
        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_remote_host remote_host 
        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_auth_package auth_package 
        TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY (case_id, artifact_type)
ORDER BY (case_id, artifact_type, source_host, timestamp)
TTL timestamp + INTERVAL 2 YEAR DELETE
SETTINGS 
    index_granularity = 8192,
    min_bytes_for_wide_part = 0,
    min_rows_for_wide_part = 0;


-- ============================================
-- Buffer table for high-speed ingestion
-- ============================================
CREATE TABLE IF NOT EXISTS events_buffer AS events
ENGINE = Buffer(
    casescope,        -- database
    events,           -- destination table
    16,               -- num_layers
    10, 100,          -- min_time, max_time (seconds)
    10000, 100000,    -- min_rows, max_rows
    10000000, 100000000  -- min_bytes, max_bytes (~10MB, ~100MB)
);


-- ============================================
-- Materialized view for detection summary
-- ============================================
CREATE MATERIALIZED VIEW IF NOT EXISTS detection_summary
ENGINE = SummingMergeTree()
PARTITION BY case_id
ORDER BY (case_id, rule_level, rule_title, toDate(timestamp))
AS SELECT
    case_id,
    rule_level,
    rule_title,
    toDate(timestamp) as detection_date,
    count() as detection_count
FROM events
WHERE rule_title IS NOT NULL AND rule_title != ''
GROUP BY case_id, rule_level, rule_title, toDate(timestamp);


-- ============================================
-- Materialized view for timeline aggregation
-- ============================================
CREATE MATERIALIZED VIEW IF NOT EXISTS timeline_hourly
ENGINE = SummingMergeTree()
PARTITION BY case_id
ORDER BY (case_id, artifact_type, hour)
AS SELECT
    case_id,
    artifact_type,
    toStartOfHour(timestamp) as hour,
    count() as event_count
FROM events
GROUP BY case_id, artifact_type, toStartOfHour(timestamp);


-- ============================================
-- Useful queries for verification
-- ============================================

-- Check table exists and structure
-- DESCRIBE events;

-- Check partitions
-- SELECT partition, name, rows, bytes_on_disk 
-- FROM system.parts 
-- WHERE table = 'events' AND active;

-- Check index usage
-- SELECT * FROM system.data_skipping_indices WHERE table = 'events';
