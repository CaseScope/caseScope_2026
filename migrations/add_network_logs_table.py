#!/usr/bin/env python3
"""
Migration: Add Network Logs Table for PCAP/Zeek Data

Creates ClickHouse table for storing parsed Zeek log output from PCAP analysis.
Also adds indexed_at column to pcap_files PostgreSQL table.

Run with: python migrations/add_network_logs_table.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.clickhouse import get_fresh_client
from app import create_app
from models.database import db
from sqlalchemy import text


# ClickHouse schema for network_logs table
NETWORK_LOGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS network_logs (
    -- ==========================================
    -- PARTITION & PRIMARY KEY FIELDS
    -- ==========================================
    case_id           UInt32,                                    -- PostgreSQL case.id
    log_type          LowCardinality(String),                    -- conn, dns, http, ssl, files, etc.
    timestamp         DateTime64(6),                             -- Zeek ts field (microsecond precision)
    
    -- ==========================================
    -- SOURCE TRACKING
    -- ==========================================
    pcap_id           UInt32,                                    -- FK to PostgreSQL pcap_files.id
    source_host       LowCardinality(String),                    -- Hostname from PCAP metadata
    uid               String DEFAULT '',                         -- Zeek connection UID
    
    -- ==========================================
    -- CONNECTION FIELDS (conn.log)
    -- ==========================================
    src_ip            Nullable(IPv6),                            -- id.orig_h (IPv6 supports both v4 and v6)
    src_port          Nullable(UInt16),                          -- id.orig_p
    dst_ip            Nullable(IPv6),                            -- id.resp_h
    dst_port          Nullable(UInt16),                          -- id.resp_p
    proto             LowCardinality(Nullable(String)),          -- tcp, udp, icmp
    service           LowCardinality(Nullable(String)),          -- Detected service (http, dns, ssl, etc.)
    duration          Nullable(Float64),                         -- Connection duration in seconds
    orig_bytes        Nullable(UInt64),                          -- Bytes from originator
    resp_bytes        Nullable(UInt64),                          -- Bytes from responder
    conn_state        LowCardinality(Nullable(String)),          -- S0, S1, SF, REJ, etc.
    missed_bytes      Nullable(UInt64),
    orig_pkts         Nullable(UInt64),
    resp_pkts         Nullable(UInt64),
    
    -- ==========================================
    -- DNS FIELDS (dns.log)
    -- ==========================================
    query             Nullable(String),                          -- DNS query
    qtype             Nullable(UInt16),                          -- Query type numeric
    qtype_name        LowCardinality(Nullable(String)),          -- A, AAAA, MX, TXT, etc.
    rcode             Nullable(UInt16),                          -- Response code numeric
    rcode_name        LowCardinality(Nullable(String)),          -- NOERROR, NXDOMAIN, etc.
    answers           Array(String) DEFAULT [],                  -- DNS answers
    ttls              Array(UInt32) DEFAULT [],                  -- TTL values
    rejected          Nullable(UInt8),                           -- Query rejected
    
    -- ==========================================
    -- HTTP FIELDS (http.log)
    -- ==========================================
    method            LowCardinality(Nullable(String)),          -- GET, POST, etc.
    host              Nullable(String),                          -- HTTP Host header
    uri               Nullable(String),                          -- Request URI
    referrer          Nullable(String),                          -- Referer header
    user_agent        Nullable(String),                          -- User-Agent string
    request_body_len  Nullable(UInt64),
    response_body_len Nullable(UInt64),
    status_code       Nullable(UInt16),                          -- HTTP status code
    status_msg        Nullable(String),
    resp_mime_type    LowCardinality(Nullable(String)),
    
    -- ==========================================
    -- SSL/TLS FIELDS (ssl.log)
    -- ==========================================
    ssl_version       LowCardinality(Nullable(String)),          -- TLSv12, TLSv13, etc.
    cipher            Nullable(String),                          -- Cipher suite
    server_name       Nullable(String),                          -- SNI
    subject           Nullable(String),                          -- Certificate subject
    issuer            Nullable(String),                          -- Certificate issuer
    validation_status LowCardinality(Nullable(String)),          -- ok, self signed, etc.
    ja3               Nullable(String),                          -- JA3 fingerprint
    ja3s              Nullable(String),                          -- JA3S fingerprint
    
    -- ==========================================
    -- FILES FIELDS (files.log)
    -- ==========================================
    fuid              Nullable(String),                          -- File UID
    file_source       LowCardinality(Nullable(String)),          -- HTTP, FTP, etc.
    analyzers         Array(LowCardinality(String)) DEFAULT [],  -- File analyzers used
    mime_type         LowCardinality(Nullable(String)),
    filename          Nullable(String),
    file_size         Nullable(UInt64),                          -- seen_bytes or total_bytes
    md5               Nullable(String),
    sha1              Nullable(String),
    sha256            Nullable(String),
    extracted         Nullable(String),                          -- Path if file was extracted
    
    -- ==========================================
    -- FLEXIBLE DATA STORAGE
    -- ==========================================
    raw_json          String CODEC(ZSTD(3)),                     -- Full Zeek log line as JSON
    search_blob       String CODEC(ZSTD(1)),                     -- Flattened text for full-text search
    
    -- ==========================================
    -- METADATA
    -- ==========================================
    indexed_at        DateTime64(3) DEFAULT now64(3),
    
    -- ==========================================
    -- INDEXES FOR SEARCH PERFORMANCE
    -- ==========================================
    INDEX idx_search_ngram search_blob 
        TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
    INDEX idx_search_token search_blob 
        TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_uid uid 
        TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY (case_id, log_type)
ORDER BY (case_id, log_type, pcap_id, timestamp)
TTL timestamp + INTERVAL 2 YEAR DELETE
SETTINGS 
    index_granularity = 8192,
    min_bytes_for_wide_part = 0,
    min_rows_for_wide_part = 0;
"""

# Buffer table for faster ingestion
NETWORK_LOGS_BUFFER = """
CREATE TABLE IF NOT EXISTS network_logs_buffer AS network_logs
ENGINE = Buffer(
    casescope,           -- database
    network_logs,        -- destination table
    16,                  -- num_layers
    10, 100,             -- min_time, max_time (seconds)
    10000, 100000,       -- min_rows, max_rows
    10000000, 100000000  -- min_bytes, max_bytes
);
"""


def migrate_clickhouse():
    """Create ClickHouse network_logs table"""
    print("Creating ClickHouse network_logs table...")
    
    client = get_fresh_client()
    
    # Create main table
    try:
        client.command(NETWORK_LOGS_SCHEMA)
        print("✓ Created network_logs table")
    except Exception as e:
        if "already exists" in str(e).lower():
            print("○ network_logs table already exists")
        else:
            raise
    
    # Create buffer table
    try:
        client.command(NETWORK_LOGS_BUFFER)
        print("✓ Created network_logs_buffer table")
    except Exception as e:
        if "already exists" in str(e).lower():
            print("○ network_logs_buffer table already exists")
        else:
            raise
    
    # Verify
    result = client.query("DESCRIBE network_logs")
    print(f"✓ Verified table has {len(result.result_rows)} columns")


def migrate_postgres():
    """Add indexed_at column to pcap_files table"""
    print("\nUpdating PostgreSQL pcap_files table...")
    
    app = create_app()
    
    with app.app_context():
        # Check if column exists
        result = db.session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'pcap_files' AND column_name = 'indexed_at'
        """))
        
        if result.fetchone():
            print("○ indexed_at column already exists")
        else:
            db.session.execute(text("""
                ALTER TABLE pcap_files 
                ADD COLUMN indexed_at TIMESTAMP NULL
            """))
            db.session.commit()
            print("✓ Added indexed_at column to pcap_files")
        
        # Also add logs_indexed count column
        result = db.session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'pcap_files' AND column_name = 'logs_indexed'
        """))
        
        if result.fetchone():
            print("○ logs_indexed column already exists")
        else:
            db.session.execute(text("""
                ALTER TABLE pcap_files 
                ADD COLUMN logs_indexed INTEGER DEFAULT 0
            """))
            db.session.commit()
            print("✓ Added logs_indexed column to pcap_files")


def migrate():
    """Run all migrations"""
    print("=" * 50)
    print("Network Logs Migration")
    print("=" * 50)
    
    migrate_clickhouse()
    migrate_postgres()
    
    print("\n" + "=" * 50)
    print("Migration complete!")
    print("=" * 50)


if __name__ == '__main__':
    migrate()
