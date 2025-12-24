#!/usr/bin/env python3
"""
Simple migration to create case_timeline table without loading full app
"""

import sqlite3
import os

db_path = '/opt/casescope/app/casescope.db'

# SQL to create the case_timeline table
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS case_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    generated_by INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    model_name VARCHAR(50) DEFAULT 'dfir-qwen:latest',
    celery_task_id VARCHAR(255),
    timeline_title VARCHAR(500),
    timeline_content TEXT,
    timeline_json TEXT,
    prompt_sent TEXT,
    raw_response TEXT,
    generation_time_seconds FLOAT,
    version INTEGER DEFAULT 1,
    event_count INTEGER,
    ioc_count INTEGER,
    system_count INTEGER,
    progress_percent INTEGER DEFAULT 0,
    progress_message VARCHAR(500),
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES "case" (id),
    FOREIGN KEY (generated_by) REFERENCES "user" (id)
);
"""

# Create indices
CREATE_INDICES_SQL = [
    "CREATE INDEX IF NOT EXISTS ix_case_timeline_case_id ON case_timeline (case_id);",
    "CREATE INDEX IF NOT EXISTS ix_case_timeline_status ON case_timeline (status);",
    "CREATE INDEX IF NOT EXISTS ix_case_timeline_celery_task_id ON case_timeline (celery_task_id);",
    "CREATE INDEX IF NOT EXISTS ix_case_timeline_created_at ON case_timeline (created_at);"
]

def main():
    print("="*80)
    print("MIGRATION: Add CaseTimeline Table (v1.16.3)")
    print("="*80)
    print()
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found at {db_path}")
        return 1
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='case_timeline'")
        if cursor.fetchone():
            print("⚠️  Table 'case_timeline' already exists. Skipping creation.")
            conn.close()
            return 0
        
        print("Creating 'case_timeline' table...")
        cursor.execute(CREATE_TABLE_SQL)
        
        print("Creating indices...")
        for sql in CREATE_INDICES_SQL:
            cursor.execute(sql)
        
        conn.commit()
        conn.close()
        
        print("✅ Table 'case_timeline' created successfully")
        print()
        print("Columns created:")
        print("  - id (Primary Key)")
        print("  - case_id (Foreign Key -> case.id)")
        print("  - generated_by (Foreign Key -> user.id)")
        print("  - status (pending/generating/completed/failed/cancelled)")
        print("  - model_name (e.g., 'dfir-qwen:latest')")
        print("  - celery_task_id (for cancellation support)")
        print("  - timeline_title")
        print("  - timeline_content (Markdown)")
        print("  - timeline_json (Structured data)")
        print("  - prompt_sent (for debugging)")
        print("  - raw_response")
        print("  - generation_time_seconds")
        print("  - version (increments on regenerate)")
        print("  - event_count, ioc_count, system_count")
        print("  - progress_percent, progress_message")
        print("  - error_message")
        print("  - created_at, updated_at")
        print()
        print("=" * 80)
        print("✅ Migration completed successfully!")
        print("=" * 80)
        return 0
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    exit(main())

