#!/usr/bin/env python3
"""Migration: Add timezone support to CaseScope

This migration adds:
1. PostgreSQL: timezone column to cases table
2. ClickHouse: timestamp_utc and timestamp_source_tz columns to events table

Run this migration after updating the codebase to v3.96.00.

Usage:
    python migrations/add_timezone_columns.py
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config


def migrate_postgresql():
    """Add timezone column to cases table"""
    print("Migrating PostgreSQL...")
    
    from app import create_app
    from models.database import db
    
    app = create_app()
    with app.app_context():
        # Check if column exists
        result = db.session.execute(db.text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'cases' AND column_name = 'timezone'
        """))
        
        if result.fetchone():
            print("  - Column 'timezone' already exists in cases table")
        else:
            db.session.execute(db.text("""
                ALTER TABLE cases 
                ADD COLUMN timezone VARCHAR(50) NOT NULL DEFAULT 'UTC'
            """))
            db.session.commit()
            print("  - Added 'timezone' column to cases table with default 'UTC'")
    
    print("PostgreSQL migration complete!")


def migrate_clickhouse():
    """Add timestamp_utc and timestamp_source_tz columns to events table"""
    print("Migrating ClickHouse...")
    
    import clickhouse_connect
    
    client = clickhouse_connect.get_client(
        host=Config.CLICKHOUSE_HOST,
        port=Config.CLICKHOUSE_PORT,
        database=Config.CLICKHOUSE_DATABASE,
        username=Config.CLICKHOUSE_USER,
        password=Config.CLICKHOUSE_PASSWORD
    )
    
    # Check if columns exist
    columns = client.query("DESCRIBE TABLE events")
    column_names = [row[0] for row in columns.result_rows]
    
    # Add timestamp_utc if not exists
    if 'timestamp_utc' not in column_names:
        client.command("""
            ALTER TABLE events 
            ADD COLUMN timestamp_utc DateTime64(3) DEFAULT timestamp
        """)
        print("  - Added 'timestamp_utc' column to events table")
        
        # Also add to buffer table
        try:
            client.command("""
                ALTER TABLE events_buffer 
                ADD COLUMN timestamp_utc DateTime64(3) DEFAULT timestamp
            """)
            print("  - Added 'timestamp_utc' column to events_buffer table")
        except Exception as e:
            print(f"  - events_buffer column may already exist or table doesn't exist: {e}")
    else:
        print("  - Column 'timestamp_utc' already exists in events table")
    
    # Add timestamp_source_tz if not exists
    if 'timestamp_source_tz' not in column_names:
        client.command("""
            ALTER TABLE events 
            ADD COLUMN timestamp_source_tz LowCardinality(String) DEFAULT 'UTC'
        """)
        print("  - Added 'timestamp_source_tz' column to events table")
        
        # Also add to buffer table
        try:
            client.command("""
                ALTER TABLE events_buffer 
                ADD COLUMN timestamp_source_tz LowCardinality(String) DEFAULT 'UTC'
            """)
            print("  - Added 'timestamp_source_tz' column to events_buffer table")
        except Exception as e:
            print(f"  - events_buffer column may already exist or table doesn't exist: {e}")
    else:
        print("  - Column 'timestamp_source_tz' already exists in events table")
    
    print("ClickHouse migration complete!")


def backfill_timestamp_utc():
    """Backfill timestamp_utc for existing data
    
    For existing data, timestamp_utc = timestamp (assuming UTC)
    This is already handled by the DEFAULT clause.
    """
    print("Backfilling timestamp_utc for existing data...")
    print("  - DEFAULT clause handles this automatically for new queries")
    print("  - Existing data will use timestamp as timestamp_utc (assuming UTC)")
    print("Backfill complete!")


def main():
    print("=" * 60)
    print("CaseScope Timezone Migration")
    print("=" * 60)
    print()
    
    try:
        migrate_postgresql()
        print()
        migrate_clickhouse()
        print()
        backfill_timestamp_utc()
        print()
        print("=" * 60)
        print("Migration completed successfully!")
        print("=" * 60)
        print()
        print("Next steps:")
        print("1. Restart casescope-web service:  sudo systemctl restart casescope-web")
        print("2. Restart casescope-workers service: sudo systemctl restart casescope-workers")
        print()
    except Exception as e:
        print(f"Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
