#!/usr/bin/env python3
"""
Database Migration: Add Hostname Tracking Fields
=================================================
Adds new fields to CaseFile model for two-phase hostname extraction and tracking

New Fields:
- archive_type: Type of archive (single_host, multi_host, unknown)
- source_system_method: How hostname was extracted (evtx, lnk, filename, manual, path)
- source_system_confidence: Confidence level (high, medium, low, pending)
- suggested_source_system: Alternative hostname found during processing
- user_specified_hostname: Manually entered hostname
- needs_review: Flag for hostname review

Usage:
    sudo -u casescope python3 migrations/add_hostname_tracking_fields.py
"""

import os
import sys

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from main import app, db
from models import CaseFile
from sqlalchemy import text
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_column_exists(table_name, column_name):
    """Check if a column exists in a table"""
    query = text("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = :table_name 
        AND column_name = :column_name
    """)
    
    result = db.session.execute(
        query, 
        {'table_name': table_name, 'column_name': column_name}
    ).fetchone()
    
    return result is not None


def add_hostname_tracking_fields():
    """Add hostname tracking fields to case_file table"""
    
    with app.app_context():
        try:
            logger.info("Starting migration: Adding hostname tracking fields")
            
            # Define new columns
            new_columns = [
                ('archive_type', 'VARCHAR(50)', None),
                ('source_system_method', 'VARCHAR(50)', None),
                ('source_system_confidence', 'VARCHAR(20)', None),
                ('suggested_source_system', 'VARCHAR(200)', None),
                ('user_specified_hostname', 'VARCHAR(200)', None),
                ('needs_review', 'BOOLEAN', 'FALSE')
            ]
            
            # Add each column if it doesn't exist
            for column_name, column_type, default_value in new_columns:
                if check_column_exists('case_file', column_name):
                    logger.info(f"✓ Column '{column_name}' already exists, skipping")
                else:
                    logger.info(f"Adding column '{column_name}'...")
                    
                    if default_value:
                        alter_sql = f"ALTER TABLE case_file ADD COLUMN {column_name} {column_type} DEFAULT {default_value}"
                    else:
                        alter_sql = f"ALTER TABLE case_file ADD COLUMN {column_name} {column_type}"
                    
                    db.session.execute(text(alter_sql))
                    logger.info(f"✓ Added column '{column_name}'")
            
            # Commit changes
            db.session.commit()
            logger.info("✓ Migration completed successfully")
            
            # Update existing records with default confidence levels
            logger.info("Updating existing records with default values...")
            
            update_query = text("""
                UPDATE case_file
                SET 
                    source_system_confidence = CASE
                        WHEN source_system IS NOT NULL AND source_system != '' THEN 'medium'
                        ELSE 'low'
                    END,
                    source_system_method = CASE
                        WHEN source_system IS NOT NULL AND source_system != '' THEN 'filename'
                        ELSE 'none'
                    END,
                    needs_review = CASE
                        WHEN source_system IS NULL OR source_system = '' OR source_system = 'Unknown' THEN TRUE
                        ELSE FALSE
                    END
                WHERE source_system_confidence IS NULL
            """)
            
            result = db.session.execute(update_query)
            db.session.commit()
            logger.info(f"✓ Updated {result.rowcount} existing records")
            
            # Show summary
            logger.info("\n" + "="*60)
            logger.info("Migration Summary:")
            logger.info("="*60)
            
            total_files = db.session.query(CaseFile).count()
            needs_review_count = db.session.query(CaseFile).filter_by(needs_review=True).count()
            
            logger.info(f"Total files: {total_files}")
            logger.info(f"Files needing review: {needs_review_count}")
            
            if needs_review_count > 0:
                logger.info(f"\n⚠️  {needs_review_count} file(s) flagged for hostname review")
                logger.info("Visit /case/<case_id>/review_hostnames to review and update")
            
            logger.info("="*60)
            logger.info("✓ Migration complete!")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Migration failed: {e}", exc_info=True)
            db.session.rollback()
            return False


def rollback_migration():
    """Rollback migration (remove added columns)"""
    
    with app.app_context():
        try:
            logger.info("Rolling back migration...")
            
            columns_to_remove = [
                'archive_type',
                'source_system_method',
                'source_system_confidence',
                'suggested_source_system',
                'user_specified_hostname',
                'needs_review'
            ]
            
            for column_name in columns_to_remove:
                if check_column_exists('case_file', column_name):
                    logger.info(f"Removing column '{column_name}'...")
                    db.session.execute(text(f"ALTER TABLE case_file DROP COLUMN {column_name}"))
                    logger.info(f"✓ Removed column '{column_name}'")
            
            db.session.commit()
            logger.info("✓ Rollback complete")
            return True
            
        except Exception as e:
            logger.error(f"❌ Rollback failed: {e}", exc_info=True)
            db.session.rollback()
            return False


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Migrate database to add hostname tracking fields')
    parser.add_argument('--rollback', action='store_true', help='Rollback the migration')
    args = parser.parse_args()
    
    if args.rollback:
        print("\n⚠️  WARNING: This will remove hostname tracking fields!")
        confirm = input("Are you sure? (yes/no): ")
        if confirm.lower() == 'yes':
            success = rollback_migration()
            sys.exit(0 if success else 1)
        else:
            print("Rollback cancelled")
            sys.exit(0)
    else:
        success = add_hostname_tracking_fields()
        sys.exit(0 if success else 1)

