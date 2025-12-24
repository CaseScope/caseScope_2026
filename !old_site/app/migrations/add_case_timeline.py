#!/usr/bin/env python3
"""
Migration: Add CaseTimeline table
Creates the new case_timeline table for AI-generated timeline feature (v1.16.3)
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db
from models import CaseTimeline
from sqlalchemy import text

def migrate():
    """Create CaseTimeline table"""
    with app.app_context():
        print("="*80)
        print("MIGRATION: Add CaseTimeline Table (v1.16.3)")
        print("="*80)
        print()
        
        # Check if table already exists
        inspector = db.inspect(db.engine)
        if 'case_timeline' in inspector.get_table_names():
            print("⚠️  Table 'case_timeline' already exists. Skipping creation.")
            return
        
        print("Creating 'case_timeline' table...")
        
        # Create table using SQLAlchemy model
        CaseTimeline.__table__.create(db.engine)
        
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
        print("  - event_count")
        print("  - ioc_count")
        print("  - system_count")
        print("  - progress_percent")
        print("  - progress_message")
        print("  - error_message")
        print("  - created_at")
        print("  - updated_at")
        print()
        print("=" * 80)
        print("✅ Migration completed successfully!")
        print("=" * 80)

if __name__ == '__main__':
    migrate()

