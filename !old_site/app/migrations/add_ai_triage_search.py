#!/usr/bin/env python3
"""
Migration: Add AITriageSearch table (v1.39.0)

This migration creates the ai_triage_search table for storing
results of the 9-phase AI Triage Search feature.

Run with: python app/migrations/add_ai_triage_search.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db
from sqlalchemy import text

def run_migration():
    """Create the ai_triage_search table."""
    
    with app.app_context():
        # Check if table already exists
        result = db.session.execute(text(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ai_triage_search')"
        ))
        exists = result.scalar()
        
        if exists:
            print("Table 'ai_triage_search' already exists. Skipping migration.")
            return True
        
        print("Creating 'ai_triage_search' table...")
        
        # Create the table
        db.session.execute(text("""
            CREATE TABLE ai_triage_search (
                id SERIAL PRIMARY KEY,
                case_id INTEGER NOT NULL REFERENCES "case"(id),
                generated_by INTEGER NOT NULL REFERENCES "user"(id),
                
                -- Task tracking
                status VARCHAR(20) DEFAULT 'pending',
                celery_task_id VARCHAR(255),
                
                -- Entry point
                entry_point VARCHAR(50),
                search_date TIMESTAMP,
                
                -- Results (JSON)
                iocs_extracted_json TEXT,
                iocs_discovered_json TEXT,
                timeline_json TEXT,
                process_trees_json TEXT,
                mitre_techniques_json TEXT,
                summary_json TEXT,
                
                -- Counts
                iocs_extracted_count INTEGER DEFAULT 0,
                iocs_discovered_count INTEGER DEFAULT 0,
                events_analyzed_count INTEGER DEFAULT 0,
                timeline_events_count INTEGER DEFAULT 0,
                auto_tagged_count INTEGER DEFAULT 0,
                techniques_found_count INTEGER DEFAULT 0,
                process_trees_count INTEGER DEFAULT 0,
                
                -- Progress tracking
                current_phase INTEGER DEFAULT 0,
                current_phase_name VARCHAR(100),
                progress_message VARCHAR(500),
                progress_percent INTEGER DEFAULT 0,
                
                -- Timing
                generation_time_seconds FLOAT,
                error_message TEXT,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
        """))
        
        # Create indexes
        db.session.execute(text(
            "CREATE INDEX idx_ai_triage_search_case_id ON ai_triage_search(case_id)"
        ))
        db.session.execute(text(
            "CREATE INDEX idx_ai_triage_search_status ON ai_triage_search(status)"
        ))
        db.session.execute(text(
            "CREATE INDEX idx_ai_triage_search_celery_task_id ON ai_triage_search(celery_task_id)"
        ))
        db.session.execute(text(
            "CREATE INDEX idx_ai_triage_search_created_at ON ai_triage_search(created_at)"
        ))
        
        db.session.commit()
        print("Successfully created 'ai_triage_search' table with indexes.")
        return True


if __name__ == '__main__':
    run_migration()

