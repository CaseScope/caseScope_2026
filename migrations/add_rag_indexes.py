#!/usr/bin/env python3
"""Database migration to add indexes on RAG tables for performance

Adds indexes on:
- rag_query_logs.created_at (for time-range queries)
- rag_query_logs.query_type (for filtering by type)
- semantic_match_feedback.created_at (for time-range queries)
- semantic_match_feedback.pattern_id (for threshold recommendations)

Author: CaseScope
Date: January 2026
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Add indexes to RAG tables"""
    app = create_app()
    
    with app.app_context():
        indexes_to_create = [
            # RAG Query Logs indexes
            ("idx_rag_query_logs_created_at", "rag_query_logs", "created_at"),
            ("idx_rag_query_logs_query_type", "rag_query_logs", "query_type"),
            ("idx_rag_query_logs_case_id", "rag_query_logs", "case_id"),
            
            # Semantic Match Feedback indexes  
            ("idx_semantic_feedback_created_at", "semantic_match_feedback", "created_at"),
            ("idx_semantic_feedback_pattern_id", "semantic_match_feedback", "pattern_id"),
            ("idx_semantic_feedback_verdict", "semantic_match_feedback", "verdict"),
            
            # Pattern Rule Matches indexes (for faster queries)
            ("idx_pattern_rule_matches_case_severity", "pattern_rule_matches", "case_id, severity"),
            ("idx_pattern_rule_matches_category", "pattern_rule_matches", "category"),
        ]
        
        created = 0
        skipped = 0
        
        for index_name, table_name, columns in indexes_to_create:
            try:
                # Check if index exists
                check_sql = f"""
                    SELECT 1 FROM pg_indexes 
                    WHERE indexname = '{index_name}'
                """
                result = db.session.execute(db.text(check_sql)).fetchone()
                
                if result:
                    print(f"  [SKIP] Index {index_name} already exists")
                    skipped += 1
                    continue
                
                # Check if table exists
                table_check = f"""
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_name = '{table_name}'
                """
                table_exists = db.session.execute(db.text(table_check)).fetchone()
                
                if not table_exists:
                    print(f"  [SKIP] Table {table_name} does not exist")
                    skipped += 1
                    continue
                
                # Create index
                create_sql = f"CREATE INDEX {index_name} ON {table_name} ({columns})"
                db.session.execute(db.text(create_sql))
                db.session.commit()
                print(f"  [OK] Created index {index_name} on {table_name}({columns})")
                created += 1
                
            except Exception as e:
                print(f"  [ERROR] Failed to create {index_name}: {e}")
                db.session.rollback()
        
        print(f"\nMigration complete: {created} indexes created, {skipped} skipped")
        return True


if __name__ == '__main__':
    print("=" * 60)
    print("RAG Table Index Migration")
    print("=" * 60)
    print()
    
    try:
        run_migration()
        sys.exit(0)
    except Exception as e:
        print(f"Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
