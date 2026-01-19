#!/usr/bin/env python3
"""Database migration for RAG instrumentation and MITRE data component tables

Creates the following new tables:
- rag_query_logs: Logs all RAG/semantic search queries for baseline establishment
- semantic_match_feedback: Analyst feedback on semantic matches for threshold tuning
- mitre_data_sources: MITRE ATT&CK Data Sources (x-mitre-data-source objects)
- mitre_data_components: MITRE ATT&CK Data Components (x-mitre-data-component objects)  
- technique_data_component_maps: Maps techniques to data components for detection

Also adds new columns to attack_patterns:
- semantic_enabled: Include in semantic searches
- semantic_threshold: Per-pattern threshold override
- detection_guidance: Full detection methodology from x_mitre_detection
- procedure_examples: Real-world usage examples

Author: CaseScope
Date: January 19, 2026
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Run the migration to add RAG instrumentation tables"""
    app = create_app()
    
    with app.app_context():
        # Check if tables already exist
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        existing_tables = inspector.get_table_names()
        
        tables_to_create = [
            'rag_query_logs',
            'semantic_match_feedback',
            'mitre_data_sources',
            'mitre_data_components',
            'technique_data_component_maps'
        ]
        
        # Check for new tables
        new_tables = [t for t in tables_to_create if t not in existing_tables]
        
        if new_tables:
            print(f"Creating new tables: {', '.join(new_tables)}")
            
            # Import models to register with SQLAlchemy
            from models.rag import (
                RAGQueryLog, 
                SemanticMatchFeedback, 
                MitreDataSource, 
                MitreDataComponent, 
                TechniqueDataComponentMap
            )
            
            # Create all tables
            db.create_all()
            print("Tables created successfully!")
        else:
            print("All RAG instrumentation tables already exist.")
        
        # Add new columns to attack_patterns if they don't exist
        attack_patterns_columns = [c['name'] for c in inspector.get_columns('attack_patterns')]
        
        columns_to_add = []
        if 'semantic_enabled' not in attack_patterns_columns:
            columns_to_add.append("ADD COLUMN semantic_enabled BOOLEAN DEFAULT TRUE")
        if 'semantic_threshold' not in attack_patterns_columns:
            columns_to_add.append("ADD COLUMN semantic_threshold FLOAT")
        if 'detection_guidance' not in attack_patterns_columns:
            columns_to_add.append("ADD COLUMN detection_guidance TEXT")
        if 'procedure_examples' not in attack_patterns_columns:
            columns_to_add.append("ADD COLUMN procedure_examples JSONB")
        
        if columns_to_add:
            print(f"Adding {len(columns_to_add)} new columns to attack_patterns...")
            for alter_stmt in columns_to_add:
                try:
                    db.session.execute(db.text(f"ALTER TABLE attack_patterns {alter_stmt}"))
                    print(f"  Added: {alter_stmt}")
                except Exception as e:
                    print(f"  Warning (may already exist): {e}")
            db.session.commit()
            print("Columns added successfully!")
        else:
            print("All new columns already exist in attack_patterns.")
        
        print("\nMigration completed successfully!")
        
        # Print summary
        print("\n=== Migration Summary ===")
        print("New tables created:")
        for table in new_tables:
            print(f"  - {table}")
        print("\nNew columns added to attack_patterns:")
        print("  - semantic_enabled (BOOLEAN): Include in semantic searches")
        print("  - semantic_threshold (FLOAT): Per-pattern threshold override")
        print("  - detection_guidance (TEXT): Full detection methodology")
        print("  - procedure_examples (JSONB): Real-world usage examples")
        
        return True


if __name__ == '__main__':
    print("=" * 60)
    print("RAG Instrumentation & MITRE Data Component Migration")
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
