"""Migration: Add license activation tables

Creates tables for:
- license_activations: Stores license activation history
- activation_audit_log: Audit trail for activation events

Run with: python migrations/add_license_tables.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from models.database import db
from sqlalchemy import text, inspect


def migrate():
    """Run the migration."""
    with app.app_context():
        inspector = inspect(db.engine)
        existing_tables = inspector.get_table_names()
        
        # Create license_activations table
        if 'license_activations' not in existing_tables:
            db.session.execute(text('''
                CREATE TABLE license_activations (
                    id SERIAL PRIMARY KEY,
                    license_id VARCHAR(100) NOT NULL,
                    customer_id VARCHAR(100) NOT NULL,
                    customer_name VARCHAR(255),
                    issued_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    features_json TEXT,
                    activated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    activated_by VARCHAR(80),
                    fingerprint_hash VARCHAR(64),
                    fingerprint_match_count INTEGER,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    deactivated_at TIMESTAMP,
                    deactivation_reason VARCHAR(255)
                )
            '''))
            
            # Create indexes
            db.session.execute(text('''
                CREATE INDEX idx_license_activations_license_id 
                ON license_activations(license_id)
            '''))
            db.session.execute(text('''
                CREATE INDEX idx_license_activations_is_active 
                ON license_activations(is_active)
            '''))
            
            db.session.commit()
            print("Created table: license_activations")
        else:
            print("Table license_activations already exists")
        
        # Create activation_audit_log table
        if 'activation_audit_log' not in existing_tables:
            db.session.execute(text('''
                CREATE TABLE activation_audit_log (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
                    action VARCHAR(50) NOT NULL,
                    username VARCHAR(80),
                    license_id VARCHAR(100),
                    details TEXT,
                    ip_address VARCHAR(45)
                )
            '''))
            
            # Create index
            db.session.execute(text('''
                CREATE INDEX idx_activation_audit_log_timestamp 
                ON activation_audit_log(timestamp)
            '''))
            
            db.session.commit()
            print("Created table: activation_audit_log")
        else:
            print("Table activation_audit_log already exists")
        
        print("Migration completed successfully!")


def rollback():
    """Rollback the migration."""
    with app.app_context():
        db.session.execute(text('DROP TABLE IF EXISTS activation_audit_log CASCADE'))
        db.session.execute(text('DROP TABLE IF EXISTS license_activations CASCADE'))
        db.session.commit()
        print("Rollback completed - tables dropped")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='License tables migration')
    parser.add_argument('--rollback', action='store_true', help='Rollback migration')
    args = parser.parse_args()
    
    if args.rollback:
        rollback()
    else:
        migrate()
