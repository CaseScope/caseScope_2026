#!/usr/bin/env python3
"""
Migration: Add vpn_ip_ranges field to Case table
Version: 1.43.0
Date: 2025-11-30

This migration adds the vpn_ip_ranges field to the Case model for storing
VPN IP ranges used during triage to identify VPN connections.

Format: "192.168.100.1-192.168.100.50, 10.10.0.0/24" (comma or semicolon separated)
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db
from sqlalchemy import text


def run_migration():
    """Add vpn_ip_ranges column to case table"""
    
    with app.app_context():
        print("=" * 60)
        print("Migration: Add vpn_ip_ranges field to Case table")
        print("=" * 60)
        
        try:
            # Check if column already exists
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'case' AND column_name = 'vpn_ip_ranges'
            """))
            
            if result.fetchone():
                print("✓ Column 'vpn_ip_ranges' already exists - skipping migration")
                return True
            
            # Add the column
            print("Adding 'vpn_ip_ranges' column to 'case' table...")
            
            db.session.execute(text("""
                ALTER TABLE "case" 
                ADD COLUMN vpn_ip_ranges TEXT
            """))
            
            db.session.commit()
            print("✓ Migration completed successfully!")
            print("\nColumn added:")
            print("  - vpn_ip_ranges (TEXT) - Stores VPN IP ranges for triage")
            print("  - Format: '192.168.100.1-192.168.100.50, 10.10.0.0/24'")
            
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"✗ Migration failed: {e}")
            return False


def rollback_migration():
    """Remove vpn_ip_ranges column (for rollback)"""
    
    with app.app_context():
        print("Rolling back migration...")
        
        try:
            db.session.execute(text("""
                ALTER TABLE "case" 
                DROP COLUMN IF EXISTS vpn_ip_ranges
            """))
            
            db.session.commit()
            print("✓ Rollback completed")
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"✗ Rollback failed: {e}")
            return False


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='VPN IP Ranges field migration')
    parser.add_argument('--rollback', action='store_true', help='Rollback the migration')
    args = parser.parse_args()
    
    if args.rollback:
        success = rollback_migration()
    else:
        success = run_migration()
    
    sys.exit(0 if success else 1)

