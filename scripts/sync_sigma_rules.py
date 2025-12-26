#!/usr/bin/env python3
"""
Initial SIGMA rules sync script
Run this once to populate the database with existing SIGMA rules
"""

import sys
import os

# Add app directory to path
sys.path.insert(0, '/opt/casescope/app')

from main import app, db
from utils.sigma_utils import sync_sigma_rules_to_database

def main():
    """Sync SIGMA rules to database"""
    with app.app_context():
        print("Starting SIGMA rules sync...")
        print("This may take 1-2 minutes...")
        
        stats = sync_sigma_rules_to_database(db)
        
        print(f"\n✓ Sync complete!")
        print(f"  Added: {stats['added']}")
        print(f"  Updated: {stats['updated']}")
        print(f"  Skipped: {stats['skipped']}")

if __name__ == '__main__':
    main()

