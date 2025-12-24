#!/usr/bin/env python3
"""
Database Migration: Case Status Workflow Enhancement
Adds improved case status tracking with automatic workflow transitions

Changes:
- Updates existing 'active' status to 'New' for unassigned cases
- Updates existing 'active' status to 'Assigned' for assigned cases
- Updates existing 'closed' status to 'Completed'
- Preserves any custom status values

Run: python migrations/add_case_status_workflow.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db, Case
from sqlalchemy import text


def migrate_case_statuses():
    """Migrate existing case statuses to new workflow values"""
    with app.app_context():
        print("=" * 70)
        print("Case Status Workflow Migration")
        print("=" * 70)
        print()
        
        # Get current status distribution
        print("Current Status Distribution:")
        print("-" * 70)
        result = db.session.execute(text("""
            SELECT status, COUNT(*) as count 
            FROM "case" 
            GROUP BY status 
            ORDER BY count DESC
        """))
        
        status_counts = {}
        for row in result:
            status_counts[row[0]] = row[1]
            print(f"  {row[0]}: {row[1]} case(s)")
        
        print()
        
        if not status_counts:
            print("✓ No cases found. Migration not needed.")
            return
        
        # Confirm migration
        print("Migration Plan:")
        print("-" * 70)
        
        # Count cases that will be updated
        active_unassigned = db.session.query(Case).filter(
            Case.status == 'active',
            Case.assigned_to.is_(None)
        ).count()
        
        active_assigned = db.session.query(Case).filter(
            Case.status == 'active',
            Case.assigned_to.isnot(None)
        ).count()
        
        closed_cases = db.session.query(Case).filter(
            Case.status == 'closed'
        ).count()
        
        if active_unassigned > 0:
            print(f"  • 'active' (unassigned) → 'New': {active_unassigned} case(s)")
        if active_assigned > 0:
            print(f"  • 'active' (assigned) → 'Assigned': {active_assigned} case(s)")
        if closed_cases > 0:
            print(f"  • 'closed' → 'Completed': {closed_cases} case(s)")
        
        total_updates = active_unassigned + active_assigned + closed_cases
        
        if total_updates == 0:
            print("✓ No cases need migration.")
            return
        
        print()
        print(f"Total cases to update: {total_updates}")
        print()
        
        response = input("Proceed with migration? (yes/no): ").strip().lower()
        
        if response != 'yes':
            print("Migration cancelled.")
            return
        
        print()
        print("Applying Migration:")
        print("-" * 70)
        
        # Migrate 'active' unassigned → 'New'
        if active_unassigned > 0:
            db.session.execute(text("""
                UPDATE "case" 
                SET status = 'New' 
                WHERE status = 'active' 
                  AND assigned_to IS NULL
            """))
            print(f"  ✓ Updated {active_unassigned} unassigned 'active' case(s) to 'New'")
        
        # Migrate 'active' assigned → 'Assigned'
        if active_assigned > 0:
            db.session.execute(text("""
                UPDATE "case" 
                SET status = 'Assigned' 
                WHERE status = 'active' 
                  AND assigned_to IS NOT NULL
            """))
            print(f"  ✓ Updated {active_assigned} assigned 'active' case(s) to 'Assigned'")
        
        # Migrate 'closed' → 'Completed'
        if closed_cases > 0:
            db.session.execute(text("""
                UPDATE "case" 
                SET status = 'Completed' 
                WHERE status = 'closed'
            """))
            print(f"  ✓ Updated {closed_cases} 'closed' case(s) to 'Completed'")
        
        db.session.commit()
        
        print()
        print("=" * 70)
        print("Migration completed successfully!")
        print("=" * 70)
        print()
        
        # Show new distribution
        print("New Status Distribution:")
        print("-" * 70)
        result = db.session.execute(text("""
            SELECT status, COUNT(*) as count 
            FROM "case" 
            GROUP BY status 
            ORDER BY count DESC
        """))
        
        for row in result:
            print(f"  {row[0]}: {row[1]} case(s)")
        
        print()


if __name__ == '__main__':
    try:
        migrate_case_statuses()
    except KeyboardInterrupt:
        print("\n\nMigration cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nERROR: Migration failed!")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

