#!/usr/bin/env python3
"""
Database Migration: Add Archive Fields to Case Table
Version: 1.18.0
Purpose: Enable case archiving feature
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_migration():
    """Add archive-related fields to case table and create app_settings table"""
    from main import app, db
    from models import Case
    
    print("\n" + "="*80)
    print("ARCHIVE CASE MIGRATION - v1.18.0")
    print("="*80)
    
    with app.app_context():
        # Get database connection
        connection = db.engine.raw_connection()
        cursor = connection.cursor()
        
        try:
            # ========================================
            # Step 1: Add archive fields to case table
            # ========================================
            print("\n📋 Step 1: Adding archive fields to 'case' table...")
            
            archive_fields = [
                ('archive_path', 'VARCHAR(1000)', 'Full path to archive ZIP file'),
                ('archived_at', 'TIMESTAMP', 'When case was archived'),
                ('archived_by', 'INTEGER REFERENCES "user"(id)', 'User who archived the case'),
                ('restored_at', 'TIMESTAMP', 'When case was last restored (audit trail)')
            ]
            
            for field_name, field_type, description in archive_fields:
                try:
                    # Check if column already exists
                    cursor.execute(f'''
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name = 'case' 
                        AND column_name = '{field_name}';
                    ''')
                    
                    if cursor.fetchone():
                        print(f"   ⚠️  Column '{field_name}' already exists, skipping")
                    else:
                        cursor.execute(f'ALTER TABLE "case" ADD COLUMN {field_name} {field_type};')
                        connection.commit()
                        print(f"   ✅ Added column: {field_name} ({description})")
                        
                except Exception as e:
                    print(f"   ❌ Error adding {field_name}: {e}")
                    connection.rollback()
                    # Continue with other fields
            
            # ========================================
            # Step 2: Insert default archive path setting (uses existing system_settings table)
            # ========================================
            print("\n📋 Step 2: Adding default archive path setting to 'system_settings' table...")
            
            cursor.execute('''
                INSERT INTO system_settings (setting_key, setting_value, description)
                VALUES ('archive_root_path', NULL, 'Root path for archived case files (e.g., /archive or /mnt/archive_drive). Must be writable by casescope user.')
                ON CONFLICT (setting_key) DO NOTHING;
            ''')
            connection.commit()
            print("   ✅ Added 'archive_root_path' setting (default: NULL)")
            
            # ========================================
            # Step 3: Verify migration
            # ========================================
            print("\n📋 Step 3: Verifying migration...")
            
            # Check case table columns
            cursor.execute('''
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'case' 
                AND column_name IN ('archive_path', 'archived_at', 'archived_by', 'restored_at')
                ORDER BY column_name;
            ''')
            case_columns = [row[0] for row in cursor.fetchall()]
            
            if len(case_columns) == 4:
                print(f"   ✅ All 4 archive fields present in 'case' table: {', '.join(case_columns)}")
            else:
                print(f"   ⚠️  Only {len(case_columns)} archive fields found: {', '.join(case_columns)}")
            
            # Check system_settings table
            cursor.execute('''
                SELECT COUNT(*) FROM system_settings WHERE setting_key = 'archive_root_path';
            ''')
            setting_count = cursor.fetchone()[0]
            
            if setting_count > 0:
                print("   ✅ Archive path setting exists in 'system_settings' table")
            else:
                print("   ⚠️  Archive path setting not found")
            
            # ========================================
            # Summary
            # ========================================
            print("\n" + "="*80)
            print("✅ MIGRATION COMPLETE")
            print("="*80)
            print("\nNext Steps:")
            print("1. Configure archive path in System Settings")
            print("2. Test archive/restore functionality")
            print("3. Update version.json to v1.18.0")
            print("\n")
            
        except Exception as e:
            print(f"\n❌ MIGRATION FAILED: {e}")
            connection.rollback()
            raise
        
        finally:
            cursor.close()
            connection.close()


if __name__ == '__main__':
    try:
        run_migration()
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)

