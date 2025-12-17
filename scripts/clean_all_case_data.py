#!/opt/casescope/venv/bin/python3
"""
CaseScope Complete Data Cleanup Script
Removes ALL case data from PostgreSQL, OpenSearch, and disk storage

⚠️  WARNING: This is DESTRUCTIVE and CANNOT be undone!
    - Deletes all cases, files, events from PostgreSQL
    - Deletes all OpenSearch indices (case_*)
    - Removes all uploaded files from disk
    - Removes all staging files from disk
    - Removes all archived case files from disk

Usage:
    sudo /opt/casescope/scripts/clean_all_case_data.py
"""

import sys
import os
import shutil
from pathlib import Path

# Add app directory to path
sys.path.insert(0, '/opt/casescope/app')


def confirm_action():
    """Get user confirmation for destructive action"""
    print("\n" + "=" * 80)
    print("⚠️  COMPLETE CASE DATA CLEANUP")
    print("=" * 80)
    print("\nThis will DELETE ALL:")
    print("  ✗ Cases from PostgreSQL database")
    print("  ✗ Files, Events, SIGMA violations, IOCs from database")
    print("  ✗ Event status records, timeline data, audit logs")
    print("  ✗ All OpenSearch indices (case_*)")
    print("  ✗ All uploaded files from /opt/casescope/uploads/")
    print("  ✗ All staging files from /opt/casescope/staging/")
    print("  ✗ All archived files from /opt/casescope/archive/")
    print("  ✗ All evidence files from /opt/casescope/evidence/")
    print("\n⚠️  THIS CANNOT BE UNDONE!\n")
    
    response = input("Type 'DELETE ALL DATA' to confirm: ")
    return response == "DELETE ALL DATA"


def clean_postgresql():
    """Clean all case-related data from PostgreSQL"""
    from main import app, db
    from models import (
        Case, CaseFile, SigmaViolation, IOC, IOCMatch, EventStatus,
        CaseTimeline, AuditLog, CaseLock, EvidenceFile, AITriageSearch, KnownUser,
        System, SkippedFile, SearchHistory, TimelineTag, TagExclusion,
        AIReport, AIReportChat, ReindexProgress
    )
    
    print("\n" + "=" * 80)
    print("🗄️  CLEANING POSTGRESQL DATABASE")
    print("=" * 80)
    
    with app.app_context():
        try:
            # Count records before deletion
            cases_count = db.session.query(Case).count()
            files_count = db.session.query(CaseFile).count()
            violations_count = db.session.query(SigmaViolation).count()
            iocs_count = db.session.query(IOC).count()
            ioc_matches_count = db.session.query(IOCMatch).count()
            event_status_count = db.session.query(EventStatus).count()
            timeline_count = db.session.query(CaseTimeline).count()
            locks_count = db.session.query(CaseLock).count()
            evidence_count = db.session.query(EvidenceFile).count()
            triage_count = db.session.query(AITriageSearch).count()
            known_users_count = db.session.query(KnownUser).count()
            systems_count = db.session.query(System).count()
            skipped_count = db.session.query(SkippedFile).count()
            search_history_count = db.session.query(SearchHistory).count()
            timeline_tags_count = db.session.query(TimelineTag).count()
            tag_exclusions_count = db.session.query(TagExclusion).count()
            ai_reports_count = db.session.query(AIReport).count()
            ai_chat_count = db.session.query(AIReportChat).count()
            reindex_count = db.session.query(ReindexProgress).count()
            
            print(f"\n📊 Current database state:")
            print(f"   • Cases: {cases_count:,}")
            print(f"   • Files: {files_count:,}")
            print(f"   • SIGMA Violations: {violations_count:,}")
            print(f"   • IOCs: {iocs_count:,}")
            print(f"   • IOC Matches: {ioc_matches_count:,}")
            print(f"   • Event Status Records: {event_status_count:,}")
            print(f"   • Timeline Entries: {timeline_count:,}")
            print(f"   • Case Locks: {locks_count:,}")
            print(f"   • Evidence Files: {evidence_count:,}")
            print(f"   • AI Triage Searches: {triage_count:,}")
            print(f"   • Known Users: {known_users_count:,}")
            print(f"   • Systems: {systems_count:,}")
            print(f"   • Skipped Files: {skipped_count:,}")
            print(f"   • Search History: {search_history_count:,}")
            print(f"   • Timeline Tags: {timeline_tags_count:,}")
            print(f"   • Tag Exclusions: {tag_exclusions_count:,}")
            print(f"   • AI Reports: {ai_reports_count:,}")
            print(f"   • AI Report Chats: {ai_chat_count:,}")
            print(f"   • Reindex Progress: {reindex_count:,}")
            
            print("\n🗑️  Deleting records...")
            
            # Delete in proper order (child tables first to avoid FK constraint issues)
            deleted_counts = {}
            
            # AI Report Chat (depends on AIReport)
            deleted_counts['ai_chat'] = db.session.query(AIReportChat).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['ai_chat']:,} AI report chat messages")
            
            # AI Reports (depends on Case)
            deleted_counts['ai_reports'] = db.session.query(AIReport).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['ai_reports']:,} AI reports")
            
            # IOC Matches (depends on IOC, CaseFile, Case)
            deleted_counts['ioc_matches'] = db.session.query(IOCMatch).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['ioc_matches']:,} IOC matches")
            
            # Timeline Tags (depends on Case)
            deleted_counts['timeline_tags'] = db.session.query(TimelineTag).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['timeline_tags']:,} timeline tags")
            
            # Tag Exclusions (depends on Case)
            deleted_counts['tag_exclusions'] = db.session.query(TagExclusion).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['tag_exclusions']:,} tag exclusions")
            
            # Search History (depends on Case)
            deleted_counts['search_history'] = db.session.query(SearchHistory).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['search_history']:,} search history entries")
            
            # Systems (depends on Case)
            deleted_counts['systems'] = db.session.query(System).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['systems']:,} systems")
            
            # Skipped Files (depends on Case)
            deleted_counts['skipped_files'] = db.session.query(SkippedFile).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['skipped_files']:,} skipped files")
            
            # Reindex Progress (depends on Case)
            deleted_counts['reindex_progress'] = db.session.query(ReindexProgress).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['reindex_progress']:,} reindex progress records")
            
            # Evidence files
            deleted_counts['evidence_files'] = db.session.query(EvidenceFile).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['evidence_files']:,} evidence file records")
            
            # Event status records
            deleted_counts['event_status'] = db.session.query(EventStatus).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['event_status']:,} event status records")
            
            # SIGMA violations
            deleted_counts['sigma_violations'] = db.session.query(SigmaViolation).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['sigma_violations']:,} SIGMA violations")
            
            # IOCs (depends on cases)
            deleted_counts['iocs'] = db.session.query(IOC).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['iocs']:,} IOCs")
            
            # Timeline entries
            deleted_counts['timeline'] = db.session.query(CaseTimeline).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['timeline']:,} timeline entries")
            
            # Case locks
            deleted_counts['locks'] = db.session.query(CaseLock).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['locks']:,} case locks")
            
            # AI Triage Searches (must be before case files)
            deleted_counts['ai_triage'] = db.session.query(AITriageSearch).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['ai_triage']:,} AI triage searches")
            
            # Known Users (must be before cases)
            deleted_counts['known_users'] = db.session.query(KnownUser).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['known_users']:,} known users")
            
            # Case files
            deleted_counts['files'] = db.session.query(CaseFile).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['files']:,} case files")
            
            # Cases (must be last)
            deleted_counts['cases'] = db.session.query(Case).delete()
            db.session.commit()
            print(f"   ✓ Deleted {deleted_counts['cases']:,} cases")
            
            # Clean up audit logs related to cases (optional - keeps system audit trail)
            # Uncomment if you want to delete ALL audit logs
            # deleted_counts['audit_logs'] = db.session.query(AuditLog).delete()
            # db.session.commit()
            # print(f"   ✓ Deleted {deleted_counts['audit_logs']:,} audit logs")
            
            print(f"\n✅ PostgreSQL cleanup complete!")
            return True
            
        except Exception as e:
            print(f"\n❌ Error cleaning PostgreSQL: {e}")
            db.session.rollback()
            return False


def clean_opensearch():
    """Delete all OpenSearch case indices"""
    from opensearchpy import OpenSearch
    
    print("\n" + "=" * 80)
    print("🔍 CLEANING OPENSEARCH INDICES")
    print("=" * 80)
    
    try:
        # Connect to OpenSearch
        client = OpenSearch(
            hosts=[{"host": "localhost", "port": 9200}],
            http_auth=None,
            use_ssl=False
        )
        
        # Get all indices
        all_indices = client.indices.get_alias(index="*")
        case_indices = [idx for idx in all_indices.keys() if idx.startswith('case_')]
        
        print(f"\n📊 Found {len(case_indices)} case indices:")
        for idx in case_indices:
            # Get document count
            try:
                count = client.count(index=idx)['count']
                print(f"   • {idx}: {count:,} documents")
            except:
                print(f"   • {idx}: (count unavailable)")
        
        if not case_indices:
            print("   • No case indices found")
            return True
        
        print("\n🗑️  Deleting indices...")
        for idx in case_indices:
            try:
                client.indices.delete(index=idx)
                print(f"   ✓ Deleted index: {idx}")
            except Exception as e:
                print(f"   ✗ Failed to delete {idx}: {e}")
        
        print(f"\n✅ OpenSearch cleanup complete!")
        return True
        
    except Exception as e:
        print(f"\n❌ Error cleaning OpenSearch: {e}")
        return False


def clean_disk_storage():
    """Remove all uploaded, staged, and archived files from disk"""
    print("\n" + "=" * 80)
    print("💾 CLEANING DISK STORAGE")
    print("=" * 80)
    
    paths_to_clean = [
        '/opt/casescope/uploads',
        '/opt/casescope/staging',
        '/opt/casescope/archive',
        '/opt/casescope/evidence',
        '/opt/casescope/local_uploads',
        '/opt/casescope/evidence_uploads',
        '/opt/casescope/bulk_import'
    ]
    
    total_size_freed = 0
    
    for path_str in paths_to_clean:
        path = Path(path_str)
        
        if not path.exists():
            print(f"\n📁 {path_str}: (does not exist)")
            continue
        
        # Calculate size before deletion
        try:
            size = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
            size_gb = size / (1024**3)
            file_count = sum(1 for f in path.rglob('*') if f.is_file())
            
            print(f"\n📁 {path_str}:")
            print(f"   • Files: {file_count:,}")
            print(f"   • Size: {size_gb:.2f} GB")
            
            # Remove all contents but keep the directory
            for item in path.iterdir():
                try:
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
                except Exception as e:
                    print(f"   ✗ Failed to delete {item.name}: {e}")
            
            print(f"   ✓ Cleaned (freed {size_gb:.2f} GB)")
            total_size_freed += size
            
        except Exception as e:
            print(f"   ✗ Error: {e}")
    
    total_gb = total_size_freed / (1024**3)
    print(f"\n✅ Disk cleanup complete! Freed {total_gb:.2f} GB")
    return True


def main():
    """Main cleanup function"""
    print("\n")
    print("╔════════════════════════════════════════════════════════════════════════════╗")
    print("║         CaseScope Complete Data Cleanup Script                            ║")
    print("║         ⚠️  DESTRUCTIVE OPERATION - ALL DATA WILL BE DELETED  ⚠️          ║")
    print("╚════════════════════════════════════════════════════════════════════════════╝")
    
    # Get confirmation
    if not confirm_action():
        print("\n❌ Cleanup cancelled by user")
        return 1
    
    print("\n🚀 Starting cleanup process...\n")
    
    # Step 1: Clean PostgreSQL
    if not clean_postgresql():
        print("\n❌ PostgreSQL cleanup failed! Aborting...")
        return 1
    
    # Step 2: Clean OpenSearch
    if not clean_opensearch():
        print("\n⚠️  OpenSearch cleanup failed, but continuing...")
    
    # Step 3: Clean disk storage
    if not clean_disk_storage():
        print("\n⚠️  Disk cleanup failed, but continuing...")
    
    print("\n" + "=" * 80)
    print("✅ CLEANUP COMPLETE!")
    print("=" * 80)
    print("\nYour CaseScope instance is now clean and ready for fresh data.")
    print("You can now:")
    print("  1. Create new cases")
    print("  2. Upload new files")
    print("  3. Start fresh investigations")
    print()
    
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n❌ Cleanup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

