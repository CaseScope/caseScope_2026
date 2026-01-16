#!/usr/bin/env python3
"""Backfill timestamp_utc for ambiguous source artifacts

For existing data where parsers didn't set timestamp_source_tz properly,
this script converts timestamps from case timezone to UTC.

Affected artifact types:
- sonicwall: SonicWall firewall logs (local time)
- iis: IIS web server logs (local time)
- firewall: Generic firewall/syslog (local time)
- csv_log: Generic CSV logs (local time)
- scheduled_task: Windows scheduled task XML (local time)

Usage:
    python migrations/backfill_timestamp_utc.py [--case-id N] [--dry-run]

Options:
    --case-id N    Only backfill specific case (default: all cases)
    --dry-run      Show what would be updated without making changes
"""

import os
import sys
import argparse
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config

# Artifact types that store local time (not UTC)
AMBIGUOUS_ARTIFACTS = [
    'sonicwall',
    'iis', 
    'firewall',
    'csv_log',
    'scheduled_task',
]

# UTC offset in hours to ADD to convert local time → UTC
# For US timezones that are behind UTC, we add hours
# For timezones ahead of UTC, we subtract (negative offset)
TIMEZONE_OFFSETS = {
    'UTC': 0,
    'America/New_York': 5,      # EST: UTC-5 → add 5 hours
    'America/Chicago': 6,        # CST: UTC-6 → add 6 hours
    'America/Denver': 7,         # MST: UTC-7 → add 7 hours
    'America/Los_Angeles': 8,    # PST: UTC-8 → add 8 hours
    'America/Phoenix': 7,        # MST (no DST)
    'America/Anchorage': 9,      # AKST: UTC-9
    'Pacific/Honolulu': 10,      # HST: UTC-10
    'Europe/London': 0,          # GMT: UTC+0
    'Europe/Paris': -1,          # CET: UTC+1 → subtract 1 hour
    'Europe/Berlin': -1,
    'Asia/Tokyo': -9,            # JST: UTC+9 → subtract 9 hours
    'Asia/Shanghai': -8,         # CST: UTC+8
    'Australia/Sydney': -11,     # AEDT: UTC+11
}


def get_clickhouse_client():
    """Get ClickHouse client"""
    import clickhouse_connect
    return clickhouse_connect.get_client(
        host=Config.CLICKHOUSE_HOST,
        port=Config.CLICKHOUSE_PORT,
        database=Config.CLICKHOUSE_DATABASE,
        username=Config.CLICKHOUSE_USER,
        password=Config.CLICKHOUSE_PASSWORD
    )


def get_cases_with_timezone():
    """Get all cases with their timezone settings"""
    from app import create_app
    from models.case import Case
    
    app = create_app()
    with app.app_context():
        cases = Case.query.all()
        return {c.id: c.timezone or 'UTC' for c in cases}


def wait_for_mutation(client, timeout_seconds=60):
    """Wait for the latest mutation to complete"""
    for _ in range(timeout_seconds):
        time.sleep(1)
        result = client.query('''
            SELECT is_done, parts_to_do
            FROM system.mutations
            WHERE table = 'events'
            ORDER BY create_time DESC
            LIMIT 1
        ''')
        if result.result_rows and result.result_rows[0][0]:
            return True
    return False


def backfill_case(client, case_id: int, case_tz: str, dry_run: bool = False):
    """Backfill timestamp_utc for a single case
    
    Args:
        client: ClickHouse client
        case_id: Case ID to backfill
        case_tz: Case timezone (IANA identifier)
        dry_run: If True, only show counts without updating
        
    Returns:
        Number of rows affected
    """
    # Build artifact type filter
    artifact_list = "', '".join(AMBIGUOUS_ARTIFACTS)
    
    # Count affected rows
    count_query = f"""
        SELECT count() FROM events 
        WHERE case_id = {{case_id:UInt32}}
        AND artifact_type IN ('{artifact_list}')
    """
    
    result = client.query(count_query, parameters={'case_id': case_id})
    count = result.result_rows[0][0] if result.result_rows else 0
    
    if count == 0:
        return 0
    
    # Get UTC offset for this timezone
    offset_hours = TIMEZONE_OFFSETS.get(case_tz, 0)
    
    print(f"  Case {case_id} ({case_tz}, offset {'+' if offset_hours >= 0 else ''}{offset_hours}h): {count} events")
    
    if dry_run:
        return count
    
    if offset_hours == 0:
        # Timezone is UTC or unknown, just mark timestamp_source_tz
        update_query = f"""
            ALTER TABLE events UPDATE 
                timestamp_source_tz = '{case_tz}'
            WHERE case_id = {{case_id:UInt32}}
            AND artifact_type IN ('{artifact_list}')
        """
    else:
        # Use addHours to convert local time to UTC
        # For EST (UTC-5): local 09:36 + 5 hours = 14:36 UTC
        update_query = f"""
            ALTER TABLE events UPDATE 
                timestamp_utc = addHours(timestamp, {offset_hours}),
                timestamp_source_tz = '{case_tz}'
            WHERE case_id = {{case_id:UInt32}}
            AND artifact_type IN ('{artifact_list}')
        """
    
    try:
        client.command(update_query, parameters={'case_id': case_id})
        
        # Wait for mutation to complete
        if wait_for_mutation(client):
            print(f"    ✓ Updated {count} events")
        else:
            print(f"    ⚠ Update submitted (mutation may still be running)")
        
        return count
    except Exception as e:
        print(f"    ✗ Error updating case {case_id}: {e}")
        return 0


def main():
    parser = argparse.ArgumentParser(description='Backfill timestamp_utc for ambiguous artifacts')
    parser.add_argument('--case-id', type=int, help='Specific case ID to backfill')
    parser.add_argument('--dry-run', action='store_true', help='Show counts without updating')
    args = parser.parse_args()
    
    print("=" * 60)
    print("Backfill timestamp_utc for Ambiguous Source Artifacts")
    print("=" * 60)
    print()
    print(f"Affected artifact types: {', '.join(AMBIGUOUS_ARTIFACTS)}")
    print()
    
    if args.dry_run:
        print("*** DRY RUN - No changes will be made ***")
        print()
    
    # Get cases with their timezones
    print("Loading case timezone settings...")
    cases = get_cases_with_timezone()
    print(f"Found {len(cases)} cases")
    print()
    
    # Filter to specific case if requested
    if args.case_id:
        if args.case_id not in cases:
            print(f"Error: Case {args.case_id} not found")
            sys.exit(1)
        cases = {args.case_id: cases[args.case_id]}
    
    # Get ClickHouse client
    client = get_clickhouse_client()
    
    # Process each case
    total_updated = 0
    print("Processing cases...")
    
    for case_id, case_tz in sorted(cases.items()):
        updated = backfill_case(client, case_id, case_tz, args.dry_run)
        total_updated += updated
    
    print()
    print("=" * 60)
    if args.dry_run:
        print(f"DRY RUN: Would update {total_updated} events total")
    else:
        print(f"Backfill complete: {total_updated} events updated")
    print("=" * 60)
    print()
    print("Note: DST is not handled. For events during DST, timestamps")
    print("may be off by 1 hour. Re-indexing provides full DST support.")


if __name__ == '__main__':
    main()
