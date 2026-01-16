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
        AND timestamp_source_tz = 'UTC'
    """
    
    result = client.query(count_query, parameters={'case_id': case_id})
    count = result.result_rows[0][0] if result.result_rows else 0
    
    if count == 0:
        return 0
    
    print(f"  Case {case_id} ({case_tz}): {count} events to update")
    
    if dry_run:
        return count
    
    # ClickHouse timezone conversion:
    # toDateTime(timestamp, 'source_tz') interprets timestamp as being in source_tz
    # then convert to UTC by removing timezone
    # 
    # For a timestamp that's actually in EST (stored as if UTC):
    # We need to "subtract" the EST offset to get true UTC
    # This is: toTimezone(timestamp, 'UTC') after treating it as case_tz
    
    # The trick: assume timestamp is in case_tz, convert to UTC
    # parseDateTimeBestEffort won't work here, we need direct conversion
    #
    # ClickHouse approach:
    # 1. Treat timestamp as if it's in case_tz: toDateTime(timestamp, case_tz)
    # 2. Convert to UTC: toTimezone(..., 'UTC')
    # 3. Store as DateTime64(3) without timezone
    
    update_query = f"""
        ALTER TABLE events UPDATE 
            timestamp_utc = toDateTime64(
                toTimezone(
                    toDateTime(timestamp, '{case_tz}'),
                    'UTC'
                ),
                3
            ),
            timestamp_source_tz = '{case_tz}'
        WHERE case_id = {{case_id:UInt32}}
        AND artifact_type IN ('{artifact_list}')
        AND timestamp_source_tz = 'UTC'
    """
    
    try:
        client.command(update_query, parameters={'case_id': case_id})
        print(f"    ✓ Updated {count} events")
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


if __name__ == '__main__':
    main()
