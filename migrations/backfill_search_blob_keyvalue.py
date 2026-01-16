#!/usr/bin/env python3
"""Backfill search_blob with key:value pairs for EVTX events

This migration updates existing EVTX events to include EventData fields
in a key:value format within search_blob, enabling searches like:
- KeyLength:0
- LogonType:3
- TargetUserName:admin

The migration:
1. Reads raw_json from each EVTX event
2. Extracts EventData fields
3. Appends key:value pairs to existing search_blob
4. Updates the record in ClickHouse

Usage:
    python backfill_search_blob_keyvalue.py [--case-id CASE_ID] [--dry-run] [--batch-size N]

Options:
    --case-id       Only process a specific case (default: all cases)
    --dry-run       Show what would be updated without making changes
    --batch-size    Number of records to process per batch (default: 10000)
"""
import os
import sys
import json
import argparse
import logging
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.clickhouse import get_client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def extract_event_data_kv(raw_json: str) -> str:
    """Extract EventData key:value pairs from raw_json
    
    Args:
        raw_json: JSON string containing event data
        
    Returns:
        Space-separated key:value pairs string
    """
    if not raw_json:
        return ''
    
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return ''
    
    # EventData may be directly in raw_json (EvtxECmd format)
    event_data = data.get('EventData', {})
    
    if not event_data:
        return ''
    
    kv_parts = []
    for key, value in event_data.items():
        if value is not None and str(value).strip():
            # Clean value - remove newlines, limit length
            clean_value = str(value).replace('\n', ' ').replace('\r', '')[:200]
            kv_parts.append(f"{key}:{clean_value}")
    
    return ' '.join(kv_parts)


def backfill_case(client, case_id: int, dry_run: bool = False, batch_size: int = 10000) -> dict:
    """Backfill search_blob for a single case
    
    Args:
        client: ClickHouse client
        case_id: Case ID to process
        dry_run: If True, don't make changes
        batch_size: Records per batch
        
    Returns:
        Dict with statistics
    """
    stats = {
        'total': 0,
        'updated': 0,
        'skipped': 0,
        'errors': 0,
    }
    
    # Count EVTX events in this case
    count_result = client.command(
        "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND artifact_type = 'evtx'",
        parameters={'case_id': case_id}
    )
    total = int(count_result)
    stats['total'] = total
    
    if total == 0:
        logger.info(f"Case {case_id}: No EVTX events to process")
        return stats
    
    logger.info(f"Case {case_id}: Processing {total:,} EVTX events...")
    
    # Process in batches using offset/limit
    offset = 0
    batch_num = 0
    
    while offset < total:
        batch_num += 1
        
        # Fetch batch of events
        query = """
            SELECT id, search_blob, raw_json
            FROM events
            WHERE case_id = {case_id:UInt32} AND artifact_type = 'evtx'
            ORDER BY id
            LIMIT {limit:UInt32} OFFSET {offset:UInt32}
        """
        
        result = client.query(
            query,
            parameters={
                'case_id': case_id,
                'limit': batch_size,
                'offset': offset,
            }
        )
        
        rows = result.result_rows
        if not rows:
            break
        
        updates = []
        
        for row in rows:
            event_id, current_blob, raw_json = row
            
            # Check if already has key:value pairs (contains pattern like "FieldName:value")
            # Simple heuristic: if blob contains patterns like "KeyLength:" or "LogonType:"
            if ':' in current_blob and any(
                f"{field}:" in current_blob 
                for field in ['KeyLength', 'LogonType', 'TargetUserName', 'SubjectUserName', 'ProcessId']
            ):
                stats['skipped'] += 1
                continue
            
            # Extract key:value pairs from raw_json
            kv_pairs = extract_event_data_kv(raw_json)
            
            if not kv_pairs:
                stats['skipped'] += 1
                continue
            
            # Build new search_blob
            new_blob = f"{current_blob} {kv_pairs}" if current_blob else kv_pairs
            
            updates.append({
                'id': event_id,
                'search_blob': new_blob,
            })
        
        if updates and not dry_run:
            # ClickHouse doesn't support UPDATE directly in the traditional sense
            # We need to use ALTER TABLE ... UPDATE for MergeTree tables
            # But for efficiency, we'll use a temporary table approach
            
            for update in updates:
                try:
                    # Use ALTER TABLE UPDATE (works on MergeTree)
                    client.command(
                        """
                        ALTER TABLE events 
                        UPDATE search_blob = {new_blob:String}
                        WHERE id = {event_id:UUID}
                        """,
                        parameters={
                            'event_id': update['id'],
                            'new_blob': update['search_blob'],
                        }
                    )
                    stats['updated'] += 1
                except Exception as e:
                    logger.error(f"Error updating event {update['id']}: {e}")
                    stats['errors'] += 1
        elif updates and dry_run:
            stats['updated'] += len(updates)
            # Show sample in dry-run mode
            if batch_num == 1 and updates:
                sample = updates[0]
                logger.info(f"  Sample update: ID={sample['id']}")
                logger.info(f"    New blob (first 200 chars): {sample['search_blob'][:200]}...")
        
        offset += batch_size
        
        # Progress update
        progress = min(offset, total)
        logger.info(f"  Case {case_id}: Processed {progress:,}/{total:,} ({100*progress/total:.1f}%)")
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description='Backfill search_blob with key:value pairs for EVTX events'
    )
    parser.add_argument(
        '--case-id', type=int, default=None,
        help='Only process a specific case (default: all cases)'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Show what would be updated without making changes'
    )
    parser.add_argument(
        '--batch-size', type=int, default=10000,
        help='Number of records to process per batch (default: 10000)'
    )
    
    args = parser.parse_args()
    
    if args.dry_run:
        logger.info("=== DRY RUN MODE - No changes will be made ===")
    
    logger.info("Connecting to ClickHouse...")
    client = get_client()
    
    # Get list of cases with EVTX events
    if args.case_id:
        case_ids = [args.case_id]
        logger.info(f"Processing case {args.case_id} only")
    else:
        result = client.query(
            "SELECT DISTINCT case_id FROM events WHERE artifact_type = 'evtx' ORDER BY case_id"
        )
        case_ids = [row[0] for row in result.result_rows]
        logger.info(f"Found {len(case_ids)} cases with EVTX events")
    
    if not case_ids:
        logger.info("No cases to process")
        return
    
    # Process each case
    total_stats = {'total': 0, 'updated': 0, 'skipped': 0, 'errors': 0}
    
    for case_id in case_ids:
        stats = backfill_case(client, case_id, args.dry_run, args.batch_size)
        
        for key in total_stats:
            total_stats[key] += stats[key]
    
    # Final summary
    logger.info("=" * 50)
    logger.info("BACKFILL COMPLETE")
    logger.info(f"  Total events processed: {total_stats['total']:,}")
    logger.info(f"  Updated: {total_stats['updated']:,}")
    logger.info(f"  Skipped (already had kv pairs or no EventData): {total_stats['skipped']:,}")
    logger.info(f"  Errors: {total_stats['errors']:,}")
    
    if args.dry_run:
        logger.info("\n*** DRY RUN - No actual changes were made ***")
        logger.info("Run without --dry-run to apply changes")


if __name__ == '__main__':
    main()
