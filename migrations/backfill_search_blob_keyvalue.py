#!/usr/bin/env python3
"""Backfill search_blob with key:value pairs for EVTX events

This migration updates existing EVTX events to include EventData fields
in a key:value format within search_blob, enabling searches like:
- KeyLength:0
- LogonType:3
- TargetUserName:admin

The migration uses ClickHouse's ALTER TABLE UPDATE mutation to efficiently
update all EVTX events in a single pass per case.

Usage:
    python backfill_search_blob_keyvalue.py [--case-id CASE_ID] [--dry-run]

Options:
    --case-id       Only process a specific case (default: all cases)
    --dry-run       Show what would be updated without making changes
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


def extract_kv_pairs_sql():
    """Generate ClickHouse SQL expression to extract key:value pairs from raw_json
    
    This function generates SQL that:
    1. Parses raw_json to extract EventData object
    2. Builds key:value pairs from EventData fields
    3. Appends them to existing search_blob
    """
    # ClickHouse expression to extract EventData and build key:value pairs
    # Using JSONExtract functions available in ClickHouse
    return """
        concat(
            search_blob,
            ' ',
            -- Extract common EventData fields and format as key:value
            if(JSONExtractString(raw_json, 'EventData', 'TargetUserName') != '', 
               concat('TargetUserName:', JSONExtractString(raw_json, 'EventData', 'TargetUserName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'SubjectUserName') != '', 
               concat('SubjectUserName:', JSONExtractString(raw_json, 'EventData', 'SubjectUserName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'TargetDomainName') != '', 
               concat('TargetDomainName:', JSONExtractString(raw_json, 'EventData', 'TargetDomainName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'LogonType') != '', 
               concat('LogonType:', JSONExtractString(raw_json, 'EventData', 'LogonType'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'KeyLength') != '', 
               concat('KeyLength:', JSONExtractString(raw_json, 'EventData', 'KeyLength'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'AuthenticationPackageName') != '', 
               concat('AuthenticationPackageName:', JSONExtractString(raw_json, 'EventData', 'AuthenticationPackageName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'LogonProcessName') != '', 
               concat('LogonProcessName:', JSONExtractString(raw_json, 'EventData', 'LogonProcessName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'WorkstationName') != '', 
               concat('WorkstationName:', JSONExtractString(raw_json, 'EventData', 'WorkstationName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'IpAddress') != '', 
               concat('IpAddress:', JSONExtractString(raw_json, 'EventData', 'IpAddress'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'IpPort') != '', 
               concat('IpPort:', JSONExtractString(raw_json, 'EventData', 'IpPort'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'ProcessName') != '', 
               concat('ProcessName:', JSONExtractString(raw_json, 'EventData', 'ProcessName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'NewProcessName') != '', 
               concat('NewProcessName:', JSONExtractString(raw_json, 'EventData', 'NewProcessName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'CommandLine') != '', 
               concat('CommandLine:', substring(JSONExtractString(raw_json, 'EventData', 'CommandLine'), 1, 200), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'ParentProcessName') != '', 
               concat('ParentProcessName:', JSONExtractString(raw_json, 'EventData', 'ParentProcessName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'TargetFilename') != '', 
               concat('TargetFilename:', JSONExtractString(raw_json, 'EventData', 'TargetFilename'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'TargetUserSid') != '', 
               concat('TargetUserSid:', JSONExtractString(raw_json, 'EventData', 'TargetUserSid'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'SubjectUserSid') != '', 
               concat('SubjectUserSid:', JSONExtractString(raw_json, 'EventData', 'SubjectUserSid'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'Status') != '', 
               concat('Status:', JSONExtractString(raw_json, 'EventData', 'Status'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'SubStatus') != '', 
               concat('SubStatus:', JSONExtractString(raw_json, 'EventData', 'SubStatus'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'FailureReason') != '', 
               concat('FailureReason:', JSONExtractString(raw_json, 'EventData', 'FailureReason'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'ElevatedToken') != '', 
               concat('ElevatedToken:', JSONExtractString(raw_json, 'EventData', 'ElevatedToken'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'TargetLogonId') != '', 
               concat('TargetLogonId:', JSONExtractString(raw_json, 'EventData', 'TargetLogonId'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'SubjectLogonId') != '', 
               concat('SubjectLogonId:', JSONExtractString(raw_json, 'EventData', 'SubjectLogonId'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'ServiceName') != '', 
               concat('ServiceName:', JSONExtractString(raw_json, 'EventData', 'ServiceName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'ServiceFileName') != '', 
               concat('ServiceFileName:', JSONExtractString(raw_json, 'EventData', 'ServiceFileName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'TaskName') != '', 
               concat('TaskName:', JSONExtractString(raw_json, 'EventData', 'TaskName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'ObjectName') != '', 
               concat('ObjectName:', JSONExtractString(raw_json, 'EventData', 'ObjectName'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'ObjectType') != '', 
               concat('ObjectType:', JSONExtractString(raw_json, 'EventData', 'ObjectType'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'AccessMask') != '', 
               concat('AccessMask:', JSONExtractString(raw_json, 'EventData', 'AccessMask'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'PrivilegeList') != '', 
               concat('PrivilegeList:', JSONExtractString(raw_json, 'EventData', 'PrivilegeList'), ' '), ''),
            if(JSONExtractString(raw_json, 'EventData', 'Hashes') != '', 
               concat('Hashes:', JSONExtractString(raw_json, 'EventData', 'Hashes'), ' '), '')
        )
    """


def backfill_case(client, case_id: int, dry_run: bool = False) -> dict:
    """Backfill search_blob for a single case using ClickHouse mutation
    
    Args:
        client: ClickHouse client
        case_id: Case ID to process
        dry_run: If True, don't make changes
        
    Returns:
        Dict with statistics
    """
    stats = {
        'total': 0,
        'mutation_submitted': False,
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
    
    logger.info(f"Case {case_id}: {total:,} EVTX events to update")
    
    # Check if already has key:value pairs (sample check)
    sample_result = client.query(
        """
        SELECT search_blob FROM events 
        WHERE case_id = {case_id:UInt32} AND artifact_type = 'evtx'
        LIMIT 5
        """,
        parameters={'case_id': case_id}
    )
    
    sample_has_kv = False
    for row in sample_result.result_rows:
        blob = row[0] or ''
        if any(f"{field}:" in blob for field in ['KeyLength', 'LogonType', 'TargetUserName']):
            sample_has_kv = True
            break
    
    if sample_has_kv:
        logger.info(f"Case {case_id}: Sample events already have key:value pairs, skipping")
        return stats
    
    if dry_run:
        logger.info(f"Case {case_id}: Would submit mutation to update {total:,} events")
        
        # Show sample of what would be updated
        sample_query = """
            SELECT 
                event_id,
                substring(search_blob, 1, 100) as current_blob_preview,
                JSONExtractString(raw_json, 'EventData', 'LogonType') as logon_type,
                JSONExtractString(raw_json, 'EventData', 'KeyLength') as key_length
            FROM events 
            WHERE case_id = {case_id:UInt32} 
                AND artifact_type = 'evtx'
                AND JSONHas(raw_json, 'EventData')
            LIMIT 3
        """
        sample = client.query(sample_query, parameters={'case_id': case_id})
        for row in sample.result_rows:
            event_id, blob_preview, logon_type, key_length = row
            logger.info(f"  Sample Event {event_id}:")
            logger.info(f"    Current: {blob_preview}...")
            logger.info(f"    Would add: LogonType:{logon_type} KeyLength:{key_length}")
        
        stats['mutation_submitted'] = True
        return stats
    
    # Submit the mutation
    kv_expression = extract_kv_pairs_sql()
    
    mutation_query = f"""
        ALTER TABLE events
        UPDATE search_blob = {kv_expression}
        WHERE case_id = {{case_id:UInt32}} 
            AND artifact_type = 'evtx'
            AND JSONHas(raw_json, 'EventData')
    """
    
    logger.info(f"Case {case_id}: Submitting mutation...")
    
    try:
        client.command(mutation_query, parameters={'case_id': case_id})
        stats['mutation_submitted'] = True
        logger.info(f"Case {case_id}: Mutation submitted successfully")
        logger.info(f"Case {case_id}: Mutation will run in background. Monitor with:")
        logger.info(f"  SELECT * FROM system.mutations WHERE table = 'events' AND is_done = 0")
    except Exception as e:
        logger.error(f"Case {case_id}: Mutation failed: {e}")
        raise
    
    return stats


def check_mutation_progress(client):
    """Check progress of running mutations"""
    result = client.query("""
        SELECT 
            mutation_id,
            command,
            create_time,
            parts_to_do,
            is_done
        FROM system.mutations
        WHERE table = 'events' AND database = 'casescope'
        ORDER BY create_time DESC
        LIMIT 10
    """)
    
    if result.result_rows:
        logger.info("Recent mutations:")
        for row in result.result_rows:
            mutation_id, command, create_time, parts_to_do, is_done = row
            status = "DONE" if is_done else f"PENDING ({parts_to_do} parts remaining)"
            logger.info(f"  {mutation_id}: {status}")
            logger.info(f"    Created: {create_time}")
    else:
        logger.info("No recent mutations found")


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
        '--check-progress', action='store_true',
        help='Check progress of running mutations'
    )
    
    args = parser.parse_args()
    
    logger.info("Connecting to ClickHouse...")
    client = get_client()
    
    if args.check_progress:
        check_mutation_progress(client)
        return
    
    if args.dry_run:
        logger.info("=== DRY RUN MODE - No changes will be made ===")
    
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
    total_events = 0
    mutations_submitted = 0
    
    for case_id in case_ids:
        stats = backfill_case(client, case_id, args.dry_run)
        total_events += stats['total']
        if stats['mutation_submitted']:
            mutations_submitted += 1
    
    # Final summary
    logger.info("=" * 50)
    logger.info("BACKFILL COMPLETE")
    logger.info(f"  Cases processed: {len(case_ids)}")
    logger.info(f"  Total EVTX events: {total_events:,}")
    logger.info(f"  Mutations submitted: {mutations_submitted}")
    
    if args.dry_run:
        logger.info("\n*** DRY RUN - No actual changes were made ***")
        logger.info("Run without --dry-run to apply changes")
    else:
        logger.info("\nMutations run asynchronously. Check progress with:")
        logger.info("  python backfill_search_blob_keyvalue.py --check-progress")


if __name__ == '__main__':
    main()
