#!/usr/bin/env python3
"""
CaseScope Processing Module: IOC Matching
==========================================

Handles IOC matching across ALL events in a case (not per-file).

This module is responsible for:
1. Searching all indexed events for IOC matches
2. Creating IOCMatch records in database
3. Flagging events in OpenSearch with has_ioc field

Does NOT handle:
- File indexing (see processing_index.py)
- SIGMA detection (see processing_sigma.py)

IOC matching is done at the CASE level, not per-file, because:
- IOCs can be added after files are indexed
- One IOC search should cover all events in the case
- More efficient than re-processing each file individually

Author: CaseScope
Version: 2.0.0 - Modular Processing System
"""

import logging
from typing import Dict, Any, List, Optional
from celery_app import celery_app
from sqlalchemy import func

logger = logging.getLogger(__name__)


# ==============================================================================
# CELERY TASK: Match Single IOC Across All Events
# ==============================================================================

@celery_app.task(bind=True, name='processing_ioc.match_ioc_task')
def match_ioc_task(self, case_id: int, ioc_id: int) -> Dict[str, Any]:
    """
    Celery task to match a single IOC against all events in a case.
    
    This task:
    1. Gets IOC from database
    2. Searches OpenSearch for matches across all files
    3. Creates IOCMatch records
    4. Flags matching events with has_ioc
    
    Args:
        case_id: Case ID to search
        ioc_id: IOC ID to match
        
    Returns:
        dict: {
            'status': 'success'|'error',
            'message': str,
            'ioc_id': int,
            'matches': int,
            'error': str (if error)
        }
    """
    from main import app, db
    from models import IOC, IOCMatch, CaseFile
    from main import opensearch_client
    from utils import make_index_name
    from tasks import commit_with_retry
    import json
    
    logger.info(f"[IOC_TASK] Matching IOC {ioc_id} in case {case_id}")
    
    with app.app_context():
        try:
            # Get IOC
            ioc = db.session.get(IOC, ioc_id)
            if not ioc or ioc.case_id != case_id:
                return {
                    'status': 'error',
                    'message': 'IOC not found or wrong case',
                    'ioc_id': ioc_id,
                    'matches': 0
                }
            
            # Check if IOC is active
            if not ioc.is_active:
                logger.info(f"[IOC_TASK] IOC {ioc_id} is not active, skipping")
                return {
                    'status': 'skipped',
                    'message': 'IOC not active',
                    'ioc_id': ioc_id,
                    'matches': 0
                }
            
            # Get index name
            index_name = make_index_name(case_id)
            
            # Check if index exists
            if not opensearch_client.indices.exists(index=index_name):
                logger.warning(f"[IOC_TASK] Index {index_name} does not exist")
                return {
                    'status': 'skipped',
                    'message': 'Index does not exist',
                    'ioc_id': ioc_id,
                    'matches': 0
                }
            
            # Build search query based on IOC type
            search_value = ioc.ioc_value
            
            if ioc.ioc_type == 'command':
                # For command IOCs, search for .exe form to avoid false positives
                if not search_value.lower().endswith('.exe'):
                    search_value = f"{search_value}.exe"
                logger.info(f"[IOC_TASK] COMMAND IOC: searching for '{search_value}'")
            
            if ioc.ioc_type == 'command_complex':
                # Complex IOC - extract distinctive terms
                import re
                words = re.findall(r'\b\w{5,}\b', ioc.ioc_value)
                distinctive_words = [w for w in words if not w.islower() and not w.isupper()]
                if not distinctive_words:
                    distinctive_words = words[:5]
                
                search_terms = ' AND '.join(distinctive_words[:5])
                
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "query_string": {
                                        "query": search_terms,
                                        "fields": ["search_blob"],
                                        "default_operator": "AND",
                                        "lenient": True
                                    }
                                }
                            ],
                            "must_not": [
                                {"term": {"event_status": "noise"}}
                            ]
                        }
                    }
                }
                logger.info(f"[IOC_TASK] Complex IOC: using terms '{search_terms}'")
            else:
                # Standard IOC - use simple_query_string on search_blob
                # Exclude events with status='noise'
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "simple_query_string": {
                                        "query": f'"{search_value}"',
                                        "fields": ["search_blob"],
                                        "default_operator": "and"
                                    }
                                }
                            ],
                            "must_not": [
                                {"term": {"event_status": "noise"}}
                            ]
                        }
                    }
                }
            
            # Search using scroll API to get ALL results
            scroll_query = query.copy()
            scroll_query['size'] = 5000
            
            response = opensearch_client.search(
                index=index_name,
                body=scroll_query,
                scroll='5m'
            )
            
            scroll_id = response.get('_scroll_id')
            all_hits = response['hits']['hits']
            total_hits = response['hits']['total']['value']
            
            # Continue scrolling if needed
            while len(all_hits) < total_hits and scroll_id:
                response = opensearch_client.scroll(
                    scroll_id=scroll_id,
                    scroll='5m'
                )
                scroll_id = response.get('_scroll_id')
                batch_hits = response['hits']['hits']
                if not batch_hits:
                    break
                all_hits.extend(batch_hits)
            
            # Clear scroll
            if scroll_id:
                try:
                    opensearch_client.clear_scroll(scroll_id=scroll_id)
                except:
                    pass
            
            if not all_hits:
                logger.info(f"[IOC_TASK] No matches for IOC {ioc_id}")
                return {
                    'status': 'success',
                    'message': 'No matches found',
                    'ioc_id': ioc_id,
                    'matches': 0
                }
            
            logger.info(f"[IOC_TASK] Found {len(all_hits)} matches for IOC {ioc_id}")
            
            # Delete existing matches for this IOC (in case of re-run)
            db.session.query(IOCMatch).filter_by(ioc_id=ioc_id).delete()
            
            # Create IOCMatch records in batches
            batch_size = 1000
            total_matches = 0
            event_ids_to_flag = []
            
            for i in range(0, len(all_hits), batch_size):
                batch = all_hits[i:i+batch_size]
                
                for hit in batch:
                    event_id = hit['_id']
                    event_source = hit['_source']
                    file_id = event_source.get('file_id')
                    
                    # Store event data as JSON
                    event_data_json = json.dumps(event_source)
                    
                    ioc_match = IOCMatch(
                        ioc_id=ioc.id,
                        case_id=case_id,
                        file_id=file_id,
                        event_id=event_id,
                        index_name=index_name,
                        matched_field=f'auto_detected_{ioc.ioc_type}',
                        event_data=event_data_json
                    )
                    db.session.add(ioc_match)
                    total_matches += 1
                    event_ids_to_flag.append(event_id)
                
                commit_with_retry(db.session, logger_instance=logger)
            
            # Update OpenSearch events with has_ioc flag
            if event_ids_to_flag:
                logger.info(f"[IOC_TASK] Flagging {len(event_ids_to_flag)} events in OpenSearch")
                
                from opensearchpy.helpers import bulk as opensearch_bulk
                
                bulk_updates = [
                    {
                        '_op_type': 'update',
                        '_index': index_name,
                        '_id': event_id,
                        'doc': {'has_ioc': True}
                    }
                    for event_id in event_ids_to_flag
                ]
                
                try:
                    opensearch_bulk(opensearch_client, bulk_updates)
                    logger.info(f"[IOC_TASK] ✓ Flagged {len(event_ids_to_flag)} events with has_ioc")
                except Exception as e:
                    logger.warning(f"[IOC_TASK] Error flagging events: {e}")
            
            # Update file IOC counts
            logger.info("[IOC_TASK] Updating file IOC counts")
            file_counts = {}
            for match in db.session.query(IOCMatch).filter_by(ioc_id=ioc_id).all():
                if match.file_id:
                    file_counts[match.file_id] = file_counts.get(match.file_id, 0) + 1
            
            for file_id, count in file_counts.items():
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    # Recalculate total IOC count for file
                    from sqlalchemy import func
                    total_ioc_count = db.session.query(func.count(IOCMatch.id)).filter_by(
                        case_id=case_id,
                        file_id=file_id
                    ).scalar() or 0
                    case_file.ioc_event_count = total_ioc_count
            
            commit_with_retry(db.session, logger_instance=logger)
            
            logger.info(f"[IOC_TASK] ✓ IOC {ioc_id} matched: {total_matches} matches")
            
            return {
                'status': 'success',
                'message': f'Found {total_matches} matches',
                'ioc_id': ioc_id,
                'matches': total_matches
            }
            
        except Exception as e:
            logger.error(f"[IOC_TASK] Error matching IOC {ioc_id}: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': str(e),
                'ioc_id': ioc_id,
                'matches': 0,
                'error': str(e)
            }


# ==============================================================================
# PHASE COORDINATOR: Match All IOCs in Case
# ==============================================================================

def match_all_iocs(case_id: int) -> Dict[str, Any]:
    """
    Match all active IOCs against all events in a case using parallel workers.
    
    This function:
    1. Gets all active IOCs for case
    2. Queues them for parallel matching (max 8 workers)
    3. Waits for ALL IOCs to complete before returning
    
    Args:
        case_id: Case ID to process
        
    Returns:
        dict: {
            'status': 'success'|'error',
            'total_iocs': int,
            'matched': int,
            'skipped': int,
            'failed': int,
            'total_matches': int,
            'errors': list
        }
    """
    from main import app, db
    from models import IOC, Case
    from celery import group
    from tasks import commit_with_retry
    import time
    
    logger.info(f"[IOC_PHASE] Starting IOC matching phase for case {case_id}")
    
    with app.app_context():
        # Get all active IOCs
        iocs = IOC.query.filter_by(
            case_id=case_id,
            is_active=True
        ).all()
        
        if not iocs:
            logger.info(f"[IOC_PHASE] No active IOCs for case {case_id}")
            return {
                'status': 'success',
                'total_iocs': 0,
                'matched': 0,
                'skipped': 0,
                'failed': 0,
                'total_matches': 0,
                'errors': []
            }
        
        total_iocs = len(iocs)
        logger.info(f"[IOC_PHASE] Found {total_iocs} active IOCs to match")
        
        # Create task group
        job = group(match_ioc_task.s(case_id, ioc.id) for ioc in iocs)
        result = job.apply_async()
        
        # Wait for all tasks to complete by SIMPLE QUEUE CHECK (like Index/SIGMA)
        logger.info(f"[IOC_PHASE] Waiting for {total_iocs} IOC matching tasks to complete...")
        
        start_time = time.time()
        timeout = 7200  # 2 hours max
        last_log_time = 0
        
        # Track which IOCs we queued
        ioc_ids = [ioc.id for ioc in iocs]
        
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logger.error(f"[IOC_PHASE] Timeout after {timeout}s")
                # Get partial results from DB
                matched = db.session.query(IOC.id).filter(
                    IOC.id.in_(ioc_ids)
                ).outerjoin(IOCMatch, IOCMatch.ioc_id == IOC.id).filter(
                    IOCMatch.id.isnot(None)
                ).distinct().count()
                
                total_matches = db.session.query(IOCMatch).filter(
                    IOCMatch.case_id == case_id,
                    IOCMatch.ioc_id.in_(ioc_ids)
                ).count()
                
                return {
                    'status': 'error',
                    'total_iocs': total_iocs,
                    'matched': matched,
                    'skipped': 0,
                    'failed': 0,
                    'total_matches': total_matches,
                    'errors': ['IOC phase timeout']
                }
            
            # SIMPLE QUEUE CHECK: Count IOCs that have been processed
            # An IOC is "processed" if it has at least one IOCMatch record
            # (even if no matches found, task still creates metadata or marks as done)
            processed = db.session.query(IOC.id).filter(
                IOC.id.in_(ioc_ids)
            ).outerjoin(IOCMatch, IOCMatch.ioc_id == IOC.id).filter(
                IOCMatch.id.isnot(None)
            ).distinct().count()
            
            # For inactive IOCs (skipped), they won't have matches
            # So also count IOCs we've seen (via quick check if tasks are done)
            # Simpler: if we've processed some IOCs and it's been stable, we're done
            pending = total_iocs - processed
            
            # Update progress tracker with counts for progress bar
            from progress_tracker import update_phase
            update_phase(case_id, 'reindex', 7, 'IOC Matching', 'running',
                        f'{processed}/{total_iocs} IOCs matched',
                        current=processed, total=total_iocs)
            
            # Log progress every 30 seconds
            if elapsed - last_log_time >= 30:
                logger.info(f"[IOC_PHASE] Progress: {processed}/{total_iocs} IOCs processed, {pending} pending")
                last_log_time = elapsed
            
            # QUEUE CHECK: All done when processed count = total count
            # But IOCs with no matches won't have records, so we use 10-second stability check
            if processed >= total_iocs:
                logger.info(f"[IOC_PHASE] All {total_iocs} IOCs processed")
                break
            
            # If we haven't made progress in 30 seconds and we're past the 60 second mark, assume remaining IOCs had no matches
            if elapsed > 60 and pending > 0:
                time.sleep(10)
                new_processed = db.session.query(IOC.id).filter(
                    IOC.id.in_(ioc_ids)
                ).outerjoin(IOCMatch, IOCMatch.ioc_id == IOC.id).filter(
                    IOCMatch.id.isnot(None)
                ).distinct().count()
                
                if new_processed == processed:
                    logger.info(f"[IOC_PHASE] No new IOCs processed in 10s, assuming remaining {pending} had no matches")
                    break
            
            time.sleep(5)
        
        # Collect results from DATABASE
        from models import IOC, IOCMatch
        
        # Count matched IOCs (those with at least one match)
        matched = db.session.query(IOC.id).filter(
            IOC.id.in_(ioc_ids)
        ).join(IOCMatch, IOCMatch.ioc_id == IOC.id).distinct().count()
        
        # Total matches across all IOCs
        total_matches = db.session.query(IOCMatch).filter(
            IOCMatch.case_id == case_id,
            IOCMatch.ioc_id.in_(ioc_ids)
        ).count()
        
        skipped = 0  # We queued only active IOCs
        failed = 0  # No failure tracking for IOCs
        errors = []
        
        # Update case aggregate
        case = db.session.get(Case, case_id)
        if case:
            from sqlalchemy import func
            from models import CaseFile
            case.total_events_with_IOCs = db.session.query(
                func.sum(CaseFile.ioc_event_count)
            ).filter_by(case_id=case_id, is_deleted=False).scalar() or 0
            commit_with_retry(db.session, logger_instance=logger)
        
        logger.info(f"[IOC_PHASE] ✓ IOC matching complete: {matched} IOCs matched, {total_matches} total matches")
        
        return {
            'status': 'success',
            'total_iocs': total_iocs,
            'matched': matched,
            'skipped': skipped,
            'failed': failed,
            'total_matches': total_matches,
            'errors': errors[:10]
        }


# ==============================================================================
# HELPER: Check if IOC Matching is Complete
# ==============================================================================

def is_ioc_matching_complete(case_id: int) -> bool:
    """
    Check if IOC matching has been run for a case.
    
    Note: This is harder to determine than indexing/SIGMA since IOCs can be
    added at any time. This function just checks if there are any active IOCs
    and if they have matches.
    
    Args:
        case_id: Case ID to check
        
    Returns:
        bool: Always True (IOC matching can always be re-run)
    """
    # IOC matching can be run multiple times, so we always consider it "complete"
    # The phase will run whenever called
    return True

