#!/usr/bin/env python3
"""
Reindex Coordinator - Orchestrates the 4-Phase Reindex Pipeline

Phase 1: Index + SIGMA (per file, parallel workers)
Phase 2: Known Good Event Hunting (bulk, parallel workers)
Phase 3: Known Noise Event Hunting (bulk, parallel workers)
Phase 4: IOC Hunting (per file, excludes noise)

Added in v1.46.0
"""

import logging
from datetime import datetime
from typing import List, Dict
from celery import group, chain, chord
from flask import current_app

logger = logging.getLogger(__name__)


def start_reindex_pipeline(db, case_id: int, user_id: int, file_ids: List[int], progress_id: int):
    """
    Phase orchestrator - runs each phase sequentially.
    
    This is called by the Celery coordinator task and runs phases in order:
    1. Clear old data (EventStatus, SigmaViolation, IOCs)
    2. Phase 1: Index + SIGMA for each file (parallel workers)
    3. Phase 2: Known Good hunting (parallel workers)
    4. Phase 3: Known Noise hunting (parallel workers)
    5. Phase 4: IOC hunting for each file (parallel workers)
    
    Args:
        db: Database session
        case_id: Case ID
        user_id: User ID who started reindex
        file_ids: List of file IDs to reindex
        progress_id: ReindexProgress record ID for tracking
    """
    from models import ReindexProgress, CaseFile
    from bulk_operations import clear_case_data_for_reindex
    
    progress = db.session.get(ReindexProgress, progress_id)
    if not progress:
        logger.error(f"[REINDEX] Progress record {progress_id} not found")
        return
    
    try:
        logger.info(f"[REINDEX] Starting pipeline for case {case_id}, {len(file_ids)} files")
        
        # ============================================================================
        # PRE-PHASE: Clear old data
        # ============================================================================
        logger.info(f"[REINDEX] Clearing old data...")
        progress.current_phase = 0
        progress.current_phase_name = 'Clearing old data'
        progress.status = 'running'
        db.session.commit()
        
        clear_result = clear_case_data_for_reindex(db, case_id, file_ids)
        progress.statuses_deleted = clear_result.get('event_statuses_deleted', 0)
        progress.violations_deleted = clear_result.get('sigma_violations_deleted', 0)
        db.session.commit()
        
        logger.info(f"[REINDEX] Cleared {progress.statuses_deleted} statuses, {progress.violations_deleted} violations")
        
        # ============================================================================
        # PHASE 1: Index + SIGMA (per file, parallel)
        # ============================================================================
        logger.info(f"[REINDEX] Starting Phase 1: Index + SIGMA")
        progress.current_phase = 1
        progress.current_phase_name = 'Index + SIGMA'
        progress.phase1_status = 'running'
        progress.phase1_total_files = len(file_ids)
        progress.phase1_completed_files = 0
        db.session.commit()
        
        phase1_results = run_phase1_index_sigma(db, case_id, file_ids, progress_id)
        
        # Update progress with Phase 1 results
        progress = db.session.get(ReindexProgress, progress_id)
        progress.phase1_completed_files = phase1_results['completed_files']
        progress.phase1_events_indexed = phase1_results['events_indexed']
        progress.phase1_sigma_violations = phase1_results['sigma_violations']
        progress.phase1_status = 'completed'
        db.session.commit()
        
        logger.info(f"[REINDEX] Phase 1 complete: {phase1_results['events_indexed']} events, {phase1_results['sigma_violations']} violations")
        
        # ============================================================================
        # PHASE 2: Known Good Hunting (bulk, parallel workers)
        # ============================================================================
        logger.info(f"[REINDEX] Starting Phase 2: Known Good Hunting")
        progress.current_phase = 2
        progress.current_phase_name = 'Hunting for Known Good Events'
        progress.phase2_status = 'running'
        progress.phase2_total_workers = 8  # Will be set by phase
        db.session.commit()
        
        phase2_results = run_phase2_known_good(db, case_id, progress_id)
        
        # Update progress with Phase 2 results
        progress = db.session.get(ReindexProgress, progress_id)
        progress.phase2_completed_workers = phase2_results['workers_completed']
        progress.phase2_events_marked = phase2_results['events_marked']
        progress.phase2_status = 'completed'
        db.session.commit()
        
        logger.info(f"[REINDEX] Phase 2 complete: {phase2_results['events_marked']} events marked as noise")
        
        # ============================================================================
        # PHASE 3: Known Noise Hunting (bulk, parallel workers)
        # ============================================================================
        logger.info(f"[REINDEX] Starting Phase 3: Known Noise Hunting")
        progress.current_phase = 3
        progress.current_phase_name = 'Hunting for Known Noise Events'
        progress.phase3_status = 'running'
        progress.phase3_total_workers = 8
        db.session.commit()
        
        phase3_results = run_phase3_known_noise(db, case_id, progress_id)
        
        # Update progress with Phase 3 results
        progress = db.session.get(ReindexProgress, progress_id)
        progress.phase3_completed_workers = phase3_results['workers_completed']
        progress.phase3_events_marked = phase3_results['events_marked']
        progress.phase3_status = 'completed'
        db.session.commit()
        
        logger.info(f"[REINDEX] Phase 3 complete: {phase3_results['events_marked']} events marked as noise")
        
        # ============================================================================
        # PHASE 4: IOC Hunting (per file, exclude noise)
        # ============================================================================
        logger.info(f"[REINDEX] Starting Phase 4: IOC Hunting")
        progress.current_phase = 4
        progress.current_phase_name = 'Hunting for IOCs'
        progress.phase4_status = 'running'
        progress.phase4_total_files = len(file_ids)
        progress.phase4_completed_files = 0
        db.session.commit()
        
        phase4_results = run_phase4_ioc_hunt(db, case_id, file_ids, progress_id)
        
        # Update progress with Phase 4 results
        progress = db.session.get(ReindexProgress, progress_id)
        progress.phase4_completed_files = phase4_results['completed_files']
        progress.phase4_iocs_found = phase4_results['iocs_found']
        progress.phase4_status = 'completed'
        db.session.commit()
        
        logger.info(f"[REINDEX] Phase 4 complete: {phase4_results['iocs_found']} IOCs found")
        
        # ============================================================================
        # COMPLETE
        # ============================================================================
        progress.status = 'completed'
        progress.completed_at = datetime.utcnow()
        progress.current_phase = 4
        progress.current_phase_name = 'Completed'
        db.session.commit()
        
        logger.info(f"[REINDEX] ✓ Pipeline complete for case {case_id}")
    
    except Exception as e:
        logger.error(f"[REINDEX] Pipeline failed: {e}", exc_info=True)
        progress = db.session.get(ReindexProgress, progress_id)
        if progress:
            progress.status = 'failed'
            progress.error_message = str(e)[:500]
            db.session.commit()
        raise


def run_phase1_index_sigma(db, case_id: int, file_ids: List[int], progress_id: int) -> Dict:
    """
    Phase 1: Index + SIGMA for each file synchronously.
    
    For each file:
    1. Index events → OpenSearch (all marked 'new')
    2. Run SIGMA detection → Store violations
    
    Returns:
        Dict with completed_files, events_indexed, sigma_violations counts
    """
    from index_evtx import index_file_simple
    from sigma_evtx import sigma_file_simple
    from main import opensearch_client  # Import the global opensearch_client
    from models import ReindexProgress
    
    logger.info(f"[PHASE1] Starting for {len(file_ids)} files")
    
    total_events = 0
    total_violations = 0
    completed = 0
    
    # Process each file synchronously
    for file_id in file_ids:
        try:
            # Index the file
            index_result = index_file_simple(db, opensearch_client, file_id, case_id)
            if index_result['status'] == 'success':
                total_events += index_result.get('events_indexed', 0)
                
                # Run SIGMA on the indexed file
                sigma_result = sigma_file_simple(db, opensearch_client, file_id, case_id)
                if sigma_result['status'] == 'success':
                    total_violations += sigma_result.get('violations_found', 0)
                
                completed += 1
                
                # Update progress every 10 files
                if completed % 10 == 0:
                    progress = db.session.get(ReindexProgress, progress_id)
                    if progress:
                        progress.phase1_completed_files = completed
                        progress.phase1_events_indexed = total_events
                        progress.phase1_sigma_violations = total_violations
                        db.session.commit()
                        logger.info(f"[PHASE1] Progress: {completed}/{len(file_ids)} files")
        
        except Exception as e:
            logger.error(f"[PHASE1] Failed for file {file_id}: {e}")
            continue
    
    # Final update
    progress = db.session.get(ReindexProgress, progress_id)
    if progress:
        progress.phase1_completed_files = completed
        progress.phase1_events_indexed = total_events
        progress.phase1_sigma_violations = total_violations
        db.session.commit()
    
    logger.info(f"[PHASE1] Complete: {completed}/{len(file_ids)} files, {total_events} events, {total_violations} violations")
    
    return {
        'completed_files': completed,
        'events_indexed': total_events,
        'sigma_violations': total_violations
    }


def run_phase2_known_good(db, case_id: int, progress_id: int) -> Dict:
    """
    Phase 2: Known Good hunting - identify benign events.
    
    Uses rules from EVENTS_KNOWN_GOOD.md to mark noise events.
    Calls the existing hide_known_good_events() function.
    
    Returns:
        Dict with workers_completed, events_marked counts
    """
    from events_known_good import hide_known_good_events
    from models import ReindexProgress
    
    logger.info(f"[PHASE2] Starting Known Good hunting")
    
    # Call the existing function (it's single-threaded but efficient)
    result = hide_known_good_events(case_id)
    
    total_marked = result.get('total_hidden', 0)
    
    # Update progress
    progress = db.session.get(ReindexProgress, progress_id)
    if progress:
        progress.phase2_total_workers = 1  # Single worker
        progress.phase2_completed_workers = 1
        progress.phase2_events_marked = total_marked
        db.session.commit()
    
    logger.info(f"[PHASE2] Complete: {total_marked} events marked as noise")
    
    return {
        'workers_completed': 1,
        'events_marked': total_marked
    }


def run_phase3_known_noise(db, case_id: int, progress_id: int) -> Dict:
    """
    Phase 3: Known Noise hunting - identify known noisy events.
    
    Uses rules from EVENTS_KNOWN_NOISE.md to mark noise events.
    Calls the existing hide_noise_events() function.
    
    Returns:
        Dict with workers_completed, events_marked counts
    """
    from events_known_noise import hide_noise_events
    from models import ReindexProgress
    
    logger.info(f"[PHASE3] Starting Known Noise hunting")
    
    # Call the existing function (it's single-threaded but efficient)
    result = hide_noise_events(case_id)
    
    total_marked = result.get('total_hidden', 0)
    
    # Update progress
    progress = db.session.get(ReindexProgress, progress_id)
    if progress:
        progress.phase3_total_workers = 1  # Single worker
        progress.phase3_completed_workers = 1
        progress.phase3_events_marked = total_marked
        db.session.commit()
    
    logger.info(f"[PHASE3] Complete: {total_marked} events marked as noise")
    
    return {
        'workers_completed': 1,
        'events_marked': total_marked
    }


def run_phase4_ioc_hunt(db, case_id: int, file_ids: List[int], progress_id: int) -> Dict:
    """
    Phase 4: IOC hunting for each file, excluding noise events.
    
    For each file:
    1. Query OpenSearch for events (exclude event_status='noise')
    2. Run IOC detection
    3. Store IOC matches
    
    Returns:
        Dict with completed_files, iocs_found counts
    """
    from file_processing import hunt_iocs
    from main import opensearch_client  # Import the global opensearch_client
    from models import ReindexProgress, CaseFile, IOC, IOCMatch
    from utils import make_index_name
    
    logger.info(f"[PHASE4] Starting IOC hunting for {len(file_ids)} files")
    
    index_name = make_index_name(case_id)
    total_iocs = 0
    completed = 0
    
    # Process each file
    for file_id in file_ids:
        try:
            result = hunt_iocs(
                db, opensearch_client, CaseFile, IOC, IOCMatch,
                file_id, index_name
            )
            
            if result.get('success'):
                total_iocs += result.get('matches', 0)
                completed += 1
                
                # Update progress periodically
                if completed % 10 == 0:
                    progress = db.session.get(ReindexProgress, progress_id)
                    if progress:
                        progress.phase4_completed_files = completed
                        progress.phase4_iocs_found = total_iocs
                        db.session.commit()
        
        except Exception as e:
            logger.error(f"[PHASE4] Failed for file {file_id}: {e}")
            continue
    
    # Final progress update
    progress = db.session.get(ReindexProgress, progress_id)
    if progress:
        progress.phase4_completed_files = completed
        progress.phase4_iocs_found = total_iocs
        db.session.commit()
    
    logger.info(f"[PHASE4] Complete: {completed}/{len(file_ids)} files, {total_iocs} IOCs found")
    
    return {
        'completed_files': completed,
        'iocs_found': total_iocs
    }

