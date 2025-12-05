#!/usr/bin/env python3
"""
CaseScope Coordinator: Reindex Files
=====================================

Handles the complete reindexing workflow for existing files.

This coordinator runs when users want to reindex files (all, selected, or single).

Workflow:
1. Files are queued (could be all, selected, or single file)
2. Clear metadata (processing_clear_metadata.py - 'all' type)
3. Run indexing phase (processing_index.py)
4. Run SIGMA detection (processing_sigma.py)
5. Run known-good filtering (events_known_good.py)
6. Run known-noise filtering (events_known_noise.py)
7. Run IOC matching (processing_ioc.py)

Author: CaseScope
Version: 2.0.0 - Modular Processing System
"""

import logging
from typing import Dict, Any, Optional, List
from celery_app import celery_app

logger = logging.getLogger(__name__)


# ==============================================================================
# MAIN COORDINATOR FUNCTION
# ==============================================================================

def reindex_files(case_id: int, file_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Complete reindexing workflow for files in a case.
    
    Args:
        case_id: Case ID to process
        file_ids: Optional list of specific file IDs to reindex. If None, reindex all files.
        
    Returns:
        dict: {
            'status': 'success'|'error'|'partial',
            'phases_completed': list,
            'phases_failed': list,
            'stats': dict,
            'errors': list,
            'duration': float
        }
    """
    import time
    import sys
    
    # DEBUG: Log to stderr to ensure it shows up
    print(f"[DEBUG] reindex_files() called for case {case_id}", file=sys.stderr, flush=True)
    
    start_time = time.time()
    result = {
        'status': 'success',
        'phases_completed': [],
        'phases_failed': [],
        'stats': {},
        'errors': [],
        'duration': 0
    }
    
    print(f"[DEBUG] About to import Flask app...", file=sys.stderr, flush=True)
    
    # Import Flask app first, then create context
    from main import app, db
    from models import CaseFile
    from progress_tracker import start_progress, update_phase, complete_progress
    
    print(f"[DEBUG] Imports successful!", file=sys.stderr, flush=True)
    
    mode = 'all files' if file_ids is None else f'{len(file_ids)} files'
    
    logger.info("="*80)
    logger.info(f"[REINDEX_COORDINATOR] Starting reindex for case {case_id} ({mode})")
    logger.info("="*80)
    
    # Start progress tracking - 7 total phases (queue, clear, index, sigma, known-good, known-noise, ioc)
    start_progress(case_id, 'reindex', total_phases=7, description=f'Reindexing {mode}')
    
    with app.app_context():
        try:
            # ===============================================================
            # PHASE 0: QUEUE FILES FOR REINDEX
            # ===============================================================
            logger.info("[REINDEX_COORDINATOR] PHASE 0: Queuing files for reindex...")
            update_phase(case_id, 'reindex', 1, 'Queuing Files', 'running', 'Preparing files for reindex...')
            
            if file_ids is None:
                # Reindex ALL files
                files = CaseFile.query.filter_by(
                    case_id=case_id,
                    is_deleted=False,
                    is_hidden=False
                ).all()
            else:
                # Reindex specific files
                files = CaseFile.query.filter(
                    CaseFile.id.in_(file_ids),
                    CaseFile.case_id == case_id,
                    CaseFile.is_deleted == False
                ).all()
            
            # Mark files for reindexing
            for f in files:
                f.indexing_status = 'Queued'
                f.is_indexed = False
            
            db.session.commit()
            
            logger.info(f"[REINDEX_COORDINATOR] Queued {len(files)} files for reindexing")
            
            # ===============================================================
            # PHASE 1: CLEAR METADATA
            # ===============================================================
            logger.info("[REINDEX_COORDINATOR] PHASE 1: Clearing metadata...")
            update_phase(case_id, 'reindex', 2, 'Clearing Data', 'running', 'Deleting old data...')
            
            # OPTIMIZATION: If reindexing ALL files, delete the entire case index at once
            # This is much faster than deleting file-by-file
            if file_ids is None:
                logger.info("[REINDEX_COORDINATOR] Bulk clearing entire case (all files)...")
                from processing_clear_metadata import bulk_clear_case
                clear_result = bulk_clear_case(case_id)
            else:
                logger.info(f"[REINDEX_COORDINATOR] Clearing {len(file_ids)} specific files...")
                from processing_clear_metadata import clear_all_queued_files
                clear_result = clear_all_queued_files(case_id, clear_type='all')
            
            if clear_result['status'] in ['success', 'partial']:
                result['phases_completed'].append('clear_metadata')
                result['stats']['clear_metadata'] = clear_result
                logger.info(f"[REINDEX_COORDINATOR] ✓ PHASE 1 complete: Cleared {clear_result.get('cleared', 'all')} data")
                update_phase(case_id, 'reindex', 2, 'Clearing Data', 'completed', f"Cleared {clear_result.get('cleared', 'all')} data")
            else:
                result['phases_failed'].append('clear_metadata')
                result['errors'].extend(clear_result.get('errors', ['Clearing failed']))
                result['status'] = 'error'
                result['duration'] = time.time() - start_time
                update_phase(case_id, 'reindex', 2, 'Clearing Data', 'failed', 'Failed to clear data')
                return result
            
            # ===============================================================
            # PHASE 3: INDEX FILES
            # ===============================================================
            logger.info("[REINDEX_COORDINATOR] PHASE 3: Indexing files...")
            update_phase(case_id, 'reindex', 3, 'Indexing Files', 'running', 'Indexing events...')
            
            from processing_index import index_all_files_in_queue
            
            index_result = index_all_files_in_queue(case_id, operation='reindex', phase_num=3)
            
            if index_result['status'] == 'success':
                result['phases_completed'].append('indexing')
                result['stats']['indexing'] = index_result
                logger.info(f"[REINDEX_COORDINATOR] ✓ PHASE 3 complete: {index_result['indexed']} files indexed")
                update_phase(case_id, 'reindex', 3, 'Indexing Files', 'completed', f"Indexed {index_result['indexed']} files")
            else:
                result['phases_failed'].append('indexing')
                result['errors'].extend(index_result.get('errors', ['Indexing failed']))
                result['status'] = 'error'
                result['duration'] = time.time() - start_time
                update_phase(case_id, 'reindex', 3, 'Indexing Files', 'failed', 'Indexing failed')
                complete_progress(case_id, 'reindex', success=False, error_message='Indexing failed')
                return result  # Stop if indexing fails
            
            # ===============================================================
            # PHASE 4: SIGMA DETECTION
            # ===============================================================
            logger.info("[REINDEX_COORDINATOR] PHASE 4: SIGMA detection...")
            update_phase(case_id, 'reindex', 4, 'SIGMA Detection', 'running', 'Running SIGMA rules...')
            
            from processing_sigma import sigma_detect_all_files
            
            sigma_result = sigma_detect_all_files(case_id, operation='reindex', phase_num=4)
            
            if sigma_result['status'] == 'success':
                result['phases_completed'].append('sigma')
                result['stats']['sigma'] = sigma_result
                logger.info(f"[REINDEX_COORDINATOR] ✓ PHASE 4 complete: {sigma_result['total_violations']} violations found")
                update_phase(case_id, 'reindex', 4, 'SIGMA Detection', 'completed', f"Found {sigma_result['total_violations']} violations")
            else:
                result['phases_failed'].append('sigma')
                result['errors'].extend(sigma_result.get('errors', ['SIGMA failed']))
                update_phase(case_id, 'reindex', 4, 'SIGMA Detection', 'failed', 'SIGMA detection failed')
            
            # ===============================================================
            # PHASE 5: HIDE KNOWN-GOOD EVENTS (PARALLEL)
            # ===============================================================
            logger.info("[REINDEX_COORDINATOR] PHASE 5: Filtering known-good events...")
            update_phase(case_id, 'reindex', 5, 'Known-Good Filter', 'running', 'Filtering known-good events...')
            
            from events_known_good import hide_known_good_all_task, has_exclusions_configured
            
            if has_exclusions_configured():
                # Dispatch task (don't block on result - let it run independently)
                kg_task = hide_known_good_all_task.delay(case_id)
                logger.info(f"[REINDEX_COORDINATOR] Known-Good filtering dispatched (task_id: {kg_task.id})")
                
                # Mark as completed (the task will update its own progress)
                result['phases_completed'].append('known_good')
                result['stats']['known_good'] = {'status': 'dispatched', 'task_id': str(kg_task.id)}
                update_phase(case_id, 'reindex', 5, 'Known-Good Filter', 'completed', 'Filtering in progress')
            else:
                result['phases_completed'].append('known_good')
                result['stats']['known_good'] = {'total_hidden': 0}
                logger.info("[REINDEX_COORDINATOR] PHASE 5 skipped: No exclusions configured")
                update_phase(case_id, 'reindex', 5, 'Known-Good Filter', 'completed', 'Skipped (no exclusions)')
            
            # ===============================================================
            # PHASE 6: HIDE KNOWN-NOISE EVENTS (PARALLEL)
            # ===============================================================
            logger.info("[REINDEX_COORDINATOR] PHASE 6: Filtering known-noise events...")
            update_phase(case_id, 'reindex', 6, 'Known-Noise Filter', 'running', 'Filtering known-noise events...')
            
            from events_known_noise import hide_noise_all_task
            
            # Dispatch task (don't block on result - let it run independently)
            noise_task = hide_noise_all_task.delay(case_id)
            logger.info(f"[REINDEX_COORDINATOR] Known-Noise filtering dispatched (task_id: {noise_task.id})")
            
            # Mark as completed (the task will update its own progress)
            result['phases_completed'].append('known_noise')
            result['stats']['known_noise'] = {'status': 'dispatched', 'task_id': str(noise_task.id)}
            update_phase(case_id, 'reindex', 6, 'Known-Noise Filter', 'completed', 'Filtering in progress')
            
            # ===============================================================
            # PHASE 7: IOC MATCHING
            # ===============================================================
            logger.info("[REINDEX_COORDINATOR] PHASE 7: IOC matching...")
            update_phase(case_id, 'reindex', 7, 'IOC Matching', 'running', 'Matching IOCs...')
            
            from processing_ioc import hunt_iocs_all_files
            
            ioc_result = hunt_iocs_all_files(case_id, operation='reindex', phase_num=7)
            
            if ioc_result['status'] == 'success':
                result['phases_completed'].append('ioc_matching')
                result['stats']['ioc_matching'] = ioc_result
                logger.info(f"[REINDEX_COORDINATOR] ✓ PHASE 7 complete: {ioc_result['total_matches']} matches found")
                update_phase(case_id, 'reindex', 7, 'IOC Matching', 'completed', f"Found {ioc_result['total_matches']} matches")
            else:
                result['phases_failed'].append('ioc_matching')
                result['errors'].extend(ioc_result.get('errors', ['IOC matching failed']))
                update_phase(case_id, 'reindex', 7, 'IOC Matching', 'failed', 'IOC matching failed')
            
            # ===============================================================
            # FINALIZE: Mark files as completed
            # ===============================================================
            logger.info("[REINDEX_COORDINATOR] Finalizing...")
            
            files_to_finalize = db.session.query(CaseFile).filter(
                CaseFile.case_id == case_id,
                CaseFile.is_deleted == False,
                CaseFile.indexing_status.in_(['SIGMA Complete', 'Indexed'])
            ).all()
            
            for f in files_to_finalize:
                f.indexing_status = 'Completed'
                f.celery_task_id = None
            
            from tasks import commit_with_retry
            commit_with_retry(db.session, logger_instance=logger)
            logger.info(f"[REINDEX_COORDINATOR] Marked {len(files_to_finalize)} files as completed")
            
            # Complete progress tracking (clears progress bar)
            complete_progress(case_id, 'reindex', success=(result['status'] in ['success', 'partial']))
            
            result['duration'] = time.time() - start_time
            
            logger.info("="*80)
            logger.info(f"[REINDEX_COORDINATOR] Complete: {len(result['phases_completed'])} phases succeeded, {len(result['phases_failed'])} failed")
            logger.info(f"[REINDEX_COORDINATOR] Duration: {result['duration']:.1f}s")
            logger.info("="*80)
            
            return result
            
        except Exception as e:
            logger.error(f"[REINDEX_COORDINATOR] Fatal error: {e}", exc_info=True)
            result['status'] = 'error'
            result['errors'].append(str(e))
            result['duration'] = time.time() - start_time
            return result


# ==============================================================================
# CELERY TASK: Run Async
# ==============================================================================

@celery_app.task(bind=True, name='coordinator_reindex.reindex_files_task')
def reindex_files_task(self, case_id: int, file_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Celery task wrapper for reindex_files.
    
    Args:
        case_id: Case ID to process
        file_ids: Optional list of file IDs to reindex
        
    Returns:
        Same as reindex_files()
    """
    mode = 'all files' if file_ids is None else f'{len(file_ids)} files'
    logger.info(f"[REINDEX_COORDINATOR_TASK] Starting for case {case_id} ({mode})")
    result = reindex_files(case_id, file_ids)
    logger.info(f"[REINDEX_COORDINATOR_TASK] Complete: {result['status']}")
    return result

