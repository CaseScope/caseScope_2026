#!/usr/bin/env python3
"""
CaseScope Coordinator: Index New Files
=======================================

Handles the complete indexing workflow for NEW files.

This coordinator runs when users upload files or manually trigger indexing.

Workflow:
1. Files are queued (already done by upload system)
2. Run indexing phase (processing_index.py)
3. Run SIGMA detection (processing_sigma.py)
4. Run known-good filtering (events_known_good.py)
5. Run known-noise filtering (events_known_noise.py)
6. Run IOC matching (processing_ioc.py)

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

def index_new_files(case_id: int, operation: str = 'index') -> Dict[str, Any]:
    """
    Complete indexing workflow for new files in a case.
    
    This function runs all processing phases in sequence:
    - Index files
    - SIGMA detection  
    - Known-good filtering
    - Known-noise filtering
    - IOC matching
    
    Args:
        case_id: Case ID to process
        operation: Operation name for progress tracking ('index' or 'reindex')
        
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
    from main import app
    from progress_tracker import start_progress, update_phase, complete_progress
    
    start_time = time.time()
    result = {
        'status': 'success',
        'phases_completed': [],
        'phases_failed': [],
        'stats': {},
        'errors': [],
        'duration': 0
    }
    
    logger.info("="*80)
    logger.info(f"[INDEX_COORDINATOR] Starting new file indexing for case {case_id} (operation: {operation})")
    logger.info("="*80)
    
    # Start progress tracking - 5 total phases (index, sigma, known-good, known-noise, ioc)
    # Only start progress if this is the main 'index' operation (not when called from reindex)
    if operation == 'index':
        start_progress(case_id, 'index', total_phases=5, description='Indexing new files')
    
    with app.app_context():
        try:
            # ===============================================================
            # PHASE 1: INDEX FILES
            # ===============================================================
            logger.info("[INDEX_COORDINATOR] PHASE 1: Indexing files...")
            update_phase(case_id, operation, 1, 'Indexing Files', 'running', 'Indexing events...')
            
            from processing_index import index_all_files_in_queue
            
            index_result = index_all_files_in_queue(case_id, operation=operation, phase_num=1)
            
            if index_result['status'] == 'success':
                result['phases_completed'].append('indexing')
                result['stats']['indexing'] = index_result
                logger.info(f"[INDEX_COORDINATOR] ✓ PHASE 1 complete: {index_result['indexed']} files indexed")
                update_phase(case_id, operation, 1, 'Indexing Files', 'completed', f"Indexed {index_result['indexed']} files")
            else:
                result['phases_failed'].append('indexing')
                result['errors'].extend(index_result.get('errors', ['Indexing failed']))
                result['status'] = 'error'
                result['duration'] = time.time() - start_time
                update_phase(case_id, operation, 1, 'Indexing Files', 'failed', 'Indexing failed')
                if operation == 'index':
                    complete_progress(case_id, 'index', success=False, error_message='Indexing failed')
                return result  # Stop if indexing fails
            
            # ===============================================================
            # PHASE 2: SIGMA DETECTION
            # ===============================================================
            logger.info("[INDEX_COORDINATOR] PHASE 2: SIGMA detection...")
            update_phase(case_id, operation, 2, 'SIGMA Detection', 'running', 'Running SIGMA rules...')
            
            from processing_sigma import sigma_detect_all_files
            
            sigma_result = sigma_detect_all_files(case_id, operation=operation, phase_num=2)
            
            if sigma_result['status'] == 'success':
                result['phases_completed'].append('sigma')
                result['stats']['sigma'] = sigma_result
                logger.info(f"[INDEX_COORDINATOR] ✓ PHASE 2 complete: {sigma_result['total_violations']} violations found")
                update_phase(case_id, operation, 2, 'SIGMA Detection', 'completed', f"Found {sigma_result['total_violations']} violations")
            else:
                result['phases_failed'].append('sigma')
                result['errors'].extend(sigma_result.get('errors', ['SIGMA failed']))
                update_phase(case_id, operation, 2, 'SIGMA Detection', 'failed', 'SIGMA detection failed')
            
            # ===============================================================
            # PHASE 3: HIDE KNOWN-GOOD EVENTS (PARALLEL)
            # ===============================================================
            logger.info("[INDEX_COORDINATOR] PHASE 3: Filtering known-good events...")
            update_phase(case_id, operation, 3, 'Known-Good Filter', 'running', 'Filtering known-good events...')
            
            from events_known_good import hide_known_good_all_task, has_exclusions_configured
            
            if has_exclusions_configured():
                # Dispatch task and WAIT for completion
                kg_task = hide_known_good_all_task.delay(case_id)
                logger.info(f"[INDEX_COORDINATOR] Known-Good filtering dispatched (task_id: {kg_task.id}), waiting for completion...")
                
                # Poll for completion (database polling, not .get())
                import time
                kg_start_time = time.time()
                timeout = 3600  # 1 hour max
                poll_interval = 5  # Check every 5 seconds
                
                while not kg_task.ready():
                    elapsed = time.time() - kg_start_time
                    if elapsed > timeout:
                        logger.error(f"[INDEX_COORDINATOR] Known-Good filter timeout after {elapsed:.0f}s")
                        result['errors'].append(f'Known-Good filter timeout after {elapsed:.0f}s')
                        break
                    time.sleep(poll_interval)
                
                # Get result
                try:
                    kg_result = kg_task.get(timeout=10)
                    result['phases_completed'].append('known_good')
                    result['stats']['known_good'] = kg_result
                    logger.info(f"[INDEX_COORDINATOR] Known-Good filter complete: {kg_result.get('total_hidden', 0)} events hidden")
                    update_phase(case_id, operation, 3, 'Known-Good Filter', 'completed', f"{kg_result.get('total_hidden', 0)} events marked as known-good")
                except Exception as e:
                    logger.error(f"[INDEX_COORDINATOR] Known-Good filter failed: {e}")
                    result['errors'].append(f'Known-Good filter failed: {e}')
                    update_phase(case_id, operation, 3, 'Known-Good Filter', 'failed', str(e))
            else:
                result['phases_completed'].append('known_good')
                result['stats']['known_good'] = {'total_hidden': 0}
                logger.info("[INDEX_COORDINATOR] PHASE 3 skipped: No exclusions configured")
                update_phase(case_id, operation, 3, 'Known-Good Filter', 'completed', 'Skipped (no exclusions)')
            
            # ===============================================================
            # PHASE 4: HIDE KNOWN-NOISE EVENTS (PARALLEL)
            # ===============================================================
            logger.info("[INDEX_COORDINATOR] PHASE 4: Filtering known-noise events...")
            update_phase(case_id, operation, 4, 'Known-Noise Filter', 'running', 'Filtering known-noise events...')
            
            from events_known_noise import hide_noise_all_task
            
            # Dispatch task and WAIT for completion
            noise_task = hide_noise_all_task.delay(case_id)
            logger.info(f"[INDEX_COORDINATOR] Known-Noise filtering dispatched (task_id: {noise_task.id}), waiting for completion...")
            
            # Poll for completion
            noise_start_time = time.time()
            while not noise_task.ready():
                elapsed = time.time() - noise_start_time
                if elapsed > timeout:
                    logger.error(f"[INDEX_COORDINATOR] Known-Noise filter timeout after {elapsed:.0f}s")
                    result['errors'].append(f'Known-Noise filter timeout after {elapsed:.0f}s')
                    break
                time.sleep(poll_interval)
            
            # Get result
            try:
                noise_result = noise_task.get(timeout=10)
                result['phases_completed'].append('known_noise')
                result['stats']['known_noise'] = noise_result
                logger.info(f"[INDEX_COORDINATOR] Known-Noise filter complete: {noise_result.get('total_hidden', 0)} events hidden")
                update_phase(case_id, operation, 4, 'Known-Noise Filter', 'completed', f"{noise_result.get('total_hidden', 0)} events marked as noise")
            except Exception as e:
                logger.error(f"[INDEX_COORDINATOR] Known-Noise filter failed: {e}")
                result['errors'].append(f'Known-Noise filter failed: {e}')
                update_phase(case_id, operation, 4, 'Known-Noise Filter', 'failed', str(e))
            
            # ===============================================================
            # PHASE 5: IOC MATCHING
            # ===============================================================
            logger.info("[INDEX_COORDINATOR] PHASE 5: IOC matching...")
            update_phase(case_id, operation, 5, 'IOC Matching', 'running', 'Matching IOCs...')
            
            from processing_ioc import hunt_iocs_all_files
            
            ioc_result = hunt_iocs_all_files(case_id, operation=operation, phase_num=5)
            
            if ioc_result['status'] == 'success':
                result['phases_completed'].append('ioc_matching')
                result['stats']['ioc_matching'] = ioc_result
                logger.info(f"[INDEX_COORDINATOR] ✓ PHASE 5 complete: {ioc_result['total_matches']} matches found")
                update_phase(case_id, operation, 5, 'IOC Matching', 'completed', f"Found {ioc_result['total_matches']} matches")
            else:
                result['phases_failed'].append('ioc_matching')
                result['errors'].extend(ioc_result.get('errors', ['IOC matching failed']))
                update_phase(case_id, operation, 5, 'IOC Matching', 'failed', 'IOC matching failed')
            
            # ===============================================================
            # FINALIZE: Update file state flags for all files
            # ===============================================================
            from models import CaseFile
            from main import db
            from tasks import commit_with_retry
            from progress_tracker import complete_progress
            import file_state_manager as fsm
            
            logger.info("[INDEX_COORDINATOR] Finalizing file states...")
            
            # Get all files that were processed
            files = db.session.query(CaseFile).filter(
                CaseFile.case_id == case_id,
                CaseFile.is_indexed == True,
                CaseFile.is_deleted == False,
                CaseFile.celery_task_id.isnot(None)
            ).all()
            
            for f in files:
                # Clear celery_task_id
                f.celery_task_id = None
                
                # Update noise checking flags
                # After known-good and known-noise filtering, mark as complete
                if not f.known_good:
                    f.known_good = True  # Noise filtering ran (known-good check complete)
                if not f.known_noise:
                    f.known_noise = True  # Noise filtering ran (known-noise check complete)
                
                # Update file_state based on completion
                # The is_completed property will determine if file is fully processed
                if f.is_completed:
                    f.file_state = 'Completed'
                elif f.failed:
                    f.file_state = 'Failed'
                elif f.is_hidden:
                    f.file_state = 'Hidden'
                # Else keep current state (Indexed, SIGMA Checked, IOC Checked, etc.)
            
            commit_with_retry(db.session, logger_instance=logger)
            logger.info(f"[INDEX_COORDINATOR] Finalized {len(files)} files - updated state flags")
            
            # Complete progress tracking (clears progress bar) - only for 'index' operation
            if operation == 'index':
                complete_progress(case_id, 'index', success=(result['status'] in ['success', 'partial']))
            
            # Final status
            result['duration'] = time.time() - start_time
            
            if result['phases_failed']:
                result['status'] = 'partial'
            
            logger.info("="*80)
            logger.info(f"[INDEX_COORDINATOR] Complete: {len(result['phases_completed'])} phases succeeded, {len(result['phases_failed'])} failed")
            logger.info(f"[INDEX_COORDINATOR] Duration: {result['duration']:.1f}s")
            logger.info("="*80)
            
            return result
            
        except Exception as e:
            logger.error(f"[INDEX_COORDINATOR] Fatal error: {e}", exc_info=True)
            result['status'] = 'error'
            result['errors'].append(str(e))
            result['duration'] = time.time() - start_time
            return result


# ==============================================================================
# CELERY TASK: Run Async
# ==============================================================================

@celery_app.task(bind=True, name='coordinator_index.index_new_files_task')
def index_new_files_task(self, case_id: int) -> Dict[str, Any]:
    """
    Celery task wrapper for index_new_files.
    
    Args:
        case_id: Case ID to process
        
    Returns:
        Same as index_new_files()
    """
    logger.info(f"[INDEX_COORDINATOR_TASK] Starting for case {case_id}")
    result = index_new_files(case_id)
    logger.info(f"[INDEX_COORDINATOR_TASK] Complete: {result['status']}")
    return result

