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

def index_new_files(case_id: int, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
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
        progress_callback: Optional callback function(phase, status, message)
        
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
    from progress_tracker import update_phase
    
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
    logger.info(f"[INDEX_COORDINATOR] Starting new file indexing for case {case_id}")
    logger.info("="*80)
    
    with app.app_context():
        try:
            # ===============================================================
            # PHASE 1: INDEX FILES
            # ===============================================================
            logger.info("[INDEX_COORDINATOR] PHASE 1: Indexing files...")
            update_phase(case_id, 'reindex', 3, 'Indexing Files', 'running', 'Indexing events...')
            if progress_callback:
                progress_callback(1, 'running', 'Indexing files...')
            
            from processing_index import index_all_files_in_queue
            
            index_result = index_all_files_in_queue(case_id)
            
            if index_result['status'] == 'success':
                result['phases_completed'].append('indexing')
                result['stats']['indexing'] = index_result
                logger.info(f"[INDEX_COORDINATOR] ✓ PHASE 1 complete: {index_result['indexed']} files indexed")
                update_phase(case_id, 'reindex', 3, 'Indexing Files', 'completed', f"Indexed {index_result['indexed']} files")
                if progress_callback:
                    progress_callback(1, 'completed', f"Indexed {index_result['indexed']} files")
            else:
                result['phases_failed'].append('indexing')
                result['errors'].extend(index_result.get('errors', ['Indexing failed']))
                result['status'] = 'error'
                result['duration'] = time.time() - start_time
                update_phase(case_id, 'reindex', 3, 'Indexing Files', 'failed', 'Indexing failed')
                if progress_callback:
                    progress_callback(1, 'failed', 'Indexing failed')
                return result  # Stop if indexing fails
            
            # ===============================================================
            # PHASE 2: SIGMA DETECTION
            # ===============================================================
            logger.info("[INDEX_COORDINATOR] PHASE 2: SIGMA detection...")
            update_phase(case_id, 'reindex', 4, 'SIGMA Detection', 'running', 'Running SIGMA rules...')
            if progress_callback:
                progress_callback(2, 'running', 'Running SIGMA detection...')
            
            from processing_sigma import sigma_detect_all_files
            
            sigma_result = sigma_detect_all_files(case_id)
            
            if sigma_result['status'] == 'success':
                result['phases_completed'].append('sigma')
                result['stats']['sigma'] = sigma_result
                logger.info(f"[INDEX_COORDINATOR] ✓ PHASE 2 complete: {sigma_result['total_violations']} violations found")
                update_phase(case_id, 'reindex', 4, 'SIGMA Detection', 'completed', f"Found {sigma_result['total_violations']} violations")
                if progress_callback:
                    progress_callback(2, 'completed', f"Found {sigma_result['total_violations']} violations")
            else:
                result['phases_failed'].append('sigma')
                result['errors'].extend(sigma_result.get('errors', ['SIGMA failed']))
                update_phase(case_id, 'reindex', 4, 'SIGMA Detection', 'failed', 'SIGMA detection failed')
                if progress_callback:
                    progress_callback(2, 'failed', 'SIGMA detection failed')
            
            # ===============================================================
            # PHASE 3: HIDE KNOWN-GOOD EVENTS
            # ===============================================================
            logger.info("[INDEX_COORDINATOR] PHASE 3: Filtering known-good events...")
            if progress_callback:
                progress_callback(3, 'running', 'Filtering known-good events...')
            
            from events_known_good import hide_known_good_events, has_exclusions_configured
            
            if has_exclusions_configured():
                kg_result = hide_known_good_events(case_id)
                if kg_result['success']:
                    result['phases_completed'].append('known_good')
                    result['stats']['known_good'] = kg_result
                    logger.info(f"[INDEX_COORDINATOR] ✓ PHASE 3 complete: {kg_result['total_hidden']} events hidden")
                    update_phase(case_id, 'reindex', 5, 'Known-Good Filter', 'completed', f"Hidden {kg_result['total_hidden']} events")
                    if progress_callback:
                        progress_callback(3, 'completed', f"Hidden {kg_result['total_hidden']} events")
                else:
                    result['phases_failed'].append('known_good')
                    result['errors'].extend(kg_result.get('errors', ['Known-good filtering failed']))
                    update_phase(case_id, 'reindex', 5, 'Known-Good Filter', 'failed', 'Known-good filtering failed')
                    if progress_callback:
                        progress_callback(3, 'failed', 'Known-good filtering failed')
            else:
                result['phases_completed'].append('known_good')
                result['stats']['known_good'] = {'total_hidden': 0}
                logger.info("[INDEX_COORDINATOR] PHASE 3 skipped: No exclusions configured")
                update_phase(case_id, 'reindex', 5, 'Known-Good Filter', 'completed', 'Skipped (no exclusions)')
                if progress_callback:
                    progress_callback(3, 'skipped', 'No exclusions configured')
            
            # ===============================================================
            # PHASE 4: HIDE KNOWN-NOISE EVENTS
            # ===============================================================
            logger.info("[INDEX_COORDINATOR] PHASE 4: Filtering known-noise events...")
            update_phase(case_id, 'reindex', 6, 'Known-Noise Filter', 'running', 'Filtering known-noise events...')
            if progress_callback:
                progress_callback(4, 'running', 'Filtering known-noise events...')
            
            from events_known_noise import hide_noise_events
            
            noise_result = hide_noise_events(case_id)
            
            if noise_result['success']:
                result['phases_completed'].append('known_noise')
                result['stats']['known_noise'] = noise_result
                logger.info(f"[INDEX_COORDINATOR] ✓ PHASE 4 complete: {noise_result['total_hidden']} events hidden")
                update_phase(case_id, 'reindex', 6, 'Known-Noise Filter', 'completed', f"Hidden {noise_result['total_hidden']} events")
                if progress_callback:
                    progress_callback(4, 'completed', f"Hidden {noise_result['total_hidden']} events")
            else:
                result['phases_failed'].append('known_noise')
                result['errors'].extend(noise_result.get('errors', ['Known-noise filtering failed']))
                update_phase(case_id, 'reindex', 6, 'Known-Noise Filter', 'failed', 'Known-noise filtering failed')
                if progress_callback:
                    progress_callback(4, 'failed', 'Known-noise filtering failed')
            
            # ===============================================================
            # PHASE 5: IOC MATCHING
            # ===============================================================
            logger.info("[INDEX_COORDINATOR] PHASE 5: IOC matching...")
            update_phase(case_id, 'reindex', 7, 'IOC Matching', 'running', 'Matching IOCs...')
            if progress_callback:
                progress_callback(5, 'running', 'Matching IOCs...')
            
            from processing_ioc import match_all_iocs
            
            ioc_result = match_all_iocs(case_id)
            
            if ioc_result['status'] == 'success':
                result['phases_completed'].append('ioc_matching')
                result['stats']['ioc_matching'] = ioc_result
                logger.info(f"[INDEX_COORDINATOR] ✓ PHASE 5 complete: {ioc_result['total_matches']} matches found")
                update_phase(case_id, 'reindex', 7, 'IOC Matching', 'completed', f"Found {ioc_result['total_matches']} matches")
                if progress_callback:
                    progress_callback(5, 'completed', f"Found {ioc_result['total_matches']} matches")
            else:
                result['phases_failed'].append('ioc_matching')
                result['errors'].extend(ioc_result.get('errors', ['IOC matching failed']))
                update_phase(case_id, 'reindex', 7, 'IOC Matching', 'failed', 'IOC matching failed')
                if progress_callback:
                    progress_callback(5, 'failed', 'IOC matching failed')
            
            # ===============================================================
            # FINALIZE
            # ===============================================================
            from models import CaseFile
            from main import db
            from tasks import commit_with_retry
            
            # Mark all indexed files as completed
            files = CaseFile.query.filter_by(
                case_id=case_id,
                is_indexed=True,
                is_deleted=False
            ).filter(
                CaseFile.indexing_status != 'Completed'
            ).all()
            
            for f in files:
                f.indexing_status = 'Completed'
                f.celery_task_id = None
            
            commit_with_retry(db.session, logger_instance=logger)
            logger.info(f"[INDEX_COORDINATOR] Marked {len(files)} files as completed")
            
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

