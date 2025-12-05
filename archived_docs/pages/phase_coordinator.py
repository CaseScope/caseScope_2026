#!/usr/bin/env python3
"""
CaseScope Processing Module: Phase Coordinator
===============================================

Orchestrates the sequential execution of all processing phases.

Processing Flow:
1. PHASE 1: Index all files (8 workers in parallel)
2. Wait for phase 1 to complete
3. Requeue files for phase 2
4. PHASE 2: Run SIGMA detection on all EVTX files (8 workers in parallel)
5. Wait for phase 2 to complete
6. PHASE 3: Run known-good event filtering (single-threaded)
7. PHASE 4: Run known-noise event filtering (single-threaded)
8. PHASE 5: Run IOC matching across all events (8 workers in parallel)
9. Wait for phase 5 to complete
10. Mark all files as completed

This ensures proper sequential execution: no phase starts until the previous
phase is 100% complete.

Author: CaseScope
Version: 2.0.0 - Modular Processing System
"""

import logging
import time
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


# ==============================================================================
# PHASE COORDINATOR: Main Entry Point
# ==============================================================================

def run_phased_processing(case_id: int, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
    """
    Run all processing phases in sequence for a case.
    
    Args:
        case_id: Case ID to process
        progress_callback: Optional callback function(phase, status, message)
        
    Returns:
        dict: {
            'status': 'success'|'error'|'partial',
            'phases_completed': list,
            'phases_failed': list,
            'stats': dict with counts per phase,
            'errors': list,
            'duration': float (seconds)
        }
    """
    from main import app, db
    from models import Case
    
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
    logger.info(f"[PHASE_COORDINATOR] Starting phased processing for case {case_id}")
    logger.info("="*80)
    
    with app.app_context():
        # Verify case exists
        case = db.session.get(Case, case_id)
        if not case:
            result['status'] = 'error'
            result['errors'].append('Case not found')
            return result
        
        try:
            # ===================================================================
            # PHASE 1: INDEX ALL FILES
            # ===================================================================
            logger.info("[PHASE_COORDINATOR] Starting PHASE 1: File Indexing")
            if progress_callback:
                progress_callback(1, 'running', 'Indexing files in parallel...')
            
            from processing_index import index_all_files_in_queue
            
            index_result = index_all_files_in_queue(case_id)
            
            if index_result['status'] == 'success':
                result['phases_completed'].append('indexing')
                result['stats']['indexing'] = {
                    'total_files': index_result['total_files'],
                    'indexed': index_result['indexed'],
                    'skipped': index_result['skipped'],
                    'failed': index_result['failed']
                }
                logger.info(f"[PHASE_COORDINATOR] ✓ PHASE 1 complete: {index_result['indexed']} files indexed")
                
                if progress_callback:
                    progress_callback(1, 'completed', f"Indexed {index_result['indexed']} files")
            else:
                result['phases_failed'].append('indexing')
                result['errors'].extend(index_result.get('errors', ['Indexing phase failed']))
                logger.error(f"[PHASE_COORDINATOR] ✗ PHASE 1 failed")
                
                if progress_callback:
                    progress_callback(1, 'failed', 'Indexing phase failed')
                
                # Don't continue if indexing failed
                result['status'] = 'error'
                result['duration'] = time.time() - start_time
                return result
            
            # ===================================================================
            # PHASE 2: SIGMA DETECTION
            # ===================================================================
            logger.info("[PHASE_COORDINATOR] Starting PHASE 2: SIGMA Detection")
            if progress_callback:
                progress_callback(2, 'running', 'Running SIGMA detection on EVTX files...')
            
            from processing_sigma import sigma_detect_all_files
            
            sigma_result = sigma_detect_all_files(case_id)
            
            if sigma_result['status'] == 'success':
                result['phases_completed'].append('sigma')
                result['stats']['sigma'] = {
                    'total_files': sigma_result['total_files'],
                    'processed': sigma_result['processed'],
                    'violations': sigma_result['total_violations'],
                    'skipped': sigma_result['skipped'],
                    'failed': sigma_result['failed']
                }
                logger.info(f"[PHASE_COORDINATOR] ✓ PHASE 2 complete: {sigma_result['total_violations']} violations found")
                
                if progress_callback:
                    progress_callback(2, 'completed', f"Found {sigma_result['total_violations']} SIGMA violations")
            else:
                result['phases_failed'].append('sigma')
                result['errors'].extend(sigma_result.get('errors', ['SIGMA phase failed']))
                logger.warning(f"[PHASE_COORDINATOR] ⚠ PHASE 2 failed (continuing)")
                
                if progress_callback:
                    progress_callback(2, 'failed', 'SIGMA phase failed')
            
            # ===================================================================
            # PHASE 3: HIDE KNOWN-GOOD EVENTS
            # ===================================================================
            logger.info("[PHASE_COORDINATOR] Starting PHASE 3: Hide Known-Good Events")
            if progress_callback:
                progress_callback(3, 'running', 'Filtering known-good events...')
            
            from events_known_good import hide_known_good_events, has_exclusions_configured
            
            if has_exclusions_configured():
                known_good_result = hide_known_good_events(
                    case_id=case_id,
                    progress_callback=lambda status, processed, total, found: 
                        progress_callback(3, 'running', f'Scanning events: {processed}/{total}') if progress_callback else None
                )
                
                if known_good_result['success']:
                    result['phases_completed'].append('known_good')
                    result['stats']['known_good'] = {
                        'scanned': known_good_result['total_scanned'],
                        'hidden': known_good_result['total_hidden']
                    }
                    logger.info(f"[PHASE_COORDINATOR] ✓ PHASE 3 complete: {known_good_result['total_hidden']} events hidden")
                    
                    if progress_callback:
                        progress_callback(3, 'completed', f"Hidden {known_good_result['total_hidden']} known-good events")
                else:
                    result['phases_failed'].append('known_good')
                    result['errors'].extend(known_good_result.get('errors', ['Known-good phase failed']))
                    logger.warning(f"[PHASE_COORDINATOR] ⚠ PHASE 3 failed (continuing)")
                    
                    if progress_callback:
                        progress_callback(3, 'failed', 'Known-good filtering failed')
            else:
                logger.info("[PHASE_COORDINATOR] No known-good exclusions configured, skipping PHASE 3")
                result['phases_completed'].append('known_good')
                result['stats']['known_good'] = {'scanned': 0, 'hidden': 0}
                
                if progress_callback:
                    progress_callback(3, 'skipped', 'No exclusions configured')
            
            # ===================================================================
            # PHASE 4: HIDE KNOWN-NOISE EVENTS
            # ===================================================================
            logger.info("[PHASE_COORDINATOR] Starting PHASE 4: Hide Known-Noise Events")
            if progress_callback:
                progress_callback(4, 'running', 'Filtering known-noise events...')
            
            from events_known_noise import hide_noise_events
            
            noise_result = hide_noise_events(
                case_id=case_id,
                progress_callback=lambda status, processed, total, found:
                    progress_callback(4, 'running', f'Scanning events: {processed}/{total}') if progress_callback else None
            )
            
            if noise_result['success']:
                result['phases_completed'].append('known_noise')
                result['stats']['known_noise'] = {
                    'scanned': noise_result['total_scanned'],
                    'hidden': noise_result['total_hidden'],
                    'by_category': noise_result.get('by_category', {})
                }
                logger.info(f"[PHASE_COORDINATOR] ✓ PHASE 4 complete: {noise_result['total_hidden']} events hidden")
                
                if progress_callback:
                    progress_callback(4, 'completed', f"Hidden {noise_result['total_hidden']} noise events")
            else:
                result['phases_failed'].append('known_noise')
                result['errors'].extend(noise_result.get('errors', ['Known-noise phase failed']))
                logger.warning(f"[PHASE_COORDINATOR] ⚠ PHASE 4 failed (continuing)")
                
                if progress_callback:
                    progress_callback(4, 'failed', 'Known-noise filtering failed')
            
            # ===================================================================
            # PHASE 5: IOC MATCHING
            # ===================================================================
            logger.info("[PHASE_COORDINATOR] Starting PHASE 5: IOC Matching")
            if progress_callback:
                progress_callback(5, 'running', 'Matching IOCs across all events...')
            
            from processing_ioc import match_all_iocs
            
            ioc_result = match_all_iocs(case_id)
            
            if ioc_result['status'] == 'success':
                result['phases_completed'].append('ioc_matching')
                result['stats']['ioc_matching'] = {
                    'total_iocs': ioc_result['total_iocs'],
                    'matched': ioc_result['matched'],
                    'total_matches': ioc_result['total_matches'],
                    'skipped': ioc_result['skipped'],
                    'failed': ioc_result['failed']
                }
                logger.info(f"[PHASE_COORDINATOR] ✓ PHASE 5 complete: {ioc_result['total_matches']} IOC matches found")
                
                if progress_callback:
                    progress_callback(5, 'completed', f"Found {ioc_result['total_matches']} IOC matches")
            else:
                result['phases_failed'].append('ioc_matching')
                result['errors'].extend(ioc_result.get('errors', ['IOC phase failed']))
                logger.warning(f"[PHASE_COORDINATOR] ⚠ PHASE 5 failed (continuing)")
                
                if progress_callback:
                    progress_callback(5, 'failed', 'IOC matching failed')
            
            # ===================================================================
            # FINALIZATION: Mark all files as completed
            # ===================================================================
            logger.info("[PHASE_COORDINATOR] Finalizing: Marking files as completed")
            
            from models import CaseFile
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
            
            logger.info(f"[PHASE_COORDINATOR] ✓ Marked {len(files)} files as completed")
            
            # ===================================================================
            # FINAL STATUS
            # ===================================================================
            result['duration'] = time.time() - start_time
            
            if result['phases_failed']:
                result['status'] = 'partial'
                logger.warning(f"[PHASE_COORDINATOR] ⚠ Processing completed with errors: {len(result['phases_failed'])} phases failed")
            else:
                result['status'] = 'success'
                logger.info(f"[PHASE_COORDINATOR] ✓ All phases completed successfully in {result['duration']:.1f}s")
            
            logger.info("="*80)
            logger.info(f"[PHASE_COORDINATOR] Summary:")
            logger.info(f"  - Phases completed: {len(result['phases_completed'])}")
            logger.info(f"  - Phases failed: {len(result['phases_failed'])}")
            logger.info(f"  - Total duration: {result['duration']:.1f}s")
            logger.info("="*80)
            
            return result
            
        except Exception as e:
            logger.error(f"[PHASE_COORDINATOR] Fatal error: {e}", exc_info=True)
            result['status'] = 'error'
            result['errors'].append(str(e))
            result['duration'] = time.time() - start_time
            return result


# ==============================================================================
# CELERY TASK: Run Phased Processing (Async)
# ==============================================================================

from celery_app import celery_app

@celery_app.task(bind=True, name='phase_coordinator.run_phased_processing_task')
def run_phased_processing_task(self, case_id: int) -> Dict[str, Any]:
    """
    Celery task wrapper for run_phased_processing.
    
    This allows phased processing to be run asynchronously in the background.
    
    Args:
        case_id: Case ID to process
        
    Returns:
        Same as run_phased_processing()
    """
    logger.info(f"[PHASE_TASK] Starting phased processing task for case {case_id}")
    
    # Run phased processing synchronously (within this task)
    result = run_phased_processing(case_id)
    
    logger.info(f"[PHASE_TASK] Phased processing complete: {result['status']}")
    
    return result


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def get_processing_status(case_id: int) -> Dict[str, Any]:
    """
    Get current processing status for a case.
    
    Args:
        case_id: Case ID to check
        
    Returns:
        dict: {
            'indexing_complete': bool,
            'sigma_complete': bool,
            'ioc_complete': bool,
            'total_files': int,
            'indexed_files': int,
            'pending_files': int,
            'failed_files': int
        }
    """
    from main import app, db
    from models import CaseFile
    from processing_index import is_indexing_complete
    from processing_sigma import is_sigma_complete
    from processing_ioc import is_ioc_matching_complete
    
    with app.app_context():
        total_files = CaseFile.query.filter_by(
            case_id=case_id,
            is_deleted=False,
            is_hidden=False
        ).count()
        
        indexed_files = CaseFile.query.filter_by(
            case_id=case_id,
            is_indexed=True,
            is_deleted=False,
            is_hidden=False
        ).count()
        
        pending_files = CaseFile.query.filter_by(
            case_id=case_id,
            is_indexed=False,
            is_deleted=False,
            is_hidden=False
        ).filter(
            CaseFile.indexing_status.in_(['Queued'])
        ).count()
        
        failed_files = CaseFile.query.filter_by(
            case_id=case_id,
            is_deleted=False,
            is_hidden=False
        ).filter(
            CaseFile.indexing_status.like('Failed%')
        ).count()
        
        return {
            'indexing_complete': is_indexing_complete(case_id),
            'sigma_complete': is_sigma_complete(case_id),
            'ioc_complete': is_ioc_matching_complete(case_id),
            'total_files': total_files,
            'indexed_files': indexed_files,
            'pending_files': pending_files,
            'failed_files': failed_files
        }

