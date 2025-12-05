#!/usr/bin/env python3
"""
CaseScope Coordinator: Re-run SIGMA Detection
==============================================

Handles re-running SIGMA detection on files (all, selected, or single).

This coordinator runs when users want to re-run SIGMA after updating rules.

Workflow:
1. Files are queued (could be all, selected, or single file)
2. Clear SIGMA metadata only (processing_clear_metadata.py - 'sigma' type)
3. Run SIGMA detection (processing_sigma.py)

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

def resigma_files(case_id: int, file_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Re-run SIGMA detection on files in a case.
    
    Args:
        case_id: Case ID to process
        file_ids: Optional list of specific file IDs. If None, process all EVTX files.
        
    Returns:
        dict: {
            'status': 'success'|'error',
            'violations': int,
            'files_processed': int,
            'duration': float
        }
    """
    import time
    from main import app, db
    from models import CaseFile
    from progress_tracker import start_progress, update_phase, complete_progress
    
    start_time = time.time()
    mode = 'all EVTX files' if file_ids is None else f'{len(file_ids)} files'
    
    logger.info("="*80)
    logger.info(f"[RESIGMA_COORDINATOR] Starting SIGMA re-detection for case {case_id} ({mode})")
    logger.info("="*80)
    
    # Start progress tracking
    start_progress(case_id, 'resigma', total_phases=3, description=f'Re-running SIGMA on {mode}')
    
    with app.app_context():
        try:
            # ===============================================================
            # PHASE 0: QUEUE FILES FOR RE-SIGMA
            # ===============================================================
            logger.info("[RESIGMA_COORDINATOR] PHASE 0: Queuing files for SIGMA...")
            update_phase(case_id, 'resigma', 0, 'Queueing Files', 'running', 'Selecting files...')
            
            if file_ids is None:
                # Re-SIGMA all EVTX files
                files = CaseFile.query.filter_by(
                    case_id=case_id,
                    is_indexed=True,
                    is_deleted=False,
                    is_hidden=False
                ).filter(
                    CaseFile.original_filename.ilike('%.evtx')
                ).all()
            else:
                # Re-SIGMA specific files
                files = CaseFile.query.filter(
                    CaseFile.id.in_(file_ids),
                    CaseFile.case_id == case_id,
                    CaseFile.is_deleted == False,
                    CaseFile.is_indexed == True
                ).all()
            
            # Mark files for re-SIGMA (keep indexed status, just update to trigger SIGMA)
            for f in files:
                f.indexing_status = 'Indexed'  # Reset to post-index state
            
            db.session.commit()
            
            logger.info(f"[RESIGMA_COORDINATOR] Queued {len(files)} files for SIGMA")
            update_phase(case_id, 'resigma', 0, 'Queueing Files', 'completed', f'Queued {len(files)} files')
            
            # ===============================================================
            # PHASE 1: CLEAR SIGMA METADATA ONLY
            # ===============================================================
            logger.info("[RESIGMA_COORDINATOR] PHASE 1: Clearing SIGMA data...")
            update_phase(case_id, 'resigma', 1, 'Clearing Data', 'running', 'Clearing old SIGMA data...')
            
            from processing_clear_metadata import clear_all_queued_files
            
            clear_result = clear_all_queued_files(case_id, clear_type='sigma')
            
            if clear_result['status'] in ['success', 'partial']:
                logger.info(f"[RESIGMA_COORDINATOR] ✓ PHASE 1 complete: Cleared SIGMA data from {clear_result['cleared']} files")
                update_phase(case_id, 'resigma', 1, 'Clearing Data', 'completed', f"Cleared {clear_result['cleared']} files")
            else:
                logger.error("[RESIGMA_COORDINATOR] ✗ PHASE 1 failed: Clearing failed")
                update_phase(case_id, 'resigma', 1, 'Clearing Data', 'failed', 'Clearing failed')
                complete_progress(case_id, 'resigma', success=False, error_message='Clearing failed')
                return {
                    'status': 'error',
                    'error': 'Clearing failed',
                    'duration': time.time() - start_time
                }
            
            # ===============================================================
            # PHASE 2: RUN SIGMA DETECTION
            # ===============================================================
            logger.info("[RESIGMA_COORDINATOR] PHASE 2: Running SIGMA detection...")
            update_phase(case_id, 'resigma', 2, 'SIGMA Detection', 'running', 'Running SIGMA rules...')
            
            from processing_sigma import sigma_detect_all_files
            
            sigma_result = sigma_detect_all_files(case_id, operation='resigma', phase_num=2)
            
            if sigma_result['status'] == 'success':
                logger.info(f"[RESIGMA_COORDINATOR] ✓ PHASE 2 complete: {sigma_result['total_violations']} violations found")
                update_phase(case_id, 'resigma', 2, 'SIGMA Detection', 'completed', f"Found {sigma_result['total_violations']} violations")
            else:
                logger.error("[RESIGMA_COORDINATOR] ✗ PHASE 2 failed: SIGMA detection failed")
                update_phase(case_id, 'resigma', 2, 'SIGMA Detection', 'failed', 'SIGMA detection failed')
                complete_progress(case_id, 'resigma', success=False, error_message='SIGMA detection failed')
                return {
                    'status': 'error',
                    'error': 'SIGMA detection failed',
                    'duration': time.time() - start_time
                }
            
            # ===============================================================
            # FINALIZE
            # ===============================================================
            logger.info("[RESIGMA_COORDINATOR] Finalizing...")
            update_phase(case_id, 'resigma', 3, 'Finalization', 'running', 'Marking files as completed...')
            from tasks import commit_with_retry
            
            # Re-query files from database to get fresh status
            # (Don't use stale 'files' variable from line 80-95)
            # Include 'SIGMA Complete' (processed) AND 'Indexed' (skipped 0-event files)
            files_to_finalize = db.session.query(CaseFile).filter(
                CaseFile.case_id == case_id,
                CaseFile.is_deleted == False,
                CaseFile.indexing_status.in_(['SIGMA Complete', 'Indexed'])
            ).all()
            
            # Mark files as completed
            for f in files_to_finalize:
                f.indexing_status = 'Completed'
            
            commit_with_retry(db.session, logger_instance=logger)
            logger.info(f"[RESIGMA_COORDINATOR] Marked {len(files_to_finalize)} files as completed")
            
            update_phase(case_id, 'resigma', 3, 'Finalization', 'completed', f'Finalized {len(files_to_finalize)} files')
            complete_progress(case_id, 'resigma', success=True)
            
            duration = time.time() - start_time
            
            logger.info("="*80)
            logger.info(f"[RESIGMA_COORDINATOR] Complete: All phases succeeded")
            logger.info(f"[RESIGMA_COORDINATOR] Duration: {duration:.1f}s")
            logger.info("="*80)
            
            return {
                'status': 'success',
                'violations': sigma_result.get('total_violations', 0),
                'files_processed': sigma_result.get('processed', 0),
                'duration': duration
            }
            
        except Exception as e:
            logger.error(f"[RESIGMA_COORDINATOR] Fatal error: {e}", exc_info=True)
            complete_progress(case_id, 'resigma', success=False, error_message=str(e))
            return {
                'status': 'error',
                'error': str(e),
                'duration': time.time() - start_time
            }


# ==============================================================================
# CELERY TASK: Run Async
# ==============================================================================

@celery_app.task(bind=True, name='coordinator_resigma.resigma_files_task')
def resigma_files_task(self, case_id: int, file_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Celery task wrapper for resigma_files.
    
    Args:
        case_id: Case ID to process
        file_ids: Optional list of file IDs
        
    Returns:
        Same as resigma_files()
    """
    mode = 'all EVTX files' if file_ids is None else f'{len(file_ids)} files'
    logger.info(f"[RESIGMA_COORDINATOR_TASK] Starting for case {case_id} ({mode})")
    
    logger.info(f"[RESIGMA_COORDINATOR_TASK] About to call resigma_files()...")
    result = resigma_files(case_id, file_ids)
    logger.info(f"[RESIGMA_COORDINATOR_TASK] resigma_files() returned")
    logger.info(f"[RESIGMA_COORDINATOR_TASK] Complete: {result['status']}")
    return result

