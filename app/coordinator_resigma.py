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

def resigma_files(case_id: int, file_ids: Optional[List[int]] = None, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
    """
    Re-run SIGMA detection on files in a case.
    
    Args:
        case_id: Case ID to process
        file_ids: Optional list of specific file IDs. If None, process all EVTX files.
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
    from main import app, db
    from models import CaseFile
    
    start_time = time.time()
    result = {
        'status': 'success',
        'phases_completed': [],
        'phases_failed': [],
        'stats': {},
        'errors': [],
        'duration': 0
    }
    
    mode = 'all EVTX files' if file_ids is None else f'{len(file_ids)} files'
    
    logger.info("="*80)
    logger.info(f"[RESIGMA_COORDINATOR] Starting SIGMA re-detection for case {case_id} ({mode})")
    logger.info("="*80)
    
    with app.app_context():
        try:
            # ===============================================================
            # PHASE 0: QUEUE FILES FOR RE-SIGMA
            # ===============================================================
            logger.info("[RESIGMA_COORDINATOR] PHASE 0: Queuing files for SIGMA...")
            if progress_callback:
                progress_callback(0, 'running', 'Queuing files...')
            
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
            if progress_callback:
                progress_callback(0, 'complete', f'Queued {len(files)} files')
            
            # ===============================================================
            # PHASE 1: CLEAR SIGMA METADATA ONLY
            # ===============================================================
            logger.info("[RESIGMA_COORDINATOR] PHASE 1: Clearing SIGMA data...")
            if progress_callback:
                progress_callback(1, 'running', 'Clearing old SIGMA data...')
            
            from processing_clear_metadata import clear_all_queued_files
            
            clear_result = clear_all_queued_files(case_id, clear_type='sigma')
            
            if clear_result['status'] in ['success', 'partial']:
                result['phases_completed'].append('clear_sigma')
                result['stats']['clear_sigma'] = clear_result
                logger.info(f"[RESIGMA_COORDINATOR] ✓ PHASE 1 complete: Cleared SIGMA data from {clear_result['cleared']} files")
                if progress_callback:
                    progress_callback(1, 'complete', f"Cleared {clear_result['cleared']} files")
            else:
                result['phases_failed'].append('clear_sigma')
                result['errors'].extend(clear_result.get('errors', ['Clearing failed']))
                result['status'] = 'error'
                result['duration'] = time.time() - start_time
                if progress_callback:
                    progress_callback(1, 'failed', 'Clearing failed')
                return result
            
            # ===============================================================
            # PHASE 2: RUN SIGMA DETECTION
            # ===============================================================
            logger.info("[RESIGMA_COORDINATOR] PHASE 2: Running SIGMA detection...")
            if progress_callback:
                progress_callback(2, 'running', 'Running SIGMA detection...')
            
            from processing_sigma import sigma_detect_all_files
            
            sigma_result = sigma_detect_all_files(case_id)
            
            if sigma_result['status'] == 'success':
                result['phases_completed'].append('sigma')
                result['stats']['sigma'] = sigma_result
                logger.info(f"[RESIGMA_COORDINATOR] ✓ PHASE 2 complete: {sigma_result['total_violations']} violations found")
                if progress_callback:
                    progress_callback(2, 'complete', f"Found {sigma_result['total_violations']} violations")
            else:
                result['phases_failed'].append('sigma')
                result['errors'].extend(sigma_result.get('errors', ['SIGMA failed']))
                result['status'] = 'error'
                if progress_callback:
                    progress_callback(2, 'failed', 'SIGMA detection failed')
            
            # ===============================================================
            # FINALIZE
            # ===============================================================
            from tasks import commit_with_retry
            
            # Re-query files from database to get fresh status
            # (Don't use stale 'files' variable from line 80-95)
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
            
            result['duration'] = time.time() - start_time
            
            if result['phases_failed']:
                result['status'] = 'partial'
            
            logger.info("="*80)
            logger.info(f"[RESIGMA_COORDINATOR] Complete: {len(result['phases_completed'])} phases succeeded, {len(result['phases_failed'])} failed")
            logger.info(f"[RESIGMA_COORDINATOR] Duration: {result['duration']:.1f}s")
            logger.info("="*80)
            
            return result
            
        except Exception as e:
            logger.error(f"[RESIGMA_COORDINATOR] Fatal error: {e}", exc_info=True)
            result['status'] = 'error'
            result['errors'].append(str(e))
            result['duration'] = time.time() - start_time
            return result


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

