#!/usr/bin/env python3
"""
CaseScope Coordinator: Re-run IOC Matching
===========================================

Handles re-running IOC matching (all, selected files, or single file).

This coordinator runs when users want to re-match IOCs after adding/updating them.

Workflow:
1. Files are queued (could be all, selected, or single file)
2. Clear IOC metadata only (processing_clear_metadata.py - 'ioc' type)
3. Run IOC matching (processing_ioc.py)

Note: IOC matching is case-level (not per-file), but we still use the queue
to track which files have been processed.

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

def reioc_files(case_id: int, file_ids: Optional[List[int]] = None, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
    """
    Re-run IOC matching for files in a case.
    
    Args:
        case_id: Case ID to process
        file_ids: Optional list of specific file IDs. If None, match across all files.
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
    
    mode = 'all files' if file_ids is None else f'{len(file_ids)} files'
    
    logger.info("="*80)
    logger.info(f"[REIOC_COORDINATOR] Starting IOC re-matching for case {case_id} ({mode})")
    logger.info("="*80)
    
    with app.app_context():
        try:
            # ===============================================================
            # PHASE 0: QUEUE FILES FOR RE-IOC
            # ===============================================================
            logger.info("[REIOC_COORDINATOR] PHASE 0: Queuing files for IOC matching...")
            if progress_callback:
                progress_callback(0, 'running', 'Queuing files...')
            
            if file_ids is None:
                # Re-IOC all indexed files
                files = CaseFile.query.filter_by(
                    case_id=case_id,
                    is_indexed=True,
                    is_deleted=False,
                    is_hidden=False
                ).all()
            else:
                # Re-IOC specific files
                files = CaseFile.query.filter(
                    CaseFile.id.in_(file_ids),
                    CaseFile.case_id == case_id,
                    CaseFile.is_deleted == False,
                    CaseFile.is_indexed == True
                ).all()
            
            # No need to change indexing_status - IOC matching is separate
            
            logger.info(f"[REIOC_COORDINATOR] Processing {len(files)} files for IOC matching")
            if progress_callback:
                progress_callback(0, 'completed', f'Queued {len(files)} files')
            
            # ===============================================================
            # PHASE 1: CLEAR IOC METADATA ONLY
            # ===============================================================
            logger.info("[REIOC_COORDINATOR] PHASE 1: Clearing IOC data...")
            if progress_callback:
                progress_callback(1, 'running', 'Clearing old IOC data...')
            
            from processing_clear_metadata import clear_specific_files
            
            # Clear IOC data for specific files (or all if file_ids is None)
            if file_ids is None:
                # For all files, we can use a more efficient approach
                # Delete all IOCMatches for this case
                from models import IOCMatch
                deleted_count = db.session.query(IOCMatch).filter_by(case_id=case_id).delete()
                db.session.commit()
                
                # Reset all file IOC counts
                for f in files:
                    f.ioc_event_count = 0
                db.session.commit()
                
                clear_result = {
                    'status': 'success',
                    'cleared': len(files),
                    'total_ioc_matches_deleted': deleted_count,
                    'errors': []
                }
                logger.info(f"[REIOC_COORDINATOR] Cleared {deleted_count} IOC matches from all files")
            else:
                # Clear specific files
                clear_result = clear_specific_files(case_id, file_ids)
            
            if clear_result['status'] in ['success', 'partial']:
                result['phases_completed'].append('clear_ioc')
                result['stats']['clear_ioc'] = clear_result
                logger.info(f"[REIOC_COORDINATOR] ✓ PHASE 1 complete: Cleared IOC data")
                if progress_callback:
                    progress_callback(1, 'completed', 'Cleared IOC data')
            else:
                result['phases_failed'].append('clear_ioc')
                result['errors'].extend(clear_result.get('errors', ['Clearing failed']))
                result['status'] = 'error'
                result['duration'] = time.time() - start_time
                if progress_callback:
                    progress_callback(1, 'failed', 'Clearing failed')
                return result
            
            # ===============================================================
            # PHASE 2: RUN IOC MATCHING
            # ===============================================================
            logger.info("[REIOC_COORDINATOR] PHASE 2: Running IOC matching...")
            if progress_callback:
                progress_callback(2, 'running', 'Matching IOCs...')
            
            from processing_ioc import hunt_iocs_all_files
            
            # Run IOC hunting on all queued files
            ioc_result = hunt_iocs_all_files(case_id)
            
            if ioc_result['status'] == 'success':
                result['phases_completed'].append('ioc_matching')
                result['stats']['ioc_matching'] = ioc_result
                logger.info(f"[REIOC_COORDINATOR] ✓ PHASE 2 complete: {ioc_result['total_matches']} matches found")
                if progress_callback:
                    progress_callback(2, 'completed', f"Found {ioc_result['total_matches']} matches")
            else:
                result['phases_failed'].append('ioc_matching')
                result['errors'].extend(ioc_result.get('errors', ['IOC matching failed']))
                result['status'] = 'error'
                if progress_callback:
                    progress_callback(2, 'failed', 'IOC matching failed')
            
            # ===============================================================
            # FINALIZE
            # ===============================================================
            from tasks import commit_with_retry
            
            logger.info("[REIOC_COORDINATOR] Finalizing: marking files as completed...")
            
            # Re-query files from database to get fresh status
            # Mark all IOC Complete files as fully Completed
            files_to_finalize = db.session.query(CaseFile).filter(
                CaseFile.case_id == case_id,
                CaseFile.is_deleted == False,
                CaseFile.indexing_status == 'IOC Complete'
            ).all()
            
            for f in files_to_finalize:
                f.indexing_status = 'Completed'
            
            commit_with_retry(db.session, logger_instance=logger)
            logger.info(f"[REIOC_COORDINATOR] Marked {len(files_to_finalize)} files as completed")
            
            result['duration'] = time.time() - start_time
            
            if result['phases_failed']:
                result['status'] = 'partial'
            
            logger.info("="*80)
            logger.info(f"[REIOC_COORDINATOR] Complete: {len(result['phases_completed'])} phases succeeded, {len(result['phases_failed'])} failed")
            logger.info(f"[REIOC_COORDINATOR] Duration: {result['duration']:.1f}s")
            logger.info("="*80)
            
            return result
            
        except Exception as e:
            logger.error(f"[REIOC_COORDINATOR] Fatal error: {e}", exc_info=True)
            result['status'] = 'error'
            result['errors'].append(str(e))
            result['duration'] = time.time() - start_time
            return result


# ==============================================================================
# CELERY TASK: Run Async
# ==============================================================================

@celery_app.task(bind=True, name='coordinator_ioc.reioc_files_task')
def reioc_files_task(self, case_id: int, file_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Celery task wrapper for reioc_files.
    
    Args:
        case_id: Case ID to process
        file_ids: Optional list of file IDs
        
    Returns:
        Same as reioc_files()
    """
    mode = 'all files' if file_ids is None else f'{len(file_ids)} files'
    logger.info(f"[REIOC_COORDINATOR_TASK] Starting for case {case_id} ({mode})")
    result = reioc_files(case_id, file_ids)
    logger.info(f"[REIOC_COORDINATOR_TASK] Complete: {result['status']}")
    return result

