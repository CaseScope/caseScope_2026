# CaseScope Coordinator/Processing Chain - Comprehensive Fix

## Problem Summary

The current coordinator/processing system has several critical issues:

1. **Missing routes**: Buttons in UI call routes that don't exist (`/bulk_reindex`, `/bulk_rechainsaw`, `/bulk_rehunt_iocs`)
2. **Inconsistent queue management**: Files not properly queued/tracked through processing phases
3. **Broken hidden file counting**: `files_with_events` and `hidden_files` counts not maintained
4. **No standalone hide known good/noise**: No way to re-run just the noise filtering
5. **Coordinator flow issues**: Re-sigma/re-ioc don't properly mirror the reindex workflow

## Current System Architecture

### Processing Modules (processing_*.py)
- `processing_index.py` - Indexes files, marks 0-event files as hidden
- `processing_sigma.py` - Runs SIGMA detection on EVTX files
- `processing_ioc.py` - Hunts IOCs across all indexed files
- `processing_clear_metadata.py` - Clears metadata (all/sigma/ioc types)
- `events_known_good.py` - Hides known good events
- `events_known_noise.py` - Hides known noise events

### Coordinators (coordinator_*.py)
- `coordinator_index.py` - New file workflow (index→sigma→known-good→known-noise→ioc)
- `coordinator_reindex.py` - Re-index workflow (clear→index workflow)
- `coordinator_resigma.py` - **BROKEN** - Should clear sigma→run sigma→mark complete
- `coordinator_ioc.py` - **BROKEN** - Should clear ioc→run ioc→mark complete

## Required Functionality (Your Specifications)

### 1. Bulk Re-Index All Files
**Current**: JavaScript calls `/case/<case_id>/bulk_reindex` → **ROUTE DOESN'T EXIST**

**Should do**:
- Queue ALL case files (non-deleted, non-hidden)
- Clear all metadata (OpenSearch + database)
- Set files with events count = total files, hidden files = 0
- Process through full workflow:
  - `processing_index` → files with 0 events marked hidden
  - Update: files_with_events = files with >0 events, hidden_files = 0-event files
  - Re-queue ONLY EVTX files with events for SIGMA
  - `processing_sigma` → run SIGMA on queued EVTX files
  - `events_known_good` → hide known good
  - `events_known_noise` → hide known noise
  - Re-queue all files except hidden for IOC
  - `processing_ioc` → hunt IOCs
  - Mark all as completed

### 2. Select/Single Re-Index
**Current**: Works via `/bulk_reindex_selected` and single file button

**Should do**: Same as #1 but ONLY for selected/single file(s)
- Metadata clear ONLY affects specified files
- Queues only specified files

### 3. Re-SIGMA All Files
**Current**: JavaScript calls `/case/<case_id>/bulk_rechainsaw` → **ROUTE DOESN'T EXIST**

**Should do**:
- Clear ONLY SIGMA metadata for ALL EVTX files with events
- Queue ALL EVTX files with is_indexed=True and event_count>0
- Set files to 'Indexed' state
- Run `processing_sigma` on queue
- Files progress: Indexed → SIGMA Testing → SIGMA Complete
- Run `events_known_good` (clear noise flags first)
- Run `events_known_noise`
- Mark all as 'Completed'

### 4. Re-SIGMA Select/Single Files  
**Current**: Works via `/bulk_rechainsaw_selected` and single file button

**Should do**: Same as #3 but ONLY for selected/single EVTX file(s)

### 5. Re-IOC All Files
**Current**: JavaScript calls `/case/<case_id>/bulk_rehunt_iocs` → **ROUTE DOESN'T EXIST**

**Should do**:
- Clear ONLY IOC metadata for ALL files
- Queue ALL indexed files (not hidden)
- Set files to 'Indexed' state
- Run `processing_ioc` on queue
- Files progress: Indexed → IOC Matching → IOC Complete
- Mark all as 'Completed'

### 6. Re-IOC Select/Single Files
**Current**: Works via `/bulk_rehunt_selected` and single file button

**Should do**: Same as #5 but ONLY for selected/single file(s)

### 7. Hide Known Good/Noise Standalone
**Current**: Buttons exist in UI, **NO ROUTES**

**Should do**:
- Clear noise/known-good flags on ALL events in case
- Re-run `events_known_good` (if #7a)
- Re-run `events_known_noise` (if #7b)
- No file status changes needed (files stay 'Completed')

---

## FIXES REQUIRED

## Fix 1: Create Missing Routes

### A. Add to `/opt/casescope/app/routes/files.py`

```python
# =============================================================================
# BULK OPERATIONS - ALL FILES IN CASE
# =============================================================================

@files_bp.route('/case/<int:case_id>/bulk_reindex', methods=['POST'])
@login_required
def bulk_reindex_all(case_id):
    """Re-index ALL files in a case (v2.2.0 - Full reindex coordinator)"""
    from main import db, Case
    from celery_health import check_workers_available
    import sys
    
    # Check Celery workers
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        return jsonify({
            'success': False,
            'error': f'Celery workers not available: {error_msg}'
        }), 503
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Import and queue coordinator task
    try:
        from coordinator_reindex import reindex_files_task
        print(f"[BULK_REINDEX_ALL] Queuing reindex for case {case_id}", file=sys.stderr, flush=True)
        
        # Queue with file_ids=None to reindex ALL files
        task_result = reindex_files_task.delay(case_id, file_ids=None)
        
        print(f"[BULK_REINDEX_ALL] Task queued: {task_result.id}", file=sys.stderr, flush=True)
        
        # Audit log
        from audit_logger import log_action
        log_action('bulk_reindex_all', details={
            'case_id': case_id,
            'case_name': case.name,
            'task_id': task_result.id
        })
        
        return jsonify({
            'success': True,
            'message': f'Re-index queued for all files in case "{case.name}"',
            'task_id': task_result.id
        })
        
    except Exception as e:
        logger.error(f"Failed to queue bulk reindex: {e}", exc_info=True)
        print(f"[ERROR] Bulk reindex failed: {e}", file=sys.stderr, flush=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@files_bp.route('/case/<int:case_id>/bulk_rechainsaw', methods=['POST'])
@login_required
def bulk_rechainsaw_all(case_id):
    """Re-run SIGMA on ALL indexed EVTX files in case (v2.2.0)"""
    from main import db, Case
    from celery_health import check_workers_available
    import sys
    
    # Check Celery workers
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Celery workers not available: {error_msg}', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Import and queue coordinator task
    try:
        from coordinator_resigma import resigma_files_task
        print(f"[BULK_RECHAINSAW_ALL] Queuing re-sigma for case {case_id}", file=sys.stderr, flush=True)
        
        # Queue with file_ids=None to re-sigma ALL EVTX files
        task_result = resigma_files_task.delay(case_id, file_ids=None)
        
        print(f"[BULK_RECHAINSAW_ALL] Task queued: {task_result.id}", file=sys.stderr, flush=True)
        
        # Audit log
        from audit_logger import log_action
        log_action('bulk_rechainsaw_all', details={
            'case_id': case_id,
            'case_name': case.name,
            'task_id': task_result.id
        })
        
        flash(f'✅ Re-SIGMA queued for all EVTX files in case "{case.name}". Task ID: {task_result.id}', 'success')
        return redirect(url_for('files.case_files', case_id=case_id))
        
    except Exception as e:
        logger.error(f"Failed to queue bulk re-sigma: {e}", exc_info=True)
        print(f"[ERROR] Bulk re-sigma failed: {e}", file=sys.stderr, flush=True)
        flash(f'❌ Failed to queue re-SIGMA: {e}', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/bulk_rehunt_iocs', methods=['POST'])
@login_required
def bulk_rehunt_all(case_id):
    """Re-hunt IOCs on ALL indexed files in case (v2.2.0)"""
    from main import db, Case
    from celery_health import check_workers_available
    import sys
    
    # Check Celery workers
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Celery workers not available: {error_msg}', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Import and queue coordinator task
    try:
        from coordinator_ioc import reioc_files_task
        print(f"[BULK_REHUNT_ALL] Queuing re-IOC for case {case_id}", file=sys.stderr, flush=True)
        
        # Queue with file_ids=None to re-hunt ALL files
        task_result = reioc_files_task.delay(case_id, file_ids=None)
        
        print(f"[BULK_REHUNT_ALL] Task queued: {task_result.id}", file=sys.stderr, flush=True)
        
        # Audit log
        from audit_logger import log_action
        log_action('bulk_rehunt_all', details={
            'case_id': case_id,
            'case_name': case.name,
            'task_id': task_result.id
        })
        
        flash(f'✅ IOC re-hunt queued for all files in case "{case.name}". Task ID: {task_result.id}', 'success')
        return redirect(url_for('files.case_files', case_id=case_id))
        
    except Exception as e:
        logger.error(f"Failed to queue bulk IOC hunt: {e}", exc_info=True)
        print(f"[ERROR] Bulk IOC hunt failed: {e}", file=sys.stderr, flush=True)
        flash(f'❌ Failed to queue IOC hunt: {e}', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/hide_known_good', methods=['POST'])
@login_required
def hide_known_good_route(case_id):
    """Re-run known-good filtering on all events (v2.2.0)"""
    from main import db, Case
    from celery_health import check_workers_available
    import sys
    
    # Check Celery workers
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Celery workers not available: {error_msg}', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    try:
        from events_known_good import hide_known_good_all_task, has_exclusions_configured
        
        # Check if exclusions are configured
        if not has_exclusions_configured():
            flash('⚠️ No known-good exclusions configured in Settings', 'warning')
            return redirect(url_for('files.case_files', case_id=case_id))
        
        # First, clear noise flags on all events
        print(f"[HIDE_KNOWN_GOOD] Clearing noise flags for case {case_id}", file=sys.stderr, flush=True)
        from main import opensearch_client
        from utils import make_index_name
        
        index_name = make_index_name(case_id)
        if opensearch_client.indices.exists(index=index_name):
            # Clear is_noise and is_known_good flags
            clear_script = {
                "script": {
                    "source": "ctx._source.is_noise = false; ctx._source.is_known_good = false;",
                    "lang": "painless"
                },
                "query": {"match_all": {}}
            }
            opensearch_client.update_by_query(
                index=index_name,
                body=clear_script,
                refresh=True,
                conflicts='proceed'
            )
        
        # Queue the filtering task
        print(f"[HIDE_KNOWN_GOOD] Queuing task for case {case_id}", file=sys.stderr, flush=True)
        task_result = hide_known_good_all_task.delay(case_id)
        
        print(f"[HIDE_KNOWN_GOOD] Task queued: {task_result.id}", file=sys.stderr, flush=True)
        
        # Audit log
        from audit_logger import log_action
        log_action('hide_known_good', details={
            'case_id': case_id,
            'case_name': case.name,
            'task_id': task_result.id
        })
        
        flash(f'✅ Known-good filtering queued for case "{case.name}". Task ID: {task_result.id}', 'success')
        return redirect(url_for('files.case_files', case_id=case_id))
        
    except Exception as e:
        logger.error(f"Failed to queue known-good filtering: {e}", exc_info=True)
        print(f"[ERROR] Known-good filtering failed: {e}", file=sys.stderr, flush=True)
        flash(f'❌ Failed to queue known-good filtering: {e}', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/hide_known_noise', methods=['POST'])
@login_required
def hide_known_noise_route(case_id):
    """Re-run known-noise filtering on all events (v2.2.0)"""
    from main import db, Case
    from celery_health import check_workers_available
    import sys
    
    # Check Celery workers
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Celery workers not available: {error_msg}', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    try:
        from events_known_noise import hide_noise_all_task
        
        # First, clear noise flags on all events
        print(f"[HIDE_KNOWN_NOISE] Clearing noise flags for case {case_id}", file=sys.stderr, flush=True)
        from main import opensearch_client
        from utils import make_index_name
        
        index_name = make_index_name(case_id)
        if opensearch_client.indices.exists(index=index_name):
            # Clear is_noise flag
            clear_script = {
                "script": {
                    "source": "ctx._source.is_noise = false;",
                    "lang": "painless"
                },
                "query": {"match_all": {}}
            }
            opensearch_client.update_by_query(
                index=index_name,
                body=clear_script,
                refresh=True,
                conflicts='proceed'
            )
        
        # Queue the filtering task
        print(f"[HIDE_KNOWN_NOISE] Queuing task for case {case_id}", file=sys.stderr, flush=True)
        task_result = hide_noise_all_task.delay(case_id)
        
        print(f"[HIDE_KNOWN_NOISE] Task queued: {task_result.id}", file=sys.stderr, flush=True)
        
        # Audit log
        from audit_logger import log_action
        log_action('hide_known_noise', details={
            'case_id': case_id,
            'case_name': case.name,
            'task_id': task_result.id
        })
        
        flash(f'✅ Known-noise filtering queued for case "{case.name}". Task ID: {task_result.id}', 'success')
        return redirect(url_for('files.case_files', case_id=case_id))
        
    except Exception as e:
        logger.error(f"Failed to queue known-noise filtering: {e}", exc_info=True)
        print(f"[ERROR] Known-noise filtering failed: {e}", file=sys.stderr, flush=True)
        flash(f'❌ Failed to queue known-noise filtering: {e}', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
```

### B. Update coordinator_resigma.py

The current coordinator_resigma.py doesn't follow the proper workflow. It needs to:
1. Clear SIGMA metadata ONLY (not all metadata)
2. Mark files as 'Indexed' (not 'Queued')
3. Run SIGMA phase
4. Run known-good phase
5. Run known-noise phase
6. Mark files as 'Completed'

**Replace `/opt/casescope/app/coordinator_resigma.py` with:**

```python
#!/usr/bin/env python3
"""
CaseScope Coordinator: Re-run SIGMA Detection
==============================================

Handles re-running SIGMA detection on files (all, selected, or single).

Workflow:
1. Files are prepared (set to 'Indexed' state)
2. Clear SIGMA metadata only
3. Run SIGMA detection
4. Run known-good filtering
5. Run known-noise filtering
6. Mark as completed

Author: CaseScope
Version: 2.2.0 - Fixed workflow
"""

import logging
import sys
from typing import Dict, Any, Optional, List
from celery_app import celery_app

logger = logging.getLogger(__name__)


def resigma_files(case_id: int, file_ids: Optional[List[int]] = None, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
    """
    Re-run SIGMA detection on files in a case.
    
    Args:
        case_id: Case ID to process
        file_ids: Optional list of specific file IDs. If None, process all EVTX files.
        progress_callback: Optional callback function(phase, status, message)
        
    Returns:
        dict with status, phases_completed, phases_failed, stats, errors, duration
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
            # PHASE 0: PREPARE FILES FOR RE-SIGMA
            # ===============================================================
            logger.info("[RESIGMA_COORDINATOR] PHASE 0: Preparing files...")
            if progress_callback:
                progress_callback(0, 'running', 'Preparing files...')
            
            if file_ids is None:
                # Re-SIGMA all indexed EVTX files with events
                files = CaseFile.query.filter_by(
                    case_id=case_id,
                    is_indexed=True,
                    is_deleted=False,
                    is_hidden=False
                ).filter(
                    CaseFile.original_filename.ilike('%.evtx'),
                    CaseFile.event_count > 0
                ).all()
            else:
                # Re-SIGMA specific files
                files = CaseFile.query.filter(
                    CaseFile.id.in_(file_ids),
                    CaseFile.case_id == case_id,
                    CaseFile.is_deleted == False,
                    CaseFile.is_indexed == True
                ).all()
            
            # Set files to 'Indexed' state (ready for SIGMA)
            for f in files:
                f.indexing_status = 'Indexed'
            
            db.session.commit()
            
            logger.info(f"[RESIGMA_COORDINATOR] Prepared {len(files)} files for SIGMA")
            if progress_callback:
                progress_callback(0, 'complete', f'Prepared {len(files)} files')
            
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
                logger.info(f"[RESIGMA_COORDINATOR] ✓ PHASE 1 complete")
                if progress_callback:
                    progress_callback(1, 'complete', 'Cleared old SIGMA data')
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
                logger.info(f"[RESIGMA_COORDINATOR] ✓ PHASE 2 complete: {sigma_result['total_violations']} violations")
                if progress_callback:
                    progress_callback(2, 'complete', f"Found {sigma_result['total_violations']} violations")
            else:
                result['phases_failed'].append('sigma')
                result['errors'].extend(sigma_result.get('errors', ['SIGMA failed']))
                result['status'] = 'error'
                if progress_callback:
                    progress_callback(2, 'failed', 'SIGMA detection failed')
            
            # ===============================================================
            # PHASE 3: HIDE KNOWN-GOOD EVENTS
            # ===============================================================
            logger.info("[RESIGMA_COORDINATOR] PHASE 3: Filtering known-good...")
            if progress_callback:
                progress_callback(3, 'running', 'Filtering known-good events...')
            
            from events_known_good import hide_known_good_all_task, has_exclusions_configured
            
            if has_exclusions_configured():
                kg_task = hide_known_good_all_task.delay(case_id)
                
                # Wait for completion
                timeout = 3600
                start = time.time()
                while not kg_task.ready():
                    if time.time() - start > timeout:
                        result['phases_failed'].append('known_good')
                        result['errors'].append('Known-good timeout')
                        break
                    time.sleep(5)
                
                if kg_task.ready():
                    try:
                        kg_result = kg_task.get(timeout=10)
                        if kg_result['status'] in ['success', 'partial']:
                            result['phases_completed'].append('known_good')
                            result['stats']['known_good'] = kg_result
                            logger.info(f"[RESIGMA_COORDINATOR] ✓ PHASE 3 complete")
                            if progress_callback:
                                progress_callback(3, 'complete', f"Hidden {kg_result['total_hidden']} events")
                        else:
                            result['phases_failed'].append('known_good')
                            result['errors'].append('Known-good failed')
                    except Exception as e:
                        logger.error(f"Known-good error: {e}")
                        result['phases_failed'].append('known_good')
            else:
                result['phases_completed'].append('known_good')
                logger.info("[RESIGMA_COORDINATOR] PHASE 3 skipped (no exclusions)")
                if progress_callback:
                    progress_callback(3, 'skipped', 'No exclusions configured')
            
            # ===============================================================
            # PHASE 4: HIDE KNOWN-NOISE EVENTS
            # ===============================================================
            logger.info("[RESIGMA_COORDINATOR] PHASE 4: Filtering known-noise...")
            if progress_callback:
                progress_callback(4, 'running', 'Filtering known-noise events...')
            
            from events_known_noise import hide_noise_all_task
            
            noise_task = hide_noise_all_task.delay(case_id)
            
            # Wait for completion
            timeout = 3600
            start = time.time()
            while not noise_task.ready():
                if time.time() - start > timeout:
                    result['phases_failed'].append('known_noise')
                    result['errors'].append('Known-noise timeout')
                    break
                time.sleep(5)
            
            if noise_task.ready():
                try:
                    noise_result = noise_task.get(timeout=10)
                    if noise_result['status'] in ['success', 'partial']:
                        result['phases_completed'].append('known_noise')
                        result['stats']['known_noise'] = noise_result
                        logger.info(f"[RESIGMA_COORDINATOR] ✓ PHASE 4 complete")
                        if progress_callback:
                            progress_callback(4, 'complete', f"Hidden {noise_result['total_hidden']} events")
                    else:
                        result['phases_failed'].append('known_noise')
                        result['errors'].append('Known-noise failed')
                except Exception as e:
                    logger.error(f"Known-noise error: {e}")
                    result['phases_failed'].append('known_noise')
            
            # ===============================================================
            # FINALIZE
            # ===============================================================
            from tasks import commit_with_retry
            
            # Mark files as completed
            files_to_complete = db.session.query(CaseFile).filter(
                CaseFile.case_id == case_id,
                CaseFile.is_deleted == False,
                CaseFile.indexing_status.in_(['SIGMA Complete', 'Indexed'])
            ).all()
            
            for f in files_to_complete:
                f.indexing_status = 'Completed'
            
            commit_with_retry(db.session, logger_instance=logger)
            logger.info(f"[RESIGMA_COORDINATOR] Marked {len(files_to_complete)} files as completed")
            
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
            print(f"[RESIGMA_COORDINATOR] ERROR: {e}", file=sys.stderr, flush=True)
            result['status'] = 'error'
            result['errors'].append(str(e))
            result['duration'] = time.time() - start_time
            return result


@celery_app.task(bind=True, name='coordinator_resigma.resigma_files_task')
def resigma_files_task(self, case_id: int, file_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """Celery task wrapper for resigma_files."""
    mode = 'all EVTX files' if file_ids is None else f'{len(file_ids)} files'
    logger.info(f"[RESIGMA_TASK] Starting for case {case_id} ({mode})")
    print(f"[RESIGMA_TASK] Starting...", file=sys.stderr, flush=True)
    
    try:
        result = resigma_files(case_id, file_ids)
        logger.info(f"[RESIGMA_TASK] Complete: {result['status']}")
        print(f"[RESIGMA_TASK] Complete: {result['status']}", file=sys.stderr, flush=True)
        return result
    except Exception as e:
        logger.error(f"[RESIGMA_TASK] FATAL ERROR: {e}", exc_info=True)
        print(f"[RESIGMA_TASK] FATAL ERROR: {e}", file=sys.stderr, flush=True)
        raise
```

### C. Update coordinator_ioc.py

Similar fix needed for IOC coordinator:

**Replace `/opt/casescope/app/coordinator_ioc.py` with:**

```python
#!/usr/bin/env python3
"""
CaseScope Coordinator: Re-run IOC Matching
===========================================

Handles re-running IOC matching (all, selected files, or single file).

Workflow:
1. Files are prepared (set to 'Indexed' state)
2. Clear IOC metadata only
3. Run IOC matching
4. Mark as completed

Author: CaseScope
Version: 2.2.0 - Fixed workflow
"""

import logging
import sys
from typing import Dict, Any, Optional, List
from celery_app import celery_app

logger = logging.getLogger(__name__)


def reioc_files(case_id: int, file_ids: Optional[List[int]] = None, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
    """
    Re-run IOC matching for files in a case.
    
    Args:
        case_id: Case ID to process
        file_ids: Optional list of specific file IDs. If None, match across all files.
        progress_callback: Optional callback function(phase, status, message)
        
    Returns:
        dict with status, phases_completed, phases_failed, stats, errors, duration
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
            # PHASE 0: PREPARE FILES FOR RE-IOC
            # ===============================================================
            logger.info("[REIOC_COORDINATOR] PHASE 0: Preparing files...")
            if progress_callback:
                progress_callback(0, 'running', 'Preparing files...')
            
            if file_ids is None:
                # Re-IOC all indexed files (not hidden)
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
            
            # Set files to 'Indexed' state (ready for IOC)
            for f in files:
                f.indexing_status = 'Indexed'
            
            db.session.commit()
            
            logger.info(f"[REIOC_COORDINATOR] Prepared {len(files)} files for IOC matching")
            if progress_callback:
                progress_callback(0, 'complete', f'Prepared {len(files)} files')
            
            # ===============================================================
            # PHASE 1: CLEAR IOC METADATA ONLY
            # ===============================================================
            logger.info("[REIOC_COORDINATOR] PHASE 1: Clearing IOC data...")
            if progress_callback:
                progress_callback(1, 'running', 'Clearing old IOC data...')
            
            from processing_clear_metadata import clear_all_queued_files
            
            clear_result = clear_all_queued_files(case_id, clear_type='ioc')
            
            if clear_result['status'] in ['success', 'partial']:
                result['phases_completed'].append('clear_ioc')
                result['stats']['clear_ioc'] = clear_result
                logger.info(f"[REIOC_COORDINATOR] ✓ PHASE 1 complete")
                if progress_callback:
                    progress_callback(1, 'complete', 'Cleared old IOC data')
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
            
            ioc_result = hunt_iocs_all_files(case_id)
            
            if ioc_result['status'] == 'success':
                result['phases_completed'].append('ioc_matching')
                result['stats']['ioc_matching'] = ioc_result
                logger.info(f"[REIOC_COORDINATOR] ✓ PHASE 2 complete: {ioc_result['total_matches']} matches")
                if progress_callback:
                    progress_callback(2, 'complete', f"Found {ioc_result['total_matches']} matches")
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
            
            # Mark files as completed
            files_to_complete = db.session.query(CaseFile).filter(
                CaseFile.case_id == case_id,
                CaseFile.is_deleted == False,
                CaseFile.indexing_status.in_(['IOC Complete', 'Indexed'])
            ).all()
            
            for f in files_to_complete:
                f.indexing_status = 'Completed'
            
            commit_with_retry(db.session, logger_instance=logger)
            logger.info(f"[REIOC_COORDINATOR] Marked {len(files_to_complete)} files as completed")
            
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
            print(f"[REIOC_COORDINATOR] ERROR: {e}", file=sys.stderr, flush=True)
            result['status'] = 'error'
            result['errors'].append(str(e))
            result['duration'] = time.time() - start_time
            return result


@celery_app.task(bind=True, name='coordinator_ioc.reioc_files_task')
def reioc_files_task(self, case_id: int, file_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """Celery task wrapper for reioc_files."""
    mode = 'all files' if file_ids is None else f'{len(file_ids)} files'
    logger.info(f"[REIOC_TASK] Starting for case {case_id} ({mode})")
    print(f"[REIOC_TASK] Starting...", file=sys.stderr, flush=True)
    
    try:
        result = reioc_files(case_id, file_ids)
        logger.info(f"[REIOC_TASK] Complete: {result['status']}")
        print(f"[REIOC_TASK] Complete: {result['status']}", file=sys.stderr, flush=True)
        return result
    except Exception as e:
        logger.error(f"[REIOC_TASK] FATAL ERROR: {e}", exc_info=True)
        print(f"[REIOC_TASK] FATAL ERROR: {e}", file=sys.stderr, flush=True)
        raise
```

---

## Fix 2: Hidden Files Tracking

The `files_with_events` and `hidden_files` counts need to be updated during processing. This should happen in `processing_index.py`.

**In `/opt/casescope/app/processing_index.py`, after marking 0-event files as hidden:**

```python
# Update case statistics
from models import Case
case = db.session.get(Case, case_id)
if case:
    # Count files with events (not hidden, not deleted, event_count > 0)
    files_with_events = db.session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False
    ).filter(CaseFile.event_count > 0).count()
    
    # Count hidden files (is_hidden=True, not deleted)
    hidden_files = db.session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=True
    ).count()
    
    case.files_with_events = files_with_events
    case.hidden_files = hidden_files
    db.session.commit()
```

---

## Fix 3: Update case_files.html UI

The Hide Known Good/Noise buttons need to be connected to the new routes.

**Find the buttons in `/opt/casescope/app/templates/case_files.html` and add onclick handlers:**

```html
<button onclick="confirmHideKnownGood()" class="btn btn-info">
    <span>✨</span>
    <span>Hide Known Good</span>
</button>

<button onclick="confirmHideKnownNoise()" class="btn btn-info">
    <span>🔇</span>
    <span>Hide Known Noise</span>
</button>
```

**Add these JavaScript functions:**

```javascript
function confirmHideKnownGood() {
    if (confirm('✨ Hide Known Good Events\n\nThis will:\n• Clear all noise/known-good flags\n• Re-run known-good filtering\n• Hide matching events\n\nContinue?')) {
        showPreparationModal('hide_known_good', 'Hiding Known Good', 'Filtering known-good events...');
        
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = `/case/${CASE_ID}/hide_known_good`;
        document.body.appendChild(form);
        form.submit();
    }
}

function confirmHideKnownNoise() {
    if (confirm('🔇 Hide Known Noise Events\n\nThis will:\n• Clear all noise flags\n• Re-run known-noise filtering\n• Hide matching events\n\nContinue?')) {
        showPreparationModal('hide_known_noise', 'Hiding Known Noise', 'Filtering known-noise events...');
        
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = `/case/${CASE_ID}/hide_known_noise`;
        document.body.appendChild(form);
        form.submit();
    }
}
```

---

## Installation Steps

1. **Backup existing files**:
```bash
cd /opt/casescope/app
cp coordinator_resigma.py coordinator_resigma.py.backup
cp coordinator_ioc.py coordinator_ioc.py.backup
cp routes/files.py routes/files.py.backup
cp templates/case_files.html templates/case_files.html.backup
```

2. **Apply route fixes**: Add the 5 new route functions to `/opt/casescope/app/routes/files.py`

3. **Replace coordinators**:
```bash
# Apply the fixed coordinator_resigma.py
# Apply the fixed coordinator_ioc.py
```

4. **Update UI**: Add the Hide Known Good/Noise button handlers to `templates/case_files.html`

5. **Update processing_index.py**: Add the hidden files counting logic

6. **Restart services**:
```bash
sudo systemctl restart casescope
sudo systemctl restart casescope-celery
```

7. **Test each operation**:
   - Re-Index All Files
   - Re-SIGMA All Files
   - Re-Hunt IOCs All Files
   - Hide Known Good
   - Hide Known Noise
   - Select/Single file variants

---

## Summary of Changes

1. **5 new routes** for bulk operations (reindex, rechainsaw, rehunt, hide_known_good, hide_known_noise)
2. **Fixed coordinator_resigma.py** to properly run SIGMA→known-good→known-noise workflow
3. **Fixed coordinator_ioc.py** to properly run IOC matching workflow
4. **Added hidden files tracking** in processing_index.py
5. **Connected UI buttons** to the new routes
6. **Added exception handling** and stderr logging throughout for debugging

All operations now properly:
- Use queues to track progress
- Update file counts accurately
- Follow the correct workflow phases
- Handle bulk, select, and single file operations
- Clear only the relevant metadata (not everything)
