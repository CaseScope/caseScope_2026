"""
Reindex Routes (Modular)
Handles bulk, selected, and single file reindexing operations
Follows pattern from route_ioc_hunt.py
"""

from flask import Blueprint, jsonify, request, redirect, url_for, flash
from flask_login import login_required, current_user
from main import db, opensearch_client
from models import CaseFile, Case
from bulk_operations import clear_case_data_for_reindex, queue_file_processing
from tasks import process_file
from celery_health import check_workers_available
from utils import make_index_name
import logging
import time

logger = logging.getLogger(__name__)

reindex_bp = Blueprint('reindex', __name__)


@reindex_bp.route('/case/<int:case_id>/reindex/all', methods=['POST'])
@login_required
def reindex_all(case_id):
    """
    Re-index ALL visible files in a case.
    Clears all metadata and rebuilds from scratch.
    """
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot reindex'}), 403
    
    # Safety check: Ensure Celery workers are available
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        return jsonify({'success': False, 'error': f'No Celery workers available: {error_msg}'}), 503
    
    # Verify case exists
    case = Case.query.get_or_404(case_id)
    
    # Archive guard
    from archive_utils import is_case_archived
    if is_case_archived(case):
        return jsonify({'success': False, 'error': 'Cannot re-index archived case'}), 403
    
    # Get all visible files
    files = CaseFile.query.filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False
    ).all()
    
    if not files:
        return jsonify({'success': False, 'error': 'No files to reindex'}), 400
    
    try:
        logger.info(f"[REINDEX ALL] Starting for case {case_id}, {len(files)} files")
        file_ids = [f.id for f in files]
        
        # Clear all metadata
        clear_result = clear_case_data_for_reindex(db, case_id, file_ids)
        
        # Delete OpenSearch index entirely (will be recreated)
        index_name = make_index_name(case_id)
        try:
            if opensearch_client.indices.exists(index=index_name):
                opensearch_client.indices.delete(index=index_name)
                logger.info(f"[REINDEX ALL] Deleted index {index_name}")
        except Exception as e:
            logger.warning(f"[REINDEX ALL] Could not delete index: {e}")
        
        # Reset file metadata
        for file in files:
            file.error_message = None
            file.celery_task_id = None
            file.event_count = 0
            file.violation_count = 0
            file.ioc_event_count = 0
        
        db.session.commit()
        
        # Queue files for reindexing
        queued = queue_file_processing(process_file, files, operation='reindex', db_session=db.session)
        
        # Audit log
        from audit_logger import log_action
        log_action('reindex_all', resource_type='file', resource_id=None,
                  resource_name=f'{len(files)} files',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'file_count': len(files),
                      'queued': queued,
                      'cleared': clear_result
                  })
        
        logger.info(f"[REINDEX ALL] Queued {queued} files for case {case_id}")
        return jsonify({'success': True, 'queued': queued, 'file_count': len(files)})
        
    except Exception as e:
        logger.error(f"[REINDEX ALL] Error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@reindex_bp.route('/case/<int:case_id>/reindex/selected', methods=['POST'])
@login_required
def reindex_selected(case_id):
    """
    Re-index SELECTED files.
    Clears metadata for selected files only and rebuilds.
    """
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot reindex'}), 403
    
    # Safety check
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        return jsonify({'success': False, 'error': f'No Celery workers available: {error_msg}'}), 503
    
    # Verify case exists
    case = Case.query.get_or_404(case_id)
    
    # Archive guard
    from archive_utils import is_case_archived
    if is_case_archived(case):
        return jsonify({'success': False, 'error': 'Cannot re-index archived case'}), 403
    
    # Get file IDs from request
    wants_json = request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    file_ids = request.form.getlist('file_ids', type=int) if not wants_json else request.get_json().get('file_ids', [])
    
    if not file_ids:
        return jsonify({'success': False, 'error': 'No files selected'}), 400
    
    # Get selected files
    files = CaseFile.query.filter(
        CaseFile.id.in_(file_ids),
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False
    ).all()
    
    if not files:
        return jsonify({'success': False, 'error': 'No valid files found'}), 404
    
    try:
        logger.info(f"[REINDEX SELECTED] Starting for case {case_id}, {len(files)} files")
        
        # Clear metadata for selected files
        clear_result = clear_case_data_for_reindex(db, case_id, file_ids)
        
        # Delete OpenSearch events for these files (not entire index)
        index_name = make_index_name(case_id)
        total_deleted = 0
        
        if opensearch_client.indices.exists(index=index_name):
            for file in files:
                try:
                    result = opensearch_client.delete_by_query(
                        index=index_name,
                        body={"query": {"term": {"file_id": file.id}}},
                        conflicts='proceed',
                        ignore=[404]
                    )
                    deleted = result.get('deleted', 0) if isinstance(result, dict) else 0
                    total_deleted += deleted
                except Exception as e:
                    logger.warning(f"[REINDEX SELECTED] Could not delete events for file {file.id}: {e}")
        
        # Reset file metadata
        for file in files:
            file.error_message = None
            file.celery_task_id = None
            file.event_count = 0
            file.violation_count = 0
            file.ioc_event_count = 0
        
        db.session.commit()
        
        # Queue files for reindexing
        queued = queue_file_processing(process_file, files, operation='reindex', db_session=db.session)
        
        # Audit log
        from audit_logger import log_action
        log_action('reindex_selected', resource_type='file', resource_id=None,
                  resource_name=f'{len(files)} files',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'file_count': len(files),
                      'queued': queued,
                      'events_deleted': total_deleted,
                      'cleared': clear_result
                  })
        
        logger.info(f"[REINDEX SELECTED] Queued {queued} files, deleted {total_deleted} events")
        return jsonify({
            'success': True,
            'queued': queued,
            'file_count': len(files),
            'events_deleted': total_deleted
        })
        
    except Exception as e:
        logger.error(f"[REINDEX SELECTED] Error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@reindex_bp.route('/case/<int:case_id>/file/<int:file_id>/reindex', methods=['POST'])
@login_required
def reindex_single(case_id, file_id):
    """
    Re-index a SINGLE file.
    Clears metadata for one file and rebuilds.
    """
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot reindex'}), 403
    
    # Safety check
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        return jsonify({'success': False, 'error': f'No Celery workers available: {error_msg}'}), 503
    
    # Get the file
    file = CaseFile.query.get_or_404(file_id)
    
    # Verify file belongs to case
    if file.case_id != case_id:
        return jsonify({'success': False, 'error': 'File not found in this case'}), 404
    
    # Archive guard
    from archive_utils import is_case_archived
    if is_case_archived(file.case):
        return jsonify({'success': False, 'error': 'Cannot re-index file from archived case'}), 403
    
    try:
        logger.info(f"[REINDEX SINGLE] Starting for file {file_id} ({file.original_filename})")
        
        # Clear metadata for this file
        clear_result = clear_case_data_for_reindex(db, case_id, [file_id])
        
        # Delete OpenSearch events for this file
        index_name = make_index_name(case_id)
        events_deleted = 0
        
        if opensearch_client.indices.exists(index=index_name):
            try:
                result = opensearch_client.delete_by_query(
                    index=index_name,
                    body={"query": {"term": {"file_id": file_id}}},
                    conflicts='proceed',
                    ignore=[404]
                )
                events_deleted = result.get('deleted', 0) if isinstance(result, dict) else 0
            except Exception as e:
                logger.warning(f"[REINDEX SINGLE] Could not delete events: {e}")
        
        # Reset file metadata
        file.error_message = None
        file.celery_task_id = None
        file.event_count = 0
        file.violation_count = 0
        file.ioc_event_count = 0
        
        db.session.commit()
        
        # Queue file for reindexing
        queued = queue_file_processing(process_file, [file], operation='reindex', db_session=db.session)
        
        # Audit log
        from audit_logger import log_action
        log_action('reindex_single', resource_type='file', resource_id=file_id,
                  resource_name=file.original_filename,
                  details={
                      'case_id': case_id,
                      'case_name': file.case.name,
                      'events_deleted': events_deleted,
                      'cleared': clear_result
                  })
        
        logger.info(f"[REINDEX SINGLE] Queued file {file_id}, deleted {events_deleted} events")
        return jsonify({
            'success': True,
            'queued': queued,
            'events_deleted': events_deleted
        })
        
    except Exception as e:
        logger.error(f"[REINDEX SINGLE] Error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
