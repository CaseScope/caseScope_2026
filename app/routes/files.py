"""
Files Blueprint - Case file management routes
Handles file listing, hidden files, bulk operations
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import logging

logger = logging.getLogger(__name__)

files_bp = Blueprint('files', __name__)


@files_bp.route('/files/global')
@login_required
def global_files():
    """Global File Management - All files across all cases"""
    from main import db, Case, CaseFile
    from sqlalchemy import func, or_
    
    # Pagination and search
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '', type=str).strip()
    per_page = 50
    
    # Base query: all visible files
    files_query = db.session.query(CaseFile).filter_by(
        is_deleted=False,
        is_hidden=False
    )
    
    # Apply search filter
    if search_term:
        search_filter = or_(
            CaseFile.original_filename.ilike(f'%{search_term}%'),
            CaseFile.file_hash.ilike(f'%{search_term}%')
        )
        files_query = files_query.filter(search_filter)
    
    files_query = files_query.order_by(CaseFile.uploaded_at.desc())
    pagination = files_query.paginate(page=page, per_page=per_page, error_out=False)
    files = pagination.items
    
    # Global stats
    all_visible = db.session.query(CaseFile).filter_by(is_deleted=False, is_hidden=False)
    total_files = all_visible.count()
    hidden_files = db.session.query(CaseFile).filter_by(is_deleted=False, is_hidden=True).count()
    
    total_space_bytes = db.session.query(func.sum(CaseFile.file_size)).filter_by(
        is_deleted=False, is_hidden=False
    ).scalar() or 0
    
    total_events = db.session.query(func.sum(CaseFile.event_count)).filter_by(
        is_deleted=False, is_hidden=False
    ).scalar() or 0
    
    sigma_events = db.session.query(func.sum(CaseFile.violation_count)).filter_by(
        is_deleted=False, is_hidden=False
    ).scalar() or 0
    
    ioc_events = db.session.query(func.sum(CaseFile.ioc_event_count)).filter_by(
        is_deleted=False, is_hidden=False
    ).scalar() or 0
    
    # File type breakdown
    file_types = {}
    for f in all_visible.all():
        ft = f.file_type or 'Unknown'
        file_types[ft] = file_types.get(ft, 0) + 1
    
    # Processing state counts
    known_statuses = ['Completed', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Queued']
    files_completed = all_visible.filter_by(indexing_status='Completed').count()
    files_queued = all_visible.filter_by(indexing_status='Queued').count()
    files_indexing = all_visible.filter_by(indexing_status='Indexing').count()
    files_sigma = all_visible.filter_by(indexing_status='SIGMA Testing').count()
    files_ioc_hunting = all_visible.filter_by(indexing_status='IOC Hunting').count()
    files_failed = all_visible.filter(~CaseFile.indexing_status.in_(known_statuses)).count()
    
    return render_template('global_files.html',
                          files=files,
                          pagination=pagination,
                          search_term=search_term,
                          total_files=total_files,
                          hidden_files=hidden_files,
                          total_space_gb=total_space_bytes / (1024**3),
                          file_types=file_types,
                          total_events=total_events,
                          total_sigma_events=sigma_events,
                          total_ioc_events=ioc_events,
                          files_completed=files_completed,
                          files_queued=files_queued,
                          files_indexing=files_indexing,
                          files_sigma=files_sigma,
                          files_ioc_hunting=files_ioc_hunting,
                          files_failed=files_failed)


@files_bp.route('/case/<int:case_id>/files')
@login_required
def case_files(case_id):
    """Case Files Management Page with Pagination and Search"""
    from main import db, Case, CaseFile
    from hidden_files import get_hidden_files_count, get_file_stats_with_hidden
    from sqlalchemy import func, or_
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Pagination and search
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '', type=str).strip()
    per_page = 50
    
    # Get visible files only (exclude hidden and deleted)
    files_query = db.session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False
    )
    
    # Apply search filter if provided
    if search_term:
        search_filter = or_(
            CaseFile.original_filename.ilike(f'%{search_term}%'),
            CaseFile.file_hash.ilike(f'%{search_term}%')
        )
        files_query = files_query.filter(search_filter)
    
    files_query = files_query.order_by(CaseFile.uploaded_at.desc())
    
    # File type breakdown - get ALL files (visible + hidden) to match "Completed" count
    all_files_query = db.session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False
    )
    # Apply same search filter if provided
    if search_term:
        search_filter = or_(
            CaseFile.original_filename.ilike(f'%{search_term}%'),
            CaseFile.file_hash.ilike(f'%{search_term}%')
        )
        all_files_query = all_files_query.filter(search_filter)
    
    all_files = all_files_query.all()
    file_types = {}
    for f in all_files:
        ft = f.file_type or 'Unknown'
        file_types[ft] = file_types.get(ft, 0) + 1
    
    pagination = files_query.paginate(page=page, per_page=per_page, error_out=False)
    files = pagination.items
    
    # Fetch uploader usernames for display
    from models import User
    for file in files:
        if file.uploaded_by:
            uploader = db.session.get(User, file.uploaded_by)
            if uploader:
                file.uploader_name = uploader.full_name or uploader.username
            else:
                file.uploader_name = f'User #{file.uploaded_by}'
        else:
            file.uploader_name = 'System'
    
    # Get comprehensive stats (includes hidden count)
    stats = get_file_stats_with_hidden(db.session, case_id)
    
    # Get event status counts (new unified system)
    from event_status import get_status_counts
    status_counts = get_status_counts(case_id)
    
    # Calculate "new" count: total events - (hunted + confirmed + noise)
    # Events without a status record are considered "new"
    tracked_events = status_counts.get('hunted', 0) + status_counts.get('confirmed', 0) + status_counts.get('noise', 0)
    status_counts['new'] = max(0, stats['total_events'] - tracked_events)
    
    return render_template('case_files.html',
                          case=case,
                          files=files,
                          pagination=pagination,
                          search_term=search_term,
                          total_files=stats['visible_files'],
                          hidden_files=stats['hidden_files'],
                          total_space_gb=stats['total_space_bytes'] / (1024**3),
                          file_types=file_types,
                          total_events=stats['total_events'],
                          total_sigma_events=stats['sigma_events'],
                          total_ioc_events=stats['ioc_events'],
                          total_hidden_events=stats.get('hidden_events', 0),
                          status_counts=status_counts,
                          files_completed=stats.get('files_completed', 0),
                          files_queued=stats.get('files_queued', 0),
                          files_indexing=stats.get('files_indexing', 0),
                          files_sigma=stats.get('files_sigma', 0),
                          files_ioc_hunting=stats.get('files_ioc_hunting', 0),
                          files_failed=stats.get('files_failed', 0))


@files_bp.route('/case/<int:case_id>/hidden_files')
@login_required
def view_hidden_files(case_id):
    """View hidden files (0-event files) with search support"""
    from main import db, Case
    from hidden_files import get_hidden_files, get_hidden_files_count
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '', type=str).strip()
    per_page = 50
    
    pagination = get_hidden_files(db.session, case_id, page, per_page, search_term)
    hidden_count = get_hidden_files_count(db.session, case_id)
    
    return render_template('hidden_files.html',
                          case=case,
                          files=pagination.items,
                          pagination=pagination,
                          hidden_count=hidden_count,
                          search_term=search_term)


@files_bp.route('/case/<int:case_id>/failed_files')
@login_required
def view_failed_files(case_id):
    """View failed files with search support"""
    from main import db, Case
    from hidden_files import get_failed_files, get_failed_files_count
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '', type=str).strip()
    per_page = 50
    
    pagination = get_failed_files(db.session, case_id, page, per_page, search_term)
    failed_count = get_failed_files_count(db.session, case_id)
    
    return render_template('failed_files.html',
                          case=case,
                          files=pagination.items,
                          pagination=pagination,
                          failed_count=failed_count,
                          search_term=search_term)


@files_bp.route('/case/<int:case_id>/file/<int:file_id>/toggle_hidden', methods=['POST'])
@login_required
def toggle_file_hidden(case_id, file_id):
    """Toggle file hidden status"""
    from main import db
    from hidden_files import toggle_file_visibility
    
    result = toggle_file_visibility(db.session, file_id, current_user.id)
    
    if result['success']:
        # Audit log
        from audit_logger import log_file_action
        from main import CaseFile
        case_file = db.session.get(CaseFile, file_id)
        if case_file:
            log_file_action('toggle_file_hidden', file_id, case_file.original_filename, details={
                'case_id': case_id,
                'case_name': case_file.case.name if case_file.case else None,
                'action': result['action'],
                'is_hidden': case_file.is_hidden
            })
        
        flash(f"File marked as {result['action']}", 'success')
    else:
        flash(result['error'], 'error')
    
    return redirect(request.referrer or url_for('files.case_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/bulk_unhide', methods=['POST'])
@login_required
def bulk_unhide(case_id):
    """Bulk unhide files"""
    from main import db, Case
    from hidden_files import bulk_unhide_files
    
    file_ids = request.form.getlist('file_ids', type=int)
    
    if not file_ids:
        flash('No files selected', 'warning')
        return redirect(url_for('files.view_hidden_files', case_id=case_id))
    
    result = bulk_unhide_files(db.session, case_id, file_ids, current_user.id)
    
    if result['success']:
        # Audit log
        from audit_logger import log_action
        case = db.session.get(Case, case_id)
        log_action('bulk_unhide_files', resource_type='file', resource_id=None,
                  resource_name=f"{case.name if case else f'Case #{case_id}'} - Bulk Unhide",
                  details={'file_count': result['count'], 'case_id': case_id, 'file_ids': file_ids})
        
        flash(f"✓ Unhid {result['count']} file(s)", 'success')
    else:
        flash(result['error'], 'error')
    
    return redirect(url_for('files.view_hidden_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/bulk_delete_hidden', methods=['POST'])
@login_required
def bulk_delete_hidden(case_id):
    """Bulk delete hidden files permanently"""
    from main import db, Case
    from hidden_files import bulk_delete_hidden_files
    
    file_ids = request.form.getlist('file_ids', type=int)
    
    if not file_ids:
        flash('No files selected', 'warning')
        return redirect(url_for('files.view_hidden_files', case_id=case_id))
    
    result = bulk_delete_hidden_files(db.session, case_id, file_ids, current_user.id)
    
    if result['success']:
        # Audit log - CRITICAL: Permanent file deletion
        from audit_logger import log_action
        case = db.session.get(Case, case_id)
        log_action('bulk_delete_hidden_files', resource_type='file', resource_id=None,
                  resource_name=f"{case.name if case else f'Case #{case_id}'} - Bulk Delete Hidden",
                  details={
                      'file_count': result['count'],
                      'case_id': case_id,
                      'file_ids': file_ids,
                      'errors': result.get('errors', []),
                      'operation': 'PERMANENT_DELETE'
                  })
        
        if result.get('errors'):
            flash(f"✓ Deleted {result['count']} file(s) with {len(result['errors'])} error(s)", 'warning')
            for error in result['errors'][:3]:  # Show first 3 errors
                flash(error, 'error')
        else:
            flash(f"✓ Successfully deleted {result['count']} hidden file(s)", 'success')
    else:
        flash(result.get('error', 'Unknown error'), 'error')
    
    return redirect(url_for('files.view_hidden_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/file/<int:file_id>/status')
@login_required
def file_status(case_id, file_id):
    """Get file processing status (AJAX endpoint)"""
    from main import db, CaseFile
    
    file = db.session.get(CaseFile, file_id)
    
    if not file or file.case_id != case_id:
        return jsonify({'error': 'File not found'}), 404
    
    return jsonify({
        'status': file.indexing_status,
        'is_indexed': file.is_indexed,
        'is_hidden': file.is_hidden,
        'event_count': file.event_count,
        'sigma_event_count': file.sigma_event_count,
        'ioc_event_count': file.ioc_event_count
    })


@files_bp.route('/case/<int:case_id>/bulk_import/scan')
@login_required
def bulk_import_scan(case_id):
    """
    Scan bulk import directory and return file counts
    GET endpoint for status check
    """
    from bulk_import import get_bulk_import_stats
    
    stats = get_bulk_import_stats()
    return jsonify(stats)


@files_bp.route('/case/<int:case_id>/bulk_import/start', methods=['POST'])
@login_required
def bulk_import_start(case_id):
    """
    Start bulk import process from local directory
    POST endpoint to trigger Celery task
    """
    from main import db, Case
    from tasks import bulk_import_directory
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Trigger Celery task
    task = bulk_import_directory.delay(case_id)
    
    logger.info(f"[BULK IMPORT] Started task {task.id} for case {case_id}")
    
    return jsonify({
        'status': 'started',
        'task_id': task.id,
        'message': 'Bulk import started'
    })


@files_bp.route('/case/<int:case_id>/bulk_import/status/<task_id>')
@login_required
def bulk_import_status(case_id, task_id):
    """
    Check status of bulk import task
    GET endpoint for progress updates
    """
    from celery.result import AsyncResult
    from celery_app import celery_app
    
    try:
        # Try to create AsyncResult - this might fail if metadata is corrupted
        try:
            task = AsyncResult(task_id, app=celery_app)
        except Exception as e:
            logger.error(f"[BULK IMPORT STATUS] Error creating AsyncResult for {task_id}: {e}")
            # Try to clear corrupted metadata
            try:
                from celery_app import celery_app
                celery_app.backend.delete(task_id)
                logger.info(f"[BULK IMPORT STATUS] Cleared corrupted task metadata for {task_id}")
            except:
                pass
            return jsonify({
                'state': 'ERROR',
                'status': 'Task metadata corrupted - please try again',
                'error': 'Task metadata is corrupted. Please start a new bulk import.',
                'progress': 0
            })
        
        # Safely get task state - catch corruption errors
        try:
            state = task.state
        except (ValueError, KeyError, TypeError) as e:
            # These errors indicate corrupted metadata
            logger.error(f"[BULK IMPORT STATUS] Corrupted task metadata for {task_id}: {e}")
            # Try to clear it
            try:
                celery_app.backend.delete(task_id)
                logger.info(f"[BULK IMPORT STATUS] Cleared corrupted task metadata for {task_id}")
            except:
                pass
            return jsonify({
                'state': 'ERROR',
                'status': 'Task metadata corrupted - please try again',
                'error': 'Task metadata is corrupted. Please start a new bulk import.',
                'progress': 0
            })
        except Exception as e:
            logger.error(f"[BULK IMPORT STATUS] Error getting task state: {e}")
            return jsonify({
                'state': 'UNKNOWN',
                'status': 'Error checking status',
                'error': 'Could not retrieve task state',
                'progress': 0
            })
        
        # Safely get task info
        try:
            task_info = task.info if task.state != 'PENDING' else {}
        except Exception as e:
            logger.warning(f"[BULK IMPORT STATUS] Error getting task info (state: {state}): {e}")
            task_info = {}
        
        if state == 'PENDING':
            response = {
                'state': state,
                'status': 'Waiting to start...',
                'progress': 0
            }
        elif state == 'PROGRESS':
            response = {
                'state': state,
                'status': task_info.get('stage', 'Processing...') if isinstance(task_info, dict) else 'Processing...',
                'progress': task_info.get('progress', 0) if isinstance(task_info, dict) else 0,
                'details': task_info if isinstance(task_info, dict) else {}
            }
        elif state == 'SUCCESS':
            response = {
                'state': state,
                'status': 'Complete',
                'progress': 100,
                'result': task_info if isinstance(task_info, dict) else {}
            }
        elif state == 'FAILURE':
            error_msg = str(task_info) if task_info else 'Unknown error'
            response = {
                'state': state,
                'status': 'Failed',
                'error': error_msg,
                'progress': 0
            }
        else:
            response = {
                'state': state,
                'status': str(state),
                'progress': 0
            }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"[BULK IMPORT STATUS] Unexpected error: {e}", exc_info=True)
        return jsonify({
            'state': 'ERROR',
            'status': 'Error checking status',
            'error': str(e)
        }), 500


@files_bp.route('/case/<int:case_id>/file/<int:file_id>/reindex', methods=['POST'])
@login_required
def reindex_single_file(case_id, file_id):
    """Re-index a single file (clears all data and rebuilds)"""
    from main import db, CaseFile, Case, opensearch_client
    from bulk_operations import clear_file_sigma_violations, clear_file_ioc_matches
    from tasks import process_file
    from index_version import check_index_compatibility, get_compatibility_warning
    import time
    
    # Check if request wants JSON (for modal updates) or redirect (for backward compat)
    wants_json = request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    
    # v1.19.8: Check index compatibility before single file re-index
    is_compatible, current_ver, required_ver = check_index_compatibility(opensearch_client, case_id)
    if not is_compatible:
        warning = get_compatibility_warning(current_ver, required_ver)
        if wants_json:
            return jsonify({
                'success': False,
                'error': 'index_version_mismatch',
                'warning_title': warning['title'],
                'warning_message': warning['message'],
                'case_id': case_id
            }), 409  # 409 Conflict
        flash('⚠️ Index version mismatch detected. Full case re-index required.', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    case_file = db.session.get(CaseFile, file_id)
    
    if not case_file or case_file.case_id != case_id:
        if wants_json:
            return jsonify({'success': False, 'error': 'File not found'}), 404
        flash('File not found', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Archive guard (v1.18.0): Prevent re-indexing archived cases
    from archive_utils import is_case_archived
    case = db.session.get(Case, case_id)
    if case and is_case_archived(case):
        if wants_json:
            return jsonify({'success': False, 'error': 'Cannot re-index archived case'}), 403
        flash('❌ Cannot re-index archived case. Please restore the case first.', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Track steps for modal updates
    steps = []
    start_time = time.time()
    
    # STEP 1: Clear database entries (reset to fresh import state)
    steps.append({'step': 'clearing_db', 'message': 'Clearing database entries', 'status': 'in_progress'})
    case_file.event_count = 0
    case_file.violation_count = 0
    case_file.ioc_event_count = 0
    case_file.is_indexed = False
    case_file.indexing_status = 'Queued'
    case_file.opensearch_key = None
    case_file.celery_task_id = None
    case_file.error_message = None
    clear_file_sigma_violations(db, file_id)
    clear_file_ioc_matches(db, file_id)
    db.session.commit()
    steps[-1]['status'] = 'completed'
    steps[-1]['duration'] = round(time.time() - start_time, 2)
    
    # STEP 2: Clear OpenSearch entries
    step_start = time.time()
    steps.append({'step': 'clearing_opensearch', 'message': 'Clearing OpenSearch entries', 'status': 'in_progress'})
    deleted_count = 0
    if case_file.opensearch_key or True:  # Always try to delete by file_id
        try:
            from utils import make_index_name
            index_name = make_index_name(case_id)  # Gets case index (not per-file)
            
            # Delete events by file_id (not entire index - it's shared by all files)
            result = opensearch_client.delete_by_query(
                index=index_name,
                body={
                    "query": {
                        "term": {"file_id": file_id}
                    }
                },
                conflicts='proceed',
                ignore=[404]
            )
            deleted_count = result.get('deleted', 0) if isinstance(result, dict) else 0
            logger.info(f"[REINDEX SINGLE] Deleted {deleted_count} events for file {file_id} from index {index_name}")
            steps[-1]['status'] = 'completed'
            steps[-1]['deleted_events'] = deleted_count
        except Exception as e:
            logger.warning(f"[REINDEX SINGLE] Could not delete events: {e}")
            steps[-1]['status'] = 'completed'  # Continue anyway
            steps[-1]['warning'] = str(e)[:100]
    else:
        steps[-1]['status'] = 'completed'
        steps[-1]['message'] = 'No OpenSearch data to clear'
    steps[-1]['duration'] = round(time.time() - step_start, 2)
    
    # STEP 3: Build file queue
    step_start = time.time()
    steps.append({'step': 'building_queue', 'message': 'Building file queue', 'status': 'in_progress'})
    
    # Queue for re-indexing (v1.16.25: Use 'reindex' operation to force processing)
    task = process_file.delay(file_id, operation='reindex')
    case_file.celery_task_id = task.id if hasattr(task, 'id') else None
    db.session.commit()
    
    steps[-1]['status'] = 'completed'
    steps[-1]['files_queued'] = 1
    steps[-1]['duration'] = round(time.time() - step_start, 2)
    
    # Audit log
    from audit_logger import log_action
    log_action('reindex_file', resource_type='file', resource_id=file_id,
              resource_name=case_file.original_filename,
              details={'case_id': case_id, 'case_name': case_file.case.name})
    
    total_duration = round(time.time() - start_time, 2)
    
    # Return JSON for modal updates or redirect for backward compatibility
    if wants_json:
        return jsonify({
            'success': True,
            'message': 'Re-indexing queued successfully',
            'steps': steps,
            'total_duration': total_duration,
            'files_queued': 1,
            'events_deleted': deleted_count
        })
    else:
        flash(f'Re-indexing queued for "{case_file.original_filename}". All data will be cleared and rebuilt.', 'success')
        return redirect(url_for('files.case_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/file/<int:file_id>/rechainsaw', methods=['POST'])
@login_required
def rechainsaw_single_file(case_id, file_id):
    """Re-run SIGMA on a single file (clears DB violations and OpenSearch flags first)"""
    from main import db, CaseFile, opensearch_client
    from bulk_operations import clear_file_sigma_violations, clear_file_sigma_flags_in_opensearch
    from file_processing import chainsaw_file
    from models import SigmaRule, SigmaViolation
    
    case_file = db.session.get(CaseFile, file_id)
    
    if not case_file or case_file.case_id != case_id:
        flash('File not found', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    if not case_file.is_indexed:
        flash('File must be indexed before SIGMA testing', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Clear existing violations (database)
    clear_file_sigma_violations(db, file_id)
    
    # CRITICAL: Clear OpenSearch SIGMA flags BEFORE re-running SIGMA
    flags_cleared = clear_file_sigma_flags_in_opensearch(opensearch_client, case_id, case_file)
    logger.info(f"[RECHAINSAW SINGLE] Cleared SIGMA flags from {flags_cleared} events before re-running SIGMA")
    
    case_file.violation_count = 0
    case_file.indexing_status = 'SIGMA Testing'
    db.session.commit()
    
    # Get index name (v1.13.1: consolidated case indices)
    from utils import make_index_name
    index_name = make_index_name(case_id)
    
    # Run chainsaw synchronously (fast operation)
    try:
        result = chainsaw_file(
            db=db,
            opensearch_client=opensearch_client,
            CaseFile=CaseFile,
            SigmaRule=SigmaRule,
            SigmaViolation=SigmaViolation,
            file_id=file_id,
            index_name=index_name
        )
        
        # Audit log
        from audit_logger import log_file_action
        log_file_action('rechainsaw_file', file_id, case_file.original_filename, details={
            'case_id': case_id,
            'case_name': case_file.case.name,
            'violations_found': result.get('violations', 0) if result.get('status') == 'success' else None,
            'flags_cleared': flags_cleared
        })
        
        if result['status'] == 'success':
            # Update status back to Completed
            from tasks import commit_with_retry
            case_file.indexing_status = 'Completed'
            commit_with_retry(db.session, logger_instance=logger)
            flash(f'SIGMA re-processing complete for "{case_file.original_filename}". Found {result.get("violations", 0)} violations.', 'success')
        else:
            from tasks import commit_with_retry
            case_file.indexing_status = f'Failed: {result.get("message", "Unknown error")}'
            commit_with_retry(db.session, logger_instance=logger)
            flash(f'SIGMA re-processing failed: {result.get("message")}', 'error')
    except Exception as e:
        logger.error(f"[RECHAINSAW SINGLE] Error: {e}", exc_info=True)
        from tasks import commit_with_retry
        case_file.indexing_status = f'Failed: {str(e)[:100]}'
        commit_with_retry(db.session, logger_instance=logger)
        flash(f'SIGMA re-processing failed: {str(e)}', 'error')
    
    return redirect(url_for('files.case_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/file/<int:file_id>/rehunt_iocs', methods=['POST'])
@login_required
def rehunt_iocs_single_file(case_id, file_id):
    """Re-hunt IOCs on a single file (clears IOC matches and OpenSearch flags first)"""
    from main import db, CaseFile, opensearch_client
    from bulk_operations import clear_file_ioc_matches
    from file_processing import hunt_iocs
    from models import IOC, IOCMatch
    
    case_file = db.session.get(CaseFile, file_id)
    
    if not case_file or case_file.case_id != case_id:
        flash('File not found', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    if not case_file.is_indexed:
        flash('File must be indexed before IOC hunting', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Clear existing IOC matches (database)
    clear_file_ioc_matches(db, file_id)
    
    # Clear OpenSearch IOC flags
    from utils import make_index_name
    index_name = make_index_name(case_id)
    
    try:
        # Clear has_ioc flags in OpenSearch for this file's events
        from opensearchpy.helpers import scan as opensearch_scan, bulk as opensearch_bulk
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"file_id": file_id}},
                        {"term": {"has_ioc": True}}
                    ]
                }
            },
            "_source": False
        }
        
        actions = []
        cleared_count = 0
        for hit in opensearch_scan(opensearch_client, index=index_name, query=query, scroll='5m'):
            actions.append({
                '_op_type': 'update',
                '_index': index_name,
                '_id': hit['_id'],
                'doc': {
                    'has_ioc': False,
                    'ioc_count': 0,
                    'ioc_details': [],
                    'matched_iocs': []
                }
            })
            
            if len(actions) >= 100:
                success, errors = opensearch_bulk(opensearch_client, actions, raise_on_error=False, raise_on_exception=False)
                if errors:
                    logger.error(f"[REHUNT IOCS SINGLE] Clearing had {len(errors)} errors. First error: {errors[0] if errors else 'N/A'}")
                cleared_count += success
                actions = []
        
        if actions:
            success, errors = opensearch_bulk(opensearch_client, actions, raise_on_error=False, raise_on_exception=False)
            if errors:
                logger.error(f"[REHUNT IOCS SINGLE] Final clearing batch had {len(errors)} errors. First error: {errors[0] if errors else 'N/A'}")
            cleared_count += success
        
        logger.info(f"[REHUNT IOCS SINGLE] ✅ Cleared IOC flags from {cleared_count} events for file {file_id}")
    
    except Exception as e:
        logger.warning(f"[REHUNT IOCS SINGLE] Could not clear OpenSearch IOC flags: {e}")
    
    # Reset IOC count
    case_file.ioc_event_count = 0
    case_file.indexing_status = 'IOC Hunting'
    db.session.commit()
    
    # Run IOC hunting synchronously
    try:
        result = hunt_iocs(
            db=db,
            opensearch_client=opensearch_client,
            CaseFile=CaseFile,
            IOC=IOC,
            IOCMatch=IOCMatch,
            file_id=file_id,
            index_name=index_name
        )
        
        # Audit log
        from audit_logger import log_file_action
        log_file_action('rehunt_iocs_file', file_id, case_file.original_filename, details={
            'case_id': case_id,
            'case_name': case_file.case.name,
            'ioc_matches_found': result.get('matches', 0) if result.get('status') == 'success' else None
        })
        
        if result['status'] == 'success':
            # Update status back to Completed
            from tasks import commit_with_retry
            case_file.indexing_status = 'Completed'
            commit_with_retry(db.session, logger_instance=logger)
            flash(f'IOC re-hunting complete for "{case_file.original_filename}". Found {result.get("matches", 0)} IOC match(es).', 'success')
        else:
            from tasks import commit_with_retry
            case_file.indexing_status = f'Failed: {result.get("message", "Unknown error")}'
            commit_with_retry(db.session, logger_instance=logger)
            flash(f'IOC re-hunting failed: {result.get("message")}', 'error')
    except Exception as e:
        logger.error(f"[REHUNT IOCS SINGLE] Error: {e}", exc_info=True)
        from tasks import commit_with_retry
        case_file.indexing_status = f'Failed: {str(e)[:100]}'
        commit_with_retry(db.session, logger_instance=logger)
        flash(f'IOC re-hunting failed: {str(e)}', 'error')
    
    return redirect(url_for('files.case_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/file/<int:file_id>/details')
@login_required
def file_details(case_id, file_id):
    """View detailed information about a specific file"""
    from main import db, CaseFile, Case
    
    case = db.session.get(Case, case_id)
    case_file = db.session.get(CaseFile, file_id)
    
    if not case or not case_file or case_file.case_id != case_id:
        flash('File not found', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    return render_template('file_details.html',
                          case=case,
                          file=case_file)


@files_bp.route('/case/<int:case_id>/bulk_reindex_selected', methods=['POST'])
@login_required
def bulk_reindex_selected(case_id):
    """Re-index selected files (clears all data and rebuilds)"""
    from main import db, CaseFile, Case, opensearch_client
    from bulk_operations import clear_file_sigma_violations, clear_file_ioc_matches, reset_file_metadata, queue_file_processing
    from tasks import process_file
    from celery_health import check_workers_available
    from index_version import check_index_compatibility, get_compatibility_warning
    import time
    
    # Check if request wants JSON (for modal updates) or redirect (for backward compat)
    wants_json = request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    
    # v1.19.8: Check index compatibility before selected files re-index
    is_compatible, current_ver, required_ver = check_index_compatibility(opensearch_client, case_id)
    if not is_compatible:
        warning = get_compatibility_warning(current_ver, required_ver)
        if wants_json:
            return jsonify({
                'success': False,
                'error': 'index_version_mismatch',
                'warning_title': warning['title'],
                'warning_message': warning['message'],
                'case_id': case_id
            }), 409  # 409 Conflict
        flash('⚠️ Index version mismatch detected. Full case re-index required.', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Archive guard (v1.18.0): Prevent re-indexing archived cases
    from archive_utils import is_case_archived
    case = db.session.get(Case, case_id)
    if case and is_case_archived(case):
        if wants_json:
            return jsonify({'success': False, 'error': 'Cannot re-index archived case'}), 403
        flash('❌ Cannot re-index archived case. Please restore the case first.', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Safety check: Ensure Celery workers are available
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        if wants_json:
            return jsonify({'success': False, 'error': f'No Celery workers available: {error_msg}'}), 503
        flash(f'⚠️ Cannot start bulk operation: {error_msg}. Please check Celery workers.', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    file_ids = request.form.getlist('file_ids', type=int) if not wants_json else request.get_json().get('file_ids', [])
    
    if not file_ids:
        if wants_json:
            return jsonify({'success': False, 'error': 'No files selected'}), 400
        flash('No files selected', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Get all selected files
    files = db.session.query(CaseFile).filter(
        CaseFile.id.in_(file_ids),
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False
    ).all()
    
    if not files:
        if wants_json:
            return jsonify({'success': False, 'error': 'No valid files found'}), 404
        flash('No valid files found', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Track steps for modal updates
    steps = []
    start_time = time.time()
    
    # STEP 1: Clear database entries (reset to fresh import state)
    steps.append({'step': 'clearing_db', 'message': f'Clearing database entries for {len(files)} files', 'status': 'in_progress'})
    for file in files:
        # Reset file metadata (same as import would set)
        reset_file_metadata(file, reset_opensearch_key=True)
        # Also clear error message
        file.error_message = None
        file.celery_task_id = None
        # Clear SIGMA and IOC data
        clear_file_sigma_violations(db, file.id)
        clear_file_ioc_matches(db, file.id)
    
    # v1.46.0: Clear EventStatus records for true fresh start
    from bulk_operations import clear_event_statuses
    statuses_deleted = clear_event_statuses(db, scope='file', case_id=case_id, file_ids=[f.id for f in files])
    
    db.session.commit()
    steps[-1]['status'] = 'completed'
    steps[-1]['files_processed'] = len(files)
    steps[-1]['statuses_deleted'] = statuses_deleted
    steps[-1]['duration'] = round(time.time() - start_time, 2)
    
    # STEP 2: Clear OpenSearch entries
    step_start = time.time()
    steps.append({'step': 'clearing_opensearch', 'message': f'Clearing OpenSearch entries for {len(files)} files', 'status': 'in_progress'})
    total_deleted = 0
    
    from utils import make_index_name
    index_name = make_index_name(case_id)  # Gets case index (shared by all files)
    
    for file in files:
        try:
            # Delete events by file_id (not entire index - it's shared)
            result = opensearch_client.delete_by_query(
                index=index_name,
                body={"query": {"term": {"file_id": file.id}}},
                conflicts='proceed',
                ignore=[404]
            )
            deleted = result.get('deleted', 0) if isinstance(result, dict) else 0
            total_deleted += deleted
        except Exception as e:
            logger.warning(f"[BULK REINDEX SELECTED] Could not delete events for file {file.id}: {e}")
    
    steps[-1]['status'] = 'completed'
    steps[-1]['deleted_events'] = total_deleted
    steps[-1]['duration'] = round(time.time() - step_start, 2)
    
    # STEP 3: Build file queue
    step_start = time.time()
    steps.append({'step': 'building_queue', 'message': f'Building queue for {len(files)} files', 'status': 'in_progress'})
    
    # Queue for re-indexing (v1.16.25: Use 'reindex' operation to force processing)
    queue_file_processing(process_file, files, operation='reindex')
    
    steps[-1]['status'] = 'completed'
    steps[-1]['files_queued'] = len(files)
    steps[-1]['duration'] = round(time.time() - step_start, 2)
    
    # Audit log
    from audit_logger import log_action
    case = db.session.get(Case, case_id)
    log_action('bulk_reindex_files', resource_type='file', resource_id=None,
              resource_name=f'{len(files)} files',
              details={
                  'case_id': case_id,
                  'case_name': case.name if case else None,
                  'file_count': len(files),
                  'file_ids': [f.id for f in files[:10]]  # Log first 10 IDs
              })
    
    total_duration = round(time.time() - start_time, 2)
    
    # Return JSON for modal updates or redirect for backward compatibility
    if wants_json:
        return jsonify({
            'success': True,
            'message': f'Re-indexing queued for {len(files)} files',
            'steps': steps,
            'total_duration': total_duration,
            'files_queued': len(files),
            'events_deleted': total_deleted
        })
    else:
        flash(f'Re-indexing queued for {len(files)} selected file(s). All data will be cleared and rebuilt.', 'success')
        return redirect(url_for('files.case_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/bulk_rechainsaw_selected', methods=['POST'])
@login_required
def bulk_rechainsaw_selected(case_id):
    """Re-run SIGMA on selected files (clears DB violations and OpenSearch flags first)"""
    from main import db, CaseFile, opensearch_client
    from bulk_operations import clear_file_sigma_violations, clear_file_sigma_flags_in_opensearch, queue_file_processing
    from tasks import process_file
    from celery_health import check_workers_available
    
    # Safety check: Ensure Celery workers are available
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Cannot start bulk operation: {error_msg}. Please check Celery workers.', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    file_ids = request.form.getlist('file_ids', type=int)
    
    if not file_ids:
        flash('No files selected', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Get all selected files that are indexed
    files = db.session.query(CaseFile).filter(
        CaseFile.id.in_(file_ids),
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False,
        CaseFile.is_indexed == True
    ).all()
    
    if not files:
        flash('No valid indexed files found', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Clear SIGMA data for each file (database and OpenSearch) and set to Queued status
    total_flags_cleared = 0
    for file in files:
        # Clear database violations
        clear_file_sigma_violations(db, file.id)
        
        # CRITICAL: Clear OpenSearch SIGMA flags BEFORE re-running SIGMA
        flags_cleared = clear_file_sigma_flags_in_opensearch(opensearch_client, case_id, file)
        total_flags_cleared += flags_cleared
        
        file.violation_count = 0
        file.indexing_status = 'Queued'
        file.celery_task_id = None
    
    db.session.commit()
    logger.info(f"[BULK RECHAINSAW SELECTED] Cleared SIGMA flags from {total_flags_cleared} events across {len(files)} files")
    
    # Queue for SIGMA reprocessing
    queue_file_processing(process_file, files, operation='chainsaw_only')
    
    # Audit log
    from audit_logger import log_action
    from main import Case
    case = db.session.get(Case, case_id)
    log_action('bulk_rechainsaw_files', resource_type='file', resource_id=None,
              resource_name=f'{len(files)} files',
              details={
                  'case_id': case_id,
                  'case_name': case.name if case else None,
                  'file_count': len(files),
                  'flags_cleared': total_flags_cleared,
                  'file_ids': [f.id for f in files[:10]]  # Log first 10 IDs
              })
    
    flash(f'SIGMA re-processing queued for {len(files)} selected file(s). Old violations and flags cleared.', 'success')
    return redirect(url_for('files.case_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/bulk_rehunt_selected', methods=['POST'])
@login_required
def bulk_rehunt_selected(case_id):
    """Re-hunt IOCs on selected files"""
    from main import db, CaseFile
    from bulk_operations import clear_file_ioc_matches, queue_file_processing
    from tasks import process_file
    from celery_health import check_workers_available
    
    # Safety check: Ensure Celery workers are available
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Cannot start bulk operation: {error_msg}. Please check Celery workers.', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    file_ids = request.form.getlist('file_ids', type=int)
    
    if not file_ids:
        flash('No files selected', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Get all selected files that are indexed
    files = db.session.query(CaseFile).filter(
        CaseFile.id.in_(file_ids),
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False,
        CaseFile.is_indexed == True
    ).all()
    
    if not files:
        flash('No valid indexed files found', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Clear IOC data for each file and set to Queued status
    for file in files:
        clear_file_ioc_matches(db, file.id)
        file.ioc_event_count = 0
        file.indexing_status = 'Queued'
        file.celery_task_id = None
    
    db.session.commit()
    
    # Queue for IOC reprocessing
    queue_file_processing(process_file, files, operation='ioc_only')
    
    # Audit log
    from audit_logger import log_action
    from main import Case
    case = db.session.get(Case, case_id)
    log_action('bulk_rehunt_iocs', resource_type='file', resource_id=None,
              resource_name=f'{len(files)} files',
              details={
                  'case_id': case_id,
                  'case_name': case.name if case else None,
                  'file_count': len(files),
                  'file_ids': [f.id for f in files[:10]]  # Log first 10 IDs
              })
    
    flash(f'IOC re-hunting queued for {len(files)} selected file(s). Old matches will be cleared.', 'success')
    return redirect(url_for('files.case_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/bulk_hide_selected', methods=['POST'])
@login_required
def bulk_hide_selected(case_id):
    """Hide selected files"""
    from main import db, CaseFile
    
    file_ids = request.form.getlist('file_ids', type=int)
    
    if not file_ids:
        flash('No files selected', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Get all selected files
    files = db.session.query(CaseFile).filter(
        CaseFile.id.in_(file_ids),
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False
    ).all()
    
    if not files:
        flash('No valid files found', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Hide all selected files
    for file in files:
        file.is_hidden = True
    
    db.session.commit()
    
    # Audit log
    from audit_logger import log_action
    from main import Case
    case = db.session.get(Case, case_id)
    log_action('bulk_hide_files', resource_type='file', resource_id=None,
              resource_name=f'{len(files)} files',
              details={
                  'case_id': case_id,
                  'case_name': case.name if case else None,
                  'file_count': len(files),
                  'file_ids': [f.id for f in files[:10]]  # Log first 10 IDs
              })
    
    flash(f'Hidden {len(files)} selected file(s). View them on the Hidden Files page.', 'success')
    return redirect(url_for('files.case_files', case_id=case_id))

@files_bp.route('/case/<int:case_id>/queue/cleanup', methods=['POST'])
@login_required
def queue_cleanup_case(case_id):
    """Per-case queue cleanup"""
    from main import db, Case, CaseFile
    from queue_cleanup import cleanup_queue
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'status': 'error', 'message': 'Case not found'}), 404
    
    try:
        result = cleanup_queue(db, CaseFile, case_id=case_id)
        
        if result['status'] == 'success':
            flash(result['message'], 'success')
        else:
            flash(result['message'], 'error')
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Queue cleanup error (case {case_id}): {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500


@files_bp.route('/case/<int:case_id>/queue/health')
@login_required
def queue_health_case(case_id):
    """Get queue health status for specific case"""
    from main import db, Case, CaseFile
    from queue_cleanup import get_queue_health
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'status': 'error', 'message': 'Case not found'}), 404
    
    try:
        health = get_queue_health(db, CaseFile, case_id=case_id)
        return jsonify(health)
    
    except Exception as e:
        logger.error(f"Queue health check error (case {case_id}): {e}", exc_info=True)
        return jsonify({
            'health_status': 'error',
            'message': f'Error: {str(e)}'
        }), 500


@files_bp.route('/case/<int:case_id>/file-stats')
@login_required
def file_stats_case(case_id):
    """Get comprehensive file and event statistics for auto-refresh (synchronous update)"""
    from main import db, Case, CaseFile
    from sqlalchemy import func
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'status': 'error', 'message': 'Case not found'}), 404
    
    try:
        # ========================================================================
        # FILE STATUS COUNTS (for queue monitoring)
        # ========================================================================
        completed = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status == 'Completed',
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).count()
        
        queued = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status == 'Queued',
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).count()
        
        indexing = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status == 'Indexing',
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).count()
        
        sigma = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status == 'SIGMA Testing',
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).count()
        
        ioc_hunting = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status == 'SIGMA Hunting',
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).count()
        
        failed = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status.like('Failed%'),
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).count()
        
        # ========================================================================
        # EVENT COUNTS (for Event Statistics tile)
        # ========================================================================
        # Total events
        total_events = int(db.session.query(func.sum(CaseFile.event_count)).filter_by(
            case_id=case_id,
            is_deleted=False,
            is_hidden=False
        ).scalar() or 0)
        
        # SIGMA violation events (distinct events with has_sigma=True)
        from models import SigmaViolation
        sigma_events = db.session.query(func.count(func.distinct(SigmaViolation.event_id))).filter_by(
            case_id=case_id
        ).scalar() or 0
        sigma_events = int(sigma_events)
        
        # IOC match events (distinct events with has_ioc=True)
        from models import IOCMatch
        ioc_events = db.session.query(func.count(func.distinct(IOCMatch.event_id))).filter_by(
            case_id=case_id
        ).scalar() or 0
        ioc_events = int(ioc_events)
        
        # ========================================================================
        # EVENT STATUS COUNTS (for status breakdown)
        # ========================================================================
        from event_status import get_status_counts
        
        # Get status counts from database
        status_counts = get_status_counts(case_id)
        
        # Calculate "new" count: total events - (hunted + confirmed + noise)
        # Events without a status record are considered "new"
        tracked_events = int(status_counts.get('hunted', 0) + status_counts.get('confirmed', 0) + status_counts.get('noise', 0))
        status_counts['new'] = max(0, total_events - tracked_events)
        
        # Convert all status_counts values to int (prevent Decimal/string serialization issues)
        status_counts = {k: int(v) for k, v in status_counts.items()}
        
        # ========================================================================
        # RETURN ALL DATA SYNCHRONOUSLY (one response, all updates together)
        # ========================================================================
        return jsonify({
            'status': 'success',
            # File status counts (queue monitoring)
            'completed': completed,
            'queued': queued,
            'indexing': indexing,
            'sigma': sigma,
            'ioc_hunting': ioc_hunting,
            'failed': failed,
            # Event counts (statistics tile)
            'total_events': total_events,
            'sigma_events': sigma_events,
            'ioc_events': ioc_events,
            # Event status breakdown
            'status_counts': status_counts
        })
    
    except Exception as e:
        logger.error(f"File stats error (case {case_id}): {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500


@files_bp.route('/files/global/queue/status')
@login_required
def queue_status_global():
    """Get global queue status across all cases"""
    from main import db, CaseFile, Case
    
    try:
        # Get queued files (all cases)
        queued_files = db.session.query(CaseFile, Case.name).join(Case).filter(
            CaseFile.indexing_status == 'Queued',
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).order_by(CaseFile.id).limit(100).all()
        
        # Get failed files (not hidden)
        failed_count = db.session.query(CaseFile).filter(
            CaseFile.indexing_status.like('Failed%'),
            CaseFile.is_hidden == False,
            CaseFile.is_deleted == False
        ).count()
        
        # Get actively processing (all cases)
        processing = db.session.query(CaseFile, Case.name).join(Case).filter(
            CaseFile.indexing_status.in_(['Staging', 'Indexing', 'SIGMA Testing', 'IOC Hunting']),
            CaseFile.is_deleted == False
        ).all()
        
        # Get total queued count
        queued_count = db.session.query(CaseFile).filter(
            CaseFile.indexing_status == 'Queued',
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).count()
        
        return jsonify({
            'status': 'success',
            'queued': [{
                'id': f.id,
                'filename': f.original_filename,
                'case_name': case_name,
                'case_id': f.case_id
            } for f, case_name in queued_files],
            'queued_count': queued_count,
            'failed_count': failed_count,
            'processing': [{
                'id': f.id,
                'filename': f.original_filename,
                'status': f.indexing_status,
                'case_name': case_name,
                'case_id': f.case_id
            } for f, case_name in processing]
        })
    except Exception as e:
        logger.error(f"Error getting global queue status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@files_bp.route('/files/global/hidden')
@login_required
def view_hidden_files_global():
    """View hidden files across ALL cases with search and pagination"""
    from main import db
    from hidden_files import get_hidden_files_global, get_hidden_files_count_global
    
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '', type=str).strip()
    per_page = 50
    
    pagination = get_hidden_files_global(db.session, page, per_page, search_term)
    hidden_count = get_hidden_files_count_global(db.session)
    
    # Transform pagination items from (CaseFile, case_name) tuples to structured data
    files_with_cases = []
    for file, case_name in pagination.items:
        files_with_cases.append({
            'file': file,
            'case_name': case_name
        })
    
    return render_template('global_hidden_files.html',
                          files_with_cases=files_with_cases,
                          pagination=pagination,
                          hidden_count=hidden_count,
                          search_term=search_term)


@files_bp.route('/files/global/failed')
@login_required
def view_failed_files_global():
    """View failed files across ALL cases with search and pagination"""
    from main import db
    from hidden_files import get_failed_files_global, get_failed_files_count_global
    
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '', type=str).strip()
    per_page = 50
    
    pagination = get_failed_files_global(db.session, page, per_page, search_term)
    failed_count = get_failed_files_count_global(db.session)
    
    # Transform pagination items from (CaseFile, case_name) tuples to structured data
    files_with_cases = []
    for file, case_name in pagination.items:
        files_with_cases.append({
            'file': file,
            'case_name': case_name
        })
    
    return render_template('global_failed_files.html',
                          files_with_cases=files_with_cases,
                          pagination=pagination,
                          failed_count=failed_count,
                          search_term=search_term)


@files_bp.route('/case/<int:case_id>/queue/status')
@login_required
def queue_status_case(case_id):
    """Get detailed queue status including file lists"""
    from main import db, Case, CaseFile
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'status': 'error', 'message': 'Case not found'}), 404
    
    try:
        # Get queued files (exclude hidden 0-event files)
        queued_files = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status == 'Queued',
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False  # CRITICAL FIX (v1.13.9): Don't show hidden files in Processing Queue UI
        ).order_by(CaseFile.id).limit(100).all()
        
        # Get failed files (not hidden)
        failed_files = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status.like('Failed%'),
            CaseFile.is_hidden == False,
            CaseFile.is_deleted == False
        ).count()
        
        # Get actively processing
        processing = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status.in_(['Indexing', 'SIGMA Testing', 'SIGMA Hunting']),
            CaseFile.is_deleted == False
        ).all()
        
        return jsonify({
            'status': 'success',
            'queued': [{
                'id': f.id,
                'filename': f.original_filename,
                'status': f.indexing_status
            } for f in queued_files],
            'queued_count': len(queued_files),
            'failed_count': failed_files,
            'processing': [{
                'id': f.id,
                'filename': f.original_filename,
                'status': f.indexing_status
            } for f in processing],
            'processing_count': len(processing)
        })
    
    except Exception as e:
        logger.error(f"Queue status error (case {case_id}): {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500


@files_bp.route('/case/<int:case_id>/file/<int:file_id>/requeue', methods=['POST'])
@login_required
def requeue_single_file(case_id, file_id):
    """Requeue a single failed file"""
    from main import db, Case, CaseFile
    from celery_app import celery_app
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    case_file = db.session.get(CaseFile, file_id)
    if not case_file or case_file.case_id != case_id:
        flash('File not found', 'error')
        return redirect(url_for('files.view_failed_files', case_id=case_id))
    
    # Check if file is actually failed
    known_statuses = ['Completed', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Queued']
    if case_file.indexing_status in known_statuses:
        flash('File is not in a failed state', 'warning')
        return redirect(url_for('files.view_failed_files', case_id=case_id))
    
    try:
        # CRITICAL: Check for stale task_id before queuing
        # If file already has a task_id, verify it's not stale
        if case_file.celery_task_id:
            from celery.result import AsyncResult
            old_task = AsyncResult(case_file.celery_task_id, app=celery_app)
            
            # If old task is still active, don't requeue
            if old_task.state in ['PENDING', 'STARTED', 'RETRY']:
                logger.warning(f"[REQUEUE] File {file_id} already has active task {case_file.celery_task_id} (state: {old_task.state})")
                flash(f'File is already being processed (task state: {old_task.state})', 'warning')
                return redirect(url_for('files.view_failed_files', case_id=case_id))
            else:
                # Old task is finished (SUCCESS/FAILURE/REVOKED), clear it
                logger.info(f"[REQUEUE] File {file_id} has stale task_id {case_file.celery_task_id} (state: {old_task.state}), clearing before requeue")
                case_file.celery_task_id = None
        
        # Submit task to Celery
        task = celery_app.send_task(
            'tasks.process_file',
            args=[case_file.id, 'full']
        )
        
        # Update database
        case_file.indexing_status = 'Queued'
        case_file.celery_task_id = task.id
        db.session.commit()
        
        # Audit log
        from audit_logger import log_file_action
        log_file_action('requeue_file', file_id, case_file.original_filename, details={
            'case_id': case_id,
            'case_name': case.name,
            'task_id': task.id,
            'previous_status': case_file.indexing_status
        })
        
        flash(f'✅ File "{case_file.original_filename}" requeued for processing', 'success')
    except Exception as e:
        logger.error(f"Error requeueing file {file_id}: {e}")
        db.session.rollback()
        flash(f'Error requeueing file: {str(e)}', 'error')
    
    return redirect(url_for('files.view_failed_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/bulk_requeue_selected', methods=['POST'])
@login_required
def bulk_requeue_selected(case_id):
    """Requeue selected failed files"""
    from main import db, Case, CaseFile
    from celery_app import celery_app
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('files.view_failed_files', case_id=case_id))
    
    file_ids = request.form.getlist('file_ids', type=int)
    
    if not file_ids:
        flash('No files selected', 'warning')
        return redirect(url_for('files.view_failed_files', case_id=case_id))
    
    try:
        # Find selected files that are failed
        known_statuses = ['Completed', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Queued']
        failed_files = db.session.query(CaseFile).filter(
            CaseFile.id.in_(file_ids),
            CaseFile.case_id == case_id,
            CaseFile.is_deleted == False,
            ~CaseFile.indexing_status.in_(known_statuses)
        ).all()
        
        if not failed_files:
            flash('No failed files found in selection', 'warning')
            return redirect(url_for('files.view_failed_files', case_id=case_id))
        
        requeued = 0
        errors = 0
        
        for case_file in failed_files:
            try:
                # CRITICAL: Check for stale task_id before queuing
                if case_file.celery_task_id:
                    from celery.result import AsyncResult
                    old_task = AsyncResult(case_file.celery_task_id, app=celery_app)
                    
                    # If old task is still active, skip this file
                    if old_task.state in ['PENDING', 'STARTED', 'RETRY']:
                        logger.warning(f"[BULK REQUEUE] File {case_file.id} already has active task {case_file.celery_task_id} (state: {old_task.state}), skipping")
                        continue
                    else:
                        # Old task is finished, clear it
                        logger.info(f"[BULK REQUEUE] File {case_file.id} has stale task_id {case_file.celery_task_id} (state: {old_task.state}), clearing before requeue")
                        case_file.celery_task_id = None
                
                # Submit task to Celery
                task = celery_app.send_task(
                    'tasks.process_file',
                    args=[case_file.id, 'full']
                )
                
                # Update database
                case_file.indexing_status = 'Queued'
                case_file.celery_task_id = task.id
                db.session.commit()
                
                requeued += 1
                
            except Exception as e:
                errors += 1
                logger.error(f"Error requeueing file {case_file.id}: {e}")
                db.session.rollback()
        
        # Audit log
        from audit_logger import log_action
        log_action('bulk_requeue_files', resource_type='file', resource_id=None,
                  resource_name=f'{requeued} files',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'requeued_count': requeued,
                      'errors': errors,
                      'file_ids': [f.id for f in failed_files[:10]]  # Log first 10 IDs
                  })
        
        message = f'✅ Requeued {requeued} file(s)'
        if errors > 0:
            message += f' (⚠️ {errors} error(s))'
        flash(message, 'success' if errors == 0 else 'warning')
        
    except Exception as e:
        logger.error(f"Bulk requeue error (case {case_id}): {e}", exc_info=True)
        db.session.rollback()
        flash(f'Error requeueing files: {str(e)}', 'error')
    
    return redirect(url_for('files.view_failed_files', case_id=case_id))


@files_bp.route('/case/<int:case_id>/queue/requeue-failed', methods=['POST'])
@login_required
def requeue_failed_files(case_id):
    """Requeue all failed files that are not hidden"""
    from main import db, Case, CaseFile
    from celery_app import celery_app
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'status': 'error', 'message': 'Case not found'}), 404
    
    try:
        # Find all failed files that are NOT hidden
        failed_files = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status.like('Failed%'),
            CaseFile.is_hidden == False,
            CaseFile.is_deleted == False
        ).all()
        
        if not failed_files:
            return jsonify({
                'status': 'success',
                'message': 'No failed files to requeue',
                'requeued': 0
            })
        
        requeued = 0
        errors = 0
        
        for case_file in failed_files:
            try:
                # CRITICAL: Check for stale task_id before queuing
                if case_file.celery_task_id:
                    from celery.result import AsyncResult
                    old_task = AsyncResult(case_file.celery_task_id, app=celery_app)
                    
                    # If old task is still active, skip this file
                    if old_task.state in ['PENDING', 'STARTED', 'RETRY']:
                        logger.warning(f"[BULK REQUEUE GLOBAL] File {case_file.id} already has active task {case_file.celery_task_id} (state: {old_task.state}), skipping")
                        continue
                    else:
                        # Old task is finished, clear it
                        logger.info(f"[BULK REQUEUE GLOBAL] File {case_file.id} has stale task_id {case_file.celery_task_id} (state: {old_task.state}), clearing before requeue")
                        case_file.celery_task_id = None
                
                # Submit task to Celery
                task = celery_app.send_task(
                    'tasks.process_file',
                    args=[case_file.id]
                )
                
                # Update database
                case_file.indexing_status = 'Queued'
                case_file.celery_task_id = task.id
                db.session.commit()
                
                requeued += 1
                
            except Exception as e:
                errors += 1
                logger.error(f"Error requeueing file {case_file.id}: {e}")
                db.session.rollback()
        
        message = f'✅ Requeued {requeued} failed file(s)'
        if errors > 0:
            message += f' (⚠️ {errors} error(s))'
        
        return jsonify({
            'status': 'success',
            'message': message,
            'requeued': requeued,
            'errors': errors
        })
    
    except Exception as e:
        logger.error(f"Requeue failed files error (case {case_id}): {e}", exc_info=True)
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500


# ============================================================================
# GLOBAL BULK OPERATIONS (v1.13.7)
# Similar to case-level operations but work across ALL cases
# ============================================================================

@files_bp.route('/files/global/requeue_failed', methods=['POST'])
@login_required
def requeue_failed_files_global_route():
    """Requeue all failed files across ALL cases"""
    from main import db
    from bulk_operations import requeue_failed_files
    
    try:
        count = requeue_failed_files(db, scope='global')
        
        flash(f'✅ Requeued {count} failed file(s) across all cases', 'success')
        return redirect(url_for('files.global_files'))
    
    except Exception as e:
        logger.error(f"[GLOBAL BULK] Requeue failed error: {e}", exc_info=True)
        flash(f'Error requeuing failed files: {str(e)}', 'error')
        return redirect(url_for('files.global_files'))


@files_bp.route('/files/global/bulk_reindex', methods=['POST'])
@login_required
def bulk_reindex_global_route():
    """Re-index all files across ALL cases"""
    from main import db, celery_app, opensearch_client
    from celery_health import check_workers_available
    from bulk_operations import (get_files, clear_opensearch_events, clear_sigma_violations, 
                                 clear_ioc_matches, prepare_files_for_reindex, queue_file_processing)
    from tasks import process_file
    import time
    
    # Check if request wants JSON (for modal updates) or redirect (for backward compat)
    wants_json = request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    
    # Safety check
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        if wants_json:
            return jsonify({'success': False, 'error': f'No Celery workers available: {error_msg}'}), 503
        flash(f'⚠️ Cannot start global bulk operation: {error_msg}', 'error')
        return redirect(url_for('files.global_files'))
    
    try:
        # Track steps for modal updates
        steps = []
        start_time = time.time()
        
        # Get all indexed files across all cases (excluding archived cases - v1.18.0)
        from archive_utils import is_case_archived
        all_files = [f for f in get_files(db, scope='global', include_hidden=False) if f.is_indexed]
        files = [f for f in all_files if not is_case_archived(f.case)]
        
        if not files:
            if wants_json:
                return jsonify({'success': True, 'message': 'No files to reindex', 'steps': [], 'files_queued': 0})
            flash('No indexed files found globally (archived cases excluded)', 'warning')
            return redirect(url_for('files.global_files'))
        
        # STEP 1: Clear database entries (reset to fresh import state)
        steps.append({'step': 'clearing_db', 'message': f'Clearing database entries for {len(files)} files', 'status': 'in_progress'})
        
        # Clear SIGMA, IOC, and EventStatus data
        sigma_deleted = clear_sigma_violations(db, scope='global')
        ioc_deleted = clear_ioc_matches(db, scope='global')
        
        # v1.46.0: Clear EventStatus records for true fresh start
        from bulk_operations import clear_event_statuses
        statuses_deleted = clear_event_statuses(db, scope='global')
        
        # Prepare files for reindex
        prepare_files_for_reindex(db, files, scope='global')
        
        steps[-1]['status'] = 'completed'
        steps[-1]['files_processed'] = len(files)
        steps[-1]['sigma_deleted'] = sigma_deleted
        steps[-1]['ioc_deleted'] = ioc_deleted
        steps[-1]['statuses_deleted'] = statuses_deleted
        steps[-1]['ioc_deleted'] = ioc_deleted
        steps[-1]['duration'] = round(time.time() - start_time, 2)
        
        # STEP 2: Clear OpenSearch entries
        step_start = time.time()
        steps.append({'step': 'clearing_opensearch', 'message': f'Clearing OpenSearch entries for {len(files)} files', 'status': 'in_progress'})
        
        # Clear OpenSearch events
        events_deleted = clear_opensearch_events(opensearch_client, files, scope='global')
        
        steps[-1]['status'] = 'completed'
        steps[-1]['deleted_events'] = events_deleted
        steps[-1]['duration'] = round(time.time() - step_start, 2)
        
        # STEP 3: Build file queue
        step_start = time.time()
        steps.append({'step': 'building_queue', 'message': f'Building queue for {len(files)} files', 'status': 'in_progress'})
        
        # Queue files with 'reindex' operation (v1.16.25 fix)
        queued = queue_file_processing(process_file, files, operation='reindex', db_session=db.session, scope='global')
        
        steps[-1]['status'] = 'completed'
        steps[-1]['files_queued'] = queued
        steps[-1]['duration'] = round(time.time() - step_start, 2)
        
        # Audit log - HIGH: Global reindex operation
        from audit_logger import log_action
        log_action('bulk_reindex_global', resource_type='file', resource_id=None,
                  resource_name='Global Bulk Re-Index (ALL CASES)',
                  details={
                      'file_count': len(files),
                      'queued_count': queued,
                      'worker_count': worker_count,
                      'operation': 'GLOBAL_REINDEX'
                  })
        
        total_duration = round(time.time() - start_time, 2)
        
        # Return JSON for modal updates or redirect for backward compatibility
        if wants_json:
            return jsonify({
                'success': True,
                'message': f'Re-indexing queued for {queued} files across all cases',
                'steps': steps,
                'total_duration': total_duration,
                'files_queued': queued,
                'events_deleted': events_deleted,
                'sigma_deleted': sigma_deleted,
                'ioc_deleted': ioc_deleted
            })
        else:
            flash(f'✅ Re-indexing queued for {queued} file(s) across all cases ({worker_count} worker(s) available)', 'success')
            return redirect(url_for('files.global_files'))
    
    except Exception as e:
        logger.error(f"[GLOBAL BULK] Reindex error: {e}", exc_info=True)
        if wants_json:
            return jsonify({'success': False, 'error': str(e)}), 500
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('files.global_files'))


@files_bp.route('/files/global/bulk_rechainsaw', methods=['POST'])
@login_required
def bulk_rechainsaw_global_route():
    """Re-run SIGMA on all files across ALL cases"""
    from main import db
    from celery_health import check_workers_available
    from bulk_operations import (get_files, clear_sigma_violations, 
                                 prepare_files_for_rechainsaw, queue_file_processing)
    from tasks import process_file
    
    # Safety check
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Cannot start global bulk operation: {error_msg}', 'error')
        return redirect(url_for('files.global_files'))
    
    try:
        files = [f for f in get_files(db, scope='global', include_hidden=False) if f.is_indexed]
        
        if not files:
            flash('No indexed files found globally', 'warning')
            return redirect(url_for('files.global_files'))
        
        # Clear SIGMA data
        clear_sigma_violations(db, scope='global')
        
        # Prepare and queue files
        prepare_files_for_rechainsaw(db, files, scope='global')
        queued = queue_file_processing(process_file, files, 'sigma_only', db.session, scope='global')
        
        # Audit log - HIGH: Global re-SIGMA operation
        from audit_logger import log_action
        log_action('bulk_rechainsaw_global', resource_type='file', resource_id=None,
                  resource_name='Global Bulk Re-SIGMA (ALL CASES)',
                  details={
                      'file_count': len(files),
                      'queued_count': queued,
                      'worker_count': worker_count,
                      'operation': 'GLOBAL_RESIGMA'
                  })
        
        flash(f'✅ Re-SIGMA queued for {queued} file(s) across all cases ({worker_count} worker(s) available)', 'success')
        return redirect(url_for('files.global_files'))
    
    except Exception as e:
        logger.error(f"[GLOBAL BULK] Re-SIGMA error: {e}", exc_info=True)
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('files.global_files'))


@files_bp.route('/files/global/bulk_rehunt_iocs', methods=['POST'])
@login_required
def bulk_rehunt_iocs_global_route():
    """Re-hunt IOCs on all files across ALL cases"""
    from main import db, opensearch_client
    from celery_health import check_workers_available
    from bulk_operations import (get_files, clear_ioc_matches, clear_ioc_flags_in_opensearch,
                                 prepare_files_for_rehunt, queue_file_processing)
    from tasks import process_file
    
    # Safety check
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Cannot start global bulk operation: {error_msg}', 'error')
        return redirect(url_for('files.global_files'))
    
    try:
        # Clear OpenSearch caches
        try:
            opensearch_client.indices.clear_cache(index='*', fielddata=True, query=True, request=True)
        except Exception as e:
            logger.warning(f"[GLOBAL BULK] Failed to clear OpenSearch cache: {e}")
        
        files = [f for f in get_files(db, scope='global', include_hidden=False) if f.is_indexed]
        
        if not files:
            flash('No indexed files found globally', 'warning')
            return redirect(url_for('files.global_files'))
        
        # Clear IOC data
        clear_ioc_matches(db, scope='global')
        clear_ioc_flags_in_opensearch(opensearch_client, files, scope='global')
        
        # Prepare and queue files
        prepare_files_for_rehunt(db, files, scope='global')
        queued = queue_file_processing(process_file, files, 'ioc_only', db.session, scope='global')
        
        # Audit log - HIGH: Global IOC re-hunting operation
        from audit_logger import log_action
        log_action('bulk_rehunt_iocs_global', resource_type='file', resource_id=None,
                  resource_name='Global Bulk Re-Hunt IOCs (ALL CASES)',
                  details={
                      'file_count': len(files),
                      'queued_count': queued,
                      'worker_count': worker_count,
                      'operation': 'GLOBAL_REHUNT_IOCS'
                  })
        
        flash(f'✅ IOC re-hunting queued for {queued} file(s) across all cases ({worker_count} worker(s) available)', 'success')
        return redirect(url_for('files.global_files'))
    
    except Exception as e:
        logger.error(f"[GLOBAL BULK] IOC rehunt error: {e}", exc_info=True)
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('files.global_files'))


@files_bp.route('/files/global/bulk_delete_files', methods=['POST'])
@login_required
def bulk_delete_files_global_route():
    """Delete all files across ALL cases - ADMIN ONLY"""
    from main import db, opensearch_client
    from bulk_operations import get_files, delete_files
    
    # Admin check
    if current_user.role != 'administrator':
        flash('Only administrators can delete all files globally', 'error')
        return redirect(url_for('files.global_files'))
    
    try:
        files = get_files(db, scope='global', include_deleted=False, include_hidden=True)
        
        if not files:
            flash('No files to delete', 'info')
            return redirect(url_for('files.global_files'))
        
        file_count = len(files)
        
        # Delete files
        stats = delete_files(db, opensearch_client, files, scope='global')
        
        # Audit log - CRITICAL: Global file deletion (admin only)
        from audit_logger import log_action
        log_action('bulk_delete_files_global', resource_type='file', resource_id=None,
                  resource_name='Global Bulk Delete (ALL CASES)',
                  details={
                      'files_deleted': stats['files_deleted'],
                      'events_deleted': stats['events_deleted'],
                      'sigma_deleted': stats['sigma_deleted'],
                      'ioc_deleted': stats['ioc_deleted'],
                      'operation': 'GLOBAL_PERMANENT_DELETE',
                      'admin_only': True
                  })
        
        flash(f'✅ Deleted {stats["files_deleted"]} files, {stats["events_deleted"]} events, '
              f'{stats["sigma_deleted"]} SIGMA violations, {stats["ioc_deleted"]} IOC matches', 'success')
        return redirect(url_for('files.global_files'))
    
    except Exception as e:
        logger.error(f"[GLOBAL BULK] Delete error: {e}", exc_info=True)
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('files.global_files'))


# ============================================================================
# SELECTED FILES GLOBAL BULK OPERATIONS (v1.13.7)
# Work on specific files selected by user (can span multiple cases)
# ============================================================================

@files_bp.route('/files/global/bulk_reindex_selected', methods=['POST'])
@login_required
def bulk_reindex_selected_global_route():
    """Re-index selected files (cross-case)"""
    from main import db, opensearch_client
    from celery_health import check_workers_available
    from bulk_operations import (get_files, clear_opensearch_events, clear_sigma_violations,
                                 clear_ioc_matches, prepare_files_for_reindex, queue_file_processing)
    from tasks import process_file
    import time
    
    # Check if request wants JSON (for modal updates) or redirect (for backward compat)
    wants_json = request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    
    file_ids = request.form.getlist('file_ids[]', type=int) if not wants_json else request.get_json().get('file_ids', [])
    if not file_ids:
        if wants_json:
            return jsonify({'success': False, 'error': 'No files selected'}), 400
        flash('No files selected', 'warning')
        return redirect(url_for('files.global_files'))
    
    # Safety check
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        if wants_json:
            return jsonify({'success': False, 'error': f'No Celery workers available: {error_msg}'}), 503
        flash(f'⚠️ Cannot start operation: {error_msg}', 'error')
        return redirect(url_for('files.global_files'))
    
    try:
        # Track steps for modal updates
        steps = []
        start_time = time.time()
        
        all_files = get_files(db, scope='global', file_ids=file_ids)
        
        # Filter out files from archived cases (v1.18.0)
        from archive_utils import is_case_archived
        files = [f for f in all_files if not is_case_archived(f.case)]
        archived_count = len(all_files) - len(files)
        
        if not files:
            if archived_count > 0:
                error_msg = f'Cannot re-index: All {archived_count} selected file(s) are in archived cases'
                if wants_json:
                    return jsonify({'success': False, 'error': error_msg}), 403
                flash(error_msg, 'error')
            else:
                if wants_json:
                    return jsonify({'success': False, 'error': 'Selected files not found'}), 404
                flash('Selected files not found', 'warning')
            return redirect(url_for('files.global_files'))
        
        # STEP 1: Clear database entries (reset to fresh import state)
        steps.append({'step': 'clearing_db', 'message': f'Clearing database entries for {len(files)} files', 'status': 'in_progress'})
        
        # Clear SIGMA, IOC, and EventStatus data
        sigma_deleted = clear_sigma_violations(db, scope='global', file_ids=file_ids)
        ioc_deleted = clear_ioc_matches(db, scope='global', file_ids=file_ids)
        
        # v1.46.0: Clear EventStatus records - need to do per-case for file-specific
        from bulk_operations import clear_event_statuses
        statuses_deleted = 0
        files_by_case = {}
        for f in files:
            if f.case_id not in files_by_case:
                files_by_case[f.case_id] = []
            files_by_case[f.case_id].append(f.id)
        
        for case_id, file_id_list in files_by_case.items():
            statuses_deleted += clear_event_statuses(db, scope='file', case_id=case_id, file_ids=file_id_list)
        
        # Prepare files for reindex
        prepare_files_for_reindex(db, files, scope='global')
        
        steps[-1]['status'] = 'completed'
        steps[-1]['files_processed'] = len(files)
        steps[-1]['sigma_deleted'] = sigma_deleted
        steps[-1]['ioc_deleted'] = ioc_deleted
        steps[-1]['statuses_deleted'] = statuses_deleted
        if archived_count > 0:
            steps[-1]['archived_skipped'] = archived_count
        steps[-1]['duration'] = round(time.time() - start_time, 2)
        
        # STEP 2: Clear OpenSearch entries
        step_start = time.time()
        steps.append({'step': 'clearing_opensearch', 'message': f'Clearing OpenSearch entries for {len(files)} files', 'status': 'in_progress'})
        
        events_deleted = clear_opensearch_events(opensearch_client, files, scope='global')
        
        steps[-1]['status'] = 'completed'
        steps[-1]['deleted_events'] = events_deleted
        steps[-1]['duration'] = round(time.time() - step_start, 2)
        
        # STEP 3: Build file queue
        step_start = time.time()
        steps.append({'step': 'building_queue', 'message': f'Building queue for {len(files)} files', 'status': 'in_progress'})
        
        # Queue files (v1.16.25: Use 'reindex' operation to force processing)
        queued = queue_file_processing(process_file, files, operation='reindex', db_session=db.session, scope='global')
        
        steps[-1]['status'] = 'completed'
        steps[-1]['files_queued'] = queued
        steps[-1]['duration'] = round(time.time() - step_start, 2)
        
        # Audit log - MEDIUM: Global reindex selected files
        from audit_logger import log_action
        log_action('bulk_reindex_selected_global', resource_type='file', resource_id=None,
                  resource_name='Global Re-Index Selected Files (Cross-Case)',
                  details={
                      'file_count': len(files),
                      'queued_count': queued,
                      'file_ids': file_ids,
                      'worker_count': worker_count,
                      'operation': 'GLOBAL_REINDEX_SELECTED'
                  })
        
        total_duration = round(time.time() - start_time, 2)
        
        # Return JSON for modal updates or redirect for backward compatibility
        if wants_json:
            response = {
                'success': True,
                'message': f'Re-indexing queued for {queued} selected files',
                'steps': steps,
                'total_duration': total_duration,
                'files_queued': queued,
                'events_deleted': events_deleted,
                'sigma_deleted': sigma_deleted,
                'ioc_deleted': ioc_deleted
            }
            if archived_count > 0:
                response['warning'] = f'Skipped {archived_count} file(s) from archived cases'
            return jsonify(response)
        else:
            if archived_count > 0:
                flash(f'⚠️ Skipped {archived_count} file(s) from archived cases', 'warning')
            flash(f'✅ Re-indexing queued for {queued} selected file(s) ({worker_count} worker(s) available)', 'success')
            return redirect(url_for('files.global_files'))
    
    except Exception as e:
        logger.error(f"[GLOBAL BULK] Selected reindex error: {e}", exc_info=True)
        if wants_json:
            return jsonify({'success': False, 'error': str(e)}), 500
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('files.global_files'))


@files_bp.route('/files/global/bulk_rechainsaw_selected', methods=['POST'])
@login_required
def bulk_rechainsaw_selected_global_route():
    """Re-SIGMA selected files (cross-case)"""
    from main import db
    from celery_health import check_workers_available
    from bulk_operations import (get_files, clear_sigma_violations, 
                                 prepare_files_for_rechainsaw, queue_file_processing)
    from tasks import process_file
    
    file_ids = request.form.getlist('file_ids[]', type=int)
    if not file_ids:
        flash('No files selected', 'warning')
        return redirect(url_for('files.global_files'))
    
    # Safety check
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Cannot start operation: {error_msg}', 'error')
        return redirect(url_for('files.global_files'))
    
    try:
        files = get_files(db, scope='global', file_ids=file_ids)
        
        if not files:
            flash('Selected files not found', 'warning')
            return redirect(url_for('files.global_files'))
        
        # Clear SIGMA data
        clear_sigma_violations(db, scope='global', file_ids=file_ids)
        
        # Prepare and queue
        prepare_files_for_rechainsaw(db, files, scope='global')
        queued = queue_file_processing(process_file, files, 'sigma_only', db.session, scope='global')
        
        # Audit log - MEDIUM: Global re-SIGMA selected files
        from audit_logger import log_action
        log_action('bulk_rechainsaw_selected_global', resource_type='file', resource_id=None,
                  resource_name='Global Re-SIGMA Selected Files (Cross-Case)',
                  details={
                      'file_count': len(files),
                      'queued_count': queued,
                      'file_ids': file_ids,
                      'worker_count': worker_count,
                      'operation': 'GLOBAL_RESIGMA_SELECTED'
                  })
        
        flash(f'✅ Re-SIGMA queued for {queued} selected file(s) ({worker_count} worker(s) available)', 'success')
        return redirect(url_for('files.global_files'))
    
    except Exception as e:
        logger.error(f"[GLOBAL BULK] Selected re-SIGMA error: {e}", exc_info=True)
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('files.global_files'))


@files_bp.route('/files/global/bulk_rehunt_selected', methods=['POST'])
@login_required
def bulk_rehunt_iocs_selected_global_route():
    """Re-hunt IOCs on selected files (cross-case)"""
    from main import db, opensearch_client
    from celery_health import check_workers_available
    from bulk_operations import (get_files, clear_ioc_matches, clear_ioc_flags_in_opensearch,
                                 prepare_files_for_rehunt, queue_file_processing)
    from tasks import process_file
    
    file_ids = request.form.getlist('file_ids[]', type=int)
    if not file_ids:
        flash('No files selected', 'warning')
        return redirect(url_for('files.global_files'))
    
    # Safety check
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Cannot start operation: {error_msg}', 'error')
        return redirect(url_for('files.global_files'))
    
    try:
        files = get_files(db, scope='global', file_ids=file_ids)
        
        if not files:
            flash('Selected files not found', 'warning')
            return redirect(url_for('files.global_files'))
        
        # Clear IOC data
        clear_ioc_matches(db, scope='global', file_ids=file_ids)
        clear_ioc_flags_in_opensearch(opensearch_client, files, scope='global')
        
        # Prepare and queue
        prepare_files_for_rehunt(db, files, scope='global')
        queued = queue_file_processing(process_file, files, 'ioc_only', db.session, scope='global')
        
        # Audit log - MEDIUM: Global re-hunt IOCs selected files
        from audit_logger import log_action
        log_action('bulk_rehunt_selected_global', resource_type='file', resource_id=None,
                  resource_name='Global Re-Hunt IOCs Selected Files (Cross-Case)',
                  details={
                      'file_count': len(files),
                      'queued_count': queued,
                      'file_ids': file_ids,
                      'worker_count': worker_count,
                      'operation': 'GLOBAL_REHUNT_SELECTED'
                  })
        
        flash(f'✅ IOC re-hunting queued for {queued} selected file(s) ({worker_count} worker(s) available)', 'success')
        return redirect(url_for('files.global_files'))
    
    except Exception as e:
        logger.error(f"[GLOBAL BULK] Selected IOC rehunt error: {e}", exc_info=True)
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('files.global_files'))


@files_bp.route('/files/global/bulk_hide_selected', methods=['POST'])
@login_required
def bulk_hide_selected_global_route():
    """Hide selected files (cross-case)"""
    from main import db
    from bulk_operations import get_files
    
    file_ids = request.form.getlist('file_ids[]', type=int)
    if not file_ids:
        flash('No files selected', 'warning')
        return redirect(url_for('files.global_files'))
    
    try:
        files = get_files(db, scope='global', file_ids=file_ids)
        
        if not files:
            flash('Selected files not found', 'warning')
            return redirect(url_for('files.global_files'))
        
        # Hide files
        for f in files:
            f.is_hidden = True
        
        db.session.commit()
        
        # Audit log - MEDIUM: Global hide selected files
        from audit_logger import log_action
        log_action('bulk_hide_selected_global', resource_type='file', resource_id=None,
                  resource_name='Global Hide Selected Files (Cross-Case)',
                  details={
                      'file_count': len(files),
                      'file_ids': file_ids,
                      'operation': 'GLOBAL_HIDE_SELECTED'
                  })
        
        flash(f'✅ Hidden {len(files)} selected file(s)', 'success')
        return redirect(url_for('files.global_files'))
    
    except Exception as e:
        logger.error(f"[GLOBAL BULK] Hide selected error: {e}", exc_info=True)
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('files.global_files'))
