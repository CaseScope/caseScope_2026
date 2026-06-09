"""Parsing API Routes for CaseScope

Provides endpoints for:
- Triggering file parsing
- Checking parse status
- Managing parsing tasks
"""
import os
import logging
from flask import Blueprint, jsonify, request, session
from flask_login import login_required, current_user

from models.database import db
from models.case import Case
from models.case_file import CaseFile
from config import Config
from utils.artifact_paths import ensure_case_artifact_paths, is_within_any_root
from utils.async_status import build_async_status_response

logger = logging.getLogger(__name__)

parsing_bp = Blueprint('parsing', __name__, url_prefix='/api/parsing')
PARSING_TASK_SESSION_KEY = 'parsing_task_access'


def _viewer_write_error():
    return jsonify({'success': False, 'error': 'Viewers cannot modify parsing state'}), 403


def _remember_task_access(task_id, case_uuid=None):
    tracked = session.get(PARSING_TASK_SESSION_KEY, {})
    tracked[task_id] = {'case_uuid': case_uuid}
    if len(tracked) > 100:
        tracked = dict(list(tracked.items())[-100:])
    session[PARSING_TASK_SESSION_KEY] = tracked
    session.modified = True


def _task_access_allowed(task_id):
    return task_id in session.get(PARSING_TASK_SESSION_KEY, {})


@parsing_bp.route('/detect-type', methods=['POST'])
@login_required
def detect_file_type():
    """Detect the artifact type of a file
    
    Request JSON:
        file_path: Path to the file
        
    Returns:
        JSON with detected artifact type
    """
    try:
        from parsers import get_registry
        
        data = request.get_json()
        file_path = data.get('file_path')
        case_uuid = data.get('case_uuid')
        
        if not file_path or not case_uuid:
            return jsonify({'success': False, 'error': 'file_path and case_uuid required'}), 400

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404

        allowed_roots = ensure_case_artifact_paths(case_uuid)
        if not is_within_any_root(file_path, allowed_roots.values()):
            return jsonify({'success': False, 'error': 'File path must belong to this case'}), 400
        
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        registry = get_registry()
        detected_type = registry.detect_type(file_path)
        parser = registry.get_parser_for_file(
            file_path=file_path,
            case_id=case.id,
            case_tz=case.timezone or 'UTC',
        )
        confirmed_type = parser.artifact_type if parser else None
        
        return jsonify({
            'success': True,
            'file_path': file_path,
            'artifact_type': confirmed_type or detected_type,
            'detected_artifact_type': detected_type,
            'confirmed_artifact_type': confirmed_type,
            'parseable': confirmed_type is not None,
        })
        
    except Exception as e:
        logger.exception("Error detecting file type")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/parsers', methods=['GET'])
@login_required
def list_parsers():
    """List all available parsers
    
    Returns:
        JSON with parser information
    """
    try:
        from parsers import get_registry
        
        registry = get_registry()
        parsers = registry.list_parsers()
        
        return jsonify({
            'success': True,
            'parsers': parsers,
            'count': len(parsers),
        })
        
    except Exception as e:
        logger.exception("Error listing parsers")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/process/file', methods=['POST'])
@login_required
def process_single_file():
    """Rebuild a single file from retained originals.
    
    Request JSON:
        case_uuid: Case UUID
        case_file_id: CaseFile ID
        
    Returns:
        JSON with task ID
    """
    try:
        if current_user.permission_level == 'viewer':
            return _viewer_write_error()

        from tasks.celery_tasks import rebuild_single_case_file_task
        
        data = request.get_json()
        case_uuid = data.get('case_uuid')
        case_file_id = data.get('case_file_id')
        
        if not case_uuid:
            return jsonify({'success': False, 'error': 'case_uuid required'}), 400
        
        if not case_file_id:
            return jsonify({'success': False, 'error': 'case_file_id required'}), 400
        
        # Get case
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get case file
        case_file = CaseFile.query.get(case_file_id)
        if not case_file or case_file.case_uuid != case_uuid:
            return jsonify({'success': False, 'error': 'CaseFile not found'}), 404
        
        rebuild_mode = (data.get('rebuild_mode') or 'parent_archive').strip() or 'parent_archive'
        if rebuild_mode not in ('parent_archive', 'single_member'):
            return jsonify({'success': False, 'error': 'Invalid rebuild_mode'}), 400

        task = rebuild_single_case_file_task.delay(
            case_uuid=case_uuid,
            case_id=case.id,
            case_file_id=case_file.id,
            username=current_user.username,
            rebuild_mode=rebuild_mode,
        )
        _remember_task_access(task.id, case_uuid=case_uuid)

        return jsonify({
            'success': True,
            'task_id': task.id,
            'case_file_id': case_file.id,
            'filename': case_file.filename,
            'mode': rebuild_mode,
        })
        
    except Exception as e:
        logger.exception("Error queuing file for parsing")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/process/case', methods=['POST'])
@login_required
def process_case_files():
    """Queue all pending files for a case
    
    Request JSON:
        case_uuid: Case UUID
        file_ids: Optional list of specific file IDs
        
    Returns:
        JSON with queued task info
    """
    try:
        if current_user.permission_level == 'viewer':
            return _viewer_write_error()

        from tasks import process_case_files_task
        
        data = request.get_json()
        case_uuid = data.get('case_uuid')
        file_ids = data.get('file_ids')
        
        if not case_uuid:
            return jsonify({'success': False, 'error': 'case_uuid required'}), 400
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Queue task
        task = process_case_files_task.delay(
            case_uuid=case_uuid,
            file_ids=file_ids,
        )
        _remember_task_access(task.id, case_uuid=case_uuid)
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'case_uuid': case_uuid,
        })
        
    except Exception as e:
        logger.exception("Error queuing case files for parsing")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/process/staging', methods=['POST'])
@login_required
def process_staging_directory():
    """Process all files in a case's staging directory
    
    Request JSON:
        case_uuid: Case UUID
        
    Returns:
        JSON with queued task info
    """
    try:
        if current_user.permission_level == 'viewer':
            return _viewer_write_error()

        from tasks import process_staging_directory_task
        
        data = request.get_json()
        case_uuid = data.get('case_uuid')
        
        if not case_uuid:
            return jsonify({'success': False, 'error': 'case_uuid required'}), 400
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Check staging directory exists
        staging_path = os.path.join(Config.STAGING_FOLDER, case_uuid)
        if not os.path.isdir(staging_path):
            return jsonify({'success': False, 'error': 'Staging directory not found'}), 404
        
        # Queue task
        task = process_staging_directory_task.delay(
            case_uuid=case_uuid,
            staging_path=staging_path,
        )
        _remember_task_access(task.id, case_uuid=case_uuid)
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'case_uuid': case_uuid,
            'staging_path': staging_path,
        })
        
    except Exception as e:
        logger.exception("Error queuing staging directory for parsing")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/task/<task_id>', methods=['GET'])
@login_required
def get_task_status(task_id):
    """Get status of a parsing task
    
    Args:
        task_id: Celery task ID
        
    Returns:
        JSON with task status
    """
    try:
        from tasks import celery_app

        if not _task_access_allowed(task_id):
            return jsonify({'success': False, 'error': 'Task not found'}), 404
        
        result = celery_app.AsyncResult(task_id)

        payload, status_code = build_async_status_response(
            result,
            task_id=task_id,
            pending_builder=lambda _task: {'status': 'pending'},
            progress_builder=lambda task: {
                'status': 'processing',
                'meta': task.info or {},
            },
            success_builder=lambda task: {
                'status': 'completed',
                'result': task.result,
            },
            failure_builder=lambda task: {
                'status': 'failed',
                'error': str(task.result) if task.result else 'Unknown error',
            },
            other_builder=lambda task: {'status': (getattr(task, 'status', '') or '').lower()},
        )
        return jsonify(payload), status_code
        
    except Exception as e:
        logger.exception(f"Error getting task status: {task_id}")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/stats/<case_uuid>', methods=['GET'])
@login_required
def get_case_event_stats(case_uuid):
    """Get event statistics for a case
    
    Args:
        case_uuid: Case UUID
        
    Returns:
        JSON with event statistics
    """
    try:
        from utils.clickhouse import get_event_stats
        
        # Get case
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        stats = get_event_stats(case.id)
        stats['success'] = True
        stats['case_uuid'] = case_uuid
        
        return jsonify(stats)
        
    except Exception as e:
        logger.exception(f"Error getting stats for case: {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/destructive-rewrite/active', methods=['GET'])
@login_required
def get_active_destructive_rewrite():
    """Report whether a destructive events-table rewrite is currently running.

    Read-only visibility into the Redis rewrite lock so callers can check
    in-flight destructive work (case delete, dedup) without attempting a
    destructive call and parsing the 409.

    Returns:
        JSON with active flag and rewrite metadata (operation, case_id, started_at)
    """
    try:
        from utils.clickhouse import get_active_destructive_event_rewrite

        active_rewrite = get_active_destructive_event_rewrite()
        return jsonify({
            'success': True,
            'active': bool(active_rewrite),
            'rewrite': active_rewrite,
        })
    except Exception as e:
        logger.exception("Error reading active destructive rewrite state")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/delete-events/<case_uuid>', methods=['DELETE'])
@login_required
def delete_case_events(case_uuid):
    """Delete all events for a case from ClickHouse
    
    Args:
        case_uuid: Case UUID
        
    Returns:
        JSON with deletion status
    """
    try:
        from tasks import delete_case_events_task
        from tasks.celery_tasks import INTERACTIVE_CASE_DELETE_MAX_EVENTS
        from utils.clickhouse import count_events, get_active_destructive_event_rewrite

        if current_user.permission_level == 'viewer':
            return _viewer_write_error()

        data = request.get_json(silent=True) or {}
        force_large_delete = bool(data.get('force_large_delete'))
        
        # Get case
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404

        active_rewrite = get_active_destructive_event_rewrite()
        if active_rewrite:
            return jsonify({
                'success': False,
                'error': 'Another destructive event rewrite is already running',
                'active_rewrite': active_rewrite,
            }), 409

        event_count = count_events(case.id)
        if (
            INTERACTIVE_CASE_DELETE_MAX_EVENTS
            and event_count > INTERACTIVE_CASE_DELETE_MAX_EVENTS
            and not force_large_delete
        ):
            return jsonify({
                'success': False,
                'error': (
                    f'Case-wide event deletion is blocked for cases larger than '
                    f'{INTERACTIVE_CASE_DELETE_MAX_EVENTS} events without force_large_delete'
                ),
                'requires_force': True,
                'event_count': event_count,
                'safety_threshold_events': INTERACTIVE_CASE_DELETE_MAX_EVENTS,
            }), 409
        
        # Queue deletion task
        task = delete_case_events_task.delay(case_id=case.id, force_large_delete=force_large_delete)
        _remember_task_access(task.id, case_uuid=case_uuid)
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'case_uuid': case_uuid,
            'event_count': event_count,
            'force_large_delete': force_large_delete,
            'message': 'Event deletion queued',
        })
        
    except Exception as e:
        logger.exception(f"Error deleting events for case: {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/files/<case_uuid>', methods=['GET'])
@login_required
def get_case_file_status(case_uuid):
    """Get parsing status of all files for a case
    
    Args:
        case_uuid: Case UUID
        
    Returns:
        JSON with file statuses
    """
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get all case files
        files = CaseFile.query.filter_by(case_uuid=case_uuid).order_by(CaseFile.uploaded_at.desc()).all()
        
        # Group by status
        status_counts = {}
        file_list = []
        
        for cf in files:
            status_counts[cf.status] = status_counts.get(cf.status, 0) + 1
            file_list.append({
                'id': cf.id,
                'filename': cf.filename,
                'file_type': cf.file_type,
                'hostname': cf.hostname,
                'status': cf.status,
                'file_size': cf.file_size,
                'uploaded_at': cf.uploaded_at.isoformat() if cf.uploaded_at else None,
                'processed_at': cf.processed_at.isoformat() if cf.processed_at else None,
            })
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'total_files': len(files),
            'status_counts': status_counts,
            'files': file_list,
        })
        
    except Exception as e:
        logger.exception(f"Error getting file status for case: {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/sigma-rules/stats', methods=['GET'])
@login_required
def get_sigma_rules_stats():
    """Get Sigma/Hayabusa rule statistics
    
    Returns:
        JSON with rule count and last update timestamp
    """
    try:
        import subprocess
        from pathlib import Path
        
        rules_dir = Path(Config.RULES_FOLDER)
        
        # Check all possible rule directories
        # hayabusa-rules is the primary (updated via hayabusa update-rules)
        # hayabusa and sigma are legacy/bundled rules
        hayabusa_rules_dir = rules_dir / 'hayabusa-rules'
        hayabusa_legacy = rules_dir / 'hayabusa'
        sigma_legacy = rules_dir / 'sigma'
        
        # Count rules - prefer hayabusa-rules if it exists
        if hayabusa_rules_dir.exists():
            # New structure from hayabusa update-rules
            hayabusa_count = len(list((hayabusa_rules_dir / 'hayabusa').rglob('*.yml'))) if (hayabusa_rules_dir / 'hayabusa').exists() else 0
            sigma_count = len(list((hayabusa_rules_dir / 'sigma').rglob('*.yml'))) if (hayabusa_rules_dir / 'sigma').exists() else 0
            rules_paths = [hayabusa_rules_dir]
        else:
            # Fallback to legacy structure
            hayabusa_count = len(list(hayabusa_legacy.rglob('*.yml'))) if hayabusa_legacy.exists() else 0
            sigma_count = len(list(sigma_legacy.rglob('*.yml'))) if sigma_legacy.exists() else 0
            rules_paths = [hayabusa_legacy, sigma_legacy]
        
        total_count = hayabusa_count + sigma_count
        
        # Get last modification time (newest file in rules directories)
        last_updated = None
        newest_time = 0
        
        for rules_path in rules_paths:
            if rules_path.exists():
                for yml_file in rules_path.rglob('*.yml'):
                    mtime = yml_file.stat().st_mtime
                    if mtime > newest_time:
                        newest_time = mtime
        
        if newest_time > 0:
            from datetime import datetime
            last_updated = datetime.fromtimestamp(newest_time).isoformat()
        
        # Get hayabusa version if available
        hayabusa_version = None
        hayabusa_bin = os.path.join(Config.BIN_FOLDER, 'hayabusa')
        if os.path.exists(hayabusa_bin):
            try:
                result = subprocess.run(
                    [hayabusa_bin, '--version'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    hayabusa_version = result.stdout.strip().split('\n')[0]
            except Exception:
                pass
        
        return jsonify({
            'success': True,
            'hayabusa_rules': hayabusa_count,
            'sigma_rules': sigma_count,
            'total_rules': total_count,
            'last_updated': last_updated,
            'hayabusa_version': hayabusa_version,
            'hayabusa_available': os.path.exists(hayabusa_bin),
        })
        
    except Exception as e:
        logger.exception("Error getting sigma rule stats")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/update-rules', methods=['POST'])
@login_required
def update_hayabusa_rules():
    """Update Hayabusa detection rules
    
    Returns:
        JSON with update task info
    """
    try:
        from tasks import update_hayabusa_rules_task
        from utils.global_task_markers import get_global_task_inflight, mark_global_task_inflight
        
        # Admin only
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403

        inflight = get_global_task_inflight('hayabusa_rules_update')
        if inflight:
            if inflight.get('task_id'):
                _remember_task_access(inflight['task_id'])
            return jsonify({
                'success': False,
                'error': 'A Hayabusa rule update is already running',
                'in_progress': True,
                'task_id': inflight.get('task_id'),
            }), 409
        
        task = update_hayabusa_rules_task.delay()
        mark_global_task_inflight('hayabusa_rules_update', task_id=task.id)
        _remember_task_access(task.id)
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'Rule update queued',
        })
        
    except Exception as e:
        logger.exception("Error queuing rule update")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/update-rules/active', methods=['GET'])
@login_required
def get_active_hayabusa_update():
    """Report whether a Hayabusa rule update is currently in flight."""
    try:
        from utils.global_task_markers import get_global_task_inflight

        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403

        inflight = get_global_task_inflight('hayabusa_rules_update')
        if inflight and inflight.get('task_id'):
            _remember_task_access(inflight['task_id'])
        return jsonify({
            'success': True,
            'active': bool(inflight),
            'task_id': (inflight or {}).get('task_id'),
        })
    except Exception as e:
        logger.exception("Error reading active Hayabusa update state")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# MITRE ATT&CK Enterprise API Endpoints
# ============================================================================

@parsing_bp.route('/mitre/stats', methods=['GET'])
@login_required
def get_mitre_attack_stats():
    """Get local MITRE ATT&CK Enterprise database statistics."""
    try:
        from models.mitre_attack import MitreAttackObject

        stats = MitreAttackObject.get_stats()
        return jsonify({
            'success': True,
            **stats,
        })

    except Exception as e:
        logger.exception("Error getting MITRE ATT&CK stats")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/mitre/check', methods=['POST'])
@login_required
def check_mitre_attack_update():
    """Check whether the remote MITRE ATT&CK Enterprise version changed."""
    try:
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403

        from utils.mitre_attack_sync import check_for_mitre_update

        return jsonify(check_for_mitre_update())

    except Exception as e:
        logger.exception("Error checking MITRE ATT&CK update status")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/mitre/update', methods=['POST'])
@login_required
def update_mitre_attack_database():
    """Queue MITRE ATT&CK Enterprise database update."""
    try:
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403

        from tasks import update_mitre_attack_database_task
        from utils.global_task_markers import get_global_task_inflight, mark_global_task_inflight

        inflight = get_global_task_inflight('mitre_update')
        if inflight:
            if inflight.get('task_id'):
                _remember_task_access(inflight['task_id'])
            return jsonify({
                'success': False,
                'error': 'A MITRE ATT&CK update is already running',
                'in_progress': True,
                'task_id': inflight.get('task_id'),
            }), 409

        task = update_mitre_attack_database_task.delay(current_user.username)
        mark_global_task_inflight('mitre_update', task_id=task.id)
        _remember_task_access(task.id)

        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'MITRE ATT&CK update queued',
        })

    except Exception as e:
        logger.exception("Error queuing MITRE ATT&CK update")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/mitre/update/active', methods=['GET'])
@login_required
def get_active_mitre_update():
    """Report whether a MITRE ATT&CK update is currently in flight."""
    try:
        from utils.global_task_markers import get_global_task_inflight

        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403

        inflight = get_global_task_inflight('mitre_update')
        if inflight and inflight.get('task_id'):
            _remember_task_access(inflight['task_id'])
        return jsonify({
            'success': True,
            'active': bool(inflight),
            'task_id': (inflight or {}).get('task_id'),
        })
    except Exception as e:
        logger.exception("Error reading active MITRE update state")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# EVTX Event Description API Endpoints
# ============================================================================

@parsing_bp.route('/evtx-descriptions/stats', methods=['GET'])
@login_required
def get_evtx_description_stats():
    """Get EVTX event description statistics
    
    Returns:
        JSON with event description stats
    """
    try:
        from models.event_description import EventDescription
        
        stats = EventDescription.get_stats()
        
        return jsonify({
            'success': True,
            'total_events': stats['total'],
            'by_source': stats['by_source'],
            'by_category': stats['by_category'],
            'by_website': stats['by_website'],
            'manual_count': stats.get('manual_count', 0),
            'last_updated': stats['last_updated']
        })
        
    except Exception as e:
        logger.exception("Error getting EVTX description stats")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/evtx-descriptions/scrape', methods=['POST'])
@login_required
def scrape_evtx_descriptions():
    """Trigger EVTX description scraping task
    
    Returns:
        JSON with task info
    """
    try:
        from tasks.celery_tasks import celery_app
        from utils.global_task_markers import get_global_task_inflight, mark_global_task_inflight
        
        # Admin only
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403

        inflight = get_global_task_inflight('evtx_scrape')
        if inflight:
            if inflight.get('task_id'):
                _remember_task_access(inflight['task_id'])
            return jsonify({
                'success': False,
                'error': 'An EVTX description scrape is already running',
                'in_progress': True,
                'task_id': inflight.get('task_id'),
            }), 409
        
        # Queue the scraping task
        task = celery_app.send_task('tasks.scrape_event_descriptions')
        mark_global_task_inflight('evtx_scrape', task_id=task.id)
        _remember_task_access(task.id)
        
        logger.info(f"Event description scraping task queued: {task.id}")
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'Scraping task started'
        })
        
    except Exception as e:
        logger.exception("Error starting EVTX scrape task")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/evtx-descriptions/scrape/active', methods=['GET'])
@login_required
def get_active_evtx_scrape():
    """Report whether an EVTX description scrape is currently in flight.

    Lets the settings page re-attach to a running scrape after a reload
    (cross-user); the running task id is remembered for this session so the
    task-keyed status endpoint accepts subsequent polls.
    """
    try:
        from utils.global_task_markers import get_global_task_inflight

        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403

        inflight = get_global_task_inflight('evtx_scrape')
        if inflight and inflight.get('task_id'):
            _remember_task_access(inflight['task_id'])
        return jsonify({
            'success': True,
            'active': bool(inflight),
            'task_id': (inflight or {}).get('task_id'),
        })
    except Exception as e:
        logger.exception("Error reading active EVTX scrape state")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/evtx-descriptions/scrape/status/<task_id>', methods=['GET'])
@login_required
def get_evtx_scrape_status(task_id):
    """Check status of EVTX description scraping task
    
    Returns:
        JSON with task status
    """
    try:
        from celery.result import AsyncResult

        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        if not _task_access_allowed(task_id):
            return jsonify({'success': False, 'error': 'Task not found'}), 404
        
        task = AsyncResult(task_id)

        payload, status_code = build_async_status_response(
            task,
            task_id=task_id,
            pending_builder=lambda _task: {'status': 'pending'},
            progress_builder=lambda task: {
                'status': (task.info or {}).get('status', ''),
                'meta': task.info or {},
            },
            success_builder=lambda task: {'status': 'completed', 'result': task.result},
            failure_builder=lambda task: {'status': 'failed', 'error': str(task.info)},
            other_builder=lambda task: {'status': (getattr(task, 'state', '') or '').lower()},
        )
        return jsonify(payload), status_code
        
    except Exception as e:
        logger.exception("Error checking EVTX scrape task status")
        return jsonify({'error': str(e)}), 500


@parsing_bp.route('/evtx-descriptions', methods=['GET'])
@login_required
def list_evtx_descriptions():
    """List EVTX event descriptions for settings management."""
    try:
        from models.event_description import EventDescription
        from sqlalchemy import or_

        page = max(request.args.get('page', 1, type=int), 1)
        per_page = min(max(request.args.get('per_page', 25, type=int), 1), 100)
        query_text = (request.args.get('q') or '').strip()
        manual_filter = (request.args.get('manual') or '').strip().lower()

        query = EventDescription.query

        if query_text:
            like = f"%{query_text}%"
            query = query.filter(
                or_(
                    EventDescription.event_id.ilike(like),
                    EventDescription.log_source.ilike(like),
                    EventDescription.description.ilike(like),
                    EventDescription.category.ilike(like),
                )
            )

        if manual_filter in {'true', '1', 'yes'}:
            query = query.filter_by(manually_set=True)
        elif manual_filter in {'false', '0', 'no'}:
            query = query.filter_by(manually_set=False)

        pagination = query.order_by(
            EventDescription.manually_set.desc(),
            EventDescription.log_source.asc(),
            EventDescription.event_id.asc(),
        ).paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'success': True,
            'descriptions': [
                {
                    'id': item.id,
                    'event_id': item.event_id,
                    'log_source': item.log_source,
                    'description': item.description,
                    'category': item.category,
                    'subcategory': item.subcategory,
                    'source_website': item.source_website,
                    'source_url': item.source_url,
                    'manually_set': item.manually_set,
                    'updated_at': item.updated_at.isoformat() if item.updated_at else None,
                }
                for item in pagination.items
            ],
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total': pagination.total,
            'total_pages': pagination.pages,
        })

    except Exception as e:
        logger.exception("Error listing EVTX descriptions")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/evtx-descriptions/<int:description_id>', methods=['GET'])
@login_required
def get_evtx_description_record(description_id):
    """Get one EVTX event description record for editing."""
    try:
        from models.event_description import EventDescription

        item = EventDescription.query.get(description_id)
        if not item:
            return jsonify({'success': False, 'error': 'Event description not found'}), 404

        return jsonify({
            'success': True,
            'description': {
                'id': item.id,
                'event_id': item.event_id,
                'log_source': item.log_source,
                'description': item.description,
                'category': item.category,
                'subcategory': item.subcategory,
                'source_website': item.source_website,
                'source_url': item.source_url,
                'manually_set': item.manually_set,
            }
        })

    except Exception as e:
        logger.exception("Error getting EVTX description")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/evtx-descriptions/save', methods=['POST'])
@login_required
def save_evtx_description():
    """Create or update an EVTX event description from settings."""
    try:
        from models.event_description import EventDescription
        from utils.evtx_descriptions import clear_cache, normalize_channel_name

        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403

        data = request.get_json() or {}
        description_id = data.get('id')
        event_id = str(data.get('event_id') or '').strip()
        log_source = normalize_channel_name(str(data.get('log_source') or '').strip())
        description = str(data.get('description') or '').strip()
        category = str(data.get('category') or '').strip() or None
        subcategory = str(data.get('subcategory') or '').strip() or None
        source_url = str(data.get('source_url') or '').strip() or None
        manually_set = bool(data.get('manually_set', True))

        if not event_id:
            return jsonify({'success': False, 'error': 'Event ID is required'}), 400
        if not log_source:
            return jsonify({'success': False, 'error': 'Log source is required'}), 400
        if not description:
            return jsonify({'success': False, 'error': 'Description is required'}), 400

        if description_id:
            item = EventDescription.query.get(description_id)
            if not item:
                return jsonify({'success': False, 'error': 'Event description not found'}), 404
        else:
            item = EventDescription.query.filter_by(
                event_id=event_id,
                log_source=log_source,
            ).first()
            if not item:
                item = EventDescription(
                    event_id=event_id,
                    log_source=log_source,
                )
                db.session.add(item)

        duplicate = EventDescription.query.filter(
            EventDescription.event_id == event_id,
            EventDescription.log_source == log_source,
        )
        if description_id:
            duplicate = duplicate.filter(EventDescription.id != description_id)
        if duplicate.first():
            return jsonify({
                'success': False,
                'error': 'Another description already exists for this Event ID and log source'
            }), 409

        item.event_id = event_id
        item.log_source = log_source
        item.description = description
        item.category = category
        item.subcategory = subcategory
        item.source_website = 'manual' if manually_set else (item.source_website or 'manual')
        item.source_url = source_url
        item.description_length = len(description)
        item.manually_set = manually_set

        db.session.commit()
        clear_cache()

        return jsonify({
            'success': True,
            'message': 'Event description saved',
            'description_id': item.id,
        })

    except Exception as e:
        db.session.rollback()
        logger.exception("Error saving EVTX description")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/evtx-descriptions/lookup', methods=['GET'])
@login_required
def lookup_evtx_description():
    """Look up a specific event description
    
    Query params:
        event_id: The Windows Event ID
        channel: The event log channel (e.g., Security, System)
    
    Returns:
        JSON with event description if found
    """
    try:
        from utils.evtx_descriptions import get_event_description
        
        event_id = request.args.get('event_id', '')
        channel = request.args.get('channel', '')
        
        if not event_id:
            return jsonify({'success': False, 'error': 'event_id required'}), 400
        
        title, description = get_event_description(event_id, channel)
        
        if title:
            return jsonify({
                'success': True,
                'found': True,
                'event_id': event_id,
                'channel': channel,
                'title': title,
                'description': description
            })
        else:
            return jsonify({
                'success': True,
                'found': False,
                'event_id': event_id,
                'channel': channel
            })
        
    except Exception as e:
        logger.exception("Error looking up EVTX description")
        return jsonify({'success': False, 'error': str(e)}), 500


@parsing_bp.route('/evtx-descriptions/batch', methods=['POST'])
@login_required
def batch_lookup_evtx_descriptions():
    """Batch lookup event descriptions
    
    Request body:
        events: List of {event_id, channel} objects
    
    Returns:
        JSON with descriptions keyed by "event_id:channel"
    """
    try:
        from utils.evtx_descriptions import get_event_description
        
        data = request.get_json() or {}
        events = data.get('events', [])
        
        if not events:
            return jsonify({'success': True, 'descriptions': {}})
        
        # Limit batch size
        if len(events) > 200:
            events = events[:200]
        
        descriptions = {}
        
        for event in events:
            event_id = str(event.get('event_id', ''))
            channel = event.get('channel', '')
            
            if not event_id:
                continue
            
            # Create cache key
            cache_key = f"{event_id}:{channel}"
            
            # Skip if we already looked this up
            if cache_key in descriptions:
                continue
            
            title, description = get_event_description(event_id, channel)
            
            if title:
                descriptions[cache_key] = {
                    'title': title,
                    'description': description
                }
        
        return jsonify({
            'success': True,
            'descriptions': descriptions
        })
        
    except Exception as e:
        logger.exception("Error in batch EVTX description lookup")
        return jsonify({'success': False, 'error': str(e)}), 500
