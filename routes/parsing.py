"""Parsing API Routes for CaseScope

Provides endpoints for:
- Triggering file parsing
- Checking parse status
- Managing parsing tasks
"""
import os
import logging
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from models.database import db
from models.case import Case
from models.case_file import CaseFile
from config import Config
from utils.artifact_paths import ensure_case_artifact_paths, is_within_any_root, is_within_root

logger = logging.getLogger(__name__)

parsing_bp = Blueprint('parsing', __name__, url_prefix='/api/parsing')


def _viewer_write_error():
    return jsonify({'success': False, 'error': 'Viewers cannot modify parsing state'}), 403


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
    """Queue a single file for parsing
    
    Request JSON:
        case_uuid: Case UUID
        case_file_id: CaseFile ID
        
    Returns:
        JSON with task ID
    """
    try:
        if current_user.permission_level == 'viewer':
            return _viewer_write_error()

        from tasks import parse_file_task
        
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
        
        case_paths = ensure_case_artifact_paths(case_uuid)
        if not case_file.file_path or not os.path.exists(case_file.file_path):
            return jsonify({
                'success': False,
                'error': 'Transient working file is no longer available on disk. Reparse after staging cleanup is not supported in this phase.'
            }), 409

        if not is_within_root(case_file.file_path, case_paths['staging']):
            return jsonify({
                'success': False,
                'error': 'Reparse is only available while a file is still in staging. Retained originals are preserved separately and reparse from originals is not enabled in this phase.'
            }), 409
        
        # Update status
        case_file.status = 'queued'
        db.session.commit()
        
        # Queue task
        task = parse_file_task.delay(
            file_path=case_file.file_path,
            case_id=case.id,
            source_host=case_file.hostname or '',
            case_file_id=case_file.id,
        )
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'case_file_id': case_file.id,
            'filename': case_file.filename,
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
        
        result = celery_app.AsyncResult(task_id)
        
        response = {
            'task_id': task_id,
            'status': result.status,
            'ready': result.ready(),
        }
        
        if result.ready():
            if result.successful():
                response['result'] = result.result
            else:
                response['error'] = str(result.result) if result.result else 'Unknown error'
        elif result.status == 'PROCESSING':
            response['meta'] = result.info
        
        return jsonify(response)
        
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
        
        # Get case
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Queue deletion task
        task = delete_case_events_task.delay(case_id=case.id)
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'case_uuid': case_uuid,
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
        
        # Admin only
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        
        task = update_hayabusa_rules_task.delay()
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'Rule update queued',
        })
        
    except Exception as e:
        logger.exception("Error queuing rule update")
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
        
        # Admin only
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        
        # Queue the scraping task
        task = celery_app.send_task('tasks.scrape_event_descriptions')
        
        logger.info(f"Event description scraping task queued: {task.id}")
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'Scraping task started'
        })
        
    except Exception as e:
        logger.exception("Error starting EVTX scrape task")
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
        
        task = AsyncResult(task_id)
        
        response = {
            'task_id': task_id,
            'state': task.state,
            'ready': task.ready()
        }
        
        if task.state == 'PROGRESS':
            response['status'] = task.info.get('status', '')
        elif task.state == 'SUCCESS':
            response['result'] = task.result
        elif task.state == 'FAILURE':
            response['error'] = str(task.info)
        
        return jsonify(response)
        
    except Exception as e:
        logger.exception("Error checking EVTX scrape task status")
        return jsonify({'error': str(e)}), 500


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
