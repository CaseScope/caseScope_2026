"""Celery Tasks for CaseScope

Provides asynchronous processing for:
- File parsing and ingestion
- Batch case processing
- Hayabusa rule updates
- Case event deletion
"""
import os
import shutil
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from celery import Celery, chain, group, chord
from celery.exceptions import SoftTimeLimitExceeded

from config import Config

logger = logging.getLogger(__name__)

# Cached Flask app instance to avoid creating new connection pools for each task
_flask_app = None

def get_flask_app():
    """Get or create a shared Flask app instance for Celery tasks"""
    global _flask_app
    if _flask_app is None:
        from app import create_app
        _flask_app = create_app()
    return _flask_app

# Initialize Celery
celery_app = Celery(
    'casescope',
    broker=Config.CELERY_BROKER_URL,
    backend=Config.CELERY_RESULT_BACKEND,
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour hard limit
    task_soft_time_limit=3300,  # 55 minute soft limit
    worker_prefetch_multiplier=1,  # One task at a time per worker
    task_acks_late=True,  # Acknowledge after completion
    task_reject_on_worker_lost=True,
    result_expires=86400,  # Results expire after 24 hours
)


@celery_app.task(bind=True, name='tasks.parse_file')
def parse_file_task(self, file_path: str, case_id: int, source_host: str = '',
                   case_file_id: Optional[int] = None) -> Dict[str, Any]:
    """Parse a single file and insert events into ClickHouse
    
    Args:
        file_path: Path to the file to parse
        case_id: PostgreSQL case.id (used as ClickHouse case_id)
        source_host: Hostname the file came from
        case_file_id: PostgreSQL case_files.id
        
    Returns:
        Dict with parsing results
    """
    from parsers import process_file, get_registry
    from utils.clickhouse import get_fresh_client
    
    logger.info(f"Processing file: {file_path} for case {case_id}")
    
    # Mark file as ingesting
    if case_file_id:
        _update_case_file_status(
            case_file_id=case_file_id,
            status='ingesting',
            ingestion_status='not_done'
        )
    
    # Update task state
    self.update_state(state='PROCESSING', meta={
        'file': file_path,
        'stage': 'starting',
    })
    
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            if case_file_id:
                _update_case_file_status(
                    case_file_id=case_file_id,
                    status='error',
                    ingestion_status='error',
                    error_message='File not found on disk'
                )
            return {'success': False, 'error': 'File not found'}
        
        # Check if we have a parser for this file
        registry = get_registry()
        artifact_type = registry.detect_type(file_path)
        
        if not artifact_type:
            # No parser available
            if case_file_id:
                _update_case_file_status(
                    case_file_id=case_file_id,
                    status='done',
                    ingestion_status='no_parser',
                    parser_type=None
                )
            return {'success': True, 'events_count': 0, 'artifact_type': None, 'message': 'No parser available'}
        
        # Get fresh ClickHouse client for this task
        client = get_fresh_client()
        
        # Process the file
        result = process_file(
            file_path=file_path,
            case_id=case_id,
            source_host=source_host,
            case_file_id=case_file_id,
            clickhouse_client=client,
        )
        
        # Update case_file status in PostgreSQL
        if case_file_id:
            if result.success:
                ingestion_status = 'full' if result.events_count > 0 else 'full'
                if result.warnings:
                    ingestion_status = 'partial'
                _update_case_file_status(
                    case_file_id=case_file_id,
                    status='done',
                    ingestion_status=ingestion_status,
                    events_count=result.events_count,
                    parser_type=result.artifact_type
                )
            else:
                _update_case_file_status(
                    case_file_id=case_file_id,
                    status='error',
                    ingestion_status='parse_error',
                    events_count=result.events_count,
                    parser_type=result.artifact_type,
                    error_message='; '.join(result.errors) if result.errors else 'Unknown parse error'
                )
        
        return result.to_dict()
        
    except SoftTimeLimitExceeded:
        logger.warning(f"Task soft time limit exceeded for {file_path}")
        if case_file_id:
            _update_case_file_status(
                case_file_id=case_file_id,
                status='error',
                ingestion_status='error',
                error_message='Task timeout'
            )
        raise
        
    except Exception as e:
        logger.exception(f"Error processing file {file_path}")
        if case_file_id:
            _update_case_file_status(
                case_file_id=case_file_id,
                status='error',
                ingestion_status='error',
                error_message=str(e)
            )
        raise


@celery_app.task(bind=True, name='tasks.process_case_files')
def process_case_files_task(self, case_uuid: str, file_ids: List[int] = None) -> Dict[str, Any]:
    """Process all pending files for a case
    
    Args:
        case_uuid: Case UUID
        file_ids: Optional list of specific file IDs to process
        
    Returns:
        Dict with processing summary
    """
    from models.database import db
    from models.case import Case
    from models.case_file import CaseFile
    
    # Use shared app instance
    app = get_flask_app()
    
    with app.app_context():
        # Get case
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return {'success': False, 'error': f'Case not found: {case_uuid}'}
        
        # Get files to process
        if file_ids:
            files = CaseFile.query.filter(
                CaseFile.id.in_(file_ids),
                CaseFile.case_uuid == case_uuid
            ).all()
        else:
            files = CaseFile.query.filter_by(
                case_uuid=case_uuid,
                status='pending'
            ).all()
        
        if not files:
            return {'success': True, 'message': 'No files to process', 'processed': 0}
        
        # Update task state
        self.update_state(state='PROCESSING', meta={
            'total_files': len(files),
            'processed': 0,
        })
        
        # Queue parsing tasks for each file
        tasks = []
        for cf in files:
            if cf.file_path and os.path.exists(cf.file_path):
                # Mark as processing
                cf.status = 'processing'
                db.session.commit()
                
                # Queue task
                task = parse_file_task.delay(
                    file_path=cf.file_path,
                    case_id=case.id,  # Use integer ID for ClickHouse
                    source_host=cf.hostname or '',
                    case_file_id=cf.id,
                )
                tasks.append({
                    'task_id': task.id,
                    'file_id': cf.id,
                    'filename': cf.filename,
                })
        
        return {
            'success': True,
            'case_uuid': case_uuid,
            'case_id': case.id,
            'queued_tasks': tasks,
            'total_files': len(files),
        }


@celery_app.task(bind=True, name='tasks.process_staging_directory')
def process_staging_directory_task(self, case_uuid: str, staging_path: str = None) -> Dict[str, Any]:
    """Process all files in a case's staging directory
    
    Args:
        case_uuid: Case UUID
        staging_path: Optional override for staging path
        
    Returns:
        Dict with processing summary
    """
    from parsers import process_directory
    from utils.clickhouse import get_fresh_client
    
    # Build staging path
    if not staging_path:
        staging_path = os.path.join(Config.STAGING_FOLDER, case_uuid)
    
    if not os.path.isdir(staging_path):
        return {'success': False, 'error': f'Staging directory not found: {staging_path}'}
    
    # Get case ID using shared app instance
    from models.case import Case
    app = get_flask_app()
    
    with app.app_context():
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return {'success': False, 'error': f'Case not found: {case_uuid}'}
        case_id = case.id
    
    logger.info(f"Processing staging directory: {staging_path} for case {case_uuid}")
    
    # Update task state
    self.update_state(state='PROCESSING', meta={
        'stage': 'scanning',
        'directory': staging_path,
    })
    
    try:
        client = get_fresh_client()
        
        results = process_directory(
            dir_path=staging_path,
            case_id=case_id,
            clickhouse_client=client,
            recursive=True,
        )
        
        # Summarize results
        success_count = sum(1 for r in results if r.success)
        failure_count = sum(1 for r in results if not r.success)
        total_events = sum(r.events_count for r in results)
        
        return {
            'success': True,
            'case_uuid': case_uuid,
            'directory': staging_path,
            'files_processed': len(results),
            'success_count': success_count,
            'failure_count': failure_count,
            'total_events': total_events,
            'results': [r.to_dict() for r in results],
        }
        
    except Exception as e:
        logger.exception(f"Error processing staging directory {staging_path}")
        return {'success': False, 'error': str(e)}


@celery_app.task(bind=True, name='tasks.delete_case_events')
def delete_case_events_task(self, case_id: int) -> Dict[str, Any]:
    """Delete all events for a case from ClickHouse
    
    Args:
        case_id: ClickHouse case_id to delete events for
        
    Returns:
        Dict with deletion status
    """
    from utils.clickhouse import get_fresh_client
    
    logger.info(f"Deleting events for case {case_id}")
    
    try:
        client = get_fresh_client()
        
        # Count events before deletion
        count_result = client.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
            parameters={'case_id': case_id}
        )
        event_count = count_result.result_rows[0][0] if count_result.result_rows else 0
        
        # Delete events (async operation in ClickHouse)
        client.command(f"ALTER TABLE events DELETE WHERE case_id = {case_id}")
        
        # Also delete from buffer table
        try:
            client.command(f"ALTER TABLE events_buffer DELETE WHERE case_id = {case_id}")
        except:
            pass  # Buffer might not exist
        
        return {
            'success': True,
            'case_id': case_id,
            'events_deleted': event_count,
            'note': 'Deletion is asynchronous in ClickHouse, events may take time to fully remove',
        }
        
    except Exception as e:
        logger.exception(f"Error deleting events for case {case_id}")
        return {'success': False, 'error': str(e)}


@celery_app.task(name='tasks.update_hayabusa_rules')
def update_hayabusa_rules_task() -> Dict[str, Any]:
    """Update Hayabusa detection rules
    
    Returns:
        Dict with update status
    """
    from parsers.evtx_parser import HayabusaParser
    
    logger.info("Updating Hayabusa rules")
    
    try:
        success = HayabusaParser.update_rules()
        return {
            'success': success,
            'message': 'Rules updated successfully' if success else 'Rule update failed',
            'timestamp': datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.exception("Error updating Hayabusa rules")
        return {'success': False, 'error': str(e)}


@celery_app.task(name='tasks.get_case_stats')
def get_case_stats_task(case_id: int) -> Dict[str, Any]:
    """Get event statistics for a case
    
    Args:
        case_id: ClickHouse case_id
        
    Returns:
        Dict with statistics
    """
    from utils.clickhouse import get_event_stats
    
    try:
        stats = get_event_stats(case_id)
        stats['case_id'] = case_id
        stats['success'] = True
        return stats
    except Exception as e:
        logger.exception(f"Error getting stats for case {case_id}")
        return {'success': False, 'error': str(e)}


# Helper functions

def _move_file_to_storage(file_path: str) -> Optional[str]:
    """Move a file from staging to storage, preserving path structure.
    
    Args:
        file_path: Current file path in staging
        
    Returns:
        New file path in storage, or None if move failed
    """
    if not file_path:
        return None
    
    # Check if file is in staging
    staging_prefix = Config.STAGING_FOLDER
    if not file_path.startswith(staging_prefix):
        logger.debug(f"File not in staging, skipping move: {file_path}")
        return file_path  # Already not in staging, return as-is
    
    # Check if source file exists
    if not os.path.exists(file_path):
        logger.warning(f"Source file not found for move: {file_path}")
        return None
    
    # Build storage path by replacing staging prefix with storage prefix
    relative_path = file_path[len(staging_prefix):].lstrip(os.sep)
    storage_path = os.path.join(Config.STORAGE_FOLDER, relative_path)
    
    try:
        # Create destination directory if needed
        storage_dir = os.path.dirname(storage_path)
        os.makedirs(storage_dir, exist_ok=True)
        
        # Move the file
        shutil.move(file_path, storage_path)
        logger.info(f"Moved file to storage: {file_path} -> {storage_path}")
        
        return storage_path
        
    except Exception as e:
        logger.error(f"Failed to move file to storage: {file_path} -> {storage_path}: {e}")
        return None


def _update_case_file_status(case_file_id: int, status: str = None, 
                            ingestion_status: str = None,
                            events_count: int = None,
                            parser_type: str = None,
                            error_message: str = None,
                            errors: List[str] = None):
    """Update CaseFile status in PostgreSQL
    
    Args:
        case_file_id: ID of the CaseFile to update
        status: Workflow status (new, queued, ingesting, error, done)
        ingestion_status: Parsing result (not_done, full, partial, no_parser, parse_error, error)
        events_count: Number of events indexed
        parser_type: Parser type used (e.g., EVTX, HuntressNDJSON)
        error_message: Error message if parsing failed
        errors: Legacy list of errors (converted to error_message)
    """
    try:
        from models.database import db
        from models.case_file import CaseFile
        
        app = get_flask_app()
        with app.app_context():
            cf = CaseFile.query.get(case_file_id)
            if cf:
                if status is not None:
                    cf.status = status
                if ingestion_status is not None:
                    cf.ingestion_status = ingestion_status
                if events_count is not None:
                    cf.events_indexed = events_count
                if parser_type is not None:
                    cf.parser_type = parser_type
                if error_message is not None:
                    cf.error_message = error_message
                elif errors:
                    cf.error_message = '; '.join(errors)
                
                # Set processed_at when done or error
                if status in ('done', 'error'):
                    cf.processed_at = datetime.utcnow()
                
                # Move file from staging to storage when done successfully
                if status == 'done' and cf.file_path:
                    new_path = _move_file_to_storage(cf.file_path)
                    if new_path:
                        cf.file_path = new_path
                
                # Get case_uuid before commit for progress tracking
                case_uuid = cf.case_uuid
                
                db.session.commit()
                logger.debug(f"Updated CaseFile {case_file_id}: status={status}, ingestion={ingestion_status}")
                
                # Increment progress counter when file processing completes
                if status in ('done', 'error'):
                    from utils.progress import increment_progress
                    increment_progress(case_uuid)
                    
    except Exception as e:
        logger.warning(f"Could not update CaseFile status: {e}")


# Periodic tasks (if using Celery Beat)
celery_app.conf.beat_schedule = {
    'update-hayabusa-rules-weekly': {
        'task': 'tasks.update_hayabusa_rules',
        'schedule': 604800.0,  # Weekly (seconds)
    },
}


# Task routing (disabled for now - all tasks go to default queue)
# To enable separate queues, start workers with: celery -A tasks worker -Q parsing,maintenance,default
# celery_app.conf.task_routes = {
#     'tasks.parse_file': {'queue': 'parsing'},
#     'tasks.process_case_files': {'queue': 'parsing'},
#     'tasks.process_staging_directory': {'queue': 'parsing'},
#     'tasks.delete_case_events': {'queue': 'maintenance'},
#     'tasks.update_hayabusa_rules': {'queue': 'maintenance'},
#     'tasks.get_case_stats': {'queue': 'default'},
# }
