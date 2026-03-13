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
    task_time_limit=14400,  # 4 hour hard limit (supports 4GB+ EVTX/MFT files)
    task_soft_time_limit=14100,  # 3h55m soft limit
    worker_prefetch_multiplier=1,  # One task at a time per worker
    task_acks_late=True,  # Acknowledge after completion
    task_reject_on_worker_lost=True,
    result_expires=86400,  # Results expire after 24 hours
    result_backend_always_retry=True,
    result_backend_max_retries=3,
    task_allow_join_result=True,  # Allow .get() in tasks for parallel phase dispatch
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
    from models.case import Case
    
    logger.info(f"Processing file: {file_path} for case {case_id}")
    
    # Fetch case timezone for timestamp normalization
    # Must use app context for database access in Celery worker
    case_tz = 'UTC'  # Default
    try:
        app = get_flask_app()
        with app.app_context():
            case = Case.query.get(case_id)
            if case and case.timezone:
                case_tz = case.timezone
    except Exception as e:
        logger.warning(f"Could not fetch case timezone: {e}")
    
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
            case_tz=case_tz,
        )
        
        # Update case_file status in PostgreSQL
        if case_file_id:
            if result.success:
                # Check if parser rejected file (artifact_type is None)
                if result.artifact_type is None:
                    ingestion_status = 'no_parser'
                elif result.events_count > 0:
                    ingestion_status = 'full'
                    if result.warnings:
                        ingestion_status = 'partial'
                elif result.artifact_type == 'registry':
                    ingestion_status = 'partial'
                else:
                    ingestion_status = 'full'
                    
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
    from parsers.evtx_parser import EvtxECmdParser
    
    logger.info("Updating Hayabusa rules")
    
    try:
        success = EvtxECmdParser.update_rules()
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
    
    Uses row-level locking (SELECT FOR UPDATE) to prevent concurrent update conflicts.
    
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
        from sqlalchemy import select
        
        app = get_flask_app()
        with app.app_context():
            # Use row-level locking to prevent concurrent update conflicts
            # with_for_update() is a method on Select, not a separate import
            stmt = select(CaseFile).where(CaseFile.id == case_file_id).with_for_update()
            cf = db.session.execute(stmt).scalar_one_or_none()
            
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
                
                # Move file from staging to storage when processing completes
                # This includes: done, error, and duplicate (hash_only - not parsed but kept)
                # We keep all files in storage for reference, status indicates parse result
                if status in ('done', 'error', 'duplicate') and cf.file_path:
                    new_path = _move_file_to_storage(cf.file_path)
                    if new_path:
                        cf.file_path = new_path
                    else:
                        # Move failed - file stays in staging, log warning
                        logger.warning(f"Failed to move file to storage, remains in staging: {cf.file_path}")
                        if not cf.error_message:
                            cf.error_message = 'File processed but failed to move to storage'
                
                # Get case_uuid before commit for progress tracking
                case_uuid = cf.case_uuid
                
                db.session.commit()
                logger.debug(f"Updated CaseFile {case_file_id}: status={status}, ingestion={ingestion_status}")
                
                # Increment progress counter when file processing completes
                if status in ('done', 'error'):
                    from utils.progress import increment_progress, mark_completion_triggered, set_phase
                    progress = increment_progress(case_uuid)
                    
                    # Check if this was the last file - trigger completion tasks
                    # Use atomic lock to ensure only ONE worker triggers completion
                    if progress and progress.get('status') == 'complete':
                        if mark_completion_triggered(case_uuid):
                            from models.case import Case
                            case = Case.get_by_uuid(case_uuid)
                            if case:
                                # Set phase to indicate we're waiting for post-processing to start
                                set_phase(case_uuid, 'waiting_for_completion')
                                logger.info(f"All files complete for case {case_uuid}, triggering completion tasks")
                                case_indexing_complete_task.delay(
                                    case_id=case.id,
                                    case_uuid=case_uuid
                                )
                    
    except Exception as e:
        logger.warning(f"Could not update CaseFile status: {e}")


@celery_app.task(bind=True, name='tasks.case_indexing_complete')
def case_indexing_complete_task(self, case_id: int, case_uuid: str, _retry_count: int = 0) -> Dict[str, Any]:
    """Run post-indexing completion tasks for a case
    
    Triggered automatically when all files finish processing.
    
    Steps:
    0. Verify no files are still processing (defer if needed)
    1. Flush ClickHouse buffer table to main events table
    2. Run known systems discovery
    3. Run known users discovery
    
    Args:
        case_id: PostgreSQL case.id
        case_uuid: Case UUID
        _retry_count: Internal counter for deferred retries
        
    Returns:
        Dict with completion results
    """
    from utils.clickhouse import get_fresh_client
    from utils.progress import clear_progress, set_phase, clear_completion_trigger
    
    logger.info(f"Running completion tasks for case {case_uuid}")
    
    # Step 0: Verify no files are still pending/queued/ingesting
    # This prevents early completion if new files were added during processing
    app = get_flask_app()
    with app.app_context():
        from models.case_file import CaseFile
        
        # Exclude archives (is_archive=True) - they are tracked but not parsed
        pending_count = CaseFile.query.filter(
            CaseFile.case_uuid == case_uuid,
            CaseFile.status.in_(['new', 'queued', 'ingesting']),
            CaseFile.is_archive == False
        ).count()
        
        if pending_count > 0:
            max_retries = 10  # Max 10 retries (5 minutes total)
            if _retry_count < max_retries:
                logger.info(f"Deferring completion for case {case_uuid} - {pending_count} files still processing (retry {_retry_count + 1}/{max_retries})")
                # Clear completion trigger so it can be set again
                clear_completion_trigger(case_uuid)
                # Re-queue self with 30 second delay
                case_indexing_complete_task.apply_async(
                    args=[case_id, case_uuid],
                    kwargs={'_retry_count': _retry_count + 1},
                    countdown=30
                )
                return {
                    'case_uuid': case_uuid,
                    'status': 'deferred',
                    'pending_files': pending_count,
                    'retry_count': _retry_count + 1
                }
            else:
                logger.warning(f"Max retries reached for case {case_uuid} with {pending_count} files still pending - proceeding anyway")
    
    results = {
        'case_uuid': case_uuid,
        'case_id': case_id,
        'buffer_flushed': False,
        'duplicates_removed': 0,
        'dedup_details': [],
        'systems_discovered': 0,
        'users_discovered': 0,
        'errors': []
    }
    
    # Step 1: Flush ClickHouse buffer table
    set_phase(case_uuid, 'buffer_flush')
    self.update_state(state='PROCESSING', meta={'stage': 'flushing_buffer'})
    try:
        client = get_fresh_client()
        # OPTIMIZE forces buffer flush to main table
        client.command("OPTIMIZE TABLE events_buffer")
        results['buffer_flushed'] = True
        logger.info(f"Flushed ClickHouse buffer for case {case_id}")
    except Exception as e:
        # Buffer table might not exist or be empty
        logger.debug(f"Buffer flush skipped: {e}")
        results['buffer_flushed'] = True  # Not an error if buffer doesn't exist
    
    # Step 1.5: Deduplicate events (remove duplicate events from overlapping sources)
    set_phase(case_uuid, 'deduplication')
    self.update_state(state='PROCESSING', meta={'stage': 'deduplicating_events'})
    try:
        from utils.event_deduplication import deduplicate_case_events
        
        dedup_result = deduplicate_case_events(
            case_id=case_id,
            case_uuid=case_uuid,
            track_progress=True
        )
        results['duplicates_removed'] = dedup_result.get('total_duplicates_deleted', 0)
        results['dedup_details'] = dedup_result.get('details', [])
        
        if dedup_result.get('total_duplicates_deleted', 0) > 0:
            logger.info(f"Deduplication complete: {dedup_result.get('message', '')}")
        else:
            logger.debug(f"Deduplication complete: no duplicates found")
            
    except Exception as e:
        logger.warning(f"Deduplication failed: {e}")
        results['errors'].append(f"Deduplication: {str(e)}")
    
    # Step 2: Run known systems discovery (with progress tracking)
    self.update_state(state='PROCESSING', meta={'stage': 'discovering_systems'})
    try:
        from utils.known_systems_discovery import discover_known_systems
        
        app = get_flask_app()
        with app.app_context():
            systems_result = discover_known_systems(
                case_id=case_id,
                case_uuid=case_uuid,
                username='system',
                track_progress=True  # Enable progress tracking
            )
            results['systems_discovered'] = systems_result.get('systems_created', 0) + systems_result.get('systems_updated', 0)
            logger.info(f"Systems discovery complete: {results['systems_discovered']} systems")
    except Exception as e:
        logger.warning(f"Systems discovery failed: {e}")
        results['errors'].append(f"Systems discovery: {str(e)}")
    
    # Step 3: Run known users discovery (with progress tracking)
    self.update_state(state='PROCESSING', meta={'stage': 'discovering_users'})
    try:
        from utils.known_users_discovery import discover_known_users
        
        app = get_flask_app()
        with app.app_context():
            users_result = discover_known_users(
                case_id=case_id,
                case_uuid=case_uuid,
                username='system',
                track_progress=True  # Enable progress tracking
            )
            results['users_discovered'] = users_result.get('users_created', 0) + users_result.get('users_updated', 0)
            logger.info(f"Users discovery complete: {results['users_discovered']} users")
    except Exception as e:
        logger.warning(f"Users discovery failed: {e}")
        results['errors'].append(f"Users discovery: {str(e)}")
    
    # Step 3.5: Clean up stale 'ingesting' status
    try:
        from models.case_file import CaseFile
        from models.database import db
        app = get_flask_app()
        with app.app_context():
            stale = CaseFile.query.filter_by(case_uuid=case_uuid, status='ingesting').all()
            if stale:
                for cf in stale:
                    cf.status = 'error'
                    cf.ingestion_status = 'error'
                    cf.error_message = 'File processing did not complete (stale ingesting state)'
                db.session.commit()
                results['stale_ingesting_fixed'] = len(stale)
                logger.info(f"Reset {len(stale)} stale 'ingesting' files for case {case_uuid}")
    except Exception as e:
        logger.warning(f"Stale ingesting cleanup failed: {e}")
    
    # Step 3.6: Clean up duplicate file_path records
    try:
        from models.case_file import CaseFile
        from models.database import db
        from sqlalchemy import func
        app = get_flask_app()
        with app.app_context():
            dup_paths = db.session.query(CaseFile.file_path).filter(
                CaseFile.case_uuid == case_uuid,
                CaseFile.file_path.isnot(None)
            ).group_by(CaseFile.file_path).having(func.count() > 1).all()
            
            removed = 0
            for (fp,) in dup_paths:
                dupes = CaseFile.query.filter_by(
                    case_uuid=case_uuid, file_path=fp, status='duplicate'
                ).all()
                for d in dupes:
                    db.session.delete(d)
                    removed += 1
            
            if removed:
                db.session.commit()
                results['duplicate_records_cleaned'] = removed
                logger.info(f"Removed {removed} duplicate file_path records for case {case_uuid}")
    except Exception as e:
        logger.warning(f"Duplicate file_path cleanup failed: {e}")
    
    # Step 4: Verify staging folder and clean up junk files
    JUNK_EXTENSIONS = {'.sqlite-wal', '.sqlite-shm', '.sqlite-journal'}
    
    set_phase(case_uuid, 'complete')
    self.update_state(state='PROCESSING', meta={'stage': 'verifying_staging'})
    try:
        staging_path = os.path.join(Config.STAGING_FOLDER, case_uuid)
        if os.path.exists(staging_path):
            junk_files = []
            unknown_files = []
            for root, dirs, files in os.walk(staging_path):
                for f in files:
                    fpath = os.path.join(root, f)
                    ext = os.path.splitext(f)[1].lower()
                    if ext in JUNK_EXTENSIONS:
                        junk_files.append(fpath)
                    else:
                        unknown_files.append(os.path.relpath(fpath, staging_path))
            
            junk_deleted = 0
            for jf in junk_files:
                try:
                    os.remove(jf)
                    junk_deleted += 1
                except Exception:
                    pass
            
            if junk_deleted:
                logger.info(f"Deleted {junk_deleted} junk sidecar files from staging for case {case_uuid}")
            
            results['staging_junk_deleted'] = junk_deleted
            
            if unknown_files:
                results['staging_orphans'] = len(unknown_files)
                results['staging_orphan_samples'] = unknown_files[:10]
                logger.warning(f"Staging not empty for case {case_uuid}: {len(unknown_files)} non-junk files remain")
            else:
                results['staging_orphans'] = 0
                try:
                    shutil.rmtree(staging_path)
                    logger.info(f"Cleaned up staging folder for case {case_uuid}")
                except Exception as e:
                    logger.warning(f"Could not remove staging folder: {e}")
        else:
            results['staging_orphans'] = 0
            results['staging_junk_deleted'] = 0
    except Exception as e:
        logger.warning(f"Staging verification failed: {e}")
        results['errors'].append(f"Staging verification: {str(e)}")
    
    # Clear progress tracking
    clear_progress(case_uuid)
    
    results['success'] = len(results['errors']) == 0
    logger.info(f"Completion tasks finished for case {case_uuid}: {results}")
    
    return results


@celery_app.task(bind=True, name='tasks.discover_known_systems')
def discover_known_systems_task(self, case_id: int, case_uuid: str, username: str = 'system') -> Dict[str, Any]:
    """Discover known systems from artifacts for a case
    
    Runs async to avoid blocking web workers on large cases.
    
    Args:
        case_id: PostgreSQL case.id
        case_uuid: Case UUID
        username: User who triggered the discovery
        
    Returns:
        Dict with discovery results
    """
    from utils.known_systems_discovery import discover_known_systems
    
    logger.info(f"Starting known systems discovery for case {case_uuid}")
    
    app = get_flask_app()
    with app.app_context():
        results = discover_known_systems(
            case_id=case_id,
            case_uuid=case_uuid,
            username=username,
            track_progress=True
        )
    
    logger.info(f"Discovery complete for case {case_uuid}: {results['systems_created']} created, {results['systems_updated']} updated")
    return results


@celery_app.task(bind=True, name='tasks.discover_known_users')
def discover_known_users_task(self, case_id: int, case_uuid: str, username: str = 'system') -> Dict[str, Any]:
    """Discover known users from artifacts for a case
    
    Runs async to avoid blocking web workers on large cases.
    
    Args:
        case_id: PostgreSQL case.id
        case_uuid: Case UUID
        username: User who triggered the discovery
        
    Returns:
        Dict with discovery results
    """
    from utils.known_users_discovery import discover_known_users
    
    logger.info(f"Starting known users discovery for case {case_uuid}")
    
    app = get_flask_app()
    with app.app_context():
        results = discover_known_users(
            case_id=case_id,
            case_uuid=case_uuid,
            username=username,
            track_progress=True
        )
    
    logger.info(f"User discovery complete for case {case_uuid}: {results['users_created']} created, {results['users_updated']} updated")
    return results


@celery_app.task(bind=True, name='tasks.reindex_case')
def reindex_case_task(self, case_uuid: str, case_id: int, username: str = 'system') -> Dict[str, Any]:
    """Reindex all files for a case - clean slate re-ingestion
    
    Steps:
    1. Delete all events from ClickHouse for case_id
    2. Delete all CaseFile records for case_uuid
    3. Scan storage/{case_uuid}/ recursively
    4. Create new CaseFile records for each file found
    5. Queue parse_file_task for each non-archive file
    
    Args:
        case_uuid: Case UUID
        case_id: PostgreSQL case.id (used as ClickHouse case_id)
        username: User who triggered the reindex
        
    Returns:
        Dict with reindex results
    """
    from models.database import db
    from models.case_file import CaseFile
    from utils.clickhouse import get_fresh_client
    from utils.progress import init_progress
    from config import Config
    
    logger.info(f"Starting reindex for case {case_uuid}")
    
    app = get_flask_app()
    
    with app.app_context():
        # =============================================
        # STEP 1: Delete all ClickHouse events
        # =============================================
        self.update_state(state='PROCESSING', meta={'stage': 'deleting_events'})
        
        try:
            client = get_fresh_client()
            
            # Count events before deletion
            count_result = client.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
                parameters={'case_id': case_id}
            )
            events_deleted = count_result.result_rows[0][0] if count_result.result_rows else 0
            
            # Delete events
            client.command(f"ALTER TABLE events DELETE WHERE case_id = {case_id}")
            
            # Also delete from buffer table
            try:
                client.command(f"ALTER TABLE events_buffer DELETE WHERE case_id = {case_id}")
            except:
                pass  # Buffer might not exist
                
            logger.info(f"Deleted {events_deleted} events from ClickHouse for case {case_id}")
            
        except Exception as e:
            logger.error(f"Error deleting ClickHouse events: {e}")
            return {'success': False, 'error': f'ClickHouse deletion failed: {str(e)}'}
        
        # =============================================
        # STEP 2: Delete all CaseFile records
        # =============================================
        self.update_state(state='PROCESSING', meta={'stage': 'deleting_records'})
        
        try:
            files_deleted = CaseFile.query.filter_by(case_uuid=case_uuid).delete()
            db.session.commit()
            logger.info(f"Deleted {files_deleted} CaseFile records for case {case_uuid}")
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting CaseFile records: {e}")
            return {'success': False, 'error': f'Database deletion failed: {str(e)}'}
        
        # =============================================
        # STEP 3: Scan storage directory
        # =============================================
        self.update_state(state='PROCESSING', meta={'stage': 'scanning_storage'})
        
        storage_path = os.path.join(Config.STORAGE_FOLDER, case_uuid)
        
        if not os.path.isdir(storage_path):
            return {'success': False, 'error': 'Storage directory not found'}
        
        # Collect all files and extract hostname from path
        import re
        files_found = []
        for root, dirs, files in os.walk(storage_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, storage_path)
                
                # Extract hostname from path: first directory before /C/ or /D/ etc.
                # e.g., "PANEL-APP.zip_722e232a/C/Windows/..." -> "PANEL-APP"
                hostname = ''
                path_parts = rel_path.replace('\\', '/').split('/')
                for i, part in enumerate(path_parts):
                    if part.upper() in ('C', 'D', 'E') and i > 0:
                        potential_host = path_parts[i - 1]
                        if potential_host and not potential_host.startswith('.'):
                            # Strip .zip_* suffix from archive paths
                            hostname = re.sub(r'\.zip_[a-f0-9]+$', '', potential_host, flags=re.IGNORECASE)
                            break
                
                files_found.append({
                    'path': file_path,
                    'filename': rel_path,
                    'original_filename': filename,
                    'hostname': hostname
                })
        
        if not files_found:
            return {
                'success': True,
                'events_deleted': events_deleted,
                'records_deleted': files_deleted,
                'files_found': 0,
                'files_queued': 0,
                'message': 'No files found in storage'
            }
        
        logger.info(f"Found {len(files_found)} files in storage for case {case_uuid}")
        
        # =============================================
        # STEP 4: Create CaseFile records and queue parsing
        # =============================================
        self.update_state(state='PROCESSING', meta={
            'stage': 'creating_records',
            'total_files': len(files_found)
        })
        
        files_to_queue = []
        
        for idx, file_info in enumerate(files_found):
            try:
                file_path = file_info['path']
                file_size = os.path.getsize(file_path)
                sha256_hash = CaseFile.calculate_sha256(file_path)
                is_archive = CaseFile.is_zip_file(file_path)
                
                case_file = CaseFile(
                    case_uuid=case_uuid,
                    parent_id=None,
                    filename=file_info['filename'],
                    original_filename=file_info['original_filename'],
                    file_path=file_path,
                    file_size=file_size,
                    sha256_hash=sha256_hash,
                    hostname=file_info.get('hostname', ''),
                    file_type='Other',
                    upload_source='reindex',
                    is_archive=is_archive,
                    is_extracted=False,
                    extraction_status='n/a',
                    status='new',
                    uploaded_by=username
                )
                
                db.session.add(case_file)
                db.session.flush()
                
                # Queue non-archive files for parsing
                if not is_archive:
                    files_to_queue.append(case_file)
                    
            except Exception as e:
                logger.warning(f"Error processing file {file_info['filename']}: {e}")
                continue
        
        db.session.commit()
        
        # =============================================
        # STEP 5: Initialize progress and queue parsing tasks
        # =============================================
        self.update_state(state='PROCESSING', meta={
            'stage': 'queuing_tasks',
            'files_to_queue': len(files_to_queue)
        })
        
        if files_to_queue:
            init_progress(case_uuid, len(files_to_queue))
            
            for cf in files_to_queue:
                cf.status = 'queued'
                db.session.flush()
                
                parse_file_task.delay(
                    file_path=cf.file_path,
                    case_id=case_id,
                    source_host=cf.hostname or '',
                    case_file_id=cf.id,
                )
            
            db.session.commit()
        
        logger.info(f"Reindex complete for case {case_uuid}: {len(files_to_queue)} files queued for parsing")
        
        return {
            'success': True,
            'case_uuid': case_uuid,
            'events_deleted': events_deleted,
            'records_deleted': files_deleted,
            'files_found': len(files_found),
            'files_queued': len(files_to_queue),
            'message': 'Reindex complete'
        }


@celery_app.task(bind=True, name='tasks.tag_iocs_for_case')
def tag_iocs_for_case(self, case_id: int) -> Dict[str, Any]:
    """Tag all artifacts in a case with matching IOCs.
    
    This is a long-running task that:
    1. Searches all events in the case for IOC matches
    2. Updates artifact counts on IOCs
    3. Creates system sightings for matched hosts
    4. Marks events with IOC type badges
    
    Args:
        case_id: PostgreSQL case.id
        
    Returns:
        Dict with tagging results
    """
    from utils.ioc_artifact_tagger import tag_all_iocs_globally
    
    logger.info(f"Starting IOC tagging for case {case_id}")
    
    self.update_state(state='PROCESSING', meta={
        'case_id': case_id,
        'stage': 'tagging',
    })
    
    try:
        app = get_flask_app()
        with app.app_context():
            results = tag_all_iocs_globally(case_id)
            
            logger.info(
                f"IOC tagging complete for case {case_id}: "
                f"{results.get('iocs_with_matches', 0)} IOCs matched, "
                f"{results.get('total_artifact_matches', 0)} total matches, "
                f"{results.get('system_sightings_created', 0)} system sightings"
            )
            
            return {
                'success': results.get('success', False),
                'case_id': case_id,
                'total_iocs': results.get('total_iocs', 0),
                'iocs_with_matches': results.get('iocs_with_matches', 0),
                'new_links_created': results.get('new_links_created', 0),
                'total_artifact_matches': results.get('total_artifact_matches', 0),
                'events_tagged': results.get('events_tagged', 0),
                'system_sightings_created': results.get('system_sightings_created', 0),
                'error': results.get('error')
            }
            
    except Exception as e:
        logger.error(f"Error tagging IOCs for case {case_id}: {e}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'case_id': case_id,
            'error': str(e)
        }


@celery_app.task(bind=True, name='tasks.find_iocs_in_events')
def find_iocs_in_events_task(self, case_id: int, username: str = 'system') -> Dict[str, Any]:
    """Find additional IOCs in events that are already tagged with IOCs.
    
    Uses FAST regex extraction (not AI) for speed - processes events in batches.
    
    This task:
    1. Queries all events where ioc_types is not empty
    2. Extracts IOCs from each event's raw_json using fast regex patterns
    3. Compares against existing IOCs, known systems/users
    4. Returns deduplicated results for analyst review
    
    Args:
        case_id: PostgreSQL case.id
        username: User running the extraction
        
    Returns:
        Dict with extraction results
    """
    import redis
    import json
    from config import Config
    
    logger.info(f"Starting Find IOCs in Events for case {case_id}")
    
    # Redis for progress tracking
    r = redis.Redis(
        host=Config.REDIS_HOST,
        port=Config.REDIS_PORT,
        db=Config.REDIS_DB,
        decode_responses=True
    )
    
    progress_key = f"find_iocs_progress:{case_id}:{self.request.id}"
    results_key = f"find_iocs_results:{case_id}:{self.request.id}"
    
    def update_progress(current, total, found_count, current_value='', status='processing'):
        r.setex(progress_key, 600, json.dumps({
            'status': status,
            'current': current,
            'total': total,
            'found_count': found_count,
            'current_value': current_value[:100] if current_value else ''
        }))
    
    try:
        app = get_flask_app()
        with app.app_context():
            from utils.clickhouse import get_fresh_client
            from utils.ioc_extractor import RegexIOCExtractor, process_extraction_for_import
            from models.ioc import IOC
            
            client = get_fresh_client()
            
            # Get ALL events tagged with IOCs (no limit - regex is fast)
            query = """
                SELECT event_id, raw_json, artifact_type, source_host, timestamp
                FROM events 
                WHERE case_id = {case_id:UInt32} 
                  AND length(ioc_types) > 0
                ORDER BY timestamp DESC
            """
            
            result = client.query(query, parameters={'case_id': case_id})
            events = result.result_rows
            total_events = len(events)
            
            logger.info(f"Found {total_events} tagged events to process with regex extraction")
            
            if total_events == 0:
                update_progress(0, 0, 0, '', 'complete')
                r.setex(results_key, 3600, json.dumps({
                    'events_processed': 0,
                    'used_ai': False,
                    'iocs_to_import': [],
                    'known_systems_results': [],
                    'known_users_results': []
                }))
                return {'success': True, 'events_processed': 0}
            
            update_progress(0, total_events, 0, 'Initializing regex extractor...')
            
            # Use fast regex extractor
            extractor = RegexIOCExtractor()
            
            # Track IOC sightings: {(ioc_type, value): {'count': N, 'hosts': set(), 'types': set()}}
            ioc_sightings = {}
            
            # Aggregate all extracted IOCs
            all_iocs = {
                'hashes': [],
                'ip_addresses': [],
                'domains': [],
                'urls': [],
                'file_paths': [],
                'file_names': [],
                'users': [],
                'sids': [],
                'registry_keys': [],
                'commands': [],
                'processes': [],
                'credentials': [],
                'hostnames': [],
                'timestamps': [],
                'network_shares': [],
                'email_addresses': [],
                'mitre_indicators': [],
                'services': [],
                'scheduled_tasks': [],
                'cves': [],
                'threat_names': [],
            }
            
            found_count = 0
            batch_size = 100  # Process in batches for progress updates
            
            # Process events in batches
            for batch_start in range(0, total_events, batch_size):
                batch_end = min(batch_start + batch_size, total_events)
                batch = events[batch_start:batch_end]
                
                # Update progress at batch level (not per-event for speed)
                update_progress(batch_end, total_events, found_count, f'Processing batch {batch_start//batch_size + 1}...')
                
                # Process each event in batch
                for event in batch:
                    event_id, raw_json, artifact_type, source_host, timestamp = event
                    
                    if not raw_json:
                        continue
                    
                    try:
                        # Fast regex extraction
                        extraction = extractor.extract(raw_json)
                        
                        # Merge extracted IOCs into aggregate and track sightings
                        iocs = extraction.get('iocs', {})
                        for key in all_iocs.keys():
                            if key in iocs and iocs[key]:
                                for ioc_item in iocs[key]:
                                    # Get value from dict or string
                                    if isinstance(ioc_item, dict):
                                        val = ioc_item.get('value', '')
                                    else:
                                        val = str(ioc_item)
                                    
                                    if not val:
                                        continue
                                    
                                    # Track sighting
                                    sighting_key = (key, val.lower())
                                    if sighting_key not in ioc_sightings:
                                        ioc_sightings[sighting_key] = {
                                            'count': 0,
                                            'hosts': set(),
                                            'artifact_types': set()
                                        }
                                    
                                    ioc_sightings[sighting_key]['count'] += 1
                                    if source_host:
                                        ioc_sightings[sighting_key]['hosts'].add(source_host)
                                    if artifact_type:
                                        ioc_sightings[sighting_key]['artifact_types'].add(artifact_type)
                                
                                all_iocs[key].extend(iocs[key])
                                found_count += len(iocs[key])
                                
                    except Exception as e:
                        # Skip problematic events silently for speed
                        continue
            
            update_progress(total_events, total_events, found_count, 'Deduplicating and matching...')
            
            # Process aggregated IOCs for import (dedup, match against existing)
            processed = process_extraction_for_import(
                extraction={'iocs': all_iocs, 'extraction_summary': {}},
                case_id=case_id,
                username=username
            )
            
            # Enrich processed IOCs with sighting info
            for ioc_entry in processed.get('iocs_to_import', []):
                val = (ioc_entry.get('value') or '').lower()
                # Find matching sighting key
                for (ioc_cat, ioc_val), sighting in ioc_sightings.items():
                    if ioc_val == val:
                        ioc_entry['sighting_count'] = sighting['count']
                        ioc_entry['seen_on_hosts'] = sorted(list(sighting['hosts']))[:10]  # Limit to 10
                        ioc_entry['artifact_types'] = sorted(list(sighting['artifact_types']))
                        break
            
            # Store results in Redis (1 hour expiry)
            results_data = {
                'events_processed': total_events,
                'used_ai': False,  # Using regex, not AI
                'iocs_to_import': processed.get('iocs_to_import', []),
                'known_systems_results': processed.get('known_systems_results', []),
                'known_users_results': processed.get('known_users_results', [])
            }
            r.setex(results_key, 3600, json.dumps(results_data))
            
            # Mark complete
            final_count = len(processed.get('iocs_to_import', []))
            update_progress(total_events, total_events, final_count, '', 'complete')
            
            logger.info(
                f"Find IOCs complete for case {case_id}: "
                f"processed {total_events} events, found {final_count} potential IOCs (regex)"
            )
            
            return {
                'success': True,
                'case_id': case_id,
                'events_processed': total_events,
                'iocs_found': final_count
            }
            
    except Exception as e:
        logger.error(f"Error finding IOCs in events for case {case_id}: {e}")
        import traceback
        traceback.print_exc()
        
        # Update progress with error
        r.setex(progress_key, 600, json.dumps({
            'status': 'failed',
            'error': str(e)
        }))
        
        return {
            'success': False,
            'case_id': case_id,
            'error': str(e)
        }


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

# Import additional task modules to register their tasks
import tasks.pcap_tasks  # noqa: F401 - PCAP/Zeek processing tasks
