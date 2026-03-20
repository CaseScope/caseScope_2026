"""CaseScope Tasks Package

Celery tasks for asynchronous processing.

Usage:
    # Start Celery worker
    celery -A tasks worker --loglevel=info
    
    # Start Celery Beat for scheduled tasks
    celery -A tasks beat --loglevel=info
    
    # Queue a file for parsing
    from tasks import parse_file_task
    result = parse_file_task.delay('/path/to/file.evtx', case_id=123)
    
    # Process all pending files for a case
    from tasks import process_case_files_task
    result = process_case_files_task.delay(case_uuid='abc-123')
"""

from tasks.celery_tasks import (
    celery_app,
    parse_file_task,
    process_case_files_task,
    process_staging_directory_task,
    delete_case_events_task,
    reindex_case_task,
    rebuild_single_case_file_task,
    update_hayabusa_rules_task,
    get_case_stats_task,
)

from tasks.noise_tagger import tag_noise_events
from tasks.task_scrape_events import scrape_event_descriptions_task
from tasks.rag_tasks import (
    rag_sync_opencti_patterns,
    rag_discover_patterns,
    rag_hunt_related,
    rag_generate_timeline,
    rag_seed_builtin_patterns,
    rag_sync_external_patterns,
)
from tasks.memory_tasks import process_memory_dump
from tasks.archive_tasks import (
    archive_case_task,
    restore_case_task,
    get_archive_progress,
)

__all__ = [
    'celery_app',
    'parse_file_task',
    'process_case_files_task',
    'process_staging_directory_task',
    'delete_case_events_task',
    'reindex_case_task',
    'rebuild_single_case_file_task',
    'update_hayabusa_rules_task',
    'get_case_stats_task',
    'tag_noise_events',
    'scrape_event_descriptions_task',
    'rag_sync_opencti_patterns',
    'rag_discover_patterns',
    'rag_hunt_related',
    'rag_generate_timeline',
    'rag_seed_builtin_patterns',
    'rag_sync_external_patterns',
    'process_memory_dump',
    'archive_case_task',
    'restore_case_task',
    'get_archive_progress',
]
