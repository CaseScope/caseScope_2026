"""
CaseScope 2026 v1.0.0 - Celery Application
"""

from celery import Celery
import logging

# Setup logging using centralized configuration
from logging_config import setup_logging, get_logger
setup_logging()  # Initialize logging system
logger = get_logger('celery')  # Get celery-specific logger

# Create Celery app
celery_app = Celery('casescope')

# Load configuration from config.py
celery_app.config_from_object('config.Config', namespace='CELERY')

# Configure Celery
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # No time limits - user can cancel via UI if needed
    broker_connection_retry_on_startup=True,
    # CRITICAL: Expire task results after 24 hours to prevent Redis bloat
    # Without this, Redis accumulates task metadata indefinitely (celery-task-meta-* keys)
    result_expires=86400,  # 24 hours in seconds
    # Clean up backend on task completion (removes result immediately after retrieval)
    result_backend_transport_options={'master_name': 'mymaster'},
)

# Import tasks directly (instead of autodiscover)
import tasks

# Import metadata clearing tasks (v2.0.0)
import processing_clear_metadata

# Import event filtering tasks (v2.1.0)
import events_known_good
import events_known_noise

# v2.3.0: Removed coordinators and processing_* wrappers
# All processing now happens in tasks.py using file_processing.py functions directly

logger.info("Celery app initialized (v2.3.0 - No Coordinators)")
