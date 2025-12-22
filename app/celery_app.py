"""
Celery Application Factory
Handles async task queue for background processing
"""

from celery import Celery
import logging

logger = logging.getLogger(__name__)

def create_celery_app():
    """
    Create and configure Celery application
    
    Returns:
        Celery: Configured Celery instance
    """
    # Import config
    from config import CeleryConfig
    
    # Create Celery instance
    celery_app = Celery('casescope')
    
    # Load configuration
    celery_app.config_from_object(CeleryConfig)
    
    # Note: Most tasks don't need Flask app context
    # They work directly with files and OpenSearch
    # Only use app context if you need database access
    
    celery_app.Task = celery_app.Task  # Use default task class
    
    logger.info(f"✓ Celery configured with broker: {CeleryConfig.broker_url.split('@')[-1] if '@' in CeleryConfig.broker_url else CeleryConfig.broker_url}")
    
    return celery_app

# Create global Celery instance
celery = create_celery_app()

# Auto-discover tasks in tasks/ directory
celery.autodiscover_tasks(['tasks'], force=True)

# Import tasks to register them
try:
    from tasks import task_file_upload
    logger.info("✓ Registered file upload tasks")
except Exception as e:
    logger.warning(f"⚠ Could not load task_file_upload: {e}")
