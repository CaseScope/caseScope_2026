"""
Celery tasks for SIGMA rules management
Handles updating rules from GitHub and syncing to database
"""

import logging
from celery import current_task

logger = logging.getLogger(__name__)


def update_sigma_rules():
    """
    Update SIGMA rules from GitHub repository
    
    This task:
    1. Clones or pulls latest rules from SigmaHQ/sigma repository
    2. Syncs all rules to database
    3. Preserves user's enabled/disabled settings
    
    Returns:
        dict: Update statistics
    """
    from main import app
    
    with app.app_context():
        from main import db
        from utils.sigma_utils import update_sigma_rules_from_github, sync_sigma_rules_to_database
        
        try:
            logger.info("Starting SIGMA rules update from GitHub")
            
            # Update progress
            if current_task:
                current_task.update_state(
                    state='PROGRESS',
                    meta={'status': 'Updating rules from GitHub...'}
                )
            
            # Clone or pull from GitHub
            result = update_sigma_rules_from_github()
            
            if not result['success']:
                logger.error(f"Failed to update from GitHub: {result['message']}")
                return {
                    'success': False,
                    'error': result['message']
                }
            
            logger.info("GitHub update completed, syncing to database...")
            
            # Update progress
            if current_task:
                current_task.update_state(
                    state='PROGRESS',
                    meta={'status': 'Syncing rules to database...'}
                )
            
            # Sync to database
            sync_stats = sync_sigma_rules_to_database(db)
            
            logger.info(f"SIGMA rules update complete: {sync_stats}")
            
            return {
                'success': True,
                'message': f"Updated successfully. Added: {sync_stats['added']}, Updated: {sync_stats['updated']}, Skipped: {sync_stats['skipped']}",
                'stats': sync_stats
            }
        
        except Exception as e:
            logger.error(f"Error updating SIGMA rules: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }


def sync_sigma_rules():
    """
    Sync SIGMA rules from disk to database
    
    This task:
    1. Scans all SIGMA rule folders on disk
    2. Parses rule metadata
    3. Syncs to database (preserves enabled/disabled settings)
    
    Returns:
        dict: Sync statistics
    """
    from main import app
    
    with app.app_context():
        from main import db
        from utils.sigma_utils import sync_sigma_rules_to_database
        
        try:
            logger.info("Starting SIGMA rules sync from disk")
            
            # Update progress
            if current_task:
                current_task.update_state(
                    state='PROGRESS',
                    meta={'status': 'Scanning rule files...'}
                )
            
            # Sync to database
            sync_stats = sync_sigma_rules_to_database(db)
            
            logger.info(f"SIGMA rules sync complete: {sync_stats}")
            
            return {
                'success': True,
                'added': sync_stats['added'],
                'updated': sync_stats['updated'],
                'skipped': sync_stats['skipped']
            }
        
        except Exception as e:
            logger.error(f"Error syncing SIGMA rules: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }


# Register tasks with Celery
try:
    from celery_app import celery
    update_sigma_rules = celery.task(name='tasks.update_sigma_rules')(update_sigma_rules)
    sync_sigma_rules = celery.task(name='tasks.sync_sigma_rules')(sync_sigma_rules)
except ImportError:
    # Not running as Celery worker
    pass

