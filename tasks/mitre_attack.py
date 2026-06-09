"""MITRE ATT&CK reference data tasks."""
import logging
from typing import Any, Dict

from tasks.celery_tasks import celery_app, get_flask_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name='tasks.update_mitre_attack_database')
def update_mitre_attack_database_task(self, username: str = 'system') -> Dict[str, Any]:
    """Fetch and import the MITRE ATT&CK Enterprise STIX database."""
    app = get_flask_app()

    with app.app_context():
        from utils.async_cancellation import clear_cancellation, is_cancellation_requested
        from utils.global_task_markers import clear_global_task_inflight, mark_global_task_inflight
        from utils.mitre_attack_sync import import_mitre_enterprise_attack

        logger.info("Starting MITRE ATT&CK Enterprise database update")
        if is_cancellation_requested('global_task', 'mitre_update'):
            logger.info("MITRE ATT&CK update cancelled before start")
            clear_cancellation('global_task', 'mitre_update')
            return {'success': False, 'cancelled': True}
        # Refresh the in-flight marker (also covers direct invocations)
        mark_global_task_inflight('mitre_update', task_id=self.request.id)
        self.update_state(state='PROGRESS', meta={
            'progress': 10,
            'status': 'Downloading MITRE ATT&CK Enterprise data...'
        })

        try:
            self.update_state(state='PROGRESS', meta={
                'progress': 55,
                'status': 'Importing tactics, techniques, sub-techniques, and procedures...'
            })
            result = import_mitre_enterprise_attack(updated_by=username)
            self.update_state(state='PROGRESS', meta={
                'progress': 100,
                'status': 'MITRE ATT&CK database update complete'
            })
            return result
        except Exception as exc:
            logger.exception("Error updating MITRE ATT&CK Enterprise database")
            return {'success': False, 'error': str(exc)}
        finally:
            clear_cancellation('global_task', 'mitre_update')
            clear_global_task_inflight('mitre_update')
