"""Celery tasks for recovering Hayabusa MITRE metadata on existing EVTX events."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from tasks.celery_tasks import celery_app, get_flask_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="tasks.recover_hayabusa_mitre_for_case", time_limit=14400, soft_time_limit=13800)
def recover_hayabusa_mitre_for_case(
    self,
    case_id: int,
    case_file_ids: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """Rerun Hayabusa against retained EVTX originals and recover MITRE match rows."""
    self.update_state(
        state="PROCESSING",
        meta={"stage": "starting", "case_id": int(case_id)},
    )
    app = get_flask_app()
    with app.app_context():
        from utils.hayabusa_mitre_reenrichment import recover_case_hayabusa_mitre

        try:
            result = recover_case_hayabusa_mitre(
                case_id=int(case_id),
                case_file_ids=case_file_ids,
            )
            self.update_state(
                state="PROCESSING",
                meta={
                    "stage": "complete",
                    "case_id": int(case_id),
                    "files_recovered": result.get("files_recovered", 0),
                    "matches_inserted": result.get("matches_inserted", 0),
                },
            )
            return result
        except Exception as exc:
            logger.exception("Failed to recover Hayabusa MITRE metadata for case %s", case_id)
            return {
                "success": False,
                "case_id": int(case_id),
                "error": str(exc),
            }
