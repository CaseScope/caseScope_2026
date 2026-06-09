"""AI report generation Celery task with case-keyed Redis status.

Moves the long LLM report generation out of the HTTP request so it survives
page reloads, closed modals, and proxy timeouts. Status is case-keyed (not
task-keyed) so any user/browser can resume progress display, mirroring the
case analysis pattern.
"""
import json
import logging
import os
import time
from datetime import datetime

from tasks.celery_tasks import celery_app, get_flask_app
from utils.progress import get_redis_client

logger = logging.getLogger(__name__)

# Long enough to inspect a finished run, short enough not to accumulate
AI_REPORT_STATUS_TTL_SECONDS = 6 * 60 * 60

# A live run updates status on every section; if nothing has been written for
# this long the run is considered dead (worker crash) and a new one may start.
AI_REPORT_STALE_SECONDS = 60 * 60


def _status_key(case_uuid: str) -> str:
    return f'ai_report_status:{case_uuid}'


def set_ai_report_status(case_uuid: str, **fields) -> None:
    """Merge fields into the case-keyed AI report generation status."""
    try:
        client = get_redis_client()
        current = get_ai_report_status(case_uuid) or {}
        current.update(fields)
        current['updated_at'] = time.time()
        client.setex(_status_key(case_uuid), AI_REPORT_STATUS_TTL_SECONDS, json.dumps(current))
    except Exception:
        logger.warning(f"Could not set AI report status for case {case_uuid}", exc_info=True)


def get_ai_report_status(case_uuid: str) -> dict:
    """Return the case-keyed AI report generation status, or None."""
    try:
        raw = get_redis_client().get(_status_key(case_uuid))
        return json.loads(raw) if raw else None
    except Exception:
        logger.warning(f"Could not read AI report status for case {case_uuid}", exc_info=True)
        return None


def is_ai_report_generation_running(case_uuid: str) -> dict:
    """Return the status dict if a non-stale generation is running, else None."""
    status = get_ai_report_status(case_uuid)
    if not status or status.get('status') != 'running':
        return None
    updated_at = status.get('updated_at') or 0
    if time.time() - updated_at > AI_REPORT_STALE_SECONDS:
        return None
    return status


@celery_app.task(bind=True, name='tasks.generate_ai_report', max_retries=0,
                 time_limit=7200, soft_time_limit=7000)
def generate_ai_report_task(self, case_id: int, case_uuid: str, template_id=None,
                            negative_finding_ids=None, username: str = 'system',
                            report_kind: str = 'dfir'):
    """Generate an AI report (DFIR or timeline) in the background.

    Args:
        case_id: Case primary key
        case_uuid: Case UUID (used for case-keyed status)
        template_id: Resolved ReportTemplate id (may be None for timeline)
        negative_finding_ids: Negative finding ids to include (DFIR only)
        username: User who requested the report
        report_kind: 'dfir' or 'timeline'
    """
    app = get_flask_app()
    with app.app_context():
        from models.case_report import CaseReport
        from models.case_work import CaseWorkActivityType
        from models.database import db
        from utils.case_work import safe_log_case_work_activity

        def _progress(step, total, message):
            percent = int(step * 100 / max(total or 1, 1))
            set_ai_report_status(
                case_uuid,
                status='running',
                percent=min(percent, 99),
                message=message or 'Generating...',
            )

        set_ai_report_status(
            case_uuid,
            task_id=self.request.id,
            status='running',
            percent=0,
            message='Preparing report generation...',
            report_kind=report_kind,
            username=username,
            started_at=time.time(),
            filename=None,
            download_url=None,
            error=None,
        )

        try:
            if report_kind == 'timeline':
                from utils.ai_timeline_generator import AITimelineGenerator
                generator = AITimelineGenerator(case_id, template_id, progress_callback=_progress)
            else:
                from utils.ai_report_generator import AIReportGenerator
                generator = AIReportGenerator(
                    case_id,
                    template_id,
                    progress_callback=_progress,
                    selected_negative_finding_ids=negative_finding_ids or [],
                )

            result = generator.generate_report()
        except Exception as e:
            logger.exception(f"AI report generation failed for case {case_uuid}")
            set_ai_report_status(case_uuid, status='failed', error=str(e))
            raise RuntimeError(str(e)) from e

        if not result.get('success'):
            error = result.get('error', 'Report generation failed')
            set_ai_report_status(case_uuid, status='failed', error=error)
            return {'success': False, 'error': error}

        ai_model = result.get('ai_model', '')
        try:
            output_path = result['output_path']
            stat = os.stat(output_path)
            report_record = CaseReport(
                case_id=case_id,
                filename=result['filename'],
                file_path=output_path,
                file_size=stat.st_size,
                report_type=CaseReport.extract_report_type(result['filename']),
                ai_model=ai_model,
                file_created_at=datetime.fromtimestamp(stat.st_mtime),
                created_by=username,
            )
            db.session.add(report_record)
            db.session.commit()
        except Exception as e:
            logger.warning(f"Could not create report record: {e}")
            db.session.rollback()

        download_url = f"/api/reports/download/{case_uuid}/{result['filename']}"
        safe_log_case_work_activity(
            case_uuid,
            CaseWorkActivityType.REPORT_ACTION,
            'Generated AI timeline report' if report_kind == 'timeline' else 'Generated AI case report',
            details={
                'filename': result['filename'],
                'report_type': report_kind,
                'template_id': template_id,
                'ai_model': ai_model,
                'stats': result.get('stats'),
            },
            username=username,
        )
        set_ai_report_status(
            case_uuid,
            status='completed',
            percent=100,
            message='Report generated',
            filename=result['filename'],
            download_url=download_url,
            ai_model=ai_model,
        )
        return {
            'success': True,
            'filename': result['filename'],
            'output_path': result['output_path'],
            'download_url': download_url,
            'report_type': report_kind,
            'ai_model': ai_model,
        }
