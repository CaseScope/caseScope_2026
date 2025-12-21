"""
Global IOC Hunt Routes
Separate from per-file IOC processing - this is for on-demand global hunts
"""

from flask import Blueprint, jsonify, request, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from main import db
from models import Case, IOC
from model_ioc_hunt import IOCHuntJob, IOCHuntMatch
from task_ioc_hunt import hunt_all_iocs_task
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

ioc_hunt_bp = Blueprint('ioc_hunt', __name__)


@ioc_hunt_bp.route('/case/<int:case_id>/ioc-hunt/start', methods=['POST'])
@login_required
def start_hunt(case_id):
    """Start a new global IOC hunt for this case."""
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot start IOC hunts'}), 403
    
    # Verify case exists
    case = Case.query.get_or_404(case_id)
    
    # Check for existing running job
    existing = IOCHuntJob.query.filter(
        IOCHuntJob.case_id == case_id,
        IOCHuntJob.status.in_(["pending", "running"])
    ).first()
    
    if existing:
        return jsonify({
            'success': False,
            'error': 'Hunt already in progress',
            'job_id': existing.id
        }), 409
    
    # CLEANUP: Clear old IOC hunt data to ensure fresh, accurate results
    logger.info(f"[IOC_HUNT] Clearing old IOC hunt data for case {case_id}")
    
    # 1. Delete old completed hunt jobs and their matches (keep last 5 for history)
    old_jobs = IOCHuntJob.query.filter_by(case_id=case_id)\
        .order_by(IOCHuntJob.created_at.desc())\
        .offset(5).all()
    for old_job in old_jobs:
        db.session.delete(old_job)  # Cascade will delete matches too
    
    # 2. Clear per-file IOC data (to be repopulated by hunt)
    from main import CaseFile, IOCMatch
    
    # Clear IOC matches from database
    IOCMatch.query.filter_by(case_id=case_id).delete()
    
    # Reset IOC event counts on files
    CaseFile.query.filter_by(case_id=case_id).update({'ioc_event_count': 0})
    
    db.session.commit()
    
    # 3. Clear has_ioc flags in OpenSearch
    from main import opensearch_client
    index_name = f"case_{case_id}"
    
    try:
        if opensearch_client.indices.exists(index=index_name):
            # Update all events to clear has_ioc flag
            update_query = {
                "script": {
                    "source": "ctx._source.has_ioc = false; ctx._source.remove('ioc_matches');",
                    "lang": "painless"
                },
                "query": {
                    "term": {"has_ioc": True}
                }
            }
            opensearch_client.update_by_query(
                index=index_name,
                body=update_query,
                conflicts='proceed',
                wait_for_completion=True,
                request_timeout=120
            )
            logger.info(f"[IOC_HUNT] Cleared has_ioc flags in OpenSearch for case {case_id}")
    except Exception as e:
        logger.warning(f"[IOC_HUNT] Failed to clear OpenSearch flags: {e}")
        # Continue anyway - not critical
    
    logger.info(f"[IOC_HUNT] Cleanup complete for case {case_id}")
    
    # Create job record
    job = IOCHuntJob(
        case_id=case_id,
        status="pending",
        created_by=current_user.id
    )
    db.session.add(job)
    db.session.commit()
    
    # Start Celery task
    task = hunt_all_iocs_task.delay(job.id, case_id)
    
    job.task_id = task.id
    db.session.commit()
    
    # Audit log
    try:
        from audit_logger import log_action
        log_action('start_ioc_hunt', resource_type='ioc_hunt', resource_id=job.id,
                  resource_name=f'Global IOC Hunt - {case.name}',
                  details={'case_id': case_id, 'task_id': task.id})
    except Exception as e:
        logger.warning(f"[IOC_HUNT] Audit log failed: {e}")
    
    logger.info(f"[IOC_HUNT] Started job {job.id} for case {case_id} (task {task.id})")
    
    return jsonify({
        'success': True,
        'job_id': job.id,
        'task_id': task.id
    })


@ioc_hunt_bp.route('/case/<int:case_id>/ioc-hunt/status/<int:job_id>')
@login_required
def hunt_status(case_id, job_id):
    """Get hunt job status with progress."""
    
    job = IOCHuntJob.query.get_or_404(job_id)
    
    # Verify job belongs to this case
    if job.case_id != case_id:
        return jsonify({'success': False, 'error': 'Job not found'}), 404
    
    # Calculate events with IOCs from match count
    events_with_iocs = 0
    if job.status == 'completed':
        events_with_iocs = db.session.query(IOCHuntMatch.event_id).filter_by(
            job_id=job_id
        ).distinct().count()
    
    return jsonify({
        'success': True,
        'id': job.id,
        'status': job.status,
        'progress': job.progress,
        'total_iocs': job.total_iocs,
        'processed_iocs': job.processed_iocs,
        'match_count': job.match_count,
        'total_events_searched': job.total_events_searched,
        'events_with_iocs': events_with_iocs,
        'message': job.message,
        'created_at': job.created_at.isoformat() if job.created_at else None,
        'completed_at': job.completed_at.isoformat() if job.completed_at else None
    })


@ioc_hunt_bp.route('/case/<int:case_id>/ioc-hunt/cancel/<int:job_id>', methods=['POST'])
@login_required
def cancel_hunt(case_id, job_id):
    """Cancel a running hunt job."""
    
    job = IOCHuntJob.query.get_or_404(job_id)
    
    if job.case_id != case_id:
        return jsonify({'success': False, 'error': 'Job not found'}), 404
    
    if job.status not in ["pending", "running"]:
        return jsonify({'success': False, 'error': 'Job not running'}), 400
    
    job.status = "cancelled"
    job.message = "Cancelled by user"
    job.completed_at = datetime.utcnow()
    db.session.commit()
    
    # Audit log
    try:
        from audit_logger import log_action
        log_action('cancel_ioc_hunt', resource_type='ioc_hunt', resource_id=job.id,
                  resource_name=f'Global IOC Hunt #{job.id}',
                  details={'case_id': case_id})
    except Exception as e:
        logger.warning(f"[IOC_HUNT] Audit log failed: {e}")
    
    logger.info(f"[IOC_HUNT] Cancelled job {job.id}")
    
    return jsonify({'success': True})


@ioc_hunt_bp.route('/case/<int:case_id>/ioc-hunt/matches/<int:job_id>')
@login_required
def hunt_matches(case_id, job_id):
    """Get matches for a completed hunt job (paginated)."""
    
    job = IOCHuntJob.query.get_or_404(job_id)
    
    if job.case_id != case_id:
        return jsonify({'success': False, 'error': 'Job not found'}), 404
    
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)
    
    # Get matches with IOC details
    matches_query = IOCHuntMatch.query.filter_by(job_id=job_id)\
        .join(IOC)\
        .order_by(IOCHuntMatch.created_at.desc())
    
    matches_page = matches_query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'success': True,
        'matches': [{
            'id': m.id,
            'ioc_value': m.matched_value,
            'ioc_type': m.ioc.ioc_type,
            'event_id': m.event_id,
            'event_index': m.event_index,
            'created_at': m.created_at.isoformat()
        } for m in matches_page.items],
        'total': matches_page.total,
        'page': page,
        'pages': matches_page.pages,
        'per_page': per_page
    })


@ioc_hunt_bp.route('/case/<int:case_id>/ioc-hunt/results/<int:job_id>')
@login_required
def view_results(case_id, job_id):
    """View hunt results in a dedicated page."""
    
    job = IOCHuntJob.query.get_or_404(job_id)
    
    if job.case_id != case_id:
        flash('Hunt job not found', 'error')
        return redirect(url_for('triage_case', case_id=case_id))
    
    case = Case.query.get_or_404(case_id)
    
    # Get match counts by IOC
    from sqlalchemy import func
    ioc_match_counts = db.session.query(
        IOC.ioc_value,
        IOC.ioc_type,
        func.count(IOCHuntMatch.id).label('match_count')
    ).join(IOCHuntMatch).filter(
        IOCHuntMatch.job_id == job_id
    ).group_by(IOC.id, IOC.ioc_value, IOC.ioc_type).order_by(func.count(IOCHuntMatch.id).desc()).all()
    
    return render_template(
        'ioc_hunt_results.html',
        case=case,
        job=job,
        ioc_match_counts=ioc_match_counts
    )
