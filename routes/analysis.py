"""Analysis API Routes for CaseScope Enhanced Analysis System

Provides API endpoints for:
- Starting case analysis
- Checking analysis status
- Retrieving analysis results
- Managing suggested actions
- Viewing analysis history
"""

import logging
from datetime import datetime
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from models.database import db
from models.case import Case
from models.behavioral_profiles import (
    CaseAnalysisRun, AnalysisStatus,
    GapDetectionFinding, SuggestedAction
)

logger = logging.getLogger(__name__)

analysis_bp = Blueprint('analysis', __name__, url_prefix='/api/case')
ANALYSIS_STALE_MINUTES = 20


def _get_running_analysis(case_id: int):
    return CaseAnalysisRun.query.filter_by(case_id=case_id).filter(
        CaseAnalysisRun.status.in_(AnalysisStatus.running_statuses())
    ).order_by(CaseAnalysisRun.started_at.desc()).first()


def _mark_run_stale(run: CaseAnalysisRun):
    now = datetime.utcnow()
    run.status = AnalysisStatus.FAILED
    run.error_message = (
        f'Automatically marked stale after {ANALYSIS_STALE_MINUTES} minutes without progress.'
    )
    run.current_phase = 'Analysis marked stale'
    run.completed_at = now
    run.last_progress_at = run.last_progress_at or now
    db.session.commit()
    logger.warning(f"[Analysis API] Marked stale analysis {run.analysis_id} for case {run.case_id}")


def _build_run_status_response(run: CaseAnalysisRun) -> dict:
    response = {
        'success': True,
        'analysis_id': run.analysis_id,
        'status': run.status,
        'progress_percent': run.progress_percent or 0,
        'current_phase': run.current_phase,
        'status_message': run.status_message,
        'mode': run.mode,
        'started_at': run.started_at.isoformat() if run.started_at else None,
        'completed_at': run.completed_at.isoformat() if run.completed_at else None,
        'last_progress_at': run.last_progress_at.isoformat() if run.last_progress_at else None,
        'partial_results_available': run.has_partial_results(),
        'is_stale': run.is_stale(ANALYSIS_STALE_MINUTES),
    }

    if run.status in (AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL) or run.has_partial_results():
        if run.summary and isinstance(run.summary, dict):
            response['total_findings'] = run.summary.get('total_findings', 0)
            response['gap_findings'] = run.summary.get('gap_findings', 0)
            response['attack_chains'] = run.summary.get('attack_chains', 0)
            response['patterns_analyzed'] = run.summary.get('patterns_analyzed', 0)
        else:
            gap_count = GapDetectionFinding.query.filter_by(analysis_id=run.analysis_id).count()
            response['total_findings'] = run.findings_generated or gap_count
            response['gap_findings'] = gap_count
            response['attack_chains'] = run.attack_chains_found or 0
            response['patterns_analyzed'] = run.patterns_analyzed or 0
        response['users_profiled'] = run.users_profiled or 0
        response['systems_profiled'] = run.systems_profiled or 0

    if run.status in (AnalysisStatus.FAILED, AnalysisStatus.PARTIAL):
        response['error_message'] = run.error_message

    return response


# =============================================================================
# START ANALYSIS
# =============================================================================

@analysis_bp.route('/<int:case_id>/analysis/run', methods=['POST'])
@login_required
def start_analysis(case_id):
    """
    Start case analysis Celery task.
    
    Returns:
        {
            'success': bool,
            'task_id': str,
            'analysis_id': str,
            'message': str
        }
    """
    # Verify case exists and user has access
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Check if analysis is already running
    running = _get_running_analysis(case_id)
    
    if running:
        if running.is_stale(ANALYSIS_STALE_MINUTES):
            _mark_run_stale(running)
        else:
            return jsonify({
                'success': False,
                'error': 'Analysis already in progress',
                'analysis_id': running.analysis_id,
                'status': running.status,
                'progress_percent': running.progress_percent
            }), 409
    
    try:
        from tasks.rag_tasks import run_case_analysis
        
        # Start Celery task
        task = run_case_analysis.delay(case_id)
        
        logger.info(f"[Analysis API] Started analysis for case {case_id}, task {task.id}")
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': f'Analysis started for case {case_id}'
        })
        
    except Exception as e:
        logger.error(f"[Analysis API] Failed to start analysis: {e}")
        return jsonify({
            'success': False,
            'error': f'Failed to start analysis: {str(e)}'
        }), 500


# =============================================================================
# ANALYSIS STATUS
# =============================================================================

@analysis_bp.route('/<int:case_id>/analysis/status', methods=['GET'])
@login_required
def get_latest_analysis_status(case_id):
    """
    Get status of the latest analysis run for this case.
    
    Returns:
        {
            'status': str,
            'progress_percent': int,
            'current_phase': str,
            'mode': str,
            'findings_count': int (if complete)
        }
    """
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    run = CaseAnalysisRun.query.filter_by(
        case_id=case_id
    ).order_by(CaseAnalysisRun.id.desc()).first()
    
    if not run:
        return jsonify({
            'success': True,
            'has_analysis': False,
            'message': 'No analysis has been run for this case'
        })

    if run.is_stale(ANALYSIS_STALE_MINUTES):
        _mark_run_stale(run)
    
    response = _build_run_status_response(run)
    response['has_analysis'] = True
    return jsonify(response)


@analysis_bp.route('/<int:case_id>/analysis/status/<analysis_id>', methods=['GET'])
@login_required
def get_analysis_status(case_id, analysis_id):
    """
    Get current progress and status of a specific analysis run.
    
    Returns:
        {
            'status': str,
            'progress_percent': int,
            'current_phase': str,
            'mode': str,
            'findings_count': int (if complete)
        }
    """
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    run = CaseAnalysisRun.query.filter_by(
        case_id=case_id,
        analysis_id=analysis_id
    ).first()
    
    if not run:
        return jsonify({
            'success': False,
            'error': f'Analysis {analysis_id} not found'
        }), 404

    if run.is_stale(ANALYSIS_STALE_MINUTES):
        _mark_run_stale(run)
    
    return jsonify(_build_run_status_response(run))


# =============================================================================
# ANALYSIS RESULTS
# =============================================================================

@analysis_bp.route('/<int:case_id>/analysis/results/<analysis_id>', methods=['GET'])
@login_required
def get_analysis_results(case_id, analysis_id):
    """
    Get analysis results.
    
    Query params:
        view: 'summary' | 'timeline' | 'pattern' | 'entity' (default: 'summary')
        format: 'json' | 'csv' | 'markdown' (default: 'json')
        
    Returns:
        Formatted results based on view parameter
    """
    from utils.analysis_results_formatter import AnalysisResultsFormatter
    
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    run = CaseAnalysisRun.query.filter_by(
        case_id=case_id,
        analysis_id=analysis_id
    ).first()
    
    if not run:
        return jsonify({
            'success': False,
            'error': f'Analysis {analysis_id} not found'
        }), 404
    
    view = request.args.get('view', 'summary')
    format_type = request.args.get('format', 'json')
    
    formatter = AnalysisResultsFormatter(analysis_id)
    
    try:
        if view == 'summary':
            data = formatter.get_summary()
        elif view == 'timeline':
            data = {'items': formatter.get_timeline_view()}
        elif view == 'pattern':
            grouped = formatter.get_pattern_grouped_view()
            groups = {}
            for finding_type, bucket in grouped.get('gap_detection', {}).items():
                findings = bucket.get('findings', [])
                if findings:
                    groups[finding_type] = findings
            for pattern_id, bucket in grouped.get('pattern_detection', {}).items():
                findings = bucket.get('findings', [])
                if findings:
                    groups[bucket.get('name') or pattern_id] = findings
            data = {'groups': groups}
        elif view == 'entity':
            data = formatter.get_entity_grouped_view()
        elif view == 'actions':
            data = {'actions': formatter.get_suggested_actions()}
        elif view == 'export':
            # Full export
            content = formatter.export_report(format_type)
            if format_type == 'csv':
                return content, 200, {
                    'Content-Type': 'text/csv',
                    'Content-Disposition': f'attachment; filename=analysis_{analysis_id}.csv'
                }
            elif format_type == 'markdown':
                return content, 200, {
                    'Content-Type': 'text/markdown',
                    'Content-Disposition': f'attachment; filename=analysis_{analysis_id}.md'
                }
            else:
                return content, 200, {'Content-Type': 'application/json'}
        else:
            data = formatter.get_summary()
        
        return jsonify({
            'success': True,
            'view': view,
            'data': data
        })
        
    except Exception as e:
        logger.error(f"[Analysis API] Failed to get results: {e}")
        return jsonify({
            'success': False,
            'error': f'Failed to retrieve results: {str(e)}'
        }), 500


# =============================================================================
# FINDING DETAIL
# =============================================================================

@analysis_bp.route('/<int:case_id>/analysis/findings/<finding_type>/<int:finding_id>', methods=['GET'])
@login_required
def get_finding_detail(case_id, finding_type, finding_id):
    """
    Get full detail for a single finding.
    
    Args:
        finding_type: 'pattern' or 'gap'
        finding_id: ID of the finding
        
    Returns:
        Complete finding with all context
    """
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    if finding_type == 'gap':
        finding = GapDetectionFinding.query.get(finding_id)
        if not finding or finding.case_id != case_id:
            return jsonify({'success': False, 'error': 'Finding not found'}), 404
        
        # Get the analysis formatter
        from utils.analysis_results_formatter import AnalysisResultsFormatter
        formatter = AnalysisResultsFormatter(finding.analysis_id)
        detail = formatter.get_finding_detail(finding_id, 'gap')
        
        return jsonify({
            'success': True,
            'finding': detail
        })
    
    elif finding_type == 'pattern':
        from models.rag import AIAnalysisResult
        result = AIAnalysisResult.query.get(finding_id)
        if not result or result.case_id != case_id:
            return jsonify({'success': False, 'error': 'Finding not found'}), 404
        
        from utils.analysis_results_formatter import AnalysisResultsFormatter
        formatter = AnalysisResultsFormatter(result.analysis_id)
        detail = formatter.get_finding_detail(finding_id, 'pattern')
        
        return jsonify({
            'success': True,
            'finding': detail
        })
    
    else:
        return jsonify({
            'success': False,
            'error': f'Unknown finding type: {finding_type}'
        }), 400


@analysis_bp.route('/<int:case_id>/analysis/findings/<finding_type>/<int:finding_id>/verdict', methods=['POST'])
@login_required
def save_finding_verdict(case_id, finding_type, finding_id):
    """Persist analyst verdict for a case analysis finding."""
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404

    data = request.get_json() or {}
    verdict = data.get('verdict')
    notes = data.get('notes', '')

    if verdict not in ['confirmed', 'false_positive', 'needs_investigation']:
        return jsonify({'success': False, 'error': 'Invalid verdict'}), 400

    if finding_type == 'gap':
        finding = GapDetectionFinding.query.get(finding_id)
        if not finding or finding.case_id != case_id:
            return jsonify({'success': False, 'error': 'Finding not found'}), 404

        finding.analyst_reviewed = True
        finding.analyst_verdict = verdict
        finding.analyst_notes = notes
        db.session.commit()

        return jsonify({
            'success': True,
            'review': {
                'verdict': finding.analyst_verdict,
                'notes': finding.analyst_notes or '',
                'reviewed': True
            }
        })

    if finding_type == 'pattern':
        from models.rag import AIAnalysisResult, AnalystVerdict

        result = AIAnalysisResult.query.get(finding_id)
        if not result or result.case_id != case_id:
            return jsonify({'success': False, 'error': 'Finding not found'}), 404

        review = AnalystVerdict(
            analysis_result_id=result.id,
            verdict=verdict,
            analyst_id=current_user.id,
            notes=notes
        )
        db.session.add(review)
        db.session.commit()

        return jsonify({
            'success': True,
            'review': {
                'verdict': review.verdict,
                'notes': review.notes or '',
                'reviewed': True,
                'reviewed_at': review.created_at.isoformat() if review.created_at else None
            }
        })

    return jsonify({'success': False, 'error': f'Unknown finding type: {finding_type}'}), 400


# =============================================================================
# SUGGESTED ACTIONS
# =============================================================================

@analysis_bp.route('/<int:case_id>/analysis/suggested-actions', methods=['GET'])
@login_required
def get_suggested_actions(case_id):
    """
    Get pending suggested actions for this case.
    
    Query params:
        status: 'pending' | 'accepted' | 'rejected' | 'all' (default: 'pending')
        analysis_id: Optional, filter by specific analysis run
        
    Returns:
        List of suggested actions
    """
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    status_filter = request.args.get('status', 'pending')
    analysis_id = request.args.get('analysis_id')
    
    query = SuggestedAction.query.filter_by(case_id=case_id)
    
    if analysis_id:
        query = query.filter_by(analysis_id=analysis_id)
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    actions = query.order_by(SuggestedAction.confidence.desc()).all()
    
    result = []
    for a in actions:
        result.append({
            'id': a.id,
            'action_type': a.action_type,
            'target_type': a.target_type,
            'target_value': a.target_value,
            'target_entity': a.target_value,
            'reason': a.reason,
            'confidence': a.confidence,
            'source_type': a.source_type,
            'source_id': a.source_id,
            'status': a.status,
            'analyst_notes': a.analyst_notes,
            'created_at': a.created_at.isoformat() if a.created_at else None,
            'accepted_at': a.accepted_at.isoformat() if a.accepted_at else None,
            'accepted_by': a.accepted_by,
            'handled_at': a.accepted_at.isoformat() if a.accepted_at else None,
            'handled_by': a.accepted_by,
            'execution_result': a.execution_result
        })
    
    return jsonify({
        'success': True,
        'count': len(result),
        'actions': result
    })


@analysis_bp.route('/<int:case_id>/analysis/suggested-actions/<int:action_id>', methods=['POST'])
@login_required
def handle_suggested_action(case_id, action_id):
    """
    Accept or reject a suggested action.
    
    Body:
        {
            'status': 'accepted' | 'rejected',
            'notes': str (optional)
        }
        
    If accepted:
        - mark_user_compromised: Updates known_users.compromised = True
        - mark_system_compromised: Updates known_systems.compromised = True
        - add_ioc: Creates IOC record
        
    Returns:
        Updated action record
    """
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    action = SuggestedAction.query.get(action_id)
    if not action or action.case_id != case_id:
        return jsonify({'success': False, 'error': 'Action not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Request body required'}), 400
    
    new_status = data.get('status')
    if new_status not in ['accepted', 'rejected']:
        return jsonify({
            'success': False,
            'error': 'Status must be "accepted" or "rejected"'
        }), 400
    
    notes = data.get('notes', '')
    
    # Update action status
    action.status = new_status
    action.analyst_notes = notes
    action.accepted_at = datetime.utcnow()
    action.accepted_by = current_user.username if current_user else None
    
    # If accepted, perform the action
    if new_status == 'accepted':
        try:
            result = _execute_suggested_action(action, case_id)
            action.execution_result = result
        except Exception as e:
            logger.error(f"[Analysis API] Failed to execute action: {e}")
            action.execution_result = {'error': str(e)}
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'action': {
            'id': action.id,
            'status': action.status,
            'accepted_at': action.accepted_at.isoformat() if action.accepted_at else None,
            'accepted_by': action.accepted_by,
            'handled_at': action.accepted_at.isoformat() if action.accepted_at else None,
            'handled_by': action.accepted_by,
            'execution_result': action.execution_result
        }
    })


def _execute_suggested_action(action: SuggestedAction, case_id: int) -> dict:
    """Execute a suggested action when accepted"""
    action_type = action.action_type
    target = action.target_value
    
    if action_type == 'mark_user_compromised':
        from models.known_user import KnownUser
        user = KnownUser.query.filter_by(case_id=case_id).filter(
            KnownUser.username.ilike(target)
        ).first()
        
        if user:
            user.compromised = True
            db.session.commit()
            return {'executed': True, 'user_id': user.id, 'username': user.username}
        else:
            return {'executed': False, 'error': f'User {target} not found'}
    
    elif action_type == 'mark_system_compromised':
        from models.known_system import KnownSystem
        system = KnownSystem.query.filter_by(case_id=case_id).filter(
            KnownSystem.hostname.ilike(target)
        ).first()
        
        if system:
            system.compromised = True
            db.session.commit()
            return {'executed': True, 'system_id': system.id, 'hostname': system.hostname}
        else:
            return {'executed': False, 'error': f'System {target} not found'}
    
    elif action_type == 'add_ioc':
        from models.ioc import IOC, detect_ioc_type_from_value, get_category_for_type
        
        # Determine IOC type based on target format
        ioc_type = _infer_ioc_type(target)
        if ioc_type == 'Unknown':
            ioc_type = detect_ioc_type_from_value(target)
        category = get_category_for_type(ioc_type)
        if not category:
            return {'executed': False, 'error': f'Unable to determine IOC type for {target}'}
        
        existing = IOC.find_by_value(target, ioc_type, case_id=case_id)
        if existing:
            return {'executed': True, 'ioc_id': existing.id, 'already_existed': True}

        ioc, created = IOC.get_or_create(
            value=target,
            ioc_type=ioc_type,
            category=category,
            created_by='analysis',
            case_id=case_id,
            source='analysis'
        )

        if created and action.reason:
            ioc.notes = action.reason

        db.session.commit()
        
        return {'executed': True, 'ioc_id': ioc.id, 'created': created}
    
    elif action_type in ['investigate', 'credential_review', 'lateral_movement_trace',
                         'data_exposure_assessment', 'persistence_check', 'review_timeline',
                         'investigate_user', 'investigate_host']:
        # These are informational actions - mark as acknowledged
        return {'executed': True, 'action': 'acknowledged', 'note': 'Informational action noted'}
    
    else:
        return {'executed': False, 'error': f'Unknown action type: {action_type}'}


def _infer_ioc_type(value: str) -> str:
    """Infer IOC type from value format"""
    import re
    
    # IP address patterns
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ipv4_pattern, value):
        return 'IP Address (IPv4)'
    
    # Hash patterns
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return 'MD5 Hash'
    if re.match(r'^[a-fA-F0-9]{40}$', value):
        return 'SHA1 Hash'
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return 'SHA256 Hash'
    
    # Domain/hostname
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', value):
        return 'Domain'
    
    # Email
    if '@' in value and '.' in value:
        return 'Email Address'
    
    # Username
    if '\\' in value or value.startswith('DOMAIN\\'):
        return 'Username'
    
    # Default
    return 'Unknown'


# =============================================================================
# ANALYSIS HISTORY
# =============================================================================

@analysis_bp.route('/<int:case_id>/analysis/history', methods=['GET'])
@login_required
def get_analysis_history(case_id):
    """
    Get list of past analysis runs for this case.
    
    Query params:
        limit: Number of records to return (default: 10)
        
    Returns:
        List of case_analysis_runs records with summary stats
    """
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    limit = request.args.get('limit', 10, type=int)
    
    runs = CaseAnalysisRun.query.filter_by(
        case_id=case_id
    ).order_by(
        CaseAnalysisRun.started_at.desc()
    ).limit(limit).all()
    
    result = []
    for run in runs:
        duration = None
        if run.started_at and run.completed_at:
            duration = (run.completed_at - run.started_at).total_seconds()
        
        result.append({
            'analysis_id': run.analysis_id,
            'status': run.status,
            'mode': run.mode,
            'started_at': run.started_at.isoformat() if run.started_at else None,
            'completed_at': run.completed_at.isoformat() if run.completed_at else None,
            'duration_seconds': duration,
            'progress_percent': run.progress_percent,
            'total_findings': run.findings_generated,
            'high_confidence_findings': run.high_confidence_findings,
            'users_profiled': run.users_profiled,
            'systems_profiled': run.systems_profiled,
            'peer_groups_created': run.peer_groups_created,
            'partial_results_available': run.has_partial_results(),
            'last_progress_at': run.last_progress_at.isoformat() if run.last_progress_at else None,
            'error_message': run.error_message if run.status in (AnalysisStatus.FAILED, AnalysisStatus.PARTIAL) else None
        })
    
    return jsonify({
        'success': True,
        'count': len(result),
        'history': result
    })


# =============================================================================
# FEATURE AVAILABILITY
# =============================================================================

@analysis_bp.route('/<int:case_id>/analysis/capabilities', methods=['GET'])
@login_required
def get_analysis_capabilities(case_id):
    """
    Get current analysis capabilities based on feature availability.
    
    Returns:
        {
            'mode': str,
            'mode_description': str,
            'capabilities': {...}
        }
    """
    from utils.feature_availability import FeatureAvailability
    
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    status = FeatureAvailability.get_status_summary()
    
    return jsonify({
        'success': True,
        **status
    })
