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
    running = CaseAnalysisRun.query.filter_by(
        case_id=case_id
    ).filter(
        CaseAnalysisRun.status.in_([AnalysisStatus.PENDING, AnalysisStatus.PROFILING,
                                    AnalysisStatus.CORRELATING, AnalysisStatus.ANALYZING])
    ).first()
    
    if running:
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
    
    response = {
        'success': True,
        'has_analysis': True,
        'analysis_id': run.analysis_id,
        'status': run.status,
        'progress_percent': run.progress_percent or 0,
        'current_phase': run.current_phase,
        'status_message': run.current_phase,  # Use current_phase as status message
        'mode': run.mode,
        'started_at': run.started_at.isoformat() if run.started_at else None,
        'completed_at': run.completed_at.isoformat() if run.completed_at else None
    }
    
    if run.status == AnalysisStatus.COMPLETE:
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
    
    if run.status == AnalysisStatus.FAILED:
        response['error_message'] = run.error_message
    
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
    
    response = {
        'success': True,
        'analysis_id': run.analysis_id,
        'status': run.status,
        'progress_percent': run.progress_percent or 0,
        'current_phase': run.current_phase,
        'status_message': run.current_phase,  # Use current_phase as status message
        'mode': run.mode,
        'started_at': run.started_at.isoformat() if run.started_at else None,
        'completed_at': run.completed_at.isoformat() if run.completed_at else None
    }
    
    if run.status == AnalysisStatus.COMPLETE:
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
    
    if run.status == AnalysisStatus.FAILED:
        response['error_message'] = run.error_message
    
    return jsonify(response)


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
            data = formatter.get_timeline_view()
        elif view == 'pattern':
            data = formatter.get_pattern_grouped_view()
        elif view == 'entity':
            data = formatter.get_entity_grouped_view()
        elif view == 'actions':
            data = formatter.get_suggested_actions()
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
            'target_entity': a.target_entity,
            'reason': a.reason,
            'confidence': a.confidence,
            'source_type': a.source_type,
            'source_id': a.source_id,
            'status': a.status,
            'analyst_notes': a.analyst_notes,
            'created_at': a.created_at.isoformat() if a.created_at else None,
            'handled_at': a.handled_at.isoformat() if a.handled_at else None,
            'handled_by': a.handled_by
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
    action.handled_at = datetime.utcnow()
    action.handled_by = current_user.username if current_user else None
    
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
            'handled_at': action.handled_at.isoformat() if action.handled_at else None,
            'handled_by': action.handled_by,
            'execution_result': action.execution_result
        }
    })


def _execute_suggested_action(action: SuggestedAction, case_id: int) -> dict:
    """Execute a suggested action when accepted"""
    action_type = action.action_type
    target = action.target_entity
    
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
        from models.ioc import IOC, IOCCase
        
        # Determine IOC type based on target format
        ioc_type = _infer_ioc_type(target)
        
        # Check if IOC already exists
        existing = IOC.query.filter_by(value=target).first()
        if existing:
            # Link to case if not already linked
            link = IOCCase.query.filter_by(ioc_id=existing.id, case_id=case_id).first()
            if not link:
                link = IOCCase(ioc_id=existing.id, case_id=case_id)
                db.session.add(link)
                db.session.commit()
            return {'executed': True, 'ioc_id': existing.id, 'already_existed': True}
        
        # Create new IOC
        ioc = IOC(
            value=target,
            ioc_type=ioc_type,
            description=action.reason or 'Added from analysis suggestion',
            source='analysis'
        )
        db.session.add(ioc)
        db.session.flush()
        
        # Link to case
        link = IOCCase(ioc_id=ioc.id, case_id=case_id)
        db.session.add(link)
        db.session.commit()
        
        return {'executed': True, 'ioc_id': ioc.id, 'created': True}
    
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
            'error_message': run.error_message if run.status == AnalysisStatus.FAILED else None
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
