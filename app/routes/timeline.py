#!/usr/bin/env python3
"""
CaseScope - AI Timeline Routes
Handles AI-generated case timelines with Qwen model
"""

from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime
from logging_config import get_logger

logger = get_logger('app')

timeline_bp = Blueprint('timeline', __name__)


@timeline_bp.route('/case/<int:case_id>/generate_timeline', methods=['POST'])
@login_required
def generate_timeline(case_id):
    """Generate AI timeline for a case using Qwen model"""
    from main import db
    from models import Case, CaseTimeline
    from routes.settings import get_setting
    from tasks import generate_case_timeline as generate_timeline_task
    from ai_report import check_ollama_status
    
    # Check if AI is enabled
    ai_enabled = get_setting('ai_enabled', 'false') == 'true'
    if not ai_enabled:
        return jsonify({
            'success': False,
            'error': 'AI features are not enabled. Please enable in System Settings.'
        }), 403
    
    # Check Ollama status
    ollama_status = check_ollama_status()
    if not ollama_status['running']:
        return jsonify({
            'success': False,
            'error': 'Ollama service is not running. Please start Ollama first.'
        }), 503
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    try:
        # Get timeline model from AI selector (Qwen 7B on 8GB, Qwen 14B on 16GB)
        from ai_model_selector import get_ai_model
        timeline_model = get_ai_model('timeline')
        
        # Check if model exists in Ollama
        import subprocess
        import json as json_lib
        try:
            result = subprocess.run(
                ['ollama', 'list', '--json'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                models = json_lib.loads(result.stdout)
                model_names = [m.get('name', '').split(':')[0] for m in models.get('models', [])]
                timeline_model_base = timeline_model.split(':')[0]
                
                if timeline_model_base not in model_names:
                    return jsonify({
                        'success': False,
                        'error': f'Timeline model "{timeline_model}" not found in Ollama. Please pull the model first.'
                    }), 400
        except Exception as e:
            logger.warning(f"[TIMELINE] Could not verify model existence: {e}")
            # Continue anyway - let Ollama handle the error
        
        # Create timeline record
        new_timeline = CaseTimeline(
            case_id=case_id,
            generated_by=current_user.id,
            status='pending',
            model_name=timeline_model
        )
        db.session.add(new_timeline)
        db.session.commit()
        
        # Get the latest version number for this case
        latest_version = db.session.query(db.func.max(CaseTimeline.version)).filter_by(case_id=case_id).scalar() or 0
        new_timeline.version = latest_version + 1
        db.session.commit()
        
        # Queue Celery task
        generate_timeline_task.delay(new_timeline.id)
        
        logger.info(f"[TIMELINE] Timeline generation queued for case {case_id}, timeline_id={new_timeline.id}, version={new_timeline.version}")
        
        # Audit log
        from audit_logger import log_action
        log_action('generate_timeline', resource_type='case', resource_id=case_id,
                  resource_name=case.name, details={
                      'timeline_id': new_timeline.id,
                      'model': timeline_model,
                      'version': new_timeline.version
                  })
        
        return jsonify({
            'success': True,
            'timeline_id': new_timeline.id,
            'version': new_timeline.version,
            'status': 'pending',
            'message': 'Timeline generation started. This may take 3-5 minutes.'
        })
    except Exception as e:
        logger.error(f"[TIMELINE] Error generating timeline: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@timeline_bp.route('/case/<int:case_id>/timeline/status', methods=['GET'])
@login_required
def timeline_status(case_id):
    """Check if a timeline exists for this case and its status"""
    from main import db
    from models import Case, CaseTimeline
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Get latest timeline for this case
    timeline = CaseTimeline.query.filter_by(case_id=case_id).order_by(CaseTimeline.created_at.desc()).first()
    
    if not timeline:
        return jsonify({
            'success': True,
            'exists': False,
            'message': 'No timeline found for this case'
        })
    
    return jsonify({
        'success': True,
        'exists': True,
        'timeline_id': timeline.id,
        'status': timeline.status,
        'version': timeline.version,
        'model_name': timeline.model_name,
        'created_at': timeline.created_at.isoformat() if timeline.created_at else None,
        'event_count': timeline.event_count,
        'ioc_count': timeline.ioc_count,
        'system_count': timeline.system_count
    })


@timeline_bp.route('/timeline/<int:timeline_id>', methods=['GET', 'DELETE'])
@login_required
def view_timeline(timeline_id):
    """View or delete a case timeline"""
    from main import db
    from models import CaseTimeline, Case
    from flask import request
    
    timeline = db.session.get(CaseTimeline, timeline_id)
    if not timeline:
        if request.method == 'DELETE':
            return jsonify({'success': False, 'error': 'Timeline not found'}), 404
        flash('Timeline not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Verify case access
    case = db.session.get(Case, timeline.case_id)
    if not case:
        if request.method == 'DELETE':
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Handle DELETE request
    if request.method == 'DELETE':
        # Only allow deletion of failed timelines by anyone, or any timeline by admins
        from flask_login import current_user
        if timeline.status != 'failed' and current_user.role != 'administrator':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        # Don't allow deletion of generating timelines
        if timeline.status == 'generating':
            return jsonify({'success': False, 'error': 'Cannot delete timeline that is currently generating'}), 400
        
        try:
            # Audit log
            from audit_logger import log_action
            log_action(
                action='delete_timeline',
                resource_type='timeline',
                resource_id=timeline.id,
                resource_name=f'{case.name} - Timeline v{timeline.version}',
                status='success',
                details={
                    'timeline_id': timeline.id,
                    'case_id': case.id,
                    'case_name': case.name,
                    'version': timeline.version,
                    'status': timeline.status
                }
            )
            
            db.session.delete(timeline)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Timeline deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # Handle GET request
    # Get all timelines for this case (for version history)
    all_timelines = CaseTimeline.query.filter_by(
        case_id=timeline.case_id
    ).order_by(CaseTimeline.version.desc()).all()
    
    return render_template('view_timeline.html',
                         timeline=timeline,
                         case=case,
                         all_timelines=all_timelines)


@timeline_bp.route('/timeline/<int:timeline_id>/api', methods=['GET'])
@login_required
def get_timeline(timeline_id):
    """Get timeline details (API endpoint for AJAX)"""
    from main import db
    from models import CaseTimeline, Case
    
    timeline = db.session.get(CaseTimeline, timeline_id)
    if not timeline:
        return jsonify({'error': 'Timeline not found'}), 404
    
    # Verify case access
    case = db.session.get(Case, timeline.case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # v1.18.3 FIX: Show partial content during generation from raw_response
    content = timeline.timeline_content
    if timeline.status == 'generating' and not content and hasattr(timeline, 'raw_response') and timeline.raw_response:
        # Use partial content from raw_response during generation
        content = timeline.raw_response
    
    return jsonify({
        'success': True,
        'timeline_id': timeline.id,
        'case_id': timeline.case_id,
        'case_name': case.name,
        'status': timeline.status,
        'version': timeline.version,
        'model_name': timeline.model_name,
        'timeline_title': timeline.timeline_title,
        'timeline_content': content,  # v1.18.3: Shows partial content during generation
        'timeline_json': timeline.timeline_json,
        'event_count': timeline.event_count,
        'ioc_count': timeline.ioc_count,
        'system_count': timeline.system_count,
        'generation_time_seconds': timeline.generation_time_seconds,
        'created_at': timeline.created_at.isoformat() if timeline.created_at else None,
        'error_message': timeline.error_message if hasattr(timeline, 'error_message') else None,
        'progress_percent': timeline.progress_percent if hasattr(timeline, 'progress_percent') else None,
        'progress_message': timeline.progress_message if hasattr(timeline, 'progress_message') else None,
        'is_partial': timeline.status == 'generating'  # v1.18.3: Flag to indicate partial content
    })


@timeline_bp.route('/timeline/<int:timeline_id>/cancel', methods=['POST'])
@login_required
def cancel_timeline(timeline_id):
    """Cancel a timeline generation"""
    from main import db
    from models import CaseTimeline
    from celery import current_app as celery_app
    
    timeline = db.session.get(CaseTimeline, timeline_id)
    if not timeline:
        return jsonify({'success': False, 'error': 'Timeline not found'}), 404
    
    # Only allow cancelling if generating or pending
    if timeline.status not in ['pending', 'generating']:
        return jsonify({'success': False, 'error': 'Timeline is not generating'}), 400
    
    try:
        # Revoke Celery task
        if timeline.celery_task_id:
            celery_app.control.revoke(timeline.celery_task_id, terminate=True, signal='SIGKILL')
            logger.info(f"[TIMELINE] Revoked Celery task {timeline.celery_task_id}")
        
        # Update timeline status
        timeline.status = 'cancelled'
        timeline.error_message = 'Cancelled by user'
        db.session.commit()
        
        logger.info(f"[TIMELINE] Timeline {timeline_id} cancelled by user {current_user.username}")
        
        # Audit log
        from audit_logger import log_action
        log_action('cancel_timeline', resource_type='timeline', resource_id=timeline_id,
                  resource_name=f"Timeline v{timeline.version}", details={
                      'case_id': timeline.case_id
                  })
        
        return jsonify({'success': True, 'message': 'Timeline generation cancelled'})
    except Exception as e:
        logger.error(f"[TIMELINE] Error cancelling timeline: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@timeline_bp.route('/timeline/<int:timeline_id>/delete', methods=['POST'])
@login_required
def delete_timeline(timeline_id):
    """Delete a timeline (admin only)"""
    from main import db
    from models import CaseTimeline
    
    # Check if user is administrator
    if current_user.role != 'administrator':
        return jsonify({'error': 'Unauthorized - Administrator access required'}), 403
    
    timeline = db.session.get(CaseTimeline, timeline_id)
    if not timeline:
        return jsonify({'error': 'Timeline not found'}), 404
    
    try:
        case_id = timeline.case_id
        version = timeline.version
        
        db.session.delete(timeline)
        db.session.commit()
        
        logger.info(f"[TIMELINE] Timeline {timeline_id} deleted by {current_user.username}")
        
        # Audit log
        from audit_logger import log_action
        log_action('delete_timeline', resource_type='timeline', resource_id=timeline_id,
                  resource_name=f"Timeline v{version}", details={
                      'case_id': case_id
                  })
        
        return jsonify({'success': True, 'message': 'Timeline deleted'})
    except Exception as e:
        logger.error(f"[TIMELINE] Error deleting timeline: {e}")
        return jsonify({'error': str(e)}), 500


@timeline_bp.route('/case/<int:case_id>/timelines', methods=['GET'])
@login_required
def list_timelines(case_id):
    """List all timelines for a case"""
    from main import db
    from models import Case, CaseTimeline
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    timelines = CaseTimeline.query.filter_by(case_id=case_id).order_by(CaseTimeline.created_at.desc()).all()
    
    return jsonify({
        'success': True,
        'case_id': case_id,
        'case_name': case.name,
        'timelines': [{
            'id': t.id,
            'version': t.version,
            'status': t.status,
            'model_name': t.model_name,
            'timeline_title': t.timeline_title,
            'event_count': t.event_count,
            'ioc_count': t.ioc_count,
            'system_count': t.system_count,
            'generation_time_seconds': t.generation_time_seconds,
            'created_at': t.created_at.isoformat() if t.created_at else None,
            'generated_by_username': t.user.username if t.user else 'Unknown'
        } for t in timelines]
    })

