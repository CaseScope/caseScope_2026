"""
Settings Routes
Handles system configuration and settings management
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from main import db
import logging
import os
import psutil
import subprocess

logger = logging.getLogger(__name__)

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')


def admin_required(f):
    """Decorator to require administrator role"""
    from functools import wraps
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'administrator':
            flash('Administrator access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@settings_bp.route('/')
@login_required
@admin_required
def settings_page():
    """
    System settings page
    """
    # Reload config to get current values from file
    import importlib
    import config as config_module
    importlib.reload(config_module)
    
    current_workers = config_module.CELERY_WORKERS
    
    # Get system info
    cpu_count = psutil.cpu_count(logical=True)
    max_workers = int((cpu_count * 2) / 3)  # 2/3 of CPU cores
    
    return render_template('admin/settings.html',
                         current_workers=current_workers,
                         cpu_count=cpu_count,
                         max_workers=max_workers,
                         config=config_module)


@settings_bp.route('/workers/update', methods=['POST'])
@login_required
@admin_required
def update_workers():
    """
    Update Celery worker count
    """
    from audit_logger import log_action
    
    # Reload config to get current value
    import importlib
    import config as config_module
    importlib.reload(config_module)
    
    current_workers = config_module.CELERY_WORKERS
    
    try:
        # Get requested worker count
        requested_workers = int(request.json.get('workers', 0))
        
        # Validate worker count options
        if requested_workers not in [2, 4, 6, 8]:
            return jsonify({
                'success': False,
                'error': 'Invalid worker count. Must be 2, 4, 6, or 8.'
            }), 400
        
        # Check CPU limit (2/3 of cores)
        cpu_count = psutil.cpu_count(logical=True)
        max_workers = int((cpu_count * 2) / 3)
        
        if requested_workers > max_workers:
            return jsonify({
                'success': False,
                'error': f'Cannot set {requested_workers} workers. Your system has {cpu_count} CPU cores. Maximum allowed: {max_workers} workers (2/3 of cores).'
            }), 400
        
        if requested_workers == current_workers:
            return jsonify({
                'success': True,
                'message': f'Worker count is already set to {requested_workers}.',
                'restart_needed': False
            })
        
        # Update config file
        config_path = '/opt/casescope/app/config.py'
        
        with open(config_path, 'r') as f:
            config_content = f.read()
        
        # Replace the CELERY_WORKERS line
        import re
        pattern = r'CELERY_WORKERS\s*=\s*\d+'
        replacement = f'CELERY_WORKERS = {requested_workers}'
        
        new_content = re.sub(pattern, replacement, config_content)
        
        # Write back to file
        with open(config_path, 'w') as f:
            f.write(new_content)
        
        logger.info(f"Updated CELERY_WORKERS from {current_workers} to {requested_workers}")
        
        # Audit log
        log_action('update_workers',
                   resource_type='system_settings',
                   resource_id=1,
                   resource_name='celery_workers',
                   details={
                       'old_value': current_workers,
                       'new_value': requested_workers,
                       'cpu_count': cpu_count,
                       'max_allowed': max_workers,
                       'updated_by': current_user.username
                   })
        
        # Restart services
        try:
            # Restart Celery workers
            subprocess.run(['sudo', 'systemctl', 'restart', 'casescope-workers'], 
                         check=True, capture_output=True, timeout=30)
            logger.info("Celery workers restarted successfully")
            
            services_restarted = ['casescope-workers']
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout while restarting services")
            return jsonify({
                'success': False,
                'error': 'Timeout while restarting services. Please restart manually.'
            }), 500
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restart services: {e}")
            return jsonify({
                'success': False,
                'error': f'Failed to restart services: {e.stderr.decode() if e.stderr else str(e)}'
            }), 500
        
        return jsonify({
            'success': True,
            'message': f'Worker count updated from {current_workers} to {requested_workers}. Services restarted.',
            'old_value': current_workers,
            'new_value': requested_workers,
            'services_restarted': services_restarted,
            'restart_needed': False
        })
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': 'Invalid worker count format'
        }), 400
    except Exception as e:
        logger.error(f"Error updating worker count: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_bp.route('/evtx-descriptions')
@login_required
@admin_required
def evtx_descriptions():
    """
    EVTX Descriptions management page
    """
    from models import EventDescription
    
    # Get statistics
    total_events = EventDescription.query.count()
    
    # Count by source
    from sqlalchemy import func
    stats_by_source = db.session.query(
        EventDescription.log_source,
        func.count(EventDescription.id)
    ).group_by(EventDescription.log_source).all()
    
    source_stats = {source: count for source, count in stats_by_source}
    
    return render_template('admin/evtx_descriptions.html',
                         total_events=total_events,
                         source_stats=source_stats)


@settings_bp.route('/evtx-descriptions/api/list')
@login_required
@admin_required
def api_list_descriptions():
    """
    API endpoint to list event descriptions with pagination
    """
    from models import EventDescription
    
    try:
        # Get query parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(10, int(request.args.get('per_page', 50))))
        search_query = request.args.get('q', '').strip()
        log_source_filter = request.args.get('source', '')
        
        # Build query
        query = EventDescription.query
        
        # Apply search filter
        if search_query:
            query = query.filter(
                db.or_(
                    EventDescription.event_id.like(f'%{search_query}%'),
                    EventDescription.description.like(f'%{search_query}%')
                )
            )
        
        # Apply log source filter
        if log_source_filter:
            query = query.filter(EventDescription.log_source == log_source_filter)
        
        # Order by event_id
        query = query.order_by(EventDescription.event_id.asc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Format results
        events = []
        for event in pagination.items:
            events.append({
                'id': event.id,
                'event_id': event.event_id,
                'log_source': event.log_source,
                'description': event.description,
                'category': event.category,
                'source_website': event.source_website,
                'source_url': event.source_url,
                'scraped_at': event.scraped_at.isoformat() if event.scraped_at else None
            })
        
        return jsonify({
            'events': events,
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'total_pages': pagination.pages
        })
        
    except Exception as e:
        logger.error(f"Error listing event descriptions: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/evtx-descriptions/api/scrape', methods=['POST'])
@login_required
@admin_required
def api_scrape_descriptions():
    """
    API endpoint to trigger scraping task
    """
    from audit_logger import log_action
    from celery_app import celery
    
    try:
        # Queue the scraping task using send_task (avoids circular import)
        task = celery.send_task('tasks.scrape_event_descriptions')
        
        # Audit log
        log_action('scrape_event_descriptions',
                   resource_type='system_settings',
                   resource_id=1,
                   resource_name='event_descriptions',
                   details={
                       'task_id': task.id,
                       'triggered_by': current_user.username
                   })
        
        logger.info(f"Event description scraping task queued: {task.id}")
        
        return jsonify({
            'success': True,
            'message': 'Scraping task started',
            'task_id': task.id
        })
        
    except Exception as e:
        logger.error(f"Error starting scrape task: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_bp.route('/evtx-descriptions/api/scrape/status/<task_id>')
@login_required
@admin_required
def api_scrape_status(task_id):
    """
    Check status of scraping task
    """
    from celery.result import AsyncResult
    
    try:
        task = AsyncResult(task_id)
        
        response = {
            'task_id': task_id,
            'state': task.state,
            'ready': task.ready()
        }
        
        if task.state == 'PROGRESS':
            response['status'] = task.info.get('status', '')
        elif task.state == 'SUCCESS':
            response['result'] = task.result
        elif task.state == 'FAILURE':
            response['error'] = str(task.info)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error checking task status: {e}")
        return jsonify({'error': str(e)}), 500
