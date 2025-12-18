#!/usr/bin/env python3
"""
CaseScope 2026 - Admin Routes
Audit trail and system log viewing for administrators
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime, timedelta
import subprocess
import threading
import time
import os

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(f):
    """Require administrator role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'administrator':
            return "Administrator access required", 403
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# AUDIT TRAIL
# ============================================================================

@admin_bp.route('/audit')
@login_required
@admin_required
def audit_trail():
    """View audit trail"""
    from main import db
    from models import AuditLog, User
    
    # Get filter parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 1000)  # Max 1000 per page
    action_filter = request.args.get('action', '')
    resource_filter = request.args.get('resource', '')
    user_filter = request.args.get('user', '')
    status_filter = request.args.get('status', '')
    days_filter = request.args.get('days', 7, type=int)
    
    # Build query
    query = AuditLog.query
    
    # Time filter
    if days_filter > 0:
        start_date = datetime.utcnow() - timedelta(days=days_filter)
        query = query.filter(AuditLog.created_at >= start_date)
    
    # Action filter
    if action_filter:
        query = query.filter(AuditLog.action.like(f'%{action_filter}%'))
    
    # Resource type filter
    if resource_filter:
        query = query.filter(AuditLog.resource_type == resource_filter)
    
    # User filter
    if user_filter:
        query = query.filter(AuditLog.username.like(f'%{user_filter}%'))
    
    # Status filter
    if status_filter:
        query = query.filter(AuditLog.status == status_filter)
    
    # Order by most recent first
    query = query.order_by(AuditLog.created_at.desc())
    
    # Paginate
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get unique values for filters
    actions = db.session.query(AuditLog.action).distinct().all()
    actions = sorted([a[0] for a in actions if a[0]])
    
    resources = db.session.query(AuditLog.resource_type).distinct().all()
    resources = sorted([r[0] for r in resources if r[0]])
    
    users = db.session.query(AuditLog.username).distinct().all()
    users = sorted([u[0] for u in users if u[0]])
    
    # Statistics
    total_logs = AuditLog.query.count()
    logs_today = AuditLog.query.filter(
        AuditLog.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)
    ).count()
    
    failed_logs = AuditLog.query.filter(AuditLog.status != 'success').count()
    
    return render_template('admin_audit.html',
                         logs=pagination.items,
                         pagination=pagination,
                         actions=actions,
                         resources=resources,
                         users=users,
                         action_filter=action_filter,
                         resource_filter=resource_filter,
                         user_filter=user_filter,
                         status_filter=status_filter,
                         days_filter=days_filter,
                         total_logs=total_logs,
                         logs_today=logs_today,
                         failed_logs=failed_logs)


@admin_bp.route('/audit/<int:log_id>')
@login_required
@admin_required
def audit_detail(log_id):
    """Get detailed information about an audit log entry"""
    from main import db
    from models import AuditLog
    
    log = db.session.get(AuditLog, log_id)
    if not log:
        return jsonify({'error': 'Log not found'}), 404
    
    return jsonify({
        'id': log.id,
        'username': log.username,
        'action': log.action,
        'resource_type': log.resource_type,
        'resource_id': log.resource_id,
        'resource_name': log.resource_name,
        'details': log.details,
        'ip_address': log.ip_address,
        'user_agent': log.user_agent,
        'status': log.status,
        'created_at': log.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
    })


# ============================================================================
# SYSTEM LOGS
# ============================================================================

@admin_bp.route('/logs')
@login_required
@admin_required
def system_logs():
    """View system logs"""
    return render_template('admin_logs.html')


@admin_bp.route('/logs/fetch')
@login_required
@admin_required
def fetch_system_logs():
    """Fetch system logs via AJAX"""
    lines = request.args.get('lines', 100, type=int)
    level = request.args.get('level', 'all')  # all, error, warning, info
    service = request.args.get('service', 'casescope')
    
    # Limit lines to prevent abuse
    lines = min(lines, 1000)
    
    try:
        # Build journalctl command (use full path)
        cmd = ['/usr/bin/journalctl', '-u', f'{service}.service', '-n', str(lines), '--no-pager']
        
        # Add level filter if specified
        if level == 'error':
            cmd.extend(['-p', 'err'])
        elif level == 'warning':
            cmd.extend(['-p', 'warning'])
        
        # Execute command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            logs = result.stdout
            return jsonify({
                'success': True,
                'logs': logs,
                'lines': len(logs.split('\n'))
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to fetch logs',
                'stderr': result.stderr
            }), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'error': 'Log fetch timed out'
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/logs/worker')
@login_required
@admin_required
def fetch_worker_logs():
    """Fetch Celery worker logs"""
    lines = request.args.get('lines', 100, type=int)
    lines = min(lines, 1000)
    
    try:
        cmd = ['/usr/bin/journalctl', '-u', 'casescope-worker.service', '-n', str(lines), '--no-pager']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            return jsonify({
                'success': True,
                'logs': result.stdout,
                'lines': len(result.stdout.split('\n'))
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to fetch worker logs'
            }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/logs/download/<service>')
@login_required
@admin_required
def download_logs(service):
    """Download system logs as a file"""
    from flask import send_file
    import tempfile
    
    if service not in ['casescope', 'casescope-worker']:
        return "Invalid service", 400
    
    try:
        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            cmd = ['/usr/bin/journalctl', '-u', f'{service}.service', '-n', '5000', '--no-pager']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                f.write(result.stdout)
                temp_path = f.name
        
        # Send file
        filename = f'{service}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.log'
        return send_file(temp_path, as_attachment=True, download_name=filename,
                        mimetype='text/plain')
    except Exception as e:
        return f"Error downloading logs: {str(e)}", 500


# ============================================================================
# SYSTEM DIAGNOSTICS
# ============================================================================

@admin_bp.route('/diagnostics')
@login_required
@admin_required
def diagnostics():
    """System diagnostics page with service controls and queue management"""
    return render_template('diagnostics.html')


@admin_bp.route('/diagnostics/restart_web', methods=['POST'])
@login_required
@admin_required
def restart_web_service():
    """Restart the CaseScope web service (spawns async to avoid self-termination)"""
    from audit_logger import log_action
    
    try:
        # Log the action
        log_action(
            action='restart_web_service',
            resource_type='system',
            resource_name='casescope.service',
            status='initiated',
            details={'user': current_user.username}
        )
        
        def delayed_restart():
            """Execute restart after 2-second delay to allow response to be sent"""
            time.sleep(2)
            try:
                result = subprocess.run(
                    ['/usr/bin/sudo', '/usr/bin/systemctl', 'restart', 'casescope.service'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                # Note: Can't log result here since DB connection will be gone after restart
            except Exception as e:
                # Can't log - service will be restarting
                pass
        
        # Spawn restart in background thread
        thread = threading.Thread(target=delayed_restart, daemon=True)
        thread.start()
        
        # Return success immediately (restart will happen in 2 seconds)
        log_action(
            action='restart_web_service',
            resource_type='system',
            resource_name='casescope.service',
            status='success',
            details={'user': current_user.username, 'note': 'Restart scheduled (2s delay)'}
        )
        
        return jsonify({
            'success': True,
            'message': '✅ Web service restart initiated (reloading in 2 seconds...)'
        })
            
    except Exception as e:
        log_action(
            action='restart_web_service',
            resource_type='system',
            resource_name='casescope.service',
            status='error',
            details={'user': current_user.username, 'error': str(e)}
        )
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/diagnostics/restart_worker', methods=['POST'])
@login_required
@admin_required
def restart_worker_service():
    """Restart the CaseScope worker service"""
    from audit_logger import log_action
    
    try:
        # Log the action
        log_action(
            action='restart_worker_service',
            resource_type='system',
            resource_name='casescope-worker.service',
            status='initiated',
            details={'user': current_user.username}
        )
        
        # Restart the service (use full path to sudo)
        result = subprocess.run(
            ['/usr/bin/sudo', '/usr/bin/systemctl', 'restart', 'casescope-worker.service'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            log_action(
                action='restart_worker_service',
                resource_type='system',
                resource_name='casescope-worker.service',
                status='success',
                details={'user': current_user.username}
            )
            return jsonify({
                'success': True,
                'message': '✅ Worker service restarted successfully'
            })
        else:
            # Better error message handling
            error_msg = result.stderr.strip() if result.stderr and result.stderr.strip() else result.stdout.strip() if result.stdout and result.stdout.strip() else f'Command returned exit code {result.returncode}'
            log_action(
                action='restart_worker_service',
                resource_type='system',
                resource_name='casescope-worker.service',
                status='failed',
                details={
                    'user': current_user.username,
                    'error': error_msg,
                    'returncode': result.returncode,
                    'stderr': result.stderr,
                    'stdout': result.stdout
                }
            )
            return jsonify({
                'success': False,
                'error': f'Failed to restart service: {error_msg}'
            }), 500
            
    except Exception as e:
        log_action(
            action='restart_worker_service',
            resource_type='system',
            resource_name='casescope-worker.service',
            status='error',
            details={'user': current_user.username, 'error': str(e)}
        )
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/diagnostics/clear_queue', methods=['POST'])
@login_required
@admin_required
def clear_queue():
    """Clear the entire queue and reset all queued files to initial state"""
    from main import db, app
    from models import CaseFile
    from audit_logger import log_action
    
    try:
        # Log the action
        log_action(
            action='clear_queue',
            resource_type='system',
            resource_name='celery_queue',
            status='initiated',
            details={'user': current_user.username}
        )
        
        # Get all files with celery_task_id (currently queued or processing)
        queued_files = db.session.query(CaseFile).filter(
            CaseFile.celery_task_id.isnot(None)
        ).all()
        
        queued_count = len(queued_files)
        
        if queued_count == 0:
            return jsonify({
                'success': True,
                'message': 'ℹ️ Queue is already empty',
                'files_cleared': 0,
                'files': []
            })
        
        # Reset each file to initial state
        reset_files = []
        for file in queued_files:
            file_info = {
                'id': file.id,
                'filename': file.original_filename,
                'case_id': file.case_id,
                'previous_status': file.file_state or 'Unknown'
            }
            
            # Reset to initial state using new state system
            file.celery_task_id = None
            file.is_indexed = False
            file.event_count = 0
            file.ioc_event_count = 0
            file.violation_count = 0
            file.error_message = None
            # Reset all state flags
            file.sigma_hunted = False
            file.ioc_hunted = False
            file.known_good = False
            file.known_noise = False
            file.failed = False
            file.file_state = 'New'
            
            reset_files.append(file_info)
        
        db.session.commit()
        
        # Purge the Celery queue (Redis)
        try:
            from celery_app import celery_app as celery
            celery.control.purge()
        except Exception as celery_error:
            # Log but don't fail - DB reset is more important
            print(f"Warning: Could not purge Celery queue: {celery_error}")
        
        # Log success
        log_action(
            action='clear_queue',
            resource_type='system',
            resource_name='celery_queue',
            status='success',
            details={
                'user': current_user.username,
                'files_cleared': queued_count,
                'files': reset_files
            }
        )
        
        return jsonify({
            'success': True,
            'message': f'✅ Queue cleared: {queued_count} file(s) reset to Pending status',
            'files_cleared': queued_count,
            'files': reset_files
        })
        
    except Exception as e:
        db.session.rollback()
        log_action(
            action='clear_queue',
            resource_type='system',
            resource_name='celery_queue',
            status='error',
            details={'user': current_user.username, 'error': str(e)}
        )
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@admin_bp.route('/diagnostics/clear_stale_tasks', methods=['POST'])
@login_required
@admin_required
def clear_stale_tasks():
    """Clear orphaned Celery task metadata from Redis"""
    from audit_logger import log_action
    from diagnostics_clear_tasks import clear_stale_tasks as clear_tasks_func
    
    try:
        # Log the action
        log_action(
            action='clear_stale_tasks',
            resource_type='system',
            resource_name='redis_celery',
            status='initiated',
            details={'user': current_user.username}
        )
        
        # Call the clear function
        result = clear_tasks_func()
        
        if result['success']:
            # Log success
            log_action(
                action='clear_stale_tasks',
                resource_type='system',
                resource_name='redis_celery',
                status='success',
                details={
                    'user': current_user.username,
                    'total_cleared': result['total_cleared'],
                    'task_metadata': result['task_metadata_cleared'],
                    'unacked': result['unacked_cleared'],
                    'kombu': result['kombu_cleared']
                }
            )
            
            return jsonify(result)
        else:
            # Log failure
            log_action(
                action='clear_stale_tasks',
                resource_type='system',
                resource_name='redis_celery',
                status='error',
                details={'user': current_user.username, 'error': result.get('error', 'Unknown error')}
            )
            
            return jsonify(result), 500
        
    except Exception as e:
        log_action(
            action='clear_stale_tasks',
            resource_type='system',
            resource_name='redis_celery',
            status='error',
            details={'user': current_user.username, 'error': str(e)}
        )
        return jsonify({
            'success': False,
            'error': str(e),
            'message': f'Failed to clear stale tasks: {e}'
        }), 500

