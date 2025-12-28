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
import tempfile
import re

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
    
    # Get parallel processing config
    from utils.parallel_config import get_parallel_config_info
    parallel_config = get_parallel_config_info()
    
    return render_template('admin/settings.html',
                         current_workers=current_workers,
                         cpu_count=cpu_count,
                         max_workers=max_workers,
                         parallel_config=parallel_config,
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
        # Get requested worker count and parallel percentage
        requested_workers = int(request.json.get('worker_count', 0))
        parallel_percentage = request.json.get('parallel_percentage')
        
        # Validate worker count options
        if requested_workers not in [2, 4, 6, 8]:
            return jsonify({
                'success': False,
                'error': 'Invalid worker count. Must be 2, 4, 6, or 8.'
            }), 400
        
        # Validate parallel percentage if provided
        if parallel_percentage is not None:
            parallel_percentage = int(parallel_percentage)
            if not (25 <= parallel_percentage <= 75):
                return jsonify({
                    'success': False,
                    'error': 'Invalid parallel percentage. Must be between 25 and 75.'
                }), 400
        
        # Check CPU limit (2/3 of cores)
        cpu_count = psutil.cpu_count(logical=True)
        max_workers = int((cpu_count * 2) / 3)
        
        if requested_workers > max_workers:
            return jsonify({
                'success': False,
                'error': f'Cannot set {requested_workers} workers. Your system has {cpu_count} CPU cores. Maximum allowed: {max_workers} workers (2/3 of cores).'
            }), 400
        
        if requested_workers == current_workers and parallel_percentage is None:
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
        
        # Replace TASK_PARALLEL_PERCENTAGE if provided
        if parallel_percentage is not None:
            pattern = r'TASK_PARALLEL_PERCENTAGE\s*=\s*\d+'
            replacement = f'TASK_PARALLEL_PERCENTAGE = {parallel_percentage}'
            new_content = re.sub(pattern, replacement, new_content)
        
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


# ============================================================================
# SIGMA Rules Management Routes
# ============================================================================

@settings_bp.route('/sigma-rules')
@login_required
@admin_required
def sigma_rules():
    """
    SIGMA Rules management page
    """
    from models import SigmaRule
    from sqlalchemy import func
    
    # Get statistics
    total_rules = SigmaRule.query.count()
    enabled_rules = SigmaRule.query.filter_by(is_enabled=True).count()
    disabled_rules = SigmaRule.query.filter_by(is_enabled=False).count()
    
    # Count by source folder
    stats_by_folder = db.session.query(
        SigmaRule.source_folder,
        func.count(SigmaRule.id).label('total'),
        func.sum(db.case((SigmaRule.is_enabled == True, 1), else_=0)).label('enabled'),
        func.sum(db.case((SigmaRule.is_enabled == False, 1), else_=0)).label('disabled')
    ).group_by(SigmaRule.source_folder).all()
    
    source_folders = {}
    for folder, total, enabled, disabled in stats_by_folder:
        source_folders[folder] = {
            'total': total or 0,
            'enabled': enabled or 0,
            'disabled': disabled or 0
        }
    
    return render_template('admin/sigma_rules.html',
                         total_rules=total_rules,
                         enabled_rules=enabled_rules,
                         disabled_rules=disabled_rules,
                         source_folders=source_folders)


@settings_bp.route('/sigma-rules/api/list')
@login_required
@admin_required
def api_list_sigma_rules():
    """
    API endpoint to list SIGMA rules with pagination
    """
    from models import SigmaRule
    
    try:
        # Get query parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(10, int(request.args.get('per_page', 50))))
        search_query = request.args.get('q', '').strip()
        folder_filter = request.args.get('folder', '')
        level_filter = request.args.get('level', '')
        status_filter = request.args.get('status', '')
        
        # Build query
        query = SigmaRule.query
        
        # Apply search filter
        if search_query:
            query = query.filter(
                db.or_(
                    SigmaRule.rule_title.ilike(f'%{search_query}%'),
                    SigmaRule.rule_id.ilike(f'%{search_query}%'),
                    SigmaRule.mitre_tags.ilike(f'%{search_query}%')
                )
            )
        
        # Apply folder filter
        if folder_filter:
            query = query.filter(SigmaRule.source_folder == folder_filter)
        
        # Apply level filter
        if level_filter:
            query = query.filter(SigmaRule.rule_level == level_filter)
        
        # Apply status filter
        if status_filter == 'enabled':
            query = query.filter(SigmaRule.is_enabled == True)
        elif status_filter == 'disabled':
            query = query.filter(SigmaRule.is_enabled == False)
        
        # Order by title
        query = query.order_by(SigmaRule.rule_title.asc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Format results
        rules = []
        for rule in pagination.items:
            rules.append({
                'id': rule.id,
                'rule_id': rule.rule_id,
                'rule_title': rule.rule_title,
                'rule_level': rule.rule_level,
                'rule_status': rule.rule_status,
                'rule_category': rule.rule_category,
                'rule_path': rule.rule_path,
                'source_folder': rule.source_folder,
                'mitre_tags': rule.mitre_tags,
                'is_enabled': rule.is_enabled,
                'last_synced': rule.last_synced.isoformat() if rule.last_synced else None
            })
        
        return jsonify({
            'rules': rules,
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'total_pages': pagination.pages
        })
        
    except Exception as e:
        logger.error(f"Error listing SIGMA rules: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/sigma-rules/api/toggle', methods=['POST'])
@login_required
@admin_required
def api_toggle_sigma_rule():
    """
    API endpoint to toggle a SIGMA rule enabled/disabled
    """
    from models import SigmaRule
    from audit_logger import log_action
    
    try:
        rule_id = request.json.get('rule_id')
        is_enabled = request.json.get('is_enabled')
        
        if not rule_id:
            return jsonify({'success': False, 'error': 'Missing rule_id'}), 400
        
        rule = SigmaRule.query.get(rule_id)
        if not rule:
            return jsonify({'success': False, 'error': 'Rule not found'}), 404
        
        old_value = rule.is_enabled
        rule.is_enabled = is_enabled
        db.session.commit()
        
        # Audit log
        log_action('toggle_sigma_rule',
                   resource_type='sigma_rule',
                   resource_id=rule_id,
                   resource_name=rule.rule_title,
                   details={
                       'rule_path': rule.rule_path,
                       'old_value': old_value,
                       'new_value': is_enabled,
                       'updated_by': current_user.username
                   })
        
        logger.info(f"SIGMA rule {rule.rule_title} {'enabled' if is_enabled else 'disabled'} by {current_user.username}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error toggling SIGMA rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/sigma-rules/api/bulk-toggle', methods=['POST'])
@login_required
@admin_required
def api_bulk_toggle_sigma_rules():
    """
    API endpoint to bulk enable/disable SIGMA rules
    Modes: 'threat_hunting' or 'enable_all'
    """
    from models import SigmaRule
    from audit_logger import log_action
    
    try:
        mode = request.json.get('mode')
        
        if mode == 'threat_hunting':
            # Enable threat hunting and emerging threats, disable all others
            threat_hunting_folders = ['rules-threat-hunting', 'rules-emerging-threats']
            
            # Disable all rules first
            disabled_count = SigmaRule.query.update({'is_enabled': False})
            
            # Enable threat hunting and emerging threats
            enabled_count = SigmaRule.query.filter(
                SigmaRule.source_folder.in_(threat_hunting_folders)
            ).update({'is_enabled': True}, synchronize_session=False)
            
            db.session.commit()
            
            # Audit log
            log_action('bulk_toggle_sigma_rules',
                       resource_type='sigma_rules',
                       resource_id=1,
                       resource_name='threat_hunting_mode',
                       details={
                           'mode': 'threat_hunting',
                           'enabled': enabled_count,
                           'disabled': disabled_count - enabled_count,
                           'folders_enabled': threat_hunting_folders,
                           'updated_by': current_user.username
                       })
            
            logger.info(f"Threat Hunting mode activated by {current_user.username}: {enabled_count} enabled, {disabled_count - enabled_count} disabled")
            
            return jsonify({
                'success': True,
                'enabled': enabled_count,
                'disabled': disabled_count - enabled_count
            })
        
        elif mode == 'enable_all':
            # Enable all rules
            enabled_count = SigmaRule.query.update({'is_enabled': True})
            db.session.commit()
            
            # Audit log
            log_action('bulk_toggle_sigma_rules',
                       resource_type='sigma_rules',
                       resource_id=1,
                       resource_name='enable_all',
                       details={
                           'mode': 'enable_all',
                           'enabled': enabled_count,
                           'updated_by': current_user.username
                       })
            
            logger.info(f"All SIGMA rules enabled by {current_user.username}: {enabled_count} rules")
            
            return jsonify({
                'success': True,
                'enabled': enabled_count
            })
        
        else:
            return jsonify({'success': False, 'error': 'Invalid mode'}), 400
        
    except Exception as e:
        logger.error(f"Error bulk toggling SIGMA rules: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/sigma-rules/api/stats')
@login_required
@admin_required
def api_sigma_rules_stats():
    """
    API endpoint to get SIGMA rules statistics
    """
    from models import SigmaRule
    
    try:
        total_rules = SigmaRule.query.count()
        enabled_rules = SigmaRule.query.filter_by(is_enabled=True).count()
        disabled_rules = SigmaRule.query.filter_by(is_enabled=False).count()
        
        return jsonify({
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'disabled_rules': disabled_rules
        })
        
    except Exception as e:
        logger.error(f"Error getting SIGMA rules stats: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/sigma-rules/api/update', methods=['POST'])
@login_required
@admin_required
def api_update_sigma_rules():
    """
    API endpoint to trigger SIGMA rules update from GitHub
    """
    from audit_logger import log_action
    from celery_app import celery
    
    try:
        # Queue the update task
        task = celery.send_task('tasks.update_sigma_rules')
        
        # Audit log
        log_action('update_sigma_rules',
                   resource_type='system_settings',
                   resource_id=1,
                   resource_name='sigma_rules',
                   details={
                       'task_id': task.id,
                       'triggered_by': current_user.username
                   })
        
        logger.info(f"SIGMA rules update task queued: {task.id}")
        
        return jsonify({
            'success': True,
            'message': 'Update task started',
            'task_id': task.id
        })
        
    except Exception as e:
        logger.error(f"Error starting SIGMA rules update task: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_bp.route('/sigma-rules/api/update/status/<task_id>')
@login_required
@admin_required
def api_update_sigma_rules_status(task_id):
    """
    Check status of SIGMA rules update task
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
        logger.error(f"Error checking SIGMA update task status: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/sigma-rules/api/sync', methods=['POST'])
@login_required
@admin_required
def api_sync_sigma_rules():
    """
    API endpoint to trigger SIGMA rules sync from disk
    """
    from audit_logger import log_action
    from celery_app import celery
    
    try:
        # Queue the sync task
        task = celery.send_task('tasks.sync_sigma_rules')
        
        # Audit log
        log_action('sync_sigma_rules',
                   resource_type='system_settings',
                   resource_id=1,
                   resource_name='sigma_rules',
                   details={
                       'task_id': task.id,
                       'triggered_by': current_user.username
                   })
        
        logger.info(f"SIGMA rules sync task queued: {task.id}")
        
        return jsonify({
            'success': True,
            'message': 'Sync task started',
            'task_id': task.id
        })
        
    except Exception as e:
        logger.error(f"Error starting SIGMA rules sync task: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_bp.route('/sigma-rules/api/sync/status/<task_id>')
@login_required
@admin_required
def api_sync_sigma_rules_status(task_id):
    """
    Check status of SIGMA rules sync task
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
        logger.error(f"Error checking SIGMA sync task status: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# SSL Certificate Management Routes
# ============================================================================

@settings_bp.route('/api/upload-ssl', methods=['POST'])
@login_required
@admin_required
def api_upload_ssl():
    """
    API endpoint to upload SSL certificate and private key
    """
    from audit_logger import log_action
    from werkzeug.utils import secure_filename
    import shutil
    from datetime import datetime
    
    try:
        # Get uploaded files
        if 'cert_file' not in request.files or 'key_file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Both certificate and key files are required'
            }), 400
        
        cert_file = request.files['cert_file']
        key_file = request.files['key_file']
        
        if cert_file.filename == '' or key_file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No files selected'
            }), 400
        
        # Validate file extensions
        cert_filename = secure_filename(cert_file.filename)
        key_filename = secure_filename(key_file.filename)
        
        cert_ext = cert_filename.rsplit('.', 1)[1].lower() if '.' in cert_filename else ''
        key_ext = key_filename.rsplit('.', 1)[1].lower() if '.' in key_filename else ''
        
        allowed_cert_exts = {'pem', 'crt', 'cer'}
        allowed_key_exts = {'pem', 'key'}
        
        if cert_ext not in allowed_cert_exts:
            return jsonify({
                'success': False,
                'error': f'Certificate file must have one of these extensions: {", ".join(allowed_cert_exts)}'
            }), 400
        
        if key_ext not in allowed_key_exts:
            return jsonify({
                'success': False,
                'error': f'Key file must have one of these extensions: {", ".join(allowed_key_exts)}'
            }), 400
        
        # Read file contents for validation
        cert_content = cert_file.read().decode('utf-8')
        key_content = key_file.read().decode('utf-8')
        
        # Helper function to detect and convert PKCS#12/bag format to PEM
        def extract_pem_from_bag(content, extract_type='certificate'):
            """Extract PEM content from PKCS#12 bag format"""
            lines = content.strip().split('\n')
            pem_lines = []
            in_pem = False
            
            if extract_type == 'certificate':
                start_markers = ['-----BEGIN CERTIFICATE-----']
                end_markers = ['-----END CERTIFICATE-----']
            else:  # private key
                start_markers = [
                    '-----BEGIN PRIVATE KEY-----',
                    '-----BEGIN RSA PRIVATE KEY-----',
                    '-----BEGIN EC PRIVATE KEY-----'
                ]
                end_markers = [
                    '-----END PRIVATE KEY-----',
                    '-----END RSA PRIVATE KEY-----',
                    '-----END EC PRIVATE KEY-----'
                ]
            
            for line in lines:
                # Check if we're starting PEM content
                if any(marker in line for marker in start_markers):
                    in_pem = True
                    pem_lines.append(line)
                elif in_pem:
                    pem_lines.append(line)
                    # Check if we're ending PEM content
                    if any(marker in line for marker in end_markers):
                        break
            
            if pem_lines:
                return '\n'.join(pem_lines)
            return None
        
        # Check if certificate is in PEM format or needs extraction
        if not cert_content.strip().startswith('-----BEGIN CERTIFICATE-----'):
            # Try to extract PEM from bag format
            extracted_cert = extract_pem_from_bag(cert_content, 'certificate')
            if extracted_cert:
                cert_content = extracted_cert
                logger.info("Converted certificate from PKCS#12/bag format to PEM")
            else:
                return jsonify({
                    'success': False,
                    'error': 'Invalid certificate format. File must be PEM-encoded or contain PEM data'
                }), 400
        
        # Validate certificate has proper end marker
        if not cert_content.strip().endswith('-----END CERTIFICATE-----'):
            return jsonify({
                'success': False,
                'error': 'Invalid certificate format. Certificate must end with "-----END CERTIFICATE-----"'
            }), 400
        
        # Validate private key format
        key_headers = [
            '-----BEGIN PRIVATE KEY-----',
            '-----BEGIN RSA PRIVATE KEY-----',
            '-----BEGIN EC PRIVATE KEY-----',
        ]
        
        # Check if key needs extraction from bag format
        if not any(key_content.strip().startswith(header) for header in key_headers):
            extracted_key = extract_pem_from_bag(key_content, 'key')
            if extracted_key:
                key_content = extracted_key
                logger.info("Converted private key from PKCS#12/bag format to PEM")
            else:
                return jsonify({
                    'success': False,
                    'error': 'Invalid private key format. File must be PEM-encoded or contain PEM data'
                }), 400
        
        # Check for encrypted private key (not supported by Gunicorn)
        if '-----BEGIN ENCRYPTED PRIVATE KEY-----' in key_content or 'Proc-Type: 4,ENCRYPTED' in key_content:
            return jsonify({
                'success': False,
                'error': 'Encrypted private keys are not supported. Please provide an unencrypted private key.'
            }), 400
        
        # Ensure SSL directory exists
        ssl_dir = '/opt/casescope/ssl'
        os.makedirs(ssl_dir, exist_ok=True)
        
        # Backup existing certificates if they exist
        backup_dir = f'/opt/casescope/ssl/backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        cert_path = '/opt/casescope/ssl/cert.pem'
        key_path = '/opt/casescope/ssl/key.pem'
        
        if os.path.exists(cert_path) or os.path.exists(key_path):
            os.makedirs(backup_dir, exist_ok=True)
            if os.path.exists(cert_path):
                shutil.copy2(cert_path, os.path.join(backup_dir, 'cert.pem'))
            if os.path.exists(key_path):
                shutil.copy2(key_path, os.path.join(backup_dir, 'key.pem'))
            logger.info(f"Backed up existing SSL certificates to {backup_dir}")
        
        # Write new certificate and key
        with open(cert_path, 'w') as f:
            f.write(cert_content)
        
        with open(key_path, 'w') as f:
            f.write(key_content)
        
        # Set proper permissions (readable by casescope user only)
        os.chmod(cert_path, 0o600)
        os.chmod(key_path, 0o600)
        
        # Change ownership to casescope user
        try:
            import pwd
            casescope_uid = pwd.getpwnam('casescope').pw_uid
            casescope_gid = pwd.getpwnam('casescope').pw_gid
            os.chown(cert_path, casescope_uid, casescope_gid)
            os.chown(key_path, casescope_uid, casescope_gid)
            os.chown(ssl_dir, casescope_uid, casescope_gid)
            if os.path.exists(backup_dir):
                os.chown(backup_dir, casescope_uid, casescope_gid)
        except Exception as e:
            logger.warning(f"Could not change ownership to casescope user: {e}")
        
        logger.info(f"SSL certificate and key uploaded successfully by {current_user.username}")
        
        # Audit log
        log_action('upload_ssl_certificate',
                   resource_type='system_settings',
                   resource_id=1,
                   resource_name='ssl_certificate',
                   details={
                       'cert_path': cert_path,
                       'key_path': key_path,
                       'backup_dir': backup_dir if os.path.exists(backup_dir) else None,
                       'uploaded_by': current_user.username,
                       'cert_filename': cert_filename,
                       'key_filename': key_filename
                   })
        
        return jsonify({
            'success': True,
            'message': f'SSL certificate and private key uploaded successfully to {ssl_dir}',
            'cert_path': cert_path,
            'key_path': key_path,
            'backup_dir': backup_dir if os.path.exists(backup_dir) else None,
            'restart_required': True
        })
        
    except UnicodeDecodeError:
        return jsonify({
            'success': False,
            'error': 'Invalid file encoding. Files must be text-based PEM format.'
        }), 400
    except Exception as e:
        logger.error(f"Error uploading SSL certificate: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_bp.route('/api/restart-service', methods=['POST'])
@admin_required
def restart_service():
    """Restart the casescope-new service"""
    try:
        # Import audit logger
        from app.audit_logger import log_action
        
        logger.info(f"Service restart requested by {current_user.username}")
        
        # Execute service restart with sudo
        result = subprocess.run(
            ['sudo', 'systemctl', 'restart', 'casescope-new'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            # Audit log
            log_action('restart_service',
                      resource_type='system',
                      resource_id=1,
                      resource_name='casescope-new',
                      details={
                          'service': 'casescope-new',
                          'restarted_by': current_user.username
                      })
            
            return jsonify({
                'success': True,
                'message': 'Service casescope-new restarted successfully'
            })
        else:
            logger.error(f"Failed to restart service: {result.stderr}")
            return jsonify({
                'success': False,
                'error': f'Failed to restart service: {result.stderr}'
            }), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'error': 'Service restart timed out'
        }), 500
    except Exception as e:
        logger.error(f"Error restarting service: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
