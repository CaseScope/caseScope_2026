#!/usr/bin/env python3
"""
CaseScope 2026 v1.0.0 - Main Flask Application
Minimal viable product - essential routes only
"""

import os
import logging
import shutil
from datetime import datetime
from flask import Flask, render_template_string, render_template, request, redirect, url_for, jsonify, session, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from opensearchpy import OpenSearch
from sqlalchemy import text

# Import config and models
from config import Config
from models import db, User, Case, CaseFile, SigmaRule, SigmaViolation, IOC, IOCMatch, System, SkippedFile, SystemSettings, TimelineTag, AIReport, EvidenceFile
from celery_app import celery_app

# Setup logging using centralized configuration
from logging_config import setup_logging, get_logger
setup_logging()  # Initialize logging system
logger = get_logger('app')  # Get app-specific logger

# Create Flask app
app = Flask(__name__)
app.config.from_object(Config)


# Helper function to check if OpenSearch index exists
def index_exists(case_id: int) -> bool:
    """
    Check if the consolidated case index exists in OpenSearch.
    Returns True if index exists, False otherwise.
    
    v1.13.1+: Uses consolidated index (case_{id}), not per-file indices
    """
    try:
        index_name = f"case_{case_id}"
        return opensearch_client.indices.exists(index=index_name)
    except Exception as e:
        logger.error(f"[INDEX_CHECK] Error checking if index exists for case {case_id}: {e}")
        return False


# Helper function for extracting nested field values
def get_nested_field(source_dict, field_path):
    """
    Extract a nested field value from a dictionary using dot notation
    Example: get_nested_field(event, 'Event.EventData.SubjectUserName')
    """
    if not field_path or not source_dict:
        return None
    
    keys = field_path.split('.')
    value = source_dict
    
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
            if value is None:
                return None
        else:
            return None
    
    # Handle dict values (like {'#text': 'value'})
    if isinstance(value, dict):
        if '#text' in value:
            return value['#text']
        elif 'text' in value:
            return value['text']
        # For other dicts, return string representation
        return str(value)
    
    return value


# Register Jinja filter
app.jinja_env.filters['get_nested'] = get_nested_field

# Disable static file caching for CSS/JS
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Cache busting timestamp for static files and templates
# Update this whenever templates change to force browser reload
import time
CACHE_BUST_TIME = str(int(time.time()))  # Auto-updates on server restart
TEMPLATE_VERSION = "v1.19.5.3"  # Manual: Modal CSS + polling fix applied

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize rate limiter (Redis-backed for distributed rate limiting)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"
)

# Initialize OpenSearch
opensearch_client = OpenSearch(
    hosts=[{'host': app.config['OPENSEARCH_HOST'], 'port': app.config['OPENSEARCH_PORT']}],
    http_compress=True,
    use_ssl=app.config['OPENSEARCH_USE_SSL'],
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False,
    timeout=60,  # Increase from default 10s to 60s for bulk operations
    max_retries=3,
    retry_on_timeout=True
)

# Register blueprints
from routes.ioc import ioc_bp
app.register_blueprint(ioc_bp)
from routes.systems import systems_bp
app.register_blueprint(systems_bp)
from routes.known_users import known_users_bp
app.register_blueprint(known_users_bp)
from routes.evidence import evidence_bp
app.register_blueprint(evidence_bp)
from routes.files import files_bp
from routes.cases import cases_bp
from routes.api_stats import api_stats_bp
from routes.settings import settings_bp
from routes.users import users_bp
from routes.admin import admin_bp
from routes.timeline import timeline_bp
from routes.archive import archive_bp
from routes.ai_search import ai_search_bp
app.register_blueprint(files_bp)
app.register_blueprint(cases_bp)
app.register_blueprint(api_stats_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(users_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(timeline_bp)
app.register_blueprint(archive_bp)
app.register_blueprint(ai_search_bp)

# Apply rate limiting to AI search endpoint AFTER blueprint registration
# Get the view function and wrap it with the rate limiter
ai_search_ask_func = app.view_functions['ai_search.ai_search_ask']
app.view_functions['ai_search.ai_search_ask'] = limiter.limit("10 per minute")(ai_search_ask_func)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Context processor - inject global template variables
@app.after_request
def add_header(response):
    """Add cache control headers to prevent caching"""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.context_processor
def inject_global_vars():
    """Inject available_cases, current_case, and version info into all templates"""
    import json
    import os
    
    # Load version info from version.json
    version_info = {'version': 'unknown', 'name': 'CaseScope', 'release_date': '', 'build': ''}
    try:
        version_file = os.path.join(os.path.dirname(__file__), 'version.json')
        if os.path.exists(version_file):
            with open(version_file, 'r') as f:
                version_info = json.load(f)
    except Exception as e:
        print(f"Error loading version.json: {e}")
    
    if current_user.is_authenticated:
        # v1.16.0+: Show all cases regardless of status
        available_cases = db.session.query(Case).order_by(Case.created_at.desc()).all()
        
        # Determine current case: URL > Session > None
        current_case = None
        
        # Priority 1: case_id in URL (set session from URL)
        if request.view_args and 'case_id' in request.view_args:
            case_id = request.view_args['case_id']
            current_case = db.session.get(Case, case_id)
            if current_case:
                session['current_case_id'] = case_id
        # Priority 2: case_id in session
        elif 'current_case_id' in session:
            current_case = db.session.get(Case, session['current_case_id'])
            # Clear session if case no longer exists
            if not current_case:
                session.pop('current_case_id', None)
        
        return {
            'available_cases': available_cases,
            'current_case': current_case,
            'db': db,
            'CaseFile': CaseFile,
            'app_version': version_info,
            'cache_bust': CACHE_BUST_TIME
        }
    return {
        'app_version': version_info,
        'cache_bust': CACHE_BUST_TIME
    }


# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # Get version info
    import json
    import os
    version_info = {'version': 'unknown'}
    try:
        version_file = os.path.join(os.path.dirname(__file__), 'version.json')
        if os.path.exists(version_file):
            with open(version_file, 'r') as f:
                version_info = json.load(f)
    except:
        pass
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = db.session.query(User).filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            # Check if user is active
            if not user.is_active:
                # Log failed login attempt
                from audit_logger import log_action
                log_action('login_failed', resource_type='auth', resource_name=username, 
                          details='Account deactivated', status='failed')
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
                return render_template('login.html', app_version=version_info, cache_bust=CACHE_BUST_TIME)
            
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log successful login
            from audit_logger import log_action
            log_action('login', resource_type='auth', resource_name=username, status='success')
            
            return redirect(url_for('dashboard'))
        
        # Log failed login attempt
        from audit_logger import log_action
        log_action('login_failed', resource_type='auth', resource_name=username or 'unknown', 
                  details='Invalid credentials', status='failed')
        flash('Invalid username or password', 'error')
    
    return render_template('login.html', app_version=version_info, cache_bust=CACHE_BUST_TIME)

# OLD LOGIN TEMPLATE - DELETED, NOW USING templates/login.html
def _old_login_template():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CaseScope 2026 - Login</title>
        <style>
            body { font-family: Arial; background: #1a1a1a; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .login-box { background: #2a2a2a; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); min-width: 350px; }
            .logo-container { text-align: center; margin-bottom: 30px; }
            .logo-main { margin-bottom: 5px; }
            .logo-text { font-size: 28px; font-weight: 700; }
            .logo-case { color: #4ade80; font-weight: 600; }
            .logo-scope { color: #fff; font-weight: 300; }
            .logo-year { color: #fff; font-weight: 300; margin-left: 8px; }
            .logo-version { color: #94a3b8; font-size: 12px; font-weight: 400; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #444; background: #333; color: #fff; border-radius: 5px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin-top: 10px; }
            button:hover { background: #0052a3; }
            .error { color: #ff4444; margin-bottom: 15px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <div class="logo-container">
                <div class="logo-main">
                    <span class="logo-text">
                        <span class="logo-case">case</span><span class="logo-scope">Scope</span><span class="logo-year">2026</span>
                    </span>
                </div>
                <div class="logo-version">v{{ version }}</div>
            </div>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="error">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required autofocus>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    ''', version=version_info.get('version', 'unknown'))


@app.route('/logout')
@login_required
def logout():
    """Logout and release all case locks (v1.25.0)"""
    from audit_logger import log_action
    from case_lock_manager import release_all_user_locks
    
    username = current_user.username if current_user.is_authenticated else 'unknown'
    user_id = current_user.id if current_user.is_authenticated else None
    
    # Release all locks held by this user
    if user_id:
        count, msg = release_all_user_locks(user_id)
        if count > 0:
            log_action('release_locks_on_logout', resource_type='case_lock', 
                      resource_name=f'{count} locks released', 
                      details={'user_id': user_id, 'username': username})
    
    # Log logout
    log_action('logout', resource_type='auth', resource_name=username)
    
    logout_user()
    return redirect(url_for('login'))


# ============================================================================
# CASE SELECTION
# ============================================================================

def get_session_id():
    """Generate a consistent session ID for lock management (v1.25.0)"""
    # Use a combination of session data to create a unique session ID
    # Flask session is a SecureCookieSession without a direct .sid attribute
    import hashlib
    # Create a hash from the session's identity
    session_data = f"{current_user.id}_{id(session)}"
    return hashlib.md5(session_data.encode()).hexdigest()


@app.route('/select_case/<int:case_id>')
@login_required
def select_case(case_id):
    """
    Set the current case in session and acquire lock (v1.25.0)
    Checks if another user has the case locked and shows warning if so
    """
    from case_lock_manager import acquire_case_lock, get_case_lock_info
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Check lock status first
    lock_info = get_case_lock_info(case_id)
    
    # If case is locked by another user, show warning and return lock info as JSON for modal
    if lock_info['is_locked'] and lock_info['locked_by_user_id'] != current_user.id:
        # Return JSON for AJAX request (modal will handle display)
        if request.args.get('check_only') == '1':
            return jsonify({
                'locked': True,
                'locked_by': lock_info['locked_by_username'],
                'locked_at': lock_info['locked_at'].isoformat() + 'Z' if lock_info['locked_at'] else None,
                'last_activity': lock_info['last_activity'].isoformat() + 'Z' if lock_info['last_activity'] else None,
                'is_stale': lock_info['is_stale'],
                'case_name': case.name,
                'case_id': case_id
            })
        else:
            # Direct navigation - show flash message and redirect
            flash(f'⚠️ Case "{case.name}" is currently being worked on by {lock_info["locked_by_username"]}', 'warning')
            return redirect(url_for('dashboard'))
    
    # Try to acquire lock
    force = request.args.get('force') == '1'  # Allow force override if ?force=1
    session_id = get_session_id()
    success, lock, message, locked_by = acquire_case_lock(
        case_id=case_id,
        user_id=current_user.id,
        session_id=session_id,
        force=force
    )
    
    if success:
        session['current_case_id'] = case_id
        flash(f'Case selected: {case.name}', 'success')
        return redirect(url_for('view_case', case_id=case_id))
    else:
        # Failed to acquire lock
        flash(f'⚠️ {message}', 'warning')
        return redirect(url_for('dashboard'))


@app.route('/clear_case')
@login_required
def clear_case():
    """Clear the current case selection and release lock (v1.25.0)"""
    from case_lock_manager import release_case_lock
    
    case_id = session.get('current_case_id')
    if case_id:
        # Release lock when clearing case
        session_id = get_session_id()
        release_case_lock(case_id, user_id=current_user.id, session_id=session_id)
    
    session.pop('current_case_id', None)
    flash('Case selection cleared', 'info')
    return redirect(url_for('dashboard'))


# ============================================================================
# CASE LOCK MANAGEMENT (v1.25.0)
# ============================================================================

@app.route('/case/<int:case_id>/unlock', methods=['POST'])
@login_required
def unlock_case(case_id):
    """
    Unlock a case (release lock voluntarily)
    Called when user clicks "Unlock Case" button
    """
    from case_lock_manager import release_case_lock
    
    session_id = get_session_id()
    success, message = release_case_lock(case_id, user_id=current_user.id, session_id=session_id)
    
    if success:
        # Clear from session
        if session.get('current_case_id') == case_id:
            session.pop('current_case_id', None)
        
        flash('Case unlocked successfully', 'success')
        return redirect(url_for('case_selection'))
    else:
        flash(f'Error unlocking case: {message}', 'error')
        return redirect(url_for('view_case', case_id=case_id))


@app.route('/case/<int:case_id>/lock_status', methods=['GET'])
@login_required
def case_lock_status(case_id):
    """Get lock status for a case (AJAX endpoint)"""
    from case_lock_manager import get_case_lock_info
    
    lock_info = get_case_lock_info(case_id)
    
    return jsonify({
        'is_locked': lock_info['is_locked'],
        'locked_by_user_id': lock_info['locked_by_user_id'],
        'locked_by_username': lock_info['locked_by_username'],
        'locked_at': lock_info['locked_at'].isoformat() if lock_info['locked_at'] else None,
        'last_activity': lock_info['last_activity'].isoformat() if lock_info['last_activity'] else None,
        'is_stale': lock_info['is_stale'],
        'can_force_unlock': lock_info['can_force_unlock']
    })


@app.route('/case/<int:case_id>/heartbeat', methods=['POST'])
@login_required
def case_heartbeat(case_id):
    """
    Update case lock activity (heartbeat)
    Called periodically by frontend JavaScript to keep lock alive
    """
    from case_lock_manager import update_lock_activity
    
    session_id = get_session_id()
    success, message = update_lock_activity(case_id, current_user.id, session_id)
    
    return jsonify({
        'success': success,
        'message': message
    })


# ============================================================================
# HEALTH CHECK ENDPOINTS
# ============================================================================

@app.route('/health/db')
@login_required
def db_health_check():
    """
    Database connection pool health check endpoint.
    
    Monitors pool usage to detect connection leaks and exhaustion.
    
    Returns:
        JSON with pool statistics and health status
    """
    try:
        pool = db.engine.pool
        
        # Get pool statistics
        pool_size = pool.size()
        checked_out = pool.checkedout()
        checked_in = pool.checkedin()
        overflow = pool.overflow()
        max_overflow = pool._max_overflow
        
        # Calculate health status
        # Unhealthy if: using all connections + all overflow
        total_available = pool_size + max_overflow
        total_used = checked_out
        utilization = (total_used / total_available * 100) if total_available > 0 else 0
        
        # Health thresholds
        if utilization < 50:
            status = 'healthy'
            color = 'green'
        elif utilization < 80:
            status = 'warning'
            color = 'yellow'
        else:
            status = 'critical'
            color = 'red'
        
        return jsonify({
            'status': status,
            'color': color,
            'utilization_percent': round(utilization, 1),
            'pool': {
                'size': pool_size,
                'max_overflow': max_overflow,
                'total_available': total_available,
                'checked_out': checked_out,
                'checked_in': checked_in,
                'overflow': overflow
            },
            'message': f'Database pool {status}: {utilization:.1f}% utilized ({checked_out}/{total_available} connections in use)'
        })
        
    except Exception as e:
        logger.error(f"[HEALTH] DB pool check failed: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/health/system')
@login_required
def system_health_check():
    """
    Overall system health check endpoint with detailed metrics.
    
    Checks:
    - Database connection pool
    - OpenSearch cluster
    - Celery workers
    - Disk space
    
    Returns:
        JSON with detailed system health metrics for diagnostics dashboard
    """
    from system_stats import get_system_status
    import shutil
    
    response = {}
    
    # DATABASE - Get pool statistics
    try:
        pool = db.engine.pool
        checked_out = pool.checkedout()
        checked_in = pool.checkedin()
        size = pool.size()
        max_overflow = pool._max_overflow
        total_available = size + max_overflow
        utilization = (checked_out / total_available * 100) if total_available > 0 else 0
        
        if utilization < 50:
            status = 'healthy'
        elif utilization < 80:
            status = 'warning'
        else:
            status = 'critical'
        
        response['database'] = {
            'status': status,
            'message': f'Pool: {checked_out}/{total_available} connections in use',
            'pool': {
                'size': size,
                'checked_out': checked_out,
                'checked_in': checked_in,
                'max_overflow': max_overflow,
                'total_available': total_available,
                'utilization_percent': round(utilization, 1)
            }
        }
    except Exception as e:
        logger.error(f"[HEALTH] Database check failed: {e}")
        response['database'] = {
            'status': 'unknown',
            'message': f'Error: {str(e)}',
            'pool': {}
        }
    
    # OPENSEARCH - Get cluster info
    try:
        cluster_health = opensearch_client.cluster.health()
        cluster_stats = opensearch_client.cluster.stats()
        indices_count = opensearch_client.cat.indices(format='json')
        
        status_map = {
            'green': 'healthy',
            'yellow': 'warning',
            'red': 'critical'
        }
        
        response['opensearch'] = {
            'status': status_map.get(cluster_health.get('status', 'unknown'), 'unknown'),
            'message': f"Cluster: {cluster_health.get('cluster_name', 'unknown')}",
            'cluster_name': cluster_health.get('cluster_name', 'N/A'),
            'indices_count': len(indices_count) if indices_count else 0,
            'nodes': cluster_health.get('number_of_nodes', 0)
        }
    except Exception as e:
        logger.error(f"[HEALTH] OpenSearch check failed: {e}")
        response['opensearch'] = {
            'status': 'unknown',
            'message': f'Error: {str(e)}',
            'cluster_name': 'N/A',
            'indices_count': 0
        }
    
    # CELERY - Get worker statistics
    try:
        from celery_app import celery_app as celery
        inspect = celery.control.inspect()
        stats = inspect.stats()
        active = inspect.active()
        
        if stats:
            active_workers = len(stats)
            active_tasks = sum(len(tasks) for tasks in active.values()) if active else 0
            
            if active_workers == 0:
                status = 'critical'
            elif active_tasks > 100:
                status = 'warning'
            else:
                status = 'healthy'
            
            response['celery'] = {
                'status': status,
                'message': f'{active_workers} workers, {active_tasks} tasks',
                'active_workers': active_workers,
                'active_tasks': active_tasks
            }
        else:
            response['celery'] = {
                'status': 'critical',
                'message': 'No workers responding',
                'active_workers': 0,
                'active_tasks': 0
            }
    except Exception as e:
        logger.error(f"[HEALTH] Celery check failed: {e}")
        response['celery'] = {
            'status': 'unknown',
            'message': f'Error: {str(e)}',
            'active_workers': 0,
            'active_tasks': 0
        }
    
    # DISK SPACE - Get usage statistics
    try:
        disk_usage = shutil.disk_usage('/opt/casescope')
        free_gb = disk_usage.free / (1024**3)
        total_gb = disk_usage.total / (1024**3)
        used_gb = disk_usage.used / (1024**3)
        percent_used = (disk_usage.used / disk_usage.total * 100) if disk_usage.total > 0 else 0
        
        if percent_used > 90:
            status = 'critical'
        elif percent_used > 80:
            status = 'warning'
        else:
            status = 'healthy'
        
        response['disk'] = {
            'status': status,
            'message': f'{round(free_gb, 1)} GB free ({round(100 - percent_used, 1)}% available)',
            'free_gb': round(free_gb, 1),
            'used_gb': round(used_gb, 1),
            'total_gb': round(total_gb, 1),
            'percent_used': round(percent_used, 1)
        }
    except Exception as e:
        logger.error(f"[HEALTH] Disk check failed: {e}")
        response['disk'] = {
            'status': 'unknown',
            'message': f'Error: {str(e)}',
            'free_gb': 0,
            'percent_used': 0
        }
    
    return jsonify(response)


# ============================================================================
# DASHBOARD
# ============================================================================

@app.route('/')
@login_required
def dashboard():
    """Enhanced System Dashboard with comprehensive stats"""
    from system_stats import get_system_status, get_case_files_space, get_software_versions, get_sigma_rules_info
    
    # System Status
    system_status = get_system_status()
    case_files_space_gb = get_case_files_space()
    
    # CaseScope Status
    # v1.16.0+: Count all cases regardless of status
    total_cases = db.session.query(Case).count()
    # v1.18.0+: Count archived cases separately
    archived_cases = db.session.query(Case).filter_by(status='Archived').count()
    total_files = db.session.query(CaseFile).filter_by(is_deleted=False, is_hidden=False).count()
    sigma_info = get_sigma_rules_info()
    total_iocs = db.session.query(IOC).count()
    
    # Events Status
    total_events = int(db.session.query(CaseFile).filter_by(is_deleted=False, is_hidden=False).with_entities(
        db.func.sum(CaseFile.event_count)
    ).scalar() or 0)
    total_sigma_violations = db.session.query(SigmaViolation).count()
    total_ioc_events = int(db.session.query(CaseFile).filter_by(is_deleted=False, is_hidden=False).with_entities(
        db.func.sum(CaseFile.ioc_event_count)
    ).scalar() or 0)
    
    # Software Status
    software_versions = get_software_versions()
    
    # Recent Cases (last 10)
    recent_cases = db.session.query(Case).order_by(Case.created_at.desc()).limit(10).all()
    
    # Recent Files (last 10)
    recent_files = db.session.query(CaseFile).filter_by(
        is_deleted=False,
        is_hidden=False
    ).order_by(CaseFile.uploaded_at.desc()).limit(10).all()
    
    return render_template('dashboard_enhanced.html',
        system_status=system_status,
        case_files_space_gb=case_files_space_gb,
        total_cases=total_cases,
        archived_cases=archived_cases,
        total_files=total_files,
        sigma_info=sigma_info,
        total_iocs=total_iocs,
        total_events=total_events,
        total_sigma_violations=total_sigma_violations,
        total_ioc_events=total_ioc_events,
        software_versions=software_versions,
        recent_cases=recent_cases,
        recent_files=recent_files
    )


# OLD INLINE TEMPLATE - KEEPING FOR REFERENCE, CAN BE DELETED
def _old_dashboard_template():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CaseScope 2026 - Dashboard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: Arial; background: #1a1a1a; color: #fff; }
            .header { background: #2a2a2a; padding: 20px; border-bottom: 2px solid #0066cc; display: flex; justify-content: space-between; align-items: center; }
            .header h1 { font-size: 24px; }
            .header a { color: #0066cc; text-decoration: none; margin-left: 20px; }
            .container { padding: 30px; max-width: 1400px; margin: 0 auto; }
            .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
            .stat-card { background: #2a2a2a; padding: 20px; border-radius: 8px; text-align: center; }
            .stat-card h3 { font-size: 36px; color: #0066cc; margin-bottom: 10px; }
            .stat-card p { color: #999; }
            .section { background: #2a2a2a; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .section h2 { margin-bottom: 20px; font-size: 20px; }
            table { width: 100%; border-collapse: collapse; }
            th { background: #333; padding: 12px; text-align: left; font-weight: 600; }
            td { padding: 12px; border-bottom: 1px solid #333; }
            tr:hover { background: #333; }
            .btn { background: #0066cc; color: white; padding: 8px 16px; border-radius: 5px; text-decoration: none; display: inline-block; border: none; cursor: pointer; }
            .btn:hover { background: #0052a3; }
            .btn-sm { padding: 6px 12px; font-size: 13px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 CaseScope 2026</h1>
            <div>
                <a href="{{ url_for('create_case') }}" class="btn">+ New Case</a>
                <a href="{{ url_for('logout') }}">Logout ({{ current_user.username }})</a>
            </div>
        </div>
        
        <div class="container">
            <div class="stats">
                <div class="stat-card">
                    <h3>{{ total_cases }}</h3>
                    <p>Total Cases</p>
                </div>
                <div class="stat-card">
                    <h3>{{ total_files }}</h3>
                    <p>Files Indexed</p>
                </div>
                <div class="stat-card">
                    <h3>{{ total_violations }}</h3>
                    <p>SIGMA Violations</p>
                </div>
                <div class="stat-card">
                    <h3>{{ total_ioc_matches }}</h3>
                    <p>IOC Matches</p>
                </div>
            </div>
            
            <div class="section">
                <h2>Active Cases</h2>
                {% if cases %}
                <table>
                    <thead>
                        <tr>
                            <th>Case Name</th>
                            <th>Company</th>
                            <th>Files</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for case in cases %}
                        <tr>
                            <td><strong>{{ case.name }}</strong></td>
                            <td>{{ case.company or 'N/A' }}</td>
                            <td>{{ case.files.count() }}</td>
                            <td>{{ case.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                            <td>
                                <a href="{{ url_for('view_case', case_id=case.id) }}" class="btn btn-sm">View</a>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p style="color: #999; text-align: center; padding: 40px;">No cases yet. Create your first case to get started.</p>
                {% endif %}
            </div>
        </div>
    </body>
    </html>
    ''', cases=cases, total_cases=total_cases, total_files=total_files, 
         total_violations=total_violations, total_ioc_matches=total_ioc_matches)


# ============================================================================
# QUEUE CLEANUP & HEALTH CHECK
# ============================================================================

@app.route('/queue/cleanup', methods=['POST'])
@login_required
def queue_cleanup_all():
    """System-wide queue cleanup (all cases)"""
    from queue_cleanup import cleanup_queue
    
    try:
        result = cleanup_queue(db, CaseFile, case_id=None)
        
        if result['status'] == 'success':
            flash(result['message'], 'success')
        else:
            flash(result['message'], 'error')
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Queue cleanup error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500


@app.route('/queue/health', methods=['GET'])
@login_required
def queue_health_check():
    """Get queue health status (system-wide)"""
    from queue_cleanup import get_queue_health
    
    try:
        health = get_queue_health(db, CaseFile, case_id=None)
        return jsonify(health)
    
    except Exception as e:
        logger.error(f"Queue health check error: {e}", exc_info=True)
        return jsonify({
            'health_status': 'error',
            'message': f'Error: {str(e)}'
        }), 500


# ============================================================================
# CASE MANAGEMENT
# ============================================================================

@app.route('/cases')
@login_required
def case_selection():
    """Case Selection Page - List all active cases (alphabetically sorted with search)"""
    # Get search term from query parameter
    search_term = request.args.get('search', '', type=str).strip()
    
    # Build query for all cases, ordered alphabetically by name
    # v1.16.0+: Show all cases regardless of status
    query = db.session.query(Case)
    
    # Apply search filter if provided
    if search_term:
        search_pattern = f"%{search_term}%"
        query = query.filter(
            (Case.name.ilike(search_pattern)) |
            (Case.description.ilike(search_pattern)) |
            (Case.company.ilike(search_pattern))
        )
    
    # Order alphabetically by case name
    cases = query.order_by(Case.name.asc()).all()
    
    # Get file counts and other stats for each case
    case_stats = []
    for case in cases:
        file_count = db.session.query(CaseFile).filter_by(
            case_id=case.id,
            is_deleted=False,
            is_hidden=False
        ).count()
        
        total_events = db.session.query(CaseFile).filter_by(
            case_id=case.id,
            is_deleted=False,
            is_hidden=False
        ).with_entities(db.func.sum(CaseFile.event_count)).scalar() or 0
        
        # Get assigned to user info
        assigned_user = None
        if case.assigned_to:
            assigned_user = db.session.get(User, case.assigned_to)
        
        # Get created by user info
        created_by_user = None
        if case.created_by:
            created_by_user = db.session.get(User, case.created_by)
        
        case_stats.append({
            'case': case,
            'file_count': file_count,
            'total_events': total_events,
            'assigned_user': assigned_user,
            'created_by_user': created_by_user
        })
    
    return render_template('case_selection.html', case_stats=case_stats, search_term=search_term)


@app.route('/case/create', methods=['GET', 'POST'])
@login_required
def create_case():
    """Create new case"""
    # Permission check: Read-only users cannot create cases
    if current_user.role == 'read-only':
        flash('Read-only users cannot create cases', 'error')
        return redirect(url_for('case_selection'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        company = request.form.get('company')
        
        case = Case(
            name=name,
            description=description,
            company=company,
            status='New',  # v1.16.0: Default status for new cases
            created_by=current_user.id
        )
        db.session.add(case)
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('create_case', resource_type='case', resource_id=case.id,
                  resource_name=case.name, 
                  details={'company': company, 'description': description})
        
        flash('Case created successfully', 'success')
        return redirect(url_for('view_case', case_id=case.id))
    
    return render_template('create_case.html')


@app.route('/case/<int:case_id>/status')
@login_required
def case_file_status(case_id):
    """API endpoint: Get file statuses and aggregated stats for live updates"""
    from hidden_files import get_file_stats_with_hidden
    from sqlalchemy import func
    
    files = db.session.query(CaseFile).filter_by(
        case_id=case_id, 
        is_deleted=False, 
        is_hidden=False
    ).all()
    
    # Get aggregated statistics
    stats = get_file_stats_with_hidden(db.session, case_id)
    
    return jsonify({
        'files': [{
            'id': f.id,
            'status': f.indexing_status,
            'event_count': f.event_count or 0,
            'violation_count': f.violation_count or 0,
            'ioc_event_count': f.ioc_event_count or 0
        } for f in files],
        'stats': {
            'total_events': stats['total_events'],
            'sigma_events': stats['sigma_events'],
            'ioc_events': stats['ioc_events']
        }
    })


@app.route('/case/<int:case_id>')
@login_required
def view_case(case_id):
    """Enhanced case dashboard with 3 tiles: Case Details, Case Files, Event Stats"""
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get creator username
    creator_name = 'System'
    if case.created_by:
        creator = db.session.get(User, case.created_by)
        if creator:
            creator_name = creator.full_name or creator.username
    
    # Get assigned user name
    assigned_name = 'Unassigned'
    if case.assigned_to:
        assignee = db.session.get(User, case.assigned_to)
        if assignee:
            assigned_name = assignee.full_name or assignee.username
    
    # Get only the 10 most recent files for display
    files = db.session.query(CaseFile).filter_by(case_id=case_id, is_deleted=False, is_hidden=False).order_by(CaseFile.uploaded_at.desc()).limit(10).all()
    
    # Count all active IOCs for this case
    total_iocs = db.session.query(IOC).filter_by(
        case_id=case_id,
        is_active=True
    ).count()
    
    # Count total systems for this case (visible only)
    from models import System
    total_systems = db.session.query(System).filter_by(
        case_id=case_id,
        hidden=False
    ).count()
    
    # Check DFIR-IRIS integration status
    dfir_iris_enabled = False
    iris_setting = SystemSettings.query.filter_by(setting_key='dfir_iris_enabled').first()
    if iris_setting and iris_setting.setting_value == 'true':
        dfir_iris_enabled = True
    
    return render_template('view_case_enhanced.html', case=case, files=files, total_iocs=total_iocs, total_systems=total_systems, creator_name=creator_name, assigned_name=assigned_name, dfir_iris_enabled=dfir_iris_enabled)


# ============================================================================
# AI REPORT ROUTES
# ============================================================================

@app.route('/ai/status')
@login_required
def ai_status():
    """Check Ollama and AI model status"""
    from ai_report import check_ollama_status
    from routes.settings import get_setting
    
    ai_enabled = get_setting('ai_enabled', 'false') == 'true'
    status = check_ollama_status()
    
    return jsonify({
        'ai_enabled': ai_enabled,
        'ollama_installed': status['installed'],
        'ollama_running': status['running'],
        'model_available': status['model_available'],
        'models': status.get('model_names', []),
        'error': status.get('error')
    })


@app.route('/case/<int:case_id>/ai/generate', methods=['POST'])
@login_required
def generate_ai_report(case_id):
    """Generate AI report for a case"""
    from routes.settings import get_setting
    from models import AIReport
    from tasks import generate_ai_report as generate_ai_report_task
    from ai_report import check_ollama_status
    
    # Check if AI is enabled
    ai_enabled = get_setting('ai_enabled', 'false') == 'true'
    if not ai_enabled:
        return jsonify({
            'success': False,
            'error': 'AI features are not enabled. Please enable in System Settings.'
        }), 403
    
    # Check if Ollama is running
    status = check_ollama_status()
    if not status['running'] or not status['model_available']:
        return jsonify({
            'success': False,
            'error': 'AI system not available. Please check Ollama installation and model availability.',
            'status': status
        }), 503
    
    # Check case exists
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Check for existing pending/generating report
    existing_report = AIReport.query.filter_by(
        case_id=case_id,
        status='pending'
    ).first()
    
    if not existing_report:
        existing_report = AIReport.query.filter_by(
            case_id=case_id,
            status='generating'
        ).first()
    
    if existing_report:
        return jsonify({
            'success': False,
            'error': 'A report is already being generated for this case',
            'report_id': existing_report.id,
            'status': existing_report.status
        }), 409
    
    # CRITICAL: Check if AI resources are already locked (training or another report)
    from ai_resource_lock import acquire_ai_lock
    lock_acquired, lock_message = acquire_ai_lock(
        operation_type='AI Report Generation',
        user_id=current_user.id,
        operation_details=f'Case: {case.name} (ID: {case_id})'
    )
    
    if not lock_acquired:
        return jsonify({
            'success': False,
            'error': lock_message
        }), 409  # 409 Conflict
    
    # Calculate estimated duration based on IOC and tagged event counts
    ioc_count = IOC.query.filter_by(case_id=case_id).count()
    tagged_event_count = TimelineTag.query.filter_by(case_id=case_id).count()
    
    # Smart estimation algorithm for LLaMA 3.1 8B (faster than 14B):
    # Base time: 90 seconds (1.5 min)
    # Per IOC: +2 seconds
    # Per tagged event: +0.5 second
    # Model overhead: +30 seconds for model loading
    estimated_seconds = 90 + (ioc_count * 2) + (tagged_event_count * 0.5) + 30
    # Cap between 2-15 minutes (8B is faster than 14B)
    estimated_seconds = max(120, min(estimated_seconds, 900))
    
    # Create new AIReport record
    new_report = AIReport(
        case_id=case_id,
        generated_by=current_user.id,
        status='pending',
        model_name=get_setting('ai_model_name', 'dfir-llama:latest'),
        estimated_duration_seconds=estimated_seconds
    )
    
    db.session.add(new_report)
    db.session.commit()
    
    # Queue Celery task
    try:
        generate_ai_report_task.delay(new_report.id)
        
        logger.info(f"[AI] Report generation queued for case {case_id}, report_id={new_report.id}")
        
        return jsonify({
            'success': True,
            'report_id': new_report.id,
            'status': 'pending',
            'message': 'Report generation started. This may take 3-5 minutes.'
        })
    except Exception as e:
        logger.error(f"[AI] Error queuing report generation: {e}")
        new_report.status = 'failed'
        new_report.error_message = f'Failed to queue: {str(e)}'
        db.session.commit()
        
        return jsonify({
            'success': False,
            'error': f'Failed to start report generation: {str(e)}'
        }), 500


@app.route('/ai/report/<int:report_id>/view')
@login_required
def view_ai_report(report_id):
    """View AI report in dedicated full-page viewer"""
    from models import AIReport
    
    report = db.session.get(AIReport, report_id)
    if not report:
        flash('Report not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Verify case access
    case = db.session.get(Case, report.case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Parse validation results if available
    validation_data = None
    if report.validation_results:
        try:
            import json
            validation_data = json.loads(report.validation_results)
        except:
            validation_data = None
    
    # Create a view-friendly report object with validation
    class ReportView:
        def __init__(self, report, validation):
            self.id = report.id
            self.case_id = report.case_id
            self.status = report.status
            self.title = report.report_title
            self.content = report.report_content
            self.model_name = report.model_name
            self.generation_time = report.generation_time_seconds
            self.error_message = report.error_message
            self.progress_percent = report.progress_percent or 0
            self.progress_message = report.progress_message or 'Initializing...'
            self.created_at = report.created_at
            self.user = report.generator  # AIReport uses 'generator' relationship, not 'user'
            self.validation = validation
    
    report_view = ReportView(report, validation_data)
    
    return render_template('view_ai_report.html',
                         report=report_view,
                         case=case)


@app.route('/ai/report/<int:report_id>')
@login_required
def get_ai_report(report_id):
    """Get AI report details"""
    from models import AIReport
    
    report = db.session.get(AIReport, report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # Check case access (basic check - could be enhanced)
    case = db.session.get(Case, report.case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Parse validation results if available
    validation_data = None
    if report.validation_results:
        try:
            import json
            validation_data = json.loads(report.validation_results)
        except:
            validation_data = None
    
    return jsonify({
        'id': report.id,
        'case_id': report.case_id,
        'case_name': case.name,
        'status': report.status,
        'title': report.report_title,
        'content': report.report_content,
        'model_name': report.model_name,
        'generation_time': report.generation_time_seconds,
        'estimated_duration': report.estimated_duration_seconds,
        'tokens_per_second': report.tokens_per_second,
        'total_tokens': report.total_tokens,
        'error_message': report.error_message,
        'progress_percent': report.progress_percent or 0,
        'progress_message': report.progress_message or 'Initializing...',
        'current_stage': report.current_stage or 'Initializing',
        'validation': validation_data,
        'created_at': report.created_at.isoformat() if report.created_at else None,
        'completed_at': report.completed_at.isoformat() if report.completed_at else None
    })


@app.route('/ai/report/<int:report_id>/live-preview', methods=['GET'])
@login_required
def get_ai_report_live_preview(report_id):
    """Get live preview of report being generated"""
    from models import AIReport
    
    report = db.session.get(AIReport, report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # Check case access
    case = db.session.get(Case, report.case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    return jsonify({
        'raw_response': report.raw_response or '',
        'tokens': report.total_tokens or 0,
        'tok_per_sec': report.tokens_per_second or 0,
        'status': report.status,
        'progress_message': report.progress_message
    })


@app.route('/ai/report/<int:report_id>/cancel', methods=['POST'])
@login_required
def cancel_ai_report(report_id):
    """Cancel an AI report generation (revoke Celery task and kill Ollama)"""
    from models import AIReport
    import logging
    
    logger = logging.getLogger(__name__)
    
    report = db.session.get(AIReport, report_id)
    if not report:
        return jsonify({'success': False, 'error': 'Report not found'}), 404
    
    # Check case access
    case = db.session.get(Case, report.case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Only allow cancelling if report is in progress
    if report.status not in ['pending', 'generating']:
        return jsonify({
            'success': False,
            'error': f'Cannot cancel report with status: {report.status}'
        }), 400
    
    logger.info(f"[AI REPORT] Cancelling report #{report_id} (Task ID: {report.celery_task_id})")
    
    # Revoke the Celery task if it exists
    if report.celery_task_id:
        try:
            from celery_app import celery_app
            # Revoke the task (terminate=True kills the worker process if running)
            celery_app.control.revoke(report.celery_task_id, terminate=True, signal='SIGKILL')
            logger.info(f"[AI REPORT] Revoked Celery task: {report.celery_task_id}")
        except Exception as e:
            logger.error(f"[AI REPORT] Error revoking task: {e}")
    
    # Update database
    report.status = 'cancelled'
    report.current_stage = 'Cancelled'
    report.error_message = f'Report generation cancelled by user ({current_user.username})'
    report.completed_at = datetime.utcnow()
    report.celery_task_id = None
    db.session.commit()
    
    logger.info(f"[AI REPORT] Report #{report_id} cancelled successfully")
    
    return jsonify({
        'success': True,
        'message': 'Report generation cancelled',
        'report_id': report_id
    })


@app.route('/ai/report/<int:report_id>/download')
@login_required
def download_ai_report(report_id):
    """Download AI report as markdown file"""
    from models import AIReport
    from flask import make_response
    
    report = db.session.get(AIReport, report_id)
    if not report:
        flash('Report not found', 'error')
        return redirect(url_for('dashboard'))
    
    if report.status != 'completed':
        flash('Report is not ready for download', 'error')
        return redirect(url_for('view_case', case_id=report.case_id))
    
    # Create response with markdown content
    response = make_response(report.report_content)
    response.headers['Content-Type'] = 'text/markdown; charset=utf-8'
    
    # Generate safe filename
    case = db.session.get(Case, report.case_id)
    case_name_safe = case.name.replace(' ', '_').replace('/', '_') if case else 'report'
    timestamp = report.created_at.strftime('%Y%m%d_%H%M%S') if report.created_at else 'unknown'
    
    filename = f"AI_Report_{case_name_safe}_{timestamp}.md"
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response


@app.route('/ai/report/<int:report_id>/chat', methods=['POST'])
@login_required
def ai_report_chat(report_id):
    """Send a chat message to refine the AI report (with streaming)"""
    from models import AIReport, AIReportChat, IOC, TimelineTag
    from ai_report import refine_report_with_chat
    from flask import Response, stream_with_context
    import json
    
    report = db.session.get(AIReport, report_id)
    if not report or report.status != 'completed':
        return jsonify({'error': 'Report not found or not completed'}), 404
    
    # Check case access
    case = db.session.get(Case, report.case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Get user message from request
    data = request.get_json()
    user_message = data.get('message', '').strip()
    if not user_message:
        return jsonify({'error': 'Message is required'}), 400
    
    # Save user message to database
    user_chat = AIReportChat(
        report_id=report.id,
        user_id=current_user.id,
        role='user',
        message=user_message
    )
    db.session.add(user_chat)
    db.session.commit()
    
    # Get chat history for context
    previous_chats = AIReportChat.query.filter_by(report_id=report.id).order_by(AIReportChat.created_at.asc()).all()
    chat_history = [{'role': msg.role, 'message': msg.message} for msg in previous_chats]
    
    # Get case data (IOCs and tagged events)
    iocs = IOC.query.filter_by(case_id=case.id).all()
    
    # Get tagged events
    tagged_event_ids = [tag.event_id for tag in TimelineTag.query.filter_by(case_id=case.id).all()]
    tagged_events = []
    if tagged_event_ids:
        case_index = f"case_{case.id}"  # v1.13.1: consolidated index
        try:
            result = es.search(
                index=case_index,
                body={
                    "query": {
                        "ids": {"values": tagged_event_ids}
                    },
                    "size": 200
                }
            )
            tagged_events = result.get('hits', {}).get('hits', [])
        except Exception as e:
            logger.warning(f"Could not fetch tagged events: {e}")
    
    # Stream AI response
    def generate():
        full_response = ""
        try:
            for chunk in refine_report_with_chat(
                user_message, 
                report.report_content, 
                case, 
                iocs, 
                tagged_events, 
                chat_history,
                model=report.model_name
            ):
                full_response += chunk
                # Send chunk to frontend
                yield f"data: {json.dumps({'chunk': chunk})}\n\n"
            
            # Save AI response to database
            ai_chat = AIReportChat(
                report_id=report.id,
                user_id=current_user.id,
                role='assistant',
                message=full_response
            )
            db.session.add(ai_chat)
            db.session.commit()
            
            # Send completion signal with message ID
            yield f"data: {json.dumps({'done': True, 'message_id': ai_chat.id})}\n\n"
            
        except Exception as e:
            logger.error(f"[AI Chat] Error during chat: {str(e)}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')


@app.route('/ai/report/<int:report_id>/chat', methods=['GET'])
@login_required
def get_ai_report_chat_history(report_id):
    """Get chat history for an AI report"""
    from models import AIReport, AIReportChat
    
    report = db.session.get(AIReport, report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # Check case access
    case = db.session.get(Case, report.case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Get all chat messages
    chats = AIReportChat.query.filter_by(report_id=report.id).order_by(AIReportChat.created_at.asc()).all()
    
    return jsonify({
        'messages': [{
            'id': msg.id,
            'role': msg.role,
            'message': msg.message,
            'applied': msg.applied,
            'created_at': msg.created_at.isoformat() if msg.created_at else None
        } for msg in chats]
    })


@app.route('/ai/report/<int:report_id>/review', methods=['GET'])
@login_required
def get_ai_report_review(report_id):
    """Get prompt and response for AI report review/debugging"""
    from models import AIReport
    
    report = db.session.get(AIReport, report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # Check case access
    case = db.session.get(Case, report.case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    return jsonify({
        'prompt_sent': report.prompt_sent or 'No prompt stored (generated before v1.10.44)',
        'raw_response': report.raw_response or 'No raw response stored (generated before v1.10.44)',
        'prompt_length': len(report.prompt_sent) if report.prompt_sent else 0,
        'response_length': len(report.raw_response) if report.raw_response else 0,
        'model_name': report.model_name,
        'total_tokens': report.total_tokens,
        'created_at': report.created_at.isoformat() if report.created_at else None
    })


@app.route('/ai/report/<int:report_id>/apply', methods=['POST'])
@login_required
def apply_ai_chat_refinement(report_id):
    """Apply AI-suggested refinements to the report"""
    from models import AIReport, AIReportChat
    
    report = db.session.get(AIReport, report_id)
    if not report or report.status != 'completed':
        return jsonify({'error': 'Report not found or not completed'}), 404
    
    # Check case access and permissions
    case = db.session.get(Case, report.case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Get the chat message to apply
    data = request.get_json()
    message_id = data.get('message_id')
    new_content = data.get('content', '').strip()
    
    if not message_id or not new_content:
        return jsonify({'error': 'Message ID and content are required'}), 400
    
    # Get the chat message
    chat_msg = db.session.get(AIReportChat, message_id)
    if not chat_msg or chat_msg.report_id != report.id:
        return jsonify({'error': 'Chat message not found'}), 404
    
    # Update the report content with the new refinement
    # Note: Frontend will handle inserting the content at the right place
    # We just mark this message as "applied"
    chat_msg.applied = True
    report.report_content = new_content  # Replace with refined content
    db.session.commit()
    
    logger.info(f"[AI Chat] Applied refinement to Report ID {report.id} from Chat ID {chat_msg.id}")
    
    return jsonify({
        'success': True,
        'message': 'Refinement applied to report'
    })


@app.route('/ai/report/<int:report_id>', methods=['DELETE'])
@login_required
def delete_ai_report(report_id):
    """Delete an AI report (admin only)"""
    from models import AIReport, AIReportChat
    
    # Check if user is administrator
    if current_user.role != 'administrator':
        return jsonify({'error': 'Unauthorized - Administrator access required'}), 403
    
    report = db.session.get(AIReport, report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # Store case_id for response
    case_id = report.case_id
    
    # Delete associated chat messages first (cascade should handle this, but be explicit)
    AIReportChat.query.filter_by(report_id=report_id).delete()
    
    # Delete the report
    db.session.delete(report)
    db.session.commit()
    
    logger.info(f"[ADMIN] User {current_user.username} deleted AI Report #{report_id} from Case {case_id}")
    
    return jsonify({
        'success': True,
        'message': f'Report #{report_id} deleted successfully',
        'case_id': case_id
    })


@app.route('/case/<int:case_id>/ai/reports')
@login_required
def list_ai_reports(case_id):
    """List all AI reports for a case"""
    from models import AIReport
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    reports = AIReport.query.filter_by(case_id=case_id).order_by(AIReport.created_at.desc()).all()
    
    return jsonify({
        'reports': [{
            'id': r.id,
            'status': r.status,
            'title': r.report_title,
            'model_name': r.model_name,
            'generation_time': r.generation_time_seconds,
            'created_at': r.created_at.isoformat() if r.created_at else None,
            'completed_at': r.completed_at.isoformat() if r.completed_at else None,
            'error_message': r.error_message
        } for r in reports]
    })


@app.route('/evtx_descriptions')
@login_required
def evtx_descriptions():
    """EVTX Event Descriptions Management"""
    from models import EventDescription
    from sqlalchemy import or_
    
    # Get search query and source filter
    search_query = request.args.get('q', '').strip()
    source_filter = request.args.get('source', '').strip()
    
    # Get statistics (for all events, not filtered by search or source)
    total_events = db.session.query(EventDescription).count()
    
    # Get counts by source (domain-based grouping)
    source_stats = {}
    
    # Count Ultimate Windows Security events
    uws_count = db.session.query(EventDescription).filter(
        EventDescription.source_url.like('%ultimatewindowssecurity%')
    ).count()
    if uws_count > 0:
        source_stats['Ultimate Windows Security'] = uws_count
    
    # Count GitHub Gist events
    github_count = db.session.query(EventDescription).filter(
        EventDescription.source_url.like('%github%')
    ).count()
    if github_count > 0:
        source_stats['GitHub Gist'] = github_count
    
    # Count Infrasos events
    infrasos_count = db.session.query(EventDescription).filter(
        EventDescription.source_url.like('%infrasos%')
    ).count()
    if infrasos_count > 0:
        source_stats['Infrasos'] = infrasos_count
    
    # Count MyEventLog.com events
    myeventlog_count = db.session.query(EventDescription).filter(
        EventDescription.source_url.like('%myeventlog%')
    ).count()
    if myeventlog_count > 0:
        source_stats['MyEventLog.com'] = myeventlog_count
    
    # Count Microsoft Sysmon events
    ms_sysmon_count = db.session.query(EventDescription).filter(
        EventDescription.source_url.like('%learn.microsoft.com/en-us/sysinternals%')
    ).count()
    if ms_sysmon_count > 0:
        source_stats['Microsoft Sysmon'] = ms_sysmon_count
    
    # Count Microsoft Security Auditing events
    ms_security_count = db.session.query(EventDescription).filter(
        EventDescription.source_url.like('%learn.microsoft.com/en-us/previous-versions%')
    ).count()
    if ms_security_count > 0:
        source_stats['Microsoft Security Auditing'] = ms_security_count
    
    # Get last updated
    last_updated = db.session.query(
        db.func.max(EventDescription.last_updated)
    ).scalar()
    
    # Count custom events (v1.13.7)
    custom_count = db.session.query(EventDescription).filter(
        EventDescription.is_custom == True
    ).count()
    if custom_count > 0:
        source_stats['Custom Events'] = custom_count
    
    # Build query with source filter and search filter
    events_query = db.session.query(EventDescription)
    
    # Apply source filter first
    if source_filter:
        if source_filter == 'uws':
            events_query = events_query.filter(EventDescription.source_url.like('%ultimatewindowssecurity%'))
        elif source_filter == 'github':
            events_query = events_query.filter(EventDescription.source_url.like('%github%'))
        elif source_filter == 'infrasos':
            events_query = events_query.filter(EventDescription.source_url.like('%infrasos%'))
        elif source_filter == 'myeventlog':
            events_query = events_query.filter(EventDescription.source_url.like('%myeventlog%'))
        elif source_filter == 'ms_sysmon':
            events_query = events_query.filter(EventDescription.source_url.like('%learn.microsoft.com/en-us/sysinternals%'))
        elif source_filter == 'ms_security':
            events_query = events_query.filter(EventDescription.source_url.like('%learn.microsoft.com/en-us/previous-versions%'))
        elif source_filter == 'custom':
            events_query = events_query.filter(EventDescription.is_custom == True)
    
    # Apply search filter
    if search_query:
        # Search by event_id (exact or partial) OR title (contains)
        if search_query.isdigit():
            # If search is numeric, prioritize event_id exact match
            events_query = events_query.filter(
                or_(
                    EventDescription.event_id == int(search_query),
                    EventDescription.title.ilike(f'%{search_query}%'),
                    EventDescription.description.ilike(f'%{search_query}%')
                )
            )
        else:
            # Text search in title and description
            events_query = events_query.filter(
                or_(
                    EventDescription.title.ilike(f'%{search_query}%'),
                    EventDescription.description.ilike(f'%{search_query}%')
                )
            )
    
    events_query = events_query.order_by(EventDescription.event_id.asc())
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Show 50 events per page
    pagination = events_query.paginate(page=page, per_page=per_page, error_out=False)
    events = pagination.items
    
    return render_template(
        'evtx_descriptions.html',
        total_events=total_events,
        source_stats=source_stats,
        last_updated=last_updated,
        events=events,
        pagination=pagination,
        search_query=search_query,
        source_filter=source_filter
    )


@app.route('/evtx_descriptions/update', methods=['POST'])
@login_required
def evtx_descriptions_update():
    """Update EVTX descriptions from all sources"""
    from models import EventDescription
    from evtx_descriptions import update_all_descriptions
    
    # Admin check
    if current_user.role != 'administrator':
        flash('Only administrators can update EVTX descriptions', 'error')
        return redirect(url_for('evtx_descriptions'))
    
    try:
        stats = update_all_descriptions(db, EventDescription)
        
        # Audit log success
        from audit_logger import log_action
        log_action('update_evtx_definitions', resource_type='evtx', 
                  resource_name='EVTX Event Descriptions',
                  details={'stats': stats})
        
        flash(f"Successfully updated EVTX descriptions: {stats['total_processed']} processed, "
              f"{stats['new_events']} new, {stats['updated_events']} updated", 'success')
        
        for source, count in stats['sources'].items():
            flash(f"{source}: {count} events", 'info')
            
    except Exception as e:
        # Audit log failure
        from audit_logger import log_action
        log_action('update_evtx_definitions', resource_type='evtx',
                  resource_name='EVTX Event Descriptions',
                  details={'error': str(e)}, status='failed')
        
        flash(f'Error updating descriptions: {str(e)}', 'error')
        logger.error(f"[EVTX UPDATE] Error: {e}", exc_info=True)
    
    return redirect(url_for('evtx_descriptions'))


# ============================================================================
# CUSTOM EVENT CRUD ROUTES (v1.13.7)
# ============================================================================

@app.route('/evtx_descriptions/custom', methods=['POST'])
@login_required
def create_custom_event():
    """Create a new custom event description"""
    from models import EventDescription
    from audit_logger import log_action
    
    try:
        data = request.json
        event_id = data.get('event_id')
        title = data.get('title')
        description = data.get('description')
        category = data.get('category')
        
        # Validation
        if not event_id or not title:
            return jsonify({'success': False, 'error': 'Event ID and Title are required'}), 400
        
        # Check if event ID already exists as custom event
        existing = db.session.query(EventDescription).filter_by(
            event_id=event_id,
            is_custom=True
        ).first()
        
        if existing:
            return jsonify({'success': False, 'error': f'Custom Event ID {event_id} already exists'}), 400
        
        # Create new custom event
        custom_event = EventDescription(
            event_id=event_id,
            event_source='Custom',
            title=title,
            description=description,
            category=category,
            is_custom=True,
            created_by=current_user.id
        )
        
        db.session.add(custom_event)
        db.session.commit()
        
        # Audit log
        log_action('create_custom_event', resource_type='event_description',
                  resource_id=custom_event.id, resource_name=f'Event {event_id}',
                  details={'event_id': event_id, 'title': title})
        
        logger.info(f"[CUSTOM EVENT] Created Event {event_id}: {title} by user {current_user.username}")
        
        return jsonify({'success': True, 'id': custom_event.id})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"[CUSTOM EVENT] Error creating event: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/evtx_descriptions/custom/<int:event_desc_id>', methods=['PUT'])
@login_required
def update_custom_event(event_desc_id):
    """Update an existing custom event description"""
    from models import EventDescription
    from audit_logger import log_action
    
    try:
        custom_event = db.session.get(EventDescription, event_desc_id)
        
        if not custom_event:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
        
        # Only allow editing custom events
        if not custom_event.is_custom:
            return jsonify({'success': False, 'error': 'Cannot edit scraped events, only custom events'}), 403
        
        # Only allow owner or admin to edit
        if custom_event.created_by != current_user.id and current_user.role != 'administrator':
            return jsonify({'success': False, 'error': 'You can only edit your own custom events'}), 403
        
        data = request.json
        
        # Update fields (event_id cannot be changed once created)
        if 'title' in data:
            custom_event.title = data['title']
        if 'description' in data:
            custom_event.description = data['description']
        if 'category' in data:
            custom_event.category = data['category']
        
        db.session.commit()
        
        # Audit log
        log_action('update_custom_event', resource_type='event_description',
                  resource_id=custom_event.id, resource_name=f'Event {custom_event.event_id}',
                  details={'event_id': custom_event.event_id, 'title': custom_event.title})
        
        logger.info(f"[CUSTOM EVENT] Updated Event {custom_event.event_id}: {custom_event.title} by user {current_user.username}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"[CUSTOM EVENT] Error updating event: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/evtx_descriptions/custom/<int:event_desc_id>', methods=['DELETE'])
@login_required
def delete_custom_event(event_desc_id):
    """Delete a custom event description"""
    from models import EventDescription
    from audit_logger import log_action
    
    try:
        custom_event = db.session.get(EventDescription, event_desc_id)
        
        if not custom_event:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
        
        # Only allow deleting custom events
        if not custom_event.is_custom:
            return jsonify({'success': False, 'error': 'Cannot delete scraped events, only custom events'}), 403
        
        # Only allow owner or admin to delete
        if custom_event.created_by != current_user.id and current_user.role != 'administrator':
            return jsonify({'success': False, 'error': 'You can only delete your own custom events'}), 403
        
        event_id = custom_event.event_id
        title = custom_event.title
        
        db.session.delete(custom_event)
        db.session.commit()
        
        # Audit log
        log_action('delete_custom_event', resource_type='event_description',
                  resource_id=event_desc_id, resource_name=f'Event {event_id}',
                  details={'event_id': event_id, 'title': title})
        
        logger.info(f"[CUSTOM EVENT] Deleted Event {event_id}: {title} by user {current_user.username}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"[CUSTOM EVENT] Error deleting event: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# EVENT DESCRIPTION REFRESH ROUTES (v1.13.7)
# ============================================================================

@app.route('/case/<int:case_id>/refresh_descriptions', methods=['POST'])
@login_required
def refresh_descriptions_case_route(case_id):
    """Refresh event descriptions for a case (reusable from multiple pages)"""
    from tasks import refresh_descriptions_case
    from celery_health import check_workers_available
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Safety check: Ensure Celery workers are available
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Cannot start operation: {error_msg}. Please check Celery workers.', 'error')
        return _redirect_refresh_descriptions(case_id)
    
    # Queue refresh task
    refresh_descriptions_case.delay(case_id)
    
    flash(f'✅ Event description refresh queued for case "{case.name}" ({worker_count} worker(s) available)', 'success')
    return _redirect_refresh_descriptions(case_id)


@app.route('/refresh_descriptions_global', methods=['POST'])
@login_required
def refresh_descriptions_global_route():
    """Refresh event descriptions for ALL cases (reusable from multiple pages)"""
    from tasks import refresh_descriptions_global
    from celery_health import check_workers_available
    
    # Safety check: Ensure Celery workers are available
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Cannot start global operation: {error_msg}. Please check Celery workers.', 'error')
        return _redirect_refresh_descriptions_global()
    
    # Get case count for user feedback
    case_count = db.session.query(Case).count()
    
    if case_count == 0:
        flash('No cases found to refresh', 'warning')
        return _redirect_refresh_descriptions_global()
    
    # Queue global refresh task
    refresh_descriptions_global.delay()
    
    flash(f'✅ Global event description refresh queued for {case_count} case(s) ({worker_count} worker(s) available)', 'success')
    return _redirect_refresh_descriptions_global()


def _redirect_refresh_descriptions(case_id):
    """Helper to redirect back to originating page after case refresh"""
    redirect_to = request.args.get('redirect_to', request.form.get('redirect_to'))
    if not redirect_to:
        # Check referer to determine where user came from
        referer = request.referrer or ''
        if '/files' in referer:
            redirect_to = 'case_files'
        elif '/evtx' in referer:
            redirect_to = 'evtx_descriptions'
        else:
            redirect_to = 'case_dashboard'
    
    if redirect_to == 'case_files':
        return redirect(url_for('files.case_files', case_id=case_id))
    elif redirect_to == 'evtx_descriptions':
        return redirect(url_for('evtx_descriptions'))
    else:
        return redirect(url_for('view_case', case_id=case_id))


def _redirect_refresh_descriptions_global():
    """Helper to redirect back to originating page after global refresh"""
    redirect_to = request.args.get('redirect_to', request.form.get('redirect_to'))
    if not redirect_to:
        # Check referer to determine where user came from
        referer = request.referrer or ''
        if '/files/global' in referer:
            redirect_to = 'global_files'
        elif '/evtx' in referer:
            redirect_to = 'evtx_descriptions'
        else:
            redirect_to = 'dashboard'
    
    if redirect_to == 'global_files':
        return redirect(url_for('files.global_files'))
    elif redirect_to == 'evtx_descriptions':
        return redirect(url_for('evtx_descriptions'))
    else:
        return redirect(url_for('dashboard'))


@app.route('/case/<int:case_id>/search')
@login_required
def search_events(case_id):
    """Advanced Event Search Page"""
    from models import SearchHistory, TimelineTag
    from search_utils import build_search_query, execute_search, extract_event_fields
    from utils import make_index_name
    from routes.settings import get_setting
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get search parameters
    search_text = request.args.get('q', '')
    filter_type = request.args.get('filter', 'all')  # all, sigma, ioc, sigma_and_ioc, tagged
    date_range = request.args.get('date_range', 'all')
    file_types = request.args.getlist('file_types')  # ['EVTX', 'EDR', 'JSON', 'CSV', 'IIS']
    if not file_types:  # Default: all types checked
        file_types = ['EVTX', 'EDR', 'JSON', 'CSV', 'IIS']
    hidden_filter = request.args.get('hidden_filter', 'hide')  # 'hide', 'show', 'only'
    sort_field = request.args.get('sort', 'normalized_timestamp')  # Use normalized field
    sort_order = request.args.get('order', 'desc')
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 1000)  # Max 1000 per page
    
    # Get custom date range if provided
    custom_date_start = None
    custom_date_end = None
    custom_date_start_str = ''
    custom_date_end_str = ''
    
    if date_range == 'custom':
        custom_date_start_str = request.args.get('custom_date_start', '')
        custom_date_end_str = request.args.get('custom_date_end', '')
        
        if custom_date_start_str:
            try:
                custom_date_start = datetime.fromisoformat(custom_date_start_str)
            except:
                pass
        
        if custom_date_end_str:
            try:
                custom_date_end = datetime.fromisoformat(custom_date_end_str)
            except:
                pass
    
    # If filtering by tagged events, get the list of tagged event IDs for this case
    tagged_event_ids = None
    if filter_type == 'tagged':
        from models import TimelineTag
        tagged_events = TimelineTag.query.filter_by(case_id=case_id).all()
        tagged_event_ids = [tag.event_id for tag in tagged_events]
        logger.debug(f"[SEARCH] Found {len(tagged_event_ids)} tagged events for case {case_id}")
    
    # Get column configuration from session or use defaults
    columns = session.get(f'search_columns_{case_id}', [
        'event_id', 'timestamp', 'description', 'computer_name', 'source_file'
    ])
    
    # Build index name for case (1 index per case in v1.13.1+)
    index_pattern = f"case_{case_id}"
    
    # Get latest event timestamp for relative date filters (24h, 7d, 30d)
    latest_event_timestamp = None
    if date_range in ['24h', '7d', '30d']:
        try:
            # Query OpenSearch for the latest timestamp
            latest_query = {
                "size": 1,
                "sort": [{"normalized_timestamp": {"order": "desc"}}],
                "_source": ["normalized_timestamp"]
            }
            latest_result = opensearch_client.search(index=index_pattern, body=latest_query)
            if latest_result['hits']['hits']:
                timestamp_str = latest_result['hits']['hits'][0]['_source'].get('normalized_timestamp')
                if timestamp_str:
                    latest_event_timestamp = datetime.fromisoformat(timestamp_str)
                    logger.info(f"[SEARCH] Latest event timestamp for case {case_id}: {latest_event_timestamp}")
        except Exception as e:
            logger.warning(f"[SEARCH] Could not get latest timestamp for case {case_id}: {e}")
            # Fall back to current time if query fails
            latest_event_timestamp = datetime.utcnow()
    
    # Build query (if no search text AND showing all events, match all)
    if not search_text and filter_type == 'all' and date_range == 'all' and len(file_types) == 5 and hidden_filter == 'show':
        # Simple match_all for performance (only if all 5 file types selected AND showing all events including hidden) v1.14.0: Changed 4→5 (added IIS)
        query_dsl = {"query": {"match_all": {}}}
    else:
        # Build proper query with hidden filter applied
        query_dsl = build_search_query(
            search_text=search_text,
            filter_type=filter_type,
            date_range=date_range,
            file_types=file_types,
            tagged_event_ids=tagged_event_ids,
            custom_date_start=custom_date_start,
            custom_date_end=custom_date_end,
            latest_event_timestamp=latest_event_timestamp,
            hidden_filter=hidden_filter
        )
    
    # Execute search
    try:
        results, total_count, aggregations = execute_search(
            opensearch_client,
            index_pattern,
            query_dsl,
            page=page,
            per_page=per_page,
            sort_field=sort_field,
            sort_order=sort_order
        )
    except Exception as e:
        logger.error(f"[SEARCH] Search failed: {e}")
        flash(f'Search error: {str(e)}', 'error')
        results, total_count, aggregations = [], 0, {}
    
    # Extract normalized fields and enrich with IOC types
    events = []
    event_ids_to_check = []
    event_id_map = {}  # Map OpenSearch _id to event dict
    
    for result in results:
        fields = extract_event_fields(result['_source'])
        fields['_id'] = result['_id']
        fields['_index'] = result['_index']
        fields['_source'] = result['_source']  # Store raw source for custom column access
        fields['ioc_types'] = []  # Will be populated if IOCs match
        fields['is_hidden'] = result['_source'].get('is_hidden', False)  # Include hidden status
        events.append(fields)
        
        if fields.get('has_ioc'):
            event_ids_to_check.append(result['_id'])
            event_id_map[result['_id']] = fields
    
    # Batch lookup IOC types for events with matches
    if event_ids_to_check:
        # Query IOCMatch with IOC to get types
        ioc_matches = db.session.query(
            IOCMatch.event_id,
            IOC.ioc_type
        ).join(
            IOC, IOCMatch.ioc_id == IOC.id
        ).filter(
            IOCMatch.event_id.in_(event_ids_to_check)
        ).all()
        
        # Group IOC types by event_id
        from collections import defaultdict
        event_ioc_types = defaultdict(set)
        for event_id, ioc_type in ioc_matches:
            event_ioc_types[event_id].add(ioc_type)
        
        # Map IOC types back to events (as sorted lists)
        for event_id, ioc_types in event_ioc_types.items():
            if event_id in event_id_map:
                event_id_map[event_id]['ioc_types'] = sorted(ioc_types)
    
    # Calculate pagination
    total_pages = (total_count + per_page - 1) // per_page
    
    # Get tagged event IDs for this case
    tagged_ids = {tag.event_id for tag in db.session.query(TimelineTag).filter_by(case_id=case_id).all()}
    
    # Get recent searches for this user and case
    recent_searches_raw = db.session.query(SearchHistory).filter_by(
        user_id=current_user.id,
        case_id=case_id
    ).order_by(SearchHistory.last_used.desc()).limit(10).all()
    
    # Parse JSON for template
    import json
    recent_searches = []
    for search in recent_searches_raw:
        try:
            search_data = json.loads(search.search_query)
            recent_searches.append({
                'id': search.id,
                'search_text': search_data.get('search_text', ''),
                'filter_type': search.filter_type,
                'date_range': search.date_range
            })
        except:
            pass
    
    # Get favorite searches
    favorite_searches_raw = db.session.query(SearchHistory).filter_by(
        user_id=current_user.id,
        case_id=case_id,
        is_favorite=True
    ).order_by(SearchHistory.search_name.asc()).all()
    
    favorite_searches = []
    for search in favorite_searches_raw:
        try:
            search_data = json.loads(search.search_query)
            favorite_searches.append({
                'id': search.id,
                'search_name': search.search_name or 'Unnamed Search',
                'search_text': search_data.get('search_text', ''),
                'filter_type': search.filter_type,
                'date_range': search.date_range
            })
        except:
            pass
    
    # Save to history if results returned
    if total_count > 0:
        from search_utils import save_search_to_history
        save_search_to_history(
            db, SearchHistory, current_user.id, case_id,
            {
                'search_text': search_text,
                'filter_type': filter_type,
                'date_range': date_range,
                'sort_field': sort_field,
                'sort_order': sort_order,
                'column_config': columns
            },
            total_count
        )
    
    # Check if DFIR-IRIS is enabled
    dfir_iris_enabled = get_setting('dfir_iris_enabled', 'false') == 'true'
    
    return render_template(
        'search_events.html',
        case=case,
        events=events,
        search_text=search_text,
        filter_type=filter_type,
        date_range=date_range,
        file_types=file_types,
        hidden_filter=hidden_filter,
        sort_field=sort_field,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
        total_count=total_count,
        total_pages=total_pages,
        columns=columns,
        tagged_ids=tagged_ids,
        recent_searches=recent_searches,
        favorite_searches=favorite_searches,
        custom_date_start=custom_date_start_str,
        custom_date_end=custom_date_end_str,
        dfir_iris_enabled=dfir_iris_enabled
    )


@app.route('/case/<int:case_id>/search/export')
@login_required
def export_search_results(case_id):
    """Export current search results as CSV (unlimited results via Scroll API)"""
    from models import TimelineTag
    from search_utils import build_search_query, execute_search_scroll, extract_event_fields
    from export_utils import generate_events_csv
    from flask import make_response
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get same search parameters as search_events
    search_text = request.args.get('q', '')
    filter_type = request.args.get('filter', 'all')
    date_range = request.args.get('date_range', 'all')
    file_types = request.args.getlist('file_types')
    if not file_types:
        file_types = ['EVTX', 'EDR', 'JSON', 'CSV', 'IIS']
    sort_field = request.args.get('sort', 'normalized_timestamp')
    sort_order = request.args.get('order', 'desc')
    
    # Get custom date range if provided
    custom_date_start = None
    custom_date_end = None
    if date_range == 'custom':
        custom_date_start_str = request.args.get('custom_date_start', '')
        custom_date_end_str = request.args.get('custom_date_end', '')
        
        if custom_date_start_str:
            try:
                custom_date_start = datetime.fromisoformat(custom_date_start_str)
            except:
                pass
        
        if custom_date_end_str:
            try:
                custom_date_end = datetime.fromisoformat(custom_date_end_str)
            except:
                pass
    
    # Get tagged event IDs if filtering by tagged
    tagged_event_ids = None
    if filter_type == 'tagged':
        tagged_events = TimelineTag.query.filter_by(case_id=case_id).all()
        tagged_event_ids = [tag.event_id for tag in tagged_events]
    
    # Build index name for case (1 index per case in v1.13.1+)
    index_pattern = f"case_{case_id}"
    
    # Get latest event timestamp for relative date filters (24h, 7d, 30d)
    latest_event_timestamp = None
    if date_range in ['24h', '7d', '30d']:
        try:
            latest_query = {
                "size": 1,
                "sort": [{"normalized_timestamp": {"order": "desc"}}],
                "_source": ["normalized_timestamp"]
            }
            latest_result = opensearch_client.search(index=index_pattern, body=latest_query)
            if latest_result['hits']['hits']:
                timestamp_str = latest_result['hits']['hits'][0]['_source'].get('normalized_timestamp')
                if timestamp_str:
                    latest_event_timestamp = datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.warning(f"[EXPORT] Could not get latest timestamp: {e}")
            latest_event_timestamp = datetime.utcnow()
    
    # Build query (reuse same logic)
    if not search_text and filter_type == 'all' and date_range == 'all' and len(file_types) == 5:
        query_dsl = {"query": {"match_all": {}}}  # v1.14.0: Changed 4→5 (added IIS)
    else:
        query_dsl = build_search_query(
            search_text=search_text,
            filter_type=filter_type,
            date_range=date_range,
            file_types=file_types,
            tagged_event_ids=tagged_event_ids,
            custom_date_start=custom_date_start,
            custom_date_end=custom_date_end,
            latest_event_timestamp=latest_event_timestamp
        )
    
    # Execute search - export ALL results using Scroll API (unlimited)
    try:
        logger.info(f"[EXPORT] Starting unlimited CSV export for case {case_id}")
        results, total_count = execute_search_scroll(
            opensearch_client,
            index_pattern,
            query_dsl,
            batch_size=2000,  # 2000 events per scroll batch (balanced for performance)
            sort_field=sort_field,
            sort_order=sort_order
        )
        logger.info(f"[EXPORT] Successfully retrieved {len(results)} events (total count: {total_count})")
    except Exception as e:
        logger.error(f"[EXPORT] Scroll export failed: {e}")
        flash(f'Export error: {str(e)}', 'error')
        return redirect(url_for('search_events', case_id=case_id))
    
    # Pass FULL _source data to CSV (not just extracted fields)
    # This ensures EventData (TargetUserName, ShareName, etc.) is included
    full_events = []
    for result in results:
        event_data = result['_source'].copy()
        # Add metadata
        event_data['_id'] = result.get('_id')
        event_data['_index'] = result.get('_index')
        full_events.append(event_data)
    
    # Generate CSV with full event data
    csv_content = generate_events_csv(full_events)
    
    # Create response with CSV
    response = make_response(csv_content)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=case_{case_id}_events_export_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response


@app.route('/case/<int:case_id>/search/event/<event_id>')
@login_required
def get_event_detail_route(case_id, event_id):
    """Get event detail (AJAX) with IOC list for highlighting"""
    from search_utils import get_event_detail, format_event_for_display
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Get index name from query parameter
    index_name = request.args.get('index')
    if not index_name:
        return jsonify({'error': 'Index name required'}), 400
    
    # Retrieve event
    event = get_event_detail(opensearch_client, index_name, event_id)
    if not event:
        return jsonify({'error': 'Event not found'}), 404
    
    # Format for display
    fields = format_event_for_display(event['_source'])
    
    # Get active IOCs for this case (for highlighting)
    iocs = db.session.query(IOC).filter_by(
        case_id=case_id,
        is_active=True
    ).all()
    
    ioc_values = [ioc.ioc_value.lower() for ioc in iocs]  # Lowercase for case-insensitive matching
    
    # Get SIGMA rule if present in event
    sigma_rule = event['_source'].get('sigma_rule', None)
    has_sigma = event['_source'].get('has_sigma', False)
    
    return jsonify({
        'event_id': event_id,
        'index': index_name,
        'fields': fields,
        'iocs': ioc_values,  # Include IOCs for client-side highlighting
        'has_sigma': has_sigma,
        'sigma_rule': sigma_rule  # Include SIGMA rule for purple highlighting
    })


@app.route('/case/<int:case_id>/search/tag', methods=['POST'])
@login_required
def tag_timeline_event(case_id):
    """Tag event for timeline"""
    # Permission check: Read-only users cannot tag events
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot tag events'}), 403
    
    from models import TimelineTag
    import json
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    data = request.json
    event_id = data.get('event_id')
    index_name = data.get('index_name')
    event_data = data.get('event_data', {})
    notes = data.get('notes', '')
    tag_color = data.get('tag_color', 'blue')
    
    if not event_id or not index_name:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if already tagged
    existing = db.session.query(TimelineTag).filter_by(
        case_id=case_id,
        event_id=event_id,
        index_name=index_name
    ).first()
    
    if existing:
        return jsonify({'error': 'Event already tagged', 'tag_id': existing.id}), 400
    
    # Create tag
    tag = TimelineTag(
        case_id=case_id,
        user_id=current_user.id,
        event_id=event_id,
        index_name=index_name,
        event_data=json.dumps(event_data),
        tag_color=tag_color,
        notes=notes
    )
    db.session.add(tag)
    db.session.commit()
    
    logger.info(f"[TIMELINE TAG] User {current_user.id} tagged event {event_id} in case {case_id}")
    
    return jsonify({
        'success': True,
        'tag_id': tag.id,
        'created_at': tag.created_at.isoformat()
    })


@app.route('/case/<int:case_id>/search/untag', methods=['POST'])
@login_required
def untag_timeline_event(case_id):
    """Remove timeline tag"""
    # Permission check: Read-only users cannot untag events
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot untag events'}), 403
    
    from models import TimelineTag
    
    data = request.json
    event_id = data.get('event_id')
    index_name = data.get('index_name')
    
    tag = db.session.query(TimelineTag).filter_by(
        case_id=case_id,
        event_id=event_id,
        index_name=index_name
    ).first()
    
    if not tag:
        return jsonify({'error': 'Tag not found'}), 404
    
    # Only allow creator or admin to remove
    if tag.user_id != current_user.id and current_user.role != 'administrator':
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(tag)
    db.session.commit()
    
    return jsonify({'success': True})


@app.route('/case/<int:case_id>/search/hide', methods=['POST'])
@login_required
def hide_event(case_id):
    """Hide event from search results by setting is_hidden flag in OpenSearch"""
    # Permission check: Read-only users cannot hide events
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot hide events'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    data = request.json
    event_id = data.get('event_id')
    index_name = data.get('index_name')
    
    if not event_id or not index_name:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Update OpenSearch document to set is_hidden flag
    try:
        opensearch_client.update(
            index=index_name,
            id=event_id,
            body={
                'script': {
                    'source': 'ctx._source.is_hidden = true; ctx._source.hidden_by = params.user_id; ctx._source.hidden_at = params.timestamp',
                    'lang': 'painless',
                    'params': {
                        'user_id': current_user.id,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                }
            }
        )
        
        logger.info(f"[HIDE EVENT] User {current_user.id} hid event {event_id} in case {case_id}")
        
        return jsonify({
            'success': True,
            'event_id': event_id
        })
    except Exception as e:
        logger.error(f"[HIDE EVENT] Error hiding event {event_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/case/<int:case_id>/search/unhide', methods=['POST'])
@login_required
def unhide_event(case_id):
    """Unhide event by removing is_hidden flag from OpenSearch"""
    # Permission check: Read-only users cannot unhide events
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot unhide events'}), 403
    
    data = request.json
    event_id = data.get('event_id')
    index_name = data.get('index_name')
    
    if not event_id or not index_name:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Update OpenSearch document to remove is_hidden flag
    try:
        opensearch_client.update(
            index=index_name,
            id=event_id,
            body={
                'script': {
                    'source': 'ctx._source.remove("is_hidden"); ctx._source.remove("hidden_by"); ctx._source.remove("hidden_at")',
                    'lang': 'painless'
                }
            }
        )
        
        logger.info(f"[UNHIDE EVENT] User {current_user.id} unhid event {event_id} in case {case_id}")
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"[UNHIDE EVENT] Error unhiding event {event_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/case/<int:case_id>/search/bulk-tag', methods=['POST'])
@login_required
def bulk_tag_events(case_id):
    """Bulk tag multiple events for timeline"""
    # Permission check: Read-only users cannot tag events
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot tag events'}), 403
    
    from models import TimelineTag
    import json
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    data = request.json
    events = data.get('events', [])  # List of {event_id, index_name}
    tag_color = data.get('tag_color', 'blue')
    
    if not events:
        return jsonify({'error': 'No events provided'}), 400
    
    tagged_count = 0
    skipped_count = 0
    
    for event in events:
        event_id = event.get('event_id')
        index_name = event.get('index_name')
        
        if not event_id or not index_name:
            continue
        
        # Check if already tagged
        existing = db.session.query(TimelineTag).filter_by(
            case_id=case_id,
            event_id=event_id,
            index_name=index_name
        ).first()
        
        if existing:
            skipped_count += 1
            continue
        
        # Create tag
        tag = TimelineTag(
            case_id=case_id,
            user_id=current_user.id,
            event_id=event_id,
            index_name=index_name,
            event_data=json.dumps(event.get('event_data', {})),
            tag_color=tag_color,
            notes=''
        )
        db.session.add(tag)
        tagged_count += 1
    
    db.session.commit()
    
    logger.info(f"[BULK TAG] User {current_user.id} tagged {tagged_count} events in case {case_id} (skipped {skipped_count})")
    
    return jsonify({
        'success': True,
        'tagged': tagged_count,
        'skipped': skipped_count
    })


@app.route('/case/<int:case_id>/search/bulk-untag', methods=['POST'])
@login_required
def bulk_untag_events(case_id):
    """Bulk remove timeline tags from multiple events"""
    # Permission check: Read-only users cannot untag events
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot untag events'}), 403
    
    from models import TimelineTag
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    data = request.json
    events = data.get('events', [])  # List of {event_id, index_name}
    
    if not events:
        return jsonify({'error': 'No events provided'}), 400
    
    untagged_count = 0
    
    for event in events:
        event_id = event.get('event_id')
        index_name = event.get('index_name')
        
        if not event_id or not index_name:
            continue
        
        # Find and delete tag
        tag = db.session.query(TimelineTag).filter_by(
            case_id=case_id,
            event_id=event_id,
            index_name=index_name
        ).first()
        
        if tag:
            db.session.delete(tag)
            untagged_count += 1
    
    db.session.commit()
    
    logger.info(f"[BULK UNTAG] User {current_user.id} untagged {untagged_count} events in case {case_id}")
    
    return jsonify({
        'success': True,
        'untagged': untagged_count
    })


@app.route('/case/<int:case_id>/sync-timeline-to-iris', methods=['POST'])
@login_required
def sync_timeline_to_iris_case(case_id):
    """Sync all tagged events in this case to DFIR-IRIS timeline"""
    # Permission check: Read-only users cannot sync
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot sync to DFIR-IRIS'}), 403
    
    from flask import jsonify
    from dfir_iris import DFIRIrisClient, sync_case_to_dfir_iris
    from routes.settings import get_setting
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Check if DFIR-IRIS is enabled
    dfir_iris_enabled = get_setting('dfir_iris_enabled', 'false') == 'true'
    if not dfir_iris_enabled:
        return jsonify({'success': False, 'error': 'DFIR-IRIS integration is not enabled'}), 400
    
    # Get DFIR-IRIS connection settings
    dfir_iris_url = get_setting('dfir_iris_url')
    dfir_iris_api_key = get_setting('dfir_iris_api_key')
    
    if not dfir_iris_url or not dfir_iris_api_key:
        return jsonify({
            'success': False,
            'error': 'DFIR-IRIS connection not configured. Please configure in System Settings.'
        }), 400
    
    # Get case
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    try:
        # Create DFIR-IRIS client
        client = DFIRIrisClient(dfir_iris_url, dfir_iris_api_key)
        
        # Sync case (includes IOCs and timeline events)
        result = sync_case_to_dfir_iris(db.session, opensearch_client, case_id, client)
        
        if result.get('success'):
            logger.info(f"[DFIR-IRIS SYNC] User {current_user.id} synced case {case_id} timeline to DFIR-IRIS")
            logger.info(f"[DFIR-IRIS SYNC] Results: {result.get('events_synced', 0)} events, "
                       f"{result.get('iocs_synced', 0)} IOCs, {result.get('events_removed', 0)} removed")
            
            return jsonify({
                'success': True,
                'events_synced': result.get('events_synced', 0),
                'events_removed': result.get('events_removed', 0),
                'iocs_synced': result.get('iocs_synced', 0),
                'customer_id': result.get('customer_id'),
                'case_id': result.get('case_id'),
                'errors': result.get('errors', [])
            })
        else:
            error_msg = '; '.join(result.get('errors', ['Unknown error']))
            logger.error(f"[DFIR-IRIS SYNC] Failed to sync case {case_id}: {error_msg}")
            return jsonify({
                'success': False,
                'error': error_msg
            }), 500
            
    except Exception as e:
        logger.error(f"[DFIR-IRIS SYNC] Exception syncing case {case_id}: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Error connecting to DFIR-IRIS: {str(e)}'
        }), 500


def bulk_update_hidden_status(case_id, events, is_hidden_value, user_id):
    """Helper function to bulk update is_hidden status in OpenSearch"""
    from opensearchpy.helpers import bulk as opensearch_bulk
    
    bulk_ops = []
    timestamp = datetime.utcnow().isoformat()
    
    for event in events:
        event_id = event.get('event_id')
        index_name = event.get('index_name')
        
        if not event_id or not index_name:
            continue
        
        if is_hidden_value:
            # Set is_hidden = true
            script_source = 'ctx._source.is_hidden = true; ctx._source.hidden_by = params.user_id; ctx._source.hidden_at = params.timestamp'
        else:
            # Remove is_hidden flag
            script_source = 'ctx._source.remove("is_hidden"); ctx._source.remove("hidden_by"); ctx._source.remove("hidden_at")'
        
        bulk_ops.append({
            '_op_type': 'update',
            '_index': index_name,
            '_id': event_id,
            'script': {
                'source': script_source,
                'lang': 'painless',
                'params': {
                    'user_id': user_id,
                    'timestamp': timestamp
                }
            }
        })
    
    if not bulk_ops:
        return 0, 0
    
    # Execute bulk update
    success, failed = opensearch_bulk(opensearch_client, bulk_ops, raise_on_error=False)
    return success, len(failed)


@app.route('/case/<int:case_id>/search/bulk-hide', methods=['POST'])
@login_required
def bulk_hide_events(case_id):
    """Bulk hide multiple events by setting is_hidden flag in OpenSearch"""
    # Permission check: Read-only users cannot hide events
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot hide events'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    data = request.json
    events = data.get('events', [])
    
    if not events:
        return jsonify({'error': 'No events provided'}), 400
    
    try:
        success, failed = bulk_update_hidden_status(case_id, events, True, current_user.id)
        
        logger.info(f"[BULK HIDE] User {current_user.id} hid {success} events in case {case_id} ({failed} failed)")
        
        return jsonify({
            'success': True,
            'hidden': success,
            'failed': failed
        })
    except Exception as e:
        logger.error(f"[BULK HIDE] Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/case/<int:case_id>/search/bulk-unhide', methods=['POST'])
@login_required
def bulk_unhide_events(case_id):
    """Bulk unhide multiple events by removing is_hidden flag from OpenSearch"""
    # Permission check: Read-only users cannot unhide events
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot unhide events'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    data = request.json
    events = data.get('events', [])
    
    if not events:
        return jsonify({'error': 'No events provided'}), 400
    
    try:
        success, failed = bulk_update_hidden_status(case_id, events, False, current_user.id)
        
        logger.info(f"[BULK UNHIDE] User {current_user.id} unhid {success} events in case {case_id} ({failed} failed)")
        
        return jsonify({
            'success': True,
            'unhidden': success,
            'failed': failed
        })
    except Exception as e:
        logger.error(f"[BULK UNHIDE] Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/case/<int:case_id>/search/columns', methods=['POST'])
@login_required
def update_search_columns(case_id):
    """Update search column configuration"""
    try:
        # Validate request has JSON data
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Request must be JSON'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data provided'}), 400
        
        columns = data.get('columns', [])
        if not isinstance(columns, list):
            return jsonify({'success': False, 'error': 'Columns must be a list'}), 400
        
        # Validate case exists
        case = db.session.get(Case, case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Save to session
        session[f'search_columns_{case_id}'] = columns
        
        logger.info(f"[SEARCH COLUMNS] Updated columns for case {case_id}: {len(columns)} columns")
        
        return jsonify({'success': True, 'columns': columns})
    
    except Exception as e:
        logger.error(f"[SEARCH COLUMNS] Error updating columns for case {case_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/case/<int:case_id>/search/history/<int:search_id>/favorite', methods=['POST'])
@login_required
def toggle_search_favorite(case_id, search_id):
    """Toggle search favorite status"""
    from models import SearchHistory
    
    search = db.session.get(SearchHistory, search_id)
    if not search or search.user_id != current_user.id:
        return jsonify({'error': 'Search not found'}), 404
    
    search.is_favorite = not search.is_favorite
    db.session.commit()
    
    return jsonify({'success': True, 'is_favorite': search.is_favorite})


# ========================================
# GLOBAL SAVED SEARCHES (v1.17.0)
# ========================================

@app.route('/search/saved/list', methods=['GET'])
@login_required
def list_saved_searches():
    """Get all global saved searches for current user"""
    from models import SearchHistory
    import json
    
    searches = db.session.query(SearchHistory).filter_by(
        user_id=current_user.id,
        case_id=None,  # Global searches only (not tied to specific case)
        is_favorite=True  # Use is_favorite field to mark global saved searches
    ).order_by(SearchHistory.search_name.asc()).all()
    
    result = []
    for search in searches:
        try:
            search_data = json.loads(search.search_query)
            result.append({
                'id': search.id,
                'title': search.search_name or 'Unnamed Search',
                'search_query': search_data.get('search_text', ''),
                'filter_type': search.filter_type,
                'date_range': search.date_range,
                'file_types': search_data.get('file_types', []),
                'results_per_page': search_data.get('results_per_page', 50),
                'visibility': search_data.get('visibility', 'hide'),
                'created_at': search.created_at.strftime('%Y-%m-%d %H:%M')
            })
        except:
            pass
    
    return jsonify({'success': True, 'searches': result})


@app.route('/search/saved/<int:search_id>', methods=['GET'])
@login_required
def get_saved_search(search_id):
    """Get a specific saved search"""
    from models import SearchHistory
    import json
    
    search = db.session.get(SearchHistory, search_id)
    if not search or search.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Search not found'}), 404
    
    try:
        search_data = json.loads(search.search_query)
        result = {
            'id': search.id,
            'title': search.search_name or 'Unnamed Search',
            'search_query': search_data.get('search_text', ''),
            'filter_type': search.filter_type,
            'date_range': search.date_range,
            'file_types': search_data.get('file_types', []),
            'results_per_page': search_data.get('results_per_page', 50),
            'visibility': search_data.get('visibility', 'hide')
        }
        return jsonify({'success': True, 'search': result})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/search/saved/save', methods=['POST'])
@login_required
def save_search():
    """Save a new global search"""
    from models import SearchHistory
    from audit_logger import log_action
    import json
    
    data = request.get_json()
    
    if not data.get('title'):
        return jsonify({'success': False, 'message': 'Title is required'}), 400
    
    # Create search params dict
    search_params = {
        'search_text': data.get('search_query', ''),
        'filter_type': data.get('filter_type', 'all'),
        'date_range': data.get('date_range', 'all'),
        'file_types': data.get('file_types', []),
        'results_per_page': data.get('results_per_page', 50),
        'visibility': data.get('visibility', 'hide')
    }
    
    # Create new search history entry
    search = SearchHistory(
        user_id=current_user.id,
        case_id=None,  # Global search (not tied to case)
        search_name=data['title'],
        search_query=json.dumps(search_params),
        filter_type=data.get('filter_type', 'all'),
        date_range=data.get('date_range', 'all'),
        is_favorite=True,  # Mark as favorite to distinguish global saved searches
        result_count=0
    )
    
    db.session.add(search)
    db.session.commit()
    
    # Audit log
    log_action(
        action='saved_search_created',
        resource_type='search',
        resource_id=search.id,
        resource_name=data['title'],
        details={'query': search_params.get('search_text', ''), 'filter': search_params.get('filter_type')},
        status='success'
    )
    
    return jsonify({'success': True, 'search_id': search.id})


@app.route('/search/saved/<int:search_id>/delete', methods=['POST'])
@login_required
def delete_saved_search(search_id):
    """Delete a saved search"""
    from models import SearchHistory
    from audit_logger import log_action
    
    search = db.session.get(SearchHistory, search_id)
    if not search or search.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Search not found'}), 404
    
    search_name = search.search_name
    
    # Audit log before deletion
    log_action(
        action='saved_search_deleted',
        resource_type='search',
        resource_id=search.id,
        resource_name=search_name,
        details={'query': search.search_query[:100] if search.search_query else ''},
        status='success'
    )
    
    db.session.delete(search)
    db.session.commit()
    
    return jsonify({'success': True})


@app.route('/case/<int:case_id>/search/add_ioc', methods=['POST'])
@login_required
def add_field_as_ioc(case_id):
    """Add event field value as IOC"""
    # Permission check: Read-only users cannot add IOCs
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot add IOCs'}), 403
    
    from models import IOC
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    data = request.json
    ioc_value = data.get('value')
    ioc_type = data.get('type', 'other')
    threat_level = data.get('threat_level', 'medium')
    description = data.get('description', f'Added from search at {datetime.utcnow().isoformat()}')
    
    if not ioc_value:
        return jsonify({'error': 'IOC value required'}), 400
    
    if not ioc_type or ioc_type == '':
        return jsonify({'error': 'IOC type required'}), 400
    
    # Check if IOC already exists
    existing = db.session.query(IOC).filter_by(
        case_id=case_id,
        ioc_value=ioc_value
    ).first()
    
    if existing:
        return jsonify({'error': 'IOC already exists', 'ioc_id': existing.id}), 400
    
    # Create IOC
    ioc = IOC(
        case_id=case_id,
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        threat_level=threat_level,
        description=description,
        created_by=current_user.id,
        is_active=True
    )
    db.session.add(ioc)
    db.session.commit()
    
    logger.info(f"[IOC] User {current_user.id} added IOC from search: {ioc_value}")
    
    return jsonify({
        'success': True,
        'ioc_id': ioc.id,
        'ioc_value': ioc_value
    })


@app.route('/case/<int:case_id>/search/bulk_add_iocs', methods=['POST'])
@login_required
def bulk_add_iocs(case_id):
    """Bulk add usernames as IOCs from login analysis"""
    # Permission check: Read-only users cannot add IOCs
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot add IOCs'}), 403
    
    from models import IOC
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    data = request.json
    usernames = data.get('usernames', [])
    threat_level = data.get('threat_level', 'medium')
    source = data.get('source', 'Login Analysis')
    
    if not usernames or not isinstance(usernames, list):
        return jsonify({'error': 'Usernames array required'}), 400
    
    if len(usernames) == 0:
        return jsonify({'error': 'No usernames provided'}), 400
    
    added_count = 0
    skipped_count = 0
    skipped_usernames = []
    
    for username in usernames:
        username = str(username).strip()
        if not username:
            continue
        
        # Check if IOC already exists
        existing = db.session.query(IOC).filter_by(
            case_id=case_id,
            ioc_value=username,
            ioc_type='username'
        ).first()
        
        if existing:
            skipped_count += 1
            skipped_usernames.append(username)
            continue
        
        # Create IOC
        ioc = IOC(
            case_id=case_id,
            ioc_value=username,
            ioc_type='username',
            threat_level=threat_level,
            description=f'Bulk added from {source}',
            created_by=current_user.id,
            is_active=True
        )
        db.session.add(ioc)
        added_count += 1
    
    db.session.commit()
    
    logger.info(f"[IOC_BULK] User {current_user.id} bulk added {added_count} IOCs, skipped {skipped_count} duplicates")
    
    return jsonify({
        'success': True,
        'added': added_count,
        'skipped': skipped_count,
        'skipped_usernames': skipped_usernames,
        'total': len(usernames)
    })


@app.route('/case/<int:case_id>/search/logins-ok', methods=['GET'])
@login_required
def show_logins_ok(case_id):
    """Show distinct successful Windows logon events (Event ID 4624)"""
    from login_analysis import get_successful_logins
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # CRITICAL: Check if index exists before querying (v1.13.7)
    if not index_exists(case_id):
        logger.info(f"[LOGINS_OK] Index does not exist for case {case_id} - files still processing")
        return jsonify({
            'success': True,
            'logins': [],
            'total_events': 0,
            'distinct_count': 0,
            'message': 'No data available yet. Files are still being processed and indexed. Please try again in a few minutes.'
        })
    
    # Get date range parameters (use same filters as main search)
    date_range = request.args.get('date_range', 'all')
    custom_date_start = None
    custom_date_end = None
    
    if date_range == 'custom':
        custom_date_start_str = request.args.get('custom_date_start', '')
        custom_date_end_str = request.args.get('custom_date_end', '')
        
        if custom_date_start_str:
            try:
                custom_date_start = datetime.fromisoformat(custom_date_start_str)
            except:
                pass
        
        if custom_date_end_str:
            try:
                custom_date_end = datetime.fromisoformat(custom_date_end_str)
            except:
                pass
    
    # Get latest event timestamp for relative date filters
    latest_event_timestamp = None
    if date_range in ['24h', '7d', '30d']:
        try:
            index_pattern = f"case_{case_id}"
            latest_query = {
                "size": 1,
                "sort": [{"normalized_timestamp": {"order": "desc"}}],
                "_source": ["normalized_timestamp"]
            }
            latest_result = opensearch_client.search(index=index_pattern, body=latest_query)
            if latest_result['hits']['hits']:
                timestamp_str = latest_result['hits']['hits'][0]['_source'].get('normalized_timestamp')
                if timestamp_str:
                    latest_event_timestamp = datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.warning(f"[LOGINS_OK] Could not get latest timestamp: {e}")
            latest_event_timestamp = datetime.utcnow()
    
    # Get login data
    result = get_successful_logins(
        opensearch_client,
        case_id,
        date_range=date_range,
        custom_date_start=custom_date_start,
        custom_date_end=custom_date_end,
        latest_event_timestamp=latest_event_timestamp
    )
    
    return jsonify(result)


@app.route('/case/<int:case_id>/search/logins-failed', methods=['GET'])
@login_required
def show_logins_failed(case_id):
    """Show distinct failed Windows logon events (Event ID 4625)"""
    from login_analysis import get_failed_logins
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # CRITICAL: Check if index exists before querying (v1.13.7)
    if not index_exists(case_id):
        logger.info(f"[LOGINS_FAILED] Index does not exist for case {case_id} - files still processing")
        return jsonify({
            'success': True,
            'logins': [],
            'total_events': 0,
            'distinct_count': 0,
            'message': 'No data available yet. Files are still being processed and indexed. Please try again in a few minutes.'
        })
    
    # Get date range parameters (use same filters as main search)
    date_range = request.args.get('date_range', 'all')
    custom_date_start = None
    custom_date_end = None
    
    if date_range == 'custom':
        custom_date_start_str = request.args.get('custom_date_start', '')
        custom_date_end_str = request.args.get('custom_date_end', '')
        
        if custom_date_start_str:
            try:
                custom_date_start = datetime.fromisoformat(custom_date_start_str)
            except:
                pass
        
        if custom_date_end_str:
            try:
                custom_date_end = datetime.fromisoformat(custom_date_end_str)
            except:
                pass
    
    # Get latest event timestamp for relative date filters
    latest_event_timestamp = None
    if date_range in ['24h', '7d', '30d']:
        try:
            index_pattern = f"case_{case_id}"
            latest_query = {
                "size": 1,
                "sort": [{"normalized_timestamp": {"order": "desc"}}],
                "_source": ["normalized_timestamp"]
            }
            latest_result = opensearch_client.search(index=index_pattern, body=latest_query)
            if latest_result['hits']['hits']:
                timestamp_str = latest_result['hits']['hits'][0]['_source'].get('normalized_timestamp')
                if timestamp_str:
                    latest_event_timestamp = datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.warning(f"[LOGINS_FAILED] Could not get latest timestamp: {e}")
            latest_event_timestamp = datetime.utcnow()
    
    # Get failed login data
    result = get_failed_logins(
        opensearch_client,
        case_id,
        date_range=date_range,
        custom_date_start=custom_date_start,
        custom_date_end=custom_date_end,
        latest_event_timestamp=latest_event_timestamp
    )
    
    return jsonify(result)


@app.route('/case/<int:case_id>/search/rdp-connections', methods=['GET'])
@login_required
def show_rdp_connections(case_id):
    """Show distinct RDP connections (Event ID 1149 - TerminalServices-RemoteConnectionManager)"""
    from login_analysis import get_rdp_connections
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # CRITICAL: Check if index exists before querying (v1.13.7)
    if not index_exists(case_id):
        logger.info(f"[RDP_CONNECTIONS] Index does not exist for case {case_id} - files still processing")
        return jsonify({
            'success': True,
            'logins': [],
            'total_events': 0,
            'distinct_count': 0,
            'message': 'No data available yet. Files are still being processed and indexed. Please try again in a few minutes.'
        })
    
    # Get date range parameters (use same filters as main search)
    date_range = request.args.get('date_range', 'all')
    custom_date_start = None
    custom_date_end = None
    
    if date_range == 'custom':
        custom_date_start_str = request.args.get('custom_date_start', '')
        custom_date_end_str = request.args.get('custom_date_end', '')
        
        if custom_date_start_str:
            try:
                custom_date_start = datetime.fromisoformat(custom_date_start_str)
            except:
                pass
        
        if custom_date_end_str:
            try:
                custom_date_end = datetime.fromisoformat(custom_date_end_str)
            except:
                pass
    
    # Get latest event timestamp for relative date filters
    latest_event_timestamp = None
    if date_range in ['24h', '7d', '30d']:
        try:
            index_pattern = f"case_{case_id}"
            latest_query = {
                "size": 1,
                "sort": [{"normalized_timestamp": {"order": "desc"}}],
                "_source": ["normalized_timestamp"]
            }
            latest_result = opensearch_client.search(index=index_pattern, body=latest_query)
            if latest_result['hits']['hits']:
                timestamp_str = latest_result['hits']['hits'][0]['_source'].get('normalized_timestamp')
                if timestamp_str:
                    latest_event_timestamp = datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.warning(f"[RDP_CONNECTIONS] Could not get latest timestamp: {e}")
            latest_event_timestamp = datetime.utcnow()
    
    # Get RDP connection data
    result = get_rdp_connections(
        opensearch_client,
        case_id,
        date_range=date_range,
        custom_date_start=custom_date_start,
        custom_date_end=custom_date_end,
        latest_event_timestamp=latest_event_timestamp
    )
    
    return jsonify(result)


@app.route('/case/<int:case_id>/search/console-logins', methods=['GET'])
@login_required
def show_console_logins(case_id):
    """Show distinct console logins (Event ID 4624 with LogonType = 2)"""
    from login_analysis import get_console_logins
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # CRITICAL: Check if index exists before querying (v1.13.7)
    if not index_exists(case_id):
        logger.info(f"[CONSOLE_LOGINS] Index does not exist for case {case_id} - files still processing")
        return jsonify({
            'success': True,
            'logins': [],
            'total_events': 0,
            'distinct_count': 0,
            'message': 'No data available yet. Files are still being processed and indexed. Please try again in a few minutes.'
        })
    
    # Get date range parameters (use same filters as main search)
    date_range = request.args.get('date_range', 'all')
    custom_date_start = None
    custom_date_end = None
    
    if date_range == 'custom':
        custom_date_start_str = request.args.get('custom_date_start', '')
        custom_date_end_str = request.args.get('custom_date_end', '')
        
        if custom_date_start_str:
            try:
                custom_date_start = datetime.fromisoformat(custom_date_start_str)
            except:
                pass
        
        if custom_date_end_str:
            try:
                custom_date_end = datetime.fromisoformat(custom_date_end_str)
            except:
                pass
    
    # Get latest event timestamp for relative date filters
    latest_event_timestamp = None
    if date_range in ['24h', '7d', '30d']:
        try:
            index_pattern = f"case_{case_id}"
            latest_query = {
                "size": 1,
                "sort": [{"normalized_timestamp": {"order": "desc"}}],
                "_source": ["normalized_timestamp"]
            }
            latest_result = opensearch_client.search(index=index_pattern, body=latest_query)
            if latest_result['hits']['hits']:
                timestamp_str = latest_result['hits']['hits'][0]['_source'].get('normalized_timestamp')
                if timestamp_str:
                    latest_event_timestamp = datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.warning(f"[CONSOLE_LOGINS] Could not get latest timestamp: {e}")
            latest_event_timestamp = datetime.utcnow()
    
    # Get console login data
    result = get_console_logins(
        opensearch_client,
        case_id,
        date_range=date_range,
        custom_date_start=custom_date_start,
        custom_date_end=custom_date_end,
        latest_event_timestamp=latest_event_timestamp
    )
    
    return jsonify(result)


@app.route('/case/<int:case_id>/search/vpn-authentications', methods=['GET'])
@login_required
def show_vpn_authentications(case_id):
    """Show VPN authentications (Event ID 4624 with firewall IP) - NO deduplication"""
    from login_analysis import get_vpn_authentications
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # CRITICAL: Check if index exists before querying (v1.13.7)
    if not index_exists(case_id):
        logger.info(f"[VPN_AUTHS] Index does not exist for case {case_id} - files still processing")
        return jsonify({
            'success': True,
            'logins': [],
            'total_events': 0,
            'distinct_count': 0,
            'message': 'No data available yet. Files are still being processed and indexed. Please try again in a few minutes.'
        })
    
    # Get firewall IP and name from request
    firewall_ip = request.args.get('firewall_ip', '')
    firewall_name = request.args.get('firewall_name', 'Firewall')
    
    if not firewall_ip:
        return jsonify({'success': False, 'error': 'Firewall IP is required'}), 400
    
    # Get date range parameters (use same filters as main search)
    date_range = request.args.get('date_range', 'all')
    custom_date_start = None
    custom_date_end = None
    
    if date_range == 'custom':
        custom_date_start_str = request.args.get('custom_date_start', '')
        custom_date_end_str = request.args.get('custom_date_end', '')
        
        if custom_date_start_str:
            try:
                custom_date_start = datetime.fromisoformat(custom_date_start_str)
            except:
                pass
        
        if custom_date_end_str:
            try:
                custom_date_end = datetime.fromisoformat(custom_date_end_str)
            except:
                pass
    
    # Get latest event timestamp for relative date filters
    latest_event_timestamp = None
    if date_range in ['24h', '7d', '30d']:
        try:
            index_pattern = f"case_{case_id}"
            latest_query = {
                "size": 1,
                "sort": [{"normalized_timestamp": {"order": "desc"}}],
                "_source": ["normalized_timestamp"]
            }
            latest_result = opensearch_client.search(index=index_pattern, body=latest_query)
            if latest_result['hits']['hits']:
                timestamp_str = latest_result['hits']['hits'][0]['_source'].get('normalized_timestamp')
                if timestamp_str:
                    latest_event_timestamp = datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.warning(f"[VPN_AUTHS] Could not get latest timestamp: {e}")
            latest_event_timestamp = datetime.utcnow()
    
    # Get VPN authentication data (ALL events, no deduplication)
    result = get_vpn_authentications(
        opensearch_client,
        case_id,
        firewall_ip=firewall_ip,
        date_range=date_range,
        custom_date_start=custom_date_start,
        custom_date_end=custom_date_end,
        latest_event_timestamp=latest_event_timestamp
    )
    
    return jsonify(result)


@app.route('/case/<int:case_id>/search/vpn-failed-attempts', methods=['GET'])
@login_required
def show_failed_vpn_attempts(case_id):
    """Show failed VPN attempts (Event ID 4625 with firewall IP) - NO deduplication"""
    from login_analysis import get_failed_vpn_attempts
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # CRITICAL: Check if index exists before querying (v1.13.7)
    if not index_exists(case_id):
        logger.info(f"[FAILED_VPN] Index does not exist for case {case_id} - files still processing")
        return jsonify({
            'success': True,
            'logins': [],
            'total_events': 0,
            'distinct_count': 0,
            'message': 'No data available yet. Files are still being processed and indexed. Please try again in a few minutes.'
        })
    
    # Get firewall IP and name from request
    firewall_ip = request.args.get('firewall_ip', '')
    firewall_name = request.args.get('firewall_name', 'Firewall')
    
    if not firewall_ip:
        return jsonify({'success': False, 'error': 'Firewall IP is required'}), 400
    
    # Get date range parameters (use same filters as main search)
    date_range = request.args.get('date_range', 'all')
    custom_date_start = None
    custom_date_end = None
    
    if date_range == 'custom':
        custom_date_start_str = request.args.get('custom_date_start', '')
        custom_date_end_str = request.args.get('custom_date_end', '')
        
        if custom_date_start_str:
            try:
                custom_date_start = datetime.fromisoformat(custom_date_start_str)
            except:
                pass
        
        if custom_date_end_str:
            try:
                custom_date_end = datetime.fromisoformat(custom_date_end_str)
            except:
                pass
    
    # Get latest event timestamp for relative date filters
    latest_event_timestamp = None
    if date_range in ['24h', '7d', '30d']:
        try:
            index_pattern = f"case_{case_id}"
            latest_query = {
                "size": 1,
                "sort": [{"normalized_timestamp": {"order": "desc"}}],
                "_source": ["normalized_timestamp"]
            }
            latest_result = opensearch_client.search(index=index_pattern, body=latest_query)
            if latest_result['hits']['hits']:
                timestamp_str = latest_result['hits']['hits'][0]['_source'].get('normalized_timestamp')
                if timestamp_str:
                    latest_event_timestamp = datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.warning(f"[FAILED_VPN] Could not get latest timestamp: {e}")
            latest_event_timestamp = datetime.utcnow()
    
    # Get failed VPN attempt data (ALL events, no deduplication)
    result = get_failed_vpn_attempts(
        opensearch_client,
        case_id,
        firewall_ip=firewall_ip,
        date_range=date_range,
        custom_date_start=custom_date_start,
        custom_date_end=custom_date_end,
        latest_event_timestamp=latest_event_timestamp
    )
    
    return jsonify(result)


@app.route('/sigma')
@login_required
def sigma_management():
    """SIGMA Management - View and manage SIGMA detection rules"""
    from sigma_utils import list_sigma_rules, get_sigma_stats
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 1000)  # Max 1000 per page
    search_query = request.args.get('search', '', type=str).strip()
    
    # Get SIGMA stats
    sigma_info = get_sigma_stats()
    
    # List rules with pagination
    rules_data = list_sigma_rules(page=page, per_page=per_page, search_query=search_query)
    
    return render_template('sigma_management.html', 
                         sigma_info=sigma_info,
                         rules=rules_data['rules'],
                         page=rules_data['page'],
                         per_page=rules_data['per_page'],
                         total=rules_data['total'],
                         total_pages=rules_data['total_pages'],
                         search_query=search_query)


@app.route('/sigma/update', methods=['POST'])
@login_required
def update_sigma():
    """Update SIGMA rules from GitHub"""
    from sigma_utils import update_sigma_rules
    
    result = update_sigma_rules()
    
    # Audit log
    from audit_logger import log_action
    status = 'success' if result['success'] else 'failed'
    log_action('update_sigma_rules', resource_type='sigma', resource_name='SIGMA Rules',
              details={'result': result['message']}, status=status)
    
    if result['success']:
        flash(result['message'], 'success')
    else:
        flash(f"{result['message']}: {result['output'][:200]}", 'error')
    
    return redirect(url_for('sigma_management'))


@app.route('/files')
@login_required
def file_management():
    """Redirect to new global files page in blueprint"""
    return redirect(url_for('files.global_files'))


@app.route('/case/<int:case_id>/events')
@login_required
def event_search(case_id):
    """Event Search - Search and view events for a specific case"""
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get case files
    files = db.session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False
    ).all()
    
    # Calculate stats
    total_events = sum(f.event_count or 0 for f in files)
    sigma_violations = sum(f.violation_count or 0 for f in files)
    ioc_events = sum(f.ioc_event_count or 0 for f in files)
    indexed_files = len([f for f in files if f.indexing_status == 'Completed'])
    
    # Get recent SIGMA violations for this case (last 50)
    violations = db.session.query(SigmaViolation).join(CaseFile).filter(
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False
    ).order_by(SigmaViolation.id.desc()).limit(50).all()
    
    return render_template('event_search.html',
                         case=case,
                         total_events=total_events,
                         sigma_violations=sigma_violations,
                         ioc_events=ioc_events,
                         indexed_files=indexed_files,
                         violations=violations)


@app.route('/case/<int:case_id>/clear_files', methods=['POST'])
@login_required
def clear_all_files(case_id):
    """Clear all files for a case - removes from filesystem, database, and OpenSearch"""
    import os
    import shutil
    from utils import make_index_name
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Archive guard (v1.18.0): Prevent clearing archived cases
    from archive_utils import is_case_archived
    if is_case_archived(case):
        flash('❌ Cannot clear files from archived case. Please restore the case first.', 'error')
        return redirect(url_for('view_case', case_id=case_id))
    
    # Get all files for this case (including deleted/hidden)
    files = db.session.query(CaseFile).filter_by(case_id=case_id).all()
    
    deleted_count = 0
    errors = []
    
    for file in files:
        try:
            # 1. Delete from OpenSearch (v1.13.1: delete by file_id from case index)
            if file.opensearch_key:
                try:
                    # Get case index (shared by all files)
                    index_name = make_index_name(case_id)
                    
                    # Delete events by file_id (more reliable than opensearch_key)
                    opensearch_client.delete_by_query(
                        index=index_name,
                        body={
                            "query": {
                                "term": {"file_id": file.id}
                            }
                        },
                        conflicts='proceed',
                        ignore=[404]  # Ignore if index doesn't exist
                    )
                except Exception as e:
                    # Don't fail the whole operation if OpenSearch delete fails
                    errors.append(f"OpenSearch delete error for file {file.id}: {str(e)}")
            
            # 2. Delete physical file from filesystem
            if file.file_path and os.path.exists(file.file_path):
                try:
                    os.remove(file.file_path)
                except Exception as e:
                    errors.append(f"Filesystem delete error for {file.original_filename}: {str(e)}")
            
            # 3. Delete related records from database
            # Delete SIGMA violations
            db.session.query(SigmaViolation).filter_by(file_id=file.id).delete()
            
            # Delete IOC matches
            db.session.query(IOCMatch).filter_by(file_id=file.id).delete()
            
            # Delete the CaseFile record
            db.session.delete(file)
            
            deleted_count += 1
            
        except Exception as e:
            errors.append(f"Error deleting file {file.id}: {str(e)}")
    
    # Delete staging and archive directories for this case
    staging_dir = f'/opt/casescope/staging/{case_id}'
    archive_dir = f'/opt/casescope/archive/{case_id}'
    uploads_dir = f'/opt/casescope/uploads/{case_id}'
    
    for dir_path in [staging_dir, archive_dir, uploads_dir]:
        if os.path.exists(dir_path):
            try:
                shutil.rmtree(dir_path)
            except Exception as e:
                errors.append(f"Error deleting directory {dir_path}: {str(e)}")
    
    # Commit all database changes
    try:
        db.session.commit()
        
        if errors:
            flash(f'Cleared {deleted_count} file(s) with {len(errors)} error(s)', 'warning')
            for error in errors[:5]:  # Show first 5 errors
                flash(error, 'error')
        else:
            flash(f'Successfully cleared all {deleted_count} file(s) from case', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Database error: {str(e)}', 'error')
    
    return redirect(url_for('view_case', case_id=case_id))


# @app.route('/case/<int:case_id>/files')
# @login_required
# def case_files(case_id):
#     """Dedicated Case Files Management Page with Pagination"""
#     case = db.session.get(Case, case_id)
#     if not case:
#         flash('Case not found', 'error')
#         return redirect(url_for('dashboard'))
#     
#     # Pagination parameters
#     page = request.args.get('page', 1, type=int)
#     per_page = request.args.get('per_page', 50, type=int)  # Default 50 files per page
#     
#     # Get files with pagination
#     files_query = db.session.query(CaseFile).filter_by(
#         case_id=case_id,
#         is_deleted=False,
#         is_hidden=False
#     ).order_by(CaseFile.uploaded_at.desc())
#     
#     # Use paginate for efficient pagination
#     pagination = files_query.paginate(page=page, per_page=per_page, error_out=False)
#     files = pagination.items
#     
#     # Calculate tile 1 stats: files and space (ALL files, not just current page)
#     all_files = files_query.all()
#     total_files = len(all_files)
#     total_space_bytes = sum(f.file_size or 0 for f in all_files)
#     total_space_gb = total_space_bytes / (1024**3)
#     
#     # File type breakdown (ALL files)
#     file_types = {}
#     for f in all_files:
#         ftype = f.file_type or 'UNKNOWN'
#         file_types[ftype] = file_types.get(ftype, 0) + 1
#     
#     # Calculate tile 2 stats: events (ALL files)
#     total_events = sum(f.event_count or 0 for f in all_files)
#     total_sigma_events = sum(f.violation_count or 0 for f in all_files)
#     total_ioc_events = sum(f.ioc_event_count or 0 for f in all_files)
#     
#     return render_template(
#         'case_files.html',
#         case=case,
#         files=files,
#         pagination=pagination,
#         total_files=total_files,
#         total_space_gb=total_space_gb,
#         file_types=file_types,
#         total_events=total_events,
#         total_sigma_events=total_sigma_events,
#         total_ioc_events=total_ioc_events
#     )
# 
# 
@app.route('/case/<int:case_id>/bulk_reindex', methods=['POST'])
@login_required
def bulk_reindex_route(case_id):
    """Re-index all files in a case"""
    from celery_health import check_workers_available
    from bulk_operations import (
        get_case_files, clear_case_opensearch_indices, 
        clear_case_sigma_violations, clear_case_ioc_matches,
        clear_case_timeline_tags, reset_file_metadata, queue_file_processing
    )
    from tasks import process_file
    import time
    
    # Check if request wants JSON (for modal updates) or redirect (for backward compat)
    wants_json = request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    
    case = db.session.get(Case, case_id)
    if not case:
        if wants_json:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Archive guard (v1.18.0): Prevent re-indexing archived cases
    from archive_utils import is_case_archived
    if is_case_archived(case):
        if wants_json:
            return jsonify({'success': False, 'error': 'Cannot re-index archived case'}), 403
        flash('❌ Cannot re-index archived case. Please restore the case first.', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Safety check: Ensure Celery workers are available
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        if wants_json:
            return jsonify({'success': False, 'error': f'No Celery workers available: {error_msg}'}), 503
        flash(f'⚠️ Cannot start bulk operation: {error_msg}. Please check Celery workers.', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Track steps for modal updates
    steps = []
    start_time = time.time()
    
    # Get all files for case (exclude deleted and hidden files)
    files = get_case_files(db, case_id, include_deleted=False, include_hidden=False)
    
    if not files:
        if wants_json:
            return jsonify({'success': True, 'message': 'No files to reindex', 'steps': [], 'files_queued': 0})
        flash('No files found to re-index', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # STEP 1: Clear database entries (reset to fresh import state)
    steps.append({'step': 'clearing_db', 'message': f'Clearing database entries for {len(files)} files', 'status': 'in_progress'})
    
    # Clear all SIGMA violations, IOC matches, and timeline tags for this case
    sigma_deleted = clear_case_sigma_violations(db, case_id)
    ioc_deleted = clear_case_ioc_matches(db, case_id)
    tags_deleted = clear_case_timeline_tags(db, case_id)
    
    # Reset all file metadata (including opensearch_key)
    for f in files:
        reset_file_metadata(f, reset_opensearch_key=True)
        f.error_message = None
        f.celery_task_id = None
    
    from tasks import commit_with_retry
    commit_with_retry(db.session, logger_instance=logger)
    
    steps[-1]['status'] = 'completed'
    steps[-1]['files_processed'] = len(files)
    steps[-1]['sigma_deleted'] = sigma_deleted
    steps[-1]['ioc_deleted'] = ioc_deleted
    steps[-1]['tags_deleted'] = tags_deleted
    steps[-1]['duration'] = round(time.time() - start_time, 2)
    
    # STEP 2: Clear OpenSearch entries (DELETE ENTIRE INDEX for clean slate)
    step_start = time.time()
    steps.append({'step': 'clearing_opensearch', 'message': 'Deleting case index for clean rebuild', 'status': 'in_progress'})
    
    # v1.19.8: Delete entire case index to prevent mapping conflicts
    # When re-indexing ALL files, we want a clean slate with fresh mappings
    from utils import make_index_name
    index_name = make_index_name(case_id)
    try:
        opensearch_client.indices.delete(index=index_name, ignore=[404])
        logger.info(f"[BULK REINDEX] Deleted index {index_name} for clean rebuild")
        indices_deleted = 1
    except Exception as e:
        logger.warning(f"[BULK REINDEX] Could not delete index {index_name}: {e}")
        # Fallback to clearing events
        indices_deleted = clear_case_opensearch_indices(opensearch_client, case_id, files)
    
    steps[-1]['status'] = 'completed'
    steps[-1]['indices_cleared'] = indices_deleted
    steps[-1]['duration'] = round(time.time() - step_start, 2)
    
    # STEP 3: Build file queue
    step_start = time.time()
    steps.append({'step': 'building_queue', 'message': f'Building queue for {len(files)} files', 'status': 'in_progress'})
    
    # Queue for re-indexing (v1.16.25: Use 'reindex' operation to force processing)
    queued = queue_file_processing(process_file, files, operation='reindex', db_session=db.session)
    
    steps[-1]['status'] = 'completed'
    steps[-1]['files_queued'] = queued
    steps[-1]['duration'] = round(time.time() - step_start, 2)
    
    # Audit log
    from audit_logger import log_action
    log_action('bulk_reindex_case', resource_type='case', resource_id=case_id,
              resource_name=case.name,
              details={'file_count': len(files), 'worker_count': worker_count})
    
    total_duration = round(time.time() - start_time, 2)
    
    # Return JSON for modal updates or redirect for backward compatibility
    if wants_json:
        return jsonify({
            'success': True,
            'message': f'Re-indexing queued for {len(files)} files',
            'steps': steps,
            'total_duration': total_duration,
            'files_queued': queued,
            'indices_cleared': indices_deleted,
            'sigma_deleted': sigma_deleted,
            'ioc_deleted': ioc_deleted,
            'tags_deleted': tags_deleted
        })
    else:
        flash(f'✅ Re-indexing queued for {len(files)} file(s) ({worker_count} worker(s) available). All data will be cleared and rebuilt.', 'success')
        return redirect(url_for('files.case_files', case_id=case_id))


@app.route('/case/<int:case_id>/bulk_rechainsaw', methods=['POST'])
@login_required
def bulk_rechainsaw_route(case_id):
    """Re-run SIGMA on all files in a case"""
    from tasks import bulk_rechainsaw
    from celery_health import check_workers_available
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Safety check: Ensure Celery workers are available
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Cannot start bulk operation: {error_msg}. Please check Celery workers.', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    file_count = db.session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_indexed=True
    ).count()
    
    if file_count == 0:
        flash('No indexed files found to re-SIGMA', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Queue re-SIGMA task (clears old violations)
    bulk_rechainsaw.delay(case_id)
    
    flash(f'✅ SIGMA re-processing queued for {file_count} file(s) ({worker_count} worker(s) available). Old violations will be cleared.', 'success')
    return redirect(url_for('files.case_files', case_id=case_id))


@app.route('/case/<int:case_id>/bulk_rehunt_iocs', methods=['POST'])
@login_required
def bulk_rehunt_iocs_route(case_id):
    """Re-hunt IOCs on all files in a case"""
    from tasks import bulk_rehunt
    from celery_health import check_workers_available
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Safety check: Ensure Celery workers are available
    workers_ok, worker_count, error_msg = check_workers_available(min_workers=1)
    if not workers_ok:
        flash(f'⚠️ Cannot start bulk operation: {error_msg}. Please check Celery workers.', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    file_count = db.session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_indexed=True
    ).count()
    
    if file_count == 0:
        flash('No indexed files found to re-hunt', 'warning')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    # Queue re-hunt task (clears old matches)
    bulk_rehunt.delay(case_id)
    
    flash(f'✅ IOC re-hunting queued for {file_count} file(s) ({worker_count} worker(s) available). Old matches will be cleared.', 'success')
    return redirect(url_for('files.case_files', case_id=case_id))


@app.route('/case/<int:case_id>/bulk_delete_files', methods=['POST'])
@login_required
def bulk_delete_files(case_id):
    """Delete all files for a case - ADMIN ONLY"""
    import os
    import shutil
    from bulk_operations import (
        clear_case_opensearch_indices,
        clear_case_sigma_violations,
        clear_case_ioc_matches,
        get_case_files
    )
    
    # Admin check
    if current_user.role != 'administrator':
        flash('Only administrators can delete all files', 'error')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all files for this case (including deleted)
    files = get_case_files(db, case_id, include_deleted=True)
    
    if not files:
        flash('No files to delete', 'info')
        return redirect(url_for('files.case_files', case_id=case_id))
    
    deleted_count = 0
    errors = []
    
    # 1. Delete ALL OpenSearch indices for this case (entire indices, not just documents)
    try:
        indices_deleted = clear_case_opensearch_indices(opensearch_client, case_id, files)
        logger.info(f"[BULK DELETE] Deleted {indices_deleted} OpenSearch indices for case {case_id}")
    except Exception as e:
        errors.append(f"OpenSearch error: {str(e)}")
    
    # 2. Clear all SIGMA violations and IOC matches for this case
    try:
        sigma_deleted = clear_case_sigma_violations(db, case_id)
        ioc_deleted = clear_case_ioc_matches(db, case_id)
        logger.info(f"[BULK DELETE] Cleared {sigma_deleted} SIGMA violations and {ioc_deleted} IOC matches")
    except Exception as e:
        errors.append(f"Database cleanup error: {str(e)}")
    
    # 3. Delete physical files from filesystem
    for file in files:
        try:
            if file.file_path and os.path.exists(file.file_path):
                os.remove(file.file_path)
                logger.debug(f"[BULK DELETE] Deleted file: {file.file_path}")
        except Exception as e:
            errors.append(f"Filesystem error for {file.original_filename}: {str(e)}")
    
    # 4. Delete all CaseFile records from database
    try:
        for file in files:
            db.session.delete(file)
        deleted_count = len(files)
    except Exception as e:
        errors.append(f"Database delete error: {str(e)}")
    
    # 5. Delete staging and archive directories for this case
    staging_dir = f'/opt/casescope/staging/{case_id}'
    archive_dir = f'/opt/casescope/archive/{case_id}'
    uploads_dir = f'/opt/casescope/uploads/{case_id}'
    
    for dir_path in [staging_dir, archive_dir, uploads_dir]:
        if os.path.exists(dir_path):
            try:
                shutil.rmtree(dir_path)
                logger.info(f"[BULK DELETE] Deleted directory: {dir_path}")
            except Exception as e:
                errors.append(f"Directory delete error: {str(e)}")
    
    # 6. Commit all database changes
    try:
        db.session.commit()
        logger.info(f"[BULK DELETE] Completed: deleted {deleted_count} file(s)")
        
        # Audit log
        from audit_logger import log_action
        log_action('bulk_delete_files', resource_type='case', resource_id=case_id,
                  resource_name=case.name,
                  details={'files_deleted': deleted_count, 'errors': len(errors)})
        
        if errors:
            flash(f'Deleted {deleted_count} file(s) with {len(errors)} error(s)', 'warning')
            for error in errors[:5]:
                flash(error, 'error')
        else:
            flash(f'✓ Successfully deleted all {deleted_count} file(s) and cleared all data', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"[BULK DELETE] Database error: {str(e)}")
        flash(f'Database error: {str(e)}', 'error')
    
    return redirect(url_for('files.case_files', case_id=case_id))


@app.route('/case/<int:case_id>/rehunt_iocs', methods=['POST'])
@login_required
def rehunt_iocs(case_id):
    """Re-run IOC hunting on all completed files in a case (reusable from multiple pages)"""
    from tasks import bulk_rehunt
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all indexed files for this case
    file_count = db.session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_indexed=True
    ).count()
    
    # Determine redirect based on referer or query param
    redirect_to = request.args.get('redirect_to', request.form.get('redirect_to'))
    if not redirect_to:
        # Check referer to determine where user came from
        referer = request.referrer or ''
        if '/ioc' in referer:
            redirect_to = 'ioc_management'
        elif '/files' in referer:
            redirect_to = 'case_files'
        else:
            redirect_to = 'case_dashboard'
    
    if file_count == 0:
        flash('No indexed files found to re-hunt', 'warning')
        if redirect_to == 'ioc_management':
            return redirect(url_for('ioc.ioc_management', case_id=case_id))
        elif redirect_to == 'case_files':
            return redirect(url_for('files.case_files', case_id=case_id))
        else:
            return redirect(url_for('view_case', case_id=case_id))
    
    # Queue re-hunt task (task handles clearing)
    bulk_rehunt.delay(case_id)
    
    flash(f'IOC re-hunting queued for {file_count} file(s). Old matches will be cleared.', 'success')
    
    # Redirect back to where they came from
    if redirect_to == 'ioc_management':
        return redirect(url_for('ioc.ioc_management', case_id=case_id))
    elif redirect_to == 'case_files':
        return redirect(url_for('files.case_files', case_id=case_id))
    else:
        return redirect(url_for('view_case', case_id=case_id))


@app.route('/case/<int:case_id>/file/<int:file_id>/rehunt_iocs', methods=['POST'])
@login_required
def rehunt_single_file(case_id, file_id):
    """Re-run IOC hunting on a single file (reusable from multiple pages)"""
    from tasks import single_file_rehunt
    
    case_file = db.session.get(CaseFile, file_id)
    
    # Determine redirect based on referer or query param
    redirect_to = request.args.get('redirect_to', request.form.get('redirect_to'))
    if not redirect_to:
        # Check referer to determine where user came from
        referer = request.referrer or ''
        if '/ioc' in referer:
            redirect_to = 'ioc_management'
        elif '/files' in referer:
            redirect_to = 'case_files'
        else:
            redirect_to = 'case_dashboard'
    
    if not case_file or case_file.case_id != case_id:
        flash('File not found', 'error')
        if redirect_to == 'ioc_management':
            return redirect(url_for('ioc.ioc_management', case_id=case_id))
        elif redirect_to == 'case_files':
            return redirect(url_for('files.case_files', case_id=case_id))
        else:
            return redirect(url_for('view_case', case_id=case_id))
    
    if not case_file.is_indexed:
        flash('File must be indexed before IOC hunting', 'warning')
        if redirect_to == 'ioc_management':
            return redirect(url_for('ioc.ioc_management', case_id=case_id))
        elif redirect_to == 'case_files':
            return redirect(url_for('files.case_files', case_id=case_id))
        else:
            return redirect(url_for('view_case', case_id=case_id))
    
    # Queue single file re-hunt (task handles clearing)
    single_file_rehunt.delay(file_id)
    
    flash(f'IOC re-hunting queued for "{case_file.original_filename}". Old matches will be cleared.', 'success')
    
    # Redirect back to where they came from
    if redirect_to == 'ioc_management':
        return redirect(url_for('ioc.ioc_management', case_id=case_id))
    elif redirect_to == 'case_files':
        return redirect(url_for('files.case_files', case_id=case_id))
    else:
        return redirect(url_for('view_case', case_id=case_id))


# OLD INLINE TEMPLATE - KEEPING FOR REFERENCE, CAN BE DELETED
def _old_view_case_template():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ case.name }} - CaseScope 2026</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: Arial; background: #1a1a1a; color: #fff; }
            .header { background: #2a2a2a; padding: 20px; border-bottom: 2px solid #0066cc; display: flex; justify-content: space-between; align-items: center; }
            .header h1 { font-size: 24px; }
            .container { padding: 30px; max-width: 1400px; margin: 0 auto; }
            .case-info { background: #2a2a2a; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .case-info h2 { margin-bottom: 15px; }
            .case-info p { color: #999; margin: 5px 0; }
            .section { background: #2a2a2a; padding: 20px; border-radius: 8px; }
            table { width: 100%; border-collapse: collapse; }
            th { background: #333; padding: 12px; text-align: left; font-weight: 600; }
            td { padding: 12px; border-bottom: 1px solid #333; }
            tr:hover { background: #333; }
            .btn { background: #0066cc; color: white; padding: 8px 16px; border-radius: 5px; text-decoration: none; display: inline-block; }
            .btn:hover { background: #0052a3; }
            .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
            .status-completed { background: #00cc66; color: #000; }
            .status-indexing { background: #ff9800; color: #000; }
            .status-queued { background: #999; color: #000; }
            .status-failed { background: #ff4444; color: #fff; }
            .status-sigma { background: #9c27b0; color: #fff; }
            .status-ioc { background: #2196f3; color: #fff; }
            .pulsing { animation: pulse 2s ease-in-out infinite; }
            @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 {{ case.name }}</h1>
            <div>
                <a href="{{ url_for('upload_files', case_id=case.id) }}" class="btn">+ Upload Files</a>
                <a href="{{ url_for('dashboard') }}" class="btn" style="background: #444;">← Back</a>
            </div>
        </div>
        
        <div class="container">
            <div class="case-info">
                <h2>Case Information</h2>
                <p><strong>Company:</strong> {{ case.company or 'N/A' }}</p>
                <p><strong>Description:</strong> {{ case.description or 'No description' }}</p>
                <p><strong>Created:</strong> {{ case.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</p>
                <p><strong>Total Files:</strong> {{ files|length }}</p>
            </div>
            
            <div class="section">
                <h2 style="margin-bottom: 20px;">Files</h2>
                {% if files %}
                <table>
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <th>Status</th>
                            <th>Events</th>
                            <th>SIGMA</th>
                            <th>IOCs</th>
                            <th>Uploaded</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for file in files %}
                        <tr data-file-id="{{ file.id }}">
                            <td><strong>{{ file.original_filename }}</strong></td>
                            <td class="status-cell">
                                {% if file.indexing_status == 'Completed' %}
                                    <span class="status status-completed">Completed</span>
                                {% elif file.indexing_status == 'Indexing' %}
                                    <span class="status status-indexing pulsing">Indexing</span>
                                {% elif file.indexing_status == 'SIGMA Testing' %}
                                    <span class="status status-sigma pulsing">SIGMA Testing</span>
                                {% elif file.indexing_status == 'IOC Hunting' %}
                                    <span class="status status-ioc pulsing">IOC Hunting</span>
                                {% elif file.indexing_status == 'Queued' %}
                                    <span class="status status-queued">Queued</span>
                                {% else %}
                                    <span class="status status-failed">{{ file.indexing_status }}</span>
                                {% endif %}
                            </td>
                            <td class="event-count">{{ file.event_count or 0 }}</td>
                            <td class="sigma-count">{{ file.violation_count or 0 }}</td>
                            <td class="ioc-count">{{ file.ioc_event_count or 0 }}</td>
                            <td>{{ file.uploaded_at.strftime('%Y-%m-%d %H:%M') }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p style="color: #999; text-align: center; padding: 40px;">No files uploaded yet.</p>
                {% endif %}
            </div>
        </div>
        
        <script>
            // Auto-refresh file statuses every 3 seconds
            function updateStatuses() {
                fetch('/case/{{ case.id }}/status')
                    .then(response => response.json())
                    .then(data => {
                        data.files.forEach(file => {
                            const row = document.querySelector(`tr[data-file-id="${file.id}"]`);
                            if (!row) return;
                            
                            // Update status
                            const statusCell = row.querySelector('.status-cell');
                            const currentStatus = statusCell.textContent.trim();
                            
                            if (currentStatus !== file.status) {
                                let statusClass = 'status-failed';
                                let pulsing = '';
                                
                                if (file.status === 'Completed') {
                                    statusClass = 'status-completed';
                                } else if (file.status === 'Indexing') {
                                    statusClass = 'status-indexing';
                                    pulsing = ' pulsing';
                                } else if (file.status === 'SIGMA Testing') {
                                    statusClass = 'status-sigma';
                                    pulsing = ' pulsing';
                                } else if (file.status === 'IOC Hunting') {
                                    statusClass = 'status-ioc';
                                    pulsing = ' pulsing';
                                } else if (file.status === 'Queued') {
                                    statusClass = 'status-queued';
                                }
                                
                                statusCell.innerHTML = `<span class="status ${statusClass}${pulsing}">${file.status}</span>`;
                            }
                            
                            // Update counts
                            row.querySelector('.event-count').textContent = file.event_count;
                            row.querySelector('.sigma-count').textContent = file.violation_count;
                            row.querySelector('.ioc-count').textContent = file.ioc_event_count;
                        });
                    })
                    .catch(err => console.error('Status update failed:', err));
            }
            
            // Update every 3 seconds
            setInterval(updateStatuses, 3000);
            
            // Initial update after 1 second
            setTimeout(updateStatuses, 1000);
        </script>
    </body>
    </html>
    ''', case=case, files=files)


# ============================================================================
# FILE UPLOAD
# ============================================================================

@app.route('/case/<int:case_id>/upload', methods=['GET', 'POST'])
@login_required
def upload_files(case_id):
    """Upload files to case"""
    # Permission check: Read-only users cannot upload files
    if current_user.role == 'read-only':
        flash('Read-only users cannot upload files', 'error')
        return redirect(url_for('view_case', case_id=case_id))
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Archive guard (v1.18.0): Prevent uploads to archived cases
    from archive_utils import is_case_archived
    if is_case_archived(case):
        flash('❌ Cannot upload files to archived case. Please restore the case first.', 'error')
        return redirect(url_for('view_case', case_id=case_id))
    
    if request.method == 'POST':
        from upload_integration import handle_http_upload_v96
        
        # Get uploaded files from request
        uploaded_files = request.files.getlist('files')
        if not uploaded_files:
            flash('No files selected', 'error')
            return redirect(url_for('view_case', case_id=case_id))
        
        response = handle_http_upload_v96(
            app=app,
            db=db,
            Case=Case,
            CaseFile=CaseFile,
            SkippedFile=SkippedFile,
            celery_app=celery_app,
            current_user=current_user,
            uploaded_files=uploaded_files,
            case_id=case_id
        )
        
        # handle_http_upload_v96 returns a JSON response tuple
        result_data = response[0].get_json() if isinstance(response, tuple) else response.get_json()
        
        if result_data.get('success'):
            stats = result_data.get('stats', {})
            flash(f"Upload complete: {stats.get('files_queued', 0)} files queued for processing", 'success')
        else:
            flash(f"Upload failed: {result_data.get('error', 'Unknown error')}", 'error')
        
        return redirect(url_for('view_case', case_id=case_id))
    
    return render_template('upload_files.html', case=case)

# OLD UPLOAD TEMPLATE - DELETED, NOW USING templates/upload_files.html
def _old_upload_template():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Upload Files - {{ case.name }}</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; background: #1a1a1a; color: #fff; }
            .header { background: #2a2a2a; padding: 20px; border-bottom: 2px solid #0066cc; }
            .container { padding: 30px; max-width: 900px; margin: 0 auto; }
            .upload-box { background: #2a2a2a; padding: 40px; border-radius: 8px; border: 2px dashed #444; }
            input[type="file"] { display: none; }
            .btn { background: #0066cc; color: white; padding: 12px 24px; border-radius: 5px; border: none; cursor: pointer; font-size: 16px; display: inline-block; margin: 10px; transition: all 0.3s; }
            .btn:hover { background: #0052a3; }
            .btn:disabled { background: #444; cursor: not-allowed; }
            .btn-secondary { background: #444; }
            .btn-secondary:hover { background: #555; }
            .upload-info { color: #999; margin: 20px 0; font-size: 14px; }
            .file-list { margin-top: 30px; text-align: left; }
            .file-item { background: #333; padding: 15px; border-radius: 5px; margin-bottom: 10px; }
            .file-name { font-weight: bold; margin-bottom: 5px; word-break: break-all; }
            .file-size { color: #999; font-size: 12px; margin-bottom: 8px; }
            .progress-bar { background: #222; height: 24px; border-radius: 4px; overflow: hidden; position: relative; }
            .progress-fill { background: linear-gradient(90deg, #0066cc, #0088ff); height: 100%; transition: width 0.3s; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: bold; }
            .progress-text { position: absolute; width: 100%; text-align: center; line-height: 24px; font-size: 12px; z-index: 1; }
            .status { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 11px; margin-left: 10px; }
            .status-uploading { background: #0066cc; }
            .status-success { background: #28a745; }
            .status-error { background: #dc3545; }
            .upload-stats { display: flex; gap: 20px; justify-content: center; margin-top: 20px; padding: 15px; background: #333; border-radius: 5px; }
            .stat { text-align: center; }
            .stat-value { font-size: 24px; font-weight: bold; color: #0066cc; }
            .stat-label { font-size: 12px; color: #999; margin-top: 5px; }
            .alert { padding: 15px; border-radius: 5px; margin-bottom: 20px; }
            .alert-info { background: #1f3a5f; border-left: 4px solid #0066cc; }
            .alert-warning { background: #5f471f; border-left: 4px solid #ffaa00; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 Upload Files - {{ case.name }}</h1>
        </div>
        
        <div class="container">
            <div id="chunkedUploadSection">
            <div class="upload-box">
                    <h2 style="margin-bottom: 20px;">⚡ Upload Files</h2>
                    <p class="upload-info">
                        Supports: EVTX, JSON, NDJSON, ZIP<br>
                        <strong>Features:</strong> Real-time progress, chunked upload for large files
                    </p>
                    
                    <input type="file" id="chunkedFileInput" multiple accept=".evtx,.json,.ndjson,.zip">
                    <label for="chunkedFileInput" class="btn">Choose Files</label>
                    <button onclick="startChunkedUpload()" class="btn" id="startUploadBtn" disabled>Start Upload</button>
                    <a href="{{ url_for('view_case', case_id=case.id) }}" class="btn btn-secondary">Cancel</a>
                </div>

                <div id="uploadStats" class="upload-stats" style="display: none;">
                    <div class="stat">
                        <div class="stat-value" id="filesCompleted">0</div>
                        <div class="stat-label">Files Completed</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="totalSize">0 MB</div>
                        <div class="stat-label">Total Size</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="uploadSpeed">0 MB/s</div>
                        <div class="stat-label">Upload Speed</div>
                    </div>
                </div>

                <div id="fileList" class="file-list"></div>
            </div>
        </div>
        
        <script>
            // Chunked upload
            let selectedFiles = [];
            let uploadQueue = [];
            let currentUploads = 0;
            const MAX_CONCURRENT = 2;
            const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB chunks
            let startTime = Date.now();

            document.getElementById('chunkedFileInput').addEventListener('change', function(e) {
                selectedFiles = Array.from(e.target.files);
                displayFileList();
                document.getElementById('startUploadBtn').disabled = selectedFiles.length === 0;
            });

            function displayFileList() {
                const fileList = document.getElementById('fileList');
                fileList.innerHTML = '';
                
                selectedFiles.forEach((file, index) => {
                    const div = document.createElement('div');
                    div.className = 'file-item';
                    div.id = `file-${index}`;
                    div.innerHTML = `
                        <div class="file-name">📄 ${file.name} <span class="status status-uploading" id="status-${index}">Queued</span></div>
                        <div class="file-size">${formatSize(file.size)}</div>
                        <div class="progress-bar">
                            <div class="progress-text" id="progress-text-${index}">0%</div>
                            <div class="progress-fill" id="progress-${index}" style="width: 0%;"></div>
                        </div>
                    `;
                    fileList.appendChild(div);
                });

                // Show stats
                document.getElementById('uploadStats').style.display = 'flex';
                const totalSize = selectedFiles.reduce((sum, f) => sum + f.size, 0);
                document.getElementById('totalSize').textContent = formatSize(totalSize);
            }

            function formatSize(bytes) {
                if (bytes < 1024) return bytes + ' B';
                if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
                if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
                return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
            }

            async function startChunkedUpload() {
                document.getElementById('startUploadBtn').disabled = true;
                startTime = Date.now();
                uploadQueue = selectedFiles.map((file, index) => ({ file, index }));
                processQueue();
            }

            function processQueue() {
                while (uploadQueue.length > 0 && currentUploads < MAX_CONCURRENT) {
                    const item = uploadQueue.shift();
                    currentUploads++;
                    uploadFileInChunks(item.file, item.index);
                }
            }

            async function uploadFileInChunks(file, fileIndex) {
                const uploadId = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
                const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
                
                document.getElementById(`status-${fileIndex}`).textContent = 'Uploading';
                
                try {
                    // Upload chunks
                    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                        const start = chunkIndex * CHUNK_SIZE;
                        const end = Math.min(start + CHUNK_SIZE, file.size);
                        const chunk = file.slice(start, end);
                        
                        const formData = new FormData();
                        formData.append('chunk', chunk);
                        formData.append('upload_id', uploadId);
                        formData.append('chunk_index', chunkIndex);
                        formData.append('total_chunks', totalChunks);
                        formData.append('filename', file.name);
                        
                        const response = await fetch('/case/{{ case.id }}/upload_chunk', {
                            method: 'POST',
                            body: formData
                        });
                        
                        if (!response.ok) throw new Error('Chunk upload failed');
                        
                        const progress = ((chunkIndex + 1) / totalChunks) * 100;
                        updateProgress(fileIndex, progress);
                    }
                    
                    // Finalize upload
                    document.getElementById(`status-${fileIndex}`).textContent = 'Finalizing';
                    const finalizeResponse = await fetch('/case/{{ case.id }}/finalize_upload', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ upload_id: uploadId, filename: file.name })
                    });
                    
                    if (!finalizeResponse.ok) throw new Error('Finalization failed');
                    
                    document.getElementById(`status-${fileIndex}`).textContent = 'Complete';
                    document.getElementById(`status-${fileIndex}`).className = 'status status-success';
                    
                    const completed = parseInt(document.getElementById('filesCompleted').textContent) + 1;
                    document.getElementById('filesCompleted').textContent = completed;
                    
                    updateSpeed();
                    
                } catch (error) {
                    console.error('Upload error:', error);
                    document.getElementById(`status-${fileIndex}`).textContent = 'Failed';
                    document.getElementById(`status-${fileIndex}`).className = 'status status-error';
                }
                
                currentUploads--;
                
                if (uploadQueue.length === 0 && currentUploads === 0) {
                    setTimeout(() => {
                        window.location.href = '/case/{{ case.id }}';
                    }, 2000);
                } else {
                    processQueue();
                }
            }

            function updateProgress(fileIndex, progress) {
                const progressBar = document.getElementById(`progress-${fileIndex}`);
                const progressText = document.getElementById(`progress-text-${fileIndex}`);
                progressBar.style.width = progress + '%';
                progressText.textContent = Math.round(progress) + '%';
            }

            function updateSpeed() {
                const elapsed = (Date.now() - startTime) / 1000;
                const completed = parseInt(document.getElementById('filesCompleted').textContent);
                const totalSize = selectedFiles.slice(0, completed).reduce((sum, f) => sum + f.size, 0);
                const speed = totalSize / elapsed / (1024 * 1024);
                document.getElementById('uploadSpeed').textContent = speed.toFixed(2) + ' MB/s';
            }
        </script>
    </body>
    </html>
    ''', case=case)


@app.route('/case/<int:case_id>/upload_chunk', methods=['POST'])
@login_required
def upload_chunk(case_id):
    """Receive individual file chunks for chunked uploads"""
    # Permission check: Read-only users cannot upload files
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot upload files'}), 403
    
    try:
        # Verify case exists
        case = db.session.get(Case, case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get chunk metadata
        upload_id = request.form.get('upload_id')
        chunk_index = request.form.get('chunk_index')
        total_chunks = request.form.get('total_chunks')
        filename = request.form.get('filename')
        
        if not all([upload_id, chunk_index, total_chunks, filename]):
            return jsonify({'success': False, 'error': 'Missing chunk metadata'}), 400
        
        # Get chunk data
        chunk_file = request.files.get('chunk')
        if not chunk_file:
            return jsonify({'success': False, 'error': 'No chunk data'}), 400
        
        # Create chunks directory
        chunks_dir = os.path.join('/opt/casescope/staging', f'chunks_{upload_id}')
        os.makedirs(chunks_dir, exist_ok=True)
        
        # Save chunk
        chunk_path = os.path.join(chunks_dir, f'{upload_id}_{chunk_index}')
        chunk_file.save(chunk_path)
        
        logger.info(f"[Chunk Upload] Saved chunk {chunk_index}/{total_chunks} for {filename}")
        
        return jsonify({
            'success': True,
            'chunk_index': int(chunk_index),
            'message': f'Chunk {chunk_index} received'
        })
        
    except Exception as e:
        logger.error(f"[Chunk Upload] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/case/<int:case_id>/finalize_upload', methods=['POST'])
@login_required
def finalize_upload(case_id):
    """Finalize chunked upload - assemble chunks and process"""
    # Permission check: Read-only users cannot upload files
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot upload files'}), 403
    
    try:
        data = request.get_json()
        upload_id = data.get('upload_id')
        filename = data.get('filename')
        
        if not all([upload_id, filename]):
            return jsonify({'success': False, 'error': 'Missing upload metadata'}), 400
        
        chunks_folder = os.path.join('/opt/casescope/staging', f'chunks_{upload_id}')
        
        if not os.path.exists(chunks_folder):
            return jsonify({'success': False, 'error': 'Upload chunks not found'}), 404
        
        # Use the existing chunked upload handler
        from upload_integration import handle_chunked_upload_finalize_v96
        
        response = handle_chunked_upload_finalize_v96(
            app=app,
            db=db,
            Case=Case,
            CaseFile=CaseFile,
            SkippedFile=SkippedFile,
            celery_app=celery_app,
            current_user=current_user,
            upload_id=upload_id,
            filename=filename,
            case_id=case_id,
            chunks_folder=chunks_folder
        )
        
        return response
        
    except Exception as e:
        logger.error(f"[Finalize Upload] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

@app.cli.command('init-db')
def init_db():
    """Initialize database and create default admin user"""
    db.create_all()
    
    # Create default admin user
    admin = db.session.query(User).filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@casescope.local',
            password_hash=generate_password_hash('admin'),
            full_name='Administrator',
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
        print("✓ Database initialized")
        print("✓ Default admin user created (username: admin, password: admin)")
    else:
        print("✓ Database already initialized")


@app.route('/search-instructions')
def search_instructions():
    """Display comprehensive search instructions and examples"""
    return render_template('search_instructions.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

