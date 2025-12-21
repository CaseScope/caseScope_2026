"""
Administrator Routes
User management, audit logs, and system settings
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from functools import wraps
import logging

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(f):
    """Decorator to require administrator role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'administrator':
            flash('Administrator access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/settings')
@admin_required
def settings():
    """System settings page"""
    return render_template('admin/settings.html')


@admin_bp.route('/users')
@admin_required
def users():
    """User management page"""
    from main import db
    from models import User
    
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


@admin_bp.route('/audit-log')
@admin_required
def audit_log():
    """Audit log viewer"""
    from main import db
    from models import AuditLog
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Filters
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    
    # Build query
    query = AuditLog.query
    
    if action_filter:
        query = query.filter(AuditLog.action.ilike(f'%{action_filter}%'))
    
    if user_filter:
        query = query.filter(AuditLog.username.ilike(f'%{user_filter}%'))
    
    # Order by most recent first
    query = query.order_by(AuditLog.timestamp.desc())
    
    # Paginate
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/audit_log.html', 
                         logs=pagination.items,
                         pagination=pagination,
                         action_filter=action_filter,
                         user_filter=user_filter)
