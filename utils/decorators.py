"""Authentication and authorization decorators"""
from functools import wraps
from flask import redirect, url_for, flash, abort
from flask_login import current_user
from config import PermissionLevel


def admin_required(f):
    """Decorator to require administrator access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('auth.login'))
        if not current_user.is_administrator:
            flash('Administrator access required', 'error')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def analyst_required(f):
    """Decorator to require analyst or higher access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('auth.login'))
        if current_user.permission_level not in [PermissionLevel.ADMINISTRATOR, PermissionLevel.ANALYST]:
            flash('Analyst access required', 'error')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def can_delete(f):
    """Decorator to check delete permission"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('auth.login'))
        if not current_user.can_delete():
            flash('Delete permission required', 'error')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def case_access_required(case_id_param='case_id'):
    """Decorator factory to check case access permission
    
    Usage: @case_access_required('case_id')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page', 'error')
                return redirect(url_for('auth.login'))
            
            case_id = kwargs.get(case_id_param)
            if case_id is not None and not current_user.can_access_case(case_id):
                flash('You do not have access to this case', 'error')
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
