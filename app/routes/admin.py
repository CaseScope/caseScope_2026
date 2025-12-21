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


def admin_or_analyst_required(f):
    """Decorator to require administrator or analyst role (no viewers)"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['administrator', 'analyst']:
            flash('Administrator or Analyst access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/settings')
@admin_required
def settings():
    """System settings page"""
    return render_template('admin/settings.html')


@admin_bp.route('/users')
@admin_or_analyst_required
def users():
    """
    User management page
    - Administrators: Can see and edit all users
    - Analysts: Can see themselves and all viewers (can edit themselves + viewers only)
    - Viewers: Cannot access (handled by decorator)
    """
    from main import db
    from models import User, Case
    
    # Filter users based on current user's role
    if current_user.role == 'administrator':
        # Administrators see everyone
        users_list = User.query.order_by(User.created_at.desc()).all()
    else:
        # Analysts see themselves and all viewers (not other analysts or administrators)
        users_list = User.query.filter(
            db.or_(
                User.id == current_user.id,  # Themselves
                User.role == 'read-only'      # All viewers
            )
        ).order_by(User.created_at.desc()).all()
    
    # Get all cases for the dropdown
    cases = Case.query.order_by(Case.name).all()
    
    return render_template('admin/users.html', users=users_list, cases=cases, current_user=current_user)


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


@admin_bp.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    """
    Create new user
    Only administrators can create users
    """
    from main import db
    from models import User
    from audit_logger import log_action
    
    try:
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        role = request.form.get('role', 'analyst')
        is_active = request.form.get('is_active') == 'true'
        case_assigned = request.form.get('case_assigned', type=int) or None
        
        # Validation
        if not username or not email or not password:
            return jsonify({'success': False, 'error': 'Username, email, and password are required'}), 400
        
        # Check for existing username
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username already exists'}), 400
        
        # Check for existing email
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already exists'}), 400
        
        # Create user
        user = User(
            username=username,
            email=email,
            full_name=full_name,
            role=role,
            is_active=is_active,
            case_assigned=case_assigned if role == 'read-only' else None
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Audit log
        log_action('create_user', resource_type='user', resource_id=user.id,
                   resource_name=username,
                   details={'role': role, 'created_by': current_user.username})
        
        return jsonify({'success': True, 'user_id': user.id})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/users/<int:user_id>/edit', methods=['POST'])
@admin_or_analyst_required
def edit_user(user_id):
    """
    Edit existing user
    - Administrators: Can edit any user
    - Analysts: Can edit themselves OR any viewer user
    """
    from main import db
    from models import User
    from audit_logger import log_action
    
    user = User.query.get_or_404(user_id)
    
    # Analysts can only edit themselves or viewers
    if current_user.role == 'analyst':
        # Check if editing themselves OR a viewer
        if user.id != current_user.id and user.role != 'read-only':
            return jsonify({'success': False, 'error': 'Analysts can only edit themselves or viewer accounts'}), 403
    
    try:
        changes = {}
        
        # Update fields
        full_name = request.form.get('full_name', '').strip()
        if full_name != user.full_name:
            changes['full_name'] = {'old': user.full_name, 'new': full_name}
            user.full_name = full_name
        
        email = request.form.get('email', '').strip()
        if email != user.email:
            # Check for duplicate email
            existing = User.query.filter(User.email == email, User.id != user_id).first()
            if existing:
                return jsonify({'success': False, 'error': 'Email already in use'}), 400
            changes['email'] = {'old': user.email, 'new': email}
            user.email = email
        
        role = request.form.get('role')
        if role and role != user.role:
            # Analysts can only change role if editing a viewer
            if current_user.role == 'analyst':
                # Analysts cannot change roles at all (to prevent escalation)
                return jsonify({'success': False, 'error': 'Analysts cannot change user roles'}), 403
            changes['role'] = {'old': user.role, 'new': role}
            user.role = role
        
        is_active = request.form.get('is_active') == 'true'
        if is_active != user.is_active:
            changes['is_active'] = {'old': user.is_active, 'new': is_active}
            user.is_active = is_active
        
        # Case assignment (for read-only users)
        case_assigned = request.form.get('case_assigned', type=int) or None
        if role == 'read-only' and case_assigned != user.case_assigned:
            changes['case_assigned'] = {'old': user.case_assigned, 'new': case_assigned}
            user.case_assigned = case_assigned
        elif role != 'read-only':
            user.case_assigned = None
        
        # Change password if provided
        password = request.form.get('password', '').strip()
        if password:
            user.set_password(password)
            changes['password'] = 'changed'
        
        db.session.commit()
        
        # Audit log
        if changes:
            log_action('modify_user', resource_type='user', resource_id=user.id,
                       resource_name=user.username,
                       details={'changes': changes, 'modified_by': current_user.username})
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error editing user {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/users/<int:user_id>/get')
@admin_or_analyst_required
def get_user(user_id):
    """Get user details for editing"""
    from models import User
    
    user = User.query.get_or_404(user_id)
    
    # Analysts can only view themselves or viewers
    if current_user.role == 'analyst':
        if user.id != current_user.id and user.role != 'read-only':
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    return jsonify({
        'success': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name or '',
            'role': user.role,
            'is_active': user.is_active,
            'case_assigned': user.case_assigned
        }
    })


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """
    Delete a user
    Only administrators can delete users
    Cannot delete yourself
    """
    from main import db
    from models import User
    from audit_logger import log_action
    
    # Cannot delete yourself
    if user_id == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400
    
    user = User.query.get_or_404(user_id)
    
    try:
        username = user.username
        user_role = user.role
        
        db.session.delete(user)
        db.session.commit()
        
        # Audit log
        log_action('delete_user', resource_type='user', resource_id=user_id,
                   resource_name=username,
                   details={'role': user_role, 'deleted_by': current_user.username})
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
