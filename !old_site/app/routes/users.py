#!/usr/bin/env python3
"""
CaseScope 2026 - User Management Routes
Handles user CRUD operations with permission-based access control
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from functools import wraps
from werkzeug.security import generate_password_hash
from datetime import datetime

users_bp = Blueprint('users', __name__)


# ============================================================================
# PERMISSION DECORATORS
# ============================================================================

def analyst_required(f):
    """Require at least analyst permission (analyst or administrator)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if current_user.role not in ['analyst', 'administrator']:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Require administrator permission"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if current_user.role != 'administrator':
            flash('You must be an administrator to access this page.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def can_edit_user(target_user):
    """
    Check if current user can edit target user
    
    Rules:
    - Administrator: Can edit anyone
    - Analyst: Can edit users they created AND users of lower permission (read-only)
    - Read-Only: Cannot edit anyone
    """
    if current_user.role == 'administrator':
        return True
    
    if current_user.role == 'analyst':
        # Can edit users they created
        if target_user.created_by == current_user.id:
            return True
        # Can edit read-only users
        if target_user.role == 'read-only':
            return True
        # Cannot edit other analysts or administrators
        return False
    
    # Read-only users cannot edit anyone
    return False


# ============================================================================
# USER MANAGEMENT ROUTES
# ============================================================================

@users_bp.route('/users')
@login_required
@analyst_required
def list_users():
    """List all users (analyst and admin can view)"""
    from main import db, User
    
    users = User.query.order_by(User.created_at.desc()).all()
    
    return render_template('users_list.html',
                         users=users,
                         current_user=current_user)


@users_bp.route('/users/new', methods=['GET', 'POST'])
@login_required
@analyst_required
def create_user():
    """Create new user"""
    from main import db, User
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'read-only')
        is_active = request.form.get('is_active') == 'on'
        
        # Validation
        if not username or not email or not password:
            flash('Username, email, and password are required.', 'error')
            return redirect(url_for('users.create_user'))
        
        # Permission check: Analyst can only create read-only users
        if current_user.role == 'analyst' and role != 'read-only':
            flash('Analysts can only create read-only users.', 'error')
            return redirect(url_for('users.create_user'))
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('users.create_user'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return redirect(url_for('users.create_user'))
        
        # Create user
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            password_hash=generate_password_hash(password),
            role=role,
            is_active=is_active,
            created_by=current_user.id,
            created_at=datetime.utcnow()
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('create_user', resource_type='user', resource_id=new_user.id,
                  resource_name=username,
                  details={'role': role, 'email': email, 'is_active': is_active})
        
        flash(f'User {username} created successfully.', 'success')
        return redirect(url_for('users.list_users'))
    
    return render_template('user_edit.html',
                         user=None,
                         current_user=current_user,
                         is_new=True)


@users_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@analyst_required
def edit_user(user_id):
    """Edit existing user"""
    from main import db, User
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users.list_users'))
    
    # Permission check
    if not can_edit_user(user):
        flash('You do not have permission to edit this user.', 'error')
        return redirect(url_for('users.list_users'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        role = request.form.get('role', user.role)
        is_active = request.form.get('is_active') == 'on'
        password = request.form.get('password', '').strip()
        
        # Email validation (if changed)
        if email != user.email:
            if User.query.filter_by(email=email).first():
                flash('Email already exists.', 'error')
                return redirect(url_for('users.edit_user', user_id=user_id))
        
        # Permission check for role changes
        if current_user.role == 'analyst':
            # Analyst can only set role to read-only
            if role != 'read-only':
                flash('Analysts can only set role to read-only.', 'error')
                return redirect(url_for('users.edit_user', user_id=user_id))
        
        # Track changes
        changes = {}
        if email != user.email:
            changes['email'] = {'from': user.email, 'to': email}
        if full_name != user.full_name:
            changes['full_name'] = {'from': user.full_name, 'to': full_name}
        if role != user.role:
            changes['role'] = {'from': user.role, 'to': role}
        if is_active != user.is_active:
            changes['is_active'] = {'from': user.is_active, 'to': is_active}
        if password:
            changes['password'] = 'changed'
        
        # Update user
        user.email = email
        user.full_name = full_name
        user.role = role
        user.is_active = is_active
        
        # Update password if provided
        if password:
            user.password_hash = generate_password_hash(password)
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('edit_user', resource_type='user', resource_id=user.id,
                  resource_name=user.username, details=changes)
        
        flash(f'User {user.username} updated successfully.', 'success')
        return redirect(url_for('users.list_users'))
    
    return render_template('user_edit.html',
                         user=user,
                         current_user=current_user,
                         is_new=False,
                         can_edit=can_edit_user(user))


@users_bp.route('/users/<int:user_id>/toggle_status', methods=['POST'])
@login_required
@analyst_required
def toggle_user_status(user_id):
    """Toggle user active/inactive status"""
    from main import db, User
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Cannot deactivate yourself
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot deactivate your own account'}), 400
    
    # Permission check
    if not can_edit_user(user):
        return jsonify({'success': False, 'message': 'Permission denied'}), 403
    
    # Toggle status
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    return jsonify({
        'success': True,
        'message': f'User {user.username} {status} successfully',
        'is_active': user.is_active
    })


@users_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete user (admin only)"""
    from main import db, User
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users.list_users'))
    
    # Cannot delete yourself
    if user.id == current_user.id:
        flash('Cannot delete your own account.', 'error')
        return redirect(url_for('users.list_users'))
    
    username = user.username
    user_role = user.role
    db.session.delete(user)
    db.session.commit()
    
    # Audit log
    from audit_logger import log_action
    log_action('delete_user', resource_type='user', resource_id=user_id,
              resource_name=username, details={'role': user_role})
    
    flash(f'User {username} deleted successfully.', 'success')
    return redirect(url_for('users.list_users'))


@users_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """View and edit own profile (limited for read-only users)"""
    from main import db, User
    
    if request.method == 'POST':
        # Read-only users cannot edit their profile
        if current_user.role == 'read-only':
            flash('Read-only users cannot edit their profile.', 'error')
            return redirect(url_for('users.profile'))
        
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        password = request.form.get('password', '').strip()
        
        # Email validation (if changed)
        if email != current_user.email:
            if User.query.filter_by(email=email).first():
                flash('Email already exists.', 'error')
                return redirect(url_for('users.profile'))
        
        # Update profile
        current_user.email = email
        current_user.full_name = full_name
        
        # Update password if provided
        if password:
            current_user.password_hash = generate_password_hash(password)
        
        db.session.commit()
        
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('users.profile'))
    
    return render_template('user_profile.html', user=current_user)

