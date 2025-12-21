"""
Authentication Routes
Handles login, logout, and session management
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def auth_login():
    """Login page"""
    # If already logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        from main import db
        from models import User
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if user is None or not user.check_password(password):
            flash('Invalid username or password', 'error')
            logger.warning(f"Failed login attempt for username: {username}")
            return render_template('login.html')
        
        if not user.is_active:
            flash('Account is disabled. Contact an administrator.', 'error')
            logger.warning(f"Login attempt for disabled account: {username}")
            return render_template('login.html')
        
        # Log in the user
        login_user(user, remember=remember)
        
        # Update last login timestamp
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"User logged in: {username} (role: {user.role})")
        flash(f'Welcome back, {user.full_name or user.username}!', 'success')
        
        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('index'))
    
    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def auth_logout():
    """Logout"""
    username = current_user.username
    logout_user()
    logger.info(f"User logged out: {username}")
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.auth_login'))
