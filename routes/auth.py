"""Authentication routes for CaseScope"""
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from models.database import db
from models.user import User
from models.audit_log import audit_login, audit_logout
from config import UserSettings

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication"""
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html', page_title='Login')
        
        user = User.query.filter_by(username=username).first()
        
        if user is None:
            flash('Invalid username or password', 'error')
            return render_template('login.html', page_title='Login')
        
        # Check if account is locked
        if user.is_account_locked():
            flash('Account is temporarily locked. Please try again later.', 'error')
            return render_template('login.html', page_title='Login')
        
        # Check if account is active
        if not user.is_active:
            flash('Account is disabled. Contact an administrator.', 'error')
            return render_template('login.html', page_title='Login')
        
        # Verify password
        if not user.check_password(password):
            user.record_failed_login()
            db.session.commit()
            audit_login(username, success=False, reason='invalid_password')
            flash('Invalid username or password', 'error')
            return render_template('login.html', page_title='Login')
        
        # Successful login
        user.record_successful_login()
        db.session.commit()
        
        login_user(user, remember=bool(remember))
        audit_login(username, success=True)
        
        # Set session expiry
        session.permanent = UserSettings.SESSION_PERMANENT
        
        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('main.index'))
    
    return render_template('login.html', page_title='Login')


@auth_bp.route('/logout')
@login_required
def logout():
    """Logout and redirect to login page"""
    username = current_user.username  # Capture before logout
    audit_logout(username)
    logout_user()
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('auth.login'))


@auth_bp.before_app_request
def check_session_timeout():
    """Check session timeout before each request"""
    if current_user.is_authenticated:
        # Update last activity timestamp
        session['last_activity'] = datetime.utcnow().isoformat()
