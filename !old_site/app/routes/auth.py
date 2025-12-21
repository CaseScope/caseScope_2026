"""
Authentication Routes
Login, logout, user management
"""

from flask import Blueprint, render_template_string, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from datetime import datetime

from models import db, User
from audit_logger import log_login, log_logout

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = db.session.query(User).filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Audit log successful login
            log_login(username, success=True, details={'role': user.role})
            
            return redirect(url_for('dashboard.index'))
        
        # Audit log failed login attempt
        log_login(username, success=False, details={'reason': 'Invalid credentials'})
        flash('Invalid username or password', 'error')
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CaseScope 2026 - Login</title>
        <style>
            body { font-family: Arial; background: #1a1a1a; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .login-box { background: #2a2a2a; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); min-width: 350px; }
            h1 { margin: 0 0 30px 0; font-size: 28px; text-align: center; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #444; background: #333; color: #fff; border-radius: 5px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin-top: 10px; }
            button:hover { background: #0052a3; }
            .error { color: #ff4444; margin-bottom: 15px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h1>🔍 CaseScope 2026</h1>
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
    ''')


@auth_bp.route('/logout')
@login_required
def logout():
    """Logout"""
    username = current_user.username
    logout_user()
    
    # Audit log logout
    log_logout(username)
    
    return redirect(url_for('auth.login'))

