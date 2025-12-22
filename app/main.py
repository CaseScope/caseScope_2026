"""
CaseScope 2026 - Main Application
Clean, modular DFIR platform
"""

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required
import os

# Initialize Flask
app = Flask(__name__, 
            template_folder='../templates',
            static_folder='../static')

# Load config
app.config.from_object('config.Config')

# Initialize database
db = SQLAlchemy(app)

# Import models after db initialization
from models import User, Case

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.auth_login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# User loader (required by Flask-Login)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create upload directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('/opt/casescope/logs', exist_ok=True)

# ============================================================================
# AUTO-LOAD ROUTES
# ============================================================================

import importlib
import pkgutil
from pathlib import Path

# Auto-discover and register all blueprints from routes/ directory
routes_path = Path(__file__).parent / 'routes'
if routes_path.exists():
    for (_, module_name, _) in pkgutil.iter_modules([str(routes_path)]):
        try:
            module = importlib.import_module(f'routes.{module_name}')
            # Look for blueprint in module by checking known blueprint naming pattern
            blueprint_registered = False
            for attr_name in ['auth_bp', 'admin_bp', 'case_bp', 'dashboard_bp', 'settings_bp', f'{module_name}_bp']:
                if hasattr(module, attr_name):
                    attr = getattr(module, attr_name)
                    if hasattr(attr, 'name') and hasattr(attr, 'register'):
                        # This is a Blueprint
                        app.register_blueprint(attr)
                        print(f"✓ Registered blueprint: {attr.name}")
                        blueprint_registered = True
                        break
            
            if not blueprint_registered:
                # Fallback: try to find any blueprint
                for attr_name in dir(module):
                    try:
                        attr = getattr(module, attr_name)
                        if hasattr(attr, 'name') and hasattr(attr, 'register'):
                            # This is a Blueprint
                            app.register_blueprint(attr)
                            print(f"✓ Registered blueprint: {attr.name}")
                            blueprint_registered = True
                            break
                    except:
                        pass  # Skip attributes that fail to access
                        
        except Exception as e:
            print(f"✗ Failed to load routes.{module_name}: {e}")

# ============================================================================
# BASIC ROUTES
# ============================================================================

@app.route('/')
@login_required
def index():
    """Homepage - requires authentication"""
    return render_template('index.html')

@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'ok', 'version': '2026.1.0'}

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', 
                         error_code=404, 
                         error_message='Page not found'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html',
                         error_code=500,
                         error_message='Internal server error'), 500

if __name__ == '__main__':
    # Development: Use port 5000
    # Production: Runs via Gunicorn on port 443 with SSL
    app.run(host='0.0.0.0', port=5000, debug=True)
