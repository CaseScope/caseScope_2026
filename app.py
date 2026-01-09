"""CaseScope Application Factory"""
import json
import os
from flask import Flask, redirect, url_for
from flask_login import LoginManager, current_user
from config import Config, UserSettings

# Initialize Flask-Login
login_manager = LoginManager()


def load_version():
    """Load version info from version.json"""
    version_file = os.path.join(os.path.dirname(__file__), 'version.json')
    try:
        with open(version_file, 'r') as f:
            return json.load(f)
    except Exception:
        return {"version": "0.0.0", "changelog": []}


def create_app():
    app = Flask(
        __name__,
        template_folder='static/templates',
        static_folder='static'
    )
    
    # Load config
    app.config.from_object('config.Config')
    
    # Session configuration
    app.config['SESSION_PERMANENT'] = UserSettings.SESSION_PERMANENT
    app.config['PERMANENT_SESSION_LIFETIME'] = UserSettings.PERMANENT_SESSION_LIFETIME
    app.config['REMEMBER_COOKIE_DURATION'] = UserSettings.REMEMBER_COOKIE_DURATION
    
    # Load version into app config
    version_data = load_version()
    app.config['VERSION'] = version_data.get('version', '0.0.0')
    app.config['CHANGELOG'] = version_data.get('changelog', [])
    
    # Initialize database
    from models.database import db
    db.init_app(app)
    
    # Initialize Flask-Login
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page'
    login_manager.login_message_category = 'error'
    
    @login_manager.user_loader
    def load_user(user_id):
        from models.user import User
        return User.query.get(int(user_id))
    
    # Context processor for templates
    @app.context_processor
    def inject_globals():
        return {
            'version': app.config['VERSION'],
            'app_name': 'caseScope 2026',
            'current_user': current_user
        }
    
    # Register blueprints
    from routes.main import main_bp
    from routes.auth import auth_bp
    from routes.api import api_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    
    # Create database tables
    with app.app_context():
        # Import all models so they're registered before create_all
        from models.user import User
        from models.case import Case
        db.create_all()
        
        # Create default admin user if not exists
        from config import PermissionLevel
        
        admin = User.query.filter_by(username=UserSettings.DEFAULT_ADMIN_USERNAME).first()
        if admin is None:
            admin = User(
                username=UserSettings.DEFAULT_ADMIN_USERNAME,
                full_name=UserSettings.DEFAULT_ADMIN_FULLNAME,
                email=UserSettings.DEFAULT_ADMIN_EMAIL,
                permission_level=PermissionLevel.ADMINISTRATOR,
                created_by='system'
            )
            admin.set_password(UserSettings.DEFAULT_ADMIN_PASSWORD)
            db.session.add(admin)
            db.session.commit()
            print(f"Created default admin user: {UserSettings.DEFAULT_ADMIN_USERNAME}")
    
    return app


# Create app instance
app = create_app()

if __name__ == '__main__':
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        ssl_context=(app.config['SSL_CERT'], app.config['SSL_KEY']),
        debug=True
    )
