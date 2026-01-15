"""CaseScope Application Factory"""
import json
import os
from flask import Flask, redirect, url_for, session
from flask_login import LoginManager, current_user
from config import Config, UserSettings

# Initialize Flask-Login
login_manager = LoginManager()


def _run_schema_migrations():
    """Run schema migrations for new columns in existing tables.
    
    SQLAlchemy's create_all() doesn't add columns to existing tables,
    so we need to handle that manually.
    """
    from models.database import db
    from sqlalchemy import text, inspect
    
    inspector = inspect(db.engine)
    
    # Migration: Add match_type column to iocs table
    if 'iocs' in inspector.get_table_names():
        columns = [c['name'] for c in inspector.get_columns('iocs')]
        if 'match_type' not in columns:
            try:
                db.session.execute(text(
                    "ALTER TABLE iocs ADD COLUMN match_type VARCHAR(20)"
                ))
                db.session.commit()
                print("Migration: Added match_type column to iocs table")
            except Exception as e:
                db.session.rollback()
                # Column may already exist
                print(f"Migration note: match_type column - {e}")
        
        # Migration: Add sources column to iocs table
        if 'sources' not in columns:
            try:
                db.session.execute(text(
                    "ALTER TABLE iocs ADD COLUMN sources JSON DEFAULT '[]'"
                ))
                db.session.commit()
                print("Migration: Added sources column to iocs table")
            except Exception as e:
                db.session.rollback()
                print(f"Migration note: sources column - {e}")


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
        from models.case import Case
        active_case = None
        if 'active_case_uuid' in session:
            active_case = Case.get_by_uuid(session['active_case_uuid'])
        return {
            'version': app.config['VERSION'],
            'app_name': 'caseScope 2026',
            'current_user': current_user,
            'active_case': active_case
        }
    
    # Custom Jinja2 filter for parsing EDR reports
    @app.template_filter('parse_edr_report')
    def parse_edr_report(text):
        """Parse EDR report text into structured HTML sections."""
        import re
        from markupsafe import Markup, escape
        
        if not text:
            return ''
        
        # Split by *** NEW REPORT *** separator
        reports = re.split(r'\n*\*\*\* NEW REPORT \*\*\*\n*', text)
        
        html_parts = []
        for idx, report in enumerate(reports):
            report = report.strip()
            if not report:
                continue
            
            # Add report separator for all but first report
            if idx > 0:
                html_parts.append('<div class="edr-report-separator">*** NEW REPORT ***</div>')
            
            html_parts.append('<div class="edr-report-section">')
            
            # Parse each line
            lines = report.split('\n')
            current_group = []
            in_data_block = False
            
            for line in lines:
                escaped_line = str(escape(line))
                
                # Check for key:value pattern (key is alphanumeric/spaces, followed by colon and value)
                kv_match = re.match(r'^([A-Za-z][A-Za-z0-9 _-]{0,40}):\s*(.*)$', line)
                
                if kv_match:
                    key = kv_match.group(1).strip()
                    value = kv_match.group(2).strip()
                    escaped_key = str(escape(key))
                    escaped_value = str(escape(value))
                    html_parts.append(f'<div class="edr-field"><span class="edr-key">{escaped_key}:</span> <span class="edr-value">{escaped_value}</span></div>')
                elif line.strip() == '':
                    html_parts.append('<div class="edr-spacer"></div>')
                elif line.startswith('---') or line.startswith('==='):
                    html_parts.append(f'<div class="edr-divider">{escaped_line}</div>')
                elif line.startswith('  ') or line.startswith('\t'):
                    # Indented content - treat as data/code block
                    html_parts.append(f'<div class="edr-data">{escaped_line}</div>')
                else:
                    # Regular line
                    html_parts.append(f'<div class="edr-line">{escaped_line}</div>')
            
            html_parts.append('</div>')
        
        return Markup(''.join(html_parts))
    
    # Register blueprints
    from routes.main import main_bp
    from routes.auth import auth_bp
    from routes.api import api_bp
    from routes.parsing import parsing_bp
    from routes.noise import noise_bp
    from routes.evidence import evidence_bp
    from routes.rag import rag_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(parsing_bp)
    app.register_blueprint(noise_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(rag_bp)
    
    # Create database tables
    with app.app_context():
        # Import all models so they're registered before create_all
        from models.user import User
        from models.case import Case
        from models.case_file import CaseFile
        from models.known_system import (
            KnownSystem, KnownSystemIP, KnownSystemMAC, KnownSystemAlias,
            KnownSystemShare, KnownSystemCase, KnownSystemAudit
        )
        from models.known_user import (
            KnownUser, KnownUserAlias, KnownUserEmail,
            KnownUserCase, KnownUserAudit
        )
        from models.ioc import (
            IOC, IOCSystemSighting, IOCCase, IOCAudit
        )
        from models.noise import (
            NoiseCategory, NoiseRule, NoiseRuleAudit, seed_noise_defaults
        )
        from models.system_settings import SystemSettings
        from models.event_description import EventDescription
        from models.evidence_file import EvidenceFile
        from models.rag import (
            AttackPattern, PatternPiece, PatternMatch, 
            AttackCampaign, RAGSyncLog, PatternRuleMatch
        )
        from models.file_audit_log import FileAuditLog
        from models.audit_log import AuditLog
        db.create_all()
        
        # Run schema migrations for new columns
        _run_schema_migrations()
        
        # Seed noise filter defaults if not exists
        seed_noise_defaults()
        
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
