"""CaseScope Application Factory"""
import json
import logging
import os
from flask import Flask, redirect, url_for, session
from flask_login import LoginManager, current_user
from config import Config, UserSettings

# Initialize Flask-Login
login_manager = LoginManager()
logger = logging.getLogger(__name__)


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _write_generated_admin_password(username: str, password: str) -> str:
    target_path = os.environ.get(
        'ADMIN_BOOTSTRAP_PASSWORD_FILE',
        os.path.join(Config.BASE_DIR, 'temp', 'generated_admin_password.txt')
    )
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, 'w') as handle:
        handle.write(f"username={username}\npassword={password}\n")
    os.chmod(target_path, 0o600)
    return target_path


def _run_schema_migrations():
    """Run schema migrations for new columns in existing tables.
    
    SQLAlchemy's create_all() doesn't add columns to existing tables,
    so we need to handle that manually.
    
    Each migration is tracked in a ``schema_migrations`` table so it
    executes exactly once, even when multiple processes (web + workers)
    call create_app() concurrently.  A PostgreSQL advisory lock prevents
    race conditions.
    """
    from models.database import db
    from sqlalchemy import text, inspect
    from sqlalchemy.orm import Session as SQLAlchemySession

    migration_connection = db.engine.connect()
    migration_session = SQLAlchemySession(bind=migration_connection)
    original_session = db.session
    db.session = migration_session

    try:
        # Keep migration work on one dedicated connection so the advisory lock
        # cannot be orphaned on an idle pooled session across intermediate commits.
        # Ensure tracking table exists
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                name VARCHAR(255) PRIMARY KEY,
                applied_at TIMESTAMP NOT NULL DEFAULT NOW()
            )
        """))
        db.session.commit()

        def _migration_applied(name):
            row = db.session.execute(
                text("SELECT 1 FROM schema_migrations WHERE name = :n"),
                {'n': name}
            ).fetchone()
            return row is not None

        def _record_migration(name):
            db.session.execute(
                text("INSERT INTO schema_migrations (name) VALUES (:n) ON CONFLICT DO NOTHING"),
                {'n': name}
            )
            db.session.commit()

        destructive_cleanup_allowed = _env_flag('ALLOW_DESTRUCTIVE_STARTUP_MIGRATIONS', default=False)

        def _finalize_case_scope_migration(table_name, drop_constraint_sql, add_constraint_sql):
            orphan_count = db.session.execute(
                text(f"SELECT count(*) FROM {table_name} WHERE case_id IS NULL")
            ).scalar() or 0

            if orphan_count:
                if not destructive_cleanup_allowed:
                    print(
                        f"Migration note: {table_name} still has {orphan_count} rows without case_id. "
                        "Set ALLOW_DESTRUCTIVE_STARTUP_MIGRATIONS=true to remove them during startup."
                    )
                    return False
                db.session.execute(text(f"DELETE FROM {table_name} WHERE case_id IS NULL"))
                db.session.commit()
                print(f"Migration: Removed orphan rows from {table_name}")

            db.session.execute(text(f"ALTER TABLE {table_name} ALTER COLUMN case_id SET NOT NULL"))
            db.session.commit()

            try:
                db.session.execute(text(drop_constraint_sql))
                db.session.commit()
            except Exception:
                db.session.rollback()

            try:
                db.session.execute(text(add_constraint_sql))
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"Migration note: {table_name} case-scoped unique constraint - {e}")

            return True

        # Acquire an advisory lock so only one process runs migrations at a time.
        db.session.execute(text("SELECT pg_advisory_lock(73946201)"))

        inspector = inspect(migration_connection)

        # --- iocs table migrations ---
        if 'iocs' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('iocs')]

            if 'match_type' not in columns and not _migration_applied('iocs_add_match_type'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE iocs ADD COLUMN match_type VARCHAR(20)"
                    ))
                    db.session.commit()
                    _record_migration('iocs_add_match_type')
                    print("Migration: Added match_type column to iocs table")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: match_type column - {e}")

            if 'sources' not in columns and not _migration_applied('iocs_add_sources'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE iocs ADD COLUMN sources JSON DEFAULT '[]'"
                    ))
                    db.session.commit()
                    _record_migration('iocs_add_sources')
                    print("Migration: Added sources column to iocs table")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: sources column - {e}")

            if not _migration_applied('iocs_add_case_id'):
                try:
                    if 'case_id' not in columns:
                        db.session.execute(text("""
                            ALTER TABLE iocs ADD COLUMN case_id INTEGER REFERENCES cases(id)
                        """))
                        db.session.commit()
                        print("Migration: Added case_id column to iocs table")

                    db.session.execute(text("""
                        UPDATE iocs SET case_id = (
                            SELECT case_id FROM ioc_cases WHERE ioc_id = iocs.id ORDER BY first_seen_in_case LIMIT 1
                        )
                    """))
                    db.session.commit()
                    print("Migration: Populated case_id from ioc_cases junction table")

                    finalized = _finalize_case_scope_migration(
                        'iocs',
                        "ALTER TABLE iocs DROP CONSTRAINT IF EXISTS uq_ioc_type_value",
                        """
                        ALTER TABLE iocs ADD CONSTRAINT uq_ioc_case_type_value 
                        UNIQUE (case_id, ioc_type, value_normalized)
                        """
                    )
                    if finalized:
                        print("Migration: Finalized case_id migration for iocs")
                        _record_migration('iocs_add_case_id')
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: iocs case_id column - {e}")

        # --- known_systems table migrations ---
        if 'known_systems' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('known_systems')]
            if not _migration_applied('known_systems_add_case_id'):
                try:
                    if 'case_id' not in columns:
                        db.session.execute(text("""
                            ALTER TABLE known_systems ADD COLUMN case_id INTEGER REFERENCES cases(id)
                        """))
                        db.session.commit()
                        print("Migration: Added case_id column to known_systems table")

                    db.session.execute(text("""
                        UPDATE known_systems SET case_id = (
                            SELECT case_id FROM known_system_cases 
                            WHERE system_id = known_systems.id 
                            ORDER BY first_seen_in_case LIMIT 1
                        )
                    """))
                    db.session.commit()
                    print("Migration: Populated case_id from known_system_cases junction table")

                    finalized = _finalize_case_scope_migration(
                        'known_systems',
                        "ALTER TABLE known_systems DROP CONSTRAINT IF EXISTS known_systems_hostname_key",
                        """
                        ALTER TABLE known_systems ADD CONSTRAINT uq_system_case_hostname 
                        UNIQUE (case_id, hostname)
                        """
                    )
                    if finalized:
                        print("Migration: Finalized case_id migration for known_systems")
                        _record_migration('known_systems_add_case_id')
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: known_systems case_id column - {e}")

        # --- known_users table migrations ---
        if 'known_users' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('known_users')]
            if not _migration_applied('known_users_add_case_id'):
                try:
                    if 'case_id' not in columns:
                        db.session.execute(text("""
                            ALTER TABLE known_users ADD COLUMN case_id INTEGER REFERENCES cases(id)
                        """))
                        db.session.commit()
                        print("Migration: Added case_id column to known_users table")

                    db.session.execute(text("""
                        UPDATE known_users SET case_id = (
                            SELECT case_id FROM known_user_cases 
                            WHERE user_id = known_users.id 
                            ORDER BY first_seen_in_case LIMIT 1
                        )
                    """))
                    db.session.commit()
                    print("Migration: Populated case_id from known_user_cases junction table")

                    finalized = _finalize_case_scope_migration(
                        'known_users',
                        "ALTER TABLE known_users DROP CONSTRAINT IF EXISTS known_users_sid_key",
                        """
                        ALTER TABLE known_users ADD CONSTRAINT uq_user_case_sid 
                        UNIQUE (case_id, sid)
                        """
                    )
                    if finalized:
                        print("Migration: Finalized case_id migration for known_users")
                        _record_migration('known_users_add_case_id')
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: known_users case_id column - {e}")

        # --- artifact custody / retention migrations ---
        if 'case_files' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('case_files')]
            if 'source_path' not in columns and not _migration_applied('case_files_add_source_path'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE case_files ADD COLUMN source_path VARCHAR(1024)"
                    ))
                    db.session.commit()
                    db.session.execute(text(
                        "UPDATE case_files SET source_path = file_path WHERE source_path IS NULL"
                    ))
                    db.session.commit()
                    _record_migration('case_files_add_source_path')
                    print("Migration: Added source_path column to case_files")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: case_files source_path - {e}")

            if 'retention_state' not in columns and not _migration_applied('case_files_add_retention_state'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE case_files ADD COLUMN retention_state VARCHAR(50) DEFAULT 'retained'"
                    ))
                    db.session.commit()
                    db.session.execute(text(
                        "UPDATE case_files SET retention_state = 'retained' WHERE retention_state IS NULL"
                    ))
                    db.session.commit()
                    _record_migration('case_files_add_retention_state')
                    print("Migration: Added retention_state column to case_files")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: case_files retention_state - {e}")

        if 'pcap_files' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('pcap_files')]
            if 'duplicate_of_id' not in columns and not _migration_applied('pcap_files_add_duplicate_of_id'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE pcap_files ADD COLUMN duplicate_of_id INTEGER REFERENCES pcap_files(id)"
                    ))
                    db.session.commit()
                    _record_migration('pcap_files_add_duplicate_of_id')
                    print("Migration: Added duplicate_of_id column to pcap_files")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: pcap_files duplicate_of_id - {e}")

            if 'source_path' not in columns and not _migration_applied('pcap_files_add_source_path'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE pcap_files ADD COLUMN source_path VARCHAR(1024)"
                    ))
                    db.session.commit()
                    db.session.execute(text(
                        "UPDATE pcap_files SET source_path = file_path WHERE source_path IS NULL"
                    ))
                    db.session.commit()
                    _record_migration('pcap_files_add_source_path')
                    print("Migration: Added source_path column to pcap_files")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: pcap_files source_path - {e}")

            if 'retention_state' not in columns and not _migration_applied('pcap_files_add_retention_state'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE pcap_files ADD COLUMN retention_state VARCHAR(50) DEFAULT 'retained'"
                    ))
                    db.session.commit()
                    db.session.execute(text(
                        "UPDATE pcap_files SET retention_state = 'retained' WHERE retention_state IS NULL"
                    ))
                    db.session.commit()
                    _record_migration('pcap_files_add_retention_state')
                    print("Migration: Added retention_state column to pcap_files")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: pcap_files retention_state - {e}")

        if 'evidence_file' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('evidence_file')]
            if 'duplicate_of_id' not in columns and not _migration_applied('evidence_file_add_duplicate_of_id'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE evidence_file ADD COLUMN duplicate_of_id INTEGER REFERENCES evidence_file(id)"
                    ))
                    db.session.commit()
                    _record_migration('evidence_file_add_duplicate_of_id')
                    print("Migration: Added duplicate_of_id column to evidence_file")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: evidence_file duplicate_of_id - {e}")

            if 'source_path' not in columns and not _migration_applied('evidence_file_add_source_path'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE evidence_file ADD COLUMN source_path VARCHAR(1000)"
                    ))
                    db.session.commit()
                    db.session.execute(text(
                        "UPDATE evidence_file SET source_path = file_path WHERE source_path IS NULL"
                    ))
                    db.session.commit()
                    _record_migration('evidence_file_add_source_path')
                    print("Migration: Added source_path column to evidence_file")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: evidence_file source_path - {e}")

            if 'retention_state' not in columns and not _migration_applied('evidence_file_add_retention_state'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE evidence_file ADD COLUMN retention_state VARCHAR(50) DEFAULT 'retained'"
                    ))
                    db.session.commit()
                    db.session.execute(text(
                        "UPDATE evidence_file SET retention_state = 'retained' WHERE retention_state IS NULL"
                    ))
                    db.session.commit()
                    _record_migration('evidence_file_add_retention_state')
                    print("Migration: Added retention_state column to evidence_file")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: evidence_file retention_state - {e}")

        if 'memory_jobs' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('memory_jobs')]
            if 'original_source_file' not in columns and not _migration_applied('memory_jobs_add_original_source_file'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE memory_jobs ADD COLUMN original_source_file VARCHAR(500)"
                    ))
                    db.session.commit()
                    db.session.execute(text(
                        "UPDATE memory_jobs SET original_source_file = source_file WHERE original_source_file IS NULL"
                    ))
                    db.session.commit()
                    _record_migration('memory_jobs_add_original_source_file')
                    print("Migration: Added original_source_file column to memory_jobs")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: memory_jobs original_source_file - {e}")

            if 'extracted_file_path' not in columns and not _migration_applied('memory_jobs_add_extracted_file_path'):
                try:
                    db.session.execute(text(
                        "ALTER TABLE memory_jobs ADD COLUMN extracted_file_path VARCHAR(500)"
                    ))
                    db.session.commit()
                    _record_migration('memory_jobs_add_extracted_file_path')
                    print("Migration: Added extracted_file_path column to memory_jobs")
                except Exception as e:
                    db.session.rollback()
                    print(f"Migration note: memory_jobs extracted_file_path - {e}")
    finally:
        try:
            migration_session.rollback()
        except Exception:
            pass

        try:
            migration_session.execute(text("SELECT pg_advisory_unlock(73946201)"))
            migration_session.commit()
        except Exception:
            migration_session.rollback()
        finally:
            db.session = original_session
            migration_session.close()
            migration_connection.close()


def load_version():
    """Load version info from version.json"""
    version_file = os.path.join(os.path.dirname(__file__), 'version.json')
    try:
        with open(version_file, 'r') as f:
            return json.load(f)
    except Exception as exc:
        logger.warning(f"Failed to load version metadata from {version_file}: {exc}")
        return {"version": "0.0.0", "changelog": []}


def create_app(run_startup_bootstrap: bool = True):
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
    from routes.memory import memory_bp
    from routes.pcap import pcap_bp
    from routes.network_hunting import network_hunting_bp
    from routes.analysis import analysis_bp
    from routes.activation import activation_bp
    from routes.chat import chat_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(parsing_bp)
    app.register_blueprint(noise_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(rag_bp)
    app.register_blueprint(memory_bp)
    app.register_blueprint(pcap_bp)
    app.register_blueprint(network_hunting_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(activation_bp)
    app.register_blueprint(chat_bp)
    
    # Create database tables and run startup bootstrap for the web app only
    if run_startup_bootstrap:
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
                AttackCampaign, RAGSyncLog, PatternRuleMatch,
                ChatConversationSession
            )
            from models.file_audit_log import FileAuditLog
            from models.audit_log import AuditLog
            from models.field_enhancer import FieldEnhancer, seed_field_enhancers
            from models.memory_job import MemoryJob
            from models.pcap_file import PcapFile
            from models.license import LicenseActivation, ActivationAuditLog
            db.create_all()
            
            # Run schema migrations for new columns
            _run_schema_migrations()
            
            # Seed noise filter defaults if not exists
            seed_noise_defaults()
            
            # Seed field enhancers for Windows events
            seed_field_enhancers()
            
            # Create default admin user if not exists
            from config import PermissionLevel
            
            admin = User.query.filter_by(username=UserSettings.DEFAULT_ADMIN_USERNAME).first()
            if admin is None:
                import secrets
                admin_pw = UserSettings.DEFAULT_ADMIN_PASSWORD
                generated = False
                if not admin_pw:
                    admin_pw = secrets.token_urlsafe(16)
                    generated = True
                admin = User(
                    username=UserSettings.DEFAULT_ADMIN_USERNAME,
                    full_name=UserSettings.DEFAULT_ADMIN_FULLNAME,
                    email=UserSettings.DEFAULT_ADMIN_EMAIL,
                    permission_level=PermissionLevel.ADMINISTRATOR,
                    created_by='system'
                )
                admin.set_password(admin_pw)
                db.session.add(admin)
                db.session.commit()
                if generated:
                    try:
                        password_path = _write_generated_admin_password(
                            UserSettings.DEFAULT_ADMIN_USERNAME,
                            admin_pw,
                        )
                        print(
                            f"Created admin user '{UserSettings.DEFAULT_ADMIN_USERNAME}'. "
                            f"Bootstrap password written to {password_path}."
                        )
                    except Exception as exc:
                        print(
                            f"Created admin user '{UserSettings.DEFAULT_ADMIN_USERNAME}', "
                            f"but failed to persist the generated password safely: {exc}"
                        )
                        if _env_flag('ALLOW_GENERATED_ADMIN_PASSWORD_STDOUT', default=False):
                            print(
                                f"Generated password for '{UserSettings.DEFAULT_ADMIN_USERNAME}': {admin_pw}"
                            )
                    print("*** Change this password immediately after first login.")
                else:
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
