"""CaseScope Configuration"""
import os
from datetime import timedelta

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'casescope-dev-key-change-in-production'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://casescope:casescope@localhost/casescope'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    UPLOAD_FOLDER_WEB = os.path.join(BASE_DIR, 'uploads', 'web')
    UPLOAD_FOLDER_SFTP = os.path.join(BASE_DIR, 'uploads', 'sftp')
    STORAGE_FOLDER = os.path.join(BASE_DIR, 'storage')
    STAGING_FOLDER = os.path.join(BASE_DIR, 'staging')
    LOG_FOLDER = os.path.join(BASE_DIR, 'logs')
    BIN_FOLDER = os.path.join(BASE_DIR, 'bin')
    RULES_FOLDER = os.path.join(BASE_DIR, 'rules')
    
    # SSL
    SSL_CERT = os.environ.get('SSL_CERT') or '/opt/casescope/ssl/cert.pem'
    SSL_KEY = os.environ.get('SSL_KEY') or '/opt/casescope/ssl/key.pem'
    
    # Server
    HOST = '0.0.0.0'
    PORT = 443
    
    # ClickHouse
    CLICKHOUSE_HOST = os.environ.get('CLICKHOUSE_HOST') or 'localhost'
    CLICKHOUSE_PORT = int(os.environ.get('CLICKHOUSE_PORT', 8123))
    CLICKHOUSE_DATABASE = os.environ.get('CLICKHOUSE_DATABASE') or 'casescope'
    CLICKHOUSE_USER = os.environ.get('CLICKHOUSE_USER') or 'default'
    CLICKHOUSE_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD') or ''
    CLICKHOUSE_USE_BUFFER = True  # Use buffer table for faster ingestion
    
    # Redis / Celery
    REDIS_HOST = os.environ.get('REDIS_HOST') or 'localhost'
    REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
    REDIS_DB = int(os.environ.get('REDIS_DB', 0))
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or f'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or f'redis://localhost:6379/0'
    
    # Hayabusa Configuration
    HAYABUSA_BIN = os.environ.get('HAYABUSA_BIN') or os.path.join(BASE_DIR, 'bin', 'hayabusa')
    HAYABUSA_RULES = os.environ.get('HAYABUSA_RULES') or os.path.join(BASE_DIR, 'rules')
    HAYABUSA_PROFILE = os.environ.get('HAYABUSA_PROFILE') or 'all-field-info'
    HAYABUSA_MIN_LEVEL = os.environ.get('HAYABUSA_MIN_LEVEL') or 'informational'
    
    # Parser Configuration
    PARSER_BATCH_SIZE = int(os.environ.get('PARSER_BATCH_SIZE', 10000))
    PARSER_MAX_MFT_ENTRIES = int(os.environ.get('PARSER_MAX_MFT_ENTRIES', 100000))


class UserSettings:
    """User and Authentication Settings
    
    Central configuration for all user-related settings.
    These can be modified to adjust site behavior.
    """
    
    # Session Configuration
    SESSION_TIMEOUT_MINUTES = int(os.environ.get('SESSION_TIMEOUT_MINUTES', 30))
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    
    # Remember Me cookie duration (days)
    REMEMBER_COOKIE_DURATION = timedelta(days=int(os.environ.get('REMEMBER_COOKIE_DAYS', 7)))
    
    # Password Requirements
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = False
    
    # Login Settings
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    LOCKOUT_DURATION_MINUTES = int(os.environ.get('LOCKOUT_DURATION_MINUTES', 15))
    
    # User Defaults
    DEFAULT_ADMIN_USERNAME = 'admin'
    DEFAULT_ADMIN_PASSWORD = 'admin'
    DEFAULT_ADMIN_EMAIL = 'admin@casescope.local'
    DEFAULT_ADMIN_FULLNAME = 'System Administrator'


class PermissionLevel:
    """User Permission Levels
    
    Administrator: Full access to all features
    Analyst: Can create/modify own data, cannot delete, cannot modify other users
    Viewer: Read-only access to assigned cases only
    """
    ADMINISTRATOR = 'administrator'
    ANALYST = 'analyst'
    VIEWER = 'viewer'
    
    @classmethod
    def choices(cls):
        """Return list of permission level choices for forms"""
        return [
            (cls.ADMINISTRATOR, 'Administrator'),
            (cls.ANALYST, 'Analyst'),
            (cls.VIEWER, 'Viewer')
        ]
    
    @classmethod
    def all(cls):
        """Return all permission levels"""
        return [cls.ADMINISTRATOR, cls.ANALYST, cls.VIEWER]
