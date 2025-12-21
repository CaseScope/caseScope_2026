"""
CaseScope 2026 - User Configuration
Adjust these settings as needed for your deployment
"""

import os

# ============================================================================
# WEB SERVER SETTINGS (User Adjustable)
# ============================================================================

# Web server port (default: 443 for HTTPS)
# Change to 80 for HTTP, or any custom port
# Note: Ports below 1024 require root/capabilities
WEB_SERVER_PORT = 443

# Web server host (0.0.0.0 = all interfaces)
WEB_SERVER_HOST = '0.0.0.0'

# Number of Gunicorn worker processes
# Recommended: 2-4 x CPU cores
WEB_WORKERS = 4

# Request timeout in seconds
WEB_TIMEOUT = 300

# ============================================================================
# SSL/TLS SETTINGS (User Adjustable)
# ============================================================================

# Enable HTTPS (True = use SSL, False = HTTP only)
SSL_ENABLED = True

# SSL certificate paths (for HTTPS)
# Default: Self-signed cert in /opt/casescope/ssl/
# Production: Upload your own cert and update these paths
SSL_CERT_PATH = '/opt/casescope/ssl/cert.pem'
SSL_KEY_PATH = '/opt/casescope/ssl/key.pem'

# ============================================================================
# DATABASE SETTINGS (User Adjustable)
# ============================================================================

# PostgreSQL connection
# Format: postgresql://username:password@host/database
DATABASE_HOST = 'localhost'
DATABASE_PORT = 5432
DATABASE_NAME = 'casescope'
DATABASE_USER = 'casescope'
DATABASE_PASSWORD = 'casescope'

# Constructed connection string (do not edit)
SQLALCHEMY_DATABASE_URI = f'postgresql://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}'

# ============================================================================
# OPENSEARCH SETTINGS (User Adjustable)
# ============================================================================

# OpenSearch connection
OPENSEARCH_HOST = 'localhost'
OPENSEARCH_PORT = 9200
OPENSEARCH_USE_SSL = False

# Index prefix (do not change after initial setup)
OPENSEARCH_INDEX_PREFIX = 'case_'

# ============================================================================
# UPLOAD SETTINGS (User Adjustable)
# ============================================================================

# Upload directory
UPLOAD_FOLDER = '/opt/casescope/data/uploads'

# Maximum file upload size in MB
MAX_UPLOAD_SIZE_MB = 500

# ============================================================================
# SESSION SETTINGS (User Adjustable)
# ============================================================================

# Session timeout in seconds (default: 1 hour)
SESSION_TIMEOUT = 3600

# Secret key for session encryption
# CHANGE THIS IN PRODUCTION!
SECRET_KEY = os.environ.get('SECRET_KEY') or 'CHANGE-THIS-SECRET-KEY-IN-PRODUCTION'

# ============================================================================
# LOGGING SETTINGS (User Adjustable)
# ============================================================================

# Log directory
LOG_DIRECTORY = '/opt/casescope/logs'

# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = 'INFO'

# ============================================================================
# FLASK CONFIGURATION (Advanced - Do Not Edit Unless You Know What You're Doing)
# ============================================================================

class Config:
    """Flask configuration object"""
    
    # Flask core
    SECRET_KEY = SECRET_KEY
    
    # Database
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }
    
    # Upload
    UPLOAD_FOLDER = UPLOAD_FOLDER
    MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    
    # Session
    PERMANENT_SESSION_LIFETIME = SESSION_TIMEOUT
    SESSION_COOKIE_SECURE = SSL_ENABLED
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # OpenSearch (stored as class attributes for easy access)
    OPENSEARCH_HOST = OPENSEARCH_HOST
    OPENSEARCH_PORT = OPENSEARCH_PORT
    OPENSEARCH_USE_SSL = OPENSEARCH_USE_SSL
