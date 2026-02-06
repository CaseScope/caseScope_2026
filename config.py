"""CaseScope Configuration"""
import os
from datetime import timedelta

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'casescope-dev-key-change-in-production'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://casescope:casescope@localhost/casescope'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'max_overflow': 20,
    }
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    UPLOAD_FOLDER_WEB = os.path.join(BASE_DIR, 'uploads', 'web')
    UPLOAD_FOLDER_SFTP = os.path.join(BASE_DIR, 'uploads', 'sftp')
    STORAGE_FOLDER = os.path.join(BASE_DIR, 'storage')
    STAGING_FOLDER = os.path.join(BASE_DIR, 'staging')
    LOG_FOLDER = os.path.join(BASE_DIR, 'logs')
    BIN_FOLDER = os.path.join(BASE_DIR, 'bin')
    RULES_FOLDER = os.path.join(BASE_DIR, 'rules')
    
    # Evidence storage (NOT parsed - separate from processing pipeline)
    EVIDENCE_FOLDER = os.path.join(BASE_DIR, 'evidence')
    EVIDENCE_BULK_FOLDER = os.path.join(BASE_DIR, 'evidence_uploads')
    
    # PCAP file storage for Zeek analysis
    PCAP_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads', 'pcap')
    PCAP_STORAGE_FOLDER = os.path.join(STORAGE_FOLDER)  # Storage at /storage/case_uuid/pcap
    
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
    
    # RAG System Configuration
    QDRANT_HOST = os.environ.get('QDRANT_HOST', 'localhost')
    QDRANT_PORT = int(os.environ.get('QDRANT_PORT', 6333))
    QDRANT_COLLECTION_PATTERNS = 'attack_patterns'
    
    # Ollama LLM
    OLLAMA_HOST = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')
    OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'qwen2.5:14b-instruct-q5_K_M')
    
    # Embedding model configuration
    EMBEDDING_MODEL = os.environ.get('EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
    EMBEDDING_DEVICE = os.environ.get('EMBEDDING_DEVICE', 'cuda')  # 'cuda' for GPU, 'cpu' for CPU
    EMBEDDING_BATCH_SIZE = int(os.environ.get('EMBEDDING_BATCH_SIZE', 128))  # Optimal for A2 GPU
    
    # RAG Processing
    RAG_BATCH_SIZE = int(os.environ.get('RAG_BATCH_SIZE', 100))
    RAG_TIME_WINDOW_HOURS = int(os.environ.get('RAG_TIME_WINDOW_HOURS', 24))
    RAG_MAX_CONTEXT_TOKENS = int(os.environ.get('RAG_MAX_CONTEXT_TOKENS', 6000))
    RAG_MAX_CONTEXT_CHARS = int(os.environ.get('RAG_MAX_CONTEXT_CHARS', 12000))  # ~3000 tokens
    
    # Semantic Search Thresholds (centralized)
    RAG_SEMANTIC_THRESHOLD = float(os.environ.get('RAG_SEMANTIC_THRESHOLD', 0.45))  # Pattern matching
    RAG_ASK_AI_THRESHOLD = float(os.environ.get('RAG_ASK_AI_THRESHOLD', 0.40))  # Ask AI context
    RAG_PATTERN_DISCOVERY_THRESHOLD = float(os.environ.get('RAG_PATTERN_DISCOVERY_THRESHOLD', 0.40))  # Pattern discovery
    RAG_CONFIDENCE_THRESHOLD = float(os.environ.get('RAG_CONFIDENCE_THRESHOLD', 0.7))  # Legacy/general
    
    # Qdrant configuration
    QDRANT_STORAGE = os.path.join(BASE_DIR, 'qdrant')
    QDRANT_HNSW_M = int(os.environ.get('QDRANT_HNSW_M', 16))  # HNSW connections per element
    QDRANT_HNSW_EF_CONSTRUCT = int(os.environ.get('QDRANT_HNSW_EF_CONSTRUCT', 100))  # HNSW construction param
    
    # Ollama retry configuration
    OLLAMA_MAX_RETRIES = int(os.environ.get('OLLAMA_MAX_RETRIES', 3))
    OLLAMA_RETRY_DELAY = float(os.environ.get('OLLAMA_RETRY_DELAY', 1.0))  # seconds
    
    # =============================================================================
    # ENHANCED ANALYSIS SYSTEM SETTINGS
    # =============================================================================
    
    # --- Behavioral Profiling ---
    ANALYSIS_MIN_EVENTS_FOR_PROFILE = int(os.environ.get('ANALYSIS_MIN_EVENTS_FOR_PROFILE', 10))
    ANALYSIS_PEER_GROUP_MIN_SIZE = int(os.environ.get('ANALYSIS_PEER_GROUP_MIN_SIZE', 3))
    ANALYSIS_ANOMALY_Z_THRESHOLD = float(os.environ.get('ANALYSIS_ANOMALY_Z_THRESHOLD', 3.0))
    
    # --- Gap Detection: Password Spraying ---
    SPRAY_MIN_UNIQUE_USERS = int(os.environ.get('SPRAY_MIN_UNIQUE_USERS', 10))
    SPRAY_MIN_FAILURE_RATE = float(os.environ.get('SPRAY_MIN_FAILURE_RATE', 0.9))
    SPRAY_TIME_WINDOW_HOURS = int(os.environ.get('SPRAY_TIME_WINDOW_HOURS', 2))
    SPRAY_TIMING_STD_THRESHOLD = float(os.environ.get('SPRAY_TIMING_STD_THRESHOLD', 5.0))
    
    # --- Gap Detection: Brute Force ---
    BRUTE_MIN_ATTEMPTS = int(os.environ.get('BRUTE_MIN_ATTEMPTS', 20))
    BRUTE_MIN_FAILURE_RATE = float(os.environ.get('BRUTE_MIN_FAILURE_RATE', 0.95))
    BRUTE_TIME_WINDOW_HOURS = int(os.environ.get('BRUTE_TIME_WINDOW_HOURS', 1))
    BRUTE_DISTRIBUTED_THRESHOLD = int(os.environ.get('BRUTE_DISTRIBUTED_THRESHOLD', 3))
    
    # --- Pattern Analysis ---
    ANALYSIS_MAX_EVENTS_PER_PATTERN = int(os.environ.get('ANALYSIS_MAX_EVENTS_PER_PATTERN', 5000))
    ANALYSIS_HIGH_CONFIDENCE_THRESHOLD = int(os.environ.get('ANALYSIS_HIGH_CONFIDENCE_THRESHOLD', 75))
    ANALYSIS_HAYABUSA_CORRELATION_WINDOW = int(os.environ.get('ANALYSIS_HAYABUSA_CORRELATION_WINDOW', 60))
    
    # --- AI Analysis Settings ---
    AI_ANALYSIS_ENABLED = os.environ.get('AI_ANALYSIS_ENABLED', 'true').lower() == 'true'
    AI_MODEL_PRIMARY = os.environ.get('AI_MODEL_PRIMARY', 'deepseek-r1:14b')
    AI_MODEL_FALLBACK = os.environ.get('AI_MODEL_FALLBACK', 'qwen2.5:14b-instruct')
    AI_TEMPERATURE = float(os.environ.get('AI_TEMPERATURE', 0.6))
    AI_MAX_TOKENS = int(os.environ.get('AI_MAX_TOKENS', 4000))
    
    # --- OpenCTI Settings ---
    OPENCTI_ENABLED = os.environ.get('OPENCTI_ENABLED', 'true').lower() == 'true'
    OPENCTI_URL = os.environ.get('OPENCTI_URL', '')
    OPENCTI_API_KEY = os.environ.get('OPENCTI_API_KEY', '')
    OPENCTI_CACHE_TTL_HOURS = int(os.environ.get('OPENCTI_CACHE_TTL_HOURS', 24))


class UserSettings:
    """User and Authentication Settings
    
    Central configuration for all user-related settings.
    These can be modified to adjust site behavior.
    """
    
    # Session Configuration
    SESSION_TIMEOUT_MINUTES = int(os.environ.get('SESSION_TIMEOUT_MINUTES', 90))
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
