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

# Session timeout in hours (default: 8 hours)
SESSION_TIMEOUT_HOURS = 8

# Session timeout in seconds (calculated from hours)
SESSION_TIMEOUT = SESSION_TIMEOUT_HOURS * 3600

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
# CELERY / TASK QUEUE SETTINGS (User Adjustable)
# ============================================================================

# Celery broker (message queue) - Options: 'redis' or 'rabbitmq'
# Redis is simpler and sufficient for most deployments
# RabbitMQ is more robust for high-volume production environments
CELERY_BROKER_TYPE = 'redis'

# Redis settings (if using Redis as broker)
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None  # Set to None if no password, or 'your_password'

# RabbitMQ settings (if using RabbitMQ as broker)
RABBITMQ_HOST = 'localhost'
RABBITMQ_PORT = 5672
RABBITMQ_USER = 'casescope'
RABBITMQ_PASSWORD = 'casescope'
RABBITMQ_VHOST = 'casescope'

# Celery worker settings
CELERY_WORKERS = 8  # Number of concurrent workers (auto-tuned on startup, default: 8)
CELERY_MAX_TASKS_PER_CHILD = 1000  # Restart worker after N tasks (prevents memory leaks)
CELERY_TASK_TIME_LIMIT = None  # Task hard timeout in seconds (None = no limit, user can cancel via UI)
CELERY_TASK_SOFT_TIME_LIMIT = None  # Task soft timeout in seconds (None = no limit)

# Parallel processing within tasks (uses OpenSearch slice scrolling)
# Each long-running task (IOC hunt, SIGMA hunt, noise tagging) uses multiple threads internally
TASK_PARALLEL_PERCENTAGE = 50  # Use 50% of CELERY_WORKERS for internal parallelism
TASK_PARALLEL_MIN = 2          # Minimum parallel slices (even on small systems)
TASK_PARALLEL_MAX = 8          # Maximum parallel slices (prevents over-threading)

# Performance tuning for large files
CELERY_WORKER_PREFETCH_MULTIPLIER = 2  # How many tasks to prefetch per worker
CELERY_TASK_ACKS_LATE = True  # Acknowledge tasks after completion (prevents task loss)
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000  # Same as CELERY_MAX_TASKS_PER_CHILD

# Celery result backend - where to store task results
# Options: 'redis', 'database', 'none'
# 'redis' = fast, temporary storage (recommended)
# 'database' = permanent storage in PostgreSQL
# 'none' = don't store results (saves resources)
CELERY_RESULT_BACKEND = 'redis'

# Task prefetch settings (helps prevent worker overload)
# Lower values = better load distribution, higher values = better performance
CELERY_PREFETCH_MULTIPLIER = 1  # CRITICAL: Always 1 for fair distribution!

# Task acknowledgement - when to mark task as received
# True = after task starts (safer, prevents task loss)
# False = before task starts (faster, but can lose tasks if worker crashes)
CELERY_TASK_ACKS_LATE = True  # CRITICAL: Prevents task loss on worker crash!

# Retry failed tasks automatically
CELERY_TASK_REJECT_ON_WORKER_LOST = True  # CRITICAL: Re-queue tasks if worker crashes!

# Result expiration (prevents Redis bloat)
# CRITICAL: Without this, Redis accumulates task metadata indefinitely (celery-task-meta-* keys)
CELERY_RESULT_EXPIRES = 86400  # 24 hours in seconds (clean up old results)

# OpenSearch bulk indexing settings (prevents timeouts)
# These are critical for avoiding Celery/OpenSearch issues
OPENSEARCH_BULK_CHUNK_SIZE = 500  # Events per bulk request (lower = safer, higher = faster)
OPENSEARCH_BULK_TIMEOUT = 60  # Seconds to wait for bulk operation
OPENSEARCH_REQUEST_TIMEOUT = 30  # Seconds to wait for single request
OPENSEARCH_MAX_RETRIES = 3  # Number of retries on failure

# OpenSearch index settings (field limits for forensic datasets)
# Forensic data can have hundreds/thousands of dynamic fields from event logs
# Default OpenSearch limit is 5000, which is insufficient for large cases
OPENSEARCH_TOTAL_FIELDS_LIMIT = 50000  # Maximum number of fields per index (default: 5000)
OPENSEARCH_NESTED_FIELDS_LIMIT = 500   # Maximum number of nested fields (default: 100)

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


# ============================================================================
# CELERY CONFIGURATION (Advanced - Do Not Edit Unless You Know What You're Doing)
# ============================================================================

class CeleryConfig:
    """Celery configuration object"""
    
    # Broker URL construction
    if CELERY_BROKER_TYPE == 'redis':
        if REDIS_PASSWORD:
            broker_url = f'redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}'
        else:
            broker_url = f'redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}'
    elif CELERY_BROKER_TYPE == 'rabbitmq':
        broker_url = f'amqp://{RABBITMQ_USER}:{RABBITMQ_PASSWORD}@{RABBITMQ_HOST}:{RABBITMQ_PORT}/{RABBITMQ_VHOST}'
    else:
        raise ValueError(f"Invalid CELERY_BROKER_TYPE: {CELERY_BROKER_TYPE}")
    
    # Result backend URL construction
    if CELERY_RESULT_BACKEND == 'redis':
        if REDIS_PASSWORD:
            result_backend = f'redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}'
        else:
            result_backend = f'redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}'
    elif CELERY_RESULT_BACKEND == 'database':
        result_backend = SQLALCHEMY_DATABASE_URI
    elif CELERY_RESULT_BACKEND == 'none':
        result_backend = None
    else:
        raise ValueError(f"Invalid CELERY_RESULT_BACKEND: {CELERY_RESULT_BACKEND}")
    
    # Task settings
    task_serializer = 'json'
    accept_content = ['json']
    result_serializer = 'json'
    timezone = 'UTC'
    enable_utc = True
    task_track_started = True  # Track task start and state changes
    result_expires = 3600  # Results expire after 1 hour
    
    # Worker settings
    worker_prefetch_multiplier = CELERY_PREFETCH_MULTIPLIER
    worker_max_tasks_per_child = CELERY_MAX_TASKS_PER_CHILD
    
    # Task execution settings
    task_acks_late = CELERY_TASK_ACKS_LATE
    task_reject_on_worker_lost = CELERY_TASK_REJECT_ON_WORKER_LOST
    task_time_limit = CELERY_TASK_TIME_LIMIT  # None = no limit
    task_soft_time_limit = CELERY_TASK_SOFT_TIME_LIMIT  # None = no limit
    
    # Result backend settings
    result_expires = CELERY_RESULT_EXPIRES  # 24 hours - prevents Redis bloat!
    result_persistent = False  # Don't persist results to disk
    
    # Broker connection settings (prevents connection issues)
    broker_connection_retry = True
    broker_connection_retry_on_startup = True
    broker_connection_max_retries = 10
    
    # Task routing (can define different queues for different task types)
    task_routes = {
        'tasks.process_uploaded_files': {'queue': 'file_processing'},
        'tasks.ingest_staged_file': {'queue': 'ingestion'},
        'tasks.ingest_all_staged_files': {'queue': 'ingestion'},
    }
    
    # Task priority settings
    task_default_priority = 5
    
    # Logging
    worker_log_format = '[%(asctime)s: %(levelname)s/%(processName)s] %(message)s'
    worker_task_log_format = '[%(asctime)s: %(levelname)s/%(processName)s] [%(task_name)s(%(task_id)s)] %(message)s'


# ============================================================================
# AI / LLM SETTINGS (User Adjustable)
# ============================================================================

# Master AI toggle - Set to False to disable all AI features
# When disabled:
#   - AI routes will return 404
#   - AI UI elements will be hidden
#   - No AI dependencies loaded
#   - Saves resources (no Ollama/embedding models loaded)
AI_ENABLED = True

# Auto-detect AI availability on startup (recommended)
# If True and AI_ENABLED=True, will check if Ollama/models are available
# and gracefully disable AI if not found (prevents crashes)
AI_AUTO_DETECT = True

# Ollama connection
OLLAMA_HOST = 'http://localhost:11434'

# Models (Q5_K_M quantization optimized for Tesla A2 16GB VRAM)
# Tesla A2: 7B Q5_K_M provides better quality than Q4 with same speed
# 14B models are 3.3x slower on A2 due to 60W TDP limitation
# For CPU-only systems, use: 'qwen2.5:3b'
LLM_MODEL_CHAT = 'qwen2.5:7b-instruct-q5_k_m'      # Chat and analysis (Q5 = better quality)
LLM_MODEL_CODE = 'qwen2.5-coder:7b-instruct-q5_k_m' # DSL generation (Q5 = better accuracy)

# Embedding model (runs on CPU via FastEmbed)
EMBEDDING_MODEL = 'BAAI/bge-small-en-v1.5'

# Vector store settings (uses PostgreSQL + pgvector)
VECTOR_STORE_CONFIG = {
    'host': DATABASE_HOST,
    'port': DATABASE_PORT,
    'database': DATABASE_NAME,
    'user': DATABASE_USER,
    'password': DATABASE_PASSWORD
}

# Sigma rules path
SIGMA_RULES_PATH = '/opt/casescope/data/sigma/sigma/rules'
MITRE_ATTACK_PATH = '/opt/casescope/data/sigma/mitre_attack.json'

# AI query settings
AI_MAX_CONTEXT_EVENTS = 50  # Max events to include in LLM context
AI_RAG_TOP_K = 5            # Number of patterns to retrieve from vector store

