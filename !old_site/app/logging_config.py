"""
CaseScope 2026 - Logging Configuration
Centralized logging setup with separate log files per component
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

# Log directory (use existing logs folder)
LOG_DIR = '/opt/casescope/logs'

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Log file paths
LOG_FILES = {
    'cases': os.path.join(LOG_DIR, 'cases.log'),
    'files': os.path.join(LOG_DIR, 'files.log'),
    'workers': os.path.join(LOG_DIR, 'workers.log'),
    'app': os.path.join(LOG_DIR, 'app.log'),
    'api': os.path.join(LOG_DIR, 'api.log'),
    'dfir_iris': os.path.join(LOG_DIR, 'dfir_iris.log'),
    'opencti': os.path.join(LOG_DIR, 'opencti.log'),
}

# Log format
LOG_FORMAT = '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Max log file size (10MB) and backup count
MAX_BYTES = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5


def get_log_level_from_settings():
    """Get log level from SystemSettings table, default to INFO"""
    try:
        from models import SystemSettings
        from main import db
        
        log_level_setting = SystemSettings.query.filter_by(setting_key='log_level').first()
        if log_level_setting:
            level = log_level_setting.setting_value.upper()
            return getattr(logging, level, logging.INFO)
    except Exception:
        pass
    
    return logging.INFO


def create_rotating_handler(log_file, formatter):
    """Create a rotating file handler"""
    handler = RotatingFileHandler(
        log_file,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding='utf-8'
    )
    handler.setFormatter(formatter)
    return handler


def setup_logging(log_level=None):
    """
    Setup logging configuration with separate log files
    
    Args:
        log_level: Override log level (DEBUG, INFO, WARNING, ERROR)
                  If None, reads from SystemSettings
    """
    # Get log level
    if log_level is None:
        log_level = get_log_level_from_settings()
    elif isinstance(log_level, str):
        log_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler (for systemd/journald)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)
    
    # ========================================================================
    # CASE LOGGER - Case management operations
    # ========================================================================
    case_logger = logging.getLogger('cases')
    case_logger.setLevel(log_level)
    case_logger.handlers.clear()
    case_logger.addHandler(create_rotating_handler(LOG_FILES['cases'], formatter))
    case_logger.propagate = False
    
    # ========================================================================
    # FILE LOGGER - File operations (upload, index, process)
    # ========================================================================
    file_logger = logging.getLogger('files')
    file_logger.setLevel(log_level)
    file_logger.handlers.clear()
    file_logger.addHandler(create_rotating_handler(LOG_FILES['files'], formatter))
    file_logger.propagate = False
    
    # ========================================================================
    # WORKER LOGGER - Celery worker operations
    # ========================================================================
    worker_logger = logging.getLogger('celery')
    worker_logger.setLevel(log_level)
    worker_logger.handlers.clear()
    worker_logger.addHandler(create_rotating_handler(LOG_FILES['workers'], formatter))
    worker_logger.propagate = False
    
    # ========================================================================
    # APP LOGGER - Flask application (routes, requests, etc)
    # ========================================================================
    app_logger = logging.getLogger('app')
    app_logger.setLevel(log_level)
    app_logger.handlers.clear()
    app_logger.addHandler(create_rotating_handler(LOG_FILES['app'], formatter))
    app_logger.propagate = False
    
    # ========================================================================
    # API LOGGER - External API calls and integrations
    # ========================================================================
    api_logger = logging.getLogger('api')
    api_logger.setLevel(log_level)
    api_logger.handlers.clear()
    api_logger.addHandler(create_rotating_handler(LOG_FILES['api'], formatter))
    api_logger.propagate = False
    
    # ========================================================================
    # DFIR-IRIS LOGGER - DFIR-IRIS integration logs
    # ========================================================================
    dfir_logger = logging.getLogger('dfir_iris')
    dfir_logger.setLevel(log_level)
    dfir_logger.handlers.clear()
    dfir_logger.addHandler(create_rotating_handler(LOG_FILES['dfir_iris'], formatter))
    dfir_logger.propagate = False
    
    # ========================================================================
    # OPENCTI LOGGER - OpenCTI integration logs
    # ========================================================================
    opencti_logger = logging.getLogger('opencti')
    opencti_logger.setLevel(log_level)
    opencti_logger.handlers.clear()
    opencti_logger.addHandler(create_rotating_handler(LOG_FILES['opencti'], formatter))
    opencti_logger.propagate = False
    
    # Log startup message
    root_logger.info(f"=== CaseScope Logging Initialized (Level: {logging.getLevelName(log_level)}) ===")
    root_logger.info(f"Log directory: {LOG_DIR}")
    root_logger.info(f"Log files created: {', '.join(LOG_FILES.keys())}")


def get_logger(name):
    """
    Get a logger for a specific component
    
    Args:
        name: Logger name (cases, files, workers, app, api, dfir_iris, opencti)
    
    Returns:
        logging.Logger instance
    
    Usage:
        from logging_config import get_logger
        logger = get_logger('cases')
        logger.info('Case created')
    """
    return logging.getLogger(name)


def update_log_level(new_level):
    """
    Update log level for all loggers dynamically
    
    Args:
        new_level: New log level (DEBUG, INFO, WARNING, ERROR)
    """
    if isinstance(new_level, str):
        new_level = getattr(logging, new_level.upper(), logging.INFO)
    
    # Update all loggers
    logging.getLogger().setLevel(new_level)
    logging.getLogger('cases').setLevel(new_level)
    logging.getLogger('files').setLevel(new_level)
    logging.getLogger('celery').setLevel(new_level)
    logging.getLogger('app').setLevel(new_level)
    logging.getLogger('api').setLevel(new_level)
    logging.getLogger('dfir_iris').setLevel(new_level)
    logging.getLogger('opencti').setLevel(new_level)
    
    logging.info(f"Log level updated to: {logging.getLevelName(new_level)}")


# ============================================================================
# USAGE EXAMPLES
# ============================================================================
"""
# In routes/cases.py:
from logging_config import get_logger
logger = get_logger('cases')

@cases_bp.route('/case/create', methods=['POST'])
def create_case():
    logger.info(f"Creating new case: {case_name}")
    # ... create case ...
    logger.debug(f"Case created with ID: {case.id}")

# In file_processing.py:
from logging_config import get_logger
logger = get_logger('files')

def index_file(file_path):
    logger.info(f"Indexing file: {file_path}")
    logger.debug(f"File size: {file_size} bytes")
    # ... index file ...
    logger.warning(f"File contains {error_count} errors")

# In tasks.py (Celery):
from logging_config import get_logger
logger = get_logger('celery')

@celery_app.task
def process_file(file_id):
    logger.info(f"Worker processing file ID: {file_id}")
    # ... process ...
    logger.error(f"Failed to process file: {error}")

# In dfir_iris.py:
from logging_config import get_logger
logger = get_logger('dfir_iris')

def sync_to_iris(case):
    logger.info(f"Syncing case {case.id} to DFIR-IRIS")
    logger.debug(f"API endpoint: {iris_url}")
    # ... sync ...
    logger.error(f"DFIR-IRIS sync failed: {error}")
"""

