"""CaseScope Logging System

Provides centralized logging for the entire application.
Supports both global logs and case-specific logs.

Usage:
    from utils.logger import get_logger, log_file_activity, log_case_activity
    
    # Module-level logging
    logger = get_logger(__name__)
    logger.info("Something happened")
    
    # File activity logging (case-specific)
    log_file_activity(case_uuid, 'UPLOADED', 'evidence.evtx',
                      sha256='abc123', user='jdube', source='web')
    
    # Entity activity logging (case-specific)
    log_case_activity(case_uuid, 'IOC_CREATED', '192.168.1.100',
                      type='ipv4', user='jdube')
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from functools import lru_cache
from typing import Optional
import threading

# Thread-local storage for context
_context = threading.local()

# Default settings (used before DB is available)
DEFAULT_LOG_LEVEL = 'INFO'
DEFAULT_LOG_PATH = '/opt/casescope/logs'
DEFAULT_MAX_SIZE_MB = 100
DEFAULT_RETENTION_DAYS = 90

# Log level mapping
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}


# ============================================================
# Settings Cache
# ============================================================

_settings_cache = {}
_settings_cache_time = None
_CACHE_TTL_SECONDS = 60  # Refresh settings every 60 seconds


def _get_cached_settings():
    """Get logging settings with caching to avoid DB hits"""
    global _settings_cache, _settings_cache_time
    
    now = datetime.utcnow()
    
    # Return cached if still valid
    if _settings_cache_time and (now - _settings_cache_time).total_seconds() < _CACHE_TTL_SECONDS:
        return _settings_cache
    
    # Try to get from database
    try:
        from models.system_settings import SystemSettings, SettingKeys
        _settings_cache = {
            'log_level': SystemSettings.get(SettingKeys.LOG_LEVEL, DEFAULT_LOG_LEVEL),
            'log_path': SystemSettings.get(SettingKeys.LOG_PATH, DEFAULT_LOG_PATH),
            'max_size_mb': SystemSettings.get(SettingKeys.LOG_MAX_SIZE_MB, DEFAULT_MAX_SIZE_MB),
            'retention_days': SystemSettings.get(SettingKeys.LOG_RETENTION_DAYS, DEFAULT_RETENTION_DAYS),
        }
        _settings_cache_time = now
    except Exception:
        # Database not available, use defaults
        _settings_cache = {
            'log_level': DEFAULT_LOG_LEVEL,
            'log_path': DEFAULT_LOG_PATH,
            'max_size_mb': DEFAULT_MAX_SIZE_MB,
            'retention_days': DEFAULT_RETENTION_DAYS,
        }
    
    return _settings_cache


def get_log_path() -> str:
    """Get configured log directory path"""
    return _get_cached_settings().get('log_path', DEFAULT_LOG_PATH)


def get_log_level() -> str:
    """Get configured log level"""
    return _get_cached_settings().get('log_level', DEFAULT_LOG_LEVEL)


def get_log_level_int() -> int:
    """Get configured log level as integer"""
    level = get_log_level()
    return LOG_LEVELS.get(level.upper(), logging.INFO)


def invalidate_settings_cache():
    """Force refresh of settings cache (call after settings change)"""
    global _settings_cache_time
    _settings_cache_time = None


# ============================================================
# Directory Management
# ============================================================

def ensure_log_directories():
    """Create log directory structure if it doesn't exist"""
    log_path = get_log_path()
    
    dirs = [
        log_path,
        os.path.join(log_path, 'cases'),
    ]
    
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        # Ensure proper permissions (casescope user)
        try:
            import pwd
            import grp
            uid = pwd.getpwnam('casescope').pw_uid
            gid = grp.getgrnam('casescope').gr_gid
            os.chown(d, uid, gid)
        except (KeyError, PermissionError):
            pass  # User/group doesn't exist or no permission


def ensure_case_log_directory(case_uuid: str) -> str:
    """Ensure case-specific log directory exists"""
    log_path = get_log_path()
    case_log_dir = os.path.join(log_path, 'cases', case_uuid)
    runs_dir = os.path.join(case_log_dir, 'runs')
    
    os.makedirs(case_log_dir, exist_ok=True)
    os.makedirs(runs_dir, exist_ok=True)
    
    # Set permissions
    try:
        import pwd
        import grp
        uid = pwd.getpwnam('casescope').pw_uid
        gid = grp.getgrnam('casescope').gr_gid
        os.chown(case_log_dir, uid, gid)
        os.chown(runs_dir, uid, gid)
    except (KeyError, PermissionError):
        pass
    
    return case_log_dir


# ============================================================
# Logger Factory
# ============================================================

_loggers = {}


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger for a module.
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        Configured logging.Logger instance
    
    Usage:
        from utils.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Something happened")
    """
    if name in _loggers:
        return _loggers[name]
    
    logger = logging.getLogger(name)
    logger.setLevel(get_log_level_int())
    
    # Don't add handlers if already configured
    if not logger.handlers:
        # Determine which log file based on name
        if 'celery' in name.lower() or 'tasks' in name.lower():
            log_file = 'celery.log'
        elif 'ai' in name.lower() or 'rag' in name.lower() or 'ollama' in name.lower():
            log_file = 'ai.log'
        else:
            log_file = 'webserver.log'
        
        log_path = get_log_path()
        ensure_log_directories()
        
        settings = _get_cached_settings()
        max_bytes = settings.get('max_size_mb', DEFAULT_MAX_SIZE_MB) * 1024 * 1024
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            os.path.join(log_path, log_file),
            maxBytes=max_bytes,
            backupCount=5
        )
        file_handler.setLevel(get_log_level_int())
        
        # Format: timestamp | level | logger | message
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-5s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Also add error handler for ERROR+ level
        error_handler = RotatingFileHandler(
            os.path.join(log_path, 'error.log'),
            maxBytes=max_bytes,
            backupCount=10
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        logger.addHandler(error_handler)
    
    _loggers[name] = logger
    return logger


def log_error(message: str, exc_info=None, **context):
    """
    Log to error.log with optional exception info.
    
    Args:
        message: Error message
        exc_info: Exception info (True to capture current, or exception tuple)
        **context: Additional context to include
    """
    logger = get_logger('error')
    
    if context:
        context_str = ' | '.join(f'{k}={v}' for k, v in context.items())
        message = f'{message} | {context_str}'
    
    logger.error(message, exc_info=exc_info)


# ============================================================
# Case-Level File Activity Logging
# ============================================================

def log_file_activity(case_uuid: str, action: str, filename: str,
                      sha256: str = None, level: str = 'INFO', **kwargs):
    """
    Log file activity to case-specific files.log
    
    Args:
        case_uuid: Case UUID
        action: Action type (UPLOADED, QUEUED, INGESTING, DONE, ERROR, etc.)
        filename: Filename being processed
        sha256: File hash (first 12 chars shown)
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        **kwargs: Additional context (user, source, size, events, duration, etc.)
    
    Log format:
        2026-01-14 10:23:45 | INFO  | UPLOADED | evidence.evtx | sha256:abc123def456 | user:jdube | source:web
    """
    case_log_dir = ensure_case_log_directory(case_uuid)
    log_file = os.path.join(case_log_dir, 'files.log')
    
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    
    # Build log line
    parts = [
        timestamp,
        level.upper().ljust(5),
        action.upper().ljust(12),
        filename
    ]
    
    if sha256:
        # Show first 12 chars of hash
        parts.append(f'sha256:{sha256[:12]}')
    
    # Add additional context
    for key, value in kwargs.items():
        if value is not None:
            parts.append(f'{key}:{value}')
    
    log_line = ' | '.join(parts)
    
    # Write to file
    try:
        with open(log_file, 'a') as f:
            f.write(log_line + '\n')
    except Exception as e:
        # Fallback to main logger if file write fails
        get_logger('files').error(f'Failed to write to {log_file}: {e}')
        get_logger('files').info(log_line)
    
    # Also log errors to global error.log
    if level.upper() == 'ERROR':
        log_error(f'File error: {action} {filename}', case_uuid=case_uuid, **kwargs)


# ============================================================
# Case-Level Entity Activity Logging
# ============================================================

def log_case_activity(case_uuid: str, action: str, target: str,
                      level: str = 'INFO', **kwargs):
    """
    Log entity activity to case-specific activity.log
    
    Args:
        case_uuid: Case UUID
        action: Action type (IOC_CREATED, SYSTEM_LINKED, USER_CREATED, etc.)
        target: Entity being affected (IOC value, hostname, username, etc.)
        level: Log level
        **kwargs: Additional context (type, user, source, etc.)
    
    Log format:
        2026-01-14 11:00:00 | INFO  | IOC_CREATED | 192.168.1.100 | type:ipv4 | user:jdube
    """
    case_log_dir = ensure_case_log_directory(case_uuid)
    log_file = os.path.join(case_log_dir, 'activity.log')
    
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    
    # Build log line
    parts = [
        timestamp,
        level.upper().ljust(5),
        action.upper().ljust(16),
        target
    ]
    
    # Add additional context
    for key, value in kwargs.items():
        if value is not None:
            parts.append(f'{key}:{value}')
    
    log_line = ' | '.join(parts)
    
    # Write to file
    try:
        with open(log_file, 'a') as f:
            f.write(log_line + '\n')
    except Exception as e:
        get_logger('activity').error(f'Failed to write to {log_file}: {e}')
        get_logger('activity').info(log_line)
    
    # Also log errors to global error.log
    if level.upper() == 'ERROR':
        log_error(f'Activity error: {action} {target}', case_uuid=case_uuid, **kwargs)


# ============================================================
# Batch/Run Logging
# ============================================================

class RunLogger:
    """
    Context manager for detailed batch operation logging.
    
    Creates timestamped run log files for bulk operations.
    
    Usage:
        with RunLogger(case_uuid, 'bulk_upload', user='jdube') as run:
            run.log("Processing file: evidence.evtx")
            run.log("Extracted 23 files from archive")
            run.set_stats(processed=45, succeeded=43, failed=2)
    
    Creates: logs/cases/{uuid}/runs/{timestamp}_{run_type}.log
    """
    
    def __init__(self, case_uuid: str, run_type: str, **context):
        self.case_uuid = case_uuid
        self.run_type = run_type
        self.context = context
        self.start_time = None
        self.log_file = None
        self.stats = {}
        self._file = None
    
    def __enter__(self):
        self.start_time = datetime.utcnow()
        timestamp = self.start_time.strftime('%Y-%m-%d_%H%M%S')
        
        case_log_dir = ensure_case_log_directory(self.case_uuid)
        self.log_file = os.path.join(case_log_dir, 'runs', f'{timestamp}_{self.run_type}.log')
        
        self._file = open(self.log_file, 'w')
        
        # Write header
        self._file.write(f'=== {self.run_type.replace("_", " ").title()} Started ===\n')
        self._file.write(f'Time: {self.start_time.strftime("%Y-%m-%d %H:%M:%S")}\n')
        self._file.write(f'Case: {self.case_uuid}\n')
        
        for key, value in self.context.items():
            self._file.write(f'{key.replace("_", " ").title()}: {value}\n')
        
        self._file.write('\n')
        self._file.flush()
        
        return self
    
    def log(self, message: str, level: str = 'INFO'):
        """Log a step in the run"""
        if self._file:
            timestamp = datetime.utcnow().strftime('%H:%M:%S')
            level_indicator = {'ERROR': '!', 'WARNING': '?', 'DEBUG': '-'}.get(level.upper(), ' ')
            self._file.write(f'[{timestamp}]{level_indicator} {message}\n')
            self._file.flush()
    
    def set_stats(self, **stats):
        """Set summary statistics"""
        self.stats.update(stats)
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            end_time = datetime.utcnow()
            duration = (end_time - self.start_time).total_seconds()
            
            self._file.write('\n')
            self._file.write('=== Summary ===\n')
            
            # Write stats
            for key, value in self.stats.items():
                self._file.write(f'{key.replace("_", " ").title()}: {value}\n')
            
            # Duration
            if duration < 60:
                duration_str = f'{duration:.1f}s'
            elif duration < 3600:
                duration_str = f'{duration / 60:.1f}m'
            else:
                duration_str = f'{duration / 3600:.1f}h'
            self._file.write(f'Duration: {duration_str}\n')
            
            # Status
            if exc_type:
                self._file.write(f'Status: FAILED\n')
                self._file.write(f'Error: {exc_val}\n')
            else:
                self._file.write(f'Status: COMPLETED\n')
            
            self._file.close()
            self._file = None
        
        # Don't suppress exceptions
        return False


# ============================================================
# Flask Integration
# ============================================================

def setup_flask_logging(app):
    """
    Configure Flask request/response logging.
    
    Call this in create_app() to enable HTTP request logging.
    
    Usage:
        from utils.logger import setup_flask_logging
        
        def create_app():
            app = Flask(__name__)
            setup_flask_logging(app)
            ...
    """
    from flask import request, g
    import time
    
    logger = get_logger('webserver')
    
    @app.before_request
    def log_request_start():
        g.request_start_time = time.time()
        
        # Skip static files and health checks
        if request.path.startswith('/static') or request.path == '/health':
            return
        
        if get_log_level() == 'DEBUG':
            logger.debug(f'{request.method} {request.path} started')
    
    @app.after_request
    def log_request_end(response):
        # Skip static files and health checks
        if request.path.startswith('/static') or request.path == '/health':
            return response
        
        duration = 0
        if hasattr(g, 'request_start_time'):
            duration = int((time.time() - g.request_start_time) * 1000)
        
        # Get user
        try:
            from flask_login import current_user
            user = current_user.username if current_user.is_authenticated else 'anonymous'
        except Exception:
            user = 'unknown'
        
        # Log based on status code
        log_msg = f'{request.method} {request.path} {response.status_code} {duration}ms user:{user}'
        
        if response.status_code >= 500:
            logger.error(log_msg)
        elif response.status_code >= 400:
            logger.warning(log_msg)
        else:
            logger.info(log_msg)
        
        return response
    
    @app.errorhandler(Exception)
    def log_exception(error):
        logger.error(f'Unhandled exception: {error}', exc_info=True)
        raise error


# ============================================================
# Log Maintenance
# ============================================================

def cleanup_old_logs(retention_days: int = None):
    """
    Delete logs older than retention period.
    
    Args:
        retention_days: Days to keep logs (uses setting if None)
    """
    import glob
    from datetime import timedelta
    
    if retention_days is None:
        settings = _get_cached_settings()
        retention_days = settings.get('retention_days', DEFAULT_RETENTION_DAYS)
    
    log_path = get_log_path()
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    deleted_count = 0
    
    # Find all .log files
    for log_file in glob.glob(os.path.join(log_path, '**', '*.log'), recursive=True):
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(log_file))
            if mtime < cutoff_date:
                os.remove(log_file)
                deleted_count += 1
        except Exception as e:
            get_logger('maintenance').error(f'Failed to delete old log {log_file}: {e}')
    
    # Also delete rotated logs (.log.1, .log.2, etc.)
    for log_file in glob.glob(os.path.join(log_path, '**', '*.log.*'), recursive=True):
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(log_file))
            if mtime < cutoff_date:
                os.remove(log_file)
                deleted_count += 1
        except Exception as e:
            get_logger('maintenance').error(f'Failed to delete old log {log_file}: {e}')
    
    if deleted_count:
        get_logger('maintenance').info(f'Cleaned up {deleted_count} old log files')
    
    return deleted_count


def get_log_files_info(case_uuid: str = None) -> dict:
    """
    Get information about log files.
    
    Args:
        case_uuid: If provided, get case-specific logs only
    
    Returns:
        Dict with log file info
    """
    log_path = get_log_path()
    
    if case_uuid:
        base_path = os.path.join(log_path, 'cases', case_uuid)
    else:
        base_path = log_path
    
    files = []
    
    if os.path.exists(base_path):
        for root, dirs, filenames in os.walk(base_path):
            for filename in filenames:
                if filename.endswith('.log'):
                    filepath = os.path.join(root, filename)
                    stat = os.stat(filepath)
                    files.append({
                        'name': filename,
                        'path': filepath,
                        'relative_path': os.path.relpath(filepath, log_path),
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
    
    return {
        'base_path': base_path,
        'files': sorted(files, key=lambda x: x['modified'], reverse=True)
    }


def read_log_tail(log_file: str, lines: int = 100) -> list:
    """
    Read last N lines from a log file.
    
    Args:
        log_file: Path to log file
        lines: Number of lines to read
    
    Returns:
        List of log lines
    """
    try:
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
            return [line.rstrip() for line in all_lines[-lines:]]
    except Exception as e:
        return [f'Error reading log: {e}']
