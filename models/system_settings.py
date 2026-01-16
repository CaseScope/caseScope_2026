"""System Settings Model for CaseScope

Stores application-wide settings as key-value pairs.
"""
from datetime import datetime
from models.database import db


class SystemSettings(db.Model):
    """System-wide settings stored as key-value pairs"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    value_type = db.Column(db.String(20), nullable=False, default='string')  # string, bool, int, json
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.String(80), nullable=True)
    
    def __repr__(self):
        return f'<SystemSettings {self.key}={self.value}>'
    
    @staticmethod
    def get(key, default=None):
        """Get a setting value by key"""
        setting = SystemSettings.query.filter_by(key=key).first()
        if not setting:
            return default
        
        # Convert based on type
        if setting.value_type == 'bool':
            return setting.value.lower() in ('true', '1', 'yes')
        elif setting.value_type == 'int':
            try:
                return int(setting.value)
            except (ValueError, TypeError):
                return default
        elif setting.value_type == 'json':
            import json
            try:
                return json.loads(setting.value)
            except (ValueError, TypeError):
                return default
        
        return setting.value
    
    @staticmethod
    def set(key, value, value_type='string', updated_by=None):
        """Set a setting value"""
        import json
        
        setting = SystemSettings.query.filter_by(key=key).first()
        
        # Convert value to string for storage
        if value_type == 'bool':
            str_value = 'true' if value else 'false'
        elif value_type == 'json':
            str_value = json.dumps(value)
        else:
            str_value = str(value) if value is not None else None
        
        if setting:
            setting.value = str_value
            setting.value_type = value_type
            setting.updated_by = updated_by
        else:
            setting = SystemSettings(
                key=key,
                value=str_value,
                value_type=value_type,
                updated_by=updated_by
            )
            db.session.add(setting)
        
        db.session.commit()
        return setting
    
    @staticmethod
    def delete(key):
        """Delete a setting"""
        setting = SystemSettings.query.filter_by(key=key).first()
        if setting:
            db.session.delete(setting)
            db.session.commit()
            return True
        return False


# Setting key constants
class SettingKeys:
    """Constants for system setting keys"""
    AI_ENABLED = 'ai_enabled'
    AI_DEFAULT_MODEL = 'ai_default_model'
    AI_GPU_INDEX = 'ai_gpu_index'
    AI_GPU_TIER = 'ai_gpu_tier'  # '8gb' or '16gb' - set during GPU detection
    
    # Worker settings
    WORKER_CONCURRENCY = 'worker_concurrency'
    WORKER_OVERRIDE_RECOMMENDED = 'worker_override_recommended'
    
    # Default timezone for new cases (IANA identifier e.g., 'America/New_York')
    DEFAULT_TIMEZONE = 'default_timezone'
    
    # OpenCTI integration settings
    OPENCTI_ENABLED = 'opencti_enabled'
    OPENCTI_URL = 'opencti_url'
    OPENCTI_API_KEY = 'opencti_api_key'
    OPENCTI_SSL_VERIFY = 'opencti_ssl_verify'
    OPENCTI_AUTO_ENRICH = 'opencti_auto_enrich'  # Auto-enrich IOCs on creation
    OPENCTI_RAG_SYNC = 'opencti_rag_sync'  # Sync attack patterns to RAG system
    
    # Logging settings
    LOG_LEVEL = 'log_level'                      # DEBUG, INFO, WARNING, ERROR
    LOG_PATH = 'log_path'                        # Base directory for logs
    LOG_RETENTION_DAYS = 'log_retention_days'    # Auto-cleanup logs older than X days
    LOG_MAX_SIZE_MB = 'log_max_size_mb'          # Max size per log file before rotation
    AUDIT_VIEW_PERMISSION = 'audit_view_permission'  # Who can view audit logs


# AI Model Configuration based on GPU VRAM
# These are system-determined, not user-editable
AI_MODEL_CONFIG = {
    # 8GB GPU configuration
    '8gb': {
        'ioc_extraction': 'qwen2.5:7b-instruct-q4_k_m',
        'rag': 'qwen2.5:7b-instruct-q4_k_m',
        'timeline': 'qwen2.5:7b-instruct-q4_k_m',
        'threat_hunting': 'mistral:7b-instruct-v0.3-q4_K_M',
    },
    # 16GB GPU configuration
    '16gb': {
        'ioc_extraction': 'qwen2.5:14b-instruct-q4_k_m',
        'rag': 'qwen2.5:14b-instruct-q5_K_M',
        'timeline': 'qwen2.5:14b-instruct-q4_k_m',
        'threat_hunting': 'qwen2.5:14b-instruct-q4_k_m',
    }
}

# Function descriptions for display
AI_FUNCTION_DESCRIPTIONS = {
    'ioc_extraction': 'IOC Extraction from EDR Reports',
    'rag': 'RAG (Retrieval Augmented Generation)',
    'timeline': 'Timeline Creation',
    'threat_hunting': 'Interactive Threat Hunting',
}


def get_ai_model_config(vram_mb):
    """Get the appropriate model configuration based on GPU VRAM
    
    Args:
        vram_mb: GPU VRAM in megabytes
    
    Returns:
        dict with model assignments for each function
    """
    if vram_mb is None:
        return None
    
    # 16GB = 16384 MB, use 14000 as threshold
    if vram_mb >= 14000:
        return AI_MODEL_CONFIG['16gb']
    else:
        return AI_MODEL_CONFIG['8gb']


def get_model_for_function(function_name, vram_mb):
    """Get the model to use for a specific AI function
    
    Args:
        function_name: One of 'ioc_extraction', 'rag', 'timeline', 'threat_hunting'
        vram_mb: GPU VRAM in megabytes
    
    Returns:
        Model name string or None if not configured
    """
    config = get_ai_model_config(vram_mb)
    if config:
        return config.get(function_name)
    return None


# Worker Settings Helpers
WORKER_OPTIONS = [2, 4, 6, 8, 10, 12, 14, 16]


def get_system_cores():
    """Get the number of CPU cores on the system"""
    import os
    return os.cpu_count() or 4


def get_worker_limits():
    """Calculate worker limits based on system cores
    
    Returns:
        dict with:
            - total_cores: Total system cores
            - recommended_max: 3/4 of cores (floor to even number, min 2)
            - absolute_max: Total cores (floor to even number, min 2)
            - default: Half of recommended max (floor to even, min 2)
    """
    total_cores = get_system_cores()
    
    # Recommended max is 3/4 of cores
    recommended_raw = int(total_cores * 0.75)
    # Floor to nearest even number from our options
    recommended_max = max(2, max([o for o in WORKER_OPTIONS if o <= recommended_raw], default=2))
    
    # Absolute max is total cores (can't exceed)
    absolute_max = max(2, max([o for o in WORKER_OPTIONS if o <= total_cores], default=2))
    
    # Default is half of recommended max
    default_raw = recommended_max // 2
    default = max(2, max([o for o in WORKER_OPTIONS if o <= default_raw], default=2))
    
    return {
        'total_cores': total_cores,
        'recommended_max': recommended_max,
        'absolute_max': absolute_max,
        'default': default
    }


def get_worker_concurrency():
    """Get the current worker concurrency setting
    
    Returns:
        int: Current concurrency value, or default if not set
    """
    limits = get_worker_limits()
    return SystemSettings.get(SettingKeys.WORKER_CONCURRENCY, limits['default'])


def get_worker_override():
    """Check if user has overridden recommended limits
    
    Returns:
        bool: True if override is enabled
    """
    return SystemSettings.get(SettingKeys.WORKER_OVERRIDE_RECOMMENDED, False)
