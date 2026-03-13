"""System Settings Model for CaseScope

Stores application-wide settings as key-value pairs.
"""
import base64
import hashlib
import logging
from datetime import datetime

from models.database import db

logger = logging.getLogger(__name__)
_logged_decrypt_failures = set()


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
    
    # Active provider selection
    AI_PROVIDER_TYPE = 'ai_provider_type'    # openai_compatible, openai, claude
    
    # Legacy single-provider keys (kept for backward compat)
    AI_API_URL = 'ai_api_url'
    AI_API_KEY = 'ai_api_key'
    AI_MODEL_NAME = 'ai_model_name'
    
    # Per-provider settings
    AI_COMPAT_URL = 'ai_compat_url'
    AI_COMPAT_KEY = 'ai_compat_key'
    AI_COMPAT_MODEL = 'ai_compat_model'
    AI_OPENAI_KEY = 'ai_openai_key'
    AI_OPENAI_MODEL = 'ai_openai_model'
    AI_CLAUDE_KEY = 'ai_claude_key'
    AI_CLAUDE_MODEL = 'ai_claude_model'
    
    # Per-function model overrides (empty = use the provider's default model)
    AI_COMPAT_MODEL_PATTERN = 'ai_compat_model_pattern'
    AI_COMPAT_MODEL_CHAT = 'ai_compat_model_chat'
    AI_COMPAT_MODEL_REPORT = 'ai_compat_model_report'
    AI_COMPAT_MODEL_TIMELINE = 'ai_compat_model_timeline'
    AI_COMPAT_MODEL_IOC = 'ai_compat_model_ioc'
    AI_OPENAI_MODEL_PATTERN = 'ai_openai_model_pattern'
    AI_OPENAI_MODEL_CHAT = 'ai_openai_model_chat'
    AI_OPENAI_MODEL_REPORT = 'ai_openai_model_report'
    AI_OPENAI_MODEL_TIMELINE = 'ai_openai_model_timeline'
    AI_OPENAI_MODEL_IOC = 'ai_openai_model_ioc'
    AI_CLAUDE_MODEL_PATTERN = 'ai_claude_model_pattern'
    AI_CLAUDE_MODEL_CHAT = 'ai_claude_model_chat'
    AI_CLAUDE_MODEL_REPORT = 'ai_claude_model_report'
    AI_CLAUDE_MODEL_TIMELINE = 'ai_claude_model_timeline'
    AI_CLAUDE_MODEL_IOC = 'ai_claude_model_ioc'
    
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
    
    # Folder paths
    ARCHIVE_PATH = 'archive_path'                # Path for archived cases/evidence
    ORIGINALS_PATH = 'originals_path'            # Path for original uploaded files (NDJSON, archives)


# AI Provider Types
class AIProviderType:
    OPENAI_COMPATIBLE = 'openai_compatible'
    OPENAI = 'openai'
    CLAUDE = 'claude'
    
    ALL = [OPENAI_COMPATIBLE, OPENAI, CLAUDE]
    
    LABELS = {
        OPENAI_COMPATIBLE: 'Local/OpenAI Compatible',
        OPENAI: 'OpenAI',
        CLAUDE: 'Anthropic',
    }


def _get_encryption_key():
    """Derive a Fernet key from the app SECRET_KEY."""
    from config import Config
    raw = Config.SECRET_KEY.encode('utf-8')
    digest = hashlib.sha256(raw).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_api_key(plaintext: str) -> str:
    """Encrypt an API key for storage. Returns a base64 string."""
    if not plaintext:
        return ''
    try:
        from cryptography.fernet import Fernet
        f = Fernet(_get_encryption_key())
        return f.encrypt(plaintext.encode('utf-8')).decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to encrypt API key: {e}")
        return ''


def _looks_like_fernet_token(value: str) -> bool:
    """Best-effort check for Fernet-encrypted values stored as strings."""
    if not value:
        return False
    return value.startswith('gAAAA')


def _is_local_compat_endpoint(url: str) -> bool:
    """Return True for local OpenAI-compatible endpoints that don't need auth."""
    if not url:
        return True
    normalized = url.strip().lower()
    return (
        normalized.startswith('http://127.0.0.1')
        or normalized.startswith('http://localhost')
        or normalized.startswith('http://0.0.0.0')
    )


def decrypt_api_key(ciphertext: str, *, log_errors: bool = True,
                    allow_plaintext_fallback: bool = True) -> str:
    """Decrypt a stored API key.

    Plaintext legacy values are returned as-is when allowed. This keeps
    older installations functional while avoiding noisy decrypt failures
    on values that were never encrypted.
    """
    if not ciphertext:
        return ''

    token = ciphertext.strip()
    if allow_plaintext_fallback and not _looks_like_fernet_token(token):
        return token

    try:
        from cryptography.fernet import Fernet
        f = Fernet(_get_encryption_key())
        return f.decrypt(token.encode('utf-8')).decode('utf-8')
    except Exception as e:
        if log_errors:
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            if token_hash not in _logged_decrypt_failures:
                _logged_decrypt_failures.add(token_hash)
                logger.warning(f"Failed to decrypt API key: {e}")
        return ''


def mask_api_key(key: str) -> str:
    """Mask an API key for safe display (e.g., sk-...xxxx)."""
    if not key or len(key) < 8:
        return '****'
    return key[:3] + '...' + key[-4:]


def get_ai_provider_settings(include_all_keys: bool = False) -> dict:
    """Get all AI provider settings as a dict.
    
    Returns per-provider settings plus the active provider's resolved
    api_url / api_key / model_name for use by the LLM factory.
    Callers displaying keys to users should use mask_api_key().
    """
    provider_type = SystemSettings.get(
        SettingKeys.AI_PROVIDER_TYPE, AIProviderType.OPENAI_COMPATIBLE)
    if provider_type == 'local':
        provider_type = AIProviderType.OPENAI_COMPATIBLE

    # Per-provider settings (fall back to legacy keys for migration)
    compat_url = (SystemSettings.get(SettingKeys.AI_COMPAT_URL, '')
                  or SystemSettings.get(SettingKeys.AI_API_URL, '')
                  or 'http://127.0.0.1:11434')
    compat_key_enc = (SystemSettings.get(SettingKeys.AI_COMPAT_KEY, '')
                      or (SystemSettings.get(SettingKeys.AI_API_KEY, '')
                          if provider_type == AIProviderType.OPENAI_COMPATIBLE else ''))
    compat_model = (SystemSettings.get(SettingKeys.AI_COMPAT_MODEL, '')
                    or (SystemSettings.get(SettingKeys.AI_MODEL_NAME, '')
                        if provider_type == AIProviderType.OPENAI_COMPATIBLE else ''))

    openai_key_enc = SystemSettings.get(SettingKeys.AI_OPENAI_KEY, '')
    openai_model = SystemSettings.get(SettingKeys.AI_OPENAI_MODEL, '')

    claude_key_enc = SystemSettings.get(SettingKeys.AI_CLAUDE_KEY, '')
    claude_model = SystemSettings.get(SettingKeys.AI_CLAUDE_MODEL, '')

    compat_key = ''
    openai_key = ''
    claude_key = ''

    if provider_type == AIProviderType.OPENAI_COMPATIBLE or include_all_keys:
        compat_log_errors = (
            provider_type == AIProviderType.OPENAI_COMPATIBLE
            and not _is_local_compat_endpoint(compat_url)
        )
        compat_key = decrypt_api_key(
            compat_key_enc,
            log_errors=compat_log_errors,
        )
    if provider_type == AIProviderType.OPENAI or include_all_keys:
        openai_key = decrypt_api_key(
            openai_key_enc,
            log_errors=(provider_type == AIProviderType.OPENAI),
        )
    if provider_type == AIProviderType.CLAUDE or include_all_keys:
        claude_key = decrypt_api_key(
            claude_key_enc,
            log_errors=(provider_type == AIProviderType.CLAUDE),
        )

    # Resolve active provider's settings
    if provider_type == AIProviderType.OPENAI:
        api_url, api_key, model_name = '', openai_key, openai_model
    elif provider_type == AIProviderType.CLAUDE:
        api_url, api_key, model_name = '', claude_key, claude_model
    else:
        api_url, api_key, model_name = compat_url, compat_key, compat_model

    # Per-function model overrides
    compat_fn = {
        'pattern_matching': SystemSettings.get(SettingKeys.AI_COMPAT_MODEL_PATTERN, ''),
        'chat':             SystemSettings.get(SettingKeys.AI_COMPAT_MODEL_CHAT, ''),
        'report':           SystemSettings.get(SettingKeys.AI_COMPAT_MODEL_REPORT, ''),
        'timeline':         SystemSettings.get(SettingKeys.AI_COMPAT_MODEL_TIMELINE, ''),
        'ioc_extraction':   SystemSettings.get(SettingKeys.AI_COMPAT_MODEL_IOC, ''),
    }
    openai_fn = {
        'pattern_matching': SystemSettings.get(SettingKeys.AI_OPENAI_MODEL_PATTERN, ''),
        'chat':             SystemSettings.get(SettingKeys.AI_OPENAI_MODEL_CHAT, ''),
        'report':           SystemSettings.get(SettingKeys.AI_OPENAI_MODEL_REPORT, ''),
        'timeline':         SystemSettings.get(SettingKeys.AI_OPENAI_MODEL_TIMELINE, ''),
        'ioc_extraction':   SystemSettings.get(SettingKeys.AI_OPENAI_MODEL_IOC, ''),
    }
    claude_fn = {
        'pattern_matching': SystemSettings.get(SettingKeys.AI_CLAUDE_MODEL_PATTERN, ''),
        'chat':             SystemSettings.get(SettingKeys.AI_CLAUDE_MODEL_CHAT, ''),
        'report':           SystemSettings.get(SettingKeys.AI_CLAUDE_MODEL_REPORT, ''),
        'timeline':         SystemSettings.get(SettingKeys.AI_CLAUDE_MODEL_TIMELINE, ''),
        'ioc_extraction':   SystemSettings.get(SettingKeys.AI_CLAUDE_MODEL_IOC, ''),
    }

    if provider_type == AIProviderType.OPENAI:
        function_models = openai_fn
    elif provider_type == AIProviderType.CLAUDE:
        function_models = claude_fn
    else:
        function_models = compat_fn

    return {
        'provider_type': provider_type,
        'api_url': api_url,
        'api_key': api_key,
        'model_name': model_name,
        'ai_enabled': SystemSettings.get(SettingKeys.AI_ENABLED, False),
        'gpu_tier': SystemSettings.get(SettingKeys.AI_GPU_TIER, '8gb'),
        'compat_url': compat_url,
        'compat_key': compat_key,
        'compat_model': compat_model,
        'openai_key': openai_key,
        'openai_model': openai_model,
        'claude_key': claude_key,
        'claude_model': claude_model,
        'function_models': function_models,
        'compat_function_models': compat_fn,
        'openai_function_models': openai_fn,
        'claude_function_models': claude_fn,
    }


def save_ai_provider_settings(provider_type: str,
                               compat_url: str = '', compat_key: str = '',
                               compat_model: str = '',
                               openai_key: str = '', openai_model: str = '',
                               claude_key: str = '', claude_model: str = '',
                               compat_function_models: dict = None,
                               openai_function_models: dict = None,
                               claude_function_models: dict = None,
                               updated_by: str = None):
    """Persist per-provider AI settings. Encrypts API keys before storage."""
    SystemSettings.set(SettingKeys.AI_PROVIDER_TYPE, provider_type,
                       value_type='string', updated_by=updated_by)

    # Local/OpenAI Compatible
    SystemSettings.set(SettingKeys.AI_COMPAT_URL, compat_url or 'http://127.0.0.1:11434',
                       value_type='string', updated_by=updated_by)
    if compat_key:
        SystemSettings.set(SettingKeys.AI_COMPAT_KEY, encrypt_api_key(compat_key),
                           value_type='string', updated_by=updated_by)
    SystemSettings.set(SettingKeys.AI_COMPAT_MODEL, compat_model,
                       value_type='string', updated_by=updated_by)

    # OpenAI
    if openai_key:
        SystemSettings.set(SettingKeys.AI_OPENAI_KEY, encrypt_api_key(openai_key),
                           value_type='string', updated_by=updated_by)
    SystemSettings.set(SettingKeys.AI_OPENAI_MODEL, openai_model,
                       value_type='string', updated_by=updated_by)

    # Anthropic
    if claude_key:
        SystemSettings.set(SettingKeys.AI_CLAUDE_KEY, encrypt_api_key(claude_key),
                           value_type='string', updated_by=updated_by)
    SystemSettings.set(SettingKeys.AI_CLAUDE_MODEL, claude_model,
                       value_type='string', updated_by=updated_by)

    # Per-function model overrides
    _FN_KEY_MAP = {
        'compat': {
            'pattern_matching': SettingKeys.AI_COMPAT_MODEL_PATTERN,
            'chat':             SettingKeys.AI_COMPAT_MODEL_CHAT,
            'report':           SettingKeys.AI_COMPAT_MODEL_REPORT,
            'timeline':         SettingKeys.AI_COMPAT_MODEL_TIMELINE,
            'ioc_extraction':   SettingKeys.AI_COMPAT_MODEL_IOC,
        },
        'openai': {
            'pattern_matching': SettingKeys.AI_OPENAI_MODEL_PATTERN,
            'chat':             SettingKeys.AI_OPENAI_MODEL_CHAT,
            'report':           SettingKeys.AI_OPENAI_MODEL_REPORT,
            'timeline':         SettingKeys.AI_OPENAI_MODEL_TIMELINE,
            'ioc_extraction':   SettingKeys.AI_OPENAI_MODEL_IOC,
        },
        'claude': {
            'pattern_matching': SettingKeys.AI_CLAUDE_MODEL_PATTERN,
            'chat':             SettingKeys.AI_CLAUDE_MODEL_CHAT,
            'report':           SettingKeys.AI_CLAUDE_MODEL_REPORT,
            'timeline':         SettingKeys.AI_CLAUDE_MODEL_TIMELINE,
            'ioc_extraction':   SettingKeys.AI_CLAUDE_MODEL_IOC,
        },
    }
    for prefix, fn_dict in [('compat', compat_function_models),
                             ('openai', openai_function_models),
                             ('claude', claude_function_models)]:
        if fn_dict:
            for fn_name, setting_key in _FN_KEY_MAP[prefix].items():
                SystemSettings.set(setting_key, fn_dict.get(fn_name, ''),
                                   value_type='string', updated_by=updated_by)

    # Keep legacy keys in sync for backward compat
    if provider_type == AIProviderType.OPENAI:
        _sync_legacy_keys('', openai_key, openai_model, updated_by)
    elif provider_type == AIProviderType.CLAUDE:
        _sync_legacy_keys('', claude_key, claude_model, updated_by)
    else:
        _sync_legacy_keys(compat_url, compat_key, compat_model, updated_by)


def _sync_legacy_keys(api_url, api_key, model_name, updated_by):
    """Write active provider's values into the legacy single-provider keys."""
    SystemSettings.set(SettingKeys.AI_API_URL, api_url or '',
                       value_type='string', updated_by=updated_by)
    if api_key:
        SystemSettings.set(SettingKeys.AI_API_KEY, encrypt_api_key(api_key),
                           value_type='string', updated_by=updated_by)
    SystemSettings.set(SettingKeys.AI_MODEL_NAME, model_name or '',
                       value_type='string', updated_by=updated_by)


# AI Function constants
AI_FUNCTIONS = ['pattern_matching', 'chat', 'report', 'timeline', 'ioc_extraction']

AI_FUNCTION_LABELS = {
    'pattern_matching': 'Pattern Matching',
    'chat': 'Chat',
    'report': 'DFIR Reports',
    'timeline': 'Timelines',
    'ioc_extraction': 'IOC Extraction',
}

# Legacy config kept for backward compat with ioc_extractor fallback
AI_MODEL_CONFIG = {
    '8gb': {
        'ioc_extraction': 'qwen2.5:7b-instruct-q4_k_m',
        'rag': 'qwen2.5:7b-instruct-q4_k_m',
        'timeline': 'qwen2.5:7b-instruct-q4_k_m',
        'threat_hunting': 'mistral:7b-instruct-v0.3-q4_K_M',
    },
    '16gb': {
        'ioc_extraction': 'qwen2.5:14b-instruct-q4_k_m',
        'rag': 'qwen2.5:14b-instruct-q5_K_M',
        'timeline': 'qwen2.5:14b-instruct-q4_k_m',
        'threat_hunting': 'qwen2.5:14b-instruct-q4_k_m',
    }
}


def get_model_for_function(function_name: str) -> str:
    """Get the user-configured model for an AI function.

    Args:
        function_name: One of 'pattern_matching', 'chat', 'report', 'timeline'

    Returns:
        Model name string, or empty string if the user hasn't set an override
        (caller should fall back to the provider's default model).
    """
    settings = get_ai_provider_settings()
    fn_models = settings.get('function_models', {})
    return fn_models.get(function_name, '')


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
