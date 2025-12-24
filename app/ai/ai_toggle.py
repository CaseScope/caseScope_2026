"""
AI Feature Toggle Helper
Provides utilities to check if AI is enabled and available
"""

import logging

logger = logging.getLogger(__name__)


def is_ai_enabled():
    """
    Check if AI features are enabled in config
    Returns: bool
    """
    try:
        from app.config import AI_ENABLED
        return AI_ENABLED
    except ImportError:
        return False


def is_ai_available():
    """
    Check if AI components are actually available
    Returns: (bool, str) - (available, reason)
    """
    from app.config import AI_ENABLED, AI_AUTO_DETECT
    
    # First check if AI is enabled in config
    if not AI_ENABLED:
        return False, "AI disabled in config (AI_ENABLED=False)"
    
    # If auto-detect is off, assume it's available
    if not AI_AUTO_DETECT:
        return True, "AI enabled (auto-detect disabled)"
    
    # Check Ollama
    try:
        import ollama
        ollama.list()
    except Exception as e:
        logger.warning(f"AI unavailable: Ollama error - {e}")
        return False, f"Ollama not accessible: {e}"
    
    # Check vector store
    try:
        from app.config import VECTOR_STORE_CONFIG, EMBEDDING_MODEL
        from app.ai.vector_store import PatternStore
        
        store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
        stats = store.get_stats()
        
        if stats['total_patterns'] == 0:
            logger.warning("AI unavailable: Vector store is empty")
            return False, "Vector store empty (run scripts/ingest_patterns.py)"
    except Exception as e:
        logger.warning(f"AI unavailable: Vector store error - {e}")
        return False, f"Vector store error: {e}"
    
    # All checks passed
    return True, "AI fully operational"


def require_ai(func):
    """
    Decorator for Flask routes that require AI
    Returns 404 if AI is not available
    
    Usage:
        @ai_bp.route('/query')
        @require_ai
        def ai_query():
            ...
    """
    from functools import wraps
    from flask import jsonify
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        available, reason = is_ai_available()
        if not available:
            return jsonify({
                'error': 'AI features not available',
                'reason': reason
            }), 404
        return func(*args, **kwargs)
    
    return wrapper


def get_ai_status():
    """
    Get detailed AI status for display in UI
    Returns: dict
    """
    from app.config import AI_ENABLED
    
    if not AI_ENABLED:
        return {
            'enabled': False,
            'available': False,
            'status': 'disabled',
            'message': 'AI features disabled in configuration',
            'components': {
                'ollama': False,
                'vector_store': False,
                'models': False
            }
        }
    
    components = {
        'ollama': False,
        'vector_store': False,
        'models': False
    }
    
    # Check Ollama
    try:
        import ollama
        ollama.list()
        components['ollama'] = True
    except:
        pass
    
    # Check vector store
    try:
        from app.config import VECTOR_STORE_CONFIG, EMBEDDING_MODEL
        from app.ai.vector_store import PatternStore
        
        store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
        stats = store.get_stats()
        components['vector_store'] = stats['total_patterns'] > 0
    except:
        pass
    
    # Check models
    try:
        import ollama
        from app.config import LLM_MODEL_CHAT, LLM_MODEL_CODE
        
        response = ollama.list()
        model_names = []
        if hasattr(response, 'models'):
            model_names = [m.model for m in response.models]
        
        components['models'] = any(LLM_MODEL_CHAT in name for name in model_names)
    except:
        pass
    
    all_available = all(components.values())
    
    return {
        'enabled': True,
        'available': all_available,
        'status': 'operational' if all_available else 'degraded',
        'message': 'AI features ready' if all_available else 'Some AI components unavailable',
        'components': components
    }

