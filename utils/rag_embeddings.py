"""RAG Embeddings for CaseScope

Provides embedding model management for semantic search.
Uses sentence-transformers with all-MiniLM-L6-v2.
Supports GPU acceleration (CUDA) for faster processing.

Thread-safety:
- Model initialization uses double-checked locking
- LRU cache access is protected by a dedicated lock
- GPU access is serialized via semaphore to prevent CUDA errors
"""

import logging
import threading
import hashlib
from typing import List, Optional, Union, Dict, Any
from functools import lru_cache
import numpy as np

from config import Config

logger = logging.getLogger(__name__)

# Thread-safe model management
_embedding_model = None
_embedding_lock = threading.Lock()

# Thread-safe LRU cache access
# Python's lru_cache is NOT thread-safe, so we wrap with a lock
_cache_lock = threading.Lock()

# GPU access semaphore - serializes GPU operations to prevent CUDA errors
# Under high concurrency, multiple threads trying to use GPU simultaneously
# can cause CUDA out-of-memory or race conditions
_gpu_semaphore = threading.Semaphore(1)

# LRU cache for embeddings (avoids recomputing similar queries)
_embedding_cache_size = 1000


def get_embedding_model():
    """Get or create the embedding model instance (thread-safe)
    
    Uses all-MiniLM-L6-v2 by default (384 dimensions).
    Loads on GPU (CUDA) if configured and available, falls back to CPU.
    Model is cached at module level for reuse.
    
    Returns:
        SentenceTransformer model instance
    """
    global _embedding_model
    
    if _embedding_model is None:
        with _embedding_lock:
            # Double-check after acquiring lock
            if _embedding_model is None:
                try:
                    from sentence_transformers import SentenceTransformer
                    
                    model_name = Config.EMBEDDING_MODEL
                    device = getattr(Config, 'EMBEDDING_DEVICE', 'cpu')
                    
                    # Check CUDA availability if GPU requested
                    if device == 'cuda':
                        try:
                            import torch
                            if not torch.cuda.is_available():
                                logger.warning("[RAG] CUDA requested but not available, falling back to CPU")
                                device = 'cpu'
                            else:
                                gpu_name = torch.cuda.get_device_name(0)
                                logger.info(f"[RAG] Using GPU: {gpu_name}")
                        except ImportError:
                            logger.warning("[RAG] PyTorch not available, falling back to CPU")
                            device = 'cpu'
                    
                    logger.info(f"[RAG] Loading embedding model: {model_name} on {device}")
                    
                    _embedding_model = SentenceTransformer(model_name, device=device)
                    logger.info(f"[RAG] Embedding model loaded successfully on {device}")
                    
                except ImportError:
                    logger.error("[RAG] sentence-transformers not installed. Run: pip install sentence-transformers")
                    raise
                except Exception as e:
                    logger.error(f"[RAG] Failed to load embedding model: {e}")
                    raise
    
    return _embedding_model


def _compute_text_hash(text: str) -> str:
    """Compute hash for cache key"""
    return hashlib.md5(text.encode('utf-8')).hexdigest()


# LRU cache for single text embeddings
# Note: Access to this cache MUST be protected by _cache_lock
@lru_cache(maxsize=_embedding_cache_size)
def _cached_embed_text_internal(text_hash: str, text: str) -> tuple:
    """Internal cached embedding computation (returns tuple for hashability)
    
    WARNING: This function is NOT thread-safe on its own.
    Always access through embed_text() which handles locking.
    """
    model = get_embedding_model()
    # Use GPU semaphore to serialize GPU access
    with _gpu_semaphore:
        embedding = model.encode(text, convert_to_numpy=True)
    return tuple(embedding.tolist())


def embed_text(text: str, use_cache: bool = True) -> List[float]:
    """Generate embedding for a single text string (thread-safe)
    
    Thread-safety is ensured by:
    - Cache lock protecting LRU cache access
    - GPU semaphore serializing CUDA operations
    
    Args:
        text: Text to embed
        use_cache: Whether to use LRU cache (default True)
        
    Returns:
        List of floats (embedding vector)
    """
    if not text or not text.strip():
        # Return zero vector for empty text
        model = get_embedding_model()
        dim = model.get_sentence_embedding_dimension()
        return [0.0] * dim
    
    if use_cache:
        text_hash = _compute_text_hash(text)
        # Protect LRU cache access with lock
        with _cache_lock:
            return list(_cached_embed_text_internal(text_hash, text))
    else:
        model = get_embedding_model()
        # Serialize GPU access
        with _gpu_semaphore:
            embedding = model.encode(text, convert_to_numpy=True)
        return embedding.tolist()


def embed_texts(texts: List[str], batch_size: int = None) -> List[List[float]]:
    """Generate embeddings for multiple texts (batched, GPU-optimized, thread-safe)
    
    Uses GPU semaphore to prevent concurrent CUDA access which can cause
    memory errors or race conditions.
    
    Args:
        texts: List of texts to embed
        batch_size: Batch size for encoding (defaults to Config.EMBEDDING_BATCH_SIZE)
        
    Returns:
        List of embedding vectors
    """
    if not texts:
        return []
    
    if batch_size is None:
        batch_size = getattr(Config, 'EMBEDDING_BATCH_SIZE', 128)
    
    model = get_embedding_model()
    
    # Serialize GPU access for batch encoding
    with _gpu_semaphore:
        embeddings = model.encode(
            texts,
            batch_size=batch_size,
            show_progress_bar=False,
            convert_to_numpy=True
        )
    return embeddings.tolist()


def clear_embedding_cache():
    """Clear the embedding LRU cache (thread-safe)"""
    with _cache_lock:
        _cached_embed_text_internal.cache_clear()
    logger.info("[RAG] Embedding cache cleared")


def get_cache_stats() -> Dict[str, Any]:
    """Get embedding cache statistics (thread-safe)"""
    with _cache_lock:
        info = _cached_embed_text_internal.cache_info()
    return {
        'hits': info.hits,
        'misses': info.misses,
        'size': info.currsize,
        'maxsize': info.maxsize,
        'hit_rate': info.hits / (info.hits + info.misses) if (info.hits + info.misses) > 0 else 0
    }


def embed_pattern(pattern) -> List[float]:
    """Generate embedding for an attack pattern
    
    Creates a rich text representation of the pattern for embedding.
    
    Args:
        pattern: AttackPattern model instance
        
    Returns:
        Embedding vector
    """
    # Build rich text representation
    parts = [
        f"Attack Pattern: {pattern.name}",
        f"Category: {pattern.mitre_tactic or 'Unknown'}",
        f"MITRE Technique: {pattern.mitre_technique or 'Unknown'}",
    ]
    
    if pattern.description:
        parts.append(f"Description: {pattern.description}")
    
    if pattern.required_event_ids:
        parts.append(f"Event IDs: {', '.join(pattern.required_event_ids)}")
    
    if pattern.required_channels:
        parts.append(f"Channels: {', '.join(pattern.required_channels)}")
    
    text = "\n".join(parts)
    return embed_text(text)


def embed_event_context(events: List[dict]) -> List[float]:
    """Generate embedding for a group of events (context)
    
    Used for finding related events or matching to patterns.
    
    Args:
        events: List of event dictionaries
        
    Returns:
        Single embedding vector representing the event context
    """
    # Build context text from events
    context_parts = []
    
    for event in events[:10]:  # Limit to avoid too long text
        parts = []
        
        if event.get('event_id'):
            parts.append(f"EventID:{event['event_id']}")
        if event.get('channel'):
            parts.append(f"Channel:{event['channel']}")
        if event.get('rule_title'):
            parts.append(f"Rule:{event['rule_title']}")
        if event.get('username'):
            parts.append(f"User:{event['username']}")
        if event.get('process_name'):
            parts.append(f"Process:{event['process_name']}")
        
        if parts:
            context_parts.append(" ".join(parts))
    
    context_text = "\n".join(context_parts)
    return embed_text(context_text)


def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Calculate cosine similarity between two vectors
    
    Args:
        vec1: First embedding vector
        vec2: Second embedding vector
        
    Returns:
        Similarity score between -1 and 1
    """
    a = np.array(vec1)
    b = np.array(vec2)
    
    dot_product = np.dot(a, b)
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    
    if norm_a == 0 or norm_b == 0:
        return 0.0
    
    return float(dot_product / (norm_a * norm_b))


def get_embedding_dimension() -> int:
    """Get the dimension of the embedding model
    
    Returns:
        Embedding dimension (384 for all-MiniLM-L6-v2)
    """
    model = get_embedding_model()
    return model.get_sentence_embedding_dimension()


def check_embedding_normalization(embedding: List[float]) -> Dict[str, Any]:
    """Check if embedding is properly normalized (unit vector)
    
    Normalized embeddings have L2 norm ≈ 1.0, which is required for
    cosine similarity to work correctly in Qdrant.
    
    Args:
        embedding: Embedding vector to check
        
    Returns:
        Dict with normalization status
    """
    norm = np.linalg.norm(np.array(embedding))
    is_normalized = 0.99 < norm < 1.01  # Allow small floating point variance
    
    return {
        'l2_norm': float(norm),
        'is_normalized': is_normalized,
        'warning': None if is_normalized else f'Embedding not normalized (L2={norm:.4f}). Cosine similarity may be inaccurate.'
    }


def health_check() -> dict:
    """Check embedding model health and normalization
    
    Returns:
        Dict with status and model info including normalization check
    """
    try:
        model = get_embedding_model()
        
        # Test embedding
        test_embedding = embed_text("test query for embedding validation")
        
        # Check normalization
        norm_check = check_embedding_normalization(test_embedding)
        
        # Test pattern embedding (different input type)
        class MockPattern:
            name = "Test Pattern"
            mitre_tactic = "Credential Access"
            mitre_technique = "T1003"
            description = "Test description for pattern embedding"
            required_event_ids = ['4624', '4625']
            required_channels = ['Security']
        
        pattern_embedding = embed_pattern(MockPattern())
        pattern_norm_check = check_embedding_normalization(pattern_embedding)
        
        return {
            'status': 'healthy',
            'model': Config.EMBEDDING_MODEL,
            'dimension': len(test_embedding),
            'device': str(model.device) if hasattr(model, 'device') else 'unknown',
            'text_embedding': {
                'l2_norm': norm_check['l2_norm'],
                'normalized': norm_check['is_normalized']
            },
            'pattern_embedding': {
                'l2_norm': pattern_norm_check['l2_norm'],
                'normalized': pattern_norm_check['is_normalized']
            },
            'warnings': [w for w in [norm_check.get('warning'), pattern_norm_check.get('warning')] if w]
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }
