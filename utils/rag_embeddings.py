"""RAG Embeddings for CaseScope

Provides embedding model management for semantic search.
Uses sentence-transformers with all-MiniLM-L6-v2 (runs on CPU).
"""

import logging
from typing import List, Optional, Union
import numpy as np

from config import Config

logger = logging.getLogger(__name__)

# Module-level model cache
_embedding_model = None


def get_embedding_model():
    """Get or create the embedding model instance
    
    Uses all-MiniLM-L6-v2 by default (384 dimensions, fast, CPU-friendly).
    Model is cached at module level for reuse.
    
    Returns:
        SentenceTransformer model instance
    """
    global _embedding_model
    
    if _embedding_model is None:
        try:
            from sentence_transformers import SentenceTransformer
            
            model_name = Config.EMBEDDING_MODEL
            logger.info(f"[RAG] Loading embedding model: {model_name}")
            
            _embedding_model = SentenceTransformer(model_name)
            logger.info(f"[RAG] Embedding model loaded successfully")
            
        except ImportError:
            logger.error("[RAG] sentence-transformers not installed. Run: pip install sentence-transformers")
            raise
        except Exception as e:
            logger.error(f"[RAG] Failed to load embedding model: {e}")
            raise
    
    return _embedding_model


def embed_text(text: str) -> List[float]:
    """Generate embedding for a single text string
    
    Args:
        text: Text to embed
        
    Returns:
        List of floats (embedding vector)
    """
    model = get_embedding_model()
    embedding = model.encode(text, convert_to_numpy=True)
    return embedding.tolist()


def embed_texts(texts: List[str], batch_size: int = 32) -> List[List[float]]:
    """Generate embeddings for multiple texts
    
    Args:
        texts: List of texts to embed
        batch_size: Batch size for encoding
        
    Returns:
        List of embedding vectors
    """
    if not texts:
        return []
    
    model = get_embedding_model()
    embeddings = model.encode(
        texts,
        batch_size=batch_size,
        show_progress_bar=False,
        convert_to_numpy=True
    )
    return embeddings.tolist()


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


def health_check() -> dict:
    """Check embedding model health
    
    Returns:
        Dict with status and model info
    """
    try:
        model = get_embedding_model()
        
        # Test embedding
        test_embedding = embed_text("test")
        
        return {
            'status': 'healthy',
            'model': Config.EMBEDDING_MODEL,
            'dimension': len(test_embedding),
            'device': str(model.device) if hasattr(model, 'device') else 'unknown'
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }
