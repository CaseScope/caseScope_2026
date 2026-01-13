"""RAG Vector Store for CaseScope

Provides Qdrant vector database integration for semantic search.
"""

import logging
from typing import List, Dict, Any, Optional

from config import Config

logger = logging.getLogger(__name__)

# Module-level client cache
_qdrant_client = None


def get_qdrant_client():
    """Get or create the Qdrant client instance
    
    Returns:
        QdrantClient instance
    """
    global _qdrant_client
    
    if _qdrant_client is None:
        try:
            from qdrant_client import QdrantClient
            
            logger.info(f"[RAG] Connecting to Qdrant at {Config.QDRANT_HOST}:{Config.QDRANT_PORT}")
            
            _qdrant_client = QdrantClient(
                host=Config.QDRANT_HOST,
                port=Config.QDRANT_PORT,
                timeout=30.0
            )
            
            logger.info("[RAG] Qdrant client connected")
            
        except ImportError:
            logger.error("[RAG] qdrant-client not installed. Run: pip install qdrant-client")
            raise
        except Exception as e:
            logger.error(f"[RAG] Failed to connect to Qdrant: {e}")
            raise
    
    return _qdrant_client


def ensure_collection(collection_name: str, vector_size: int = 384) -> bool:
    """Ensure a collection exists, create if not
    
    Args:
        collection_name: Name of the collection
        vector_size: Dimension of vectors (384 for all-MiniLM-L6-v2)
        
    Returns:
        True if collection exists or was created
    """
    try:
        from qdrant_client.models import Distance, VectorParams
        
        client = get_qdrant_client()
        
        # Check if collection exists
        collections = client.get_collections().collections
        exists = any(c.name == collection_name for c in collections)
        
        if not exists:
            logger.info(f"[RAG] Creating collection: {collection_name}")
            client.create_collection(
                collection_name=collection_name,
                vectors_config=VectorParams(
                    size=vector_size,
                    distance=Distance.COSINE
                )
            )
            logger.info(f"[RAG] Collection created: {collection_name}")
        
        return True
        
    except Exception as e:
        logger.error(f"[RAG] Failed to ensure collection {collection_name}: {e}")
        return False


def upsert_patterns(patterns: List[Dict[str, Any]]) -> int:
    """Upsert pattern embeddings to vector store
    
    Args:
        patterns: List of pattern dicts with 'id', 'embedding', and 'payload'
        
    Returns:
        Number of patterns upserted
    """
    try:
        from qdrant_client.models import PointStruct
        
        client = get_qdrant_client()
        collection = Config.QDRANT_COLLECTION_PATTERNS
        
        # Ensure collection exists
        ensure_collection(collection)
        
        # Build points
        points = [
            PointStruct(
                id=p['id'],
                vector=p['embedding'],
                payload=p.get('payload', {})
            )
            for p in patterns
        ]
        
        # Upsert in batches
        batch_size = 100
        for i in range(0, len(points), batch_size):
            batch = points[i:i + batch_size]
            client.upsert(
                collection_name=collection,
                points=batch
            )
        
        logger.info(f"[RAG] Upserted {len(patterns)} patterns to {collection}")
        return len(patterns)
        
    except Exception as e:
        logger.error(f"[RAG] Failed to upsert patterns: {e}")
        return 0


def search_similar_patterns(
    query_vector: List[float],
    limit: int = 10,
    score_threshold: float = 0.5
) -> List[Dict[str, Any]]:
    """Search for patterns similar to query vector
    
    Args:
        query_vector: Query embedding vector
        limit: Maximum number of results
        score_threshold: Minimum similarity score
        
    Returns:
        List of matching patterns with scores
    """
    try:
        client = get_qdrant_client()
        collection = Config.QDRANT_COLLECTION_PATTERNS
        
        results = client.search(
            collection_name=collection,
            query_vector=query_vector,
            limit=limit,
            score_threshold=score_threshold
        )
        
        return [
            {
                'id': r.id,
                'score': r.score,
                'payload': r.payload
            }
            for r in results
        ]
        
    except Exception as e:
        logger.error(f"[RAG] Pattern search failed: {e}")
        return []


def delete_pattern(pattern_id: int) -> bool:
    """Delete a pattern from vector store
    
    Args:
        pattern_id: ID of pattern to delete
        
    Returns:
        True if deleted successfully
    """
    try:
        from qdrant_client.models import PointIdsList
        
        client = get_qdrant_client()
        collection = Config.QDRANT_COLLECTION_PATTERNS
        
        client.delete(
            collection_name=collection,
            points_selector=PointIdsList(points=[pattern_id])
        )
        
        logger.debug(f"[RAG] Deleted pattern {pattern_id} from vector store")
        return True
        
    except Exception as e:
        logger.error(f"[RAG] Failed to delete pattern {pattern_id}: {e}")
        return False


def get_collection_info(collection_name: str = None) -> Dict[str, Any]:
    """Get information about a collection
    
    Args:
        collection_name: Collection name (defaults to patterns collection)
        
    Returns:
        Dict with collection info
    """
    try:
        client = get_qdrant_client()
        collection = collection_name or Config.QDRANT_COLLECTION_PATTERNS
        
        info = client.get_collection(collection_name=collection)
        
        return {
            'name': collection,
            'vectors_count': info.vectors_count,
            'points_count': info.points_count,
            'status': info.status.name if info.status else 'unknown'
        }
        
    except Exception as e:
        logger.error(f"[RAG] Failed to get collection info: {e}")
        return {
            'name': collection_name,
            'error': str(e)
        }


def health_check() -> Dict[str, Any]:
    """Check Qdrant health
    
    Returns:
        Dict with status and info
    """
    try:
        client = get_qdrant_client()
        
        # Get collections
        collections = client.get_collections().collections
        
        return {
            'status': 'healthy',
            'host': Config.QDRANT_HOST,
            'port': Config.QDRANT_PORT,
            'collections': [c.name for c in collections]
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'host': Config.QDRANT_HOST,
            'port': Config.QDRANT_PORT,
            'error': str(e)
        }


def init_collections() -> bool:
    """Initialize all required collections
    
    Returns:
        True if all collections initialized
    """
    try:
        from utils.rag_embeddings import get_embedding_dimension
        
        dim = get_embedding_dimension()
        
        # Create patterns collection
        ensure_collection(Config.QDRANT_COLLECTION_PATTERNS, dim)
        
        logger.info("[RAG] All collections initialized")
        return True
        
    except Exception as e:
        logger.error(f"[RAG] Failed to initialize collections: {e}")
        return False
