"""RAG Vector Store for CaseScope

Provides Qdrant vector database integration for semantic search.
Thread-safe with optimized HNSW index configuration.
"""

import hashlib
import logging
import threading
from typing import List, Dict, Any, Optional

from config import Config

logger = logging.getLogger(__name__)

# Thread-safe client management
_qdrant_client = None
_qdrant_lock = threading.Lock()

# Payload keys that are filtered on, and so need a Qdrant payload index to avoid
# a full scan of the collection on every scope refresh.
CASE_EVENT_PAYLOAD_INDEXES = ('embedding_scope', 'embedded_at')

# The event slices that may be embedded. Shared so the API, the Celery task and
# the auto-refresh triggers cannot drift from one another.
EVENT_EMBEDDING_SCOPES = ('high_priority', 'analyst_tagged', 'ioc_tagged', 'time_range')


def get_qdrant_client():
    """Get or create the Qdrant client instance (thread-safe)
    
    Returns:
        QdrantClient instance
    """
    global _qdrant_client
    
    if _qdrant_client is None:
        with _qdrant_lock:
            # Double-check after acquiring lock
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


def ensure_collection(
    collection_name: str,
    vector_size: int = 384,
    payload_indexes: Optional[tuple] = None,
) -> bool:
    """Ensure a collection exists, create if not
    
    Creates collection with optimized HNSW index parameters from config.
    
    Args:
        collection_name: Name of the collection
        vector_size: Dimension of vectors (384 for all-MiniLM-L6-v2)
        payload_indexes: Keyword payload fields to index for filtered queries
        
    Returns:
        True if collection exists or was created
    """
    try:
        from qdrant_client.models import Distance, VectorParams, HnswConfigDiff
        
        client = get_qdrant_client()
        
        # Check if collection exists
        collections = client.get_collections().collections
        exists = any(c.name == collection_name for c in collections)
        
        if not exists:
            logger.info(f"[RAG] Creating collection: {collection_name}")
            
            # Get HNSW parameters from config
            hnsw_m = getattr(Config, 'QDRANT_HNSW_M', 16)
            hnsw_ef = getattr(Config, 'QDRANT_HNSW_EF_CONSTRUCT', 100)
            
            client.create_collection(
                collection_name=collection_name,
                vectors_config=VectorParams(
                    size=vector_size,
                    distance=Distance.COSINE
                ),
                hnsw_config=HnswConfigDiff(
                    m=hnsw_m,  # Number of connections per element
                    ef_construct=hnsw_ef,  # Size of dynamic candidate list for construction
                )
            )
            logger.info(f"[RAG] Collection created: {collection_name} (HNSW m={hnsw_m}, ef={hnsw_ef})")
        
        if payload_indexes:
            ensure_payload_indexes(collection_name, payload_indexes)
        
        return True
        
    except Exception as e:
        logger.error(f"[RAG] Failed to ensure collection {collection_name}: {e}")
        return False


def ensure_payload_indexes(collection_name: str, fields: tuple) -> None:
    """Create keyword payload indexes so filtered reads and deletes are not full scans.
    
    Creating an index that already exists is not an error worth failing a write
    over, so each field is attempted independently and logged at debug level.
    """
    from qdrant_client.models import PayloadSchemaType
    
    client = get_qdrant_client()
    
    for field in fields:
        try:
            client.create_payload_index(
                collection_name=collection_name,
                field_name=field,
                field_schema=PayloadSchemaType.KEYWORD,
            )
            logger.info(f"[RAG] Created payload index {collection_name}.{field}")
        except Exception as e:
            logger.debug(f"[RAG] Payload index {collection_name}.{field} not created: {e}")


def build_case_event_collection_name(case_id: int) -> str:
    """Return the Qdrant collection name holding one case's event vectors."""
    return f"case_{case_id}_events"


def build_event_point_id(case_id: int, scope: str, selector_key: Any) -> int:
    """Create a deterministic numeric Qdrant point ID for one case event.
    
    Keyed on selector_key, which is the only per-case unique event identifier.
    record_id is a per-file EVTX record number and is both duplicated across
    files and null for non-EVTX artifacts, so keying on it silently collapsed
    distinct events onto a shared point.
    """
    raw = f"{case_id}:{scope}:{selector_key}".encode('utf-8')
    digest = hashlib.sha1(raw).digest()
    return int.from_bytes(digest[:8], 'big') & ((1 << 63) - 1)


def search_points(
    collection_name: str,
    query_vector: List[float],
    limit: int = 10,
    score_threshold: Optional[float] = None,
    query_filter=None,
) -> List[Dict[str, Any]]:
    """Run a vector search against one collection, across qdrant-client versions.
    
    query_points replaced search in qdrant-client 1.10 and search was later
    removed outright, so calling it directly raises AttributeError on the
    installed client.
    
    Returns:
        List of dicts with 'id', 'score' and 'payload'
    """
    client = get_qdrant_client()
    
    if hasattr(client, 'query_points'):
        response = client.query_points(
            collection_name=collection_name,
            query=query_vector,
            limit=limit,
            score_threshold=score_threshold,
            query_filter=query_filter,
            with_payload=True,
        )
        results = getattr(response, 'points', response)
    else:
        results = client.search(
            collection_name=collection_name,
            query_vector=query_vector,
            limit=limit,
            score_threshold=score_threshold,
            query_filter=query_filter,
        )
    
    return [
        {
            'id': r.id,
            'score': r.score,
            'payload': r.payload,
        }
        for r in results
    ]


def collection_exists(collection_name: str) -> bool:
    """Return True when a collection is present in Qdrant."""
    client = get_qdrant_client()
    collections = client.get_collections().collections
    return any(c.name == collection_name for c in collections)


def search_case_events(
    case_id: int,
    query_vector: List[float],
    limit: int = 20,
    score_threshold: Optional[float] = None,
    scope: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search one case's embedded events, optionally restricted to a scope.
    
    Raises:
        LookupError: when the case has no event vectors yet
    """
    from qdrant_client.models import Filter, FieldCondition, MatchValue
    
    collection_name = build_case_event_collection_name(case_id)
    
    if not collection_exists(collection_name):
        raise LookupError(f'No event vectors for case {case_id}')
    
    query_filter = None
    if scope:
        query_filter = Filter(
            must=[FieldCondition(key='embedding_scope', match=MatchValue(value=scope))]
        )
    
    return search_points(
        collection_name,
        query_vector,
        limit=limit,
        score_threshold=score_threshold,
        query_filter=query_filter,
    )


def count_case_event_scopes(case_id: int, scopes: tuple) -> Dict[str, int]:
    """Return the embedded event count per scope for one case."""
    from qdrant_client.models import Filter, FieldCondition, MatchValue
    
    collection_name = build_case_event_collection_name(case_id)
    client = get_qdrant_client()
    counts = {}
    
    for scope in scopes:
        try:
            result = client.count(
                collection_name=collection_name,
                count_filter=Filter(
                    must=[FieldCondition(key='embedding_scope', match=MatchValue(value=scope))]
                ),
                exact=True,
            )
            counts[scope] = result.count
        except Exception as e:
            logger.debug(f"[RAG] Could not count scope {scope} for case {case_id}: {e}")
            counts[scope] = 0
    
    return counts


def delete_case_event_collection(case_id: int) -> bool:
    """Drop a case's event vector collection, for permanent case deletion.
    
    Returns:
        True if a collection was dropped
    """
    collection_name = build_case_event_collection_name(case_id)
    
    try:
        if not collection_exists(collection_name):
            return False
        
        get_qdrant_client().delete_collection(collection_name=collection_name)
        logger.info(f"[RAG] Dropped event vector collection {collection_name}")
        return True
        
    except Exception as e:
        logger.error(f"[RAG] Failed to drop collection {collection_name}: {e}")
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
        from utils.rag_embeddings import get_embedding_dimension
        
        client = get_qdrant_client()
        collection = Config.QDRANT_COLLECTION_PATTERNS
        
        # Size the collection from the vectors actually being written. Hardcoding
        # 384 meant that changing EMBEDDING_MODEL to any other dimension created
        # a collection every subsequent upsert would be rejected by.
        vector_size = len(patterns[0]['embedding']) if patterns else get_embedding_dimension()
        ensure_collection(collection, vector_size)
        
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


def prune_patterns_not_in(valid_pattern_ids: List[int]) -> int:
    """Delete pattern vectors whose pattern is no longer enabled or no longer exists.
    
    Without this, disabling or deleting a pattern left its vector searchable
    forever, so semantic lookups could surface patterns the analyst had
    explicitly turned off.
    
    Args:
        valid_pattern_ids: IDs that should remain in the vector store
        
    Returns:
        Number of stale pattern vectors deleted
    """
    try:
        from qdrant_client.models import PointIdsList
        
        collection = Config.QDRANT_COLLECTION_PATTERNS
        
        if not collection_exists(collection):
            return 0
        
        client = get_qdrant_client()
        keep = set(valid_pattern_ids)
        stale = []
        offset = None
        
        while True:
            points, offset = client.scroll(
                collection_name=collection,
                limit=1000,
                offset=offset,
                with_payload=False,
                with_vectors=False,
            )
            stale.extend(point.id for point in points if point.id not in keep)
            if offset is None:
                break
        
        if stale:
            client.delete(
                collection_name=collection,
                points_selector=PointIdsList(points=stale),
                wait=True,
            )
            logger.info(f"[RAG] Pruned {len(stale)} stale pattern vectors from {collection}")
        
        return len(stale)
        
    except Exception as e:
        logger.error(f"[RAG] Failed to prune stale pattern vectors: {e}")
        return 0


def search_similar_patterns(
    query_vector: List[float],
    limit: int = 10,
    score_threshold: float = None
) -> List[Dict[str, Any]]:
    """Search for patterns similar to query vector
    
    Args:
        query_vector: Query embedding vector
        limit: Maximum number of results
        score_threshold: Minimum similarity score (defaults to Config.RAG_SEMANTIC_THRESHOLD)
        
    Returns:
        List of matching patterns with scores
    """
    try:
        # Use centralized threshold if not specified
        if score_threshold is None:
            score_threshold = getattr(Config, 'RAG_SEMANTIC_THRESHOLD', 0.45)
        
        return search_points(
            Config.QDRANT_COLLECTION_PATTERNS,
            query_vector,
            limit=limit,
            score_threshold=score_threshold,
        )
        
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
        
        # qdrant-client dropped vectors_count from CollectionInfo, and the model
        # raises AttributeError rather than returning None for it, so reading it
        # unguarded turned every call into an error result.
        points_count = getattr(info, 'points_count', 0) or 0
        vectors_count = getattr(info, 'vectors_count', None)
        indexed_count = getattr(info, 'indexed_vectors_count', None)
        
        return {
            'name': collection,
            'vectors_count': vectors_count if vectors_count is not None else points_count,
            'indexed_vectors_count': indexed_count,
            'points_count': points_count,
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
