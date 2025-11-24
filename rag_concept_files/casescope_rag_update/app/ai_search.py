#!/usr/bin/env python3
"""
CaseScope AI Search Module (RAG Implementation)
Provides semantic search using embeddings + LLM-powered question answering

RAG = Retrieval-Augmented Generation:
1. Convert user question to embedding vector
2. Find semantically similar events in OpenSearch
3. Pass those events to LLM as context
4. LLM generates answer grounded in actual evidence

PERFORMANCE DESIGN:
- Embeddings use sentence-transformers on CPU (fast, leaves GPU for LLM)
- Embeddings happen ONLY at query time, NOT during ingestion
- LLM uses GPU via Ollama (your existing DFIR models)
- Zero impact on file processing pipeline
"""

import requests
import json
import logging
import numpy as np
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Generator
from logging_config import get_logger

logger = get_logger('app')

# Ollama API endpoints (for LLM generation)
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"

# Embedding model configuration
# all-MiniLM-L6-v2: 90MB, 384 dimensions, runs on CPU at ~1000+ embeddings/sec
# This keeps your GPU free for LLM inference
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# LLM model for generating answers (uses your existing DFIR models on GPU)
DEFAULT_LLM_MODEL = "dfir-llama:latest"

# Lazy-loaded embedding model (loaded on first use, not at import)
_embedding_model = None
_embedding_model_load_attempted = False


def _load_embedding_model():
    """
    Lazy-load the sentence-transformers embedding model
    
    Uses CPU by default to keep GPU free for LLM.
    Model is cached after first load (~2-3 seconds initial load).
    """
    global _embedding_model, _embedding_model_load_attempted
    
    if _embedding_model_load_attempted:
        return _embedding_model
    
    _embedding_model_load_attempted = True
    
    try:
        from sentence_transformers import SentenceTransformer
        
        logger.info(f"[AI_SEARCH] Loading embedding model: {EMBEDDING_MODEL_NAME}")
        
        # Load model - will use CPU by default
        # device='cpu' ensures GPU stays free for Ollama LLM
        _embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME, device='cpu')
        
        logger.info(f"[AI_SEARCH] Embedding model loaded successfully (CPU mode)")
        return _embedding_model
        
    except ImportError:
        logger.error("[AI_SEARCH] sentence-transformers not installed. Run: pip install sentence-transformers --break-system-packages")
        return None
    except Exception as e:
        logger.error(f"[AI_SEARCH] Failed to load embedding model: {e}")
        return None


def check_embedding_model_available() -> Dict[str, Any]:
    """
    Check if the embedding model can be loaded
    
    Returns:
        dict with 'available', 'model', and 'error' keys
    """
    try:
        # Check if sentence-transformers is installed
        import sentence_transformers
        
        # Try to load the model
        model = _load_embedding_model()
        
        if model is not None:
            return {
                'available': True,
                'model': EMBEDDING_MODEL_NAME,
                'type': 'sentence-transformers',
                'device': 'cpu',
                'error': None
            }
        else:
            return {
                'available': False,
                'model': EMBEDDING_MODEL_NAME,
                'type': 'sentence-transformers',
                'device': 'cpu',
                'error': "Failed to load embedding model"
            }
            
    except ImportError:
        return {
            'available': False,
            'model': EMBEDDING_MODEL_NAME,
            'type': 'sentence-transformers',
            'device': 'cpu',
            'error': "sentence-transformers not installed. Run: pip install sentence-transformers --break-system-packages"
        }
    except Exception as e:
        return {
            'available': False,
            'model': EMBEDDING_MODEL_NAME,
            'type': 'sentence-transformers',
            'device': 'cpu',
            'error': str(e)
        }


def get_embedding(text: str) -> Optional[np.ndarray]:
    """
    Generate embedding vector for text using sentence-transformers (CPU)
    
    Args:
        text: Text to embed (question or event summary)
    
    Returns:
        numpy array (embedding vector) or None on error
    """
    model = _load_embedding_model()
    if model is None:
        return None
    
    try:
        # Truncate very long text (model has ~256 token limit, ~1000 chars safe)
        text = text[:2000] if len(text) > 2000 else text
        
        # Generate embedding - runs on CPU, very fast
        embedding = model.encode(text, convert_to_numpy=True, show_progress_bar=False)
        
        return embedding
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Error generating embedding: {e}")
        return None


def get_embeddings_batch(texts: List[str]) -> Optional[np.ndarray]:
    """
    Generate embeddings for multiple texts efficiently (batched)
    
    Args:
        texts: List of texts to embed
    
    Returns:
        numpy array of shape (n_texts, embedding_dim) or None on error
    """
    model = _load_embedding_model()
    if model is None:
        return None
    
    try:
        # Truncate each text
        texts = [t[:2000] if len(t) > 2000 else t for t in texts]
        
        # Batch encode - much faster than individual calls
        # batch_size=32 is efficient for CPU
        embeddings = model.encode(
            texts, 
            convert_to_numpy=True, 
            show_progress_bar=False,
            batch_size=32
        )
        
        return embeddings
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Error generating batch embeddings: {e}")
        return None


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Calculate cosine similarity between two vectors"""
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


def cosine_similarity_batch(query_embedding: np.ndarray, embeddings: np.ndarray) -> np.ndarray:
    """
    Calculate cosine similarity between query and multiple embeddings
    
    Args:
        query_embedding: Single embedding vector (1D)
        embeddings: Matrix of embeddings (2D: n_docs x embedding_dim)
    
    Returns:
        Array of similarity scores
    """
    # Normalize vectors
    query_norm = query_embedding / np.linalg.norm(query_embedding)
    embeddings_norm = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)
    
    # Dot product gives cosine similarity for normalized vectors
    similarities = np.dot(embeddings_norm, query_norm)
    
    return similarities


def create_event_summary(event: Dict[str, Any]) -> str:
    """
    Create a text summary of an event for embedding/LLM context
    
    Args:
        event: Event document from OpenSearch
    
    Returns:
        Human-readable summary string
    """
    source = event.get('_source', event)
    
    parts = []
    
    # Timestamp
    timestamp = source.get('normalized_timestamp') or source.get('@timestamp') or source.get('timestamp', 'Unknown time')
    parts.append(f"Time: {timestamp}")
    
    # Computer/Host
    computer = (source.get('normalized_computer') or 
                source.get('Computer') or 
                source.get('computer') or
                source.get('host', {}).get('name') if isinstance(source.get('host'), dict) else source.get('host', 'Unknown'))
    parts.append(f"Computer: {computer}")
    
    # Event ID (for Windows events)
    event_id = source.get('normalized_event_id') or source.get('EventID') or source.get('event_id')
    if event_id:
        parts.append(f"Event ID: {event_id}")
    
    # Extract key fields from EventData or event root
    key_fields = [
        'SubjectUserName', 'TargetUserName', 'User', 'user',
        'SourceNetworkAddress', 'IpAddress', 'source_ip',
        'ProcessName', 'Image', 'process_name',
        'CommandLine', 'command_line',
        'TargetFilename', 'ObjectName', 'file_path',
        'LogonType', 'logon_type',
        'Status', 'FailureReason',
        'ServiceName', 'service_name',
        'TaskName', 'ScheduledTaskName'
    ]
    
    # Check EventData
    event_data = source.get('EventData', {})
    if isinstance(event_data, dict):
        for field in key_fields:
            if field in event_data and event_data[field]:
                value = str(event_data[field])[:200]  # Limit length
                parts.append(f"{field}: {value}")
    
    # Also check root level
    for field in key_fields:
        if field in source and source[field] and field not in str(parts):
            value = str(source[field])[:200]
            parts.append(f"{field}: {value}")
    
    # SIGMA/IOC flags
    if source.get('has_sigma'):
        parts.append("⚠️ SIGMA rule violation detected")
    if source.get('has_ioc'):
        ioc_count = source.get('ioc_count', 1)
        parts.append(f"🎯 Matches {ioc_count} IOC(s)")
    
    return " | ".join(parts)


def semantic_search_events(
    opensearch_client,
    case_id: int,
    question: str,
    max_results: int = 20,
    include_sigma: bool = True,
    include_ioc: bool = True,
    boost_tagged: bool = True
) -> Tuple[List[Dict], str]:
    """
    Perform semantic search: find events relevant to the question
    
    HYBRID APPROACH (best of both worlds):
    1. Keyword search to get candidate events (fast, OpenSearch)
    2. Embed the question and candidate events (CPU, ~500ms for 50 events)
    3. Re-rank candidates by semantic similarity
    4. Return top results
    
    This approach:
    - Has ZERO impact on ingestion (embeddings only at query time)
    - Uses CPU for embeddings, keeping GPU free for LLM
    - Gets semantic understanding without pre-indexing vectors
    
    Args:
        opensearch_client: OpenSearch client instance
        case_id: Case ID to search within
        question: Natural language question from analyst
        max_results: Maximum events to return (after re-ranking)
        include_sigma: Boost SIGMA violation events
        include_ioc: Boost IOC match events
        boost_tagged: Boost events that are tagged
    
    Returns:
        Tuple of (events list, search_explanation string)
    """
    index_name = f"case_{case_id}"
    
    # Step 1: Extract keywords for initial retrieval
    keywords = extract_keywords_from_question(question)
    
    # Build OpenSearch query for candidate retrieval
    # Get MORE candidates than we need (will re-rank with embeddings)
    candidate_count = min(max_results * 5, 100)  # Get 5x candidates, max 100
    
    query = {
        "bool": {
            "should": [],
            "minimum_should_match": 1
        }
    }
    
    # Add keyword matches
    if keywords:
        query["bool"]["should"].append({
            "query_string": {
                "query": " OR ".join(keywords),
                "default_operator": "OR",
                "analyze_wildcard": True,
                "lenient": True,
                "boost": 1.0
            }
        })
    
    # Boost SIGMA events
    if include_sigma:
        query["bool"]["should"].append({
            "term": {"has_sigma": {"value": True, "boost": 2.0}}
        })
    
    # Boost IOC events
    if include_ioc:
        query["bool"]["should"].append({
            "term": {"has_ioc": {"value": True, "boost": 2.0}}
        })
    
    # Step 2: Get candidate events from OpenSearch
    try:
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": candidate_count,
                "sort": [
                    {"_score": {"order": "desc"}},
                    {"normalized_timestamp": {"order": "desc"}}
                ],
                "_source": True
            }
        )
        
        candidates = []
        for hit in response['hits']['hits']:
            event = {
                '_id': hit['_id'],
                '_index': hit['_index'],
                '_score': hit.get('_score', 0),
                '_source': hit['_source']
            }
            candidates.append(event)
        
        if not candidates:
            return [], "No events found matching your question keywords."
        
        logger.info(f"[AI_SEARCH] Retrieved {len(candidates)} candidate events for semantic re-ranking")
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] OpenSearch query failed: {e}")
        return [], f"Search error: {str(e)}"
    
    # Step 3: Embed question and candidates for semantic re-ranking
    # Check if embedding model is available
    embedding_available = _load_embedding_model() is not None
    
    if embedding_available and len(candidates) > 1:
        try:
            # Embed the question
            question_embedding = get_embedding(question)
            
            if question_embedding is not None:
                # Create text summaries for each candidate
                event_summaries = [create_event_summary(e) for e in candidates]
                
                # Batch embed all summaries (fast on CPU)
                event_embeddings = get_embeddings_batch(event_summaries)
                
                if event_embeddings is not None:
                    # Calculate semantic similarity scores
                    similarities = cosine_similarity_batch(question_embedding, event_embeddings)
                    
                    # Combine OpenSearch score with semantic similarity
                    # Normalize OpenSearch scores to 0-1 range
                    os_scores = np.array([e['_score'] for e in candidates])
                    os_scores_norm = os_scores / (os_scores.max() + 0.001)  # Avoid div by zero
                    
                    # Combined score: 40% OpenSearch relevance + 60% semantic similarity
                    combined_scores = 0.4 * os_scores_norm + 0.6 * similarities
                    
                    # Sort by combined score
                    ranked_indices = np.argsort(combined_scores)[::-1]  # Descending
                    
                    # Re-order candidates
                    candidates = [candidates[i] for i in ranked_indices]
                    
                    # Add semantic scores for debugging
                    for i, idx in enumerate(ranked_indices):
                        if i < len(candidates):
                            candidates[i]['_semantic_score'] = float(similarities[idx])
                            candidates[i]['_combined_score'] = float(combined_scores[idx])
                    
                    logger.info(f"[AI_SEARCH] Re-ranked events using semantic similarity")
                    explanation = f"Found {len(candidates)} events, re-ranked by semantic similarity to: '{question[:50]}...'"
                else:
                    explanation = f"Found {len(candidates)} events using keywords: {', '.join(keywords[:5])}"
            else:
                explanation = f"Found {len(candidates)} events using keywords: {', '.join(keywords[:5])}"
                
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Semantic re-ranking failed, using keyword results: {e}")
            explanation = f"Found {len(candidates)} events using keywords: {', '.join(keywords[:5])}"
    else:
        explanation = f"Found {len(candidates)} events using keywords: {', '.join(keywords[:5])}"
        if not embedding_available:
            explanation += " (Install sentence-transformers for semantic search)"
    
    # Return top results after re-ranking
    return candidates[:max_results], explanation


def extract_keywords_from_question(question: str) -> List[str]:
    """
    Extract search keywords from natural language question
    
    This is a simple keyword extraction - could be enhanced with NLP
    """
    # Common DFIR-related terms to preserve
    preserve_terms = {
        'lateral movement', 'credential', 'brute force', 'logon', 'login',
        'failed', 'success', 'admin', 'administrator', 'remote', 'rdp',
        'psexec', 'powershell', 'cmd', 'command line', 'execution',
        'persistence', 'scheduled task', 'service', 'registry',
        'malware', 'ransomware', 'exfiltration', 'data theft',
        'privilege escalation', 'uac', 'mimikatz', 'kerberos',
        'pass the hash', 'pass the ticket', 'golden ticket',
        '4624', '4625', '4648', '4672', '4688', '4697', '4698', '4699',
        '5140', '5145', '1102', '7045'
    }
    
    # Words to ignore
    stop_words = {
        'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
        'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
        'should', 'may', 'might', 'must', 'shall', 'can', 'need', 'dare',
        'ought', 'used', 'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by',
        'from', 'as', 'into', 'through', 'during', 'before', 'after',
        'above', 'below', 'between', 'under', 'again', 'further', 'then',
        'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all',
        'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no',
        'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very',
        'just', 'and', 'but', 'if', 'or', 'because', 'until', 'while',
        'what', 'which', 'who', 'whom', 'this', 'that', 'these', 'those',
        'am', 'show', 'me', 'find', 'get', 'see', 'look', 'tell', 'give',
        'any', 'events', 'event', 'logs', 'log', 'please', 'i', 'you',
        'my', 'your', 'we', 'our', 'they', 'their', 'it', 'its'
    }
    
    question_lower = question.lower()
    
    # First, extract preserved multi-word terms
    keywords = []
    for term in preserve_terms:
        if term in question_lower:
            keywords.append(term)
    
    # Then extract individual words
    words = question_lower.replace('?', '').replace('.', '').replace(',', '').split()
    for word in words:
        if word not in stop_words and len(word) > 2:
            # Check if already covered by a multi-word term
            already_covered = any(word in kw for kw in keywords)
            if not already_covered:
                keywords.append(word)
    
    # Deduplicate while preserving order
    seen = set()
    unique_keywords = []
    for kw in keywords:
        if kw not in seen:
            seen.add(kw)
            unique_keywords.append(kw)
    
    return unique_keywords[:15]  # Limit to top 15 keywords


def generate_ai_answer(
    question: str,
    events: List[Dict],
    case_name: str,
    model: str = DEFAULT_LLM_MODEL,
    stream: bool = True
) -> Generator[str, None, None]:
    """
    Generate AI answer based on retrieved events
    
    Args:
        question: Analyst's question
        events: List of relevant events from semantic search
        case_name: Name of the case for context
        model: Ollama model to use
        stream: Whether to stream response
    
    Yields:
        Response text chunks
    """
    # Build context from events
    event_context = []
    for i, event in enumerate(events[:15], 1):  # Limit to 15 events for context
        summary = create_event_summary(event)
        event_id = event.get('_id', f'event_{i}')
        event_context.append(f"[Event {i}] (ID: {event_id})\n{summary}")
    
    events_text = "\n\n".join(event_context)
    
    # Build the prompt
    prompt = f"""You are a Digital Forensics and Incident Response (DFIR) analyst assistant. You help analysts understand security events and identify potential threats.

**CASE**: {case_name}

**ANALYST'S QUESTION**: {question}

**RELEVANT EVENTS FROM THE CASE** (retrieved based on your question):
{events_text}

**YOUR TASK**:
1. Answer the analyst's question based ONLY on the events provided above
2. Reference specific events by their Event number (e.g., "Event 3 shows...")
3. If the events don't contain enough information to fully answer, say so clearly
4. DO NOT make up or assume any information not present in the events
5. Be concise but thorough
6. If you identify potential attack patterns or concerns, highlight them

**IMPORTANT**: Ground your answer in the actual evidence. Every claim should reference a specific event.

**YOUR ANALYSIS**:
"""

    try:
        response = requests.post(
            OLLAMA_GENERATE_URL,
            json={
                "model": model,
                "prompt": prompt,
                "stream": stream,
                "options": {
                    "temperature": 0.3,  # Lower temperature for factual responses
                    "num_ctx": 8192,
                    "num_thread": 8
                }
            },
            stream=stream,
            timeout=300
        )
        
        response.raise_for_status()
        
        if stream:
            for line in response.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line.decode('utf-8'))
                        if 'response' in chunk:
                            yield chunk['response']
                        if chunk.get('done', False):
                            break
                    except json.JSONDecodeError:
                        continue
        else:
            data = response.json()
            yield data.get('response', '')
            
    except Exception as e:
        logger.error(f"[AI_SEARCH] Error generating AI answer: {e}")
        yield f"\n\n❌ Error generating response: {str(e)}"


def ai_question_search(
    opensearch_client,
    case_id: int,
    case_name: str,
    question: str,
    model: str = DEFAULT_LLM_MODEL,
    max_events: int = 20
) -> Generator[Dict, None, None]:
    """
    Main entry point for AI Question feature
    
    Yields status updates and the final response in chunks
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID
        case_name: Case name for context
        question: Analyst's question
        model: LLM model to use
        max_events: Maximum events to retrieve
    
    Yields:
        Dict with 'type' (status/chunk/events/done) and 'data'
    """
    # Step 1: Search for relevant events
    yield {"type": "status", "data": "Searching for relevant events..."}
    
    events, explanation = semantic_search_events(
        opensearch_client,
        case_id,
        question,
        max_results=max_events
    )
    
    if not events:
        yield {"type": "error", "data": "No relevant events found for your question. Try rephrasing or using different keywords."}
        return
    
    yield {"type": "status", "data": f"Found {len(events)} relevant events. Generating analysis..."}
    yield {"type": "events", "data": events}
    
    # Step 2: Generate AI response
    for chunk in generate_ai_answer(question, events, case_name, model):
        yield {"type": "chunk", "data": chunk}
    
    yield {"type": "done", "data": "Analysis complete"}


# Export functions
__all__ = [
    'check_embedding_model_available',
    'get_embedding',
    'get_embeddings_batch',
    'semantic_search_events',
    'generate_ai_answer',
    'ai_question_search',
    'create_event_summary',
    'EMBEDDING_MODEL_NAME',
    'DEFAULT_LLM_MODEL'
]
