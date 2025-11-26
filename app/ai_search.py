#!/usr/bin/env python3
"""
CaseScope AI Search Module (RAG Implementation) - UPDATED
Provides semantic search using embeddings + LLM-powered question answering
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
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# LLM model for generating answers (uses your existing DFIR models on GPU)
DEFAULT_LLM_MODEL = "dfir-llama:latest"

# Lazy-loaded embedding model (loaded on first use, not at import)
_embedding_model = None
_embedding_model_load_attempted = False


def _load_embedding_model():
    """
    Lazy-load the sentence-transformers embedding model
    """
    global _embedding_model, _embedding_model_load_attempted
    
    if _embedding_model_load_attempted:
        return _embedding_model
    
    _embedding_model_load_attempted = True
    
    try:
        from sentence_transformers import SentenceTransformer
        
        logger.info(f"[AI_SEARCH] Loading embedding model: {EMBEDDING_MODEL_NAME}")
        _embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME, device='cpu')
        logger.info(f"[AI_SEARCH] Embedding model loaded successfully (CPU mode)")
        return _embedding_model
        
    except ImportError:
        logger.error("[AI_SEARCH] sentence-transformers not installed")
        return None
    except Exception as e:
        logger.error(f"[AI_SEARCH] Failed to load embedding model: {e}")
        return None


def check_embedding_model_available() -> Dict[str, Any]:
    """Check if the embedding model can be loaded"""
    try:
        import sentence_transformers
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
            'error': "sentence-transformers not installed"
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
    """Generate embedding vector for text"""
    model = _load_embedding_model()
    if model is None:
        return None
    
    try:
        text = text[:2000] if len(text) > 2000 else text
        embedding = model.encode(text, convert_to_numpy=True, show_progress_bar=False)
        return embedding
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Error generating embedding: {e}")
        return None


def get_embeddings_batch(texts: List[str]) -> Optional[np.ndarray]:
    """Generate embeddings for multiple texts efficiently"""
    model = _load_embedding_model()
    if model is None:
        return None
    
    try:
        texts = [t[:2000] if len(t) > 2000 else t for t in texts]
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
    """Calculate cosine similarity between query and multiple embeddings"""
    query_norm = query_embedding / np.linalg.norm(query_embedding)
    embeddings_norm = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)
    similarities = np.dot(embeddings_norm, query_norm)
    return similarities


def create_event_summary(event: Dict[str, Any]) -> str:
    """Create a text summary of an event for embedding/LLM context"""
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
    
    # Event ID
    event_id = source.get('normalized_event_id') or source.get('EventID') or source.get('event_id')
    if event_id:
        parts.append(f"Event ID: {event_id}")
    
    # Extract key fields
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
                value = str(event_data[field])[:200]
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


def simple_keyword_search(
    opensearch_client,
    case_id: int,
    keywords: List[str],
    max_results: int = 50
) -> List[Dict]:
    """
    Fallback simple search using just query_string
    Limits keywords to prevent "too many clauses" error on large indices
    """
    index_name = f"case_{case_id}"
    
    # Limit keywords to top 5 to avoid maxClauseCount errors
    limited_keywords = keywords[:5]
    query_text = " OR ".join(limited_keywords)
    
    try:
        logger.info(f"[AI_SEARCH] Trying fallback simple search with: {query_text}")
        
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": {
                    "query_string": {
                        "query": query_text,
                        "default_operator": "OR",
                        "lenient": True,
                        "analyze_wildcard": True
                    }
                },
                "size": max_results,
                "_source": True,
                "timeout": "15s"
            },
            request_timeout=20
        )
        
        results = [
            {
                '_id': hit['_id'],
                '_index': hit['_index'],
                '_score': hit.get('_score', 0),
                '_source': hit['_source']
            }
            for hit in response['hits']['hits']
        ]
        
        logger.info(f"[AI_SEARCH] Fallback search returned {len(results)} results")
        return results
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Simple search failed: {e}")
        return []


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
    
    ENHANCED VERSION with:
    - Better multi_match queries with fuzziness
    - Fallback simple search
    - Improved logging
    - No problematic wildcards
    """
    index_name = f"case_{case_id}"
    
    # Step 1: Extract keywords for initial retrieval
    keywords = extract_keywords_from_question(question)
    
    if not keywords:
        logger.warning("[AI_SEARCH] No keywords extracted from question")
        return [], "Could not extract search terms from your question."
    
    logger.info(f"[AI_SEARCH] Searching with keywords: {keywords}")
    
    # Get MORE candidates than we need (will re-rank with embeddings)
    candidate_count = min(max_results * 5, 100)
    
    # Build a more robust query with multiple should clauses
    should_clauses = []
    
    # Remove wildcards from keywords for cleaner queries
    clean_keywords = [k for k in keywords if '*' not in k]
    
    # Add each keyword as a separate multi_match clause with fuzziness
    # LIMIT to specific fields for performance on large indices
    search_fields = [
        "event_title^3",  # Boost title matches
        "event_description^2",
        "computer_name",
        "username",
        "process_name",
        "command_line",
        "source_ip",
        "destination_ip",
        "file_path"
    ]
    
    for keyword in clean_keywords:
        should_clauses.append({
            "multi_match": {
                "query": keyword,
                "fields": search_fields,
                "type": "best_fields",
                "fuzziness": "AUTO",
                "lenient": True,
                "boost": 2.0
            }
        })
    
    # Also add a query_string for the full question (catches phrases)
    if clean_keywords:
        should_clauses.append({
            "query_string": {
                "query": " OR ".join(clean_keywords),
                "default_operator": "OR",
                "lenient": True,
                "boost": 1.0
            }
        })
    
    # Boost priority: Tagged > IOC > SIGMA > Other
    # This helps surface events analyst has already identified as important
    
    # Boost analyst-tagged events (HIGHEST priority)
    if boost_tagged:
        should_clauses.append({
            "term": {"is_tagged": {"value": True, "boost": 5.0}}
        })
    
    # Boost IOC events (HIGH priority)
    if include_ioc:
        should_clauses.append({
            "term": {"has_ioc": {"value": True, "boost": 3.5}}
        })
    
    # Boost SIGMA events (MEDIUM priority)
    if include_sigma:
        should_clauses.append({
            "term": {"has_sigma": {"value": True, "boost": 2.5}}
        })
    
    query = {
        "bool": {
            "should": should_clauses,
            "minimum_should_match": 1
        }
    }
    
    # Step 2: Execute search
    try:
        logger.info(f"[AI_SEARCH] Executing query on index {index_name}")
        
        # First, get keyword-matched events
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": candidate_count,
                "sort": [
                    {"_score": {"order": "desc"}},
                    {"normalized_timestamp": {"order": "desc"}}
                ],
                "_source": True,
                "timeout": "30s"  # Prevent long-running queries on large indices
            },
            request_timeout=35  # Client-side timeout slightly longer than query timeout
        )
        
        # Also fetch tagged events separately (they may not match keywords)
        tagged_response = None
        if boost_tagged:
            try:
                tagged_response = opensearch_client.search(
                    index=index_name,
                    body={
                        "query": {"term": {"is_tagged": True}},
                        "size": 20,  # Get up to 20 tagged events
                        "sort": [{"normalized_timestamp": {"order": "desc"}}],
                        "_source": True,
                        "timeout": "10s"
                    },
                    request_timeout=15
                )
                logger.info(f"[AI_SEARCH] Found {len(tagged_response['hits']['hits'])} tagged events")
            except Exception as e:
                logger.warning(f"[AI_SEARCH] Failed to fetch tagged events: {e}")
                tagged_response = None
        
        total_hits = response['hits']['total']['value'] if isinstance(response['hits']['total'], dict) else response['hits']['total']
        logger.info(f"[AI_SEARCH] Query returned {total_hits} total hits")
        
        candidates = []
        event_ids_seen = set()
        
        # Add keyword-matched events
        for hit in response['hits']['hits']:
            event = {
                '_id': hit['_id'],
                '_index': hit['_index'],
                '_score': hit.get('_score', 0),
                '_source': hit['_source']
            }
            candidates.append(event)
            event_ids_seen.add(hit['_id'])
        
        # Merge in tagged events (avoiding duplicates)
        if tagged_response:
            for hit in tagged_response['hits']['hits']:
                if hit['_id'] not in event_ids_seen:
                    event = {
                        '_id': hit['_id'],
                        '_index': hit['_index'],
                        '_score': 10.0,  # Give high score to ensure they rank well
                        '_source': hit['_source']
                    }
                    candidates.append(event)
                    event_ids_seen.add(hit['_id'])
            logger.info(f"[AI_SEARCH] Merged {len(candidates)} total candidates (keyword + tagged)")
        
        # Try fallback if no results
        if not candidates:
            logger.warning(f"[AI_SEARCH] Primary query returned 0 results, trying fallback")
            candidates = simple_keyword_search(opensearch_client, case_id, clean_keywords, candidate_count)
            
            if not candidates:
                logger.warning(f"[AI_SEARCH] Fallback also returned 0 results")
                return [], f"No events found matching: {', '.join(clean_keywords[:5])}"
            
            total_hits = len(candidates)
        
        logger.info(f"[AI_SEARCH] Retrieved {len(candidates)} candidate events")
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] OpenSearch query failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        
        # Try fallback on error
        logger.info("[AI_SEARCH] Attempting fallback search after error")
        candidates = simple_keyword_search(opensearch_client, case_id, clean_keywords, candidate_count)
        if not candidates:
            return [], f"Search error: {str(e)}"
        total_hits = len(candidates)
    
    # Step 3: Semantic re-ranking (if embedding model available)
    embedding_available = _load_embedding_model() is not None
    
    if embedding_available and len(candidates) > 1:
        try:
            question_embedding = get_embedding(question)
            
            if question_embedding is not None:
                event_summaries = [create_event_summary(e) for e in candidates]
                event_embeddings = get_embeddings_batch(event_summaries)
                
                if event_embeddings is not None:
                    similarities = cosine_similarity_batch(question_embedding, event_embeddings)
                    
                    os_scores = np.array([e['_score'] for e in candidates])
                    os_scores_norm = os_scores / (os_scores.max() + 0.001)
                    
                    # Calculate base scores (balanced keyword + semantic)
                    base_scores = 0.5 * os_scores_norm + 0.5 * similarities
                    
                    # Apply multiplicative boosts AFTER normalization to prevent boost erasure
                    combined_scores = np.zeros(len(candidates))
                    for i, candidate in enumerate(candidates):
                        source = candidate.get('_source', {})
                        boost = 1.0
                        
                        # Analyst-tagged events get major boost (most important)
                        if source.get('is_tagged'):
                            boost *= 2.5
                        
                        # IOC matches are strong signals
                        if source.get('has_ioc'):
                            ioc_count = source.get('ioc_count', 1)
                            boost *= (1.0 + 0.3 * min(ioc_count, 5))  # 1.3x to 2.5x
                        
                        # SIGMA matches indicate suspicious activity
                        if source.get('has_sigma'):
                            sigma_level = source.get('sigma_level', 'medium')
                            sigma_boosts = {'critical': 1.8, 'high': 1.5, 'medium': 1.3, 'low': 1.1}
                            boost *= sigma_boosts.get(sigma_level, 1.2)
                        
                        combined_scores[i] = base_scores[i] * boost
                    
                    ranked_indices = np.argsort(combined_scores)[::-1]
                    
                    candidates = [candidates[i] for i in ranked_indices]
                    
                    for i, idx in enumerate(ranked_indices):
                        if i < len(candidates):
                            candidates[i]['_semantic_score'] = float(similarities[idx])
                            candidates[i]['_combined_score'] = float(combined_scores[idx])
                    
                    logger.info(f"[AI_SEARCH] Re-ranked events using semantic similarity")
                    explanation = f"Found {total_hits} events, showing top {len(candidates[:max_results])} re-ranked by relevance"
                else:
                    explanation = f"Found {total_hits} events matching: {', '.join(clean_keywords[:5])}"
            else:
                explanation = f"Found {total_hits} events matching: {', '.join(clean_keywords[:5])}"
                
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Semantic re-ranking failed: {e}")
            explanation = f"Found {total_hits} events matching: {', '.join(clean_keywords[:5])}"
    else:
        explanation = f"Found {total_hits} events matching: {', '.join(clean_keywords[:5])}"
        if not embedding_available:
            explanation += " (semantic ranking unavailable)"
    
    return candidates[:max_results], explanation


def extract_keywords_from_question(question: str) -> List[str]:
    """
    Extract search keywords from natural language question
    
    Handles:
    - CamelCase splitting (GoToAssist → goto, assist)
    - Usernames with dots (Rachel.B → rachel.b, rachel)
    - Windows paths
    - Common DFIR terms
    
    UPDATED: Removed problematic wildcard generation
    """
    import re
    
    # Common DFIR-related terms to preserve as-is
    preserve_terms = {
        'lateral movement', 'credential', 'brute force', 'logon', 'login',
        'failed', 'success', 'admin', 'administrator', 'remote', 'rdp',
        'psexec', 'powershell', 'cmd', 'command line', 'execution',
        'persistence', 'scheduled task', 'service', 'registry',
        'malware', 'ransomware', 'exfiltration', 'data theft',
        'privilege escalation', 'uac', 'mimikatz', 'kerberos',
        'pass the hash', 'pass the ticket', 'golden ticket',
        '4624', '4625', '4648', '4672', '4688', '4697', '4698', '4699',
        '5140', '5145', '1102', '7045', 'netstat', 'ipconfig', 'tree'
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
        'my', 'your', 'we', 'our', 'they', 'their', 'it', 'its',
        'summarize', 'summary', 'describe', 'explain', 'activity',
        'involved', 'happened', 'occurred', 'can', 'about'
    }
    
    question_lower = question.lower()
    keywords = []
    
    # First, extract preserved multi-word terms
    for term in preserve_terms:
        if term in question_lower:
            keywords.append(term)
    
    # Extract quoted strings as exact terms
    quoted = re.findall(r'"([^"]+)"', question)
    for q in quoted:
        keywords.append(q.lower())
    
    # Extract usernames with dots (e.g., Rachel.B, admin.user)
    usernames = re.findall(r'\b([A-Za-z]+\.[A-Za-z]+)\b', question)
    for username in usernames:
        keywords.append(username.lower())  # rachel.b
        keywords.append(username.split('.')[0].lower())  # rachel
    
    # Extract potential hostnames/domains
    hostnames = re.findall(r'\b([A-Za-z0-9\-]+\.(?:local|com|net|org|internal))\b', question, re.IGNORECASE)
    for hostname in hostnames:
        keywords.append(hostname.lower())
    
    # Split CamelCase words
    def split_camel_case(word):
        parts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)', word)
        return [p.lower() for p in parts if len(p) > 1]
    
    # Extract words
    raw_words = re.findall(r'[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z]+)?', question)
    
    for word in raw_words:
        word_lower = word.lower()
        
        # Skip stop words
        if word_lower in stop_words:
            continue
        
        # Skip very short words
        if len(word_lower) < 3:
            continue
            
        # Check if already covered
        if any(word_lower in kw for kw in keywords):
            continue
        
        # Check for CamelCase and split
        if re.search(r'[a-z][A-Z]', word):
            parts = split_camel_case(word)
            keywords.extend(parts)
        else:
            keywords.append(word_lower)
    
    # REMOVED: Wildcard generation - causes query issues
    # The multi_match with fuzziness handles partial matching better
    
    # Deduplicate while preserving order
    seen = set()
    unique_keywords = []
    for kw in keywords:
        if kw not in seen and kw not in stop_words:
            seen.add(kw)
            unique_keywords.append(kw)
    
    logger.info(f"[AI_SEARCH] Extracted keywords from question: {unique_keywords[:20]}")
    
    return unique_keywords[:20]  # Limit to top 20 keywords


# ... rest of the file (generate_ai_answer, ai_question_search, __all__) remains the same ...

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
    # Build context from events with dynamic size check
    MAX_CONTEXT_TOKENS = 6000  # Leave room for prompt and response
    CHARS_PER_TOKEN = 4  # Approximate characters per token
    
    event_context = []
    total_length = 0
    events_included = 0
    
    for i, event in enumerate(events[:15], 1):  # Try up to 15 events
        summary = create_event_summary(event)
        event_id = event.get('_id', f'event_{i}')
        event_text = f"[Event {i}] (ID: {event_id})\n{summary}"
        
        estimated_tokens = len(event_text) // CHARS_PER_TOKEN
        
        # Check if adding this event would overflow context
        if total_length + estimated_tokens > MAX_CONTEXT_TOKENS:
            logger.info(f"[AI_SEARCH] Context limit reached at {i} events ({total_length} tokens)")
            break
        
        event_context.append(event_text)
        total_length += estimated_tokens
        events_included = i
    
    events_text = "\n\n".join(event_context)
    logger.info(f"[AI_SEARCH] Including {events_included} events in LLM context ({total_length} estimated tokens)")
    
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
