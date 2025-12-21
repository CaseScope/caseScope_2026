#!/usr/bin/env python3
"""
CaseScope AI Search Module (RAG Implementation) - V2 IMPROVED
Provides semantic search using embeddings + LLM-powered question answering

Key improvements over V1:
- DFIR query expansion (malware -> powershell, encodedcommand, certutil, etc.)
- Searches search_blob field (where all the data is!)
- Result diversification (max 3 events per event type)
- Better event summaries with SIGMA rule names
- Attack-aware LLM prompt
"""

import requests
import json
import logging
import re
import numpy as np
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Generator
from logging_config import get_logger

logger = get_logger('app')

# Ollama API endpoints
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"

# Embedding model configuration
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# LLM model
DEFAULT_LLM_MODEL = "dfir-llama:latest"

# Lazy-loaded embedding model
_embedding_model = None
_embedding_model_load_attempted = False


# =============================================================================
# DFIR QUERY EXPANSION - Maps analyst concepts to actual indicators
# =============================================================================

DFIR_QUERY_EXPANSION = {
    'malware': [
        'powershell', 'encodedcommand', 'enc', 'base64', 'frombase64string',
        'invoke-expression', 'iex', 'downloadstring', 'downloadfile', 'webclient',
        'certutil', 'decode', 'urlcache', 'bitsadmin', 'mshta', 'wscript',
        'cscript', 'regsvr32', 'rundll32', 'msiexec',
        'hidden', 'bypass', 'noprofile', 'windowstyle',
        '4688', '1',
    ],
    
    'lateral movement': [
        'psexec', 'paexec', 'remcom', 'wmic', 'wmiexec', 'smbexec', 'wmiprvse',
        'winrm', 'winrs', 'enter-pssession', 'invoke-command',
        'mstsc', '3389',
        'admin$', 'c$', 'ipc$',
        '4624', '4648', '5140', '5145', 'type 3', 'type 10',
    ],
    
    'persistence': [
        'schtasks', 'scheduled task', 'at.exe',
        'currentversion\\run', 'runonce',
        'sc create', 'sc config', 'new-service',
        'startup',
        '__eventfilter', 'commandlineeventconsumer',
        '4698', '4699', '4702', '7045', '4697',
    ],
    
    'credential': [
        'lsass', 'mimikatz', 'sekurlsa', 'logonpasswords',
        'sam', 'ntds', 'ntds.dit', 'dcsync', 'drsuapi',
        'kerberos', 'krbtgt', 'golden ticket', 'silver ticket',
        'procdump', 'comsvcs', 'minidump',
        '4768', '4769', '4776', '4672', '10',  # 10 = Sysmon process access
    ],
    
    'exfiltration': [
        'upload', 'transfer', 'curl', 'wget', 'invoke-webrequest',
        'ftp', 'sftp', 'scp',
        'onedrive', 'dropbox', 'gdrive', 'mega', 'pastebin',
        'archive', 'zip', 'rar', '7z', 'compress-archive',
    ],
    
    'discovery': [
        'whoami', 'hostname', 'ipconfig', 'netstat',
        'net user', 'net group', 'net localgroup', 'net share', 'net view',
        'nltest', 'dsquery', 'get-aduser', 'get-adcomputer',
        'systeminfo', 'tasklist', 'query user', 'quser',
    ],
    
    'defense evasion': [
        'disable', 'stop', 'tamper', 'defender', 'antivirus', 'av',
        'amsi', 'etw', 'clear-eventlog', 'wevtutil',
        'firewall', 'netsh advfirewall',
        '1102',  # Audit log cleared
    ],
    
    'execution': [
        'powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta',
        'regsvr32', 'rundll32', 'msiexec', 'certutil',
        'wmic process', 'invoke-wmimethod',
        '4688', '1',  # Process creation
    ],
}

# Question patterns to expansion categories
QUESTION_PATTERNS = [
    (r'malware|virus|trojan|ransomware|infection|compromis|malicious|suspicious', 'malware'),
    (r'lateral|spread|pivot|move.*between|hop|remote\s+execution', 'lateral movement'),
    (r'persist|backdoor|maintain.*access|survive.*reboot|autorun|startup', 'persistence'),
    (r'credential|password|hash|ticket|authenticat|logon.*as|steal.*cred|dump', 'credential'),
    (r'exfil|steal.*data|data.*theft|upload|send.*out|leak', 'exfiltration'),
    (r'recon|discover|enumerat|scan|map.*network|survey', 'discovery'),
    (r'evad|bypass|disable|hide|obfuscat|tamper|kill.*av', 'defense evasion'),
    (r'execut|run|launch|spawn|start.*process|command', 'execution'),
]


def expand_query_for_dfir(question: str) -> List[str]:
    """
    Expand a natural language question into DFIR-relevant search terms.
    
    Example:
        "Do you see signs of malware?" 
        → ['powershell', 'encodedcommand', 'certutil', 'base64', ...]
    """
    expanded_terms = []
    question_lower = question.lower()
    
    # Check which categories match the question
    matched_categories = set()
    for pattern, category in QUESTION_PATTERNS:
        if re.search(pattern, question_lower):
            matched_categories.add(category)
    
    # Add expansion terms
    for category in matched_categories:
        if category in DFIR_QUERY_EXPANSION:
            expanded_terms.extend(DFIR_QUERY_EXPANSION[category])
    
    # Deduplicate
    seen = set()
    unique_terms = []
    for term in expanded_terms:
        if term.lower() not in seen:
            seen.add(term.lower())
            unique_terms.append(term)
    
    logger.info(f"[AI_SEARCH] Query expansion matched categories: {matched_categories}")
    logger.info(f"[AI_SEARCH] Expanded to {len(unique_terms)} DFIR terms")
    
    return unique_terms[:30]


# =============================================================================
# EMBEDDING MODEL
# =============================================================================

def _load_embedding_model():
    """Lazy-load the sentence-transformers embedding model"""
    global _embedding_model, _embedding_model_load_attempted
    
    if _embedding_model_load_attempted:
        return _embedding_model
    
    _embedding_model_load_attempted = True
    
    try:
        from sentence_transformers import SentenceTransformer
        logger.info(f"[AI_SEARCH] Loading embedding model: {EMBEDDING_MODEL_NAME}")
        _embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME, device='cpu')
        logger.info(f"[AI_SEARCH] Embedding model loaded (CPU)")
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
        return {
            'available': model is not None,
            'model': EMBEDDING_MODEL_NAME,
            'type': 'sentence-transformers',
            'device': 'cpu',
            'error': None if model else "Failed to load"
        }
    except ImportError:
        return {
            'available': False,
            'model': EMBEDDING_MODEL_NAME,
            'error': "sentence-transformers not installed"
        }


def get_embedding(text: str) -> Optional[np.ndarray]:
    """Generate embedding vector for text"""
    model = _load_embedding_model()
    if model is None:
        return None
    try:
        text = text[:2000] if len(text) > 2000 else text
        return model.encode(text, convert_to_numpy=True, show_progress_bar=False)
    except Exception as e:
        logger.error(f"[AI_SEARCH] Embedding error: {e}")
        return None


def get_embeddings_batch(texts: List[str]) -> Optional[np.ndarray]:
    """Generate embeddings for multiple texts"""
    model = _load_embedding_model()
    if model is None:
        return None
    try:
        texts = [t[:2000] for t in texts]
        return model.encode(texts, convert_to_numpy=True, show_progress_bar=False, batch_size=32)
    except Exception as e:
        logger.error(f"[AI_SEARCH] Batch embedding error: {e}")
        return None


def cosine_similarity_batch(query_embedding: np.ndarray, embeddings: np.ndarray) -> np.ndarray:
    """Calculate cosine similarity between query and multiple embeddings"""
    query_norm = query_embedding / np.linalg.norm(query_embedding)
    embeddings_norm = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)
    return np.dot(embeddings_norm, query_norm)


# =============================================================================
# EVENT SUMMARY - Rich context for LLM
# =============================================================================

def create_event_summary(event: Dict[str, Any]) -> str:
    """
    Create DFIR-aware event summary with attack context.
    
    Key improvements:
    - Shows SIGMA rule NAME (not just "detected")
    - Shows event_title (human readable)
    - Structured key fields
    - Truncated intelligently
    """
    source = event.get('_source', event)
    parts = []
    
    # === HEADER ===
    timestamp = source.get('normalized_timestamp') or source.get('@timestamp', 'Unknown')
    computer = source.get('normalized_computer') or source.get('Computer', 'Unknown')
    event_id = source.get('normalized_event_id') or source.get('EventID', '?')
    event_title = source.get('event_title', '')
    
    header = f"**{timestamp}** | {computer} | Event {event_id}"
    if event_title:
        header += f" ({event_title})"
    parts.append(header)
    
    # === DETECTION FLAGS (critical for analyst) ===
    if source.get('is_tagged'):
        parts.append("⭐ **ANALYST TAGGED**")
    
    if source.get('has_sigma'):
        sigma_level = source.get('sigma_level', 'unknown').upper()
        sigma_rules = source.get('sigma_rules', [])
        if sigma_rules and isinstance(sigma_rules, list):
            rule_names = []
            for r in sigma_rules[:3]:
                if isinstance(r, dict):
                    rule_names.append(r.get('title') or r.get('name', 'Unknown rule'))
                elif isinstance(r, str):
                    rule_names.append(r)
            if rule_names:
                parts.append(f"⚠️ **SIGMA {sigma_level}**: {', '.join(rule_names)}")
            else:
                parts.append(f"⚠️ **SIGMA {sigma_level}**")
        else:
            parts.append(f"⚠️ **SIGMA {sigma_level}**")
    
    if source.get('has_ioc'):
        ioc_count = source.get('ioc_count', 1)
        ioc_matches = source.get('ioc_matches', [])
        if ioc_matches and isinstance(ioc_matches, list):
            match_vals = [str(m.get('value', ''))[:30] for m in ioc_matches[:2] if isinstance(m, dict)]
            if match_vals:
                parts.append(f"🎯 **IOC**: {', '.join(match_vals)}")
            else:
                parts.append(f"🎯 **IOC MATCH** ({ioc_count})")
        else:
            parts.append(f"🎯 **IOC MATCH** ({ioc_count})")
    
    # === KEY FORENSIC FIELDS ===
    event_data = source.get('EventData', {})
    if not event_data:
        event_data = source.get('Event', {}).get('EventData', {})
    if isinstance(event_data, str):
        event_data = {}
    
    if isinstance(event_data, dict):
        # User
        user = (event_data.get('TargetUserName') or 
                event_data.get('SubjectUserName') or 
                event_data.get('User'))
        if user and user not in ['-', '']:
            parts.append(f"User: {user}")
        
        # Process chain (CRITICAL for malware detection)
        process = (event_data.get('NewProcessName') or 
                   event_data.get('Image') or 
                   event_data.get('ProcessName'))
        parent = (event_data.get('ParentProcessName') or 
                  event_data.get('ParentImage'))
        if process:
            if parent:
                # Show the spawn chain
                parent_short = parent.split('\\')[-1] if '\\' in parent else parent
                process_short = process.split('\\')[-1] if '\\' in process else process
                parts.append(f"Process: {parent_short} → {process_short}")
            else:
                parts.append(f"Process: {process}")
        
        # Command line (THE KEY for detecting malware)
        cmdline = event_data.get('CommandLine') or event_data.get('command_line')
        if cmdline:
            parts.append(f"CommandLine: {cmdline[:600]}")
        
        # Network
        src_ip = event_data.get('IpAddress') or event_data.get('SourceNetworkAddress')
        if src_ip and src_ip not in ['-', '::1', '127.0.0.1', '', 'LOCAL']:
            parts.append(f"Source IP: {src_ip}")
        
        # Logon type
        logon_type = event_data.get('LogonType')
        if logon_type:
            logon_map = {
                '2': 'Interactive', '3': 'Network', '4': 'Batch',
                '5': 'Service', '7': 'Unlock', '10': 'RDP', '11': 'Cached'
            }
            lt_desc = logon_map.get(str(logon_type), '')
            parts.append(f"LogonType: {logon_type} ({lt_desc})" if lt_desc else f"LogonType: {logon_type}")
        
        # Target file/object
        target = (event_data.get('TargetFilename') or 
                  event_data.get('ObjectName') or 
                  event_data.get('ShareName'))
        if target:
            parts.append(f"Target: {target[:200]}")
        
        # Service/Task
        service = event_data.get('ServiceName')
        if service:
            parts.append(f"Service: {service}")
        task = event_data.get('TaskName')
        if task:
            parts.append(f"Task: {task}")
    
    # === FALLBACK to search_blob if no structured data ===
    if len(parts) <= 2:
        blob = source.get('search_blob', '')
        if blob:
            parts.append(f"Data: {blob[:1000]}")
    
    summary = '\n'.join(parts)
    
    # Truncate to fit context budget
    if len(summary) > 2500:
        summary = summary[:2500] + "..."
    
    return summary


# =============================================================================
# KEYWORD EXTRACTION
# =============================================================================

def extract_keywords_from_question(question: str) -> List[str]:
    """Extract search keywords from natural language question"""
    
    preserve_terms = {
        'lateral movement', 'brute force', 'pass the hash', 'pass the ticket',
        'golden ticket', 'command line', 'scheduled task', 'privilege escalation',
        '4624', '4625', '4648', '4672', '4688', '4697', '4698', '4699',
        '5140', '5145', '1102', '7045',
    }
    
    stop_words = {
        'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
        'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
        'should', 'may', 'might', 'must', 'can', 'to', 'of', 'in', 'for',
        'on', 'with', 'at', 'by', 'from', 'as', 'into', 'through', 'during',
        'before', 'after', 'above', 'below', 'between', 'under', 'again',
        'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how',
        'all', 'each', 'few', 'more', 'most', 'other', 'some', 'such',
        'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too',
        'very', 'just', 'and', 'but', 'if', 'or', 'because', 'until',
        'while', 'what', 'which', 'who', 'whom', 'this', 'that', 'these',
        'those', 'am', 'show', 'me', 'find', 'get', 'see', 'look', 'tell',
        'give', 'any', 'events', 'event', 'logs', 'log', 'please', 'i',
        'you', 'my', 'your', 'we', 'our', 'they', 'their', 'it', 'its',
        'summarize', 'summary', 'describe', 'explain', 'activity',
        'involved', 'happened', 'occurred', 'about', 'signs', 'evidence',
        'did', 'there', 'were', 'anything', 'something',
    }
    
    question_lower = question.lower()
    keywords = []
    
    # Preserve multi-word DFIR terms
    for term in preserve_terms:
        if term in question_lower:
            keywords.append(term)
    
    # Extract quoted strings
    quoted = re.findall(r'"([^"]+)"', question)
    keywords.extend([q.lower() for q in quoted])
    
    # Extract usernames (e.g., rachel.b)
    usernames = re.findall(r'\b([A-Za-z]+\.[A-Za-z]+)\b', question)
    for u in usernames:
        keywords.append(u.lower())
    
    # Extract individual words
    words = re.findall(r'[A-Za-z][A-Za-z0-9]*', question)
    for word in words:
        w = word.lower()
        if w not in stop_words and len(w) >= 3 and w not in keywords:
            keywords.append(w)
    
    # Deduplicate
    seen = set()
    unique = []
    for k in keywords:
        if k not in seen:
            seen.add(k)
            unique.append(k)
    
    return unique[:15]


# =============================================================================
# MAIN SEARCH FUNCTION
# =============================================================================

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
    Improved semantic search with DFIR query expansion and diversification.
    
    Key improvements:
    1. Expands DFIR concepts (malware -> powershell, certutil, etc.)
    2. Searches search_blob field
    3. Diversifies results by event type
    4. Guarantees tagged events appear
    """
    index_name = f"case_{case_id}"
    
    # Step 1: Extract keywords AND expand DFIR concepts
    keywords = extract_keywords_from_question(question)
    dfir_terms = expand_query_for_dfir(question)
    
    # Combine: keywords first, then expansion terms not already in keywords
    all_terms = keywords + [t for t in dfir_terms if t.lower() not in {k.lower() for k in keywords}]
    
    if not all_terms:
        logger.warning("[AI_SEARCH] No search terms extracted")
        return [], "Could not extract search terms from your question."
    
    logger.info(f"[AI_SEARCH] User keywords: {keywords}")
    logger.info(f"[AI_SEARCH] DFIR expansion: {dfir_terms[:10]}...")
    logger.info(f"[AI_SEARCH] Total search terms: {len(all_terms)}")
    
    # Step 2: Build query with search_blob included
    should_clauses = []
    
    # IMPORTANT: Include search_blob - that's where the data is!
    search_fields = [
        "search_blob^1.5",       # THE MAIN DATA FIELD
        "event_title^3",         # Human-readable title
        "event_description^2",
        "command_line^2",        # Critical for malware
        "process_name",
        "file_path",
        "username",
        "computer_name",
    ]
    
    # User's original keywords get high boost
    for keyword in keywords[:10]:
        should_clauses.append({
            "multi_match": {
                "query": keyword,
                "fields": search_fields,
                "type": "best_fields",
                "fuzziness": "AUTO",
                "boost": 3.0
            }
        })
    
    # DFIR expansion terms get moderate boost
    for term in dfir_terms[:20]:
        should_clauses.append({
            "multi_match": {
                "query": term,
                "fields": search_fields,
                "type": "phrase_prefix" if ' ' in term else "best_fields",
                "boost": 1.5
            }
        })
    
    # Boost flagged events
    if boost_tagged:
        should_clauses.append({"term": {"is_tagged": {"value": True, "boost": 15.0}}})
    if include_sigma:
        should_clauses.append({"term": {"has_sigma": {"value": True, "boost": 8.0}}})
    if include_ioc:
        should_clauses.append({"term": {"has_ioc": {"value": True, "boost": 6.0}}})
    
    query = {
        "bool": {
            "should": should_clauses,
            "minimum_should_match": 1
        }
    }
    
    # Step 3: Execute search with diversity (via collapse or aggs)
    candidate_count = min(max_results * 8, 200)  # Get more candidates for diversity
    
    try:
        # First query: Get diverse results by collapsing on event_id
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": candidate_count,
                "collapse": {
                    "field": "normalized_event_id",
                    "inner_hits": {
                        "name": "same_type",
                        "size": 2  # Max 2 more per event type
                    }
                },
                "sort": [
                    {"_score": {"order": "desc"}},
                    {"normalized_timestamp": {"order": "desc"}}
                ],
                "_source": True,
                "timeout": "30s"
            },
            request_timeout=35
        )
        
        # Collect results with diversity
        candidates = []
        event_ids_seen = set()
        
        for hit in response['hits']['hits']:
            # Add main hit
            event = {
                '_id': hit['_id'],
                '_index': hit['_index'],
                '_score': hit.get('_score', 0),
                '_source': hit['_source']
            }
            if hit['_id'] not in event_ids_seen:
                candidates.append(event)
                event_ids_seen.add(hit['_id'])
            
            # Add inner hits (same event type)
            inner = hit.get('inner_hits', {}).get('same_type', {}).get('hits', {}).get('hits', [])
            for ih in inner:
                if ih['_id'] not in event_ids_seen:
                    candidates.append({
                        '_id': ih['_id'],
                        '_index': ih['_index'],
                        '_score': ih.get('_score', 0),
                        '_source': ih['_source']
                    })
                    event_ids_seen.add(ih['_id'])
        
        total_hits = response['hits']['total']['value'] if isinstance(response['hits']['total'], dict) else response['hits']['total']
        logger.info(f"[AI_SEARCH] Query returned {total_hits} total, diversified to {len(candidates)}")
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Search error: {e}")
        # Fallback to simple search
        try:
            response = opensearch_client.search(
                index=index_name,
                body={
                    "query": {"query_string": {"query": " OR ".join(all_terms[:10]), "lenient": True}},
                    "size": candidate_count,
                    "_source": True
                }
            )
            candidates = [
                {'_id': h['_id'], '_index': h['_index'], '_score': h.get('_score', 0), '_source': h['_source']}
                for h in response['hits']['hits']
            ]
            total_hits = len(candidates)
        except:
            return [], f"Search error: {str(e)}"
    
    # Step 4: Fetch tagged events from database (they may not match keywords)
    if boost_tagged:
        try:
            from models import TimelineTag
            from sqlalchemy import and_
            tagged_records = TimelineTag.query.filter(
                and_(TimelineTag.case_id == case_id, TimelineTag.index_name == index_name)
            ).limit(15).all()
            
            tagged_ids = [t.event_id for t in tagged_records]
            new_tagged_ids = [tid for tid in tagged_ids if tid not in event_ids_seen]
            
            if new_tagged_ids:
                tagged_response = opensearch_client.mget(index=index_name, body={"ids": new_tagged_ids})
                for doc in tagged_response.get('docs', []):
                    if doc.get('found') and doc['_id'] not in event_ids_seen:
                        candidates.insert(0, {  # Insert at front
                            '_id': doc['_id'],
                            '_index': doc['_index'],
                            '_score': 100.0,
                            '_source': doc['_source']
                        })
                        event_ids_seen.add(doc['_id'])
                logger.info(f"[AI_SEARCH] Added {len(new_tagged_ids)} tagged events from database")
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Failed to fetch tagged events: {e}")
    
    if not candidates:
        return [], f"No events found matching your query."
    
    # Step 5: Semantic re-ranking
    embedding_available = _load_embedding_model() is not None
    
    if embedding_available and len(candidates) > 1:
        try:
            question_embedding = get_embedding(question)
            if question_embedding is not None:
                summaries = [create_event_summary(c) for c in candidates]
                event_embeddings = get_embeddings_batch(summaries)
                
                if event_embeddings is not None:
                    similarities = cosine_similarity_batch(question_embedding, event_embeddings)
                    
                    os_scores = np.array([c['_score'] for c in candidates])
                    os_scores_norm = os_scores / (os_scores.max() + 0.001)
                    
                    # Base score: 50% keyword, 50% semantic
                    base_scores = 0.5 * os_scores_norm + 0.5 * similarities
                    
                    # Apply multiplicative boosts
                    combined_scores = np.zeros(len(candidates))
                    for i, c in enumerate(candidates):
                        src = c.get('_source', {})
                        boost = 1.0
                        
                        if src.get('is_tagged'):
                            boost *= 3.0  # Tagged = analyst verified important
                        if src.get('has_sigma'):
                            level = src.get('sigma_level', 'medium')
                            boost *= {'critical': 2.5, 'high': 2.0, 'medium': 1.5, 'low': 1.2}.get(level, 1.3)
                        if src.get('has_ioc'):
                            boost *= 1.5
                        
                        combined_scores[i] = base_scores[i] * boost
                    
                    ranked_idx = np.argsort(combined_scores)[::-1]
                    candidates = [candidates[i] for i in ranked_idx]
                    
                    for i, idx in enumerate(ranked_idx):
                        if i < len(candidates):
                            candidates[i]['_semantic_score'] = float(similarities[idx])
                            candidates[i]['_combined_score'] = float(combined_scores[idx])
                    
                    logger.info("[AI_SEARCH] Re-ranked with semantic similarity")
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Semantic re-ranking failed: {e}")
    
    explanation = f"Found {total_hits} events, showing top {min(len(candidates), max_results)} (diversified by event type)"
    return candidates[:max_results], explanation


# =============================================================================
# LLM ANSWER GENERATION
# =============================================================================

def generate_ai_answer(
    question: str,
    events: List[Dict],
    case_name: str,
    model: str = DEFAULT_LLM_MODEL,
    stream: bool = True
) -> Generator[str, None, None]:
    """Generate AI answer with DFIR-aware prompt"""
    
    MAX_CONTEXT_TOKENS = 6000
    CHARS_PER_TOKEN = 4
    
    event_context = []
    total_length = 0
    events_included = 0
    
    # Count flags for context
    tagged_count = sum(1 for e in events if e.get('_source', {}).get('is_tagged'))
    sigma_count = sum(1 for e in events if e.get('_source', {}).get('has_sigma'))
    ioc_count = sum(1 for e in events if e.get('_source', {}).get('has_ioc'))
    
    for i, event in enumerate(events[:15], 1):
        summary = create_event_summary(event)
        event_id = event.get('_id', f'event_{i}')
        event_text = f"### Event {i}\n{summary}"
        
        est_tokens = len(event_text) // CHARS_PER_TOKEN
        if total_length + est_tokens > MAX_CONTEXT_TOKENS:
            break
        
        event_context.append(event_text)
        total_length += est_tokens
        events_included = i
    
    events_text = "\n\n".join(event_context)
    logger.info(f"[AI_SEARCH] LLM context: {events_included} events, ~{total_length} tokens")
    
    # Enhanced DFIR-aware prompt
    prompt = f"""You are a senior Digital Forensics and Incident Response (DFIR) analyst investigating a security incident.

## CASE: {case_name}

## ANALYST'S QUESTION
{question}

## EVIDENCE SUMMARY
- {events_included} events retrieved
- {tagged_count} analyst-tagged (⭐ = manually verified as important)
- {sigma_count} SIGMA detections (⚠️ = matches threat detection rule)
- {ioc_count} IOC matches (🎯 = matches known bad indicator)

## KEY INTERPRETATION GUIDANCE
- **Event 4688** = Process created (look at CommandLine!)
- **Event 4624** = Successful logon (LogonType: 2=interactive, 3=network, 10=RDP)
- **Event 4625** = Failed logon (brute force indicator)
- **Event 4648** = Explicit credential use (pass-the-hash indicator)
- **Event 7045** = Service installed (persistence indicator)
- **Event 4698** = Scheduled task created (persistence indicator)
- **Sysmon 1** = Process with full command line
- **Sysmon 3** = Network connection

## EVIDENCE EVENTS

{events_text}

## YOUR ANALYSIS

Based on the evidence above, answer the analyst's question. Follow these rules:
1. **Reference events by number**: "Event 3 shows..." or "[Event 3]"
2. **Prioritize flagged events**: ⭐ tagged events are analyst-verified important
3. **Look for chains**: Process spawning process, logon then lateral movement, etc.
4. **Be specific**: Quote usernames, IPs, command lines, timestamps
5. **Acknowledge gaps**: If evidence is insufficient, say what's missing
6. **NO fabrication**: Only cite what's in the events above

YOUR ANALYSIS:
"""

    try:
        response = requests.post(
            OLLAMA_GENERATE_URL,
            json={
                "model": model,
                "prompt": prompt,
                "stream": stream,
                "options": {
                    "temperature": 0.3,
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
        logger.error(f"[AI_SEARCH] LLM error: {e}")
        yield f"\n\n❌ Error: {str(e)}"


def ai_question_search(
    opensearch_client,
    case_id: int,
    case_name: str,
    question: str,
    model: str = DEFAULT_LLM_MODEL,
    max_events: int = 20
) -> Generator[Dict, None, None]:
    """Main entry point for AI Question feature"""
    
    yield {"type": "status", "data": "Analyzing question and searching for relevant events..."}
    
    events, explanation = semantic_search_events(
        opensearch_client, case_id, question, max_results=max_events
    )
    
    if not events:
        yield {"type": "error", "data": "No relevant events found. Try rephrasing or using DFIR terms like 'powershell', 'lateral movement', 'persistence'."}
        return
    
    yield {"type": "status", "data": f"Found {len(events)} relevant events. Generating analysis..."}
    yield {"type": "events", "data": events}
    
    for chunk in generate_ai_answer(question, events, case_name, model):
        yield {"type": "chunk", "data": chunk}
    
    yield {"type": "done", "data": "Analysis complete"}


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'check_embedding_model_available',
    'get_embedding',
    'get_embeddings_batch',
    'semantic_search_events',
    'generate_ai_answer',
    'ai_question_search',
    'create_event_summary',
    'expand_query_for_dfir',
    'EMBEDDING_MODEL_NAME',
    'DEFAULT_LLM_MODEL',
    'DFIR_QUERY_EXPANSION',
]
