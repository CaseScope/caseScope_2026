"""
AI Assistant Routes
Provides natural language query, event analysis, threat hunting, and IOC extraction
"""

from flask import Blueprint, request, jsonify, current_app, redirect, url_for, flash
from flask_login import login_required, current_user
from functools import wraps
import logging
from utils.opensearch_client import get_opensearch_client
import json
from datetime import datetime

from app.ai.ai_toggle import require_ai, get_ai_status
from app.ai.vector_store import PatternStore
from app.ai.llm_client import LLMClient
from app.opensearch_indexer import OpenSearchIndexer
from app.config import (
    VECTOR_STORE_CONFIG,
    EMBEDDING_MODEL,
    LLM_MODEL_CHAT,
    LLM_MODEL_CODE,
    AI_MAX_CONTEXT_EVENTS,
    AI_RAG_TOP_K,
    OPENSEARCH_HOST,
    OPENSEARCH_PORT,
    OPENSEARCH_USE_SSL
)

logger = logging.getLogger(__name__)

ai_bp = Blueprint('ai', __name__)


# ============================================================================
# Decorator
# ============================================================================

def admin_required(f):
    """Decorator to require administrator role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'administrator':
            flash('Administrator access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# Helper Functions
# ============================================================================

def get_vector_store():
    """Get PatternStore instance"""
    return PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)


def get_llm_client():
    """Get LLMClient instance"""
    return LLMClient(LLM_MODEL_CHAT, LLM_MODEL_CODE)


def get_opensearch_client():
    """Get OpenSearch indexer instance"""
    return OpenSearchIndexer(
        host=OPENSEARCH_HOST,
        port=OPENSEARCH_PORT,
        use_ssl=OPENSEARCH_USE_SSL
    )


# ============================================================================
# Status Endpoint
# ============================================================================

@ai_bp.route('/api/ai/status', methods=['GET'])
@login_required
def api_ai_status():
    """
    Get AI system status
    Returns component health and availability
    """
    try:
        status = get_ai_status()
        return jsonify(status), 200
    except Exception as e:
        logger.error(f"Error getting AI status: {e}")
        return jsonify({
            'error': 'Failed to get AI status',
            'message': str(e)
        }), 500


# ============================================================================
# Natural Language Query → OpenSearch DSL
# ============================================================================

@ai_bp.route('/api/ai/query', methods=['POST'])
@login_required
@admin_required
@require_ai
def api_ai_query():
    """
    Convert natural language question to OpenSearch query and execute
    
    Request:
        {
            "question": "Show me failed login attempts from the last 24 hours",
            "case_id": 123,  # Optional: filter to specific case
            "limit": 50      # Optional: max events to return
        }
    
    Response:
        {
            "success": true,
            "question": "...",
            "dsl_query": {...},
            "patterns_used": [...],
            "events": [...],
            "event_count": 42,
            "execution_time_ms": 1234
        }
    """
    start_time = datetime.utcnow()
    
    try:
        data = request.get_json()
        question = data.get('question', '').strip()
        case_id = data.get('case_id')
        limit = min(data.get('limit', 50), AI_MAX_CONTEXT_EVENTS)
        
        if not question:
            return jsonify({'error': 'Question is required'}), 400
        
        logger.info(f"AI Query from {current_user.username}: {question}")
        
        # 1. Get relevant patterns from vector store
        vector_store = get_vector_store()
        patterns = vector_store.search(question, k=AI_RAG_TOP_K)
        
        # Build context for LLM
        pattern_context = "\n".join([
            f"[{p['source'].upper()}] {p.get('metadata', {}).get('title') or p.get('metadata', {}).get('name') or p['id']}"
            for p in patterns
        ])
        
        # 2. Generate OpenSearch DSL using LLM
        llm_client = get_llm_client()
        
        # Get available fields from OpenSearch
        index_fields = [
            'event_id', 'normalized_event_id', 'normalized_timestamp',
            'normalized_computer', 'normalized_username', 'search_blob',
            'file_type', 'source_file', 'case_id'
        ]
        
        dsl_query = llm_client.generate_opensearch_dsl(
            question=question,
            index_fields=index_fields,
            patterns_context=pattern_context
        )
        
        # Add case filter if specified
        if case_id:
            if 'query' not in dsl_query:
                dsl_query['query'] = {}
            
            if 'bool' not in dsl_query['query']:
                original_query = dsl_query['query']
                dsl_query['query'] = {
                    'bool': {
                        'must': [original_query]
                    }
                }
            
            if 'must' not in dsl_query['query']['bool']:
                dsl_query['query']['bool']['must'] = []
            
            dsl_query['query']['bool']['must'].append({
                'term': {'case_id': case_id}
            })
        
        # 3. Execute query against OpenSearch
        os_client = get_opensearch_client()
        
        # Add size limit
        dsl_query['size'] = limit
        
        # Execute search
        response = os_client.client.search(
            index='events-*',
            body=dsl_query
        )
        
        # Parse results
        events = []
        for hit in response['hits']['hits']:
            event = hit['_source']
            event['_score'] = hit['_score']
            events.append(event)
        
        # Calculate execution time
        execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        # Audit log
        from audit_logger import log_action
        log_action(
            'ai_query',
            resource_type='search',
            resource_id=case_id,
            resource_name='AI Natural Language Query',
            details={
                'question': question,
                'event_count': len(events),
                'patterns_used': len(patterns)
            }
        )
        
        return jsonify({
            'success': True,
            'question': question,
            'dsl_query': dsl_query,
            'patterns_used': [
                {
                    'id': p['id'],
                    'source': p['source'],
                    'title': p.get('metadata', {}).get('title') or p.get('metadata', {}).get('name'),
                    'score': p['score']
                }
                for p in patterns
            ],
            'events': events,
            'event_count': len(events),
            'total_hits': response['hits']['total']['value'],
            'execution_time_ms': round(execution_time, 2)
        }), 200
        
    except Exception as e:
        logger.error(f"AI query error: {e}", exc_info=True)
        return jsonify({
            'error': 'AI query failed',
            'message': str(e)
        }), 500


# ============================================================================
# Event Analysis
# ============================================================================

@ai_bp.route('/api/ai/analyze', methods=['POST'])
@login_required
@admin_required
@require_ai
def api_ai_analyze():
    """
    Analyze events using AI with RAG context
    
    Request:
        {
            "events": [...],           # Events to analyze
            "question": "What happened?",  # Optional: specific question
            "context": "..."           # Optional: additional context
        }
    
    Response:
        {
            "success": true,
            "analysis": "...",
            "patterns_referenced": [...],
            "key_findings": [...],
            "mitre_techniques": [...]
        }
    """
    try:
        data = request.get_json()
        events = data.get('events', [])
        question = data.get('question', 'Analyze these events and explain what happened.')
        context = data.get('context', '')
        
        if not events:
            return jsonify({'error': 'Events are required'}), 400
        
        # Limit events to prevent token overflow
        events = events[:AI_MAX_CONTEXT_EVENTS]
        
        logger.info(f"AI Analysis from {current_user.username}: {len(events)} events")
        
        # 1. Build search query from events
        event_summary = f"Events involving: "
        computers = set()
        event_ids = set()
        
        for event in events:
            if event.get('normalized_computer'):
                computers.add(event['normalized_computer'])
            if event.get('normalized_event_id'):
                event_ids.add(str(event['normalized_event_id']))
        
        event_summary += f"{len(computers)} hosts, event IDs: {', '.join(list(event_ids)[:5])}"
        
        # 2. Get relevant patterns
        vector_store = get_vector_store()
        patterns = vector_store.search(event_summary + " " + question, k=AI_RAG_TOP_K)
        
        # Build pattern context
        pattern_context = "\n".join([
            f"{p['content'][:300]}..."  # Include more detail for analysis
            for p in patterns
        ])
        
        # 3. Analyze with LLM
        llm_client = get_llm_client()
        
        analysis = llm_client.analyze_events(
            events=events,
            question=question,
            patterns_context=pattern_context
        )
        
        # Audit log
        from audit_logger import log_action
        log_action(
            'ai_analyze',
            resource_type='analysis',
            resource_id=None,
            resource_name='AI Event Analysis',
            details={
                'event_count': len(events),
                'question': question
            }
        )
        
        return jsonify({
            'success': True,
            'analysis': analysis,
            'patterns_referenced': [
                {
                    'id': p['id'],
                    'source': p['source'],
                    'title': p.get('metadata', {}).get('title') or p.get('metadata', {}).get('name'),
                    'score': p['score']
                }
                for p in patterns
            ],
            'event_count': len(events)
        }), 200
        
    except Exception as e:
        logger.error(f"AI analysis error: {e}", exc_info=True)
        return jsonify({
            'error': 'AI analysis failed',
            'message': str(e)
        }), 500


# ============================================================================
# Threat Hunting Query Generation
# ============================================================================

@ai_bp.route('/api/ai/hunt', methods=['POST'])
@login_required
@admin_required
@require_ai
def api_ai_hunt():
    """
    Generate hunt queries based on a known bad event
    
    Request:
        {
            "event": {...},          # The known malicious event
            "hunt_scope": "all"      # "host", "user", "network", "all"
        }
    
    Response:
        {
            "success": true,
            "hunt_queries": [
                {
                    "description": "...",
                    "dsl": {...},
                    "rationale": "..."
                }
            ]
        }
    """
    try:
        data = request.get_json()
        event = data.get('event')
        hunt_scope = data.get('hunt_scope', 'all')
        
        if not event:
            return jsonify({'error': 'Event is required'}), 400
        
        logger.info(f"AI Hunt from {current_user.username}: scope={hunt_scope}")
        
        # 1. Get relevant attack patterns
        event_summary = f"Malicious activity: Event ID {event.get('event_id', 'unknown')}"
        if event.get('normalized_computer'):
            event_summary += f" on {event['normalized_computer']}"
        
        vector_store = get_vector_store()
        patterns = vector_store.search(event_summary, k=AI_RAG_TOP_K)
        
        pattern_context = "\n".join([p['content'][:200] for p in patterns])
        
        # 2. Generate hunt queries
        llm_client = get_llm_client()
        
        hunt_queries = llm_client.generate_hunt_queries(
            bad_event=event,
            patterns_context=pattern_context
        )
        
        # Audit log
        from audit_logger import log_action
        log_action(
            'ai_hunt',
            resource_type='hunt',
            resource_id=None,
            resource_name='AI Hunt Query Generation',
            details={
                'event_id': event.get('event_id'),
                'scope': hunt_scope,
                'queries_generated': len(hunt_queries)
            }
        )
        
        return jsonify({
            'success': True,
            'hunt_queries': hunt_queries,
            'patterns_used': [
                {
                    'id': p['id'],
                    'source': p['source'],
                    'title': p.get('metadata', {}).get('title') or p.get('metadata', {}).get('name')
                }
                for p in patterns
            ]
        }), 200
        
    except Exception as e:
        logger.error(f"AI hunt error: {e}", exc_info=True)
        return jsonify({
            'error': 'AI hunt query generation failed',
            'message': str(e)
        }), 500


# ============================================================================
# RAG Chat Assistant
# ============================================================================

@ai_bp.route('/api/ai/chat', methods=['POST'])
@login_required
@admin_required
@require_ai
def api_ai_chat():
    """
    Chat with AI assistant using RAG
    
    Request:
        {
            "message": "How do I detect lateral movement?",
            "history": [              # Optional: conversation history
                {"role": "user", "content": "..."},
                {"role": "assistant", "content": "..."}
            ],
            "context_events": [...]   # Optional: events for context
        }
    
    Response:
        {
            "success": true,
            "response": "...",
            "patterns_used": [...]
        }
    """
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        history = data.get('history', [])
        context_events = data.get('context_events', [])
        
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        
        logger.info(f"AI Chat from {current_user.username}: {message[:50]}")
        
        # 1. Get relevant patterns
        vector_store = get_vector_store()
        patterns = vector_store.search(message, k=AI_RAG_TOP_K)
        
        # Build context
        context_parts = []
        
        # Add pattern context
        for p in patterns:
            title = p.get('metadata', {}).get('title') or p.get('metadata', {}).get('name')
            context_parts.append(f"[{p['source'].upper()}] {title}")
        
        # Add event context if provided
        if context_events:
            context_parts.append(f"\nCurrent events: {len(context_events)} events loaded")
        
        context = "\n".join(context_parts)
        
        # 2. Generate response
        llm_client = get_llm_client()
        
        response = llm_client.chat(
            message=message,
            history=history[-10:],  # Last 10 messages
            context=context
        )
        
        # Audit log
        from audit_logger import log_action
        log_action(
            'ai_chat',
            resource_type='chat',
            resource_id=None,
            resource_name='AI Assistant Chat',
            details={
                'message_length': len(message)
            }
        )
        
        return jsonify({
            'success': True,
            'response': response,
            'patterns_used': [
                {
                    'id': p['id'],
                    'source': p['source'],
                    'title': p.get('metadata', {}).get('title') or p.get('metadata', {}).get('name'),
                    'score': p['score']
                }
                for p in patterns
            ]
        }), 200
        
    except Exception as e:
        logger.error(f"AI chat error: {e}", exc_info=True)
        return jsonify({
            'error': 'AI chat failed',
            'message': str(e)
        }), 500


# ============================================================================
# IOC Extraction
# ============================================================================

@ai_bp.route('/api/ai/ioc', methods=['POST'])
@login_required
@require_ai
def api_ai_ioc():
    """
    Extract IOCs from text or events
    
    Request:
        {
            "text": "...",           # Raw text to extract from
            "events": [...]          # Or events to extract from
        }
    
    Response:
        {
            "success": true,
            "iocs": {
                "ip_addresses": [...],
                "domains": [...],
                "urls": [...],
                "file_hashes": {...},
                "email_addresses": [...],
                "file_names": [...],
                "registry_keys": [...],
                "cve_ids": [...]
            }
        }
    """
    try:
        data = request.get_json()
        text = data.get('text', '')
        events = data.get('events', [])
        
        if not text and not events:
            return jsonify({'error': 'Text or events required'}), 400
        
        # Build text from events if provided
        if events and not text:
            text_parts = []
            for event in events[:20]:  # Limit to 20 events
                if event.get('search_blob'):
                    text_parts.append(event['search_blob'][:500])
            text = "\n".join(text_parts)
        
        logger.info(f"AI IOC extraction from {current_user.username}: {len(text)} chars")
        
        # Extract IOCs
        llm_client = get_llm_client()
        iocs = llm_client.extract_iocs(text)
        
        # Audit log
        total_iocs = sum([
            len(iocs.get('ip_addresses', [])),
            len(iocs.get('domains', [])),
            len(iocs.get('urls', [])),
            sum(len(v) for v in iocs.get('file_hashes', {}).values()),
            len(iocs.get('email_addresses', [])),
            len(iocs.get('file_names', [])),
            len(iocs.get('registry_keys', [])),
            len(iocs.get('cve_ids', []))
        ])
        
        from audit_logger import log_action
        log_action(
            'ai_ioc_extraction',
            resource_type='ioc',
            resource_id=None,
            resource_name='AI IOC Extraction',
            details={
                'text_length': len(text),
                'iocs_found': total_iocs
            }
        )
        
        return jsonify({
            'success': True,
            'iocs': iocs,
            'total_iocs': total_iocs
        }), 200
        
    except Exception as e:
        logger.error(f"AI IOC extraction error: {e}", exc_info=True)
        return jsonify({
            'error': 'AI IOC extraction failed',
            'message': str(e)
        }), 500

