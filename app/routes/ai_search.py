#!/usr/bin/env python3
"""
CaseScope AI Search Routes
Provides endpoints for RAG-based question answering on case events

Routes:
- GET  /case/<id>/ai-search           - AI Question page (or modal content)
- POST /case/<id>/ai-search/ask       - Submit question, get streaming response
- GET  /case/<id>/ai-search/status    - Check AI service status
"""

from flask import Blueprint, render_template, request, jsonify, Response, stream_with_context, current_app
from flask_login import login_required, current_user
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

ai_search_bp = Blueprint('ai_search', __name__)

# Rate limiting will be applied via decorator from main.limiter


@ai_search_bp.route('/case/<int:case_id>/ai-search/status')
@login_required
def ai_search_status(case_id):
    """
    Check if AI search is available (Ollama running, models installed)
    
    Returns JSON:
    {
        "available": true/false,
        "ollama_running": true/false,
        "embedding_model": "nomic-embed-text",
        "embedding_available": true/false,
        "llm_models": ["dfir-llama:latest", ...],
        "error": null or "error message"
    }
    """
    from ai_search import check_embedding_model_available, DEFAULT_LLM_MODEL
    from ai_report import check_ollama_status
    
    # Check Ollama status
    ollama_status = check_ollama_status()
    embed_status = check_embedding_model_available()
    
    # Check if at least one LLM is available
    llm_available = ollama_status.get('model_available', False)
    
    return jsonify({
        "available": ollama_status.get('running', False) and llm_available,
        "ollama_running": ollama_status.get('running', False),
        "embedding_model": embed_status.get('model'),
        "embedding_available": embed_status.get('available', False),
        "llm_models": ollama_status.get('model_names', []),
        "default_llm": DEFAULT_LLM_MODEL,
        "error": ollama_status.get('error') or embed_status.get('error')
    })


@ai_search_bp.route('/case/<int:case_id>/ai-search/ask', methods=['POST'])
@login_required
def ai_search_ask(case_id):
    """
    Submit a question and get AI-generated answer based on case events
    
    RATE LIMIT: 10 AI questions per minute per user (prevents GPU exhaustion)
    
    Request JSON:
    {
        "question": "What lateral movement occurred?",
        "model": "dfir-llama:latest",  // optional
        "max_events": 20  // optional
    }
    
    Returns: Server-Sent Events (SSE) stream with:
    - status: Progress updates
    - events: Retrieved event IDs
    - chunk: Response text chunks
    - done: Completion signal
    - error: Error messages
    """
    from models import db, Case
    from main import opensearch_client
    from ai_search import ai_question_search, DEFAULT_LLM_MODEL
    from audit_logger import log_action
    
    # Get case
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    
    # Parse request
    data = request.get_json() or {}
    question = data.get('question', '').strip()
    model = data.get('model', DEFAULT_LLM_MODEL)
    max_events = min(data.get('max_events', 20), 50)  # Cap at 50
    
    if not question:
        return jsonify({"error": "Question is required"}), 400
    
    if len(question) > 1000:
        return jsonify({"error": "Question too long (max 1000 characters)"}), 400
    
    # Log the action
    log_action(
        action='ai_search_question',
        resource_type='case',
        resource_id=case_id,
        resource_name=case.name,
        details=f"Question: {question[:100]}... (User: {current_user.username}, IP: {request.remote_addr})"
    )
    
    def generate():
        """Generator for SSE stream"""
        try:
            for update in ai_question_search(
                opensearch_client,
                case_id,
                case.name,
                question,
                model=model,
                max_events=max_events
            ):
                update_type = update.get('type', 'unknown')
                update_data = update.get('data', '')
                
                if update_type == 'events':
                    # Send event data for frontend to display directly
                    from search_utils import extract_event_fields
                    event_list = []
                    for e in update_data:
                        fields = extract_event_fields(e.get('_source', {}))
                        fields['_id'] = e.get('_id')
                        fields['_index'] = e.get('_index')
                        event_list.append(fields)
                    # Use default=str to handle datetime and other non-serializable objects
                    yield f"data: {json.dumps({'type': 'events', 'data': event_list}, default=str)}\n\n"
                elif update_type == 'chunk':
                    yield f"data: {json.dumps({'type': 'chunk', 'data': update_data})}\n\n"
                elif update_type == 'status':
                    yield f"data: {json.dumps({'type': 'status', 'data': update_data})}\n\n"
                elif update_type == 'error':
                    yield f"data: {json.dumps({'type': 'error', 'data': update_data})}\n\n"
                elif update_type == 'done':
                    yield f"data: {json.dumps({'type': 'done', 'data': update_data})}\n\n"
                    
        except Exception as e:
            logger.error(f"[AI_SEARCH] Stream error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'data': str(e)})}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'  # Disable nginx buffering
        }
    )


@ai_search_bp.route('/case/<int:case_id>/ai-search/events', methods=['POST'])
@login_required  
def ai_search_get_events(case_id):
    """
    Get full event details for a list of event IDs
    Used by frontend to display events after AI analysis
    
    Request JSON:
    {
        "event_ids": ["id1", "id2", ...]
    }
    
    Returns JSON:
    {
        "events": [
            {"_id": "...", "timestamp": "...", "event_id": "...", ...},
            ...
        ]
    }
    """
    from models import db, Case
    from main import opensearch_client
    from search_utils import extract_event_fields
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    
    data = request.get_json() or {}
    event_ids = data.get('event_ids', [])
    
    if not event_ids:
        return jsonify({"events": []})
    
    if len(event_ids) > 100:
        event_ids = event_ids[:100]  # Limit to 100
    
    index_name = f"case_{case_id}"
    
    try:
        # Multi-get events
        response = opensearch_client.mget(
            index=index_name,
            body={"ids": event_ids}
        )
        
        events = []
        for doc in response.get('docs', []):
            if doc.get('found'):
                fields = extract_event_fields(doc['_source'])
                fields['_id'] = doc['_id']
                fields['_source'] = doc['_source']
                events.append(fields)
        
        return jsonify({"events": events})
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Error fetching events: {e}")
        return jsonify({"error": str(e)}), 500


@ai_search_bp.route('/case/<int:case_id>/ai-search/store-evidence', methods=['POST'])
@login_required
def store_ai_evidence(case_id):
    """Store AI evidence event IDs in session for filtered display"""
    data = request.get_json() or {}
    event_ids = data.get('event_ids', [])
    
    if not event_ids:
        return jsonify({"error": "No event IDs provided"}), 400
    
    # Store in session
    from flask import session
    session['ai_evidence_ids'] = event_ids[:50]  # Limit to 50 events
    session['ai_evidence_case_id'] = case_id
    
    logger.info(f"[AI_SEARCH] Stored {len(event_ids)} AI evidence event IDs for case {case_id}")
    
    return jsonify({"success": True, "count": len(session['ai_evidence_ids'])})


# Register blueprint function (call from main.py)
def register_ai_search_routes(app):
    """Register AI search blueprint with Flask app"""
    app.register_blueprint(ai_search_bp)
    logger.info("[AI_SEARCH] AI Search routes registered")
