"""Chat Agent Routes for CaseScope

SSE endpoint for the DFIR chat assistant. Streams AI responses
with tool calls back to the frontend in real-time.

Endpoints:
- POST /api/chat/stream   - SSE stream for chat with tool execution
- GET  /api/chat/context   - Get case context for chat initialization
"""

import logging
import json
import uuid
from flask import Blueprint, request, Response, jsonify, stream_with_context
from flask_login import login_required, current_user

from models.case import Case
from models.system_settings import SystemSettings, SettingKeys

logger = logging.getLogger(__name__)

chat_bp = Blueprint('chat', __name__, url_prefix='/api/chat')


@chat_bp.route('/stream', methods=['POST'])
@login_required
def chat_stream():
    """SSE streaming endpoint for chat agent.
    
    Request JSON:
        case_id: int (required)
        message: str (required) - user's question
        conversation: list - prior messages [{role, content}]
        conversation_id: str - optional tracking ID
        
    Response:
        SSE stream with events:
        - token: {content: "..."} - streamed text
        - tool_start: {tools: [...]} - tool execution starting
        - tool_result: {tool: "...", result_preview: "..."} - tool result
        - tool_end: {} - tool execution complete
        - done: {tool_rounds: N} - generation complete
        - error: {error: "..."} - error occurred
    """
    from utils.chat_agent import chat_stream as agent_stream
    
    data = request.json or {}
    case_id = data.get('case_id')
    message = data.get('message', '').strip()
    conversation = data.get('conversation', [])
    conversation_id = data.get('conversation_id') or str(uuid.uuid4())
    
    # Validation
    if not case_id:
        return jsonify({'success': False, 'error': 'case_id required'}), 400
    
    if not message:
        return jsonify({'success': False, 'error': 'message required'}), 400
    
    # Check AI enabled
    ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
    if not ai_enabled:
        return jsonify({'success': False, 'error': 'AI features are disabled in settings'}), 400
    
    # Verify case exists and user has access
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Build messages list
    messages = []
    
    # Add conversation history (limit to last 10 exchanges)
    for msg in conversation[-20:]:
        role = msg.get('role', 'user')
        content = msg.get('content', '')
        if role in ('user', 'assistant') and content:
            messages.append({"role": role, "content": content})
    
    # Add current message
    messages.append({"role": "user", "content": message})
    
    logger.info(f"[Chat] User {current_user.username} chat for case {case_id}: {message[:100]}")
    
    def generate():
        try:
            for event in agent_stream(case_id, messages, conversation_id):
                yield event
        except Exception as e:
            logger.error(f"[Chat] Stream error: {e}", exc_info=True)
            error_payload = {"type": "error", "error": str(e)}
            yield f"data: {json.dumps(error_payload)}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


@chat_bp.route('/context/<int:case_id>', methods=['GET'])
@login_required
def get_context(case_id):
    """Get case context for chat initialization.
    
    Returns case name, hosts, analysis status, etc.
    Used by the frontend to display context before the user starts chatting.
    """
    from utils.chat_agent import get_case_context
    
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    context = get_case_context(case_id)
    
    # Check AI availability
    ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
    
    return jsonify({
        'success': True,
        'ai_enabled': ai_enabled,
        'case_name': context.get('case_name', ''),
        'hosts': context.get('hosts', []),
        'has_analysis': bool(context.get('analysis_summary')),
        'has_synthesis': bool(context.get('ai_synthesis'))
    })
