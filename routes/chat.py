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
from models.database import db
from models.rag import ChatConversationSession
from utils.feature_availability import FeatureAvailability

logger = logging.getLogger(__name__)

chat_bp = Blueprint('chat', __name__, url_prefix='/api/chat')


def _load_or_create_chat_session(case_id: int, user_id: str,
                                 conversation_id: str = None):
    """Resolve a chat session bound to the current user and case."""
    if conversation_id:
        existing = ChatConversationSession.get_by_conversation_id(conversation_id)
        if existing:
            if existing.case_id != case_id or existing.user_id != user_id:
                return None, False, 'conversation_mismatch'
            return existing, False, None

    session = ChatConversationSession(
        case_id=case_id,
        user_id=user_id,
        conversation_id=conversation_id or str(uuid.uuid4()),
        messages=[],
    )
    db.session.add(session)
    db.session.commit()
    return session, True, None


def _persist_chat_session(session: ChatConversationSession, messages):
    """Persist the server-authoritative transcript for a chat session."""
    try:
        session.replace_messages(messages)
        db.session.add(session)
        db.session.commit()
    except Exception as exc:
        logger.error("[Chat] Failed to persist conversation %s: %s",
                     session.conversation_id, exc, exc_info=True)
        db.session.rollback()


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
    conversation_id = data.get('conversation_id') or str(uuid.uuid4())
    
    # Validation
    if not case_id:
        return jsonify({'success': False, 'error': 'case_id required'}), 400
    
    if not message:
        return jsonify({'success': False, 'error': 'message required'}), 400
    
    # Check AI enabled
    if not FeatureAvailability.is_ai_enabled():
        return jsonify({'success': False, 'error': 'AI features are not currently available'}), 400
    
    # Verify case exists and user has access
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404

    session, _, session_error = _load_or_create_chat_session(
        case_id=case_id,
        user_id=current_user.username,
        conversation_id=conversation_id,
    )
    if session_error == 'conversation_mismatch':
        return jsonify({
            'success': False,
            'error': 'Conversation does not belong to the current case',
            'error_code': 'conversation_mismatch',
        }), 409

    messages = list(session.messages or [])
    messages.append({"role": "user", "content": message})
    
    logger.info(f"[Chat] User {current_user.username} chat for case {case_id}: {message[:100]}")
    
    def generate():
        try:
            for event in agent_stream(
                case_id,
                messages,
                session.conversation_id,
                on_complete=lambda history: _persist_chat_session(session, history),
            ):
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
    
    return jsonify({
        'success': True,
        'ai_enabled': FeatureAvailability.is_ai_enabled(),
        'case_id': case_id,
        'case_name': context.get('case_name', ''),
        'hosts': context.get('hosts', []),
        'has_analysis': bool(context.get('analysis_summary')),
        'has_synthesis': bool(context.get('ai_synthesis'))
    })


@chat_bp.route('/conversation/<conversation_id>', methods=['DELETE'])
@login_required
def clear_conversation(conversation_id):
    """Delete a specific chat conversation for the current user and case."""
    case_id = request.args.get('case_id', type=int)
    if not case_id:
        return jsonify({'success': False, 'error': 'case_id required'}), 400

    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404

    session = ChatConversationSession.get_for_user_case(
        case_id=case_id,
        user_id=current_user.username,
        conversation_id=conversation_id,
    )
    if not session:
        return jsonify({'success': False, 'error': 'Conversation not found'}), 404

    try:
        db.session.delete(session)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as exc:
        logger.error("[Chat] Failed to delete conversation %s: %s",
                     conversation_id, exc, exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(exc)}), 500
