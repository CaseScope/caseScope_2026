"""Chat Agent Routes for CaseScope

SSE endpoint for the DFIR chat assistant. Streams AI responses
with tool calls back to the frontend in real-time.

Endpoints:
- POST /api/chat/stream   - SSE stream for chat with tool execution
- GET  /api/chat/context/<case_id> - Get case context and pending approval state
- GET  /api/chat/conversation/<conversation_id> - Restore display-safe transcript
- DELETE /api/chat/conversation/<conversation_id> - Clear a persisted transcript
"""

import logging
import json
import uuid
from typing import Any, Dict, List, Optional
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


def _decode_tool_arguments_from_history(tool_call: Dict[str, Any]) -> Dict[str, Any]:
    """Decode persisted tool-call arguments from history."""
    function_payload = tool_call.get('function') or {}
    raw_arguments = function_payload.get('arguments', {})
    if isinstance(raw_arguments, dict):
        return dict(raw_arguments)
    if isinstance(raw_arguments, str):
        try:
            decoded = json.loads(raw_arguments)
            return decoded if isinstance(decoded, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _get_latest_interrupted_tool(messages) -> Optional[Dict[str, Any]]:
    """Return the latest interrupted tool request from persisted history."""
    history = list(messages or [])
    resolved_tool_call_ids = set()

    for message in reversed(history):
        if message.get('role') != 'tool':
            continue

        tool_call_id = message.get('tool_call_id')
        try:
            payload = json.loads(message.get('content') or '{}')
        except (json.JSONDecodeError, TypeError):
            continue

        status = payload.get('status')
        if status in {'completed', 'rejected', 'error'}:
            if tool_call_id:
                resolved_tool_call_ids.add(tool_call_id)
            continue

        if status != 'interrupt':
            continue

        if tool_call_id and tool_call_id in resolved_tool_call_ids:
            continue

        latest_interrupt = {
            'tool_name': message.get('name'),
            'tool_call_id': tool_call_id,
            'permission': payload.get('permission', {}),
        }
        matched_tool_call = False

        for assistant_message in reversed(history):
            if assistant_message.get('role') != 'assistant':
                continue
            for tool_call in assistant_message.get('tool_calls') or []:
                if tool_call.get('id') != latest_interrupt.get('tool_call_id'):
                    continue
                latest_interrupt['tool_name'] = latest_interrupt.get('tool_name') or (tool_call.get('function') or {}).get('name')
                latest_interrupt['params'] = _decode_tool_arguments_from_history(tool_call)
                matched_tool_call = True
                break
            if matched_tool_call:
                break
        if (
            not matched_tool_call
            or not latest_interrupt.get('tool_name')
            or not isinstance(latest_interrupt.get('params'), dict)
        ):
            continue
        if latest_interrupt.get('tool_name'):
            try:
                from utils.chat import resolve_chat_tool_policy

                tier, provenance = resolve_chat_tool_policy(latest_interrupt['tool_name'])
                latest_interrupt['tier'] = tier.value
                latest_interrupt['provenance'] = provenance.value
            except Exception:
                pass
        return latest_interrupt

    return None


def _resolve_pending_tool_approval(messages, requested_approval: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Fill missing approval fields from the latest interrupted tool in history."""
    tool_approval = dict(requested_approval or {})
    if not tool_approval:
        return None

    if (
        tool_approval.get('tool_name')
        and isinstance(tool_approval.get('params'), dict)
        and tool_approval.get('params')
    ):
        return tool_approval

    latest_interrupt = _get_latest_interrupted_tool(messages)
    if latest_interrupt is None:
        return tool_approval

    tool_approval.setdefault('tool_name', latest_interrupt.get('tool_name'))
    tool_approval.setdefault('tool_call_id', latest_interrupt.get('tool_call_id'))
    if not isinstance(tool_approval.get('params'), dict) or not tool_approval.get('params'):
        tool_approval['params'] = latest_interrupt.get('params', {})
    tool_approval.setdefault('permission', latest_interrupt.get('permission', {}))
    tool_approval.setdefault('tier', latest_interrupt.get('tier'))
    tool_approval.setdefault('provenance', latest_interrupt.get('provenance'))

    return tool_approval


def _format_approval_history_note(content: str) -> Optional[str]:
    """Convert persisted internal approval notes into display-safe text."""
    if not content.startswith('[TOOL_APPROVAL]'):
        return content

    note = content.replace('[TOOL_APPROVAL]', '', 1).strip()
    if not note:
        return None
    decision, _, remainder = note.partition(' ')
    tool_name, _, reason = remainder.partition(':')
    tool_name = tool_name.strip() or 'tool'
    decision = decision.strip().lower()
    if decision == 'allow':
        return f"Approved {tool_name} request."
    if decision in {'reject', 'do_not_ask_reject'}:
        return f"Denied {tool_name} request."
    return reason.strip() or None


def _display_chat_messages(messages) -> List[Dict[str, str]]:
    """Return only messages safe and useful for frontend transcript replay."""
    display_messages: List[Dict[str, str]] = []
    for message in messages or []:
        role = message.get('role')
        if role not in {'user', 'assistant'}:
            continue
        content = str(message.get('content') or '').strip()
        if not content:
            continue
        if role == 'user':
            content = _format_approval_history_note(content) or ''
        if not content:
            continue
        display_messages.append({
            'role': role,
            'content': content,
        })
    return display_messages


@chat_bp.route('/stream', methods=['POST'])
@login_required
def chat_stream():
    """SSE streaming endpoint for chat agent.
    
    Request JSON:
        case_id: int (required)
        message: str - user's question
        tool_approval: dict - optional approval payload for a pending tool
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
    
    data = request.get_json(silent=True) or {}
    case_id_raw = data.get('case_id')
    message = data.get('message', '').strip()
    tool_approval = data.get('tool_approval') if isinstance(data.get('tool_approval'), dict) else None
    conversation_id = data.get('conversation_id') or str(uuid.uuid4())
    hunt_run_id_raw = data.get('hunt_run_id')
    hunt_run_id = None
    
    # Validation
    if case_id_raw in (None, ""):
        return jsonify({'success': False, 'error': 'case_id required'}), 400
    try:
        case_id = int(case_id_raw)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'case_id must be an integer'}), 400
    if hunt_run_id_raw not in (None, ""):
        try:
            hunt_run_id = int(hunt_run_id_raw)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'hunt_run_id must be an integer'}), 400
    
    if not message and not tool_approval:
        return jsonify({'success': False, 'error': 'message or tool_approval required'}), 400
    
    # Check AI enabled
    if not FeatureAvailability.is_ai_enabled():
        return jsonify({'success': False, 'error': 'AI features are not currently available'}), 400
    
    # Verify case exists and user has access
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    if hunt_run_id is not None:
        from models.hunt import HuntRun

        hunt_run = HuntRun.query.filter_by(id=hunt_run_id, case_id=case_id).first()
        if not hunt_run:
            return jsonify({'success': False, 'error': 'Hunt run not found for this case'}), 404

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
    tool_approval = _resolve_pending_tool_approval(messages, tool_approval)
    if message:
        messages.append({"role": "user", "content": message})

    if tool_approval and not tool_approval.get('tool_name'):
        return jsonify({
            'success': False,
            'error': 'No pending interrupted tool could be resolved for approval',
            'error_code': 'pending_tool_not_found',
        }), 409
    
    logger.info(
        "[Chat] User %s chat for case %s: %s",
        current_user.username,
        case_id,
        message[:100] if message else "[tool approval]",
    )
    
    def generate():
        try:
            for event in agent_stream(
                case_id,
                messages,
                session.conversation_id,
                tool_approval=tool_approval,
                hunt_run_id=hunt_run_id,
                actor_metadata={
                    "created_by_type": "ai",
                    "created_by": current_user.username,
                },
                on_complete=lambda history: _persist_chat_session(session, history),
            ):
                yield event.encode('utf-8') if isinstance(event, str) else event
        except Exception as e:
            logger.error(f"[Chat] Stream error: {e}", exc_info=True)
            error_payload = {"type": "error", "error": str(e)}
            yield f"data: {json.dumps(error_payload)}\n\n".encode('utf-8')
    
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
    """Get case context and any pending tool approval state for chat."""
    from utils.chat_agent import get_case_context
    
    case = Case.get_by_id(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    context = get_case_context(case_id)
    conversation_id = request.args.get('conversation_id', '').strip()
    pending_tool = None
    if conversation_id:
        session = ChatConversationSession.get_for_user_case(
            case_id=case_id,
            user_id=current_user.username,
            conversation_id=conversation_id,
        )
        if session:
            pending_tool = _get_latest_interrupted_tool(session.messages or [])
    
    return jsonify({
        'success': True,
        'ai_enabled': FeatureAvailability.is_ai_enabled(),
        'case_id': case_id,
        'case_name': context.get('case_name', ''),
        'hosts': context.get('hosts', []),
        'has_analysis': bool(context.get('analysis_summary')),
        'has_synthesis': bool(context.get('ai_synthesis')),
        'pending_tool_approval': pending_tool,
    })


@chat_bp.route('/conversation/<conversation_id>', methods=['GET'])
@login_required
def get_conversation(conversation_id):
    """Return the server-authoritative display transcript for a chat session."""
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

    messages = list(session.messages or [])
    return jsonify({
        'success': True,
        'conversation_id': session.conversation_id,
        'case_id': case_id,
        'messages': _display_chat_messages(messages),
        'pending_tool_approval': _get_latest_interrupted_tool(messages),
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
        from utils.chat_agent import clear_runtime_session_state

        db.session.delete(session)
        db.session.commit()
        clear_runtime_session_state(conversation_id)
        return jsonify({'success': True})
    except Exception as exc:
        logger.error("[Chat] Failed to delete conversation %s: %s",
                     conversation_id, exc, exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(exc)}), 500
