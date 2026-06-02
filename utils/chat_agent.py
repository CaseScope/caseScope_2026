"""Chat Agent for CaseScope

Agentic chat loop with LLM streaming and tool execution.
Supports SSE for real-time token streaming to the frontend.

Architecture:
- Uses the configured AI provider (Ollama, OpenAI, Claude, etc.)
- Streams tokens via SSE, buffering tool-call JSON
- Executes tools from chat_tools registry
- Max tool rounds: 5 (prevents infinite loops)
- Pre-loads case context into system prompt
"""

import importlib.util
import json
import logging
import os
import re
import sys
import time
import requests
from typing import Callable, Dict, List, Any, Generator, Optional

from config import Config


def _load_local_module(name: str, relative_path: str):
    module_path = os.path.join(os.path.dirname(__file__), relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


try:
    from utils.ai.router import get_provider_descriptor, stream_chat
    from utils.privacy_aliases import AIPrivacyContext, rehydrate_for_display
except Exception:
    _ai_router = _load_local_module("ai_router_local_fallback", "ai/router.py")
    get_provider_descriptor = _ai_router.get_provider_descriptor
    stream_chat = _ai_router.stream_chat
    try:
        from utils.privacy_aliases import AIPrivacyContext, rehydrate_for_display
    except Exception:
        AIPrivacyContext = None
        def rehydrate_for_display(_case_id, payload, privacy_context=None):
            return payload

try:
    from utils.chat_tools import TOOL_DEFINITIONS, execute_tool
except Exception:
    _chat_tools = _load_local_module("chat_tools_local_fallback", "chat_tools.py")
    TOOL_DEFINITIONS = _chat_tools.TOOL_DEFINITIONS
    execute_tool = _chat_tools.execute_tool

try:
    from utils.chat import (
        AttachmentOrder,
        AttachmentScheduler,
        ConversationContext,
        PermissionResult,
        Provenance,
        feature_gate_chat_tool,
        resolve_chat_tool_policy,
        ToolDispatcher,
        ToolResultBlock,
        ToolTier,
        add_cache_breakpoints,
        inject_tool_result_cache_refs,
    )
except Exception:
    _chat_runtime = _load_local_module("chat_runtime_local_fallback", "chat/runtime.py")
    _chat_dispatch = _load_local_module("chat_dispatch_local_fallback", "chat/dispatch.py")
    AttachmentOrder = _chat_runtime.AttachmentOrder
    AttachmentScheduler = _chat_runtime.AttachmentScheduler
    ConversationContext = _chat_runtime.ConversationContext
    add_cache_breakpoints = _chat_runtime.add_cache_breakpoints
    inject_tool_result_cache_refs = _chat_runtime.inject_tool_result_cache_refs
    PermissionResult = _chat_dispatch.PermissionResult
    Provenance = _chat_dispatch.Provenance
    ToolDispatcher = _chat_dispatch.ToolDispatcher
    ToolResultBlock = _chat_dispatch.ToolResultBlock
    ToolTier = _chat_dispatch.ToolTier
    _chat_policy = _load_local_module("chat_policy_local_fallback", "chat/policy.py")
    feature_gate_chat_tool = _chat_policy.feature_gate_chat_tool
    resolve_chat_tool_policy = _chat_policy.resolve_chat_tool_policy

logger = logging.getLogger(__name__)
_TOOL_DISPATCHER = ToolDispatcher(execute_tool, feature_gate=feature_gate_chat_tool)
_TOOL_PARAMETER_SCHEMAS = {
    tool.get("function", {}).get("name", ""): tool.get("function", {}).get("parameters", {})
    for tool in TOOL_DEFINITIONS
    if tool.get("function", {}).get("name")
}

MAX_TOOL_ROUNDS = 5
CHAT_TIMEOUT = 180  # 3 minutes per LLM call
MAX_HISTORY_MESSAGES = 18
MAX_SUMMARY_ITEMS = 8
MAX_SUMMARY_CHARS = 240
MAX_TOOL_RESULT_CHARS = 12000


def _build_case_static_context_block(case_context: Dict) -> str:
    """Render the stable case-context system block."""
    hosts_str = ', '.join(case_context.get('hosts', [])[:15]) or 'Unknown'

    findings_block = ""
    if case_context.get('analysis_summary'):
        summary = case_context['analysis_summary']
        findings_block = f"""
Analysis Summary:
- Total events: {summary.get('census_total_events', 'unknown')}
- Distinct event IDs: {summary.get('census_distinct_event_ids', 'unknown')}
- Pattern matches found: {summary.get('pattern_matches_found', 0)}
- Attack chains found: {summary.get('attack_chains_found', 0)}
- IOC timeline entries: {summary.get('ioc_timeline_entries', 0)}"""
    
    # AI synthesis if available
    synthesis_block = ""
    if case_context.get('ai_synthesis'):
        synth = case_context['ai_synthesis']
        if synth.get('executive_summary'):
            synthesis_block = f"\n\nAI Executive Summary:\n{synth['executive_summary'][:500]}"

    return f"""Current Case: {case_context.get('case_name', 'Unknown')}
Case ID: {case_context.get('case_id', 'Unknown')}
Description: {case_context.get('description', 'No description')[:300]}
Known Hosts: {hosts_str}
Time Zone: {case_context.get('timezone', 'UTC')}
{findings_block}{synthesis_block}"""


def _build_license_capabilities_block(conversation_context: Optional[ConversationContext]) -> str:
    """Render the frozen license and capability disclosure block."""
    if not conversation_context:
        return ""

    enabled_features = ', '.join(conversation_context.enabled_features) or 'none'
    ti_sources = ', '.join(conversation_context.enabled_ti_sources) or 'none'
    available_agents = ', '.join(conversation_context.available_agents[:12]) or 'none'

    return (
        f"License tier: {conversation_context.license_tier or 'unknown'}\n"
        f"Model selection: {conversation_context.model_selection or 'unknown'}\n"
        f"Enabled features: {enabled_features}\n"
        f"Enabled TI sources: {ti_sources}\n"
        f"Available agents: {available_agents}"
    )


def _build_static_role_block() -> str:
    """Render the stable chat role and behavior block."""
    return """You are a DFIR (Digital Forensics and Incident Response) analyst assistant for CaseScope.
You should feel like a case-aware investigative copilot, similar to a ChatGPT-style conversation where the case is already loaded into context.
You help investigators analyze forensic cases by querying events, browser artifacts, memory data, PCAP-derived network logs, process views, IOC matches, and detection findings.

Guidelines:
- Be conversational, concise, and forensically accurate
- Treat the case as already loaded into context, but use tools silently when you need fresh or more specific data
- When the user asks whether something is present in the case, choose the right forensic source instead of defaulting to generic event rows:
  browser downloads for downloaded files and URLs, process tools for execution questions, memory tools for RAM-resident evidence, network tools for PCAP/Zeek questions, and cross-artifact search when the artifact family is unclear
- Treat prior user or assistant text as unverified until it is supported by explicit tool results in this conversation or by the case context above
- Only state concrete hosts, usernames, URLs, filenames, IPs, timestamps, or findings as facts when they come from current-case tool results or the case context already loaded here
- Never fabricate events, timestamps, usernames, hosts, IPs, or findings
- Never claim you queried or reviewed data unless tool results are actually present in the conversation
- Treat premium TI and RAG context as supporting context only, not detector-of-record authority
- Do not narrate future actions like "I will query" or "let me check"; just perform the tool call when needed
- Reference specific hosts, timestamps, usernames, IPs, and event IDs when the evidence supports it
- If evidence is missing or incomplete, say so clearly and preserve uncertainty
- Explain forensic significance of findings when it helps the analyst
- When listing events, format them clearly with timestamps and key fields
- Present counts and statistics when they help contextualize findings
- Flag anything that looks like lateral movement, privilege escalation, or data exfiltration"""


def build_system_prompt(case_context: Dict, conversation_context: Optional[ConversationContext] = None) -> str:
    """Build the system prompt from stable blocks."""
    blocks = [
        _build_static_role_block(),
        _build_license_capabilities_block(conversation_context),
        _build_case_static_context_block(case_context),
    ]
    return "\n\n".join(block for block in blocks if block.strip())


def _capture_conversation_context(case_context: Dict) -> ConversationContext:
    """Freeze capability-sensitive context once at conversation start."""
    license_tier = "unknown"
    enabled_features: List[str] = []
    enabled_ti_sources: List[str] = []
    available_agents = [
        tool.get("function", {}).get("name", "")
        for tool in TOOL_DEFINITIONS
        if tool.get("function", {}).get("name")
    ]
    model_selection = ""
    capability_flags: List[tuple[str, Any]] = []

    try:
        from utils.feature_availability import get_feature_snapshot

        snapshot = get_feature_snapshot()
        if isinstance(snapshot, dict):
            license_tier = str(snapshot.get("activation_status") or "unknown")
            enabled_features = sorted(
                key for key, value in (snapshot.get("capabilities") or {}).items()
                if value
            )
            if snapshot.get("opencti_enabled"):
                enabled_ti_sources.append("opencti")
            if snapshot.get("misp_enabled"):
                enabled_ti_sources.append("misp")
            capability_flags = sorted((snapshot.get("capabilities") or {}).items())
    except Exception:
        pass

    try:
        model_selection = get_provider_descriptor(function="chat").get("model", "")
    except Exception:
        model_selection = ""

    return ConversationContext(
        license_tier=license_tier,
        enabled_features=tuple(enabled_features),
        enabled_ti_sources=tuple(enabled_ti_sources),
        available_agents=tuple(available_agents),
        model_selection=model_selection,
        capability_flags=tuple(capability_flags),
    )


def _build_turn_attachment_message(
    case_context: Dict[str, Any],
    conversation_context: ConversationContext,
    messages: List[Dict[str, Any]],
) -> str:
    """Render the current-turn attachment bundle in the locked order."""
    scheduler = AttachmentScheduler()
    analysis_summary = case_context.get("analysis_summary") or {}
    latest_user_content = ""
    prior_turns: List[str] = []
    for message in messages:
        role = message.get("role")
        if role == "user":
            latest_user_content = str(message.get("content") or "")
        elif role in {"assistant", "tool"}:
            prior_turns.append(f"{role}: {str(message.get('content') or '')[:MAX_SUMMARY_CHARS]}")

    scheduler.add(
        AttachmentOrder.CASE_STATIC_CONTEXT,
        "CASE_STATIC_CONTEXT",
        _build_case_static_context_block(case_context),
    )
    scheduler.add(
        AttachmentOrder.LICENSE_CAPABILITIES,
        "LICENSE_CAPABILITIES",
        _build_license_capabilities_block(conversation_context),
    )
    scheduler.add(
        AttachmentOrder.AVAILABLE_ARTIFACTS,
        "AVAILABLE_ARTIFACTS",
        f"Known hosts: {', '.join(case_context.get('hosts', [])[:15]) or 'Unknown'}",
    )
    scheduler.add(
        AttachmentOrder.FINDING_SUMMARY,
        "FINDING_SUMMARY",
        (
            f"Pattern matches: {analysis_summary.get('pattern_matches_found', 0)}\n"
            f"Attack chains: {analysis_summary.get('attack_chains_found', 0)}\n"
            f"IOC timeline entries: {analysis_summary.get('ioc_timeline_entries', 0)}"
        ),
    )
    scheduler.add(
        AttachmentOrder.CONVERSATION_DELTA,
        "CONVERSATION_DELTA",
        "\n".join(prior_turns[-4:]),
    )
    scheduler.add(
        AttachmentOrder.USER_QUERY,
        "USER_QUERY",
        latest_user_content,
    )
    return scheduler.render()


def _build_request_messages(
    full_messages: List[Dict[str, Any]],
    case_context: Dict[str, Any],
    conversation_context: ConversationContext,
) -> List[Dict[str, Any]]:
    """Prepare request messages using the shared chat runtime helpers."""
    request_messages = _compact_messages(full_messages)
    request_messages = [dict(message) for message in request_messages]
    request_messages = _sanitize_tool_message_adjacency(request_messages)

    for index in range(len(request_messages) - 1, -1, -1):
        if request_messages[index].get("role") == "user":
            request_messages[index]["content"] = _build_turn_attachment_message(
                case_context,
                conversation_context,
                request_messages,
            )
            break

    request_messages = add_cache_breakpoints(request_messages)
    request_messages = inject_tool_result_cache_refs(request_messages)
    return request_messages


def _sanitize_tool_message_adjacency(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Ensure provider-bound tool messages obey chat-completions adjacency rules."""
    sanitized: List[Dict[str, Any]] = []
    index = 0
    while index < len(messages):
        message = dict(messages[index])
        role = message.get("role")

        if role == "assistant" and message.get("tool_calls"):
            tool_calls = message.get("tool_calls") or []
            expected_ids = [
                str(tool_call.get("id") or "")
                for tool_call in tool_calls
                if tool_call.get("id")
            ]
            cursor = index + 1
            following_tools: List[Dict[str, Any]] = []
            while cursor < len(messages) and messages[cursor].get("role") == "tool":
                following_tools.append(dict(messages[cursor]))
                cursor += 1

            following_ids = {
                str(tool_message.get("tool_call_id") or "")
                for tool_message in following_tools
            }
            if expected_ids and all(tool_call_id in following_ids for tool_call_id in expected_ids):
                sanitized.append(message)
                sanitized.extend(following_tools)
            else:
                stripped = {
                    "role": "assistant",
                    "content": message.get("content") or "",
                }
                if stripped["content"].strip():
                    sanitized.append(stripped)
            index = cursor
            continue

        if role == "tool":
            index += 1
            continue

        sanitized.append(message)
        index += 1

    return sanitized


def _tool_call_fingerprint(tool_name: str, params: Dict[str, Any]) -> str:
    """Create a stable fingerprint for repeat-tool detection."""
    return f"{tool_name}:{json.dumps(params or {}, sort_keys=True, default=str)}"


def _resolve_tool_policy(tool_name: str) -> tuple[ToolTier, Provenance]:
    """Resolve baseline dispatch policy for chat tool invocations."""
    return resolve_chat_tool_policy(tool_name)


def _validate_tool_argument_value(name: str, value: Any, schema: Dict[str, Any]) -> Optional[str]:
    """Return a structured validation error for one tool argument value."""
    if value is None:
        return None

    allowed_values = schema.get("enum")
    if allowed_values and value not in allowed_values:
        joined = ", ".join(str(item) for item in allowed_values)
        return f"Invalid value for '{name}'; expected one of: {joined}"

    expected_type = schema.get("type")
    if expected_type == "string" and not isinstance(value, str):
        return f"Invalid type for '{name}'; expected string"
    if expected_type == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        return f"Invalid type for '{name}'; expected integer"
    if expected_type == "boolean" and not isinstance(value, bool):
        return f"Invalid type for '{name}'; expected boolean"
    if expected_type == "object" and not isinstance(value, dict):
        return f"Invalid type for '{name}'; expected object"
    if expected_type == "array":
        if not isinstance(value, list):
            return f"Invalid type for '{name}'; expected array"
        item_schema = schema.get("items") if isinstance(schema.get("items"), dict) else {}
        item_type = item_schema.get("type")
        if item_type == "string" and any(not isinstance(item, str) for item in value):
            return f"Invalid item type for '{name}'; expected string values"
    return None


def _coerce_tool_arguments(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce narrow schema-compatible argument forms before validation."""
    schema = _TOOL_PARAMETER_SCHEMAS.get(tool_name)
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return params
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    coerced = dict(params or {})
    for key, value in list(coerced.items()):
        field_schema = properties.get(key)
        if not isinstance(field_schema, dict):
            continue
        if (
            field_schema.get("type") == "integer"
            and isinstance(value, str)
            and re.fullmatch(r"-?\d+", value.strip())
        ):
            coerced[key] = int(value.strip())
    return coerced


def _validate_tool_arguments(tool_name: str, params: Dict[str, Any]) -> Optional[str]:
    """Validate decoded tool arguments against the declared tool schema."""
    schema = _TOOL_PARAMETER_SCHEMAS.get(tool_name)
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return f"Unknown tool: {tool_name}"

    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = list(schema.get("required") or [])
    unknown_keys = sorted(key for key in params.keys() if key not in properties)
    if unknown_keys:
        return f"Unknown arguments for '{tool_name}': {', '.join(unknown_keys)}"

    missing_required = [key for key in required if key not in params]
    if missing_required:
        return f"Missing required arguments for '{tool_name}': {', '.join(missing_required)}"

    for key, value in params.items():
        field_schema = properties.get(key)
        if not isinstance(field_schema, dict):
            continue
        validation_error = _validate_tool_argument_value(key, value, field_schema)
        if validation_error:
            return validation_error
    return None


def _reject_invalid_tool_call(
    *,
    tool_name: str,
    tier: ToolTier,
    provenance: Provenance,
    reason: str,
) -> ToolResultBlock:
    """Return a structured rejection for invalid tool arguments."""
    return ToolResultBlock.reject(
        tool_name=tool_name,
        tier=tier,
        provenance=provenance,
        permission=PermissionResult(
            allowed=False,
            category="invalid tool arguments",
            reason=reason,
            cacheable=False,
        ),
        payload={"error": reason},
    )


def _is_terminal_tool_result(result: Dict[str, Any]) -> bool:
    """Return True when a tool result should stop the live tool loop."""
    return result.get("status") in {"interrupt", "rejected", "error"}


def _terminal_tool_message(tool_name: str, result: Dict[str, Any]) -> str:
    """Return a concise user-visible note for terminal tool outcomes."""
    status = result.get("status")
    permission = result.get("permission") if isinstance(result.get("permission"), dict) else {}
    reason = str(permission.get("reason") or result.get("error") or "").strip()
    if status == "interrupt":
        return (
            f"The {tool_name} request needs analyst approval before I can continue. "
            "Use Allow or Deny on the tool card."
        )
    if status == "rejected":
        return f"The {tool_name} request was not run because it was rejected{': ' + reason if reason else '.'}"
    if status == "error":
        return f"The {tool_name} request failed{': ' + reason if reason else '.'}"
    return ""


def _build_pending_tool_approval_payload(
    *,
    tool_name: str,
    tool_call_id: Optional[str],
    params: Dict[str, Any],
    permission: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the structured pending approval payload for live UI events."""
    return {
        "tool_name": tool_name,
        "tool_call_id": tool_call_id,
        "params": json.loads(json.dumps(params or {}, default=str)),
        "permission": json.loads(json.dumps(permission or {}, default=str)),
    }


def _format_tool_approval_note(tool_approval: Dict[str, Any]) -> str:
    """Render a user-visible approval note for persisted history."""
    tool_name = str(tool_approval.get("tool_name") or "tool")
    decision = str(tool_approval.get("decision") or "review").strip().lower() or "review"
    reason = str(tool_approval.get("reason") or "").strip()
    note = f"[TOOL_APPROVAL] {decision} {tool_name}"
    if reason:
        note += f": {reason}"
    return note


def _upsert_tool_result_after_call(
    messages: List[Dict[str, Any]],
    *,
    tool_call_id: str,
    tool_name: str,
    content: str,
) -> None:
    """Place a resumed tool result adjacent to its original assistant tool call."""
    if not tool_call_id:
        messages.append({
            "role": "tool",
            "tool_call_id": "approval_resume",
            "name": tool_name,
            "content": content,
        })
        return

    for index, message in enumerate(messages):
        if message.get("role") != "assistant":
            continue
        tool_calls = message.get("tool_calls") or []
        if not any(str(tool_call.get("id") or "") == tool_call_id for tool_call in tool_calls):
            continue

        insert_at = index + 1
        while insert_at < len(messages) and messages[insert_at].get("role") == "tool":
            if str(messages[insert_at].get("tool_call_id") or "") == tool_call_id:
                messages[insert_at] = {
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "name": tool_name,
                    "content": content,
                }
                return
            insert_at += 1

        messages.insert(insert_at, {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": tool_name,
            "content": content,
        })
        return

    messages.append({
        "role": "tool",
        "tool_call_id": tool_call_id,
        "name": tool_name,
        "content": content,
    })


def get_case_context(case_id: int) -> Dict:
    """Load case context for system prompt.
    
    Args:
        case_id: Case ID
        
    Returns:
        Dict with case metadata and latest analysis summary
    """
    from models.case import Case
    from models.behavioral_profiles import CaseAnalysisRun, AnalysisStatus
    from utils.clickhouse import get_fresh_client
    
    context = {
        'case_id': case_id,
        'case_name': 'Unknown',
        'description': '',
        'hosts': [],
        'timezone': 'UTC',
        'analysis_summary': {},
        'ai_synthesis': {}
    }
    
    try:
        case = Case.query.get(case_id)
        if case:
            context['case_name'] = case.name
            context['description'] = case.description or ''
            context['timezone'] = getattr(case, 'timezone', 'UTC') or 'UTC'
    except Exception as e:
        logger.warning(f"[ChatAgent] Failed to load case: {e}")
    
    # Get hosts from ClickHouse
    try:
        client = get_fresh_client()
        result = client.query(
            "SELECT DISTINCT source_host FROM events "
            "WHERE case_id = {case_id:UInt32} AND source_host != '' "
            "ORDER BY source_host LIMIT 20",
            parameters={'case_id': case_id}
        )
        context['hosts'] = [row[0] for row in result.result_rows]
    except Exception as e:
        logger.warning(f"[ChatAgent] Failed to get hosts: {e}")
    
    # Get latest analysis summary
    try:
        latest_run = CaseAnalysisRun.query.filter_by(
            case_id=case_id,
            status=AnalysisStatus.COMPLETE
        ).order_by(CaseAnalysisRun.completed_at.desc()).first()
        
        if latest_run and latest_run.summary:
            summary = latest_run.summary if isinstance(latest_run.summary, dict) else {}
            context['analysis_summary'] = summary
            context['ai_synthesis'] = summary.get('ai_synthesis', {})
    except Exception as e:
        logger.warning(f"[ChatAgent] Failed to load analysis: {e}")
    
    return context


def _stream_llm_chat(messages: List[Dict], tools: List[Dict] = None, case_id: int = None) -> Generator:
    """Stream response from the configured LLM provider.
    
    Yields dicts with 'message' containing the delta.
    When a tool_call is present, yields the full tool_call object.
    
    Args:
        messages: Chat messages
        tools: Tool definitions (optional)
        
    Yields:
        Dict chunks from the provider's streaming response
    """
    yield from stream_chat(
        function='chat',
        messages=messages,
        tools=tools,
        temperature=0.3,
        max_tokens=4096,
        privacy_context=AIPrivacyContext.case_content(case_id) if AIPrivacyContext and case_id else None,
    )


def _truncate_text(text: str, max_len: int) -> str:
    """Truncate text for compact conversation summaries."""
    text = (text or '').strip()
    if len(text) <= max_len:
        return text
    return text[:max_len].rstrip() + '...[TRUNCATED]'


def _is_compaction_summary(message: Dict[str, Any]) -> bool:
    return (
        message.get("role") == "system"
        and isinstance(message.get("content"), str)
        and message["content"].startswith("Conversation summary from earlier turns:")
    )


def _compact_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Compress older chat history into a short system summary."""
    if len(messages) <= MAX_HISTORY_MESSAGES + 1:
        return messages

    system_message = messages[0]
    history = [msg for msg in messages[1:] if not _is_compaction_summary(msg)]
    if len(history) <= MAX_HISTORY_MESSAGES:
        return [system_message, *history]

    older_messages = history[:-MAX_HISTORY_MESSAGES]
    recent_messages = history[-MAX_HISTORY_MESSAGES:]
    summary_lines = []

    for message in older_messages[-MAX_SUMMARY_ITEMS:]:
        role = message.get("role", "unknown")
        if role == "tool":
            tool_name = message.get("name", "tool")
            content = _truncate_text(str(message.get("content", "")), MAX_SUMMARY_CHARS)
            summary_lines.append(f"- Tool {tool_name}: {content}")
            continue

        content = _truncate_text(str(message.get("content", "")), MAX_SUMMARY_CHARS)
        summary_lines.append(f"- {role.title()}: {content}")

    if not summary_lines:
        return [system_message, *recent_messages]

    summary_message = {
        "role": "system",
        "content": "Conversation summary from earlier turns:\n" + "\n".join(summary_lines),
    }
    return [system_message, summary_message, *recent_messages]


def _serialize_tool_result_for_history(result: Dict[str, Any]) -> str:
    """Bound tool result size before it is re-sent to the model."""
    serialized = json.dumps(result, default=str)
    if len(serialized) <= MAX_TOOL_RESULT_CHARS:
        return serialized

    return json.dumps({
        "truncated": True,
        "preview": _preview_result(result, max_len=400),
        "content_excerpt": serialized[:MAX_TOOL_RESULT_CHARS].rstrip() + '...[TRUNCATED]',
    }, default=str)


def _history_messages_for_session(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Strip transient system messages before persisting a chat transcript."""
    persisted_messages: List[Dict[str, Any]] = []
    for message in messages:
        role = message.get("role")
        if role == "system" or _is_compaction_summary(message):
            continue
        if role not in {"user", "assistant", "tool"}:
            continue

        persisted = {
            "role": role,
            "content": message.get("content", ""),
        }
        for key in ("tool_calls", "tool_call_id", "name"):
            if key in message:
                persisted[key] = json.loads(json.dumps(message[key], default=str))
        persisted_messages.append(persisted)
    return persisted_messages


def chat_stream(case_id: int, messages: List[Dict],
                conversation_id: str = None,
                tool_approval: Optional[Dict[str, Any]] = None,
                hunt_run_id: Optional[int] = None,
                actor_metadata: Optional[Dict[str, Any]] = None,
                on_complete: Optional[Callable[[List[Dict[str, Any]]], None]] = None
                ) -> Generator[str, None, None]:
    """Run the agentic chat loop with streaming SSE output.
    
    This is the main entry point. It:
    1. Loads case context and builds system prompt
    2. Calls Ollama with tool definitions
    3. Streams text tokens as SSE events
    4. When a tool call is detected, executes it and loops back
    5. Stops after MAX_TOOL_ROUNDS or when the model produces text-only response
    
    Args:
        case_id: Case ID for context
        messages: User messages [{role, content}]
        conversation_id: Optional conversation tracking ID
        tool_approval: Optional analyst approval payload for a pending tool
        
    Yields:
        SSE-formatted strings: "data: {...}\n\n"
    """
    # Load case context
    case_context = get_case_context(case_id)
    conversation_context = _capture_conversation_context(case_context)
    system_prompt = build_system_prompt(case_context, conversation_context)
    try:
        provider_descriptor = get_provider_descriptor(function="chat")
    except Exception:
        provider_descriptor = {}
    model_metadata = {
        "model_provider": provider_descriptor.get("provider_type"),
        "model_name": provider_descriptor.get("model"),
        "prompt_version": "chat-agent-v1",
    }
    trace_actor_metadata = {
        "created_by_type": "ai",
        "created_by": "chat_agent",
        **(actor_metadata or {}),
    }
    
    # Build full message list with system prompt
    full_messages = [{"role": "system", "content": system_prompt}]
    full_messages.extend(messages)
    _seed_permission_cache_from_history(
        case_id=case_id,
        conversation_id=conversation_id,
        messages=messages,
    )
    
    tool_round = 0
    executed_tool_results: Dict[str, Dict[str, Any]] = {}
    preflight_terminal_result = False
    pending_tool_approval_state: Optional[Dict[str, Any]] = None
    had_error = False

    if tool_approval:
        approval_note = _format_tool_approval_note(tool_approval)
        full_messages.append({"role": "user", "content": approval_note})

        approved_tool_name = str(tool_approval.get("tool_name") or "").strip()
        approved_params = tool_approval.get("params") if isinstance(tool_approval.get("params"), dict) else {}
        analyst_decision = str(tool_approval.get("decision") or "").strip().lower()
        analyst_reason = str(tool_approval.get("reason") or "").strip()

        if approved_tool_name:
            tool_tier, tool_provenance = _resolve_tool_policy(approved_tool_name)
            yield _sse_event("tool_start", {"tools": [approved_tool_name]})
            approved_params = _coerce_tool_arguments(approved_tool_name, approved_params)
            validation_error = _validate_tool_arguments(approved_tool_name, approved_params)
            if validation_error:
                tool_result = _reject_invalid_tool_call(
                    tool_name=approved_tool_name,
                    tier=tool_tier,
                    provenance=tool_provenance,
                    reason=validation_error,
                )
            else:
                tool_result = _TOOL_DISPATCHER.execute(
                    tool_name=approved_tool_name,
                    case_id=case_id,
                    params=approved_params,
                    tier=tool_tier,
                    provenance=tool_provenance,
                    session_id=conversation_id,
                    analyst_decision=analyst_decision,
                    analyst_reason=analyst_reason,
                    hunt_run_id=hunt_run_id,
                    actor_metadata=trace_actor_metadata,
                    model_metadata=model_metadata,
                )
            result = tool_result.to_payload()
            if result.get("status") == "completed":
                executed_tool_results[_tool_call_fingerprint(approved_tool_name, approved_params)] = {
                    "tool_call_id": str(tool_approval.get("tool_call_id") or "approval_resume"),
                    "result": result,
                }
            pending_tool_approval_payload = (
                _build_pending_tool_approval_payload(
                    tool_name=approved_tool_name,
                    tool_call_id=str(tool_approval.get("tool_call_id") or "approval_resume"),
                    params=approved_params,
                    permission=result.get("permission", {}),
                )
                if result.get("status") == "interrupt"
                else None
            )
            pending_tool_approval_state = pending_tool_approval_payload
            yield _sse_event("tool_result", {
                "tool": approved_tool_name,
                "status": result.get("status", "completed"),
                "tier": result.get("tier"),
                "provenance": result.get("provenance"),
                "permission": result.get("permission", {}),
                "pending_tool_approval": pending_tool_approval_payload,
                "result_preview": _preview_result(result),
            })
            _upsert_tool_result_after_call(
                full_messages,
                tool_call_id=str(tool_approval.get("tool_call_id") or ""),
                tool_name=approved_tool_name,
                content=_serialize_tool_result_for_history(result),
            )
            yield _sse_event("tool_end", {})
            preflight_terminal_result = _is_terminal_tool_result(result)
            if preflight_terminal_result:
                terminal_message = _terminal_tool_message(approved_tool_name, result)
                if terminal_message:
                    full_messages.append({"role": "assistant", "content": terminal_message})
                    yield _sse_event("token", {"content": terminal_message})
    
    while not preflight_terminal_result and tool_round < MAX_TOOL_ROUNDS:
        tool_round += 1
        
        buffered_content_parts: List[str] = []
        tool_calls: List[Dict[str, Any]] = []
        had_error = False
        request_messages = _build_request_messages(
            full_messages,
            case_context,
            conversation_context,
        )
        
        for chunk in _stream_llm_chat(request_messages, TOOL_DEFINITIONS, case_id=case_id):
            # Check for errors
            if "error" in chunk:
                yield _sse_event("error", {"error": chunk["error"]})
                had_error = True
                break
            
            msg = chunk.get("message", {})
            
            # Check for tool calls
            if msg.get("tool_calls"):
                _merge_tool_calls(tool_calls, msg["tool_calls"])
            
            # Buffer content until we know whether this round is tool-backed.
            content = msg.get("content", "")
            if content:
                buffered_content_parts.append(content)

            if chunk.get("done", False):
                break
        
        if had_error:
            break

        accumulated_content = ''.join(buffered_content_parts)
        
        # If we got tool calls, execute them and loop
        if tool_calls:
            # Signal tool execution phase
            normalized_tool_calls = _history_tool_calls(tool_calls)
            terminal_tool_result = False
            yield _sse_event("tool_start", {
                "tools": [tc.get("function", {}).get("name", "tool") for tc in normalized_tool_calls]
            })
            
            # Add assistant message with tool calls to history
            assistant_msg = {"role": "assistant", "content": "", "tool_calls": normalized_tool_calls}
            full_messages.append(assistant_msg)
            
            # Execute each tool call
            terminal_tool_name = ""
            terminal_result_payload: Dict[str, Any] = {}
            for tc in normalized_tool_calls:
                func_name = tc.get("function", {}).get("name", "")
                if not func_name:
                    logger.warning("[ChatAgent] Skipping tool call without function name: %s", tc)
                    continue
                tool_tier, tool_provenance = _resolve_tool_policy(func_name)
                func_args, decode_error = _decode_tool_arguments(tc)
                func_args, decode_error = _repair_tool_arguments(
                    tool_name=func_name,
                    params=func_args,
                    decode_error=decode_error,
                    messages=full_messages,
                )
                func_args = _coerce_tool_arguments(func_name, func_args)
                validation_error = decode_error or _validate_tool_arguments(func_name, func_args)
                fingerprint = _tool_call_fingerprint(func_name, func_args)
                prior_execution = None

                if validation_error:
                    tool_result = _reject_invalid_tool_call(
                        tool_name=func_name,
                        tier=tool_tier,
                        provenance=tool_provenance,
                        reason=validation_error,
                    )
                else:
                    prior_execution = executed_tool_results.get(fingerprint)
                    if prior_execution:
                        prior_result = prior_execution.get("result") if isinstance(prior_execution, dict) else {}
                        reused_provenance = tool_provenance
                        if isinstance(prior_result, dict):
                            prior_provenance = prior_result.get("provenance")
                            if prior_provenance in Provenance._value2member_map_:
                                reused_provenance = Provenance(prior_provenance)
                        tool_result = ToolResultBlock.reused_result(
                            tool_name=func_name,
                            first_tool_call_id=prior_execution.get("tool_call_id"),
                            result_preview=_preview_result(prior_result),
                            tier=tool_tier,
                            provenance=reused_provenance,
                        )
                    else:
                        tool_result = _TOOL_DISPATCHER.execute(
                            tool_name=func_name,
                            case_id=case_id,
                            params=func_args,
                            tier=tool_tier,
                            provenance=tool_provenance,
                            session_id=conversation_id,
                            hunt_run_id=hunt_run_id,
                            actor_metadata=trace_actor_metadata,
                            model_metadata=model_metadata,
                        )
                result = tool_result.to_payload()
                if not prior_execution:
                    executed_tool_results[fingerprint] = {
                        "tool_call_id": tc.get("id"),
                        "result": result,
                    }
                pending_tool_approval_payload = (
                    _build_pending_tool_approval_payload(
                        tool_name=func_name,
                        tool_call_id=tc.get("id"),
                        params=func_args,
                        permission=result.get("permission", {}),
                    )
                    if result.get("status") == "interrupt"
                    else None
                )
                pending_tool_approval_state = pending_tool_approval_payload
                
                # Send tool result to UI
                yield _sse_event("tool_result", {
                    "tool": func_name,
                    "status": result.get("status", "completed"),
                    "tier": result.get("tier"),
                    "provenance": result.get("provenance"),
                    "permission": result.get("permission", {}),
                    "pending_tool_approval": pending_tool_approval_payload,
                    "result_preview": _preview_result(result)
                })
                
                # Add tool result to messages for next LLM call
                full_messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id"),
                    "name": func_name,
                    "content": _serialize_tool_result_for_history(result)
                })
                if _is_terminal_tool_result(result):
                    terminal_tool_result = True
                    terminal_tool_name = func_name
                    terminal_result_payload = result
                    break
            
            yield _sse_event("tool_end", {})
            if terminal_tool_result:
                terminal_message = _terminal_tool_message(
                    terminal_tool_name,
                    terminal_result_payload,
                )
                if terminal_message:
                    full_messages.append({"role": "assistant", "content": terminal_message})
                    yield _sse_event("token", {"content": terminal_message})
                break
            yield _sse_event("tool_progress", {"message": "Analyzing tool results..."})
            
            # Continue loop — LLM will now see tool results
            continue
        
        # No tool calls — model gave a text response, we're done
        if accumulated_content:
            full_messages.append({"role": "assistant", "content": accumulated_content})
        display_content = rehydrate_for_display(case_id, accumulated_content) if accumulated_content else ''
        if display_content:
            yield _sse_event("token", {"content": display_content})
        break

    if not had_error and on_complete is not None:
        try:
            on_complete(_history_messages_for_session(full_messages))
        except Exception as exc:
            logger.error("[ChatAgent] Failed to finalize transcript for %s: %s",
                         conversation_id, exc, exc_info=True)

    # Send done event
    yield _sse_event("done", {
        "tool_rounds": tool_round,
        "conversation_id": conversation_id,
        "pending_tool_approval": pending_tool_approval_state,
    })


def _sse_event(event_type: str, data: Dict) -> str:
    """Format an SSE event.
    
    Args:
        event_type: Event type (token, tool_start, tool_result, tool_end, done, error)
        data: Event data dict
        
    Returns:
        SSE-formatted string
    """
    payload = {"type": event_type, **data}
    return f"data: {json.dumps(payload, default=str)}\n\n"


def _preview_result(result: Dict, max_len: int = 200) -> str:
    """Create a short preview of a tool result for the UI.
    
    Args:
        result: Full tool result dict
        max_len: Max preview length
        
    Returns:
        Preview string
    """
    if "error" in result:
        return f"Error: {result['error']}"
    
    parts = []
    
    if "event_count" in result:
        parts.append(f"{result['event_count']} events found")
    
    if "total" in result:
        parts.append(f"Total: {result['total']}")
    
    if "groups" in result:
        top_groups = result["groups"][:5]
        group_strs = [f"{g['value']}: {g['count']}" for g in top_groups]
        parts.append(f"Top: {', '.join(group_strs)}")
    
    if "findings" in result:
        parts.append(f"{len(result['findings'])} findings")
    
    if "downloads" in result:
        parts.append(f"{result.get('total', len(result['downloads']))} downloads")

    if "artifact_types" in result and result.get("artifact_types"):
        top_types = list(result["artifact_types"].items())[:3]
        parts.append("Artifacts: " + ', '.join(f"{name}: {count}" for name, count in top_types))

    if "processes" in result:
        parts.append(f"{result.get('total', len(result['processes']))} processes")

    if "jobs_matched" in result:
        parts.append(f"Memory jobs: {result['jobs_matched']}")

    if "logs" in result:
        parts.append(f"{result.get('total', len(result['logs']))} network logs")

    if "artifacts" in result:
        parts.append(f"{result.get('total_matches', len(result['artifacts']))} artifact matches")

    if "event_matches" in result:
        parts.append(f"{result['event_matches']} event matches")
    
    if "hosts" in result:
        hosts = list(result["hosts"].keys())[:3]
        if hosts:
            parts.append(f"Hosts: {', '.join(hosts)}")
    
    preview = ' | '.join(parts) if parts else json.dumps(result, default=str)
    return preview[:max_len]


def _merge_tool_calls(target_calls: List[Dict[str, Any]], incoming_calls: List[Dict[str, Any]]) -> None:
    """Merge partial tool call chunks into a stable list."""
    for incoming in incoming_calls or []:
        index = incoming.get('index', len(target_calls))
        while len(target_calls) <= index:
            target_calls.append({
                "id": "",
                "type": "function",
                "function": {
                    "name": "",
                    "arguments": "",
                },
            })

        target = target_calls[index]

        if incoming.get("id"):
            target["id"] = incoming["id"]

        if incoming.get("type"):
            target["type"] = incoming["type"]

        incoming_function = incoming.get("function") or {}
        target_function = target.setdefault("function", {"name": "", "arguments": ""})

        function_name = incoming_function.get("name") or ""
        if function_name:
            target_function["name"] += function_name

        function_arguments = incoming_function.get("arguments")
        if function_arguments is not None:
            target_function["arguments"] += function_arguments


def _history_tool_calls(tool_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize tool calls before re-sending them to the provider."""
    normalized_calls = []
    for index, tool_call in enumerate(tool_calls):
        function_payload = tool_call.get("function") or {}
        normalized_calls.append({
            "id": tool_call.get("id") or f"tool_call_{index}",
            "type": tool_call.get("type") or "function",
            "function": {
                "name": function_payload.get("name", ""),
                "arguments": function_payload.get("arguments", ""),
            },
        })
    return normalized_calls


def _seed_permission_cache_from_history(
    *,
    case_id: int,
    conversation_id: Optional[str],
    messages: List[Dict[str, Any]],
) -> None:
    """Rebuild session-scoped permission cache from persisted tool results."""
    if not conversation_id or not hasattr(_TOOL_DISPATCHER, "cache_permission_decision"):
        return

    tool_calls_by_id: Dict[str, tuple[str, Dict[str, Any]]] = {}
    for message in messages or []:
        if message.get("role") == "assistant":
            for tool_call in message.get("tool_calls") or []:
                tool_call_id = str(tool_call.get("id") or "")
                function_payload = tool_call.get("function") or {}
                tool_name = str(function_payload.get("name") or "").strip()
                params, decode_error = _decode_tool_arguments(tool_call)
                if tool_call_id and tool_name and decode_error is None:
                    tool_calls_by_id[tool_call_id] = (tool_name, params)
            continue

        if message.get("role") != "tool":
            continue
        tool_call_id = str(message.get("tool_call_id") or "")
        if tool_call_id not in tool_calls_by_id:
            continue
        try:
            payload = json.loads(message.get("content") or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        if payload.get("status") not in {"completed", "rejected"}:
            continue

        permission_payload = payload.get("permission") or {}
        if not permission_payload.get("cacheable"):
            continue

        tool_name, params = tool_calls_by_id[tool_call_id]
        try:
            _TOOL_DISPATCHER.cache_permission_decision(
                tool_name=tool_name,
                case_id=case_id,
                session_id=conversation_id,
                params=params,
                permission=PermissionResult(
                    allowed=bool(permission_payload.get("allowed")),
                    category=str(permission_payload.get("category") or "allow"),
                    reason=str(permission_payload.get("reason") or ""),
                    cacheable=True,
                ),
            )
        except Exception:
            logger.debug(
                "[ChatAgent] Failed to seed permission cache for %s",
                tool_name,
                exc_info=True,
            )


def _latest_user_text(messages: List[Dict[str, Any]]) -> str:
    """Return the latest raw user message text from the conversation history."""
    for message in reversed(messages or []):
        if message.get("role") == "user":
            return str(message.get("content") or "")
    return ""


def _infer_count_event_arguments(user_text: str) -> Dict[str, Any]:
    """Infer safe count_events filters for common DFIR phrasing."""
    normalized = user_text.lower()
    failed_terms = ("failed login", "failed logon", "failed sign-in", "failed signin")
    successful_terms = ("successful login", "successful logon", "success login", "success logon")
    if any(term in normalized for term in failed_terms):
        return {"event_id": "4625"}
    if "failed" in normalized and any(term in normalized for term in ("login", "logon", "auth")):
        return {"event_id": "4625"}
    if any(term in normalized for term in successful_terms):
        return {"event_id": "4624"}
    if any(term in normalized for term in ("rdp", "rdweb")):
        if "failed" in normalized and any(term in normalized for term in ("login", "logon", "auth")):
            return {"event_id": "4625"}
        if any(term in normalized for term in ("login", "logon", "auth", "sign-in", "signin")):
            return {"event_id": "4624"}
    return {}


def _infer_query_event_arguments(user_text: str) -> Dict[str, Any]:
    """Infer safe query_events filters for explicit protocol/product phrasing."""
    normalized = user_text.lower()
    if "rdweb" in normalized:
        return {"search_text": "RDWeb"}
    if re.search(r"\brdp\b", normalized):
        return {"search_text": "RDP"}
    return {}


def _quoted_terms(text: str) -> set[str]:
    """Return lower-cased values explicitly quoted by the analyst."""
    return {
        match.strip().lower()
        for match in re.findall(r"['\"]([^'\"]+)['\"]", text or "")
        if match.strip()
    }


def _repair_get_processes_arguments(
    params: Dict[str, Any],
    user_text: str,
) -> Dict[str, Any]:
    """Repair common get_processes source/user confusion."""
    repaired = dict(params or {})
    source = repaired.get("source")
    if not isinstance(source, str):
        return repaired

    normalized_source = source.strip().lower()
    if normalized_source in {"all", "events", "memory"}:
        repaired["source"] = normalized_source
        return repaired

    repaired["source"] = "all"
    if not repaired.get("search") and normalized_source in _quoted_terms(user_text):
        repaired["search"] = source.strip()
    return repaired


def _repair_tool_arguments(
    *,
    tool_name: str,
    params: Dict[str, Any],
    decode_error: Optional[str],
    messages: List[Dict[str, Any]],
) -> tuple[Dict[str, Any], Optional[str]]:
    """Repair narrowly understood malformed/no-arg tool calls before validation."""
    user_text = _latest_user_text(messages)
    if tool_name == "get_processes":
        repaired = _repair_get_processes_arguments(params, user_text)
        if repaired != (params or {}):
            logger.info(
                "[ChatAgent] Repaired get_processes arguments from user query: %s",
                sorted(repaired.keys()),
            )
            return repaired, None
        return params, decode_error

    if tool_name not in {"count_events", "query_events"}:
        return params, decode_error
    if params and not decode_error:
        return params, None

    inferred = (
        _infer_count_event_arguments(user_text)
        if tool_name == "count_events"
        else _infer_query_event_arguments(user_text)
    )
    if inferred:
        logger.info(
            "[ChatAgent] Repaired %s arguments from user query: %s",
            tool_name,
            sorted(inferred.keys()),
        )
        return inferred, None
    return params, decode_error


def _decode_tool_arguments(tool_call: Dict[str, Any]) -> tuple[Dict[str, Any], Optional[str]]:
    """Decode tool arguments and preserve structured validation errors."""
    function_payload = tool_call.get("function") or {}
    raw_arguments = function_payload.get("arguments", {})
    if isinstance(raw_arguments, dict):
        return raw_arguments, None
    if isinstance(raw_arguments, str):
        if not raw_arguments.strip():
            return {}, None
        try:
            decoded = json.loads(raw_arguments)
            if isinstance(decoded, dict):
                return decoded, None
            return {}, "Tool arguments must decode to a JSON object"
        except (json.JSONDecodeError, TypeError):
            logger.warning("[ChatAgent] Invalid tool arguments for %s: %r", function_payload.get("name"), raw_arguments)
            return {}, "Tool arguments must be valid JSON"
    return {}, "Tool arguments must be a JSON object"


def clear_runtime_session_state(conversation_id: Optional[str]) -> None:
    """Clear session-scoped runtime state for a deleted conversation."""
    _TOOL_DISPATCHER.clear_session_permissions(conversation_id)
