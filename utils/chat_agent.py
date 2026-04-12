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
        Provenance,
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
    Provenance = _chat_dispatch.Provenance
    ToolDispatcher = _chat_dispatch.ToolDispatcher
    ToolResultBlock = _chat_dispatch.ToolResultBlock
    ToolTier = _chat_dispatch.ToolTier

logger = logging.getLogger(__name__)

_TOOL_DISPATCHER = ToolDispatcher(execute_tool)

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
        from utils.ai_providers import get_llm_provider

        provider = get_llm_provider(function="chat")
        model_selection = getattr(provider, "model", "") or ""
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


def _tool_call_fingerprint(tool_name: str, params: Dict[str, Any]) -> str:
    """Create a stable fingerprint for repeat-tool detection."""
    return f"{tool_name}:{json.dumps(params or {}, sort_keys=True, default=str)}"


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
            status=AnalysisStatus.COMPLETED
        ).order_by(CaseAnalysisRun.completed_at.desc()).first()
        
        if latest_run and latest_run.summary:
            summary = latest_run.summary if isinstance(latest_run.summary, dict) else {}
            context['analysis_summary'] = summary
            context['ai_synthesis'] = summary.get('ai_synthesis', {})
    except Exception as e:
        logger.warning(f"[ChatAgent] Failed to load analysis: {e}")
    
    return context


def _stream_llm_chat(messages: List[Dict], tools: List[Dict] = None) -> Generator:
    """Stream response from the configured LLM provider.
    
    Yields dicts with 'message' containing the delta.
    When a tool_call is present, yields the full tool_call object.
    
    Args:
        messages: Chat messages
        tools: Tool definitions (optional)
        
    Yields:
        Dict chunks from the provider's streaming response
    """
    from utils.ai_providers import get_llm_provider
    provider = get_llm_provider(function='chat')
    yield from provider.stream_chat(
        messages=messages,
        tools=tools,
        temperature=0.3,
        max_tokens=4096,
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
        
    Yields:
        SSE-formatted strings: "data: {...}\n\n"
    """
    # Load case context
    case_context = get_case_context(case_id)
    conversation_context = _capture_conversation_context(case_context)
    system_prompt = build_system_prompt(case_context, conversation_context)
    
    # Build full message list with system prompt
    full_messages = [{"role": "system", "content": system_prompt}]
    full_messages.extend(messages)
    
    tool_round = 0
    executed_tool_results: Dict[str, Dict[str, Any]] = {}
    
    while tool_round < MAX_TOOL_ROUNDS:
        tool_round += 1
        
        buffered_content_parts: List[str] = []
        tool_calls: List[Dict[str, Any]] = []
        had_error = False
        request_messages = _build_request_messages(
            full_messages,
            case_context,
            conversation_context,
        )
        
        for chunk in _stream_llm_chat(request_messages, TOOL_DEFINITIONS):
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
            yield _sse_event("tool_start", {
                "tools": [tc.get("function", {}).get("name", "tool") for tc in normalized_tool_calls]
            })
            
            # Add assistant message with tool calls to history
            assistant_msg = {"role": "assistant", "content": "", "tool_calls": normalized_tool_calls}
            full_messages.append(assistant_msg)
            
            # Execute each tool call
            for tc in normalized_tool_calls:
                func_name = tc.get("function", {}).get("name", "")
                if not func_name:
                    logger.warning("[ChatAgent] Skipping tool call without function name: %s", tc)
                    continue
                func_args = _decode_tool_arguments(tc)

                fingerprint = _tool_call_fingerprint(func_name, func_args)
                prior_execution = executed_tool_results.get(fingerprint)
                if prior_execution:
                    tool_result = ToolResultBlock.reused_result(
                        tool_name=func_name,
                        first_tool_call_id=prior_execution.get("tool_call_id"),
                        tier=ToolTier.READ_SAFE,
                        provenance=Provenance.ANALYST,
                    )
                else:
                    tool_result = _TOOL_DISPATCHER.execute(
                        tool_name=func_name,
                        case_id=case_id,
                        params=func_args,
                        tier=ToolTier.READ_SAFE,
                        provenance=Provenance.ANALYST,
                    )
                result = tool_result.to_payload()
                if not prior_execution:
                    executed_tool_results[fingerprint] = {
                        "tool_call_id": tc.get("id"),
                        "result": result,
                    }
                
                # Send tool result to UI
                yield _sse_event("tool_result", {
                    "tool": func_name,
                    "result_preview": _preview_result(result)
                })
                
                # Add tool result to messages for next LLM call
                full_messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id"),
                    "name": func_name,
                    "content": _serialize_tool_result_for_history(result)
                })
            
            yield _sse_event("tool_end", {})
            
            # Continue loop — LLM will now see tool results
            continue
        
        # No tool calls — model gave a text response, we're done
        if accumulated_content:
            full_messages.append({"role": "assistant", "content": accumulated_content})
        for content_part in buffered_content_parts:
            yield _sse_event("token", {"content": content_part})
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
        "conversation_id": conversation_id
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


def _decode_tool_arguments(tool_call: Dict[str, Any]) -> Dict[str, Any]:
    """Decode tool arguments safely, preserving empty dict fallback."""
    function_payload = tool_call.get("function") or {}
    raw_arguments = function_payload.get("arguments", {})
    if isinstance(raw_arguments, dict):
        return raw_arguments
    if isinstance(raw_arguments, str):
        try:
            decoded = json.loads(raw_arguments)
            return decoded if isinstance(decoded, dict) else {}
        except (json.JSONDecodeError, TypeError):
            logger.warning("[ChatAgent] Invalid tool arguments for %s: %r", function_payload.get("name"), raw_arguments)
            return {}
    return {}
