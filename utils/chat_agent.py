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
import string
import os
import re
import sys
from typing import Callable, Dict, List, Any, Generator, Optional


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
    from utils.privacy_aliases import (
        AIPrivacyContext,
        build_display_rehydrator,
        rehydrate_for_display,
    )
except Exception:
    _ai_router = _load_local_module("ai_router_local_fallback", "ai/router.py")
    get_provider_descriptor = _ai_router.get_provider_descriptor
    stream_chat = _ai_router.stream_chat
    try:
        from utils.privacy_aliases import (
            AIPrivacyContext,
            build_display_rehydrator,
            rehydrate_for_display,
        )
    except Exception:
        AIPrivacyContext = None
        def rehydrate_for_display(_case_id, payload, privacy_context=None):
            return payload
        def build_display_rehydrator(_case_id):
            return lambda text: text

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

MAX_TOOL_ROUNDS = 8
# Rounds where every tool call failed before execution do not consume the
# productive round budget; they are capped separately so a model that keeps
# emitting broken calls still terminates.
MAX_TOOL_RECOVERY_ROUNDS = 4
MAX_TOOL_RETRIES_PER_TOOL = 2
CHAT_TIMEOUT = 180  # 3 minutes per LLM call
# Token reserves carved out of the model context window before history is fitted.
MAX_RESPONSE_TOKENS = 4096
DEFAULT_CONTEXT_WINDOW = 16384
SYSTEM_PROMPT_RESERVE_TOKENS = 2048
CONTEXT_SAFETY_MARGIN_TOKENS = 1024
MIN_HISTORY_TOKENS = 2000
MAX_SUMMARY_ITEMS = 8
MAX_SUMMARY_CHARS = 240
MAX_TOOL_RESULT_CHARS = 12000
TOKEN_CHARS_APPROX = 4

# Fields carrying conclusions, negative results, coverage and caveats. These
# survive truncation; bulk evidence lists are shortened around them.
PRIORITY_RESULT_FIELDS = frozenset({
    "answer_draft",
    "key_findings",
    "caveats",
    "negative_checks",
    "coverage",
    "coverage_status",
    "source_availability_status",
    "missing_sources",
    "noise_policy",
    "interpreted_question",
    "analysis_window",
    "summary",
    "reasoning",
    "filters",
    "total",
    "total_events",
    "status",
    "error",
    "recoverable",
    "retry_guidance",
    "retries_remaining",
    "tool_name",
    "tier",
    "provenance",
    "permission",
})


def _build_case_static_context_block(case_context: Dict) -> str:
    """Render case identity. Hosts and findings are separate ordered blocks."""
    synthesis_block = ""
    if case_context.get('ai_synthesis'):
        synth = case_context['ai_synthesis']
        if synth.get('executive_summary'):
            synthesis_block = f"\n\nAI Executive Summary:\n{synth['executive_summary'][:500]}"

    return f"""Current Case: {case_context.get('case_name', 'Unknown')}
Case ID: {case_context.get('case_id', 'Unknown')}
Description: {case_context.get('description', 'No description')[:300]}
Time Zone: {case_context.get('timezone', 'UTC')}{synthesis_block}"""


def _build_available_artifacts_block(case_context: Dict) -> str:
    """Render the known-host inventory block."""
    return f"Known hosts: {', '.join(case_context.get('hosts', [])[:15]) or 'Unknown'}"


def _build_finding_summary_block(case_context: Dict) -> str:
    """Render the case analysis totals block."""
    summary = case_context.get('analysis_summary') or {}
    if not summary:
        return ""
    return (
        f"Total events: {summary.get('census_total_events', 'unknown')}\n"
        f"Distinct event IDs: {summary.get('census_distinct_event_ids', 'unknown')}\n"
        f"Pattern matches: {summary.get('pattern_matches_found', 0)}\n"
        f"Attack chains: {summary.get('attack_chains_found', 0)}\n"
        f"IOC timeline entries: {summary.get('ioc_timeline_entries', 0)}"
    )


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
- For open-ended forensic questions like "what happened", "what did this user do", "is this hypothesis supported", or "what happened after this event", prefer investigate_question first so the investigation can pivot across evidence families before you answer
- Use atomic tools such as query_events, search_artifacts, get_processes, and get_browser_downloads for narrow follow-up checks or when the user asks for a specific source
- When the user asks whether something is present in the case, choose the right forensic source instead of defaulting to generic event rows:
  browser downloads for downloaded files and URLs, process tools for execution questions, memory tools for RAM-resident evidence, network tools for PCAP/Zeek questions, and cross-artifact search when the artifact family is unclear
- Treat analyst-style search lists such as "ConnectWise / ScreenConnect / Control" as alternative terms to check individually, not as one literal phrase
- If a user challenges a negative finding or points to visible evidence, re-run the relevant pivots with explicit terms, include noise-tagged evidence where supported, and compare the new results against the prior conclusion before answering
- A zero-result search is not enough to close a question unless the searched terms, filters, source coverage, noise policy, and artifact family are appropriate for the question
- For RMM and remote-support questions, check both normalized fields and raw event/artifact text because user/session labels often appear only in service event descriptions
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


def _sanitize_case_context_blocks(case_id: Any, blocks: List[str], provider: Any) -> List[str]:
    """Alias the case-derived prompt blocks, leaving authored text untouched.

    Returns the blocks unchanged when there is no case to scope aliases to; the
    router still sanitizes everything else on the way out, so nothing case-
    derived can reach a provider unaliased by skipping this.
    """
    if not case_id:
        return blocks
    from utils.privacy_aliases import sanitize_case_context_blocks

    return sanitize_case_context_blocks(int(case_id), blocks, provider=provider)


def build_system_prompt(
    case_context: Dict,
    conversation_context: Optional[ConversationContext] = None,
    provider_descriptor: Optional[Dict[str, Any]] = None,
) -> str:
    """Build the system prompt, the single home for every conversation-stable block.

    These blocks do not change between rounds, so keeping them here (and out of
    the per-turn messages) both removes duplicate copies from every request and
    leaves a stable prefix that providers can cache.

    The case-derived blocks are aliased here rather than at the router, so that
    the role and behaviour instructions around them are not rewritten by a
    vault that holds ordinary words. The caller marks the resulting message
    with PRESANITIZED_MESSAGE_KEY.
    """
    case_static, artifacts, findings = _sanitize_case_context_blocks(
        case_context.get("case_id") or case_context.get("id"),
        [
            _build_case_static_context_block(case_context),
            _build_available_artifacts_block(case_context),
            _build_finding_summary_block(case_context),
        ],
        (provider_descriptor or {}).get("provider_type"),
    )

    scheduler = AttachmentScheduler()
    scheduler.add(AttachmentOrder.CASE_STATIC_CONTEXT, "CASE_STATIC_CONTEXT", case_static)
    scheduler.add(
        AttachmentOrder.LICENSE_CAPABILITIES,
        "LICENSE_CAPABILITIES",
        _build_license_capabilities_block(conversation_context),
    )
    scheduler.add(AttachmentOrder.AVAILABLE_ARTIFACTS, "AVAILABLE_ARTIFACTS", artifacts)
    scheduler.add(AttachmentOrder.FINDING_SUMMARY, "FINDING_SUMMARY", findings)
    return f"{_build_static_role_block()}\n\n{scheduler.render()}"


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


def _build_request_messages(
    full_messages: List[Dict[str, Any]],
    case_context: Dict[str, Any],
    conversation_context: ConversationContext,
    provider_descriptor: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Prepare request messages using the shared chat runtime helpers.

    Conversation-stable context lives in the system prompt only. Prior turns are
    already present as real messages, so nothing is replayed into the user turn.
    """
    del case_context
    request_messages = _compact_messages(
        full_messages,
        token_budget=_history_token_budget(conversation_context),
    )
    request_messages = [dict(message) for message in request_messages]
    request_messages = _sanitize_tool_message_adjacency(request_messages)

    provider_type = str((provider_descriptor or {}).get("provider_type") or "").lower()
    if provider_type in {"claude", "anthropic"}:
        request_messages = add_cache_breakpoints(request_messages)
    request_messages = inject_tool_result_cache_refs(request_messages)
    request_messages.insert(1, {
        "role": "system",
        "content": _build_token_budget_block(request_messages, conversation_context),
    })
    return _mark_presanitized_system_messages(request_messages, provider_type)


def _mark_presanitized_system_messages(
    messages: List[Dict[str, Any]],
    provider_type: str,
) -> List[Dict[str, Any]]:
    """Exempt the two authored system messages from a second sanitizer pass.

    Their case-derived blocks were aliased by build_system_prompt; the text
    around them is CaseScope's own, and letting the router alias it again
    rewrites the instructions themselves. The marker is stripped before egress.

    Only marked when the provider was resolved, because that is the same
    condition under which build_system_prompt aliased those blocks. Marking an
    unsanitized prompt would tell the router to skip the only pass left.
    """
    if not provider_type:
        return messages

    from utils.privacy_aliases import PRESANITIZED_MESSAGE_KEY

    for message in messages[:2]:
        if message.get("role") == "system":
            message[PRESANITIZED_MESSAGE_KEY] = True
    return messages


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


def _is_local_chat_provider(provider_descriptor: Dict[str, Any]) -> bool:
    """Return True when chat tool calls stay on a local provider."""
    if provider_descriptor.get("is_local") is True:
        return True
    provider_type = str(provider_descriptor.get("provider_type") or "").lower()
    return provider_type == "local"


def _local_auto_approval_for_tier(
    provider_descriptor: Dict[str, Any],
    tier: ToolTier,
) -> tuple[Optional[str], str]:
    """Auto-approve local sensitive read tools without prompting."""
    if tier == ToolTier.READ_SENSITIVE and _is_local_chat_provider(provider_descriptor):
        return "allow_session", "Local chat provider keeps tool use on this host"
    return None, ""


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


# Rejection categories the model can act on by correcting or abandoning the call.
# Analyst denials and cross-case denials are deliberately absent: those are human
# or policy decisions the model must not retry around.
RECOVERABLE_PERMISSION_CATEGORIES = {
    "invalid tool arguments",
    "invalid provenance",
    "feature unavailable",
}


def _permission_category(result: Dict[str, Any]) -> str:
    permission = result.get("permission") if isinstance(result.get("permission"), dict) else {}
    return str(permission.get("category") or "")


def _is_recoverable_tool_result(result: Dict[str, Any]) -> bool:
    """Return True when the model may correct the call and continue the turn."""
    status = result.get("status")
    if status == "error":
        return True
    if status != "rejected":
        return False
    return _permission_category(result) in RECOVERABLE_PERMISSION_CATEGORIES


def _is_terminal_tool_result(result: Dict[str, Any]) -> bool:
    """Return True when a tool result should stop the live tool loop."""
    if _is_recoverable_tool_result(result):
        return False
    return result.get("status") in {"interrupt", "rejected", "error"}


def _recovery_guidance(tool_name: str, result: Dict[str, Any], retries_remaining: int) -> str:
    """Return actionable guidance the model can use to correct a failed call."""
    category = _permission_category(result)

    if category == "feature unavailable":
        return (
            f"{tool_name} is not licensed or configured on this installation. "
            "Do not call it again in this conversation. Answer from case evidence "
            "and state plainly that the capability is unavailable."
        )

    if retries_remaining <= 0:
        return (
            f"{tool_name} has failed too many times in this turn and will not be run again. "
            "Use a different tool or answer from the evidence already gathered."
        )

    if category == "invalid tool arguments":
        schema = _TOOL_PARAMETER_SCHEMAS.get(tool_name) or {}
        properties = sorted((schema.get("properties") or {}).keys())
        required = sorted(schema.get("required") or [])
        return (
            f"Correct the arguments and call {tool_name} again. "
            f"Allowed arguments: {', '.join(properties) or 'none'}. "
            f"Required arguments: {', '.join(required) or 'none'}."
        )

    return (
        f"{tool_name} did not run. Fix the request or choose a different tool; "
        "do not repeat the identical call."
    )


def _annotate_recoverable_result(
    result: Dict[str, Any],
    *,
    tool_name: str,
    retries_remaining: int,
) -> Dict[str, Any]:
    """Attach retry guidance so the failure is actionable in the next round."""
    return {
        **result,
        "recoverable": True,
        "retries_remaining": max(0, retries_remaining),
        "retry_guidance": _recovery_guidance(tool_name, result, retries_remaining),
    }


def _retry_budget_exhausted_result(
    *,
    tool_name: str,
    tier: ToolTier,
    provenance: Provenance,
) -> Dict[str, Any]:
    """Return a cheap refusal for a tool that already burned its retry budget."""
    reason = f"{tool_name} exceeded its retry budget for this turn"
    block = ToolResultBlock.reject(
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
    return _annotate_recoverable_result(
        block.to_payload(),
        tool_name=tool_name,
        retries_remaining=0,
    )


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
    tier: Optional[str] = None,
    provenance: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the structured pending approval payload for live UI events."""
    definition = next(
        (
            tool.get("function", {})
            for tool in TOOL_DEFINITIONS
            if tool.get("function", {}).get("name") == tool_name
        ),
        {},
    )
    schema = definition.get("parameters") if isinstance(definition.get("parameters"), dict) else {}
    required_params = schema.get("required", []) if isinstance(schema, dict) else []
    return {
        "tool_name": tool_name,
        "tool_call_id": tool_call_id,
        "description": definition.get("description", ""),
        "tier": tier,
        "provenance": provenance,
        "params": json.loads(json.dumps(params or {}, default=str)),
        "required_params": list(required_params or []),
        "permission": json.loads(json.dumps(permission or {}, default=str)),
        "approval_options": [
            {"decision": "allow", "label": "Allow once", "cacheable": False},
            {"decision": "allow_session", "label": "Allow for this session", "cacheable": True},
            {"decision": "reject", "label": "Deny", "cacheable": False},
            {"decision": "do_not_ask_reject", "label": "Deny and explain", "cacheable": True},
        ],
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
    params: Optional[Dict[str, Any]] = None,
) -> None:
    """Place a resumed tool result adjacent to its original assistant tool call."""
    call_id = tool_call_id or "approval_resume"

    def _assistant_tool_call() -> Dict[str, Any]:
        return {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": call_id,
                "type": "function",
                "function": {
                    "name": tool_name,
                    "arguments": json.dumps(params or {}, sort_keys=True, default=str),
                },
            }],
        }

    def _tool_message() -> Dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": call_id,
            "name": tool_name,
            "content": content,
        }

    if not tool_call_id:
        messages.append(_assistant_tool_call())
        messages.append(_tool_message())
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
                messages[insert_at] = _tool_message()
                return
            insert_at += 1

        messages.insert(insert_at, _tool_message())
        return

    messages.append(_assistant_tool_call())
    messages.append(_tool_message())


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


def _stream_llm_chat(
    messages: List[Dict],
    tools: List[Dict] = None,
    case_id: int = None,
    privacy_context=None,
) -> Generator:
    """Stream response from the configured LLM provider.

    In strict E2 mode each provider round that includes newly retrieved case
    evidence must carry a new freeze/verify proof. A prior round's verified
    proof must not be reused after a tool fetches additional events.
    """
    context = privacy_context
    if context is None and AIPrivacyContext and case_id:
        context = AIPrivacyContext.case_content(case_id)
    yield from stream_chat(
        function='chat',
        messages=messages,
        tools=tools,
        temperature=0.3,
        max_tokens=MAX_RESPONSE_TOKENS,
        privacy_context=context,
    )


def _truncate_text(text: str, max_len: int) -> str:
    """Truncate text for compact conversation summaries."""
    text = (text or '').strip()
    if len(text) <= max_len:
        return text
    return text[:max_len].rstrip() + '...[TRUNCATED]'


# An alias token is a run of [A-Za-z0-9_] optionally followed by '$' for machine
# accounts. Text can be released up to the last character that cannot belong to
# one, which makes splitting an alias across two SSE frames impossible.
_ALIAS_TOKEN_CHARS = frozenset(string.ascii_letters + string.digits + "_$")


class _AliasSafeDisplayStream:
    """Release display text as it streams without ever splitting an alias token."""

    def __init__(self, case_id: int) -> None:
        self._buffer = ""
        try:
            self._rehydrate = build_display_rehydrator(case_id) if case_id else (lambda text: text)
        except Exception as exc:
            logger.warning("[ChatAgent] Alias rehydration unavailable for case %s: %s", case_id, exc)
            self._rehydrate = lambda text: text

    def feed(self, chunk: str) -> str:
        """Return the display-safe text unlocked by this chunk, if any."""
        self._buffer += chunk
        cut = len(self._buffer)
        while cut > 0 and self._buffer[cut - 1] in _ALIAS_TOKEN_CHARS:
            cut -= 1
        if cut <= 0:
            return ""
        released, self._buffer = self._buffer[:cut], self._buffer[cut:]
        return self._safe_rehydrate(released)

    def flush(self) -> str:
        """Return any text still held back, once no more chunks can arrive."""
        released, self._buffer = self._buffer, ""
        return self._safe_rehydrate(released) if released else ""

    def discard(self) -> None:
        self._buffer = ""

    def _safe_rehydrate(self, text: str) -> str:
        try:
            return self._rehydrate(text)
        except Exception as exc:
            logger.warning("[ChatAgent] Alias rehydration failed: %s", exc)
            return text


def _safe_rehydrate_for_display(case_id: int, payload: Any) -> Any:
    """Restore privacy aliases when app context is available; otherwise return payload."""
    try:
        return rehydrate_for_display(case_id, payload)
    except RuntimeError:
        return payload


def _is_compaction_summary(message: Dict[str, Any]) -> bool:
    return (
        message.get("role") == "system"
        and isinstance(message.get("content"), str)
        and message["content"].startswith("Conversation summary from earlier turns:")
    )


def _estimate_message_tokens(messages: List[Dict[str, Any]]) -> int:
    """Estimate chat token pressure without provider-specific tokenizers."""
    char_count = 0
    for message in messages:
        char_count += len(str(message.get("content") or ""))
        for tool_call in message.get("tool_calls") or []:
            char_count += len(json.dumps(tool_call, default=str))
    return max(1, int(char_count / TOKEN_CHARS_APPROX))


def _build_token_budget_block(messages: List[Dict[str, Any]], conversation_context: ConversationContext) -> str:
    """Render a compact token-budget advisory for the model and audit trail."""
    estimated = _estimate_message_tokens(messages)
    context_window = _model_context_window(conversation_context)
    remaining = max(0, context_window - estimated)
    return (
        "TOKEN_BUDGET\n"
        f"- Estimated request tokens: {estimated}\n"
        f"- Model context window: {context_window}\n"
        f"- Estimated remaining context: {remaining}\n"
        "- Treat tool outputs as evidence-backed facts; treat prior assistant-only claims as hypotheses unless supported by tool results."
    )


def _model_context_window(conversation_context: Optional[ConversationContext]) -> int:
    """Return the configured model's context window, falling back conservatively."""
    try:
        from utils.ai_providers import get_model_profile

        model = (conversation_context.model_selection if conversation_context else "") or ""
        profile = get_model_profile(model)
    except Exception:
        profile = {}
    return int((profile or {}).get("context_window") or DEFAULT_CONTEXT_WINDOW)


def _history_token_budget(conversation_context: Optional[ConversationContext]) -> int:
    """Tokens available for chat history after the response and prompt reserves."""
    available = (
        _model_context_window(conversation_context)
        - MAX_RESPONSE_TOKENS
        - SYSTEM_PROMPT_RESERVE_TOKENS
        - CONTEXT_SAFETY_MARGIN_TOKENS
    )
    return max(MIN_HISTORY_TOKENS, available)


def _compact_messages(
    messages: List[Dict[str, Any]],
    token_budget: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Compress older chat history into a short system summary.

    History is trimmed against an estimated token budget rather than a message
    count, because a single tool result can outweigh a dozen chat turns.
    """
    if len(messages) <= 1:
        return messages

    budget = token_budget if token_budget is not None else MIN_HISTORY_TOKENS
    system_message = messages[0]
    history = [msg for msg in messages[1:] if not _is_compaction_summary(msg)]

    retained: List[Dict[str, Any]] = []
    used_tokens = 0
    for message in reversed(history):
        message_tokens = _estimate_message_tokens([message])
        if retained and used_tokens + message_tokens > budget:
            break
        retained.append(message)
        used_tokens += message_tokens
    retained.reverse()

    if len(retained) == len(history):
        return [system_message, *history]

    older_messages = history[:len(history) - len(retained)]
    recent_messages = retained
    evidence_lines = []
    hypothesis_lines = []
    user_lines = []

    for message in older_messages[-MAX_SUMMARY_ITEMS:]:
        role = message.get("role", "unknown")
        if role == "tool":
            tool_name = message.get("name", "tool")
            content = _truncate_text(str(message.get("content", "")), MAX_SUMMARY_CHARS)
            evidence_lines.append(f"- Tool {tool_name}: {content}")
            continue

        content = _truncate_text(str(message.get("content", "")), MAX_SUMMARY_CHARS)
        if role == "assistant":
            hypothesis_lines.append(f"- Assistant hypothesis: {content}")
        elif role == "user":
            user_lines.append(f"- Analyst/user request: {content}")
        else:
            hypothesis_lines.append(f"- {role.title()}: {content}")

    if not evidence_lines and not hypothesis_lines and not user_lines:
        return [system_message, *recent_messages]

    summary_lines = [
        "Evidence-backed tool results:",
        *(evidence_lines or ["- None retained from compacted turns."]),
        "Prior analyst requests:",
        *(user_lines or ["- None retained from compacted turns."]),
        "Model-generated hypotheses or summaries:",
        *(hypothesis_lines or ["- None retained from compacted turns."]),
    ]
    summary_message = {
        "role": "system",
        "content": "Conversation summary from earlier turns:\n" + "\n".join(summary_lines),
    }
    return [system_message, summary_message, *recent_messages]


def _bulk_result_fields(payload: Dict[str, Any]) -> List[str]:
    """Return trimmable evidence lists, excluding fields that carry conclusions."""
    return [
        key for key, value in payload.items()
        if key not in PRIORITY_RESULT_FIELDS and isinstance(value, list) and value
    ]


def _serialize_tool_result_for_history(result: Dict[str, Any]) -> str:
    """Bound tool result size, shortening bulk evidence before conclusions.

    Slicing the serialized JSON discarded whatever came last, which for an
    investigation payload is the reasoning that qualifies the raw rows. Trim the
    largest evidence lists instead and record what was dropped.
    """
    serialized = json.dumps(result, default=str)
    if len(serialized) <= MAX_TOOL_RESULT_CHARS or not isinstance(result, dict):
        return serialized

    trimmed = dict(result)
    dropped: Dict[str, Dict[str, int]] = {}
    while len(json.dumps(trimmed, default=str)) > MAX_TOOL_RESULT_CHARS:
        candidates = [
            (len(json.dumps(trimmed[key], default=str)), key)
            for key in _bulk_result_fields(trimmed)
        ]
        if not candidates:
            break
        _, largest = max(candidates)
        items = trimmed[largest]
        original = dropped.get(largest, {}).get("original", len(items))
        kept = len(items) // 2
        trimmed[largest] = items[:kept]
        dropped[largest] = {"original": original, "kept": kept}

    if dropped:
        trimmed["_trimmed_for_context"] = {
            key: f"kept {info['kept']} of {info['original']} items"
            for key, info in dropped.items()
        }

    serialized = json.dumps(trimmed, default=str)
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

    Wraps the agent loop so that a client disconnect mid-stream still persists
    the turn: the in-flight assistant text and any completed tool work are
    saved via on_complete from the finally block instead of being dropped.
    """
    stream_state: Dict[str, Any] = {
        "full_messages": None,
        "partial_parts": None,
        "persisted": False,
    }
    try:
        yield from _chat_stream_impl(
            case_id,
            messages,
            conversation_id=conversation_id,
            tool_approval=tool_approval,
            hunt_run_id=hunt_run_id,
            actor_metadata=actor_metadata,
            on_complete=on_complete,
            stream_state=stream_state,
        )
    finally:
        if not stream_state["persisted"] and on_complete is not None \
                and stream_state["full_messages"] is not None:
            full_messages = stream_state["full_messages"]
            partial_text = ''.join(stream_state.get("partial_parts") or []).strip()
            if partial_text:
                full_messages.append({
                    "role": "assistant",
                    "content": partial_text + "\n\n_[Response interrupted before completion.]_",
                })
            try:
                on_complete(_history_messages_for_session(full_messages))
                logger.info("[ChatAgent] Persisted interrupted transcript for %s", conversation_id)
            except Exception as exc:
                logger.error("[ChatAgent] Failed to persist interrupted transcript for %s: %s",
                             conversation_id, exc, exc_info=True)


def _chat_stream_impl(case_id: int, messages: List[Dict],
                      conversation_id: str = None,
                      tool_approval: Optional[Dict[str, Any]] = None,
                      hunt_run_id: Optional[int] = None,
                      actor_metadata: Optional[Dict[str, Any]] = None,
                      on_complete: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
                      stream_state: Optional[Dict[str, Any]] = None
                      ) -> Generator[str, None, None]:
    """Agentic chat loop. It:
    1. Loads case context and builds system prompt
    2. Calls the LLM with tool definitions
    3. Streams text tokens as SSE events
    4. When a tool call is detected, executes it and loops back
    5. Stops after MAX_TOOL_ROUNDS or when the model produces text-only response
    
    Args:
        case_id: Case ID for context
        messages: User messages [{role, content}]
        conversation_id: Optional conversation tracking ID
        tool_approval: Optional analyst approval payload for a pending tool
        stream_state: Shared dict for the chat_stream wrapper to observe
            in-flight history/partial output for disconnect persistence
        
    Yields:
        SSE-formatted strings: "data: {...}\n\n"
    """
    if stream_state is None:
        stream_state = {}
    # Load case context
    case_context = get_case_context(case_id)
    conversation_context = _capture_conversation_context(case_context)
    try:
        provider_descriptor = get_provider_descriptor(function="chat")
    except Exception:
        provider_descriptor = {}
    # Resolved before the prompt is built: aliasing the case-derived blocks
    # depends on whether the provider is local.
    system_prompt = build_system_prompt(case_context, conversation_context, provider_descriptor)
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
    stream_state["full_messages"] = full_messages
    _seed_permission_cache_from_history(
        case_id=case_id,
        conversation_id=conversation_id,
        messages=messages,
    )
    
    tool_round = 0
    recovery_rounds = 0
    tool_retry_counts: Dict[str, int] = {}
    executed_tool_results: Dict[str, Dict[str, Any]] = {}
    preflight_terminal_result = False
    pending_tool_approval_state: Optional[Dict[str, Any]] = None
    had_error = False
    stream_error_text = ""
    produced_answer = False
    final_synthesis = False
    buffered_content_parts: List[str] = []

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
            if _is_recoverable_tool_result(result):
                tool_retry_counts[approved_tool_name] = tool_retry_counts.get(approved_tool_name, 0) + 1
                result = _annotate_recoverable_result(
                    result,
                    tool_name=approved_tool_name,
                    retries_remaining=MAX_TOOL_RETRIES_PER_TOOL - tool_retry_counts[approved_tool_name] + 1,
                )
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
                    tier=result.get("tier"),
                    provenance=result.get("provenance"),
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
                "recoverable": bool(result.get("recoverable")),
                "result_preview": _preview_result(result),
            })
            _upsert_tool_result_after_call(
                full_messages,
                tool_call_id=str(tool_approval.get("tool_call_id") or ""),
                tool_name=approved_tool_name,
                content=_serialize_tool_result_for_history(result),
                params=approved_params,
            )
            yield _sse_event("tool_end", {})
            preflight_terminal_result = _is_terminal_tool_result(result)
            if preflight_terminal_result:
                terminal_message = _terminal_tool_message(approved_tool_name, result)
                if terminal_message:
                    full_messages.append({"role": "assistant", "content": terminal_message})
                    produced_answer = True
                    yield _sse_event("token", {"content": terminal_message})
    
    while (
        not preflight_terminal_result
        and tool_round < MAX_TOOL_ROUNDS
        and recovery_rounds < MAX_TOOL_RECOVERY_ROUNDS
    ):
        buffered_content_parts: List[str] = []
        stream_state["partial_parts"] = buffered_content_parts
        tool_calls: List[Dict[str, Any]] = []
        had_error = False
        display_stream = _AliasSafeDisplayStream(case_id)
        streamed_provisional = False
        request_messages = _build_request_messages(
            full_messages,
            case_context,
            conversation_context,
            provider_descriptor=provider_descriptor,
        )
        
        for chunk in _stream_llm_chat(request_messages, TOOL_DEFINITIONS, case_id=case_id):
            # Check for errors
            if "error" in chunk:
                stream_error_text = str(chunk["error"])
                yield _sse_event("error", {"error": chunk["error"]})
                had_error = True
                break
            
            msg = chunk.get("message", {})
            
            # Check for tool calls
            if msg.get("tool_calls"):
                _merge_tool_calls(tool_calls, msg["tool_calls"])
            
            # Stream content as it arrives. It is provisional until the round
            # ends: if a tool call follows, this was pre-tool narration and the
            # client is told to drop it.
            content = msg.get("content", "")
            if content:
                buffered_content_parts.append(content)
                if not tool_calls:
                    unlocked = display_stream.feed(content)
                    if unlocked:
                        streamed_provisional = True
                        yield _sse_event("token", {"content": unlocked, "provisional": True})

            if chunk.get("done", False):
                break
        
        if had_error:
            break

        accumulated_content = ''.join(buffered_content_parts)
        # Round content is consumed below; stop tracking it as partial output
        stream_state["partial_parts"] = None
        
        # If we got tool calls, execute them and loop
        if tool_calls:
            # The round narrated before calling a tool; withdraw that text.
            display_stream.discard()
            if streamed_provisional:
                yield _sse_event("token_retract", {})

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
            round_executed_tool = False
            for tc in normalized_tool_calls:
                func_name = tc.get("function", {}).get("name", "")
                if not func_name:
                    logger.warning("[ChatAgent] Skipping tool call without function name: %s", tc)
                    continue
                tool_tier, tool_provenance = _resolve_tool_policy(func_name)
                if tool_retry_counts.get(func_name, 0) > MAX_TOOL_RETRIES_PER_TOOL:
                    result = _retry_budget_exhausted_result(
                        tool_name=func_name,
                        tier=tool_tier,
                        provenance=tool_provenance,
                    )
                    yield _sse_event("tool_result", {
                        "tool": func_name,
                        "status": result.get("status"),
                        "tier": result.get("tier"),
                        "provenance": result.get("provenance"),
                        "permission": result.get("permission", {}),
                        "pending_tool_approval": None,
                        "recoverable": True,
                        "result_preview": _preview_result(result),
                    })
                    full_messages.append({
                        "role": "tool",
                        "tool_call_id": tc.get("id"),
                        "name": func_name,
                        "content": _serialize_tool_result_for_history(result),
                    })
                    continue
                func_args, decode_error = _decode_tool_arguments(tc)
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
                            result_payload=prior_result,
                            tier=tool_tier,
                            provenance=reused_provenance,
                        )
                    else:
                        auto_decision, auto_reason = _local_auto_approval_for_tier(
                            provider_descriptor,
                            tool_tier,
                        )
                        tool_result = _TOOL_DISPATCHER.execute(
                            tool_name=func_name,
                            case_id=case_id,
                            params=func_args,
                            tier=tool_tier,
                            provenance=tool_provenance,
                            session_id=conversation_id,
                            analyst_decision=auto_decision,
                            analyst_reason=auto_reason,
                            hunt_run_id=hunt_run_id,
                            actor_metadata=trace_actor_metadata,
                            model_metadata=model_metadata,
                        )
                result = tool_result.to_payload()
                if _is_recoverable_tool_result(result):
                    attempts = tool_retry_counts.get(func_name, 0) + 1
                    tool_retry_counts[func_name] = attempts
                    if _permission_category(result) == "feature unavailable":
                        # Licensed capability is off; retrying cannot change that.
                        tool_retry_counts[func_name] = MAX_TOOL_RETRIES_PER_TOOL + 1
                        attempts = MAX_TOOL_RETRIES_PER_TOOL + 1
                    result = _annotate_recoverable_result(
                        result,
                        tool_name=func_name,
                        retries_remaining=MAX_TOOL_RETRIES_PER_TOOL - attempts + 1,
                    )
                    logger.info(
                        "[ChatAgent] Recoverable %s failure (%s), attempt %s: %s",
                        func_name,
                        _permission_category(result) or result.get("status"),
                        attempts,
                        result.get("error"),
                    )
                else:
                    round_executed_tool = True
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
                        tier=result.get("tier"),
                        provenance=result.get("provenance"),
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
                    "recoverable": bool(result.get("recoverable")),
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
                    produced_answer = True
                    yield _sse_event("token", {"content": terminal_message})
                break

            # A round where nothing reached an executor is recovery, not progress.
            if round_executed_tool:
                tool_round += 1
                yield _sse_event("tool_progress", {"message": "Analyzing tool results..."})
            else:
                recovery_rounds += 1
                yield _sse_event("tool_progress", {"message": "Correcting the tool request..."})

            # Continue loop — LLM will now see tool results
            continue
        
        # No tool calls — model gave a text response, we're done
        if accumulated_content:
            full_messages.append({"role": "assistant", "content": accumulated_content})
            produced_answer = True
        tail = display_stream.flush()
        if tail:
            yield _sse_event("token", {"content": tail, "provisional": True})
        if accumulated_content:
            yield _sse_event("token_commit", {})
        break

    # A turn must never end silently. When the tool budget is spent, or the model
    # returned nothing, ask once more with tools disabled so the analyst gets an
    # answer grounded in the evidence already gathered.
    if not had_error and not produced_answer:
        synthesis_parts: List[str] = []
        stream_state["partial_parts"] = synthesis_parts
        synthesis_messages = _build_request_messages(
            full_messages,
            case_context,
            conversation_context,
            provider_descriptor=provider_descriptor,
        )
        synthesis_messages.append({"role": "system", "content": FINAL_SYNTHESIS_DIRECTIVE})

        yield _sse_event("tool_progress", {"message": "Summarizing the evidence gathered..."})
        synthesis_stream = _AliasSafeDisplayStream(case_id)
        for chunk in _stream_llm_chat(synthesis_messages, None, case_id=case_id):
            if "error" in chunk:
                stream_error_text = str(chunk["error"])
                yield _sse_event("error", {"error": chunk["error"]})
                had_error = True
                break
            content = chunk.get("message", {}).get("content", "")
            if content:
                synthesis_parts.append(content)
                unlocked = synthesis_stream.feed(content)
                if unlocked:
                    yield _sse_event("token", {"content": unlocked, "provisional": True})
            if chunk.get("done", False):
                break

        synthesis_content = ''.join(synthesis_parts).strip()
        stream_state["partial_parts"] = None
        tail = synthesis_stream.flush()
        if tail:
            yield _sse_event("token", {"content": tail, "provisional": True})
        if synthesis_content:
            full_messages.append({"role": "assistant", "content": synthesis_content})
            produced_answer = True
            final_synthesis = True
            yield _sse_event("token_commit", {})

    if had_error:
        # The analyst's question and any completed tool work must survive a
        # provider failure, so the turn is recorded rather than discarded.
        partial_text = ''.join(buffered_content_parts).strip() if buffered_content_parts else ''
        error_note = f"_[The assistant could not complete this response: {stream_error_text}]_"
        full_messages.append({
            "role": "assistant",
            "content": f"{partial_text}\n\n{error_note}".strip() if partial_text else error_note,
        })

    if on_complete is not None:
        try:
            on_complete(_history_messages_for_session(full_messages))
        except Exception as exc:
            logger.error("[ChatAgent] Failed to finalize transcript for %s: %s",
                         conversation_id, exc, exc_info=True)
    # Every completion path above persists the turn, so the wrapper must not
    # persist again from its finally block
    stream_state["persisted"] = True

    # Send done event
    yield _sse_event("done", {
        "tool_rounds": tool_round,
        "conversation_id": conversation_id,
        "pending_tool_approval": pending_tool_approval_state,
        "final_synthesis": final_synthesis,
    })


FINAL_SYNTHESIS_DIRECTIVE = (
    "SYNTHESIS_REQUIRED\n"
    "The tool budget for this turn is spent. Do not request any more tools.\n"
    "Answer the analyst now using only the tool results and case context already present "
    "in this conversation.\n"
    "State what the evidence supports, what remains unverified, and what you could not check. "
    "Do not invent evidence to fill the gaps."
)


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
        function_name = str(function_payload.get("name") or "").strip()
        if not function_name:
            continue
        normalized_calls.append({
            "id": tool_call.get("id") or f"tool_call_{index}",
            "type": tool_call.get("type") or "function",
            "function": {
                "name": function_name,
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
            permission = PermissionResult(
                allowed=bool(permission_payload.get("allowed")),
                category=str(permission_payload.get("category") or "allow"),
                reason=str(permission_payload.get("reason") or ""),
                cacheable=True,
            )
            if (
                permission.allowed
                and permission.category == "session allow"
                and hasattr(_TOOL_DISPATCHER, "cache_session_permission_decision")
            ):
                _TOOL_DISPATCHER.cache_session_permission_decision(
                    case_id=case_id,
                    session_id=conversation_id,
                    permission=permission,
                )
            else:
                _TOOL_DISPATCHER.cache_permission_decision(
                    tool_name=tool_name,
                    case_id=case_id,
                    session_id=conversation_id,
                    params=params,
                    permission=permission,
                )
        except Exception:
            logger.debug(
                "[ChatAgent] Failed to seed permission cache for %s",
                tool_name,
                exc_info=True,
            )


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
