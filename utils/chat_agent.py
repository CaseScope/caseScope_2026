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

import json
import logging
import time
import requests
from typing import Dict, List, Any, Generator, Optional

from config import Config
from utils.chat_tools import TOOL_DEFINITIONS, execute_tool

logger = logging.getLogger(__name__)

MAX_TOOL_ROUNDS = 5
CHAT_TIMEOUT = 180  # 3 minutes per LLM call


def build_system_prompt(case_context: Dict) -> str:
    """Build the system prompt with case context.
    
    Args:
        case_context: Dict with case_name, description, hosts, etc.
        
    Returns:
        System prompt string
    """
    hosts_str = ', '.join(case_context.get('hosts', [])[:15]) or 'Unknown'
    
    # Build findings summary if available
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
    
    return f"""You are a DFIR (Digital Forensics and Incident Response) analyst assistant for CaseScope.
You should feel like a case-aware investigative copilot, similar to a ChatGPT-style conversation where the case is already loaded into context.
You help investigators analyze forensic cases by querying events, browser artifacts, memory data, PCAP-derived network logs, process views, IOC matches, and detection findings.

Current Case: {case_context.get('case_name', 'Unknown')}
Case ID: {case_context.get('case_id', 'Unknown')}
Description: {case_context.get('description', 'No description')[:300]}
Known Hosts: {hosts_str}
Time Zone: {case_context.get('timezone', 'UTC')}
{findings_block}{synthesis_block}

Guidelines:
- Be conversational, concise, and forensically accurate
- Treat the case as already loaded into context, but use tools silently when you need fresh or more specific data
- When the user asks whether something is present in the case, choose the right forensic source instead of defaulting to generic event rows:
  browser downloads for downloaded files and URLs, process tools for execution questions, memory tools for RAM-resident evidence, network tools for PCAP/Zeek questions, and cross-artifact search when the artifact family is unclear
- Never fabricate events, timestamps, usernames, hosts, IPs, or findings
- Never claim you queried or reviewed data unless tool results are actually present in the conversation
- Do not narrate future actions like "I will query" or "let me check"; just perform the tool call when needed
- Reference specific hosts, timestamps, usernames, IPs, and event IDs when the evidence supports it
- If evidence is missing or incomplete, say so clearly and preserve uncertainty
- Explain forensic significance of findings when it helps the analyst
- When listing events, format them clearly with timestamps and key fields
- Present counts and statistics when they help contextualize findings
- Flag anything that looks like lateral movement, privilege escalation, or data exfiltration"""


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


def chat_stream(case_id: int, messages: List[Dict],
                conversation_id: str = None) -> Generator[str, None, None]:
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
    system_prompt = build_system_prompt(case_context)
    
    # Build full message list with system prompt
    full_messages = [{"role": "system", "content": system_prompt}]
    full_messages.extend(messages)
    
    tool_round = 0
    
    while tool_round < MAX_TOOL_ROUNDS:
        tool_round += 1
        
        buffered_content_parts: List[str] = []
        tool_calls: List[Dict[str, Any]] = []
        had_error = False
        
        for chunk in _stream_llm_chat(full_messages, TOOL_DEFINITIONS):
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
                
                # Execute tool
                result = execute_tool(func_name, case_id, func_args)
                
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
                    "content": json.dumps(result, default=str)
                })
            
            yield _sse_event("tool_end", {})
            
            # Continue loop — LLM will now see tool results
            continue
        
        # No tool calls — model gave a text response, we're done
        for content_part in buffered_content_parts:
            yield _sse_event("token", {"content": content_part})
        break
    
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
