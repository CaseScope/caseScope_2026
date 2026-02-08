"""Chat Agent for CaseScope

Agentic chat loop with Ollama streaming and tool execution.
Supports SSE for real-time token streaming to the frontend.

Architecture:
- Uses Ollama /api/chat with tools parameter for native tool calling
- Streams tokens via SSE, buffering tool-call JSON
- Executes tools from chat_tools registry
- Max tool rounds: 5 (prevents infinite loops)
- Pre-loads case context into system prompt

The agent uses the Qwen2.5-14B model configured via Config.OLLAMA_MODEL.
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
You help investigators analyze forensic cases by querying events, looking up IOCs, and interpreting findings.

Current Case: {case_context.get('case_name', 'Unknown')}
Case ID: {case_context.get('case_id', 'Unknown')}
Description: {case_context.get('description', 'No description')[:300]}
Known Hosts: {hosts_str}
Time Zone: {case_context.get('timezone', 'UTC')}
{findings_block}{synthesis_block}

Guidelines:
- Be concise and forensically accurate
- Reference specific hosts, timestamps, and event IDs when possible
- If you need data, use the available tools rather than guessing
- Explain forensic significance of findings (what it means for the investigation)
- When listing events, format them clearly with timestamps and key fields
- If a question is ambiguous, use tools to gather data before answering
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


def _stream_ollama_chat(messages: List[Dict], tools: List[Dict] = None) -> Generator:
    """Stream response from Ollama /api/chat endpoint.
    
    Yields dicts with 'message' containing the delta.
    When a tool_call is present, yields the full tool_call object.
    
    Args:
        messages: Chat messages in Ollama format
        tools: Tool definitions (optional)
        
    Yields:
        Dict chunks from Ollama streaming response
    """
    url = f"{Config.OLLAMA_HOST}/api/chat"
    
    payload = {
        'model': Config.OLLAMA_MODEL,
        'messages': messages,
        'stream': True,
        'options': {
            'temperature': 0.3,
            'num_predict': 4096
        }
    }
    
    if tools:
        payload['tools'] = tools
    
    try:
        response = requests.post(
            url,
            json=payload,
            stream=True,
            timeout=CHAT_TIMEOUT
        )
        response.raise_for_status()
        
        for line in response.iter_lines():
            if not line:
                continue
            try:
                chunk = json.loads(line)
                yield chunk
            except json.JSONDecodeError:
                continue
                
    except requests.exceptions.Timeout:
        yield {"error": "LLM request timed out"}
    except requests.exceptions.ConnectionError:
        yield {"error": f"Cannot connect to Ollama at {Config.OLLAMA_HOST}"}
    except Exception as e:
        yield {"error": str(e)}


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
        
        # Stream from Ollama
        accumulated_content = ""
        tool_calls = []
        is_done = False
        had_error = False
        
        for chunk in _stream_ollama_chat(full_messages, TOOL_DEFINITIONS):
            # Check for errors
            if "error" in chunk:
                yield _sse_event("error", {"error": chunk["error"]})
                had_error = True
                break
            
            msg = chunk.get("message", {})
            
            # Check for tool calls
            if msg.get("tool_calls"):
                tool_calls.extend(msg["tool_calls"])
            
            # Stream text content
            content = msg.get("content", "")
            if content:
                accumulated_content += content
                yield _sse_event("token", {"content": content})
            
            # Check if done
            if chunk.get("done", False):
                is_done = True
                break
        
        if had_error:
            break
        
        # If we got tool calls, execute them and loop
        if tool_calls:
            # Signal tool execution phase
            yield _sse_event("tool_start", {
                "tools": [tc["function"]["name"] for tc in tool_calls]
            })
            
            # Add assistant message with tool calls to history
            assistant_msg = {"role": "assistant", "content": accumulated_content}
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            full_messages.append(assistant_msg)
            
            # Execute each tool call
            for tc in tool_calls:
                func_name = tc["function"]["name"]
                try:
                    func_args = tc["function"].get("arguments", {})
                    if isinstance(func_args, str):
                        func_args = json.loads(func_args)
                except (json.JSONDecodeError, TypeError):
                    func_args = {}
                
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
                    "content": json.dumps(result, default=str)
                })
            
            yield _sse_event("tool_end", {})
            
            # Continue loop — LLM will now see tool results
            continue
        
        # No tool calls — model gave a text response, we're done
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
    
    if "event_matches" in result:
        parts.append(f"{result['event_matches']} event matches")
    
    if "hosts" in result:
        hosts = list(result["hosts"].keys())[:3]
        if hosts:
            parts.append(f"Hosts: {', '.join(hosts)}")
    
    preview = ' | '.join(parts) if parts else json.dumps(result, default=str)
    return preview[:max_len]
