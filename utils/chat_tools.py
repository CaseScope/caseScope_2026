"""Chat Agent Tools for CaseScope

Thin wrappers around existing utility functions, exposed as
callable tools for the chat agent. Each tool takes structured
parameters and returns a dict result.

Tools:
- query_events: Search ClickHouse events with filters
- count_events: Quick COUNT for filtering questions
- get_findings: Get pattern matches, gap findings, chains
- lookup_ioc: Check IOC against case and OpenCTI
- get_host_profile: Get system behavioral profile + anomaly flags
- get_user_profile: Get user behavioral profile + anomaly flags

Design constraints:
- Max result size per tool call: ~2000 tokens of context
- All tools are read-only (no mutations except tag_event)
"""

import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from utils.clickhouse import get_fresh_client

logger = logging.getLogger(__name__)


# =============================================================================
# TOOL DEFINITIONS (JSON schema for LLM)
# =============================================================================

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "query_events",
            "description": "Search case events in ClickHouse with filters. Returns matching events with details. Use for questions like 'what happened on HOST-X' or 'show me 4624 events'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Filter by source_host (case-insensitive)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Filter by username (case-insensitive)"
                    },
                    "event_id": {
                        "type": "string",
                        "description": "Filter by Windows Event ID (e.g. '4624', '4625')"
                    },
                    "time_start": {
                        "type": "string",
                        "description": "Start time filter (ISO format or 'YYYY-MM-DD HH:MM')"
                    },
                    "time_end": {
                        "type": "string",
                        "description": "End time filter (ISO format or 'YYYY-MM-DD HH:MM')"
                    },
                    "search_text": {
                        "type": "string",
                        "description": "Free text search in event content"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by Hayabusa rule level: critical, high, medium, low"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results (default 25, max 50)"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "count_events",
            "description": "Quick event count with optional grouping. Use for questions like 'how many failed logins' or 'which hosts have the most events'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "event_id": {
                        "type": "string",
                        "description": "Filter by event ID"
                    },
                    "host": {
                        "type": "string",
                        "description": "Filter by host"
                    },
                    "username": {
                        "type": "string",
                        "description": "Filter by username"
                    },
                    "group_by": {
                        "type": "string",
                        "description": "Group results by: source_host, username, event_id, rule_level"
                    },
                    "time_start": {
                        "type": "string",
                        "description": "Start time filter"
                    },
                    "time_end": {
                        "type": "string",
                        "description": "End time filter"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings",
            "description": "Get detection findings for the case — pattern matches, gap findings, attack chains. Use for questions like 'what attacks were detected' or 'show me the findings'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity: critical, high, medium, low"
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by MITRE category"
                    },
                    "min_confidence": {
                        "type": "integer",
                        "description": "Minimum confidence score (0-100)"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_ioc",
            "description": "Look up an IOC value — check if it exists in the case, how many events match, and which hosts it appeared on. Use for questions like 'is this IP malicious' or 'where does 192.168.1.50 appear'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "The IOC value to look up (IP, hash, hostname, domain, etc.)"
                    }
                },
                "required": ["value"]
            }
        }
    }
]

# Map of tool name -> function
TOOL_REGISTRY = {}


def register_tool(name):
    """Decorator to register a tool function."""
    def decorator(func):
        TOOL_REGISTRY[name] = func
        return func
    return decorator


def execute_tool(name: str, case_id: int, params: Dict) -> Dict[str, Any]:
    """Execute a tool by name with given parameters.
    
    Args:
        name: Tool name
        case_id: Case ID for context
        params: Tool parameters
        
    Returns:
        Tool result dict
    """
    func = TOOL_REGISTRY.get(name)
    if not func:
        return {"error": f"Unknown tool: {name}"}
    
    try:
        return func(case_id=case_id, **params)
    except Exception as e:
        logger.error(f"[ChatTool] Tool '{name}' failed: {e}", exc_info=True)
        return {"error": f"Tool execution failed: {str(e)}"}


# =============================================================================
# TOOL IMPLEMENTATIONS
# =============================================================================

@register_tool("query_events")
def query_events(case_id: int, host: str = None, username: str = None,
                 event_id: str = None, time_start: str = None,
                 time_end: str = None, search_text: str = None,
                 severity: str = None, limit: int = 25, **kwargs) -> Dict:
    """Search events with filters."""
    client = get_fresh_client()
    
    limit = min(limit or 25, 50)
    
    where_parts = [
        f"case_id = {case_id}",
        "(noise_matched = false OR noise_matched IS NULL)"
    ]
    
    if host:
        escaped = host.replace("'", "\\'")
        where_parts.append(f"lower(source_host) = lower('{escaped}')")
    
    if username:
        escaped = username.replace("'", "\\'")
        where_parts.append(f"lower(username) = lower('{escaped}')")
    
    if event_id:
        escaped = event_id.replace("'", "\\'")
        where_parts.append(f"event_id = '{escaped}'")
    
    if severity:
        escaped = severity.lower().replace("'", "\\'")
        where_parts.append(f"rule_level = '{escaped}'")
    
    if time_start:
        escaped = time_start.replace("'", "\\'")
        where_parts.append(f"timestamp >= '{escaped}'")
    
    if time_end:
        escaped = time_end.replace("'", "\\'")
        where_parts.append(f"timestamp <= '{escaped}'")
    
    if search_text:
        escaped = search_text.replace("'", "\\'").replace("\\", "\\\\")
        where_parts.append(f"(lower(search_blob) LIKE '%{escaped.lower()}%')")
    
    query = f"""
        SELECT 
            timestamp,
            event_id,
            source_host,
            username,
            channel,
            rule_title,
            rule_level,
            process_name,
            command_line,
            toString(src_ip) as src_ip_str,
            toString(dst_ip) as dst_ip_str,
            logon_type,
            substring(search_blob, 1, 200) as summary
        FROM events
        WHERE {' AND '.join(where_parts)}
        ORDER BY timestamp ASC
        LIMIT {limit}
    """
    
    try:
        result = client.query(query)
    except Exception as e:
        return {"error": f"Query failed: {str(e)}"}
    
    events = []
    for row in result.result_rows:
        evt = {
            "timestamp": str(row[0]),
            "event_id": row[1] or "",
            "host": row[2] or "",
            "user": row[3] or "",
            "channel": row[4] or "",
            "rule": row[5] or "",
            "level": row[6] or "",
            "process": row[7] or "",
        }
        if row[8]:
            evt["cmdline"] = row[8][:150]
        if row[9] and row[9] != '0.0.0.0':
            evt["src_ip"] = row[9]
        if row[10] and row[10] != '0.0.0.0':
            evt["dst_ip"] = row[10]
        if row[11]:
            evt["logon_type"] = row[11]
        events.append(evt)
    
    return {
        "event_count": len(events),
        "events": events,
        "query_filters": {
            k: v for k, v in {
                "host": host, "username": username, "event_id": event_id,
                "severity": severity, "time_start": time_start,
                "time_end": time_end, "search_text": search_text
            }.items() if v
        }
    }


@register_tool("count_events")
def count_events(case_id: int, event_id: str = None, host: str = None,
                 username: str = None, group_by: str = None,
                 time_start: str = None, time_end: str = None,
                 **kwargs) -> Dict:
    """Quick event count with optional grouping."""
    client = get_fresh_client()
    
    where_parts = [
        f"case_id = {case_id}",
        "(noise_matched = false OR noise_matched IS NULL)"
    ]
    
    if event_id:
        where_parts.append(f"event_id = '{event_id.replace(chr(39), '')}'")
    if host:
        where_parts.append(f"lower(source_host) = lower('{host.replace(chr(39), '')}')")
    if username:
        where_parts.append(f"lower(username) = lower('{username.replace(chr(39), '')}')")
    if time_start:
        where_parts.append(f"timestamp >= '{time_start.replace(chr(39), '')}'")
    if time_end:
        where_parts.append(f"timestamp <= '{time_end.replace(chr(39), '')}'")
    
    allowed_groups = {'source_host', 'username', 'event_id', 'rule_level', 
                      'channel', 'artifact_type'}
    
    if group_by and group_by in allowed_groups:
        query = f"""
            SELECT {group_by}, count() as cnt
            FROM events
            WHERE {' AND '.join(where_parts)}
            GROUP BY {group_by}
            ORDER BY cnt DESC
            LIMIT 30
        """
        
        try:
            result = client.query(query)
        except Exception as e:
            return {"error": str(e)}
        
        groups = [{"value": str(row[0] or "(empty)"), "count": row[1]} 
                  for row in result.result_rows]
        total = sum(g["count"] for g in groups)
        
        return {"total": total, "grouped_by": group_by, "groups": groups}
    else:
        query = f"""
            SELECT count() FROM events
            WHERE {' AND '.join(where_parts)}
        """
        
        try:
            result = client.query(query)
            count = result.result_rows[0][0] if result.result_rows else 0
        except Exception as e:
            return {"error": str(e)}
        
        return {"total": count}


@register_tool("get_findings")
def get_findings(case_id: int, severity: str = None, category: str = None,
                 min_confidence: int = 0, **kwargs) -> Dict:
    """Get unified findings from all detection systems."""
    from utils.unified_findings import get_unified_findings
    
    result = get_unified_findings(
        case_id=case_id,
        min_confidence=min_confidence or 0,
        severity=severity,
        category=category,
        limit=20
    )
    
    # Slim down for context window
    slim_findings = []
    for f in result.get('findings', []):
        slim = {
            "pattern": f.get('pattern_name', ''),
            "category": f.get('category', ''),
            "severity": f.get('severity', ''),
            "confidence": f.get('confidence', 0),
            "source": f.get('source_label', ''),
            "host": f.get('source_host', ''),
            "events": f.get('event_count', 0),
        }
        if f.get('first_seen'):
            slim["first_seen"] = f['first_seen']
        if f.get('reasoning'):
            slim["reasoning"] = f['reasoning'][:200]
        slim_findings.append(slim)
    
    return {
        "findings": slim_findings,
        "summary": result.get('summary', {})
    }


@register_tool("lookup_ioc")
def lookup_ioc(case_id: int, value: str, **kwargs) -> Dict:
    """Look up an IOC value in the case."""
    from models.ioc import IOC
    from utils.ioc_artifact_tagger import search_artifacts_for_ioc
    from models.ioc import detect_ioc_type_from_value
    
    if not value:
        return {"error": "IOC value required"}
    
    value = value.strip()
    
    # Auto-detect IOC type
    ioc_type = detect_ioc_type_from_value(value)
    
    # Check if it's a known IOC in the case
    known_iocs = IOC.query.filter_by(case_id=case_id).filter(
        IOC.value_normalized.ilike(f"%{value}%")
    ).limit(5).all()
    
    known = []
    for ioc in known_iocs:
        known.append({
            "value": ioc.value,
            "type": ioc.ioc_type,
            "category": ioc.category,
            "created_by": ioc.created_by,
            "created_at": ioc.created_at.isoformat() if ioc.created_at else None
        })
    
    # Search for event matches
    artifact_result = search_artifacts_for_ioc(
        case_id=case_id,
        ioc_value=value,
        ioc_type=ioc_type
    )
    
    # Get host breakdown if there are matches
    host_breakdown = {}
    if artifact_result.get('match_count', 0) > 0:
        client = get_fresh_client()
        try:
            escaped = value.replace("'", "\\'").replace("\\", "\\\\")
            host_query = f"""
                SELECT source_host, count() as cnt
                FROM events
                WHERE case_id = {case_id}
                  AND lower(search_blob) LIKE '%{escaped.lower()}%'
                GROUP BY source_host
                ORDER BY cnt DESC
                LIMIT 10
            """
            result = client.query(host_query)
            host_breakdown = {row[0]: row[1] for row in result.result_rows if row[0]}
        except Exception:
            pass
    
    return {
        "value": value,
        "detected_type": ioc_type,
        "known_in_case": len(known) > 0,
        "known_iocs": known,
        "event_matches": artifact_result.get('match_count', 0),
        "earliest_seen": str(artifact_result.get('earliest', '')) if artifact_result.get('earliest') else None,
        "latest_seen": str(artifact_result.get('latest', '')) if artifact_result.get('latest') else None,
        "artifact_types": artifact_result.get('artifact_types', {}),
        "hosts": host_breakdown
    }
