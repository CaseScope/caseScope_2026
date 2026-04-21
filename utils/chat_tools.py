"""Chat Agent Tools for CaseScope

Thin wrappers around existing utility functions, exposed as
callable tools for the chat agent. Each tool takes structured
parameters and returns a dict result.

Tools:
- query_events: Search ClickHouse events with filters
- count_events: Quick COUNT for filtering questions
- search_artifacts: Search forensic artifacts across normalized evidence
- get_browser_downloads: Search browser download artifacts, including IOC-tagged files
- get_processes: Retrieve processes across event and memory sources
- get_process_tree: Reconstruct parent/child process relationships
- search_memory: Search memory-derived processes, services, paths, and suspicious regions
- search_network_logs: Search indexed PCAP/Zeek network logs
- get_findings: Get pattern matches, gap findings, chains
- lookup_ioc: Check IOC against case and OpenCTI

Design constraints:
- Max result size per tool call: ~2000 tokens of context
- All tools are read-only (no mutations except tag_event)
"""

import logging
from typing import Dict, List, Any, Optional

from models.database import db
from utils.clickhouse import get_fresh_client
from utils.event_noise_state import build_effective_not_noise_clause, ensure_event_noise_state_tables
from utils.forensic_chat_sources import (
    get_browser_download_rows,
    get_unified_process_list,
    get_unified_process_tree,
    search_artifacts as search_case_artifacts,
    search_memory_artifacts,
    search_network_logs_for_case,
)
from utils.provenance import (
    apply_record_provenance,
    annotate_artifact_records,
    attach_payload_provenance,
    build_record_provenance_summary,
    max_provenance,
    normalize_provenance,
)

logger = logging.getLogger(__name__)

RULE_LEVEL_ALIASES = {
    'critical': 'critical',
    'crit': 'critical',
    'high': 'high',
    'medium': 'medium',
    'med': 'medium',
    'low': 'low',
    'informational': 'informational',
    'info': 'informational',
}

COUNT_GROUP_ALIASES = {
    'host': 'source_host',
    'hostname': 'source_host',
    'user': 'username',
    'source_ip': 'src_ip',
    'destination_ip': 'dst_ip',
    'dest_ip': 'dst_ip',
    'workstation': 'workstation_name',
}


def _constant_provenance_summary(provenance: str = 'SYSTEM_DERIVED', record_count: int = 1) -> Dict[str, Any]:
    normalized = normalize_provenance(provenance, default='SYSTEM_DERIVED')
    if record_count <= 0:
        return {
            'record_count': 0,
            'highest_provenance': normalized,
            'counts': {},
        }
    return {
        'record_count': record_count,
        'highest_provenance': normalized,
        'counts': {normalized: record_count},
    }


def _mark_record_provenance(
    record: Dict[str, Any],
    field_values: Dict[str, str],
    *,
    default: str = 'SYSTEM_DERIVED',
) -> Dict[str, Any]:
    field_provenance = record.setdefault('field_provenance', {})
    field_provenance.update({
        field_name: normalize_provenance(provenance, default=default)
        for field_name, provenance in field_values.items()
    })
    record['emitted_provenance'] = max_provenance(
        field_provenance.values(),
        default=default,
    )
    return record


def _normalize_rule_level(level: Optional[str]) -> Optional[str]:
    if not level:
        return None
    return RULE_LEVEL_ALIASES.get(level.strip().lower())


def _normalize_group_by(group_by: Optional[str]) -> Optional[str]:
    if not group_by:
        return None
    cleaned = group_by.strip()
    if not cleaned:
        return None
    return COUNT_GROUP_ALIASES.get(cleaned.lower(), cleaned)


def _ip_source_match_clause(field_name: str = 'value') -> str:
    """Match an IP against normalized and source-side logon fields."""
    return (
        f"(toString(src_ip) = {{{field_name}:String}} "
        f"OR JSONExtractString(JSONExtractString(raw_json, 'EventData'), 'IpAddress') = {{{field_name}:String}} "
        f"OR lower(remote_host) = lower({{{field_name}:String}}))"
    )


# =============================================================================
# TOOL DEFINITIONS (JSON schema for LLM)
# =============================================================================

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "query_events",
            "description": "Retrieve real event rows from the case with filters. Use this whenever the user asks for evidence, timestamps, usernames, hosts, failed logons, or specific Event IDs. Prefer this over guessing or summarizing from memory.",
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
            "description": "Count matching case events with optional grouping. Use for questions like 'how many failed logins', 'group 4625 events by host', or 'which users have the most failures'. Prefer this before making claims about totals or distributions.",
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
                        "description": "Group results by: source_host, username, event_id, rule_level, channel, artifact_type, src_ip, dst_ip, remote_host, workstation_name, auth_package, logon_type"
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
            "name": "search_artifacts",
            "description": "Search case artifacts across the normalized evidence store when the question is about whether a file, URL, hash, path, hostname, registry key, or other value appears anywhere in the case. Use this when the artifact family is unclear or when you need a cross-artifact breakdown.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "Text or IOC value to search for"
                    },
                    "artifact_type": {
                        "type": "string",
                        "description": "Optional artifact type filter, or comma-separated list, such as browser_download, registry, prefetch, mft, lnk, or shellbags"
                    },
                    "host": {
                        "type": "string",
                        "description": "Optional host filter"
                    },
                    "username": {
                        "type": "string",
                        "description": "Optional username filter"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max examples to return (default 25, max 50)"
                    }
                },
                "required": ["search"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_browser_downloads",
            "description": "Retrieve browser download evidence from Chrome, Edge, and Firefox artifacts. Use this for questions about downloaded files, download paths, filenames, URLs, download users, hosts, or IOC-flagged downloads.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "Free-text filter across filename, path, URL, username, and host"
                    },
                    "filename": {
                        "type": "string",
                        "description": "Filter by downloaded filename"
                    },
                    "url": {
                        "type": "string",
                        "description": "Filter by source URL"
                    },
                    "host": {
                        "type": "string",
                        "description": "Filter by source host"
                    },
                    "username": {
                        "type": "string",
                        "description": "Filter by username"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max downloads to return (default 25, max 50)"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_processes",
            "description": "Retrieve process evidence across normalized events and memory analysis. Use this for questions about process names, command lines, parent/child execution, or whether a process existed in the case.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "Process name, command line fragment, or path fragment"
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Filter by host"
                    },
                    "source": {
                        "type": "string",
                        "enum": ["all", "events", "memory"],
                        "description": "Restrict to event data, memory data, or both"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max processes to return (default 25, max 50)"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_process_tree",
            "description": "Reconstruct a process tree for a specific host and PID across events and memory. Use this when the user asks about parent-child relationships, spawned processes, or process lineage.",
            "parameters": {
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Host that the process belongs to"
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to inspect"
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Optional process name hint for event-backed lookups"
                    },
                    "include_parent": {
                        "type": "boolean",
                        "description": "Include the parent chain when available"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum parent/child traversal depth (default 4, max 8)"
                    }
                },
                "required": ["hostname", "pid"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_memory",
            "description": "Search memory-derived artifacts such as processes, services, paths, modules, credentials, network connections, or malfind results. Use this for memory-only evidence or when the user asks about what was present in RAM.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "Text, process name, path, IP, username, hash, or other memory search term"
                    },
                    "search_type": {
                        "type": "string",
                        "enum": ["process", "network", "service", "path", "module", "credential", "malfind"],
                        "description": "Memory artifact family to search"
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Optional hostname filter"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max rows to return (default 25, max 50)"
                    }
                },
                "required": ["search"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_network_logs",
            "description": "Search indexed PCAP/Zeek logs for network evidence. Use this for DNS, HTTP, SSL, file-transfer, or generic network hunting questions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "Free-text search across indexed network logs"
                    },
                    "log_type": {
                        "type": "string",
                        "enum": ["conn", "dns", "http", "ssl", "files", "smtp", "ftp", "ssh", "dhcp", "ntp", "rdp", "smb", "dce_rpc", "kerberos", "ntlm"],
                        "description": "Optional Zeek log type"
                    },
                    "src_ip": {
                        "type": "string",
                        "description": "Optional source IP filter"
                    },
                    "dst_ip": {
                        "type": "string",
                        "description": "Optional destination IP filter"
                    },
                    "pcap_id": {
                        "type": "integer",
                        "description": "Optional PCAP file ID filter"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max logs to return (default 25, max 100)"
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
            "description": "Look up an IOC value — check if it exists in the case, how many events match, and which hosts it appeared on. For IP addresses, also return source-side logon context such as remote workstations, remote hosts, and successful users when present in case evidence.",
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
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_threat_intel",
            "description": "Query OpenCTI threat intelligence. Look up a MITRE technique ID, IOC value, or threat actor name. Use for questions like 'what groups use T1003?' or 'is this IP in our threat intel?' or 'tell me about APT29'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query_type": {
                        "type": "string",
                        "enum": ["technique", "ioc", "actor"],
                        "description": "What to look up: technique (MITRE ID), ioc (IP/hash/domain), or actor (threat group name)"
                    },
                    "value": {
                        "type": "string",
                        "description": "The technique ID (e.g. T1003), IOC value (IP/hash/domain), or actor name"
                    }
                },
                "required": ["query_type", "value"]
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
        try:
            db.session.rollback()
        except Exception:
            pass
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
    ensure_event_noise_state_tables(client)
    
    limit = min(limit or 25, 50)
    params = {'case_id': int(case_id)}
    
    where_parts = [
        "e.case_id = {case_id:UInt32}",
        build_effective_not_noise_clause(alias='e', case_id_sql='e.case_id'),
    ]
    
    if host:
        params['host'] = host
        where_parts.append("lower(e.source_host) = lower({host:String})")
    
    if username:
        params['username'] = username
        where_parts.append("lower(e.username) = lower({username:String})")
    
    if event_id:
        params['event_id'] = event_id
        where_parts.append("e.event_id = {event_id:String}")
    
    if severity:
        normalized_severity = _normalize_rule_level(severity)
        if not normalized_severity:
            return {"error": f"Invalid severity filter: {severity}"}
        params['severity'] = normalized_severity
        where_parts.append("lower(e.rule_level) = {severity:String}")
    
    if time_start:
        params['time_start'] = time_start
        where_parts.append("e.timestamp >= parseDateTimeBestEffort({time_start:String})")
    
    if time_end:
        params['time_end'] = time_end
        where_parts.append("e.timestamp <= parseDateTimeBestEffort({time_end:String})")
    
    if search_text:
        params['search_text'] = search_text
        where_parts.append("positionCaseInsensitive(e.search_blob, {search_text:String}) > 0")
    
    query = f"""
        SELECT 
            e.timestamp,
            e.artifact_type,
            e.event_id,
            e.source_host,
            e.username,
            e.channel,
            e.rule_title,
            e.rule_level,
            e.process_name,
            e.command_line,
            toString(e.src_ip) as src_ip_str,
            toString(e.dst_ip) as dst_ip_str,
            e.logon_type,
            e.remote_host,
            e.workstation_name,
            e.auth_package,
            e.logon_process,
            e.extra_fields,
            substring(e.search_blob, 1, 200) as summary
        FROM events AS e
        WHERE {' AND '.join(where_parts)}
        ORDER BY e.timestamp ASC
        LIMIT {limit}
    """
    
    try:
        result = client.query(query, parameters=params)
    except Exception as e:
        return {"error": f"Query failed: {str(e)}"}
    
    events = []
    for row in result.result_rows:
        if len(row) >= 19:
            (
                timestamp,
                artifact_type,
                event_id_value,
                host_value,
                user_value,
                channel_value,
                rule_value,
                level_value,
                process_value,
                cmdline_value,
                src_ip_value,
                dst_ip_value,
                logon_type_value,
                remote_host_value,
                workstation_value,
                auth_package_value,
                logon_process_value,
                extra_fields_value,
                summary_value,
            ) = row[:19]
        else:
            (
                timestamp,
                event_id_value,
                host_value,
                user_value,
                channel_value,
                rule_value,
                level_value,
                process_value,
                cmdline_value,
                src_ip_value,
                dst_ip_value,
                logon_type_value,
                remote_host_value,
                workstation_value,
                auth_package_value,
                logon_process_value,
                summary_value,
            ) = row
            artifact_type = ''
            extra_fields_value = {}
        evt = {
            "timestamp": str(timestamp),
            "_artifact_type": artifact_type or "",
            "event_id": event_id_value or "",
            "host": host_value or "",
            "user": user_value or "",
            "channel": channel_value or "",
            "rule": rule_value or "",
            "level": level_value or "",
            "process": process_value or "",
        }
        if cmdline_value:
            evt["cmdline"] = cmdline_value[:150]
        if src_ip_value and src_ip_value != '0.0.0.0':
            evt["src_ip"] = src_ip_value
        if dst_ip_value and dst_ip_value != '0.0.0.0':
            evt["dst_ip"] = dst_ip_value
        if logon_type_value:
            evt["logon_type"] = logon_type_value
        if remote_host_value:
            evt["remote_host"] = remote_host_value
        if workstation_value:
            evt["workstation_name"] = workstation_value
        if auth_package_value:
            evt["auth_package"] = auth_package_value
        if logon_process_value:
            evt["logon_process"] = logon_process_value
        apply_record_provenance(evt, extra_fields_value)
        if summary_value:
            evt["summary"] = summary_value
        events.append(evt)

    annotate_artifact_records(
        events,
        artifact_type_key="_artifact_type",
        fields=[
            "timestamp",
            "event_id",
            "host",
            "user",
            "channel",
            "rule",
            "level",
            "process",
            "cmdline",
            "src_ip",
            "dst_ip",
            "logon_type",
            "remote_host",
            "workstation_name",
            "auth_package",
            "logon_process",
            "summary",
        ],
    )
    provenance_summary = build_record_provenance_summary(events)

    return attach_payload_provenance({
        "event_count": len(events),
        "events": events,
        "query_filters": {
            k: v for k, v in {
                "host": host, "username": username, "event_id": event_id,
                "severity": severity, "time_start": time_start,
                "time_end": time_end, "search_text": search_text
            }.items() if v
        }
    }, summary=provenance_summary)


@register_tool("count_events")
def count_events(case_id: int, event_id: str = None, host: str = None,
                 username: str = None, group_by: str = None,
                 time_start: str = None, time_end: str = None,
                 **kwargs) -> Dict:
    """Quick event count with optional grouping."""
    client = get_fresh_client()
    ensure_event_noise_state_tables(client)
    params = {'case_id': int(case_id)}
    
    where_parts = [
        "e.case_id = {case_id:UInt32}",
        build_effective_not_noise_clause(alias='e', case_id_sql='e.case_id'),
    ]
    
    if event_id:
        params['event_id'] = event_id
        where_parts.append("e.event_id = {event_id:String}")
    if host:
        params['host'] = host
        where_parts.append("lower(e.source_host) = lower({host:String})")
    if username:
        params['username'] = username
        where_parts.append("lower(e.username) = lower({username:String})")
    if time_start:
        params['time_start'] = time_start
        where_parts.append("e.timestamp >= parseDateTimeBestEffort({time_start:String})")
    if time_end:
        params['time_end'] = time_end
        where_parts.append("e.timestamp <= parseDateTimeBestEffort({time_end:String})")
    
    allowed_groups = {
        'source_host', 'username', 'event_id', 'rule_level', 'channel',
        'artifact_type', 'src_ip', 'dst_ip', 'remote_host',
        'workstation_name', 'auth_package', 'logon_type',
    }
    normalized_group_by = _normalize_group_by(group_by)
    
    if normalized_group_by and normalized_group_by in allowed_groups:
        query = f"""
            SELECT {normalized_group_by}, count() as cnt
            FROM events AS e
            WHERE {' AND '.join(where_parts)}
            GROUP BY {normalized_group_by}
            ORDER BY cnt DESC
            LIMIT 30
        """
        
        try:
            result = client.query(query, parameters=params)
        except Exception as e:
            return {"error": str(e)}
        
        groups = [{"value": str(row[0] or "(empty)"), "count": row[1]} 
                  for row in result.result_rows]
        total = sum(g["count"] for g in groups)

        annotate_artifact_records(groups, fields=["value", "count"])
        provenance_summary = build_record_provenance_summary(groups)

        return attach_payload_provenance(
            {"total": total, "grouped_by": normalized_group_by, "groups": groups},
            summary=provenance_summary,
        )
    else:
        query = f"""
            SELECT count() FROM events AS e
            WHERE {' AND '.join(where_parts)}
        """
        
        try:
            result = client.query(query, parameters=params)
            count = result.result_rows[0][0] if result.result_rows else 0
        except Exception as e:
            return {"error": str(e)}

        return attach_payload_provenance(
            {"total": count},
            summary=_constant_provenance_summary(),
        )


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

    annotate_artifact_records(
        slim_findings,
        fields=[
            "pattern",
            "category",
            "severity",
            "confidence",
            "source",
            "host",
            "events",
            "first_seen",
            "reasoning",
        ],
    )
    for finding in slim_findings:
        field_provenance = finding.setdefault('field_provenance', {})
        if finding.get('reasoning'):
            field_provenance['reasoning'] = 'MODEL_SYNTHESIZED'
            finding['emitted_provenance'] = max_provenance(
                field_provenance.values(),
                default='SYSTEM_DERIVED',
            )
    provenance_summary = build_record_provenance_summary(slim_findings)

    return attach_payload_provenance({
        "findings": slim_findings,
        "summary": result.get('summary', {})
    }, summary=provenance_summary)


@register_tool("search_artifacts")
def search_artifacts(case_id: int, search: str, artifact_type: str = None,
                     host: str = None, username: str = None,
                     limit: int = 25, **kwargs) -> Dict:
    """Search normalized case artifacts for a value."""
    return search_case_artifacts(
        case_id,
        search=search,
        artifact_type=artifact_type or '',
        host=host or '',
        username=username or '',
        limit=limit or 25,
    )


@register_tool("get_browser_downloads")
def get_browser_downloads(case_id: int, search: str = None, filename: str = None,
                          url: str = None, host: str = None,
                          username: str = None, limit: int = 25,
                          **kwargs) -> Dict:
    """Search browser download artifacts."""
    result = get_browser_download_rows(
        case_id,
        host=host or '',
        username=username or '',
        filename=filename or '',
        url=url or '',
        search=search or '',
        limit=limit or 25,
    )
    return {
        **result,
        "filters": {
            key: value for key, value in {
                "search": search,
                "filename": filename,
                "url": url,
                "host": host,
                "username": username,
            }.items() if value
        },
    }


@register_tool("get_processes")
def get_processes(case_id: int, search: str = None, hostname: str = None,
                  source: str = 'all', limit: int = 25, **kwargs) -> Dict:
    """Return unified process evidence from events and memory."""
    return get_unified_process_list(
        case_id,
        search=search or '',
        hostname=hostname or '',
        source=source or 'all',
        limit=limit or 25,
    )


@register_tool("get_process_tree")
def get_process_tree(case_id: int, hostname: str, pid: int,
                     process_name: str = None, include_parent: bool = True,
                     max_depth: int = 4, **kwargs) -> Dict:
    """Return a process tree for a host/PID."""
    return get_unified_process_tree(
        case_id,
        hostname=hostname,
        pid=int(pid),
        process_name=process_name or '',
        include_parent=bool(include_parent),
        max_depth=max_depth or 4,
    )


@register_tool("search_memory")
def search_memory(case_id: int, search: str, search_type: str = 'process',
                  hostname: str = None, limit: int = 25, **kwargs) -> Dict:
    """Search memory-derived artifacts."""
    return search_memory_artifacts(
        case_id,
        search=search,
        search_type=search_type or 'process',
        hostname=hostname or '',
        limit=limit or 25,
    )


@register_tool("search_network_logs")
def search_network_logs(case_id: int, search: str = None, log_type: str = None,
                        src_ip: str = None, dst_ip: str = None,
                        pcap_id: int = None, limit: int = 25,
                        **kwargs) -> Dict:
    """Search indexed network logs."""
    return search_network_logs_for_case(
        case_id,
        search=search or '',
        log_type=log_type or '',
        pcap_id=pcap_id,
        src_ip=src_ip or '',
        dst_ip=dst_ip or '',
        limit=limit or 25,
    )


@register_tool("lookup_ioc")
def lookup_ioc(case_id: int, value: str, **kwargs) -> Dict:
    """Look up an IOC value in the case."""
    from models.ioc import IOC
    from utils.ioc_artifact_tagger import search_artifacts_for_ioc, build_ioc_match_clause
    from models.ioc import detect_ioc_type_from_value, detect_match_type
    
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
    annotate_artifact_records(
        known,
        fields=["value", "type", "category", "created_by", "created_at"],
    )
    for record in known:
        _mark_record_provenance(
            record,
            {
                "value": "ANALYST",
                "type": "ANALYST",
                "category": "ANALYST",
                "created_by": "SYSTEM_DERIVED",
                "created_at": "SYSTEM_DERIVED",
            },
            default='ANALYST',
        )
    
    # Search for event matches
    artifact_result = search_artifacts_for_ioc(
        case_id=case_id,
        ioc_value=value,
        ioc_type=ioc_type
    )
    
    # Get host breakdown if there are matches
    host_breakdown = {}
    ip_logon_context = {}
    if artifact_result.get('match_count', 0) > 0:
        client = get_fresh_client()
        try:
            effective_match_type = detect_match_type(value, ioc_type)
            where_clause = build_ioc_match_clause(value, ioc_type, effective_match_type)
            host_query = f"""
                SELECT source_host, count() as cnt
                FROM events
                WHERE case_id = {int(case_id)}
                  AND ({where_clause})
                GROUP BY source_host
                ORDER BY cnt DESC
                LIMIT 10
            """
            result = client.query(host_query)
            host_breakdown = {row[0]: row[1] for row in result.result_rows if row[0]}
        except Exception:
            pass

        if ioc_type in ('IP Address (IPv4)', 'IP Address (IPv6)'):
            try:
                source_context_query = f"""
                    SELECT
                        username,
                        source_host,
                        logon_type,
                        workstation_name,
                        remote_host,
                        count() as cnt,
                        min(timestamp) as first_seen,
                        max(timestamp) as last_seen
                    FROM events
                    WHERE case_id = {{case_id:UInt32}}
                      AND channel = 'Security'
                      AND event_id = '4624'
                      AND {_ip_source_match_clause('value')}
                    GROUP BY username, source_host, logon_type, workstation_name, remote_host
                    ORDER BY last_seen DESC, cnt DESC
                    LIMIT 100
                """
                source_result = client.query(
                    source_context_query,
                    parameters={'case_id': int(case_id), 'value': value}
                )

                successful_logons = []
                successful_users = {}
                target_hosts = {}
                workstation_breakdown = {}
                remote_host_breakdown = {}

                for row in source_result.result_rows:
                    username_val, target_host, logon_type, workstation_name, remote_host, count, first_seen, last_seen = row
                    username_clean = (username_val or '').strip()
                    target_host_clean = (target_host or '').strip()
                    workstation_clean = (workstation_name or '').strip()
                    remote_host_clean = (remote_host or '').strip()

                    if username_clean:
                        successful_users[username_clean] = successful_users.get(username_clean, 0) + count
                    if target_host_clean:
                        target_hosts[target_host_clean] = target_hosts.get(target_host_clean, 0) + count
                    if workstation_clean and workstation_clean != '-':
                        workstation_breakdown[workstation_clean] = workstation_breakdown.get(workstation_clean, 0) + count
                    if remote_host_clean and remote_host_clean not in ('-', value):
                        remote_host_breakdown[remote_host_clean] = remote_host_breakdown.get(remote_host_clean, 0) + count

                    successful_logons.append({
                        "user": username_clean,
                        "target_host": target_host_clean,
                        "logon_type": logon_type,
                        "workstation_name": workstation_clean,
                        "remote_host": remote_host_clean,
                        "count": count,
                        "first_seen": str(first_seen) if first_seen else None,
                        "last_seen": str(last_seen) if last_seen else None,
                    })

                ip_logon_context = {
                    "successful_users": successful_users,
                    "target_hosts": target_hosts,
                    "source_workstations": workstation_breakdown,
                    "source_remote_hosts": remote_host_breakdown,
                    "successful_logons": successful_logons[:25],
                }
            except Exception:
                pass

    matched_host_records = [{"host": host_name, "count": count} for host_name, count in host_breakdown.items()]
    annotate_artifact_records(matched_host_records, fields=["host", "count"])

    successful_logons = ip_logon_context.get("successful_logons", [])
    annotate_artifact_records(
        successful_logons,
        fields=[
            "user",
            "target_host",
            "logon_type",
            "workstation_name",
            "remote_host",
            "count",
            "first_seen",
            "last_seen",
        ],
    )
    
    # Threat-intel enrichment
    opencti_intel = {}
    try:
        from utils.feature_availability import FeatureAvailability
        from utils.opencti import lookup_threat_intel
        if FeatureAvailability.is_ioc_threat_intel_enrichment_enabled():
            enrichment = lookup_threat_intel(value, ioc_type or 'Unknown')
            if enrichment and enrichment.get('found'):
                opencti_intel = {
                    "found": True,
                    "score": enrichment.get('score'),
                    "labels": enrichment.get('labels', []),
                    "description": (enrichment.get('description') or '')[:200],
                    "match_category": enrichment.get('match_category'),
                    "providers_found": enrichment.get('providers_found', []),
                    "available_connectors": [
                        connector.get('name')
                        for connector in enrichment.get('available_connectors', [])[:5]
                        if connector.get('name')
                    ],
                }
    except Exception as e:
        logger.debug(f"[lookup_ioc] OpenCTI enrichment skipped: {e}")

    payload = {
        "value": value,
        "detected_type": ioc_type,
        "known_in_case": len(known) > 0,
        "known_iocs": known,
        "event_matches": artifact_result.get('match_count', 0),
        "earliest_seen": str(artifact_result.get('earliest', '')) if artifact_result.get('earliest') else None,
        "latest_seen": str(artifact_result.get('latest', '')) if artifact_result.get('latest') else None,
        "artifact_types": artifact_result.get('artifact_types', {}),
        "matched_hosts": host_breakdown,
        "hosts": host_breakdown,
        "ip_logon_context": ip_logon_context,
        "opencti": opencti_intel
    }

    summary_records: List[Dict[str, Any]] = []
    summary_records.extend(known)
    summary_records.extend(matched_host_records)
    summary_records.extend(successful_logons)
    if opencti_intel:
        summary_records.append({"emitted_provenance": "ELEVATED_RISK"})
    elif artifact_result.get('match_count', 0) > 0:
        summary_records.append({"emitted_provenance": "SYSTEM_DERIVED"})

    summary = (
        build_record_provenance_summary(summary_records)
        if summary_records else
        _constant_provenance_summary()
    )
    return attach_payload_provenance(payload, summary=summary)


@register_tool("lookup_threat_intel")
def lookup_threat_intel(case_id: int, query_type: str, value: str, **kwargs) -> Dict:
    """Query OpenCTI threat intelligence for a technique, IOC, or actor."""
    from utils.opencti_context import OpenCTIContextProvider
    
    if not value:
        return {"error": "value is required"}
    
    provider = OpenCTIContextProvider(case_id)
    if not provider.is_available():
        return {"error": "OpenCTI is not configured or unavailable"}
    
    value = value.strip()
    
    if query_type == "technique":
        ctx = provider.get_attack_pattern_context(value)
        if not ctx.get('technique_name'):
            return attach_payload_provenance(
                {"found": False, "value": value},
                summary=_constant_provenance_summary(),
            )
        return attach_payload_provenance({
            "found": True,
            "technique": ctx['technique_name'],
            "mitre_id": value,
            "detection_guidance": (ctx.get('detection_guidance') or '')[:300],
            "threat_actors": [a['name'] for a in ctx.get('threat_actors', [])[:5]],
            "platforms": ctx.get('platforms', []),
        }, summary=_constant_provenance_summary('ELEVATED_RISK'))
    
    elif query_type == "ioc":
        result = provider.enrich_ioc(value, 'Unknown')
        if not result or not result.get('found'):
            return attach_payload_provenance(
                {"found": False, "value": value},
                summary=_constant_provenance_summary(),
            )
        return attach_payload_provenance({
            "found": True,
            "value": value,
            "score": result.get('score'),
            "labels": result.get('labels', []),
            "description": (result.get('description') or '')[:300],
            "match_category": result.get('match_category'),
            "providers_found": result.get('providers_found', []),
            "available_connectors": [
                connector.get('name')
                for connector in result.get('available_connectors', [])[:5]
                if connector.get('name')
            ],
            "references": [
                ref.get('source_name')
                for ref in result.get('external_references', [])[:5]
                if ref.get('source_name')
            ],
        }, summary=_constant_provenance_summary('ELEVATED_RISK'))
    
    elif query_type == "actor":
        actors = provider.search_threat_actors_by_name(value)
        matches = [
            a for a in (actors or [])
            if value.lower() in a.get('name', '').lower()
            or any(value.lower() in alias.lower() for alias in a.get('aliases', []))
        ]
        if not matches:
            return attach_payload_provenance(
                {"found": False, "value": value},
                summary=_constant_provenance_summary(),
            )
        actor = matches[0]
        return attach_payload_provenance({
            "found": True,
            "name": actor['name'],
            "aliases": actor.get('aliases', []),
            "techniques": [t['mitre_id'] for t in actor.get('attack_patterns', [])[:10]
                           if t.get('mitre_id')],
        }, summary=_constant_provenance_summary('ELEVATED_RISK'))
    
    return {"error": f"Unknown query_type: {query_type}. Use 'technique', 'ioc', or 'actor'."}
