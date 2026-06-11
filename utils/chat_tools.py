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
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from models.case import Case
from models.database import db
from utils.clickhouse import get_fresh_client
from utils.event_noise_state import build_effective_not_noise_clause, ensure_event_noise_state_tables
from utils.forensic_chat_sources import (
    build_case_insensitive_any_clause,
    build_event_corpus_coverage,
    get_browser_download_rows,
    get_unified_process_list,
    get_unified_process_tree,
    normalize_forensic_search_terms,
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
from utils.timezone import format_for_display, parse_time_window, to_utc

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


def _normalize_event_sort(sort: Optional[str]) -> tuple[str, str]:
    cleaned = (sort or 'asc').strip().lower()
    if cleaned in {'desc', 'latest', 'newest'}:
        return 'DESC', cleaned
    if cleaned in {'asc', 'earliest', 'oldest'}:
        return 'ASC', cleaned
    return 'ASC', 'asc'


def _case_timezone(case_id: int) -> str:
    try:
        case = Case.get_by_id(case_id)
        return getattr(case, 'timezone', None) or 'UTC'
    except Exception:
        return 'UTC'


def _format_clickhouse_datetime(value: Optional[datetime]) -> Optional[str]:
    return value.strftime('%Y-%m-%d %H:%M:%S') if value else None


def _chat_time_to_utc(value: Optional[str], case_id: int) -> Optional[str]:
    """Treat analyst-entered chat timestamps as case-local time."""
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    case_tz = _case_timezone(case_id)
    start_utc, _ = parse_time_window(raw, '', case_tz)
    if start_utc:
        return _format_clickhouse_datetime(start_utc)
    try:
        parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        return _format_clickhouse_datetime(to_utc(parsed, case_tz))
    except ValueError:
        return raw


def _display_case_time(value: Any, case_tz: str) -> str:
    if not value:
        return ""
    if isinstance(value, datetime):
        return format_for_display(value, case_tz)
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return format_for_display(parsed, case_tz)
    except Exception:
        return str(value)


def _query_rows(client, query: str, params: Dict[str, Any]) -> List[tuple]:
    result = client.query(query, parameters=params)
    return list(getattr(result, 'result_rows', []) or [])


def _clamp_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, minimum), maximum)


def _event_row_to_record(row: tuple, case_tz: str) -> Dict[str, Any]:
    fields = [
        "timestamp", "artifact_type", "event_id", "channel", "provider", "username",
        "process_name", "process_path", "parent_process", "command_line", "target_path",
        "file_hash_md5", "file_hash_sha1", "file_hash_sha256", "file_size", "rule_title",
        "mitre_attack_ids", "mitre_attack_tactics", "summary",
    ]
    record = {field: row[idx] if idx < len(row) else None for idx, field in enumerate(fields)}
    timestamp = record.get("timestamp")
    record["timestamp"] = str(timestamp) if timestamp is not None else ""
    record["case_time"] = _display_case_time(timestamp, case_tz)
    record["summary"] = (record.get("summary") or "")[:900]
    for key in ("command_line", "target_path", "process_path"):
        if record.get(key):
            record[key] = str(record[key])[:700]
    if record.get("file_size") is not None:
        try:
            record["file_size"] = int(record["file_size"])
        except (TypeError, ValueError):
            pass
    return record


def _infer_session_action(record: Dict[str, Any]) -> str:
    text = f"{record.get('summary', '')} {record.get('event_id', '')}".lower()
    if " disconnected" in text or "disconnected" in text or str(record.get("event_id")) == "101":
        return "disconnected"
    if " connected" in text or "connected" in text or str(record.get("event_id")) == "100":
        return "connected"
    return "observed"


def _build_session_windows(markers: List[Dict[str, Any]], lookback_minutes: int, lookahead_minutes: int) -> List[Dict[str, Any]]:
    windows: List[Dict[str, Any]] = []
    open_marker: Optional[Dict[str, Any]] = None
    for marker in markers:
        action = marker.get("action") or _infer_session_action(marker)
        marker["action"] = action
        if action == "connected":
            if open_marker:
                windows.append({"start_marker": open_marker, "end_marker": None, "status": "open_or_missing_disconnect"})
            open_marker = marker
        elif action == "disconnected":
            if open_marker:
                windows.append({"start_marker": open_marker, "end_marker": marker, "status": "closed"})
                open_marker = None
            else:
                windows.append({"start_marker": None, "end_marker": marker, "status": "disconnect_without_visible_connect"})
    if open_marker:
        windows.append({"start_marker": open_marker, "end_marker": None, "status": "open_or_missing_disconnect"})
    if not windows and markers:
        windows.append({"start_marker": markers[0], "end_marker": markers[-1], "status": "derived_from_observations"})

    for window in windows:
        start_value = (window.get("start_marker") or window.get("end_marker") or {}).get("timestamp")
        end_value = (window.get("end_marker") or window.get("start_marker") or {}).get("timestamp")
        try:
            start_dt = datetime.fromisoformat(str(start_value))
        except Exception:
            start_dt = None
        try:
            end_dt = datetime.fromisoformat(str(end_value))
        except Exception:
            end_dt = start_dt
        if start_dt and end_dt:
            window["analysis_start_utc"] = _format_clickhouse_datetime(start_dt - timedelta(minutes=lookback_minutes))
            window["analysis_end_utc"] = _format_clickhouse_datetime(end_dt + timedelta(minutes=lookahead_minutes))
            window["duration_seconds"] = max(0, int((end_dt - start_dt).total_seconds()))
    return windows


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
                    },
                    "sort": {
                        "type": "string",
                        "enum": ["asc", "desc", "earliest", "latest", "oldest", "newest"],
                        "description": "Timestamp sort order. Use asc/earliest/oldest for timelines, desc/latest/newest for latest activity. Default asc preserves timeline behavior."
                    },
                    "include_noise": {
                        "type": "boolean",
                        "description": "Include events tagged as noise. Explicit text searches include noise automatically so RMM/service evidence such as ScreenConnect is not hidden."
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
                        "description": "Filter by event ID. For Windows failed logons use 4625; successful logons use 4624."
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
                    },
                    "include_noise": {
                        "type": "boolean",
                        "description": "Include events tagged as noise (default false)"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_event_context",
            "description": "Return events around a timestamp on an optional host across artifact types. Use this for DFIR pivots like 'what else happened right then' after finding a suspicious event.",
            "parameters": {
                "type": "object",
                "properties": {
                    "timestamp": {
                        "type": "string",
                        "description": "Center timestamp for the context window (ISO format or 'YYYY-MM-DD HH:MM')"
                    },
                    "host": {
                        "type": "string",
                        "description": "Optional source_host filter for host-local context"
                    },
                    "window_minutes": {
                        "type": "integer",
                        "description": "Minutes before and after the timestamp to search (default 5, max 120)"
                    },
                    "event_id": {
                        "type": "string",
                        "description": "Optional anchor event ID to highlight within the returned context"
                    },
                    "search_text": {
                        "type": "string",
                        "description": "Optional text that identifies or highlights the anchor event"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max context events to return (default 50, max 200)"
                    },
                    "include_noise": {
                        "type": "boolean",
                        "description": "Include events tagged as noise in the context window (default true)"
                    }
                },
                "required": ["timestamp"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_case_coverage",
            "description": "Summarize what evidence exists for the case: event corpus time range, artifact types, hosts, memory jobs, and indexed PCAP/network logs. Use before making absence-of-evidence claims.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Optional host filter for host-specific coverage"
                    },
                    "include_breakdowns": {
                        "type": "boolean",
                        "description": "Include artifact and host count breakdowns (default true)"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_question",
            "description": "Run an agentic DFIR investigation for an open-ended forensic question. Use when the user asks what happened, what someone did, whether a hypothesis is supported, what activity followed an event, or asks for an analyst-style answer from all indexed evidence. The tool interprets entities and intent, chooses ClickHouse pivots across events/process/file/browser/registry/network/findings, and returns a structured evidence packet with attribution, negative checks, and caveats.",
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "The user's forensic question in plain English"
                    },
                    "host": {
                        "type": "string",
                        "description": "Optional host hint, e.g. ATN80575"
                    },
                    "user": {
                        "type": "string",
                        "description": "Optional user/session/account hint"
                    },
                    "focus_terms": {
                        "type": "string",
                        "description": "Optional analyst-provided terms or aliases to pivot on, e.g. PIN.exe / ScreenConnect / tabadmin"
                    },
                    "time_start": {
                        "type": "string",
                        "description": "Optional case-local start time to bound the investigation"
                    },
                    "time_end": {
                        "type": "string",
                        "description": "Optional case-local end time to bound the investigation"
                    },
                    "lookback_minutes": {
                        "type": "integer",
                        "description": "Minutes before discovered anchors to include for context (default 5, max 120)"
                    },
                    "lookahead_minutes": {
                        "type": "integer",
                        "description": "Minutes after discovered anchors to include for follow-on activity (default 30, max 240)"
                    },
                    "investigation_depth": {
                        "type": "string",
                        "enum": ["quick", "standard", "deep"],
                        "description": "How broadly to pivot across evidence families (default standard)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum examples per evidence section (default 25, max 80)"
                    }
                },
                "required": ["question"]
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
                    },
                    "include_noise": {
                        "type": "boolean",
                        "description": "Include artifacts/events tagged as noise. Defaults to true for explicit artifact searches so RMM/service evidence is not hidden."
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
                    "time_start": {
                        "type": "string",
                        "description": "Required reviewed network telemetry start time (ISO format or 'YYYY-MM-DD HH:MM')"
                    },
                    "time_end": {
                        "type": "string",
                        "description": "Required reviewed network telemetry end time (ISO format or 'YYYY-MM-DD HH:MM')"
                    },
                    "source_availability_status": {
                        "type": "string",
                        "enum": ["available", "partial", "not_available", "unknown"],
                        "description": "Required source availability metadata for the reviewed network telemetry"
                    },
                    "missing_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Missing telemetry sources that limit the search, such as firewall, proxy, VPN, or remote-access transfer logs"
                    },
                    "limitations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Visible limitations for partial, missing, or source-limited network telemetry"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max logs to return (default 25, max 100)"
                    }
                },
                "required": ["time_start", "time_end", "source_availability_status"]
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
            "name": "add_ioc",
            "description": "Add an IOC to the current case after analyst approval. Use when the analyst asks to add a suspicious IP, domain, URL, hash, filename, path, or command line to the case IOC list.",
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "IOC value to add"
                    },
                    "ioc_type": {
                        "type": "string",
                        "description": "Optional IOC type; auto-detected when omitted"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Analyst-visible reason or evidence summary for adding the IOC"
                    },
                    "malicious": {
                        "type": "boolean",
                        "description": "Whether to mark the IOC malicious immediately (default false)"
                    }
                },
                "required": ["value", "reason"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_finding",
            "description": "Save a draft evidence-backed finding to the hunt ledger after analyst approval. Use to preserve a chat conclusion as a workflow item instead of leaving it only in the transcript.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short finding title"
                    },
                    "classification": {
                        "type": "string",
                        "enum": ["suspicious", "malicious", "benign", "inconclusive", "needs_more_review"],
                        "description": "Finding classification"
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Evidence-backed rationale for the finding"
                    },
                    "confidence": {
                        "type": "integer",
                        "description": "Confidence score from 0 to 100"
                    },
                    "decision_scope": {
                        "type": "string",
                        "enum": ["case", "host", "user", "ioc", "artifact", "process", "service", "network"],
                        "description": "Scope of the finding (default case)"
                    },
                    "target_host": {"type": "string"},
                    "target_user": {"type": "string"},
                    "target_ioc": {"type": "string"},
                    "target_artifact_path": {"type": "string"},
                    "target_process": {"type": "string"},
                    "hunt_run_id": {
                        "type": "integer",
                        "description": "Optional existing hunt run to attach the draft finding to"
                    }
                },
                "required": ["title", "classification", "rationale"]
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
    },
    {
        "type": "function",
        "function": {
            "name": "run_forensic_subagent",
            "description": "Delegate a bounded forensic analysis task to a CaseScope specialist subagent. Use after gathering enough evidence or when the user asks for a timeline, IOC review, memory review, network review, pattern correlation, or report draft.",
            "parameters": {
                "type": "object",
                "properties": {
                    "subagent": {
                        "type": "string",
                        "enum": [
                            "timeline_analyst",
                            "ioc_reviewer",
                            "memory_forensics_analyst",
                            "network_analyst",
                            "pattern_correlator",
                            "report_drafter",
                            "hypothesis_challenger"
                        ],
                        "description": "Specialist subagent to run"
                    },
                    "task": {
                        "type": "string",
                        "description": "Specific bounded task for the subagent"
                    },
                    "evidence": {
                        "type": "object",
                        "description": "Optional evidence packet from prior tool results or user-selected context"
                    }
                },
                "required": ["subagent", "task"]
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
                 severity: str = None, limit: int = 25,
                 sort: str = None, include_noise: bool = False, **kwargs) -> Dict:
    """Search events with filters."""
    client = get_fresh_client()
    ensure_event_noise_state_tables(client)
    
    limit = min(limit or 25, 50)
    sort_direction, normalized_sort = _normalize_event_sort(sort)
    params = {'case_id': int(case_id)}
    search_terms = normalize_forensic_search_terms(search_text)
    
    effective_include_noise = bool(include_noise) or bool(search_text) or bool(username)
    where_parts = ["e.case_id = {case_id:UInt32}"]
    if not effective_include_noise:
        where_parts.append(build_effective_not_noise_clause(alias='e', case_id_sql='e.case_id'))
    
    if host:
        params['host'] = host
        where_parts.append("lower(e.source_host) = lower({host:String})")
    
    if username:
        params['username'] = username
        where_parts.append(
            "(lower(e.username) = lower({username:String}) OR positionCaseInsensitive(e.search_blob, {username:String}) > 0)"
        )
    
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
        params['time_start'] = _chat_time_to_utc(time_start, case_id) or time_start
        where_parts.append("e.timestamp >= parseDateTimeBestEffort({time_start:String})")
    
    if time_end:
        params['time_end'] = _chat_time_to_utc(time_end, case_id) or time_end
        where_parts.append("e.timestamp <= parseDateTimeBestEffort({time_end:String})")
    
    if search_terms:
        where_parts.append(build_case_insensitive_any_clause("e.search_blob", "search_text_term", search_terms, params))
    
    count_query = f"""
        SELECT count()
        FROM events AS e
        WHERE {' AND '.join(where_parts)}
    """

    try:
        count_result = client.query(count_query, parameters=params)
        total_matches = int(count_result.result_rows[0][0]) if count_result.result_rows else 0
    except Exception as e:
        return {"error": f"Count failed: {str(e)}"}

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
        ORDER BY e.timestamp {sort_direction}
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
    returned_count = len(events)
    result_metadata = {
        "total_matches": total_matches,
        "returned_count": returned_count,
        "limit": limit,
        "sort": normalized_sort,
        "truncated": total_matches > returned_count,
    }
    reviewed_filters = {
        k: v for k, v in {
            "host": host, "username": username, "event_id": event_id,
            "severity": severity, "time_start": time_start,
            "time_end": time_end, "search_text": search_text,
            "expanded_search_terms": search_terms,
            "sort": normalized_sort, "include_noise": effective_include_noise,
        }.items() if v
    }
    coverage = build_event_corpus_coverage(
        client,
        case_id,
        reviewed_filters=reviewed_filters,
        result_metadata=result_metadata,
    )

    return attach_payload_provenance({
        "event_count": returned_count,
        "total_matches": total_matches,
        "returned_count": returned_count,
        "truncated": total_matches > returned_count,
        "sort": normalized_sort,
        "noise_filter": "included" if effective_include_noise else "excluded",
        "expanded_search_terms": search_terms,
        "events": events,
        "query_filters": reviewed_filters,
        **coverage,
    }, summary=provenance_summary)


@register_tool("count_events")
def count_events(case_id: int, event_id: str = None, host: str = None,
                 username: str = None, group_by: str = None,
                 time_start: str = None, time_end: str = None,
                 include_noise: bool = False,
                 **kwargs) -> Dict:
    """Quick event count with optional grouping."""
    client = get_fresh_client()
    ensure_event_noise_state_tables(client)
    params = {'case_id': int(case_id)}
    
    effective_include_noise = bool(include_noise) or bool(username)
    where_parts = ["e.case_id = {case_id:UInt32}"]
    if not effective_include_noise:
        where_parts.append(build_effective_not_noise_clause(alias='e', case_id_sql='e.case_id'))
    
    if event_id:
        params['event_id'] = event_id
        where_parts.append("e.event_id = {event_id:String}")
    if host:
        params['host'] = host
        where_parts.append("lower(e.source_host) = lower({host:String})")
    if username:
        params['username'] = username
        where_parts.append(
            "(lower(e.username) = lower({username:String}) OR positionCaseInsensitive(e.search_blob, {username:String}) > 0)"
        )
    if time_start:
        params['time_start'] = _chat_time_to_utc(time_start, case_id) or time_start
        where_parts.append("e.timestamp >= parseDateTimeBestEffort({time_start:String})")
    if time_end:
        params['time_end'] = _chat_time_to_utc(time_end, case_id) or time_end
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


@register_tool("get_event_context")
def get_event_context(
    case_id: int,
    timestamp: str,
    host: str = None,
    window_minutes: int = 5,
    event_id: str = None,
    search_text: str = None,
    limit: int = 50,
    include_noise: bool = True,
    **kwargs,
) -> Dict:
    """Return events around an anchor timestamp, optionally scoped to one host."""
    if not timestamp:
        return {"error": "timestamp is required"}

    client = get_fresh_client()
    ensure_event_noise_state_tables(client)
    window_minutes = min(max(int(window_minutes or 5), 1), 120)
    limit = min(max(int(limit or 50), 1), 200)
    query_timestamp = _chat_time_to_utc(timestamp, case_id) or timestamp
    params = {
        'case_id': int(case_id),
        'timestamp': query_timestamp,
        'window_minutes': window_minutes,
        'limit': limit,
    }
    where_parts = [
        "e.case_id = {case_id:UInt32}",
        "e.timestamp >= parseDateTimeBestEffort({timestamp:String}) - toIntervalMinute({window_minutes:UInt32})",
        "e.timestamp <= parseDateTimeBestEffort({timestamp:String}) + toIntervalMinute({window_minutes:UInt32})",
    ]
    if not include_noise:
        where_parts.insert(1, build_effective_not_noise_clause(alias='e', case_id_sql='e.case_id'))
    if host:
        params['host'] = host
        where_parts.append("lower(e.source_host) = lower({host:String})")

    where_sql = ' AND '.join(where_parts)
    try:
        count_result = client.query(
            f"SELECT count() FROM events AS e WHERE {where_sql}",
            parameters=params,
        )
        total_matches = int(count_result.result_rows[0][0]) if count_result.result_rows else 0
        type_result = client.query(
            f"""
            SELECT artifact_type, count() as cnt
            FROM events AS e
            WHERE {where_sql}
            GROUP BY artifact_type
            ORDER BY cnt DESC
            """,
            parameters=params,
        )
        row_result = client.query(
            f"""
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
                substring(e.search_blob, 1, 220) as summary
            FROM events AS e
            WHERE {where_sql}
            ORDER BY abs(dateDiff('millisecond', e.timestamp, parseDateTimeBestEffort({{timestamp:String}}))) ASC, e.timestamp ASC
            LIMIT {{limit:UInt32}}
            """,
            parameters=params,
        )
    except Exception as e:
        return {"error": f"Context query failed: {str(e)}"}

    artifact_breakdown = {row[0] or 'unknown': row[1] for row in type_result.result_rows}
    events = []
    for row in row_result.result_rows:
        (
            timestamp_value,
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
        evt = {
            "timestamp": str(timestamp_value),
            "_artifact_type": artifact_type or "",
            "event_id": event_id_value or "",
            "host": host_value or "",
            "user": user_value or "",
            "channel": channel_value or "",
            "rule": rule_value or "",
            "level": level_value or "",
            "process": process_value or "",
            "is_anchor_candidate": bool(
                (event_id and str(event_id_value or '') == str(event_id))
                or (search_text and search_text.lower() in (summary_value or '').lower())
            ),
        }
        if cmdline_value:
            evt["cmdline"] = cmdline_value[:180]
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

    annotate_artifact_records(events, artifact_type_key="_artifact_type")
    provenance_summary = build_record_provenance_summary(events)
    returned_count = len(events)
    result_metadata = {
        "total_matches": total_matches,
        "returned_count": returned_count,
        "limit": limit,
        "truncated": total_matches > returned_count,
    }
    reviewed_filters = {
        "timestamp": timestamp,
        "query_timestamp_utc": query_timestamp,
        "window_minutes": window_minutes,
        "host": host or "",
        "event_id": event_id or "",
        "search_text": search_text or "",
        "include_noise": bool(include_noise),
    }
    coverage = build_event_corpus_coverage(
        client,
        case_id,
        reviewed_filters=reviewed_filters,
        result_metadata=result_metadata,
    )
    return attach_payload_provenance({
        "anchor": reviewed_filters,
        "time_start": f"{query_timestamp} - {window_minutes}m",
        "time_end": f"{query_timestamp} + {window_minutes}m",
        "total_matches": total_matches,
        "returned_count": returned_count,
        "truncated": total_matches > returned_count,
        "noise_filter": "included" if include_noise else "excluded",
        "artifact_types": artifact_breakdown,
        "events": events,
        **coverage,
    }, summary=provenance_summary)


def _extract_investigation_terms(question: str, user: str = None, focus_terms: str = None) -> List[str]:
    terms: List[str] = []

    def add_term(value: Any) -> None:
        cleaned = str(value or "").strip().strip("'\"")
        if len(cleaned) < 2:
            return
        if cleaned.lower() in {term.lower() for term in terms}:
            return
        terms.append(cleaned)

    for supplied in (user, focus_terms):
        for term in normalize_forensic_search_terms(supplied, max_terms=12):
            add_term(term)

    text = str(question or "")
    for match in re.findall(r"['\"]([^'\"]{2,120})['\"]", text):
        add_term(match)
    for match in re.findall(r"\b[A-Za-z0-9_. -]+\.exe\b", text, flags=re.IGNORECASE):
        add_term(match)
    for match in re.findall(r"[A-Za-z]:\\[^\s'\"<>|]+", text):
        add_term(match)
    for match in re.findall(r"\b(?:[A-Z]{2,}[\w-]*\d+|\w+\d{3,}|\d{1,3}(?:\.\d{1,3}){3})\b", text):
        add_term(match)

    lowered = text.lower()
    if any(token in lowered for token in ("screenconnect", "connectwise", "rmm", "remote support", "remote-support")):
        for term in ("ScreenConnect", "ConnectWise", "ClientService", "Control"):
            add_term(term)
    return terms[:16]


def _infer_investigation_intents(question: str, terms: List[str]) -> List[str]:
    lowered = str(question or "").lower()
    joined_terms = " ".join(terms).lower()
    intents: List[str] = []

    def add_intent(intent: str) -> None:
        if intent not in intents:
            intents.append(intent)

    if any(token in lowered for token in ("what did", "after", "follow", "then", "timeline", "around", "next")):
        add_intent("timeline")
        add_intent("process_lineage")
    if any(token in lowered for token in ("connect", "session", "rmm", "remote", "screenconnect", "connectwise", "control")) or any(
        token in joined_terms for token in ("screenconnect", "connectwise", "clientservice")
    ):
        add_intent("session_activity")
        add_intent("process_lineage")
        add_intent("file_transfer")
    if any(token in lowered for token in ("process", "spawn", "parent", "child", "command", "powershell", "cmd", "execute", "ran", "run ")):
        add_intent("process_lineage")
    if any(token in lowered for token in ("file", "download", "transfer", ".exe", "hash", "amcache", "prefetch", "srum")) or any(term.lower().endswith(".exe") for term in terms):
        add_intent("file_execution")
    if any(token in lowered for token in ("browser", "url", "download", "web", "edge", "chrome", "firefox")):
        add_intent("browser_download")
    if any(token in lowered for token in ("login", "logon", "auth", "credential", "user", "account", "4648", "4624", "4625")):
        add_intent("authentication")
    if any(token in lowered for token in ("persist", "service", "scheduled", "task", "registry", "run key", "startup")):
        add_intent("persistence")
    if any(token in lowered for token in ("network", "dns", "http", "ip ", "connection", "exfil")):
        add_intent("network")
    if any(token in lowered for token in ("evidence", "prove", "support", "hypothesis", "no evidence", "absence")):
        add_intent("coverage")
    for default_intent in ("timeline", "process_lineage", "file_execution", "coverage"):
        add_intent(default_intent)
    return intents


def _event_select_columns(alias: str = "e") -> str:
    return f"""
        {alias}.timestamp,
        {alias}.artifact_type,
        {alias}.event_id,
        {alias}.channel,
        {alias}.provider,
        {alias}.username,
        {alias}.process_name,
        {alias}.process_path,
        {alias}.parent_process,
        {alias}.command_line,
        {alias}.target_path,
        {alias}.file_hash_md5,
        {alias}.file_hash_sha1,
        {alias}.file_hash_sha256,
        {alias}.file_size,
        {alias}.rule_title,
        {alias}.mitre_attack_ids,
        {alias}.mitre_attack_tactics,
        substring({alias}.search_blob, 1, 900) AS summary
    """


def _extract_executable_terms(records: List[Dict[str, Any]]) -> List[str]:
    terms: List[str] = []

    def add(value: str) -> None:
        cleaned = str(value or "").strip().strip("'\"")
        if not cleaned:
            return
        if cleaned.lower() not in {term.lower() for term in terms}:
            terms.append(cleaned)

    for record in records:
        text = " ".join(str(record.get(key) or "") for key in ("summary", "command_line", "process_path", "target_path"))
        for path in re.findall(r"[A-Za-z]:\\[^\s'\"<>|]+?\.exe", text, flags=re.IGNORECASE):
            add(path)
            add(path.split("\\")[-1])
        for name in re.findall(r"\b[A-Za-z0-9_. -]+\.exe\b", text, flags=re.IGNORECASE):
            add(name.split("\\")[-1])
    return terms[:12]


def _extract_transferred_artifact_terms(records: List[Dict[str, Any]]) -> List[str]:
    terms: List[str] = []

    def add(value: str) -> None:
        cleaned = str(value or "").strip().strip("'\"")
        if not cleaned:
            return
        cleaned = cleaned.split("\\")[-1]
        if cleaned.lower() not in {term.lower() for term in terms}:
            terms.append(cleaned)

    for record in records:
        text = " ".join(str(record.get(key) or "") for key in ("summary", "command_line", "target_path", "process_path"))
        for match in re.findall(r"Transferred files with action[^:]*:\s*([A-Za-z0-9_. -]+\.exe)", text, flags=re.IGNORECASE):
            add(match)
        for match in re.findall(r"RunFile\"?\s+\"?([A-Za-z]:\\[^\s\"]+?\.exe)", text, flags=re.IGNORECASE):
            add(match)
        for match in re.findall(r"Documents\\ScreenConnect\\Temp\\([^\\\s\"]+?\.exe)", text, flags=re.IGNORECASE):
            add(match)
    return terms[:8]


@register_tool("investigate_question")
def investigate_question(
    case_id: int,
    question: str,
    host: str = None,
    user: str = None,
    focus_terms: str = None,
    time_start: str = None,
    time_end: str = None,
    lookback_minutes: int = 5,
    lookahead_minutes: int = 30,
    investigation_depth: str = "standard",
    limit: int = 25,
    **kwargs,
) -> Dict:
    """Run deterministic multi-pivot investigation for an open-ended forensic question."""
    del kwargs
    if not question or not str(question).strip():
        return {"error": "question is required"}

    client = get_fresh_client()
    ensure_event_noise_state_tables(client)
    case_tz = _case_timezone(case_id)
    limit = _clamp_int(limit, 25, 5, 80)
    lookback_minutes = _clamp_int(lookback_minutes, 5, 0, 120)
    lookahead_minutes = _clamp_int(lookahead_minutes, 30, 0, 240)
    depth = (investigation_depth or "standard").strip().lower()
    if depth not in {"quick", "standard", "deep"}:
        depth = "standard"

    terms = _extract_investigation_terms(question, user=user, focus_terms=focus_terms)
    intents = _infer_investigation_intents(question, terms)
    question_lower = question.lower()
    include_noise = bool(terms) or any(token in question_lower for token in ("tool", "software", "service", "rmm", "remote", "screenconnect", "connectwise", "control", "no evidence"))
    base_params: Dict[str, Any] = {"case_id": int(case_id)}
    base_where = ["e.case_id = {case_id:UInt32}"]
    if not include_noise:
        base_where.append(build_effective_not_noise_clause(alias='e', case_id_sql='e.case_id'))
    if host:
        base_params["host"] = str(host).strip()
        base_where.append("lower(e.source_host) = lower({host:String})")
    if time_start:
        base_params["time_start"] = _chat_time_to_utc(time_start, case_id) or time_start
        base_where.append("e.timestamp >= parseDateTimeBestEffort({time_start:String})")
    if time_end:
        base_params["time_end"] = _chat_time_to_utc(time_end, case_id) or time_end
        base_where.append("e.timestamp <= parseDateTimeBestEffort({time_end:String})")

    anchor_params = dict(base_params)
    anchor_where = list(base_where)
    if user:
        anchor_params["user"] = user
        anchor_where.append("(lower(e.username) = lower({user:String}) OR positionCaseInsensitive(e.search_blob, {user:String}) > 0)")
    if terms:
        anchor_where.append(build_case_insensitive_any_clause("e.search_blob", "anchor_term", terms, anchor_params))
    elif not user:
        anchor_where.append("1 = 0")

    try:
        anchor_rows = _query_rows(
            client,
            f"""
            SELECT {_event_select_columns('e')}
            FROM events AS e
            WHERE {' AND '.join(anchor_where)}
            ORDER BY e.timestamp ASC
            LIMIT 200
            """,
            anchor_params,
        )
    except Exception as exc:
        return {"error": f"Anchor investigation query failed: {exc}"}

    anchors = [_event_row_to_record(row, case_tz) for row in anchor_rows]
    for anchor in anchors:
        anchor["session_action"] = _infer_session_action(anchor)

    sessions = _build_session_windows(
        [anchor for anchor in anchors if anchor.get("session_action") in {"connected", "disconnected"}],
        lookback_minutes,
        lookahead_minutes,
    )
    if sessions:
        analysis_start = min((s.get("analysis_start_utc") for s in sessions if s.get("analysis_start_utc")), default=None)
        analysis_end = max((s.get("analysis_end_utc") for s in sessions if s.get("analysis_end_utc")), default=None)
        activity_start = min(
            (
                (s.get("start_marker") or s.get("end_marker") or {}).get("timestamp")
                for s in sessions
                if (s.get("start_marker") or s.get("end_marker") or {}).get("timestamp")
            ),
            default=analysis_start,
        )
    elif anchors:
        try:
            first_ts = datetime.fromisoformat(str(anchors[0]["timestamp"]))
            last_ts = datetime.fromisoformat(str(anchors[-1]["timestamp"]))
            analysis_start = _format_clickhouse_datetime(first_ts - timedelta(minutes=lookback_minutes))
            analysis_end = _format_clickhouse_datetime(last_ts + timedelta(minutes=lookahead_minutes))
            activity_start = _format_clickhouse_datetime(first_ts)
        except Exception:
            analysis_start = base_params.get("time_start")
            analysis_end = base_params.get("time_end")
            activity_start = analysis_start
    else:
        analysis_start = base_params.get("time_start")
        analysis_end = base_params.get("time_end")
        activity_start = analysis_start

    section_base_params = dict(base_params)
    section_where_base = list(base_where)
    if activity_start:
        section_base_params["activity_start"] = activity_start
        section_where_base.append("e.timestamp >= parseDateTimeBestEffort({activity_start:String})")
    if analysis_end:
        section_base_params["analysis_end"] = analysis_end
        section_where_base.append("e.timestamp <= parseDateTimeBestEffort({analysis_end:String})")

    def run_event_section(
        name: str,
        extra_where: List[str],
        *,
        params: Optional[Dict[str, Any]] = None,
        order: str = "e.timestamp ASC",
        section_limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        merged_params = dict(section_base_params)
        if params:
            merged_params.update(params)
        merged_params["section_limit"] = int(section_limit or limit)
        try:
            rows = _query_rows(
                client,
                f"""
                SELECT {_event_select_columns('e')}
                FROM events AS e
                WHERE {' AND '.join(section_where_base + extra_where)}
                ORDER BY {order}
                LIMIT {{section_limit:UInt32}}
                """,
                merged_params,
            )
            return {"returned_count": len(rows), "records": [_event_row_to_record(row, case_tz) for row in rows]}
        except Exception as exc:
            return {"returned_count": 0, "records": [], "error": str(exc)}

    term_params: Dict[str, Any] = {}
    term_clause = build_case_insensitive_any_clause("e.search_blob", "investigation_term", terms, term_params) if terms else ""
    term_where = [term_clause] if term_clause else []

    evidence_sections: Dict[str, Dict[str, Any]] = {}
    evidence_sections["anchors"] = {"returned_count": len(anchors), "records": anchors[:80]}
    evidence_sections["timeline"] = run_event_section("timeline", [], section_limit=limit)
    evidence_sections["attributed_activity"] = run_event_section(
        "attributed_activity",
        term_where,
        params=term_params,
        section_limit=limit,
    ) if term_where else {"returned_count": 0, "records": []}

    process_where = [
        "("
        "e.artifact_type IN ('huntress', 'process', 'prefetch') "
        "OR e.process_name != '' OR e.command_line != '' OR e.parent_process != ''"
        ")"
    ]
    if "process_lineage" in intents or depth in {"standard", "deep"}:
        evidence_sections["process_activity"] = run_event_section("process_activity", process_where, section_limit=limit)

    shell_where = [
        "("
        "positionCaseInsensitive(e.search_blob, 'powershell') > 0 "
        "OR positionCaseInsensitive(e.search_blob, 'cmd.exe') > 0 "
        "OR positionCaseInsensitive(e.search_blob, 'command_line') > 0"
        ")"
    ]
    if "process_lineage" in intents or "timeline" in intents:
        evidence_sections["shell_activity"] = run_event_section("shell_activity", shell_where, section_limit=min(limit, 30))

    file_where = [
        "("
        "e.artifact_type IN ('huntress', 'prefetch', 'mft', 'registry', 'srum', 'browser_download', 'webcache_downloads', 'evtx') "
        "AND (positionCaseInsensitive(e.search_blob, '.exe') > 0 "
        "OR positionCaseInsensitive(e.search_blob, 'Transferred files') > 0 "
        "OR positionCaseInsensitive(e.search_blob, 'RunFile') > 0 "
        "OR positionCaseInsensitive(e.search_blob, 'Amcache') > 0)"
        ")"
    ]
    if "file_execution" in intents or "file_transfer" in intents or depth in {"standard", "deep"}:
        evidence_sections["file_execution"] = run_event_section("file_execution", file_where, section_limit=limit)

    file_transfer_where = [
        "("
        "positionCaseInsensitive(e.search_blob, 'Transferred files with action') > 0 "
        "OR positionCaseInsensitive(e.search_blob, 'RunFile') > 0 "
        "OR positionCaseInsensitive(e.search_blob, 'ScreenConnect\\\\Temp') > 0 "
        "OR positionCaseInsensitive(e.search_blob, 'Documents\\\\ScreenConnect') > 0"
        ")"
    ]
    if "file_transfer" in intents or depth in {"standard", "deep"}:
        evidence_sections["file_transfer_and_run"] = run_event_section(
            "file_transfer_and_run",
            file_transfer_where,
            section_limit=limit,
        )

    transferred_records = [
        record for record in (
            evidence_sections.get("file_transfer_and_run", {}).get("records", [])
            + evidence_sections.get("file_execution", {}).get("records", [])
        )
        if "transferred files" in str(record.get("summary", "")).lower()
        or "runfile" in str(record.get("summary", "")).lower()
        or "runfile" in str(record.get("command_line", "")).lower()
    ]
    transferred_artifact_terms = _extract_transferred_artifact_terms(transferred_records)
    executable_terms = transferred_artifact_terms or _extract_executable_terms(
        transferred_records or evidence_sections.get("attributed_activity", {}).get("records", [])[:20]
    )
    if executable_terms:
        exact_params: Dict[str, Any] = {}
        exact_clause = build_case_insensitive_any_clause("e.search_blob", "exec_term", executable_terms, exact_params)
        evidence_sections["follow_on_file_evidence"] = run_event_section(
            "follow_on_file_evidence",
            [exact_clause],
            params=exact_params,
            section_limit=min(max(limit, 30), 80),
        )

    if "browser_download" in intents or depth in {"standard", "deep"}:
        browser_where = [
            "("
            "positionCaseInsensitive(e.artifact_type, 'browser') > 0 "
            "OR positionCaseInsensitive(e.artifact_type, 'webcache') > 0 "
            "OR positionCaseInsensitive(e.search_blob, 'http') > 0 "
            "OR positionCaseInsensitive(e.search_blob, 'download') > 0 "
            "OR positionCaseInsensitive(e.search_blob, 'msedge') > 0 "
            "OR positionCaseInsensitive(e.search_blob, 'firefox') > 0"
            ")"
        ]
        evidence_sections["browser_and_web"] = run_event_section("browser_and_web", browser_where, section_limit=min(limit, 30))

    if "authentication" in intents or depth == "deep":
        auth_where = [
            "("
            "e.event_id IN ('4624', '4625', '4648', '4672') "
            "OR e.logon_type IS NOT NULL OR e.auth_package != '' OR e.logon_process != ''"
            ")"
        ]
        evidence_sections["authentication"] = run_event_section("authentication", auth_where, section_limit=min(limit, 40))

    if "persistence" in intents or depth in {"standard", "deep"}:
        persistence_where = [
            "("
            "positionCaseInsensitive(e.search_blob, 'CurrentVersion\\\\Run') > 0 "
            "OR positionCaseInsensitive(e.search_blob, 'Services\\\\') > 0 "
            "OR positionCaseInsensitive(e.search_blob, 'TaskCache') > 0 "
            "OR positionCaseInsensitive(e.search_blob, 'Scheduled') > 0 "
            "OR e.event_id IN ('7045', '4697')"
            ")"
        ]
        evidence_sections["persistence_like"] = run_event_section("persistence_like", persistence_where, section_limit=min(limit, 30))

    evidence_sections["mitre_mapped"] = run_event_section(
        "mitre_mapped",
        ["length(e.mitre_attack_ids) > 0"],
        section_limit=min(limit, 50),
    )

    network_coverage: Dict[str, Any] = {"count": 0}
    network_records: List[Dict[str, Any]] = []
    try:
        net_count = _query_rows(
            client,
            "SELECT count(), min(timestamp), max(timestamp) FROM network_logs WHERE case_id = {case_id:UInt32}",
            {"case_id": int(case_id)},
        )
        if net_count:
            network_coverage = {
                "count": int(net_count[0][0] or 0),
                "first_seen": str(net_count[0][1] or ""),
                "last_seen": str(net_count[0][2] or ""),
            }
        if network_coverage.get("count", 0) and (terms or "network" in intents):
            net_params: Dict[str, Any] = {"case_id": int(case_id), "section_limit": min(limit, 30)}
            net_where = ["case_id = {case_id:UInt32}"]
            if analysis_start:
                net_params["analysis_start"] = analysis_start
                net_where.append("timestamp >= parseDateTimeBestEffort({analysis_start:String})")
            if analysis_end:
                net_params["analysis_end"] = analysis_end
                net_where.append("timestamp <= parseDateTimeBestEffort({analysis_end:String})")
            if terms:
                net_clause = build_case_insensitive_any_clause("raw_json", "network_term", terms, net_params)
                net_where.append(net_clause)
            net_rows = _query_rows(
                client,
                f"""
                SELECT timestamp, log_type, src_ip, dst_ip, src_port, dst_port, protocol, substring(raw_json, 1, 600)
                FROM network_logs
                WHERE {' AND '.join(net_where)}
                ORDER BY timestamp ASC
                LIMIT {{section_limit:UInt32}}
                """,
                net_params,
            )
            network_records = [
                {
                    "timestamp": str(row[0]),
                    "case_time": _display_case_time(row[0], case_tz),
                    "log_type": row[1],
                    "src_ip": str(row[2] or ""),
                    "dst_ip": str(row[3] or ""),
                    "src_port": row[4],
                    "dst_port": row[5],
                    "protocol": row[6],
                    "summary": str(row[7] or "")[:600],
                }
                for row in net_rows
            ]
    except Exception as exc:
        network_coverage = {"count": 0, "error": str(exc)}
    evidence_sections["network"] = {"returned_count": len(network_records), "records": network_records, "coverage": network_coverage}

    negative_checks = [
        {"section": name, "checked": True, "result": "no rows returned"}
        for name, section in evidence_sections.items()
        if isinstance(section, dict) and int(section.get("returned_count") or 0) == 0
    ]
    timeline_records = []
    seen_keys = set()
    for section_name in ("anchors", "attributed_activity", "file_transfer_and_run", "follow_on_file_evidence", "file_execution", "process_activity", "authentication", "browser_and_web", "persistence_like", "mitre_mapped"):
        for record in evidence_sections.get(section_name, {}).get("records", []):
            key = (record.get("timestamp"), record.get("artifact_type"), record.get("event_id"), record.get("summary"))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            enriched = dict(record)
            enriched["evidence_section"] = section_name
            timeline_records.append(enriched)
    timeline_records.sort(key=lambda record: record.get("timestamp") or "")
    timeline_records = timeline_records[: min(max(limit * 2, 30), 120)]

    attributed_activity = []
    for section_name in ("anchors", "attributed_activity", "file_transfer_and_run", "follow_on_file_evidence", "file_execution", "process_activity"):
        for record in evidence_sections.get(section_name, {}).get("records", []):
            text = " ".join(str(record.get(key) or "") for key in ("summary", "command_line", "process_name", "parent_process", "target_path"))
            if any(term.lower() in text.lower() for term in terms) or (user and user.lower() in text.lower()):
                attributed = dict(record)
                attributed["attribution_basis"] = f"Matched investigation term/user in {section_name}"
                attributed_activity.append(attributed)
    attributed_activity = attributed_activity[:80]

    related_activity = [
        dict(record, attribution_basis="Temporal proximity only")
        for record in timeline_records
        if record not in attributed_activity
    ][:80]

    try:
        coverage = build_event_corpus_coverage(
            client,
            case_id,
            reviewed_filters={
                "host": host or "",
                "user": user or "",
                "terms": terms,
                "intents": intents,
                "analysis_start_utc": analysis_start or "",
                "analysis_end_utc": analysis_end or "",
                "include_noise": include_noise,
            },
            result_metadata={
                "anchor_count": len(anchors),
                "timeline_count": len(timeline_records),
                "sections": {name: section.get("returned_count", 0) for name, section in evidence_sections.items()},
            },
        )
    except Exception:
        coverage = {}

    key_findings: List[str] = []
    if anchors:
        key_findings.append(f"Found {len(anchors)} anchor row(s) matching the question terms.")
    else:
        key_findings.append("No direct anchor rows matched the extracted question terms.")
    transfer_like = transferred_records
    if transfer_like:
        first = transfer_like[0]
        key_findings.append(f"File transfer/run evidence appears at {first.get('case_time') or first.get('timestamp')}: {first.get('summary', '')[:180]}")
    if transferred_artifact_terms:
        key_findings.append(f"Transferred/run artifact term(s): {', '.join(transferred_artifact_terms[:5])}.")
    if evidence_sections.get("follow_on_file_evidence", {}).get("records"):
        follow_records = evidence_sections["follow_on_file_evidence"]["records"]
        first = next(
            (
                record for record in follow_records
                if any(
                    term.lower() in " ".join(str(record.get(key) or "") for key in ("command_line", "process_name", "target_path", "process_path")).lower()
                    for term in transferred_artifact_terms
                )
            ),
            follow_records[0],
        )
        key_findings.append(f"Follow-on executable evidence includes {first.get('process_name') or first.get('target_path') or first.get('summary', '')[:100]}.")
    shell_candidates = evidence_sections.get("shell_activity", {}).get("records", [])
    if shell_candidates:
        first = next(
            (
                record for record in shell_candidates
                if any(
                    term.lower() in " ".join(str(record.get(key) or "") for key in ("summary", "command_line", "parent_process", "process_name")).lower()
                    for term in terms
                )
            ),
            shell_candidates[0],
        )
        key_findings.append(f"Shell activity appears at {first.get('case_time') or first.get('timestamp')}: {first.get('command_line') or first.get('summary', '')[:140]}")

    caveats = [
        "Attribution is strongest where rows share explicit terms, provider events, parent/child process lineage, file path, or hash; nearby rows are only related by time.",
        "This investigation uses indexed ClickHouse evidence only.",
    ]
    if network_coverage.get("count", 0) == 0:
        caveats.append("No indexed network_logs rows are available for this case, so network destinations cannot be confirmed here.")

    answer_draft = {
        "summary": " ".join(key_findings[:4]),
        "confidence": "high" if attributed_activity else ("medium" if anchors else "low"),
        "recommended_response_style": "Answer directly, cite the strongest attributed rows first, then separate nearby/background activity and caveats.",
    }

    evidence_count = len(timeline_records) + len(attributed_activity) + len(anchors)
    return attach_payload_provenance(
        {
            "interpreted_question": {
                "question": question,
                "host": host or "",
                "user": user or "",
                "focus_terms": focus_terms or "",
                "extracted_terms": terms,
                "intents": intents,
                "case_timezone": case_tz,
                "include_noise": include_noise,
            },
            "pivot_plan": [
                "Extracted entities and intent from the natural-language question",
                "Searched normalized events for anchors",
                "Built a case-timezone-aware analysis window from anchors or supplied bounds",
                "Pivoted across process, file execution, browser/web, authentication, persistence, MITRE, and network evidence where applicable",
                "Separated attributed rows from temporal-only related activity",
            ],
            "analysis_window": {
                "start_utc": analysis_start or "",
                "end_utc": analysis_end or "",
                "activity_start_utc": activity_start or "",
                "lookback_minutes": lookback_minutes,
                "lookahead_minutes": lookahead_minutes,
            },
            "sessions": sessions,
            "timeline": timeline_records,
            "attributed_activity": attributed_activity,
            "related_activity": related_activity,
            "negative_checks": negative_checks,
            "evidence_sections": evidence_sections,
            "coverage": {
                **coverage,
                "network": network_coverage,
            },
            "answer_draft": answer_draft,
            "key_findings": key_findings,
            "transferred_artifact_terms": transferred_artifact_terms,
            "caveats": caveats,
        },
        summary=_constant_provenance_summary(
            provenance='ELEVATED_RISK' if evidence_count else 'SYSTEM_DERIVED',
            record_count=max(evidence_count, 1),
        ),
    )


@register_tool("get_case_coverage")
def get_case_coverage(
    case_id: int,
    host: str = None,
    include_breakdowns: bool = True,
    **kwargs,
) -> Dict:
    """Summarize available evidence coverage for a case."""
    client = get_fresh_client()
    host = (host or '').strip()
    params = {'case_id': int(case_id)}
    host_clause = ''
    if host:
        params['host'] = host
        host_clause = " AND lower(source_host) = lower({host:String})"

    event_coverage = build_event_corpus_coverage(
        client,
        case_id,
        reviewed_filters={'host': host} if host else {},
        result_metadata={},
    )
    artifact_breakdown: Dict[str, int] = {}
    host_breakdown: Dict[str, int] = {}
    total_events = 0
    try:
        total_result = client.query(
            f"SELECT count() FROM events WHERE case_id = {{case_id:UInt32}}{host_clause}",
            parameters=params,
        )
        total_events = int(total_result.result_rows[0][0]) if total_result.result_rows else 0
        if include_breakdowns:
            artifact_result = client.query(
                f"""
                SELECT artifact_type, count() as cnt
                FROM events
                WHERE case_id = {{case_id:UInt32}}{host_clause}
                GROUP BY artifact_type
                ORDER BY cnt DESC
                LIMIT 50
                """,
                parameters=params,
            )
            artifact_breakdown = {row[0] or 'unknown': row[1] for row in artifact_result.result_rows}
            host_result = client.query(
                f"""
                SELECT source_host, count() as cnt
                FROM events
                WHERE case_id = {{case_id:UInt32}}{host_clause}
                GROUP BY source_host
                ORDER BY cnt DESC
                LIMIT 50
                """,
                parameters=params,
            )
            host_breakdown = {row[0] or 'unknown': row[1] for row in host_result.result_rows}
    except Exception as e:
        return {"error": f"Coverage query failed: {str(e)}"}

    network_coverage = {
        'pcap_count': 0,
        'available_log_types': [],
        'pcaps': [],
    }
    try:
        from models import network_log

        pcap_stats = network_log.get_pcap_stats(case_id) or []
        if host:
            pcap_stats = [
                pcap for pcap in pcap_stats
                if str(pcap.get('source_host') or '').lower() == host.lower()
            ]
        available_log_types = sorted({
            str(log_type)
            for pcap in pcap_stats
            for log_type in (pcap.get('by_type') or {}).keys()
            if log_type
        })
        network_coverage = {
            'pcap_count': len(pcap_stats),
            'available_log_types': available_log_types,
            'pcaps': pcap_stats[:25],
        }
    except Exception:
        network_coverage['source_availability_status'] = 'unknown'

    memory_coverage = {
        'memory_job_count': 0,
        'source_hosts': [],
    }
    try:
        from models.memory_job import MemoryJob

        query = MemoryJob.query.filter_by(case_id=case_id, status='completed')
        if host:
            query = query.filter(MemoryJob.hostname == host)
        jobs = query.all()
        memory_coverage = {
            'memory_job_count': len(jobs),
            'source_hosts': sorted(str(job.hostname) for job in jobs if getattr(job, 'hostname', None)),
        }
    except Exception:
        memory_coverage['source_availability_status'] = 'unknown'

    coverage_detail = event_coverage.get('coverage_detail') or {}
    coverage_detail['result_metadata'] = {
        **(coverage_detail.get('result_metadata') or {}),
        'total_events': total_events,
        'artifact_type_count': len(artifact_breakdown),
        'host_count': len(host_breakdown),
        'network_pcap_count': network_coverage.get('pcap_count', 0),
        'memory_job_count': memory_coverage.get('memory_job_count', 0),
    }
    return attach_payload_provenance({
        'total_events': total_events,
        'artifact_types': artifact_breakdown,
        'hosts': host_breakdown,
        'network_coverage': network_coverage,
        'memory_coverage': memory_coverage,
        'coverage_status': event_coverage.get('coverage_status', 'unknown'),
        'source_availability_status': event_coverage.get('source_availability_status', 'unknown'),
        'coverage_detail': coverage_detail,
    }, summary=_constant_provenance_summary(record_count=1))


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
                     limit: int = 25, include_noise: bool = True, **kwargs) -> Dict:
    """Search normalized case artifacts for a value."""
    return search_case_artifacts(
        case_id,
        search=search,
        artifact_type=artifact_type or '',
        host=host or '',
        username=username or '',
        limit=limit or 25,
        include_noise=include_noise,
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
                        time_start: str = None, time_end: str = None,
                        source_availability_status: str = None,
                        missing_sources: List[str] = None,
                        limitations: List[str] = None,
                        **kwargs) -> Dict:
    """Search indexed network logs."""
    return search_network_logs_for_case(
        case_id,
        search=search or '',
        log_type=log_type or '',
        pcap_id=pcap_id,
        src_ip=src_ip or '',
        dst_ip=dst_ip or '',
        time_start=time_start or '',
        time_end=time_end or '',
        limit=limit or 25,
        source_availability_status=source_availability_status or 'unknown',
        missing_sources=missing_sources or [],
        limitations=limitations or [],
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


@register_tool("add_ioc")
def add_ioc(
    case_id: int,
    value: str,
    reason: str,
    ioc_type: str = None,
    malicious: bool = False,
    **kwargs,
) -> Dict:
    """Add or update a case IOC. Dispatcher approval gates this write."""
    if not value or not str(value).strip():
        return {"error": "value is required"}
    if not reason or not str(reason).strip():
        return {"error": "reason is required"}

    from models.ioc import IOC, detect_ioc_type_from_value, detect_match_type, get_category_for_type

    cleaned_value = str(value).strip()
    resolved_type = (ioc_type or '').strip() or detect_ioc_type_from_value(cleaned_value)
    category = get_category_for_type(resolved_type)
    if not category:
        return {"error": f"Unable to determine IOC category for type: {resolved_type}"}
    match_type = detect_match_type(cleaned_value, resolved_type)
    source_metadata = {
        'source': 'chat_agent',
        'reason': str(reason).strip()[:1000],
        'provenance': 'MODEL_SYNTHESIZED_PENDING_ANALYST_APPROVAL',
    }
    ioc, created = IOC.get_or_create(
        value=cleaned_value,
        ioc_type=resolved_type,
        category=category,
        created_by='chat_agent',
        case_id=case_id,
        match_type=match_type,
        source='chat_agent',
        source_metadata=source_metadata,
    )
    if malicious:
        ioc.malicious = True
    current_notes = (getattr(ioc, 'notes', None) or '').strip()
    note = str(reason).strip()
    if note and note not in current_notes:
        ioc.notes = f"{current_notes}\n{note}".strip() if current_notes else note
    db.session.commit()
    return attach_payload_provenance({
        'ioc_id': getattr(ioc, 'id', None),
        'uuid': getattr(ioc, 'uuid', None),
        'value': cleaned_value,
        'ioc_type': resolved_type,
        'category': category,
        'match_type': match_type,
        'created': created,
        'malicious': bool(getattr(ioc, 'malicious', False)),
        'source': 'chat_agent',
    }, summary=_constant_provenance_summary(provenance='ANALYST', record_count=1))


@register_tool("save_finding")
def save_finding(
    case_id: int,
    title: str,
    classification: str,
    rationale: str,
    confidence: int = None,
    decision_scope: str = 'case',
    target_host: str = None,
    target_user: str = None,
    target_ioc: str = None,
    target_artifact_path: str = None,
    target_process: str = None,
    hunt_run_id: int = None,
    **kwargs,
) -> Dict:
    """Persist a draft chat finding to the hunt ledger. Dispatcher approval gates this write."""
    if not title or not str(title).strip():
        return {"error": "title is required"}
    if not rationale or not str(rationale).strip():
        return {"error": "rationale is required"}

    from models.hunt import HuntCreatedByType, HuntDecisionScope, HuntRun
    from utils.hunt_trace import create_decision

    if hunt_run_id:
        run = HuntRun.query.filter_by(case_id=case_id, id=int(hunt_run_id)).first()
        if not run:
            return {"error": f"Hunt run {hunt_run_id} not found for this case"}
    else:
        run = HuntRun(
            case_id=case_id,
            objective=f"Chat saved finding: {str(title).strip()[:180]}",
            status='active',
            created_by='chat_agent',
            source_scope={'source': 'chat'},
        )
        db.session.add(run)
        db.session.commit()

    normalized_scope = (decision_scope or HuntDecisionScope.CASE).strip().lower()
    metadata = {
        'title': str(title).strip()[:255],
        'source': 'chat_agent',
        'saved_from_chat': True,
    }
    decision = create_decision(
        hunt_run_id=run.id,
        classification=classification,
        decision_state='draft',
        decision_scope=normalized_scope,
        created_by_type=HuntCreatedByType.AI,
        created_by='chat_agent',
        target_host=target_host,
        target_user=target_user,
        target_ioc=target_ioc,
        target_artifact_path=target_artifact_path,
        target_process=target_process,
        confidence=confidence,
        rationale=str(rationale).strip(),
        ai_rationale=str(rationale).strip(),
        metadata=metadata,
    )
    return attach_payload_provenance({
        'hunt_run_id': run.id,
        'decision_id': decision.id,
        'title': metadata['title'],
        'classification': decision.classification,
        'decision_scope': decision.decision_scope,
        'decision_state': decision.decision_state,
        'confidence': decision.confidence,
        'created_by': decision.created_by,
    }, summary=_constant_provenance_summary(provenance='ANALYST', record_count=1))


@register_tool("run_forensic_subagent")
def run_forensic_subagent(
    case_id: int,
    subagent: str,
    task: str,
    evidence: Dict = None,
    **kwargs
) -> Dict:
    """Run a bounded CaseScope forensic subagent."""
    del kwargs
    from utils.ai_subagents import run_subagent
    from utils.provenance import attach_payload_provenance

    result = run_subagent(
        key=subagent,
        case_id=case_id,
        task=task,
        evidence=evidence if isinstance(evidence, dict) else {},
    )
    return attach_payload_provenance(
        result,
        summary={
            "highest_provenance": "MODEL_SYNTHESIZED",
            "summary": f"{result.get('subagent', {}).get('name', subagent)} completed delegated analysis",
            "sources": ["ai_subagent"],
        },
    )


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
