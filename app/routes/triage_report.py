#!/usr/bin/env python3
"""
Triage Report Feature (v1.36.0)
================================
Full IOC discovery system that:
1. Extracts IOCs from analyst-pasted EDR/MDR reports (LLM + regex)
2. Hunts those IOCs to discover NEW related IOCs
3. Hunts malware/recon indicators for additional IOCs
4. Adds all discovered IOCs to the database with appropriate types

Progress updates are streamed to the frontend via Server-Sent Events.
"""

import json
import logging
import re
from typing import Dict, List, Set, Tuple
from flask import Blueprint, request, jsonify, Response, stream_with_context, render_template
from flask_login import login_required, current_user

logger = logging.getLogger(__name__)

triage_report_bp = Blueprint('triage_report', __name__)

# IOC type mappings for the IOC table
# v1.43.18: Added services mapping
IOC_TYPE_MAP = {
    'ips': 'ip',
    'hashes': 'hash',
    'usernames': 'username',
    'sids': 'user_sid',
    'paths': 'filepath',
    'processes': 'filename',
    'domains': 'domain',
    'urls': 'url',
    'registry_keys': 'registry',
    'commands': 'command',
    'hostnames': 'hostname',
    'threats': 'threat',
    'malware': 'malware',
    'tools': 'tool',
    'services': 'service',
}

# Noise filtering
NOISE_USERS = {
    'system', 'network service', 'local service', 'anonymous logon',
    'window manager', 'dwm-1', 'dwm-2', 'umfd-0', 'umfd-1', '-', 'n/a', '',
    'font driver host', 'defaultaccount', 'guest', 'wdagutilityaccount'
}

NOT_HOSTNAMES = {
    # Common words
    'the', 'and', 'from', 'with', 'this', 'that', 'was', 'has', 'been', 'have', 'had',
    'are', 'were', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'shall',
    'can', 'for', 'but', 'not', 'you', 'all', 'can', 'her', 'his', 'its', 'our', 'out',
    'own', 'she', 'who', 'how', 'now', 'old', 'see', 'way', 'who', 'did', 'get', 'got',
    'him', 'let', 'put', 'say', 'too', 'use', 'via', 'name', 'host', 'user', 'file',
    # IT/Security terms that aren't hostnames
    'system', 'server', 'client', 'machine', 'computer', 'endpoint', 'device', 'network',
    'domain', 'local', 'remote', 'internal', 'external', 'unknown', 'none', 'null', 'test',
    'logging', 'security', 'event', 'events', 'alert', 'alerts', 'incident', 'malware',
    'threat', 'attack', 'attacker', 'victim', 'target', 'source', 'destination',
    'process', 'service', 'application', 'software', 'hardware', 'firewall', 'router',
    'gateway', 'proxy', 'dns', 'dhcp', 'vpn', 'rdp', 'ssh', 'http', 'https', 'ftp',
    'admin', 'administrator', 'root', 'guest', 'default', 'public', 'private',
    'enabled', 'disabled', 'active', 'inactive', 'running', 'stopped', 'failed',
    'success', 'error', 'warning', 'info', 'debug', 'critical', 'high', 'medium', 'low',
    'true', 'false', 'yes', 'no', 'on', 'off', 'new', 'old', 'first', 'last',
    'powershell', 'cmd', 'command', 'script', 'executed', 'execution', 'lateral',
    'movement', 'persistence', 'credential', 'access', 'privilege', 'escalation',
    'enumeration', 'discovery', 'exfiltration', 'reconnaissance', 'initial'
}

# Recon search terms for Phase 3
RECON_SEARCH_TERMS = [
    "nltest", "net group", "net user", "net localgroup",
    "whoami", "ipconfig", "systeminfo", "domain trust",
    "quser", "query user", "dclist"
]


def is_machine_account(username: str) -> bool:
    """Check if username is a machine account (ends with $)"""
    return username.endswith('$') if username else False


def is_valid_hostname(hostname: str, ip_set: Set[str]) -> bool:
    """Check if a string looks like a valid hostname"""
    if not hostname or len(hostname) < 3:
        return False
    if hostname.lower() in NOT_HOSTNAMES:
        return False
    # Check if it's an IP
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if hostname in ip_set or re.match(ip_pattern, hostname):
        return False
    # Must have at least one letter
    if not re.search(r'[a-zA-Z]', hostname):
        return False
    return True


def extract_iocs_with_llm(summary_text: str) -> Dict:
    """
    Use LLM to extract structured IOCs from investigative summary.
    Returns dict with categorized IOCs.
    
    v2.0.0: Uses AI Model Selector for auto-selection based on VRAM tier.
    """
    import requests
    from models import SystemSettings
    from ai_model_selector import get_ai_model
    
    # Get Ollama host setting
    ollama_host = SystemSettings.query.filter_by(setting_key='ollama_host').first()
    host = ollama_host.setting_value if ollama_host else 'http://localhost:11434'
    
    # Auto-select model based on VRAM (Qwen 7B on 8GB, Qwen 14B on 16GB)
    model = get_ai_model('ioc_extraction')
    
    # v1.43.18: Improved prompt - clearer schema, defang rules, no example contamination
    prompt = f"""Extract IOCs from the following EDR/security report. Return ONLY valid JSON.

SCHEMA (use empty arrays [] if none found):
{{
  "usernames": ["exact usernames only - no SIDs, no domain prefixes"],
  "sids": ["S-1-5-21-... format only"],
  "ips": ["IP addresses only - defang: 91.236.230[.]136 becomes 91.236.230.136"],
  "hostnames": ["computer names like SERVER01, DC1, WORKSTATION - NOT domains"],
  "domains": ["domain names like evil.com, malware.net - NOT computer names"],
  "processes": ["executable names like nltest.exe, WinSCP.exe"],
  "paths": ["file/folder paths like C:\\Users\\..."],
  "commands": ["full command lines executed"],
  "hashes": ["SHA256, SHA1, or MD5 hashes"],
  "timestamps": ["ISO 8601 format: 2025-10-05T19:46:35Z"],
  "registry_keys": ["HKLM\\..., HKCU\\..."],
  "tools": ["tool/software names mentioned: WinSCP, Mimikatz, BlueVPS, etc."],
  "services": ["network services: RDP, SMB, WinRM, SSH if mentioned"],
  "threat_types": ["enumeration", "lateral_movement", "exfiltration", "persistence", etc.],
  "malware_indicated": true or false
}}

RULES:
- Extract EXACT values from text only - do not invent or assume
- Defang IPs: 91.236.230[.]136 becomes 91.236.230.136
- Usernames: extract just the username (BButler), not "BButler / S-1-5-21-..."
- IPs go in "ips", computer names go in "hostnames" - DO NOT MIX
- Include VPS/hosting providers in "tools" (BlueVPS, DigitalOcean, etc.)
- Normalize timestamps to ISO 8601 (2025-10-05 19:46:35 UTC becomes 2025-10-05T19:46:35Z)
- Set malware_indicated=true if: recon tools, exfil tools, C2, suspicious RDP, or malware
- Return ONLY the JSON object, no markdown, no explanation, no comments

Report:
{summary_text}
"""
    
    logger.info(f"[TRIAGE] Calling LLM ({model}) for IOC extraction...")
    
    try:
        response = requests.post(
            f"{host}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=120  # v1.43.18: Increased timeout for longer prompts
        )
        
        if response.status_code == 200:
            result = response.json().get('response', '')
            logger.info(f"[TRIAGE] LLM response received ({len(result)} chars)")
            
            # Try to parse JSON from response
            json_match = re.search(r'\{[\s\S]*\}', result)
            if json_match:
                try:
                    iocs = json.loads(json_match.group())
                    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
                    logger.info(f"[TRIAGE] LLM ({model}) extracted IOCs: {total_iocs} total")
                    return iocs
                except json.JSONDecodeError as e:
                    logger.warning(f"[TRIAGE] LLM returned invalid JSON: {e}")
                    logger.warning(f"[TRIAGE] Raw response (first 500 chars): {result[:500]}")
            else:
                logger.warning(f"[TRIAGE] No JSON found in LLM response: {result[:300]}")
        else:
            logger.warning(f"[TRIAGE] LLM HTTP error: {response.status_code}")
        
    except requests.exceptions.Timeout:
        logger.warning(f"[TRIAGE] LLM request timed out (120s)")
    except Exception as e:
        logger.warning(f"[TRIAGE] LLM extraction failed: {e}")
    
    logger.info("[TRIAGE] Falling back to regex extraction")
    return {}


def extract_iocs_with_regex(summary_text: str) -> Dict:
    """
    Fallback: Extract IOCs using regex patterns.
    Used if LLM fails or is unavailable.
    
    v1.43.18: Added services, threat_types fields for consistency with LLM output.
    """
    iocs = {
        'usernames': [],
        'ips': [],
        'processes': [],
        'paths': [],
        'hashes': [],
        'hostnames': [],
        'timestamps': [],
        'sids': [],
        'domains': [],
        'registry_keys': [],
        'commands': [],
        'tools': [],
        'services': [],
        'threat_types': [],
        'malware_indicated': False
    }
    
    # IP addresses (validated format)
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    iocs['ips'] = list(set(re.findall(ip_pattern, summary_text)))
    ip_set = set(iocs['ips'])
    
    # SHA256 hashes (64 hex chars)
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    iocs['hashes'].extend(re.findall(sha256_pattern, summary_text))
    
    # MD5 hashes (32 hex chars)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    iocs['hashes'].extend(re.findall(md5_pattern, summary_text))
    
    # SHA1 hashes (40 hex chars)
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    iocs['hashes'].extend(re.findall(sha1_pattern, summary_text))
    iocs['hashes'] = list(set(iocs['hashes']))
    
    # Windows SIDs
    sid_pattern = r'S-1-5-21-[\d-]+'
    iocs['sids'] = list(set(re.findall(sid_pattern, summary_text)))
    
    # === USERNAMES ===
    usernames = set()
    for match in re.findall(r'user\s*["\']([^"\']+)["\']', summary_text, re.IGNORECASE):
        usernames.add(match)
    for match in re.findall(r'account\s*["\']([^"\']+)["\']', summary_text, re.IGNORECASE):
        usernames.add(match)
    for match in re.findall(r"['\"]?([a-zA-Z0-9_\-\.]+)['\"]?\s*/\s*S-1-5-", summary_text):
        if match and len(match) > 2:
            usernames.add(match)
    noise_users = {'system', 'administrator', 'admin', 'user', 'guest', 'default'}
    iocs['usernames'] = [u for u in usernames if u.lower() not in noise_users and len(u) > 1]
    
    # === HOSTNAMES ===
    hostnames = set()
    for match in re.findall(r'host\s*["\']([^"\']+)["\']', summary_text, re.IGNORECASE):
        hostname_part = match.split()[0] if match.split() else match
        if is_valid_hostname(hostname_part, ip_set):
            hostnames.add(hostname_part)
    for match in re.findall(r'machine\s*["\']([^"\']+)["\']', summary_text, re.IGNORECASE):
        hostname_part = match.split()[0].strip() if match.split() else match.strip()
        if is_valid_hostname(hostname_part, ip_set):
            hostnames.add(hostname_part)
    for match in re.findall(r'[Hh]ost\s*name[:\s]+([A-Za-z0-9\-_]+)', summary_text):
        if is_valid_hostname(match, ip_set):
            hostnames.add(match)
    for match in re.findall(r'endpoint\s+([A-Za-z0-9\-_]+)', summary_text, re.IGNORECASE):
        if is_valid_hostname(match, ip_set):
            hostnames.add(match)
    iocs['hostnames'] = list(hostnames)
    
    # === PATHS ===
    # Match Windows paths, clean up trailing quotes/punctuation
    path_pattern = r"[A-Za-z]:\\(?:[^\s\\/:*?\"<>|']+\\)+[^\s\\/:*?\"<>|']*"
    raw_paths = list(set(re.findall(path_pattern, summary_text)))
    # Clean trailing quotes and punctuation, filter short paths
    cleaned_paths = []
    for p in raw_paths:
        p = p.rstrip("'\".,;:")  # Remove trailing quotes and punctuation
        if len(p) >= 10:
            cleaned_paths.append(p)
    iocs['paths'] = cleaned_paths
    
    # === PROCESSES ===
    # Only capture standalone exe names (not full paths - those go in paths)
    processes = set()
    # Standalone exe names mentioned in context
    for match in re.findall(r'(?:executed|ran|launched|spawned|running|process)\s+["\']?([a-zA-Z0-9_\-]+\.exe)["\']?', summary_text, re.IGNORECASE):
        processes.add(match)
    # Exe names at end of paths are already captured in paths, don't duplicate
    iocs['processes'] = list(processes)
    
    # === COMMANDS ===
    commands = set()
    ps_commands = re.findall(r'powershell(?:\.exe)?\s+[\-/][^\n]{10,}', summary_text, re.IGNORECASE)
    for cmd in ps_commands:
        commands.add(cmd.strip())
    # Recon commands
    nltest_cmds = re.findall(r'nltest(?:\.exe)?\s+[^\n]+', summary_text, re.IGNORECASE)
    for cmd in nltest_cmds:
        commands.add(cmd.strip())
    net_cmds = re.findall(r'net(?:\.exe)?\s+(?:group|user|localgroup)[^\n]+', summary_text, re.IGNORECASE)
    for cmd in net_cmds:
        commands.add(cmd.strip())
    iocs['commands'] = list(commands)
    
    # === TOOLS ===
    tools = set()
    tool_names = ['WinSCP', 'Advanced IP Scanner', 'PSEXEC', 'Mimikatz', 'Cobalt Strike', 
                  'BlueVPS', 'AnyDesk', 'TeamViewer', 'ngrok', 'Rclone']
    for tool in tool_names:
        if tool.lower() in summary_text.lower():
            tools.add(tool)
    iocs['tools'] = list(tools)
    
    # === TIMESTAMPS ===
    timestamp_pattern = r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}'
    iocs['timestamps'] = list(set(re.findall(timestamp_pattern, summary_text)))
    
    # === MALWARE INDICATION ===
    malware_keywords = ['malware', 'malicious', 'trojan', 'ransomware', 'cobalt strike',
                        'psexec', 'mimikatz', 'enumeration', 'exfiltration', 'lateral movement',
                        'command and control', 'c2', 'beacon', 'backdoor']
    iocs['malware_indicated'] = any(kw in summary_text.lower() for kw in malware_keywords)
    
    logger.info(f"[TRIAGE] Regex extracted IOCs: {sum(len(v) for v in iocs.values() if isinstance(v, list))} total")
    return iocs


def extract_from_search_results(results: List[Dict]) -> Tuple[Set[str], Set[str], Set[str]]:
    """
    Extract IPs, hostnames, and usernames from OpenSearch results.
    Handles both EVTX and EDR event formats.
    """
    ips = set()
    hostnames = set()
    usernames = set()
    
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    
    for hit in results:
        src = hit['_source']
        blob = src.get('search_blob', '')
        
        # === IPs from blob ===
        for ip in re.findall(ip_pattern, blob):
            if not ip.startswith(('127.', '0.', '255.')):
                ips.add(ip)
        
        # === EVTX: computer_name field ===
        computer = src.get('computer_name')
        if computer and computer not in ['-', 'N/A', None, '']:
            hostnames.add(computer.upper())
        
        # === EVTX: User patterns from blob ===
        for match in re.findall(r'(?:TargetUserName|SubjectUserName|AccountName)[:\s]+([A-Za-z0-9_\-\.]+)', blob):
            if match.lower() not in NOISE_USERS and not is_machine_account(match):
                usernames.add(match)
        
        # === EVTX: Workstation from blob ===
        for ws in re.findall(r'WorkstationName[:\s]+([A-Za-z0-9\-]+)', blob):
            if ws and ws != '-' and len(ws) > 2:
                hostnames.add(ws.upper())
        
        # === EDR: Nested host field ===
        host = src.get('host', {})
        if isinstance(host, dict):
            h = host.get('hostname') or host.get('name')
            if h:
                hostnames.add(h.upper())
            host_ip = host.get('ip')
            if host_ip:
                if isinstance(host_ip, list):
                    ips.update([ip for ip in host_ip if not ip.startswith('127.')])
                elif isinstance(host_ip, str) and not host_ip.startswith('127.'):
                    ips.add(host_ip)
        
        # === EDR: Nested process.user and process.user_logon ===
        process = src.get('process', {})
        if isinstance(process, dict):
            proc_user = process.get('user', {})
            if isinstance(proc_user, dict):
                name = proc_user.get('name')
                domain = proc_user.get('domain', '')
                if name and name.lower() not in NOISE_USERS and not is_machine_account(name):
                    usernames.add(f"{domain}\\{name}" if domain else name)
            
            logon = process.get('user_logon', {})
            if isinstance(logon, dict):
                name = logon.get('username')
                domain = logon.get('domain', '')
                ws = logon.get('workstation')
                logon_ip = logon.get('ip')
                if name and name.lower() not in NOISE_USERS and not is_machine_account(name):
                    usernames.add(f"{domain}\\{name}" if domain else name)
                if ws:
                    hostnames.add(ws.upper())
                if logon_ip and not logon_ip.startswith('127.'):
                    ips.add(logon_ip)
    
    return ips, hostnames, usernames


def extract_recon_from_results(results: List[Dict]) -> Tuple[Set[str], Set[str]]:
    """
    Extract recon commands and executables from search results.
    """
    commands = set()
    executables = set()
    
    for hit in results:
        src = hit['_source']
        blob = src.get('search_blob', '')
        
        # EDR process data
        process = src.get('process', {})
        if isinstance(process, dict):
            cmd_line = process.get('command_line', '')
            exe = process.get('executable', '')
            
            if cmd_line and any(t in cmd_line.lower() for t in ['nltest', 'net group', 'net user', 'whoami', 'domain_trust']):
                commands.add(cmd_line[:200])
            
            if exe and any(t in exe.lower() for t in ['nltest', 'net.exe', 'whoami', 'ipconfig']):
                executables.add(exe)
        
        # EVTX blob patterns
        nltest_match = re.search(r'(nltest[^\r\n]{0,100})', blob, re.IGNORECASE)
        if nltest_match:
            cmd = nltest_match.group(1).strip()
            if len(cmd) > 6:
                commands.add(cmd)
        
        net_match = re.search(r'(net\.exe\s+(?:group|user|localgroup)[^\r\n]{0,100})', blob, re.IGNORECASE)
        if net_match:
            cmd = net_match.group(1).strip()
            if len(cmd) > 8:
                commands.add(cmd)
    
    return commands, executables


def search_ioc(opensearch_client, case_id: int, search_term: str, max_results: int = 500) -> Tuple[List[Dict], int]:
    """
    Search for an IOC using the standard search mechanism.
    """
    from search_utils import build_search_query, execute_search
    
    query_dsl = build_search_query(
        search_text=search_term,
        filter_type="all",
        date_range="all",
        custom_date_start=None,
        custom_date_end=None,
        file_types=['EVTX', 'EDR', 'JSON', 'CSV', 'IIS'],
        tagged_event_ids=None,
        latest_event_timestamp=None,
        hidden_filter="hide"
    )
    
    results, total, aggs = execute_search(
        opensearch_client,
        f"case_{case_id}",
        query_dsl,
        page=1,
        per_page=max_results
    )
    
    return results, total


def extract_defender_threats(opensearch_client, case_id: int, search_terms: List[str]) -> Set[str]:
    """
    Search for Defender threat events and extract threat names.
    """
    threats = set()
    
    for term in search_terms:
        try:
            query = {
                "query": {"query_string": {"query": f"*{term}*"}},
                "size": 50
            }
            result = opensearch_client.search(index=f"case_{case_id}", body=query)
            
            for hit in result['hits']['hits']:
                src = hit['_source']
                event = src.get('Event', {})
                event_data_str = event.get('EventData', '{}')
                
                try:
                    if isinstance(event_data_str, str):
                        event_data = json.loads(event_data_str)
                        threat_name = event_data.get('Threat Name', '')
                        if threat_name:
                            threats.add(threat_name)
                except (json.JSONDecodeError, TypeError):
                    pass
        except Exception as e:
            logger.warning(f"[TRIAGE] Defender search error for '{term}': {e}")
    
    return threats


@triage_report_bp.route('/case/<int:case_id>/triage-report/extract', methods=['POST'])
@login_required
def extract_from_report(case_id):
    """
    Extract IOCs from pasted report text.
    Returns extracted items for preview before processing.
    """
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot use triage'}), 403
    
    from main import db
    from models import Case
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    report_text = request.json.get('report_text', '').strip()
    if not report_text:
        return jsonify({'success': False, 'error': 'Report text is required'}), 400
    
    if len(report_text) > 50000:  # 50KB limit
        return jsonify({'success': False, 'error': 'Report text too long (max 50KB)'}), 400
    
    # Try LLM extraction first, fall back to regex
    iocs = extract_iocs_with_llm(report_text)
    
    # If LLM returned empty or failed, use regex
    if not any(iocs.get(k) for k in iocs if k != 'malware_indicated'):
        logger.info("[TRIAGE] LLM extraction empty, using regex fallback")
        iocs = extract_iocs_with_regex(report_text)
    
    # Count total IOCs (excluding timestamps and malware_indicated flag)
    ioc_count = sum(len(v) for k, v in iocs.items() if isinstance(v, list) and k not in ['timestamps'])
    hostname_count = len(iocs.get('hostnames', []))
    malware_indicated = iocs.get('malware_indicated', False)
    
    return jsonify({
        'success': True,
        'iocs': iocs,
        'ioc_count': ioc_count,
        'hostname_count': hostname_count,
        'malware_indicated': malware_indicated
    })


@triage_report_bp.route('/case/<int:case_id>/triage-report/process', methods=['POST'])
@login_required
def process_triage_report(case_id):
    """
    Full triage process:
    1. Extract IOCs from report
    2. Hunt IOCs to discover new IOCs
    3. Hunt malware/recon indicators
    4. Add all IOCs to database
    
    Returns progress updates and final report.
    """
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot use triage'}), 403
    
    from main import db, opensearch_client
    from models import Case, IOC, System
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    report_text = request.json.get('report_text', '').strip()
    if not report_text:
        return jsonify({'success': False, 'error': 'Report text is required'}), 400
    
    # Track all progress and results
    progress_log = []
    
    def log_progress(phase: str, message: str):
        progress_log.append({'phase': phase, 'message': message})
        logger.info(f"[TRIAGE] [{phase}] {message}")
    
    # =========================================================================
    # PHASE 1: EXTRACT IOCs FROM REPORT
    # =========================================================================
    log_progress('Phase 1', 'Extracting IOCs from report...')
    
    iocs = extract_iocs_with_llm(report_text)
    if not any(iocs.get(k) for k in iocs if k != 'malware_indicated'):
        iocs = extract_iocs_with_regex(report_text)
    
    # Track known and discovered IOCs
    known_ips = set(iocs.get('ips', []))
    known_hostnames = set(h.upper() for h in iocs.get('hostnames', []))
    known_usernames = set(u.lower() for u in iocs.get('usernames', []))
    
    discovered_ips = set()
    discovered_hostnames = set()
    discovered_usernames = set()
    discovered_commands = set()
    discovered_paths = set()
    discovered_filenames = set()
    discovered_threats = set()
    
    malware_indicated = iocs.get('malware_indicated', False)
    
    log_progress('Phase 1', f'Extracted {len(known_ips)} IPs, {len(known_hostnames)} hostnames, {len(known_usernames)} usernames')
    log_progress('Phase 1', f'Malware indicated: {malware_indicated}')
    
    # Check if case has events indexed
    try:
        result = opensearch_client.count(index=f"case_{case_id}")
        total_events = result['count']
        log_progress('Phase 1', f'Case has {total_events} events indexed')
    except Exception as e:
        log_progress('Phase 1', f'Warning: Could not count events: {e}')
        total_events = 0
    
    # =========================================================================
    # PHASE 2: STANDARD IOC HUNTING
    # =========================================================================
    if total_events > 0:
        log_progress('Phase 2', 'Hunting IOCs to discover related indicators...')
        
        # Hunt IPs
        for ip in list(known_ips)[:10]:  # Limit to first 10
            log_progress('Phase 2', f'Searching IP: {ip}')
            results, total = search_ioc(opensearch_client, case_id, ip)
            if total > 0:
                ips, hosts, users = extract_from_search_results(results)
                new_ips = ips - known_ips - discovered_ips
                new_hosts = hosts - known_hostnames - discovered_hostnames
                new_users = {u for u in users if u.lower() not in known_usernames and u.lower() not in {x.lower() for x in discovered_usernames}}
                
                discovered_ips.update(new_ips)
                discovered_hostnames.update(new_hosts)
                discovered_usernames.update(new_users)
                
                log_progress('Phase 2', f'  → Found {total} events, +{len(new_ips)} IPs, +{len(new_hosts)} hosts, +{len(new_users)} users')
        
        # Hunt hostnames
        for hostname in list(known_hostnames)[:10]:
            log_progress('Phase 2', f'Searching hostname: {hostname}')
            results, total = search_ioc(opensearch_client, case_id, hostname)
            if total > 0:
                ips, hosts, users = extract_from_search_results(results)
                new_ips = ips - known_ips - discovered_ips
                new_users = {u for u in users if u.lower() not in known_usernames and u.lower() not in {x.lower() for x in discovered_usernames}}
                
                discovered_ips.update(new_ips)
                discovered_usernames.update(new_users)
                
                log_progress('Phase 2', f'  → Found {total} events, +{len(new_ips)} IPs, +{len(new_users)} users')
        
        # Hunt usernames
        for username in list(known_usernames)[:10]:
            log_progress('Phase 2', f'Searching username: {username}')
            results, total = search_ioc(opensearch_client, case_id, username)
            if total > 0:
                ips, hosts, users = extract_from_search_results(results)
                new_ips = ips - known_ips - discovered_ips
                new_hosts = hosts - known_hostnames - discovered_hostnames
                
                discovered_ips.update(new_ips)
                discovered_hostnames.update(new_hosts)
                
                log_progress('Phase 2', f'  → Found {total} events, +{len(new_ips)} IPs, +{len(new_hosts)} hosts')
        
        log_progress('Phase 2', f'Phase 2 complete: +{len(discovered_ips)} IPs, +{len(discovered_hostnames)} hosts, +{len(discovered_usernames)} users')
    
    # =========================================================================
    # PHASE 3: MALWARE/RECON HUNTING
    # =========================================================================
    if total_events > 0:
        log_progress('Phase 3', 'Hunting malware and recon indicators...')
        
        # Search for recon commands
        for term in RECON_SEARCH_TERMS:
            results, total = search_ioc(opensearch_client, case_id, term)
            if total > 0:
                log_progress('Phase 3', f'  "{term}" → {total} events')
                commands, executables = extract_recon_from_results(results)
                discovered_commands.update(commands)
                discovered_filenames.update(executables)
        
        # Search for tools mentioned in report
        tools = iocs.get('tools', [])
        for tool in tools:
            results, total = search_ioc(opensearch_client, case_id, tool)
            if total > 0:
                log_progress('Phase 3', f'  Tool "{tool}" → {total} events')
                # Extract any paths or executables
                for hit in results:
                    src = hit['_source']
                    process = src.get('process', {})
                    if isinstance(process, dict):
                        exe = process.get('executable', '')
                        if exe and tool.lower() in exe.lower():
                            discovered_filenames.add(exe)
        
        # Check Defender events if malware indicated
        if malware_indicated:
            log_progress('Phase 3', 'Checking Defender events...')
            search_terms = iocs.get('processes', []) + iocs.get('tools', [])
            if search_terms:
                threats = extract_defender_threats(opensearch_client, case_id, search_terms)
                discovered_threats.update(threats)
                if threats:
                    log_progress('Phase 3', f'  Found {len(threats)} Defender threat(s)')
        
        log_progress('Phase 3', f'Phase 3 complete: {len(discovered_commands)} commands, {len(discovered_filenames)} files, {len(discovered_threats)} threats')
    
    # =========================================================================
    # PHASE 4: ADD TO DATABASE
    # =========================================================================
    log_progress('Phase 4', 'Adding IOCs to database...')
    
    # Build complete IOC list with deduplication
    # Track seen values to avoid duplicates (same value with different types)
    seen_values = set()
    all_iocs = []
    
    def add_ioc(ioc_type, value, is_active, description):
        """Add IOC if not already seen (case-insensitive dedup)."""
        if not value or len(str(value)) < 2:
            return
        value_lower = str(value).lower().strip()
        if value_lower in seen_values:
            return
        seen_values.add(value_lower)
        all_iocs.append((ioc_type, str(value).strip(), is_active, description))
    
    # From report - IPs
    for ip in iocs.get('ips', []):
        add_ioc('ip', ip, True, 'Extracted from report')
    
    # From report - Hostnames
    for hostname in iocs.get('hostnames', []):
        add_ioc('hostname', hostname, True, 'Extracted from report')
    
    # From report - Usernames
    for username in iocs.get('usernames', []):
        add_ioc('username', username, True, 'Extracted from report')
    
    # From report - SIDs (inactive by default)
    for sid in iocs.get('sids', []):
        add_ioc('user_sid', sid, False, 'Extracted from report')
    
    # From report - Paths (add these BEFORE processes to prioritize full paths)
    for path in iocs.get('paths', []):
        add_ioc('filepath', path, True, 'Extracted from report')
    
    # From report - Processes (standalone exe names only, full paths already in paths)
    for proc in iocs.get('processes', []):
        add_ioc('filename', proc, True, 'Extracted from report')
    
    # From report - Hashes
    for h in iocs.get('hashes', []):
        add_ioc('hash', h, True, 'Extracted from report')
    
    # From report - Commands (inactive by default)
    for cmd in iocs.get('commands', []):
        add_ioc('command', cmd[:500], False, 'Extracted from report')
    
    # From report - Tools (inactive by default)
    for tool in iocs.get('tools', []):
        add_ioc('tool', tool, False, 'Extracted from report')
    
    # Discovered - IPs
    for ip in discovered_ips:
        add_ioc('ip', ip, True, 'Discovered via hunting')
    
    # Discovered - Hostnames
    for hostname in discovered_hostnames:
        add_ioc('hostname', hostname, True, 'Discovered via hunting')
    
    # Discovered - Usernames
    for username in discovered_usernames:
        add_ioc('username', username, True, 'Discovered via hunting')
    
    # Discovered - Commands (inactive by default)
    for cmd in discovered_commands:
        add_ioc('command', cmd[:500], False, 'Discovered via recon hunting')
    
    # Discovered - Filenames
    for filename in discovered_filenames:
        add_ioc('filepath', filename, True, 'Discovered via recon hunting')
    
    # Discovered - Threats (inactive by default)
    for threat in discovered_threats:
        add_ioc('threat', threat, False, 'Defender threat detection')
    
    # Add IOCs to database
    iocs_added = 0
    iocs_skipped = 0
    
    for ioc_type, ioc_value, is_active, description in all_iocs:
        if not ioc_value or len(str(ioc_value)) < 2:
            continue
        
        existing = IOC.query.filter_by(
            case_id=case_id,
            ioc_type=ioc_type,
            ioc_value=str(ioc_value)
        ).first()
        
        if existing:
            iocs_skipped += 1
            continue
        
        try:
            new_ioc = IOC(
                case_id=case_id,
                ioc_type=ioc_type,
                ioc_value=str(ioc_value),
                description=description,
                threat_level='medium',
                created_by=current_user.id,
                is_active=is_active
            )
            db.session.add(new_ioc)
            iocs_added += 1
        except Exception as e:
            logger.warning(f"[TRIAGE] Failed to add IOC {ioc_value}: {e}")
    
    # Add Systems (hostnames)
    systems_added = 0
    all_hostnames = set(iocs.get('hostnames', [])) | discovered_hostnames
    
    for hostname in all_hostnames:
        if not hostname or len(hostname) < 2:
            continue
        
        existing = System.query.filter_by(
            case_id=case_id,
            system_name=hostname
        ).first()
        
        if not existing:
            try:
                new_system = System(
                    case_id=case_id,
                    system_name=hostname,
                    system_type='workstation',
                    added_by=current_user.username,
                    hidden=False
                )
                db.session.add(new_system)
                systems_added += 1
            except Exception as e:
                logger.warning(f"[TRIAGE] Failed to add system {hostname}: {e}")
    
    db.session.commit()
    
    log_progress('Phase 4', f'Added {iocs_added} IOCs (skipped {iocs_skipped} existing), {systems_added} systems')
    
    # =========================================================================
    # BUILD FINAL REPORT
    # =========================================================================
    
    # Categorize all IOCs for the report
    report = {
        'from_report': {
            'ips': iocs.get('ips', []),
            'hostnames': iocs.get('hostnames', []),
            'usernames': iocs.get('usernames', []),
            'sids': iocs.get('sids', []),
            'paths': iocs.get('paths', []),
            'processes': iocs.get('processes', []),
            'hashes': iocs.get('hashes', []),
            'commands': iocs.get('commands', []),
            'tools': iocs.get('tools', []),
        },
        'discovered': {
            'ips': list(discovered_ips),
            'hostnames': list(discovered_hostnames),
            'usernames': list(discovered_usernames),
            'commands': list(discovered_commands),
            'filenames': list(discovered_filenames),
            'threats': list(discovered_threats),
        },
        'summary': {
            'iocs_added': iocs_added,
            'iocs_skipped': iocs_skipped,
            'systems_added': systems_added,
            'malware_indicated': malware_indicated,
            'total_events_searched': total_events,
        },
        'progress_log': progress_log,
        'guidance': (
            "Review the discovered IOCs and set appropriate status:\n"
            "• ACTIVE: Will be hunted when files are indexed\n"
            "• INACTIVE: Stored for reference, not actively hunted\n\n"
            "Recommended:\n"
            "• Set SIDs, commands, and tools to INACTIVE (too noisy)\n"
            "• Keep IPs, hostnames, usernames ACTIVE for hunting\n"
            "• Do NOT delete IOCs - set to INACTIVE instead to prevent re-creation"
        )
    }
    
    logger.info(f"[TRIAGE] Case {case_id}: Complete - {iocs_added} IOCs added, {systems_added} systems")
    
    return jsonify({
        'success': True,
        'report': report
    })


@triage_report_bp.route('/case/<int:case_id>/triage-report/process-stream', methods=['POST'])
@login_required  
def process_triage_report_stream(case_id):
    """
    Stream progress updates for the triage process.
    Uses Server-Sent Events to update the modal in real-time.
    """
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot use triage'}), 403
    
    from main import db, opensearch_client
    from models import Case, IOC, System
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    report_text = request.json.get('report_text', '').strip()
    if not report_text:
        return jsonify({'success': False, 'error': 'Report text is required'}), 400
    
    def generate():
        """Generator for SSE stream"""
        
        def send_update(phase: str, message: str, data: dict = None):
            event = {'phase': phase, 'message': message}
            if data:
                event['data'] = data
            yield f"data: {json.dumps(event)}\n\n"
        
        # Phase 1: Extract
        yield from send_update('Phase 1', 'Extracting IOCs from report...')
        
        iocs = extract_iocs_with_llm(report_text)
        if not any(iocs.get(k) for k in iocs if k != 'malware_indicated'):
            iocs = extract_iocs_with_regex(report_text)
        
        known_ips = set(iocs.get('ips', []))
        known_hostnames = set(h.upper() for h in iocs.get('hostnames', []))
        known_usernames = set(u.lower() for u in iocs.get('usernames', []))
        malware_indicated = iocs.get('malware_indicated', False)
        
        yield from send_update('Phase 1', f'Extracted {len(known_ips)} IPs, {len(known_hostnames)} hostnames, {len(known_usernames)} usernames')
        
        # Check event count
        try:
            result = opensearch_client.count(index=f"case_{case_id}")
            total_events = result['count']
            yield from send_update('Phase 1', f'Case has {total_events} events indexed')
        except:
            total_events = 0
        
        discovered_ips = set()
        discovered_hostnames = set()
        discovered_usernames = set()
        discovered_commands = set()
        discovered_filenames = set()
        discovered_threats = set()
        
        # Phase 2: Hunt IOCs
        if total_events > 0:
            yield from send_update('Phase 2', 'Hunting IOCs to discover related indicators...')
            
            for ip in list(known_ips)[:10]:
                yield from send_update('Phase 2', f'Searching IP: {ip}')
                results, total = search_ioc(opensearch_client, case_id, ip)
                if total > 0:
                    ips, hosts, users = extract_from_search_results(results)
                    discovered_ips.update(ips - known_ips)
                    discovered_hostnames.update(hosts - known_hostnames)
                    discovered_usernames.update({u for u in users if u.lower() not in known_usernames})
            
            for hostname in list(known_hostnames)[:10]:
                yield from send_update('Phase 2', f'Searching hostname: {hostname}')
                results, total = search_ioc(opensearch_client, case_id, hostname)
                if total > 0:
                    ips, hosts, users = extract_from_search_results(results)
                    discovered_ips.update(ips - known_ips - discovered_ips)
                    discovered_usernames.update({u for u in users if u.lower() not in known_usernames})
            
            for username in list(known_usernames)[:10]:
                yield from send_update('Phase 2', f'Searching username: {username}')
                results, total = search_ioc(opensearch_client, case_id, username)
                if total > 0:
                    ips, hosts, users = extract_from_search_results(results)
                    discovered_ips.update(ips - known_ips - discovered_ips)
                    discovered_hostnames.update(hosts - known_hostnames - discovered_hostnames)
            
            yield from send_update('Phase 2', f'Discovered: +{len(discovered_ips)} IPs, +{len(discovered_hostnames)} hosts, +{len(discovered_usernames)} users')
        
        # Phase 3: Recon hunting
        if total_events > 0:
            yield from send_update('Phase 3', 'Hunting malware and recon indicators...')
            
            for term in RECON_SEARCH_TERMS:
                results, total = search_ioc(opensearch_client, case_id, term)
                if total > 0:
                    yield from send_update('Phase 3', f'"{term}" → {total} events')
                    commands, executables = extract_recon_from_results(results)
                    discovered_commands.update(commands)
                    discovered_filenames.update(executables)
            
            if malware_indicated:
                yield from send_update('Phase 3', 'Checking Defender events...')
                search_terms = iocs.get('processes', []) + iocs.get('tools', [])
                if search_terms:
                    threats = extract_defender_threats(opensearch_client, case_id, search_terms)
                    discovered_threats.update(threats)
                    if threats:
                        yield from send_update('Phase 3', f'Found {len(threats)} Defender threat(s)')
        
        # Phase 4: Add to database
        yield from send_update('Phase 4', 'Adding IOCs to database...')
        
        # Build IOC list with deduplication
        seen_values = set()
        all_iocs = []
        
        def add_ioc(ioc_type, value, is_active, description):
            """Add IOC if not already seen (case-insensitive dedup)."""
            if not value or len(str(value)) < 2:
                return
            value_lower = str(value).lower().strip()
            if value_lower in seen_values:
                return
            seen_values.add(value_lower)
            all_iocs.append((ioc_type, str(value).strip(), is_active, description))
        
        for ip in iocs.get('ips', []):
            add_ioc('ip', ip, True, 'Extracted from report')
        for hostname in iocs.get('hostnames', []):
            add_ioc('hostname', hostname, True, 'Extracted from report')
        for username in iocs.get('usernames', []):
            add_ioc('username', username, True, 'Extracted from report')
        for sid in iocs.get('sids', []):
            add_ioc('user_sid', sid, False, 'Extracted from report')
        # Paths first (full paths), then processes (standalone exe names)
        for path in iocs.get('paths', []):
            add_ioc('filepath', path, True, 'Extracted from report')
        for proc in iocs.get('processes', []):
            add_ioc('filename', proc, True, 'Extracted from report')
        for h in iocs.get('hashes', []):
            add_ioc('hash', h, True, 'Extracted from report')
        for cmd in iocs.get('commands', []):
            add_ioc('command', cmd[:500], False, 'Extracted from report')
        for tool in iocs.get('tools', []):
            add_ioc('tool', tool, False, 'Extracted from report')
        
        for ip in discovered_ips:
            add_ioc('ip', ip, True, 'Discovered via hunting')
        for hostname in discovered_hostnames:
            add_ioc('hostname', hostname, True, 'Discovered via hunting')
        for username in discovered_usernames:
            add_ioc('username', username, True, 'Discovered via hunting')
        for cmd in discovered_commands:
            add_ioc('command', cmd[:500], False, 'Discovered via recon hunting')
        for filename in discovered_filenames:
            add_ioc('filepath', filename, True, 'Discovered via recon hunting')
        for threat in discovered_threats:
            add_ioc('threat', threat, False, 'Defender threat detection')
        
        iocs_added = 0
        iocs_skipped = 0
        
        for ioc_type, ioc_value, is_active, description in all_iocs:
            if not ioc_value or len(str(ioc_value)) < 2:
                continue
            
            existing = IOC.query.filter_by(
                case_id=case_id,
                ioc_type=ioc_type,
                ioc_value=str(ioc_value)
            ).first()
            
            if existing:
                iocs_skipped += 1
                continue
            
            try:
                new_ioc = IOC(
                    case_id=case_id,
                    ioc_type=ioc_type,
                    ioc_value=str(ioc_value),
                    description=description,
                    threat_level='medium',
                    created_by=current_user.id,
                    is_active=is_active
                )
                db.session.add(new_ioc)
                iocs_added += 1
            except Exception as e:
                logger.warning(f"[TRIAGE] Failed to add IOC {ioc_value}: {e}")
        
        systems_added = 0
        all_hostnames = set(iocs.get('hostnames', [])) | discovered_hostnames
        
        for hostname in all_hostnames:
            if not hostname or len(hostname) < 2:
                continue
            
            existing = System.query.filter_by(
                case_id=case_id,
                system_name=hostname
            ).first()
            
            if not existing:
                try:
                    new_system = System(
                        case_id=case_id,
                        system_name=hostname,
                        system_type='workstation',
                        added_by=current_user.username,
                        hidden=False
                    )
                    db.session.add(new_system)
                    systems_added += 1
                except:
                    pass
        
        db.session.commit()
        
        yield from send_update('Phase 4', f'Added {iocs_added} IOCs (skipped {iocs_skipped} existing), {systems_added} systems')
        
        # Final report
        report = {
            'from_report': {
                'ips': iocs.get('ips', []),
                'hostnames': iocs.get('hostnames', []),
                'usernames': iocs.get('usernames', []),
                'sids': iocs.get('sids', []),
                'paths': iocs.get('paths', []),
                'processes': iocs.get('processes', []),
                'hashes': iocs.get('hashes', []),
                'commands': iocs.get('commands', []),
                'tools': iocs.get('tools', []),
            },
            'discovered': {
                'ips': list(discovered_ips),
                'hostnames': list(discovered_hostnames),
                'usernames': list(discovered_usernames),
                'commands': list(discovered_commands),
                'filenames': list(discovered_filenames),
                'threats': list(discovered_threats),
            },
            'summary': {
                'iocs_added': iocs_added,
                'iocs_skipped': iocs_skipped,
                'systems_added': systems_added,
                'malware_indicated': malware_indicated,
            }
        }
        
        yield f"data: {json.dumps({'phase': 'Complete', 'message': 'Triage complete!', 'report': report})}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


# ============================================================================
# AI TRIAGE SEARCH ROUTES (v1.39.0)
# Full 9-phase automated attack chain analysis
# ============================================================================

@triage_report_bp.route('/case/<int:case_id>/ai-triage-search/pre-check')
@login_required
def ai_triage_pre_check(case_id):
    """
    Check pre-requisites before allowing AI Triage Search to run.
    Returns status of:
    - EDR Report: Does the case have an EDR/MDR report?
    - Systems Discovery: Has "Find Systems" been run? (systems with added_by='CaseScope')
    
    v1.43.2: Added to ensure proper triage preparation
    """
    from main import db
    from models import Case, System
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Check for EDR report
    has_edr_report = bool(case.edr_report and case.edr_report.strip())
    
    # Check for auto-discovered systems (added_by='CaseScope' means from Find Systems)
    auto_discovered_count = db.session.query(System).filter_by(
        case_id=case_id,
        added_by='CaseScope'
    ).count()
    
    # Also get total systems count
    total_systems = db.session.query(System).filter_by(
        case_id=case_id,
        hidden=False
    ).count()
    
    # Systems discovery is considered done if we have any auto-discovered systems
    systems_discovered = auto_discovered_count > 0
    
    # All checks passed?
    ready = has_edr_report and systems_discovered
    
    return jsonify({
        'ready': ready,
        'has_edr_report': has_edr_report,
        'systems_discovered': systems_discovered,
        'auto_discovered_count': auto_discovered_count,
        'total_systems': total_systems,
        'edr_report_preview': (case.edr_report[:500] + '...') if case.edr_report and len(case.edr_report) > 500 else case.edr_report
    })


@triage_report_bp.route('/case/<int:case_id>/ai-triage-search/run', methods=['POST'])
@login_required
def run_ai_triage_search(case_id):
    """
    Start a new AI Triage Search for a case.
    Creates an AITriageSearch record and kicks off the Celery task.
    """
    from main import db
    from models import Case, AITriageSearch
    from tasks import run_ai_triage_search as run_triage_task
    
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot run AI Triage Search'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    try:
        # Create the search record
        search = AITriageSearch(
            case_id=case_id,
            generated_by=current_user.id,
            status='pending'
        )
        db.session.add(search)
        db.session.commit()
        
        # Start the Celery task
        task = run_triage_task.delay(search.id)
        
        # Store task ID
        search.celery_task_id = task.id
        db.session.commit()
        
        logger.info(f"[AI_TRIAGE] Started search {search.id} for case {case_id} (task: {task.id})")
        
        return jsonify({
            'success': True,
            'search_id': search.id,
            'task_id': task.id
        })
        
    except Exception as e:
        logger.error(f"[AI_TRIAGE] Failed to start search: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@triage_report_bp.route('/case/<int:case_id>/ai-triage-search/<int:search_id>/status')
@login_required
def get_ai_triage_status(case_id, search_id):
    """
    Get the current status of an AI Triage Search.
    Used for polling during the search process.
    """
    from main import db
    from models import AITriageSearch
    import json
    
    search = db.session.get(AITriageSearch, search_id)
    if not search or search.case_id != case_id:
        return jsonify({'error': 'Search not found'}), 404
    
    response = {
        'status': search.status,
        'phase': search.current_phase or 0,
        'phase_name': search.current_phase_name or 'Starting',
        'message': search.progress_message or 'Initializing...',
        'percent': search.progress_percent or 0,
        'error_message': search.error_message
    }
    
    # Add counts if completed
    if search.status == 'completed':
        response.update({
            'iocs_extracted': search.iocs_extracted_count,
            'iocs_discovered': search.iocs_discovered_count,
            'events_analyzed': search.events_analyzed_count,
            'timeline_events': search.timeline_events_count,
            'auto_tagged': search.auto_tagged_count,
            'techniques_found': search.techniques_found_count,
            'process_trees': search.process_trees_count,
            'generation_time': search.generation_time_seconds
        })
    
    return jsonify(response)


@triage_report_bp.route('/case/<int:case_id>/ai-triage-searches')
@login_required
def list_ai_triage_searches(case_id):
    """
    List all AI Triage Searches for a case.
    Used by the case dashboard to display in AI Analysis section.
    """
    from main import db
    from models import AITriageSearch, User
    
    searches = AITriageSearch.query.filter_by(case_id=case_id).order_by(
        AITriageSearch.created_at.desc()
    ).all()
    
    result = []
    for s in searches:
        user = db.session.get(User, s.generated_by)
        result.append({
            'id': s.id,
            'status': s.status,
            'entry_point': s.entry_point,
            'iocs_extracted': s.iocs_extracted_count,
            'iocs_discovered': s.iocs_discovered_count,
            'auto_tagged': s.auto_tagged_count,
            'techniques_found': s.techniques_found_count,
            'timeline_events': s.timeline_events_count,
            'generation_time': s.generation_time_seconds,
            'created_at': s.created_at.isoformat() if s.created_at else None,
            'completed_at': s.completed_at.isoformat() if s.completed_at else None,
            'generated_by': user.username if user else 'Unknown',
            'error_message': s.error_message
        })
    
    return jsonify(result)


@triage_report_bp.route('/ai-triage-search/<int:search_id>/view')
@login_required
def view_ai_triage_search(search_id):
    """
    View the full AI Triage Search report.
    Shows IOCs extracted, discovered, timeline, MITRE techniques, process trees.
    """
    import json
    from main import db
    from models import AITriageSearch, Case, User
    
    search = AITriageSearch.query.get_or_404(search_id)
    case = Case.query.get(search.case_id)
    user = db.session.get(User, search.generated_by)
    
    # Parse JSON fields
    iocs_extracted = {}
    iocs_discovered = {}
    timeline = []
    process_trees = []
    mitre_techniques = {}
    summary = {}
    
    try:
        if search.iocs_extracted_json:
            iocs_extracted = json.loads(search.iocs_extracted_json)
    except:
        pass
    
    try:
        if search.iocs_discovered_json:
            iocs_discovered = json.loads(search.iocs_discovered_json)
    except:
        pass
    
    try:
        if search.timeline_json:
            timeline = json.loads(search.timeline_json)
    except:
        pass
    
    try:
        if search.process_trees_json:
            process_trees = json.loads(search.process_trees_json)
    except:
        pass
    
    try:
        if search.mitre_techniques_json:
            mitre_techniques = json.loads(search.mitre_techniques_json)
    except:
        pass
    
    try:
        if search.summary_json:
            summary = json.loads(search.summary_json)
    except:
        pass
    
    return render_template('view_ai_triage_search.html',
        search=search,
        case=case,
        user=user,
        iocs_extracted=iocs_extracted,
        iocs_discovered=iocs_discovered,
        timeline=timeline,
        process_trees=process_trees,
        mitre_techniques=mitre_techniques,
        summary=summary
    )
