"""
AI Triage - EDR IOC Extraction Module

Extracts IOCs (Indicators of Compromise) from EDR/MDR reports.
This module is a standalone phase that can be triggered manually or as part of triage.

Flow:
1. Check if AI is enabled in system settings
2. If AI enabled: Try LLM extraction (QWEN), fall back to regex on failure
3. If AI disabled: Go straight to regex extraction
4. Return structured IOC dictionary

Usage:
    from ai_triage_edr_ioc import extract_iocs_from_report
    
    iocs = extract_iocs_from_report(report_text)
    # Returns: {'ips': [...], 'hostnames': [...], 'usernames': [...], ...}
"""

import re
import json
import logging
from typing import Dict, List, Set, Tuple, Optional

logger = logging.getLogger(__name__)


# ============================================================================
# SYSTEM SETTINGS CHECK
# ============================================================================

def is_ai_enabled() -> bool:
    """
    Check if AI is enabled in system settings.
    Returns False if setting not found or set to 'false'.
    """
    try:
        from models import SystemSettings
        setting = SystemSettings.query.filter_by(setting_key='ai_enabled').first()
        return setting and setting.setting_value == 'true'
    except Exception as e:
        logger.warning(f"[EDR_IOC] Failed to check AI setting: {e}")
        return False


def get_ollama_host() -> str:
    """Get configured Ollama host from system settings."""
    try:
        from models import SystemSettings
        setting = SystemSettings.query.filter_by(setting_key='ollama_host').first()
        return setting.setting_value if setting else 'http://localhost:11434'
    except Exception:
        return 'http://localhost:11434'


# ============================================================================
# VALIDATION HELPERS
# ============================================================================

def is_valid_hostname(hostname: str, ip_set: Set[str]) -> bool:
    """
    Validate hostname - must be alphanumeric with optional hyphens,
    not an IP, and reasonable length.
    """
    if not hostname or len(hostname) < 2 or len(hostname) > 64:
        return False
    if hostname in ip_set:
        return False
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        return False
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$', hostname):
        return False
    return True


# ============================================================================
# LLM-BASED IOC EXTRACTION (AI ENABLED)
# ============================================================================

def extract_iocs_with_llm(report_text: str) -> Dict:
    """
    Use LLM to extract structured IOCs from EDR/security report.
    
    Uses QWEN model (dfir-qwen:latest) which has been fine-tuned for
    security report analysis and IOC extraction.
    
    Returns empty dict on failure (caller should fall back to regex).
    """
    import requests
    
    host = get_ollama_host()
    model = 'dfir-qwen:latest'  # Hardcoded for best IOC extraction accuracy
    
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
{report_text}
"""
    
    logger.info(f"[EDR_IOC] Calling LLM ({model}) for IOC extraction...")
    
    try:
        response = requests.post(
            f"{host}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=120
        )
        
        if response.status_code == 200:
            result = response.json().get('response', '')
            logger.info(f"[EDR_IOC] LLM response received ({len(result)} chars)")
            
            # Try to parse JSON from response
            json_match = re.search(r'\{[\s\S]*\}', result)
            if json_match:
                try:
                    iocs = json.loads(json_match.group())
                    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
                    logger.info(f"[EDR_IOC] LLM extracted {total_iocs} IOCs successfully")
                    return iocs
                except json.JSONDecodeError as e:
                    logger.warning(f"[EDR_IOC] LLM returned invalid JSON: {e}")
            else:
                logger.warning(f"[EDR_IOC] No JSON found in LLM response")
        else:
            logger.warning(f"[EDR_IOC] LLM HTTP error: {response.status_code}")
        
    except requests.exceptions.Timeout:
        logger.warning(f"[EDR_IOC] LLM request timed out (120s)")
    except requests.exceptions.ConnectionError:
        logger.warning(f"[EDR_IOC] Cannot connect to Ollama at {host}")
    except Exception as e:
        logger.warning(f"[EDR_IOC] LLM extraction failed: {e}")
    
    return {}  # Empty dict signals failure - caller should use regex


# ============================================================================
# REGEX-BASED IOC EXTRACTION (FALLBACK / AI DISABLED)
# ============================================================================

def extract_iocs_with_regex(report_text: str) -> Dict:
    """
    Extract IOCs using regex patterns.
    Used when AI is disabled or LLM fails.
    
    Extracts:
    - IP addresses (validated format)
    - Hashes (SHA256, SHA1, MD5)
    - Windows SIDs (S-1-5-21-...)
    - Usernames (from context patterns)
    - Hostnames (computer names)
    - File paths (Windows paths)
    - Processes (executable names)
    - Commands (PowerShell, recon tools)
    - Tools (known attack/admin tools)
    - Timestamps (ISO 8601 format)
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
    
    # === IP ADDRESSES ===
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    # Also handle defanged IPs like 91.236.230[.]136
    defanged_text = re.sub(r'\[?\.\]?', '.', report_text)
    iocs['ips'] = list(set(re.findall(ip_pattern, defanged_text)))
    ip_set = set(iocs['ips'])
    
    # === HASHES ===
    # SHA256 (64 hex chars)
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    iocs['hashes'].extend(re.findall(sha256_pattern, report_text))
    # MD5 (32 hex chars)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    iocs['hashes'].extend(re.findall(md5_pattern, report_text))
    # SHA1 (40 hex chars)
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    iocs['hashes'].extend(re.findall(sha1_pattern, report_text))
    iocs['hashes'] = list(set(iocs['hashes']))
    
    # === WINDOWS SIDs ===
    sid_pattern = r'S-1-5-21-[\d-]+'
    iocs['sids'] = list(set(re.findall(sid_pattern, report_text)))
    
    # === USERNAMES ===
    usernames = set()
    # From quoted contexts
    for match in re.findall(r'user\s*["\']([^"\']+)["\']', report_text, re.IGNORECASE):
        usernames.add(match)
    for match in re.findall(r'account\s*["\']([^"\']+)["\']', report_text, re.IGNORECASE):
        usernames.add(match)
    # Username / SID pattern (extract username part)
    for match in re.findall(r"['\"]?([a-zA-Z0-9_\-\.]+)['\"]?\s*/\s*S-1-5-", report_text):
        if match and len(match) > 2:
            usernames.add(match)
    # Filter noise
    noise_users = {'system', 'administrator', 'admin', 'user', 'guest', 'default', 'local', 'service'}
    iocs['usernames'] = [u for u in usernames if u.lower() not in noise_users and len(u) > 1]
    
    # === HOSTNAMES ===
    hostnames = set()
    for match in re.findall(r'host\s*["\']([^"\']+)["\']', report_text, re.IGNORECASE):
        hostname_part = match.split()[0] if match.split() else match
        if is_valid_hostname(hostname_part, ip_set):
            hostnames.add(hostname_part)
    for match in re.findall(r'machine\s*["\']([^"\']+)["\']', report_text, re.IGNORECASE):
        hostname_part = match.split()[0].strip() if match.split() else match.strip()
        if is_valid_hostname(hostname_part, ip_set):
            hostnames.add(hostname_part)
    for match in re.findall(r'[Hh]ost\s*name[:\s]+([A-Za-z0-9\-_]+)', report_text):
        if is_valid_hostname(match, ip_set):
            hostnames.add(match)
    for match in re.findall(r'endpoint\s+([A-Za-z0-9\-_]+)', report_text, re.IGNORECASE):
        if is_valid_hostname(match, ip_set):
            hostnames.add(match)
    iocs['hostnames'] = list(hostnames)
    
    # === FILE PATHS ===
    path_pattern = r"[A-Za-z]:\\(?:[^\s\\/:*?\"<>|']+\\)+[^\s\\/:*?\"<>|']*"
    raw_paths = list(set(re.findall(path_pattern, report_text)))
    cleaned_paths = []
    for p in raw_paths:
        p = p.rstrip("'\".,;:")
        if len(p) >= 10:
            cleaned_paths.append(p)
    iocs['paths'] = cleaned_paths
    
    # === PROCESSES ===
    processes = set()
    for match in re.findall(r'(?:executed|ran|launched|spawned|running|process)\s+["\']?([a-zA-Z0-9_\-]+\.exe)["\']?', report_text, re.IGNORECASE):
        processes.add(match)
    # Known dangerous processes
    dangerous_procs = ['nltest.exe', 'net.exe', 'whoami.exe', 'mimikatz.exe', 'psexec.exe', 
                       'wmic.exe', 'powershell.exe', 'cmd.exe', 'certutil.exe', 'bitsadmin.exe']
    for proc in dangerous_procs:
        if proc.lower() in report_text.lower():
            processes.add(proc)
    iocs['processes'] = list(processes)
    
    # === COMMANDS ===
    commands = set()
    # PowerShell commands
    ps_commands = re.findall(r'powershell(?:\.exe)?\s+[\-/][^\n]{10,}', report_text, re.IGNORECASE)
    for cmd in ps_commands:
        commands.add(cmd.strip()[:500])
    # Recon commands
    for pattern in [r'nltest(?:\.exe)?\s+[^\n]+', r'net(?:\.exe)?\s+(?:group|user|localgroup)[^\n]+',
                    r'whoami(?:\.exe)?[^\n]*', r'wmic\s+[^\n]+']:
        for cmd in re.findall(pattern, report_text, re.IGNORECASE):
            commands.add(cmd.strip()[:500])
    iocs['commands'] = list(commands)
    
    # === TOOLS ===
    tools = set()
    tool_names = ['WinSCP', 'Advanced IP Scanner', 'PSEXEC', 'Mimikatz', 'Cobalt Strike',
                  'BlueVPS', 'AnyDesk', 'TeamViewer', 'ngrok', 'Rclone', 'PuTTY', 'WinRAR',
                  '7-Zip', 'FileZilla', 'Remote Desktop', 'RDP', 'ProxyShell', 'Impacket']
    for tool in tool_names:
        if tool.lower() in report_text.lower():
            tools.add(tool)
    iocs['tools'] = list(tools)
    
    # === TIMESTAMPS ===
    timestamp_pattern = r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}'
    iocs['timestamps'] = list(set(re.findall(timestamp_pattern, report_text)))
    
    # === DOMAINS ===
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz)\b'
    domains = set(re.findall(domain_pattern, report_text, re.IGNORECASE))
    # Filter out common safe domains
    safe_domains = {'microsoft.com', 'windows.com', 'google.com', 'github.com', 'amazonaws.com'}
    iocs['domains'] = [d for d in domains if d.lower() not in safe_domains]
    
    # === REGISTRY KEYS ===
    registry_pattern = r'HK(?:LM|CU|CR|U|CC)\\[^\s"\'<>]+'
    iocs['registry_keys'] = list(set(re.findall(registry_pattern, report_text)))
    
    # === MALWARE INDICATION ===
    malware_keywords = ['malware', 'malicious', 'trojan', 'ransomware', 'cobalt strike',
                        'psexec', 'mimikatz', 'enumeration', 'exfiltration', 'lateral movement',
                        'command and control', 'c2', 'beacon', 'backdoor', 'threat actor',
                        'compromise', 'intrusion', 'attack', 'breach']
    iocs['malware_indicated'] = any(kw in report_text.lower() for kw in malware_keywords)
    
    # === THREAT TYPES ===
    threat_keywords = {
        'enumeration': ['nltest', 'net group', 'whoami', 'discovery', 'enumerat'],
        'lateral_movement': ['lateral', 'psexec', 'wmi', 'remote', 'rdp'],
        'exfiltration': ['exfil', 'winscp', 'rclone', 'upload', 'transfer'],
        'persistence': ['persist', 'scheduled task', 'registry', 'startup'],
        'credential_access': ['mimikatz', 'credential', 'password', 'hash', 'lsass'],
        'initial_access': ['phish', 'exploit', 'vulnerability', 'cve-']
    }
    for threat_type, keywords in threat_keywords.items():
        if any(kw in report_text.lower() for kw in keywords):
            iocs['threat_types'].append(threat_type)
    
    total = sum(len(v) for v in iocs.values() if isinstance(v, list))
    logger.info(f"[EDR_IOC] Regex extracted {total} IOCs")
    return iocs


# ============================================================================
# MAIN EXTRACTION FUNCTION
# ============================================================================

def extract_iocs_from_report(report_text: str, force_regex: bool = False) -> Dict:
    """
    Extract IOCs from EDR/MDR report text.
    
    Flow:
    1. If force_regex=True, skip AI entirely
    2. Check if AI is enabled in system settings
    3. If AI enabled: Try LLM, fall back to regex on failure
    4. If AI disabled: Use regex directly
    
    Args:
        report_text: The EDR/MDR report text to extract IOCs from
        force_regex: If True, skip AI and use regex only
        
    Returns:
        Dict with categorized IOCs:
        {
            'usernames': [...],
            'ips': [...],
            'hostnames': [...],
            'processes': [...],
            'paths': [...],
            'hashes': [...],
            'commands': [...],
            'tools': [...],
            'timestamps': [...],
            'sids': [...],
            'domains': [...],
            'registry_keys': [...],
            'services': [...],
            'threat_types': [...],
            'malware_indicated': bool,
            'extraction_method': 'llm' | 'regex'
        }
    """
    if not report_text or not report_text.strip():
        logger.warning("[EDR_IOC] Empty report text provided")
        return {'extraction_method': 'none', 'error': 'Empty report'}
    
    # Force regex mode
    if force_regex:
        logger.info("[EDR_IOC] Force regex mode - skipping AI")
        iocs = extract_iocs_with_regex(report_text)
        iocs['extraction_method'] = 'regex'
        return iocs
    
    # Check AI setting
    ai_enabled = is_ai_enabled()
    
    if ai_enabled:
        logger.info("[EDR_IOC] AI enabled - attempting LLM extraction")
        iocs = extract_iocs_with_llm(report_text)
        
        if iocs:
            iocs['extraction_method'] = 'llm'
            return iocs
        else:
            logger.info("[EDR_IOC] LLM failed - falling back to regex")
            iocs = extract_iocs_with_regex(report_text)
            iocs['extraction_method'] = 'regex_fallback'
            return iocs
    else:
        logger.info("[EDR_IOC] AI disabled - using regex extraction")
        iocs = extract_iocs_with_regex(report_text)
        iocs['extraction_method'] = 'regex'
        return iocs


def get_ioc_summary(iocs: Dict) -> Dict:
    """
    Get a summary of extracted IOCs for display.
    
    Returns:
        Dict with counts and key items
    """
    summary = {
        'total_count': 0,
        'by_type': {},
        'malware_indicated': iocs.get('malware_indicated', False),
        'extraction_method': iocs.get('extraction_method', 'unknown'),
        'threat_types': iocs.get('threat_types', [])
    }
    
    for key, value in iocs.items():
        if isinstance(value, list) and key not in ['threat_types', 'services']:
            count = len(value)
            if count > 0:
                summary['by_type'][key] = count
                summary['total_count'] += count
    
    return summary

