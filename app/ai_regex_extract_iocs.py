"""
AI Regex IOC Extraction Module

Fallback regex-based IOC extraction when AI is disabled.
Extracts IOCs from EDR/MDR reports using pattern matching.

Designed based on Huntress EDR report format but works with most security reports.
"""

import re
import logging
from typing import Dict, List, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


def extract_iocs_with_regex(report_content: str) -> Dict[str, any]:
    """
    Extract IOCs from EDR/security report using regex patterns.
    
    Args:
        report_content: The EDR report text (may contain multiple reports)
    
    Returns:
        Dictionary with extracted IOCs in same format as AI extraction:
        {
            'ip_addresses': [],
            'domains': [],
            'urls': [],
            'file_paths': [],
            'file_hashes': {'md5': [], 'sha1': [], 'sha256': []},
            'usernames': [],
            'hostnames': [],
            'network_shares': [],
            'credentials': {'usernames': [], 'passwords': []},
            'processes': {'executables': [], 'commands': []},
            'ports': [],
            'protocols': [],
            'timestamps_utc': [],
            'ssh_keys': [],
            'registry_keys': [],
            'email_addresses': []
        }
    """
    logger.info("[REGEX_IOC] Starting regex-based IOC extraction")
    
    iocs = {
        'ip_addresses': [],
        'domains': [],
        'urls': [],
        'file_paths': [],
        'file_hashes': {'md5': [], 'sha1': [], 'sha256': []},
        'usernames': [],
        'hostnames': [],
        'network_shares': [],
        'credentials': {'usernames': [], 'passwords': []},
        'processes': {'executables': [], 'commands': []},
        'ports': [],
        'protocols': [],
        'timestamps_utc': [],
        'ssh_keys': [],
        'registry_keys': [],
        'email_addresses': []
    }
    
    # === IP ADDRESSES ===
    # Match IPv4 addresses, including defanged ones like 77.83.205[.]215
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[\.\[\]]+){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    for match in re.finditer(ip_pattern, report_content):
        ip = match.group().replace('[.]', '.').replace('[', '').replace(']', '')
        # Filter out common non-malicious IPs
        if not ip.startswith(('127.', '0.', '255.')) and ip not in iocs['ip_addresses']:
            iocs['ip_addresses'].append(ip)
    
    # === FILE HASHES ===
    # SHA256 (64 hex chars)
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    for match in re.finditer(sha256_pattern, report_content):
        hash_val = match.group().lower()
        if hash_val not in iocs['file_hashes']['sha256']:
            iocs['file_hashes']['sha256'].append(hash_val)
    
    # SHA1 (40 hex chars)
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    for match in re.finditer(sha1_pattern, report_content):
        hash_val = match.group().lower()
        if hash_val not in iocs['file_hashes']['sha1'] and hash_val not in iocs['file_hashes']['sha256']:
            iocs['file_hashes']['sha1'].append(hash_val)
    
    # MD5 (32 hex chars)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    for match in re.finditer(md5_pattern, report_content):
        hash_val = match.group().lower()
        if (hash_val not in iocs['file_hashes']['md5'] and 
            hash_val not in iocs['file_hashes']['sha1'] and 
            hash_val not in iocs['file_hashes']['sha256']):
            iocs['file_hashes']['md5'].append(hash_val)
    
    # === USERNAMES ===
    # Pattern: "user" or "username" followed by name, or "User: name" format
    username_patterns = [
        r'[Uu]ser[:\s]+"?([a-zA-Z0-9_\-\.]+)"?',
        r'[Uu]sername[:\s]+"?([a-zA-Z0-9_\-\.]+)"?',
        r'logged in as[:\s]+"?([a-zA-Z0-9_\-\.]+)"?',
        r'executing as[:\s]+"?([a-zA-Z0-9_\-\.]+)"?',
        r'account[:\s]+"?([a-zA-Z0-9_\-\.]+)"?',
    ]
    
    for pattern in username_patterns:
        for match in re.finditer(pattern, report_content, re.IGNORECASE):
            username = match.group(1)
            # Filter common noise
            if (len(username) >= 3 and 
                username.lower() not in ['system', 'administrator', 'admin', 'user', 'guest', 'default', 'local', 'service', 'root'] and
                username not in iocs['usernames']):
                iocs['usernames'].append(username)
                iocs['credentials']['usernames'].append(username)
    
    # === HOSTNAMES / COMPUTER NAMES ===
    # Pattern: "Host:" or "Computer:" or "endpoint:" followed by name
    hostname_patterns = [
        r'[Hh]ost[:\s]+([A-Za-z0-9\-_]+)',
        r'[Cc]omputer[:\s]+([A-Za-z0-9\-_]+)',
        r'[Ee]ndpoint[:\s]+([A-Za-z0-9\-_]+)',
        r'[Mm]achine[:\s]+([A-Za-z0-9\-_]+)',
    ]
    
    ip_set = set(iocs['ip_addresses'])
    for pattern in hostname_patterns:
        for match in re.finditer(pattern, report_content):
            hostname = match.group(1)
            # Validate it's not an IP and is reasonable length
            if (len(hostname) >= 2 and len(hostname) <= 64 and 
                hostname not in ip_set and
                not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname) and
                hostname not in iocs['hostnames']):
                iocs['hostnames'].append(hostname)
    
    # === FILE PATHS ===
    # Windows paths (C:\..., \\server\share\...)
    windows_path_pattern = r'[A-Za-z]:\\(?:[^\s\\/:*?"<>|\'\n]+\\)*[^\s\\/:*?"<>|\'\n]*'
    for match in re.finditer(windows_path_pattern, report_content):
        path = match.group().rstrip('.,;:)\'"')
        if len(path) >= 10 and path not in iocs['file_paths']:
            iocs['file_paths'].append(path)
    
    # UNC paths (\\server\share\...)
    unc_pattern = r'\\\\[A-Za-z0-9\-_\.]+\\[^\s\'"]+(?:\\[^\s\'"]+)*'
    for match in re.finditer(unc_pattern, report_content):
        path = match.group().rstrip('.,;:)\'"')
        if len(path) >= 10 and path not in iocs['file_paths'] and path not in iocs['network_shares']:
            # If it's just \\server\share, add to network_shares
            parts = path.split('\\')
            if len(parts) <= 4:  # \\server\share or \\server\share\
                iocs['network_shares'].append(path)
            else:
                iocs['file_paths'].append(path)
    
    # === PROCESSES / EXECUTABLES ===
    # Pattern: executable names (.exe, .dll, .sys)
    executable_pattern = r'\b([a-zA-Z0-9_\-]+\.(?:exe|dll|sys|bat|ps1|cmd|vbs|js))\b'
    for match in re.finditer(executable_pattern, report_content, re.IGNORECASE):
        exe = match.group(1)
        if exe not in iocs['processes']['executables']:
            iocs['processes']['executables'].append(exe)
    
    # === COMMANDS ===
    # Look for command patterns (common malicious commands)
    command_patterns = [
        r'Command[:\s]+["\']?([^"\'\n]{20,500})["\']?',
        r'powershell(?:\.exe)?\s+[\-/][^\n]{20,500}',
        r'cmd(?:\.exe)?\s+/[^\n]{20,500}',
        r'nltest(?:\.exe)?\s+[^\n]+',
        r'net(?:\.exe)?\s+(?:user|group|localgroup|share)[^\n]+',
        r'whoami(?:\.exe)?[^\n]*',
        r'wmic\s+[^\n]+',
        r'reg(?:\.exe)?\s+(?:add|query|delete)[^\n]+',
    ]
    
    for pattern in command_patterns:
        for match in re.finditer(pattern, report_content, re.IGNORECASE):
            cmd = match.group(1) if match.lastindex else match.group()
            cmd = cmd.strip().rstrip('.,;:)\'"')
            if len(cmd) >= 20 and cmd not in iocs['processes']['commands']:
                iocs['processes']['commands'].append(cmd[:500])  # Truncate long commands
    
    # === DOMAINS ===
    # Match domain names (but not IPs)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|tk|club|online|site)\b'
    for match in re.finditer(domain_pattern, report_content, re.IGNORECASE):
        domain = match.group().lower()
        # Filter out common safe domains
        if domain not in ['microsoft.com', 'windows.com', 'google.com', 'github.com', 'huntress.io'] and domain not in iocs['domains']:
            iocs['domains'].append(domain)
    
    # === URLS ===
    # Match full URLs
    url_pattern = r'https?://[^\s<>"\']+|ftp://[^\s<>"\']+'
    for match in re.finditer(url_pattern, report_content, re.IGNORECASE):
        url = match.group().rstrip('.,;:)\'"')
        if url not in iocs['urls']:
            iocs['urls'].append(url)
    
    # === REGISTRY KEYS ===
    registry_pattern = r'HK(?:LM|CU|CR|U|CC)\\[^\s"\'<>\n]+'
    for match in re.finditer(registry_pattern, report_content):
        reg_key = match.group().rstrip('.,;:)\'"')
        if reg_key not in iocs['registry_keys']:
            iocs['registry_keys'].append(reg_key)
    
    # === PORTS ===
    # Match port numbers in context (e.g., ":443", "port 3389")
    port_patterns = [
        r':(\d{2,5})(?:\s|/|$)',
        r'[Pp]ort[:\s]+(\d{2,5})',
    ]
    
    for pattern in port_patterns:
        for match in re.finditer(pattern, report_content):
            port = match.group(1)
            port_num = int(port)
            if 1 <= port_num <= 65535 and port not in iocs['ports']:
                iocs['ports'].append(port)
    
    # === TIMESTAMPS ===
    # Match UTC timestamps in various formats
    timestamp_patterns = [
        r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+UTC',
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',
        r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}',
    ]
    
    for pattern in timestamp_patterns:
        for match in re.finditer(pattern, report_content):
            timestamp = match.group()
            if timestamp not in iocs['timestamps_utc']:
                iocs['timestamps_utc'].append(timestamp)
    
    # === EMAIL ADDRESSES ===
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    for match in re.finditer(email_pattern, report_content):
        email = match.group().lower()
        # Filter out huntress.io emails (from report headers)
        if 'huntress.io' not in email and email not in iocs['email_addresses']:
            iocs['email_addresses'].append(email)
    
    # === PROTOCOLS ===
    # Look for mentioned protocols
    protocol_keywords = ['RDP', 'SSH', 'SMB', 'FTP', 'HTTP', 'HTTPS', 'SFTP', 'WinRM', 'LDAP', 'DNS']
    for keyword in protocol_keywords:
        if re.search(rf'\b{keyword}\b', report_content, re.IGNORECASE):
            protocol = keyword.upper()
            if protocol not in iocs['protocols']:
                iocs['protocols'].append(protocol)
    
    # Log summary
    total_iocs = (
        len(iocs['ip_addresses']) +
        len(iocs['file_hashes']['md5']) +
        len(iocs['file_hashes']['sha1']) +
        len(iocs['file_hashes']['sha256']) +
        len(iocs['usernames']) +
        len(iocs['hostnames']) +
        len(iocs['file_paths']) +
        len(iocs['processes']['executables']) +
        len(iocs['processes']['commands'])
    )
    
    logger.info(f"[REGEX_IOC] Extracted {total_iocs} IOCs using regex patterns")
    logger.info(f"[REGEX_IOC] IP Addresses: {len(iocs['ip_addresses'])}, "
                f"Hashes: {len(iocs['file_hashes']['sha256']) + len(iocs['file_hashes']['sha1']) + len(iocs['file_hashes']['md5'])}, "
                f"File Paths: {len(iocs['file_paths'])}, "
                f"Usernames: {len(iocs['usernames'])}")
    
    return iocs


def split_reports(report_content: str) -> List[str]:
    """
    Split multi-report document into individual reports.
    Reports are separated by '*** NEW REPORT ***'.
    """
    reports = report_content.strip().split('*** NEW REPORT ***')
    reports = [r.strip() for r in reports if r.strip()]
    return reports


def aggregate_iocs(all_iocs: List[dict]) -> dict:
    """
    Aggregate IOCs from multiple dictionaries into a single dictionary.
    Removes duplicates across all reports.
    """
    aggregated = defaultdict(list)
    
    # Initialize nested dicts
    aggregated['file_hashes'] = defaultdict(list)
    aggregated['credentials'] = defaultdict(list)
    aggregated['processes'] = defaultdict(list)
    
    for ioc_set in all_iocs:
        for category, values in ioc_set.items():
            if category in ['file_hashes', 'credentials', 'processes']:
                if isinstance(values, dict):
                    for sub_category, sub_values in values.items():
                        if isinstance(sub_values, list):
                            for item in sub_values:
                                if item and item not in aggregated[category][sub_category]:
                                    aggregated[category][sub_category].append(item)
            elif isinstance(values, list):
                for item in values:
                    if item and item not in aggregated[category]:
                        aggregated[category].append(item)
    
    # Convert defaultdicts back to regular dicts
    final_aggregated = {k: v for k, v in aggregated.items()}
    final_aggregated['file_hashes'] = {k: v for k, v in aggregated['file_hashes'].items()}
    final_aggregated['credentials'] = {k: v for k, v in aggregated['credentials'].items()}
    final_aggregated['processes'] = {k: v for k, v in aggregated['processes'].items()}
    
    return final_aggregated


def extract_iocs_regex_all_reports(
    case_id: int,
    report_content: str
) -> Dict[str, any]:
    """
    Main entry point: Extract IOCs from EDR report(s) using regex patterns.
    
    Handles both single reports and multi-report documents.
    
    Args:
        case_id: The case ID for logging purposes
        report_content: The EDR report content (may contain multiple reports)
    
    Returns:
        Dictionary containing:
        - success: bool
        - iocs: dict (aggregated IOCs from all reports)
        - total_reports: int (number of reports processed)
        - extraction_method: str ('regex')
    """
    if not report_content or not report_content.strip():
        return {
            'success': False,
            'error': 'No report content provided'
        }
    
    logger.info(f"[REGEX_IOC] Starting regex IOC extraction for case {case_id}")
    
    # Split into individual reports if multi-report document
    reports = split_reports(report_content)
    logger.info(f"[REGEX_IOC] Processing {len(reports)} report(s)")
    
    all_extracted_iocs = []
    
    for i, report in enumerate(reports, 1):
        logger.info(f"[REGEX_IOC] Processing report {i}/{len(reports)} ({len(report)} chars)")
        iocs = extract_iocs_with_regex(report)
        all_extracted_iocs.append(iocs)
    
    # Aggregate IOCs from all reports
    logger.info(f"[REGEX_IOC] Aggregating IOCs from {len(all_extracted_iocs)} report(s)")
    final_iocs = aggregate_iocs(all_extracted_iocs)
    
    # Count total IOCs
    total_ioc_count = 0
    for category, items in final_iocs.items():
        if isinstance(items, list):
            total_ioc_count += len(items)
        elif isinstance(items, dict):
            for sub_items in items.values():
                if isinstance(sub_items, list):
                    total_ioc_count += len(sub_items)
    
    logger.info(f"[REGEX_IOC] Extraction complete: {total_ioc_count} IOCs from {len(reports)} report(s)")
    
    return {
        'success': True,
        'iocs': final_iocs,
        'total_reports': len(reports),
        'successful_reports': len(reports),
        'failed_reports': 0,
        'total_ioc_count': total_ioc_count,
        'extraction_method': 'regex'
    }

