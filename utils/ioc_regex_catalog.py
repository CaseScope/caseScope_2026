"""Shared regex IOC catalog used by the extraction facade."""

from __future__ import annotations

import re
from typing import Dict, List


WINDOWS_PATH_PATTERN = re.compile(
    r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+'
)


IOC_TYPE_MAP: Dict[str, str] = {
    'md5': 'MD5 Hash',
    'sha1': 'SHA1 Hash',
    'sha256': 'SHA256 Hash',
    'sha512': 'SHA256 Hash',
    'ip_v4': 'IP Address (IPv4)',
    'ip_v6': 'IP Address (IPv6)',
    'domain': 'Domain',
    'fqdn': 'FQDN',
    'url': 'URL',
    'hostname': 'Hostname',
    'file_path': 'File Path',
    'file_name': 'File Name',
    'username': 'Username',
    'email': 'Email Address',
    'registry_key': 'Registry Key',
    'registry_value': 'Registry Value',
    'command_line': 'Command Line',
    'process_name': 'Process Name',
    'process_path': 'Process Path',
    'service_name': 'Service Name',
    'scheduled_task': 'Scheduled Task',
    'password': 'Password',
    'ssh_key': 'SSH Key Fingerprint',
    'api_key': 'API Key',
    'cve': 'CVE',
    'threat_name': 'Threat Name',
}


IOC_CATEGORY_MAP: Dict[str, str] = {
    'md5': 'File',
    'sha1': 'File',
    'sha256': 'File',
    'sha512': 'File',
    'ip_v4': 'Network',
    'ip_v6': 'Network',
    'domain': 'Network',
    'fqdn': 'Network',
    'url': 'Network',
    'hostname': 'Network',
    'file_path': 'File',
    'file_name': 'File',
    'username': 'Authentication',
    'email': 'Email',
    'registry_key': 'Registry',
    'registry_value': 'Registry',
    'command_line': 'Process',
    'process_name': 'Process',
    'process_path': 'Process',
    'service_name': 'Process',
    'scheduled_task': 'Process',
    'password': 'Authentication',
    'ssh_key': 'Authentication',
    'api_key': 'Authentication',
    'cve': 'Vulnerability',
    'threat_name': 'Threat Intel',
}


REGEX_IOC_PATTERNS = {
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'ip_v4': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|[\[\(]\.[\]\)])){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
    'ip_v6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|\bfe80::[0-9a-fA-F:]+\b'),
    'email': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
    'url': re.compile(r'(?:hxxps?|https?)(?:\[?://\]?|://)[\w\-\.]+(?:\[\.\]|\.)[\w\-\.]+[^\s<>"{}|\\^`\[\]]*', re.I),
    'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.))+(?:com|net|org|io|top|de|es|co|xyz|info|biz|ru|cn|uk|ca|au|zapto|anondns|ikhelp|trycloudflare)\b', re.I),
    'file_path_windows': WINDOWS_PATH_PATTERN,
    'file_path_unc': re.compile(r'\\\\[^\s<>"|?*\n]+'),
    'file_path_unix': re.compile(r'(?:^|[\s"])(/(?:usr|bin|etc|var|tmp|home|opt|sbin|lib|ProgramData|inetpub)[^\s<>"|?*\n]+)'),
    'registry_key': re.compile(r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR)\\[^\s\n"]+', re.I),
    'sid': re.compile(r'S-1-\d+-\d+(?:-\d+)+'),
    'cve': re.compile(r'CVE-\d{4}-\d{4,7}', re.I),
    'threat_name': re.compile(r'Threat Name:\s*([^\n\r]+)', re.I),
    'malware_family': re.compile(r'Malware Family(?:\s+as)?\s+([^\n\r.]+)', re.I),
    'service_name': re.compile(r'(?:Delete Service\s*-\s*name:\s*)([^\n+]+)', re.I),
    'scheduled_task': re.compile(r'C:\\WINDOWS\\System32\\Tasks\\[^\s\n"]+', re.I),
    'screenconnect_id': re.compile(r'ScreenConnect Client \(([a-f0-9]{16})\)', re.I),
    'vnc_connection_id': re.compile(r'-autoreconnect\s+ID:(\d+)', re.I),
    'net_user_password': re.compile(r'net\s+user\s+(\S+)\s+(\S+)\s+/add', re.I),
    'smb_creds': re.compile(r'net\s+use\s+[^\s]+\s+/user:(\S+)\s+(\S+)', re.I),
    'encoded_powershell': re.compile(r'-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{50,})', re.I),
    'exchange_version': re.compile(r'Exchange v(\d+\.\d+\.\d+\.\d+)', re.I),
    'cloudflare_tunnel': re.compile(r'[a-z\-]+\.trycloudflare\.com', re.I),
    'parent_process': re.compile(r'Parent Process:\s*([^\n]+)', re.I),
}


REGEX_EXTRACTOR_RMM_TOOLS: List[str] = [
    'screenconnect', 'connectwise', 'netsupport', 'anydesk', 'ultravnc',
    'simplehelp', 'atera', 'splashtop', 'gotoassist', 'centrastage',
    'datto', 'teamviewer', 'logmein', 'bomgar',
]


REGEX_EXTRACTOR_MALWARE_FAMILIES: List[str] = [
    'qakbot', 'dridex', 'socgholish', 'gootloader', 'cobalt strike',
    'trickbot', 'lunar', 'ursnif', 'fakeupdates',
]
