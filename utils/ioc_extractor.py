"""IOC Extraction from EDR Reports

Extracts Indicators of Compromise from EDR reports using AI (Ollama)
with regex fallback. Handles deduplication and integration with 
Known Systems and Known Users.

Enhanced based on analysis of 75 real Huntress EDR reports.
"""
import re
import json
import logging
import base64
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

# ============================================
# IOC Type Mappings
# ============================================

# Map extracted IOC types to database IOC types
IOC_TYPE_MAP = {
    'md5': 'MD5 Hash',
    'sha1': 'SHA1 Hash',
    'sha256': 'SHA256 Hash',
    'sha512': 'SHA256 Hash',  # Store as SHA256 for simplicity
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

# Category mappings
IOC_CATEGORY_MAP = {
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


# ============================================
# AI IOC Extraction Prompt (Example-Based)
# ============================================

SYSTEM_PROMPT = """Extract ALL Indicators of Compromise from the security report. Return ONLY valid JSON — no markdown, no explanation, no analysis.

RULES:
1. Extract ONLY concrete indicators that appear in the report text.
2. Do NOT classify, score, or analyze. No MITRE, no severity, no attack type.
3. Empty arrays [] for sections with no data. Never invent values.
4. Defang: hxxp→http, [.]→., [:]→:, [@]→@, [://]→://
5. Skip Huntress portal URLs (tabinc.huntress.io).
6. Preserve command lines exactly as written.

OUTPUT SCHEMA (populate from report only):
{
  "affected_hosts": ["..."],
  "affected_users": [{"username": "...", "sid": "..."}],
  "network_iocs": {
    "ipv4": [{"value": "...", "port": null, "context": "..."}],
    "ipv6": [{"value": "...", "context": "..."}],
    "domains": [{"value": "...", "context": "..."}],
    "urls": [{"value": "...", "context": "..."}],
    "cloudflare_tunnels": ["..."]
  },
  "file_iocs": {
    "hashes": [{"value": "...", "type": "md5|sha1|sha256", "filename": "...", "context": "..."}],
    "file_paths": [{"value": "...", "context": "..."}],
    "file_names": ["..."]
  },
  "process_iocs": {
    "commands": [{"full_command": "...", "executable": "...", "parent_process": "...", "user": "...", "pid": "..."}],
    "services": [{"name": "...", "path": "...", "action": "delete|create"}],
    "scheduled_tasks": [{"name": "...", "path": "...", "command": "..."}]
  },
  "persistence_iocs": {
    "registry": [{"key": "...", "value_name": "...", "value_data": "...", "action": "delete|create"}],
    "credential_theft_indicators": [{"registry_key": "...", "value": "...", "data": "..."}]
  },
  "authentication_iocs": {
    "compromised_users": [{"username": "...", "sid": "..."}],
    "created_users": [{"username": "...", "password": "...", "groups": ["..."]}],
    "passwords_observed": [{"username": "...", "password": "..."}]
  },
  "vulnerability_iocs": {
    "cves": ["CVE-XXXX-XXXXX"],
    "webshells": [{"path": "..."}]
  },
  "raw_artifacts": {
    "encoded_powershell": ["..."],
    "vnc_connection_ids": ["..."],
    "screenconnect_ids": ["..."]
  }
}"""


# ============================================
# Regex-based IOC Extraction (Fallback)
# ============================================

class RegexIOCExtractor:
    """Regex-based IOC extractor as fallback when AI is unavailable"""
    
    # De-obfuscation patterns - comprehensive list based on 75 reports
    DEFANG_PATTERNS = [
        # Protocol defanging
        (re.compile(r'hxxps://', re.I), 'https://'),
        (re.compile(r'hxxp://', re.I), 'http://'),
        (re.compile(r'hxxps\[://\]', re.I), 'https://'),
        (re.compile(r'hxxp\[://\]', re.I), 'http://'),
        (re.compile(r'\[://\]'), '://'),
        (re.compile(r'\[:\]//'), '://'),
        # Dot defanging
        (re.compile(r'\[\.+\]'), '.'),
        (re.compile(r'\(\.+\)'), '.'),
        (re.compile(r'\[dot\]', re.I), '.'),
        (re.compile(r'\(dot\)', re.I), '.'),
        # At symbol defanging
        (re.compile(r'\[at\]', re.I), '@'),
        (re.compile(r'\(at\)', re.I), '@'),
        (re.compile(r'\[@\]'), '@'),
        # Colon defanging
        (re.compile(r'\[:\]'), ':'),
        (re.compile(r'\(:\)'), ':'),
    ]
    
    # IOC Patterns - expanded based on 75 reports
    PATTERNS = {
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        # IPv4 - including defanged format
        'ip_v4': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|[\[\(]\.[\]\)])){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        # IPv6 - full and link-local
        'ip_v6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|\bfe80::[0-9a-fA-F:]+\b'),
        'email': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
        'url': re.compile(r'(?:hxxps?|https?)(?:\[?://\]?|://)[\w\-\.]+(?:\[\.\]|\.)[\w\-\.]+[^\s<>"{}|\\^`\[\]]*', re.I),
        'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.))+(?:com|net|org|io|top|de|es|co|xyz|info|biz|ru|cn|uk|ca|au|zapto|anondns|ikhelp|trycloudflare)\b', re.I),
        'file_path_windows': re.compile(r'[A-Za-z]:\\[^\s<>"|?*\n:]+(?:\.[a-zA-Z0-9]{1,10})?'),
        'file_path_unc': re.compile(r'\\\\[^\s<>"|?*\n]+'),
        'file_path_unix': re.compile(r'(?:^|[\s"])(/(?:usr|bin|etc|var|tmp|home|opt|sbin|lib|ProgramData|inetpub)[^\s<>"|?*\n]+)'),
        'registry_key': re.compile(r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR)\\[^\s\n"]+', re.I),
        'sid': re.compile(r'S-1-\d+-\d+(?:-\d+)+'),
        'cve': re.compile(r'CVE-\d{4}-\d{4,7}', re.I),
        'service_name': re.compile(r'(?:Delete Service\s*-\s*name:\s*)([^\n+]+)', re.I),
        'scheduled_task': re.compile(r'C:\\WINDOWS\\System32\\Tasks\\[^\s\n"]+', re.I),
        'screenconnect_id': re.compile(r'ScreenConnect Client \(([a-f0-9]{16})\)', re.I),
        'vnc_connection_id': re.compile(r'-autoreconnect\s+ID:(\d+)', re.I),
        # Password extraction from net user commands
        'net_user_password': re.compile(r'net\s+user\s+(\S+)\s+(\S+)\s+/add', re.I),
        # SMB credentials
        'smb_creds': re.compile(r'net\s+use\s+[^\s]+\s+/user:(\S+)\s+(\S+)', re.I),
        # PowerShell encoded command
        'encoded_powershell': re.compile(r'-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{50,})', re.I),
        # Exchange version
        'exchange_version': re.compile(r'Exchange v(\d+\.\d+\.\d+\.\d+)', re.I),
        # Cloudflare tunnels
        'cloudflare_tunnel': re.compile(r'[a-z\-]+\.trycloudflare\.com', re.I),
        # Process with parent context
        'parent_process': re.compile(r'Parent Process:\s*([^\n]+)', re.I),
    }
    
    # Known RMM tools to flag
    RMM_TOOLS = [
        'screenconnect', 'connectwise', 'netsupport', 'anydesk', 'ultravnc', 
        'simplehelp', 'atera', 'splashtop', 'gotoassist', 'centrastage',
        'datto', 'teamviewer', 'logmein', 'bomgar'
    ]
    
    # Known malware families from reports
    MALWARE_FAMILIES = [
        'qakbot', 'dridex', 'socgholish', 'gootloader', 'cobalt strike',
        'trickbot', 'lunar', 'ursnif', 'fakeupdates'
    ]
    
    def __init__(self):
        pass
    
    def defang(self, text: str) -> str:
        """De-obfuscate/defang indicators in text"""
        for pattern, replacement in self.DEFANG_PATTERNS:
            text = pattern.sub(replacement, text)
        return text
    
    def extract(self, text: str) -> Dict[str, Any]:
        """Extract IOCs from text using regex patterns"""
        # De-obfuscate first
        clean_text = self.defang(text)
        original_text = text  # Keep original for some patterns
        
        results = {
            'extraction_summary': {
                'method': 'regex',
                'report_date': None,
                'affected_hosts': [],
                'affected_users': [],
                'severity_indicators': [],
                'threat_families': [],
                'isolated': 'isolated' in text.lower()
            },
            'iocs': {
                'hashes': [],
                'ip_addresses': [],
                'domains': [],
                'urls': [],
                'file_paths': [],
                'file_names': [],
                'users': [],
                'sids': [],
                'registry_keys': [],
                'commands': [],
                'processes': [],
                'credentials': [],
                'hostnames': [],
                'timestamps': [],
                'network_shares': [],
                'email_addresses': [],
                'mitre_indicators': [],
                'services': [],
                'scheduled_tasks': [],
                'cves': [],
                'threat_names': [],
            },
            'raw_artifacts': {
                'full_commands': [],
                'filemasks': [],
                'encoded_powershell': [],
                'vnc_connection_ids': [],
                'screenconnect_ids': [],
                'parent_child_chains': [],
            }
        }
        
        # Extract hashes
        for match in self.PATTERNS['md5'].findall(clean_text):
            results['iocs']['hashes'].append({'value': match.lower(), 'type': 'md5', 'context': ''})
        for match in self.PATTERNS['sha1'].findall(clean_text):
            results['iocs']['hashes'].append({'value': match.lower(), 'type': 'sha1', 'context': ''})
        for match in self.PATTERNS['sha256'].findall(clean_text):
            results['iocs']['hashes'].append({'value': match.lower(), 'type': 'sha256', 'context': ''})
        
        # Extract IP addresses (IPv4 and IPv6)
        for match in self.PATTERNS['ip_v4'].findall(clean_text):
            # Clean up any remaining defang artifacts
            clean_ip = self.defang(match)
            if self._is_valid_ipv4(clean_ip):
                results['iocs']['ip_addresses'].append({
                    'value': clean_ip, 
                    'port': None, 
                    'direction': 'unknown',
                    'context': '',
                    'type': 'ipv4'
                })
        
        for match in self.PATTERNS['ip_v6'].findall(clean_text):
            # Filter out timestamps that look like IPv6 (e.g., 09:36:39, 12:30:45)
            # Valid IPv6 has at least 4 colons or fe80:: prefix
            if match.count(':') < 4 and not match.lower().startswith('fe80'):
                # Likely a timestamp, not IPv6
                continue
            results['iocs']['ip_addresses'].append({
                'value': match, 
                'port': None, 
                'direction': 'unknown',
                'context': 'IPv6 address',
                'type': 'ipv6'
            })
        
        # Extract domains
        for match in self.PATTERNS['domain'].findall(clean_text):
            domain = self.defang(match.lower())
            # Skip if it's a Huntress portal URL
            if 'huntress.io' in domain:
                continue
            results['iocs']['domains'].append({'value': domain, 'context': ''})
        
        # Extract Cloudflare tunnels
        for match in self.PATTERNS['cloudflare_tunnel'].findall(clean_text):
            results['iocs']['domains'].append({
                'value': match.lower(), 
                'context': 'Cloudflare Quick Tunnel (potential C2)'
            })
        
        # Extract URLs
        for match in self.PATTERNS['url'].findall(clean_text):
            url = self.defang(match)
            url_type = 'unknown'
            if 'huntress' in url.lower() or 'portal' in url.lower():
                continue  # Skip report URLs
            results['iocs']['urls'].append({'value': url, 'type': url_type, 'context': ''})
        
        # Extract file paths (Windows)
        for match in self.PATTERNS['file_path_windows'].findall(clean_text):
            path = match.rstrip('.,;:')
            results['iocs']['file_paths'].append({
                'value': path,
                'action': 'unknown',
                'context': ''
            })
        
        # Extract file paths (Unix/macOS)
        for match in self.PATTERNS['file_path_unix'].findall(clean_text):
            path = match.rstrip('.,;:')
            results['iocs']['file_paths'].append({
                'value': path,
                'action': 'unknown',
                'context': 'Unix/macOS path'
            })
        
        # Extract UNC paths (network shares)
        for match in self.PATTERNS['file_path_unc'].findall(clean_text):
            results['iocs']['network_shares'].append({
                'value': match.rstrip('.,;:'),
                'context': ''
            })
        
        # Extract registry keys
        for match in self.PATTERNS['registry_key'].findall(clean_text):
            results['iocs']['registry_keys'].append({
                'value': match.rstrip('.,;:'),
                'action': 'unknown',
                'context': ''
            })
        
        # Extract SIDs
        for match in self.PATTERNS['sid'].findall(clean_text):
            results['iocs']['sids'].append(match)
        
        # Extract emails
        for match in self.PATTERNS['email'].findall(clean_text):
            results['iocs']['email_addresses'].append(match.lower())
        
        # Extract CVEs
        for match in self.PATTERNS['cve'].findall(clean_text):
            results['iocs']['cves'].append(match.upper())
        
        # Extract service names from "Delete Service" entries
        for match in self.PATTERNS['service_name'].findall(original_text):
            service = match.strip()
            results['iocs']['services'].append({
                'name': service,
                'action': 'delete',
                'context': 'From remediation'
            })
        
        # Extract scheduled tasks
        for match in self.PATTERNS['scheduled_task'].findall(clean_text):
            results['iocs']['scheduled_tasks'].append({
                'path': match,
                'action': 'delete',
                'context': ''
            })
        
        # Extract ScreenConnect instance IDs
        for match in self.PATTERNS['screenconnect_id'].findall(original_text):
            results['raw_artifacts']['screenconnect_ids'].append(match)
        
        # Extract VNC connection IDs
        for match in self.PATTERNS['vnc_connection_id'].findall(clean_text):
            results['raw_artifacts']['vnc_connection_ids'].append(match)
        
        # Extract encoded PowerShell
        for match in self.PATTERNS['encoded_powershell'].findall(clean_text):
            results['raw_artifacts']['encoded_powershell'].append(match)
        
        # Extract passwords from net user commands
        for match in self.PATTERNS['net_user_password'].findall(clean_text):
            username, password = match
            results['iocs']['credentials'].append({
                'type': 'password',
                'username': username,
                'value': password,
                'context': 'From net user /add command - attacker-created account'
            })
        
        # Extract SMB credentials
        for match in self.PATTERNS['smb_creds'].findall(clean_text):
            username, password = match
            results['iocs']['credentials'].append({
                'type': 'password',
                'username': username,
                'value': password,
                'context': 'SMB share credentials from net use command'
            })
        
        # Extract parent process context
        for match in self.PATTERNS['parent_process'].findall(clean_text):
            parent = match.strip()
            # Check for SQL/IIS exploitation indicators
            if 'sqlservr.exe' in parent.lower():
                results['raw_artifacts']['parent_child_chains'].append({
                    'parent': parent,
                    'context': 'SQL Server xp_cmdshell exploitation'
                })
            elif 'w3wp.exe' in parent.lower():
                results['raw_artifacts']['parent_child_chains'].append({
                    'parent': parent,
                    'context': 'IIS web shell activity'
                })
        
        # Detect threat families
        text_lower = text.lower()
        for family in self.MALWARE_FAMILIES:
            if family in text_lower:
                results['extraction_summary']['threat_families'].append(family.title())
        
        # Detect RMM tools
        for tool in self.RMM_TOOLS:
            if tool in text_lower:
                if tool.title() not in results['extraction_summary']['severity_indicators']:
                    results['extraction_summary']['severity_indicators'].append(f"Rogue {tool.title()}")
        
        # Extract hostnames from JSON fields
        # Common Windows event log fields that contain hostnames
        hostname_fields = [
            r'"Computer"\s*:\s*"([^"]+)"',
            r'"Hostname"\s*:\s*"([^"]+)"',
            r'"hostname"\s*:\s*"([^"]+)"',
            r'"WorkstationName"\s*:\s*"([^"]+)"',
            r'"SourceHostname"\s*:\s*"([^"]+)"',
            r'"DestinationHostname"\s*:\s*"([^"]+)"',
            r'"TargetServerName"\s*:\s*"([^"]+)"',
            r'"host"\s*:\s*"([^"]+)"',
            r'"ComputerName"\s*:\s*"([^"]+)"',
            r'"source_host"\s*:\s*"([^"]+)"',
        ]
        for pattern in hostname_fields:
            for match in re.findall(pattern, original_text, re.IGNORECASE):
                hostname = match.strip()
                # Validate hostname format (not empty, not just IP, reasonable length)
                if hostname and len(hostname) <= 255 and len(hostname) >= 2:
                    # Skip if it looks like an IP address
                    if self.PATTERNS['ip_v4'].match(hostname):
                        continue
                    # Skip common non-hostname values
                    if hostname.lower() in ('-', 'localhost', 'unknown', 'n/a', 'none', 'null'):
                        continue
                    # Extract NetBIOS name if FQDN
                    netbios = hostname.split('.')[0].upper()
                    results['iocs']['hostnames'].append({
                        'value': netbios,
                        'fqdn': hostname if '.' in hostname else None,
                        'context': ''
                    })
        
        # Deduplicate
        results['iocs']['hashes'] = self._dedupe_list_of_dicts(results['iocs']['hashes'], 'value')
        results['iocs']['ip_addresses'] = self._dedupe_list_of_dicts(results['iocs']['ip_addresses'], 'value')
        results['iocs']['urls'] = self._dedupe_list_of_dicts(results['iocs']['urls'], 'value')
        results['iocs']['domains'] = self._dedupe_list_of_dicts(results['iocs']['domains'], 'value')
        results['iocs']['file_paths'] = self._dedupe_list_of_dicts(results['iocs']['file_paths'], 'value')
        results['iocs']['network_shares'] = self._dedupe_list_of_dicts(results['iocs']['network_shares'], 'value')
        results['iocs']['registry_keys'] = self._dedupe_list_of_dicts(results['iocs']['registry_keys'], 'value')
        results['iocs']['services'] = self._dedupe_list_of_dicts(results['iocs']['services'], 'name')
        results['iocs']['hostnames'] = self._dedupe_list_of_dicts(results['iocs']['hostnames'], 'value')
        results['iocs']['sids'] = list(set(results['iocs']['sids']))
        results['iocs']['email_addresses'] = list(set(results['iocs']['email_addresses']))
        results['iocs']['cves'] = list(set(results['iocs']['cves']))
        results['extraction_summary']['threat_families'] = list(set(results['extraction_summary']['threat_families']))
        
        return results
    
    def _is_valid_ipv4(self, ip: str) -> bool:
        """Validate IPv4 address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        return True
    
    def _dedupe_list_of_dicts(self, items: List[Dict], key: str) -> List[Dict]:
        """Deduplicate a list of dicts by a key"""
        seen = set()
        unique = []
        for item in items:
            val = item.get(key, '').lower()
            if val and val not in seen:
                seen.add(val)
                unique.append(item)
        return unique


# ============================================
# AI IOC Extraction
# ============================================

def extract_iocs_with_ai(report_text: str, model: str = None) -> Tuple[Dict[str, Any], bool]:
    """
    Extract IOCs from report text using a hybrid AI + regex approach.

    Flow:
      1. AI disabled  -> regex only, advise user
      2. AI enabled but call fails -> regex fallback, advise user
      3. AI enabled and succeeds -> AI first, then regex, then merge; advise user

    Returns:
        Tuple of (extraction_result, used_ai_bool)
    """
    regex_extractor = RegexIOCExtractor()

    from models.system_settings import SystemSettings, SettingKeys
    ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)

    if not ai_enabled:
        logger.info("AI extraction disabled, using regex only")
        result = regex_extractor.extract(report_text)
        result['extraction_summary']['method'] = 'regex_only'
        result['extraction_summary']['method_detail'] = (
            'AI is not enabled. Extraction used pattern matching only. '
            'Enable AI in settings for richer contextual extraction.'
        )
        return result, False

    # --- AI is enabled, attempt the call ---
    ai_extraction = None
    resolved_model = model or ''
    try:
        from utils.ai_providers import get_llm_provider

        MAX_REPORT_LENGTH = 16000
        truncated_text = report_text
        if len(truncated_text) > MAX_REPORT_LENGTH:
            truncated_text = truncated_text[:MAX_REPORT_LENGTH] + "\n\n[... REPORT TRUNCATED FOR PROCESSING ...]"
            logger.info(f"Report truncated from {len(report_text)} to {MAX_REPORT_LENGTH} chars")

        if '-filemask="' in truncated_text:
            idx = truncated_text.find('-filemask="')
            end = truncated_text.find('"', idx + 100)
            if end > idx:
                truncated_text = truncated_text[:idx+50] + '...[FILEMASK TRUNCATED]...' + truncated_text[end:]

        provider = get_llm_provider(model_override=model, function='ioc_extraction')
        resolved_model = getattr(provider, 'model', '') or model or ''

        user_prompt = (
            "Extract ALL IOCs from this Huntress EDR security report. "
            "Be thorough - capture everything:\n\n" + truncated_text
        )

        ai_result = provider.generate_json(
            prompt=user_prompt,
            system=SYSTEM_PROMPT,
            temperature=0.0,
            max_tokens=4000,
        )

        if ai_result.get('success'):
            ai_extraction = _normalize_ai_extraction(ai_result['data'])
        else:
            logger.warning(f"AI extraction failed: {ai_result.get('error')}")

    except Exception as e:
        logger.warning(f"AI extraction call failed: {e}")

    # --- AI failed entirely -> regex fallback ---
    if ai_extraction is None:
        logger.info("AI unavailable, falling back to regex only")
        result = regex_extractor.extract(report_text)
        result['extraction_summary']['method'] = 'regex_fallback'
        result['extraction_summary']['method_detail'] = (
            'AI extraction failed. Fell back to pattern matching only. '
            'Check AI provider settings and connectivity.'
        )
        return result, False

    # --- AI succeeded -> run regex and merge ---
    regex_extraction = regex_extractor.extract(report_text)
    merged = _merge_extractions(ai_extraction, regex_extraction)

    merged['extraction_summary'] = merged.get('extraction_summary', {})
    merged['extraction_summary']['method'] = 'ai_plus_regex'
    merged['extraction_summary']['model'] = resolved_model
    merged['extraction_summary']['method_detail'] = (
        'Extraction used AI for contextual analysis then pattern matching '
        'to catch any IOCs the model missed.'
    )

    return merged, True


def _merge_extractions(
    ai: Dict[str, Any],
    regex: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Merge AI and regex extraction results.

    Strategy:
      - AI is primary for semantic / contextual fields (extraction_summary,
        mitre_indicators, threat_names, commands with rich context).
      - Regex fills gaps for pattern-matchable IOCs (hashes, IPs, domains,
        URLs, file_paths, SIDs, CVEs, registry_keys, emails).
      - Deduplication by normalised value so nothing is doubled.
      - raw_artifacts are merged additively.
    """
    merged = {
        'extraction_summary': ai.get('extraction_summary', {}),
        'iocs': {},
        'raw_artifacts': {},
    }

    ai_iocs = ai.get('iocs', {})
    regex_iocs = regex.get('iocs', {})

    all_keys = set(list(ai_iocs.keys()) + list(regex_iocs.keys()))

    for key in all_keys:
        ai_items = ai_iocs.get(key, [])
        regex_items = regex_iocs.get(key, [])

        if not ai_items and not regex_items:
            merged['iocs'][key] = []
            continue

        if not ai_items:
            merged['iocs'][key] = list(regex_items)
            continue

        if not regex_items:
            merged['iocs'][key] = list(ai_items)
            continue

        seen = set()
        combined = []

        for item in ai_items:
            norm_val = _extract_dedup_key(item)
            if norm_val and norm_val not in seen:
                seen.add(norm_val)
                combined.append(item)
            elif not norm_val:
                combined.append(item)

        for item in regex_items:
            norm_val = _extract_dedup_key(item)
            if norm_val and norm_val not in seen:
                seen.add(norm_val)
                combined.append(item)

        merged['iocs'][key] = combined

    # Merge raw_artifacts additively
    ai_raw = ai.get('raw_artifacts', {})
    regex_raw = regex.get('raw_artifacts', {})
    all_raw_keys = set(list(ai_raw.keys()) + list(regex_raw.keys()))
    for key in all_raw_keys:
        ai_vals = ai_raw.get(key, [])
        regex_vals = regex_raw.get(key, [])
        if isinstance(ai_vals, list) and isinstance(regex_vals, list):
            seen = set()
            combined = []
            for v in ai_vals + regex_vals:
                norm = str(v).lower().strip() if v else ''
                if norm and norm not in seen:
                    seen.add(norm)
                    combined.append(v)
                elif not norm:
                    combined.append(v)
            merged['raw_artifacts'][key] = combined
        else:
            merged['raw_artifacts'][key] = ai_vals or regex_vals

    return merged


def _extract_dedup_key(item) -> Optional[str]:
    """
    Get a normalised deduplication key from an IOC item.
    Handles dicts (with 'value', 'name', or 'path' keys) and plain strings.
    """
    if isinstance(item, dict):
        val = (
            item.get('value')
            or item.get('name')
            or item.get('path')
            or item.get('key')
            or ''
        )
        return val.strip().lower() if val else None
    if isinstance(item, str):
        return item.strip().lower() if item else None
    return str(item).strip().lower() if item else None


def _normalize_ai_extraction(extraction: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize AI extraction output to our expected format.
    Handles variations in AI response structure.
    """
    normalized = {
        'extraction_summary': extraction.get('extraction_summary', {}),
        'iocs': {
            'hashes': [],
            'ip_addresses': [],
            'domains': [],
            'urls': [],
            'file_paths': [],
            'file_names': [],
            'users': [],
            'sids': [],
            'registry_keys': [],
            'commands': [],
            'processes': [],
            'credentials': [],
            'hostnames': [],
            'timestamps': [],
            'network_shares': [],
            'email_addresses': [],
            'mitre_indicators': [],
            'services': [],
            'scheduled_tasks': [],
            'cves': [],
            'threat_names': [],
        },
        'raw_artifacts': extraction.get('raw_artifacts', {})
    }
    
    # Map from new structure to old structure for compatibility
    
    # Network IOCs
    network = extraction.get('network_iocs', {})
    for ip in network.get('ipv4', []):
        if isinstance(ip, dict):
            ip['type'] = 'ipv4'
            normalized['iocs']['ip_addresses'].append(ip)
        else:
            normalized['iocs']['ip_addresses'].append({'value': ip, 'type': 'ipv4'})
    
    for ip in network.get('ipv6', []):
        if isinstance(ip, dict):
            ip['type'] = 'ipv6'
            normalized['iocs']['ip_addresses'].append(ip)
        else:
            normalized['iocs']['ip_addresses'].append({'value': ip, 'type': 'ipv6'})
    
    for domain in network.get('domains', []):
        if isinstance(domain, dict):
            normalized['iocs']['domains'].append(domain)
        else:
            normalized['iocs']['domains'].append({'value': domain})
    
    for tunnel in network.get('cloudflare_tunnels', []):
        normalized['iocs']['domains'].append({
            'value': tunnel,
            'context': 'Cloudflare Quick Tunnel (potential C2)'
        })
    
    for url in network.get('urls', []):
        if isinstance(url, dict):
            normalized['iocs']['urls'].append(url)
        else:
            normalized['iocs']['urls'].append({'value': url})
    
    # File IOCs
    file_iocs = extraction.get('file_iocs', {})
    for h in file_iocs.get('hashes', []):
        if isinstance(h, dict):
            normalized['iocs']['hashes'].append(h)
        else:
            normalized['iocs']['hashes'].append({'value': h})
    
    for fp in file_iocs.get('file_paths', []):
        if isinstance(fp, dict):
            normalized['iocs']['file_paths'].append(fp)
        else:
            normalized['iocs']['file_paths'].append({'value': fp})
    
    for fn in file_iocs.get('file_names', []):
        normalized['iocs']['file_names'].append(fn)
    
    # Process IOCs
    process_iocs = extraction.get('process_iocs', {})
    for cmd in process_iocs.get('commands', []):
        if isinstance(cmd, dict):
            # Map new structure to old
            mapped = {
                'value': cmd.get('full_command', ''),
                'executable': cmd.get('executable', ''),
                'context': cmd.get('context', ''),
                'parent': cmd.get('parent_process', ''),
                'user': cmd.get('user', ''),
                'pid': cmd.get('pid', '')
            }
            normalized['iocs']['commands'].append(mapped)
        else:
            normalized['iocs']['commands'].append({'value': cmd})
    
    for svc in process_iocs.get('services', []):
        if isinstance(svc, dict):
            normalized['iocs']['services'].append(svc)
        else:
            normalized['iocs']['services'].append({'name': svc})
    
    for task in process_iocs.get('scheduled_tasks', []):
        if isinstance(task, dict):
            normalized['iocs']['scheduled_tasks'].append(task)
        else:
            normalized['iocs']['scheduled_tasks'].append({'name': task})
    
    # Persistence IOCs
    persistence = extraction.get('persistence_iocs', {})
    for reg in persistence.get('registry', []):
        if isinstance(reg, dict):
            # Combine key and value into full path
            key = reg.get('key', '')
            value_name = reg.get('value_name', '')
            normalized['iocs']['registry_keys'].append({
                'value': key,
                'value_name': value_name,
                'value_data': reg.get('value_data', ''),
                'action': reg.get('action', 'unknown'),
                'context': reg.get('context', '')
            })
    
    # Credential theft indicators
    for cred_theft in persistence.get('credential_theft_indicators', []):
        if isinstance(cred_theft, dict):
            normalized['iocs']['registry_keys'].append({
                'value': cred_theft.get('registry_key', ''),
                'value_name': cred_theft.get('value', ''),
                'value_data': cred_theft.get('data', ''),
                'context': f"Credential theft: {cred_theft.get('context', '')}"
            })
    
    # Authentication IOCs
    auth = extraction.get('authentication_iocs', {})
    for user in auth.get('compromised_users', []):
        if isinstance(user, dict):
            normalized['iocs']['users'].append(user)
        else:
            normalized['iocs']['users'].append({'value': user})
    
    for user in auth.get('created_users', []):
        if isinstance(user, dict):
            # Add created users as both users and credentials
            normalized['iocs']['users'].append({
                'value': user.get('username', ''),
                'context': 'Attacker-created account',
                'sid': user.get('sid', '')
            })
            if user.get('password'):
                normalized['iocs']['credentials'].append({
                    'type': 'password',
                    'username': user.get('username', ''),
                    'value': user.get('password', ''),
                    'context': 'Attacker-created account password'
                })
    
    for cred in auth.get('passwords_observed', []):
        if isinstance(cred, dict):
            normalized['iocs']['credentials'].append({
                'type': 'password',
                'username': cred.get('username', ''),
                'value': cred.get('password', ''),
                'context': cred.get('context', '')
            })
    
    # Vulnerability IOCs
    vuln = extraction.get('vulnerability_iocs', {})
    for cve in vuln.get('cves', []):
        normalized['iocs']['cves'].append(cve)
    
    for webshell in vuln.get('webshells', []):
        if isinstance(webshell, dict):
            normalized['iocs']['file_paths'].append({
                'value': webshell.get('path', ''),
                'context': f"Web shell: {webshell.get('context', '')}",
                'action': 'malicious'
            })
    
    # Also process legacy format if present
    legacy_iocs = extraction.get('iocs', {})
    if legacy_iocs:
        for key in normalized['iocs'].keys():
            if key in legacy_iocs and legacy_iocs[key]:
                normalized['iocs'][key].extend(legacy_iocs[key])

    # Threat intel (legacy support only — new prompt omits this)
    threat = extraction.get('threat_intel', {})
    for name in threat.get('threat_names', []):
        normalized['iocs']['threat_names'].append(name)

    # Extract hostnames — new schema puts affected_hosts at top level
    for host in extraction.get('affected_hosts', []):
        normalized['iocs']['hostnames'].append(host)
    # Legacy: nested under extraction_summary
    summary = extraction.get('extraction_summary', {})
    for host in summary.get('affected_hosts', []):
        normalized['iocs']['hostnames'].append(host)

    # Build extraction_summary from whatever is available
    normalized['extraction_summary'] = summary if summary else {}
    if extraction.get('affected_hosts'):
        normalized['extraction_summary']['affected_hosts'] = extraction['affected_hosts']
    if extraction.get('affected_users'):
        normalized['extraction_summary']['affected_users'] = extraction['affected_users']

    return normalized


# ============================================
# Alias Generation for Contextual Matching
# ============================================

def generate_ioc_with_aliases(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Generate primary IOC value and aliases for contextual matching.
    
    For command lines: Primary = root executable, Aliases = full command + path-stripped
    For file paths: Primary = filename, Aliases = full path
    
    Returns:
        {
            'primary_value': str,       # The searchable IOC (e.g., 'cmd.exe')
            'primary_type': str,        # IOC type for primary (e.g., 'File Name')
            'aliases': List[str],       # Contextual aliases
            'original_value': str       # Original value
        }
    """
    import os
    import re
    
    result = {
        'primary_value': value,
        'primary_type': ioc_type,
        'aliases': [],
        'original_value': value
    }
    
    if not value:
        return result
    
    value_clean = value.strip()
    
    if ioc_type == 'Command Line':
        # Extract the root executable from the command line
        # E.g., "C:\Windows\cmd.exe /c powershell.exe -enc ABC" -> "cmd.exe"
        
        aliases = []
        
        # Add full command as alias (lowercase for matching)
        aliases.append(value_clean.lower())
        
        # Create path-stripped version
        # Replace full paths with just filenames
        path_stripped = value_clean
        # Match Windows paths like C:\path\to\file.exe
        exe_path_pattern = r'[A-Za-z]:\\(?:[^\\/:*?"<>|\s]+\\)*([^\\/:*?"<>|\s]+\.(?:exe|bat|cmd|ps1|vbs|dll|msi))'
        
        def strip_path(match):
            return match.group(1)
        
        path_stripped = re.sub(exe_path_pattern, strip_path, path_stripped, flags=re.IGNORECASE)
        
        if path_stripped.lower() != value_clean.lower():
            aliases.append(path_stripped.lower())
        
        # Extract the first executable as the primary IOC
        # Look for first .exe, .bat, .cmd, .ps1 etc in the command
        first_exe_match = re.search(
            r'(?:^|[\\\/\s"])([a-zA-Z0-9_\-\.]+\.(?:exe|bat|cmd|ps1|vbs|dll|msi))',
            value_clean,
            re.IGNORECASE
        )
        
        if first_exe_match:
            primary_exe = first_exe_match.group(1).lower()
            result['primary_value'] = primary_exe
            result['primary_type'] = 'File Name'  # Commands become File Name IOCs
        else:
            # Fallback: use first token
            first_token = value_clean.split()[0].strip('"\'') if value_clean.split() else value_clean
            first_token_name = os.path.basename(first_token.replace('\\', '/'))
            if first_token_name:
                result['primary_value'] = first_token_name.lower()
                result['primary_type'] = 'File Name'
        
        result['aliases'] = list(set(aliases))
        
    elif ioc_type in ('File Path', 'Process Path'):
        # Primary = filename, Alias = full path
        filename = os.path.basename(value_clean.replace('\\', '/'))
        
        if filename:
            result['primary_value'] = filename.lower()
            result['primary_type'] = 'File Name'
            result['aliases'] = [value_clean.lower()]
        
    elif ioc_type == 'File Name':
        # Already a filename, no aliases needed
        result['primary_value'] = value_clean.lower()
        
    else:
        # For other types (IP, hash, domain, etc.), use as-is
        result['primary_value'] = value_clean
    
    return result


# ============================================
# IOC Processing and Deduplication
# ============================================

def process_extraction_for_import(
    extraction: Dict[str, Any],
    case_id: int,
    username: str
) -> Dict[str, Any]:
    """
    Process extracted IOCs for import, handling:
    - Deduplication within extraction
    - Matching against existing IOCs in case
    - Matching against known systems/users
    
    Returns:
        Dict with iocs_to_import, known_systems_results, known_users_results
    """
    from models.ioc import IOC, get_category_for_type
    from models.known_system import KnownSystem
    from models.known_user import KnownUser
    from models.database import db
    
    iocs_to_import = []
    known_systems_results = []
    known_users_results = []
    seen_values = set()  # Track seen values for deduplication
    
    iocs_data = extraction.get('iocs', {})
    
    # Process hashes
    for hash_item in iocs_data.get('hashes', []):
        value = hash_item.get('value', '').strip().lower()
        hash_type = hash_item.get('type', 'sha256').lower()
        if not value or value in seen_values:
            continue
        seen_values.add(value)
        
        ioc_type = IOC_TYPE_MAP.get(hash_type, 'SHA256 Hash')
        category = IOC_CATEGORY_MAP.get(hash_type, 'File')
        
        context = hash_item.get('context', '')
        if hash_item.get('filename'):
            context = f"Filename: {hash_item['filename']} | {context}" if context else f"Filename: {hash_item['filename']}"
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type=ioc_type,
            category=category,
            context=context,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process IP addresses
    for ip_item in iocs_data.get('ip_addresses', []):
        value = ip_item.get('value', '').strip()
        if not value or value in seen_values:
            continue
        seen_values.add(value.lower())
        
        # Determine IPv4 or IPv6
        ip_type = ip_item.get('type', 'ipv4')
        ioc_type = 'IP Address (IPv6)' if ip_type == 'ipv6' or ':' in value else 'IP Address (IPv4)'
        
        context_parts = []
        if ip_item.get('port'):
            context_parts.append(f"Port: {ip_item['port']}")
        if ip_item.get('direction'):
            context_parts.append(f"Direction: {ip_item['direction']}")
        if ip_item.get('context'):
            context_parts.append(ip_item['context'])
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type=ioc_type,
            category='Network',
            context=' | '.join(context_parts),
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process domains
    for domain_item in iocs_data.get('domains', []):
        if isinstance(domain_item, dict):
            value = domain_item.get('value', '').strip().lower()
            context = domain_item.get('context', '')
        else:
            value = str(domain_item).strip().lower()
            context = ''
        
        if not value or value in seen_values:
            continue
        seen_values.add(value)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Domain',
            category='Network',
            context=context,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process URLs
    for url_item in iocs_data.get('urls', []):
        if isinstance(url_item, dict):
            value = url_item.get('value', '').strip()
            url_type = url_item.get('type', 'unknown')
            context = url_item.get('context', '')
        else:
            value = str(url_item).strip()
            url_type = 'unknown'
            context = ''
        
        if not value or value.lower() in seen_values:
            continue
        seen_values.add(value.lower())
        
        # Skip Huntress report URLs - these are not IOCs
        if url_type == 'report' or 'huntress.io' in value.lower():
            continue
        
        context_with_type = f"Type: {url_type}" + (f" | {context}" if context else "")
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='URL',
            category='Network',
            context=context_with_type,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process file paths - generate primary IOC (filename) with path as alias
    for fp_item in iocs_data.get('file_paths', []):
        if isinstance(fp_item, dict):
            value = fp_item.get('value', '').strip()
            action = fp_item.get('action', '')
            context = fp_item.get('context', '')
        else:
            value = str(fp_item).strip()
            action = ''
            context = ''
        
        if not value or value.lower() in seen_values:
            continue
        seen_values.add(value.lower())
        
        # Generate primary IOC (filename) with full path as alias
        alias_result = generate_ioc_with_aliases(value, 'File Path')
        primary_value = alias_result['primary_value']
        aliases = alias_result['aliases']
        
        # Check if we've already seen this primary value in THIS extraction
        if primary_value.lower() in seen_values:
            # Add the new path alias to the existing IOC entry
            for entry in iocs_to_import:
                if entry.get('value', '').lower() == primary_value.lower():
                    existing_aliases = entry.get('aliases', [])
                    entry['aliases'] = list(set(existing_aliases + aliases))
                    break
            continue
        seen_values.add(primary_value.lower())
        
        context_with_action = f"Action: {action}" if action else ""
        if context:
            context_with_action += f" | {context}" if context_with_action else context
        context_with_action += f" | Path: {value}"
        
        ioc_entry = _create_ioc_entry_with_type_awareness(
            primary_value=primary_value,
            primary_type=alias_result['primary_type'],
            aliases=aliases,
            original_type='File Path',
            category='File',
            context=context_with_action,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process file names
    for fn in iocs_data.get('file_names', []):
        value = str(fn).strip() if fn else ''
        if not value or value.lower() in seen_values:
            continue
        seen_values.add(value.lower())
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='File Name',
            category='File',
            context='',
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process registry keys
    for reg_item in iocs_data.get('registry_keys', []):
        if isinstance(reg_item, dict):
            value = reg_item.get('value', '').strip()
            action = reg_item.get('action', '')
            context = reg_item.get('context', '')
            value_name = reg_item.get('value_name', '')
            value_data = reg_item.get('value_data', '')
        else:
            value = str(reg_item).strip()
            action = ''
            context = ''
            value_name = ''
            value_data = ''
        
        if not value or value.lower() in seen_values:
            continue
        seen_values.add(value.lower())
        
        context_parts = []
        if action:
            context_parts.append(f"Action: {action}")
        if value_name:
            context_parts.append(f"Value: {value_name}")
        if value_data:
            context_parts.append(f"Data: {value_data[:200]}..." if len(str(value_data)) > 200 else f"Data: {value_data}")
        if context:
            context_parts.append(context)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Registry Key',
            category='Registry',
            context=' | '.join(context_parts),
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process services
    for svc_item in iocs_data.get('services', []):
        if isinstance(svc_item, dict):
            value = svc_item.get('name', '').strip()
            action = svc_item.get('action', '')
            context = svc_item.get('context', '')
            path = svc_item.get('path', '')
        else:
            value = str(svc_item).strip()
            action = ''
            context = ''
            path = ''
        
        if not value or value.lower() in seen_values:
            continue
        seen_values.add(value.lower())
        
        context_parts = []
        if action:
            context_parts.append(f"Action: {action}")
        if path:
            context_parts.append(f"Path: {path}")
        if context:
            context_parts.append(context)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Service Name',
            category='Process',
            context=' | '.join(context_parts),
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process scheduled tasks
    for task_item in iocs_data.get('scheduled_tasks', []):
        if isinstance(task_item, dict):
            value = task_item.get('name', '') or task_item.get('path', '')
            value = value.strip()
            action = task_item.get('action', '')
            context = task_item.get('context', '')
        else:
            value = str(task_item).strip()
            action = ''
            context = ''
        
        if not value or value.lower() in seen_values:
            continue
        seen_values.add(value.lower())
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Scheduled Task',
            category='Process',
            context=f"Action: {action} | {context}" if action else context,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process commands - generate primary IOC (executable) with command aliases
    for cmd_item in iocs_data.get('commands', []):
        if isinstance(cmd_item, dict):
            value = cmd_item.get('value', '').strip()
            executable = cmd_item.get('executable', '')
            context = cmd_item.get('context', '')
            parent = cmd_item.get('parent', '')
            user = cmd_item.get('user', '')
        else:
            value = str(cmd_item).strip()
            executable = ''
            context = ''
            parent = ''
            user = ''
        
        if not value or value.lower() in seen_values:
            continue
        seen_values.add(value.lower())
        
        # Generate primary IOC (executable) with full command as alias
        alias_result = generate_ioc_with_aliases(value, 'Command Line')
        primary_value = alias_result['primary_value']
        aliases = alias_result['aliases']
        
        # Skip if we've already seen this primary value in THIS extraction
        if primary_value.lower() in seen_values:
            for entry in iocs_to_import:
                if entry.get('value', '').lower() == primary_value.lower():
                    existing_aliases = entry.get('aliases', [])
                    entry['aliases'] = list(set(existing_aliases + aliases))
                    break
            continue
        seen_values.add(primary_value.lower())
        
        context_parts = []
        if executable:
            context_parts.append(f"Executable: {executable}")
        if parent:
            context_parts.append(f"Parent: {parent}")
        if user:
            context_parts.append(f"User: {user}")
        if context:
            context_parts.append(context)
        context_parts.append(f"Full command: {value[:500]}..." if len(value) > 500 else f"Full command: {value}")
        
        ioc_entry = _create_ioc_entry_with_type_awareness(
            primary_value=primary_value,
            primary_type=alias_result['primary_type'],
            aliases=aliases,
            original_type='Command Line',
            category='File',
            context=' | '.join(context_parts),
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process credentials (passwords, SSH keys, API keys)
    for cred_item in iocs_data.get('credentials', []):
        cred_type = cred_item.get('type', 'password')
        cred_value = cred_item.get('value', '').strip()
        cred_user = cred_item.get('username', '')
        context = cred_item.get('context', '')
        
        if not cred_value or cred_value.lower() in seen_values:
            continue
        seen_values.add(cred_value.lower())
        
        ioc_type = IOC_TYPE_MAP.get(cred_type, 'Password')
        
        context_with_user = f"Username: {cred_user}" if cred_user else ""
        if context:
            context_with_user += f" | {context}" if context_with_user else context
        
        ioc_entry = _create_ioc_entry(
            value=cred_value,
            ioc_type=ioc_type,
            category='Authentication',
            context=context_with_user,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process CVEs
    for cve in iocs_data.get('cves', []):
        value = str(cve).strip().upper()
        if not value or value in seen_values:
            continue
        seen_values.add(value)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='CVE',
            category='Vulnerability',
            context='',
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process threat names
    for threat_name in iocs_data.get('threat_names', []):
        value = str(threat_name).strip()
        if not value or value.lower() in seen_values:
            continue
        seen_values.add(value.lower())
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Threat Name',
            category='Threat Intel',
            context='',
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process email addresses
    for email in iocs_data.get('email_addresses', []):
        value = str(email).strip().lower() if email else ''
        if not value or value in seen_values:
            continue
        seen_values.add(value)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Email Address',
            category='Email',
            context='',
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process users (for Known Users integration)
    for user_item in iocs_data.get('users', []):
        if isinstance(user_item, dict):
            username_val = user_item.get('value', '').strip()
            sid = user_item.get('sid', '')
            context = user_item.get('context', '')
        else:
            username_val = str(user_item).strip()
            sid = ''
            context = ''
        
        if not username_val:
            continue
        
        # Find or create known user
        user_result = _process_known_user(username_val, sid, case_id, username, context)
        if user_result:
            known_users_results.append(user_result)
    
    # Process hostnames (for Known Systems integration AND IOC creation)
    for hostname in iocs_data.get('hostnames', []):
        if isinstance(hostname, dict):
            hostname_val = hostname.get('value', '') if isinstance(hostname, dict) else str(hostname)
            context = hostname.get('context', '')
            fqdn = hostname.get('fqdn', '')
        else:
            hostname_val = str(hostname)
            context = ''
            fqdn = ''
        hostname_val = hostname_val.strip()
        
        if not hostname_val or hostname_val.lower() in seen_values:
            continue
        seen_values.add(hostname_val.lower())
        
        # Create IOC entry for the hostname
        ioc_entry = _create_ioc_entry(
            value=hostname_val,
            ioc_type='Hostname',
            category='Network',
            context=f"FQDN: {fqdn}" if fqdn else context,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
        
        # Find or create known system
        system_result = _process_known_system(hostname_val, case_id, username)
        if system_result:
            known_systems_results.append(system_result)
    
    # Also process affected_hosts from summary
    summary = extraction.get('extraction_summary', {})
    for host in summary.get('affected_hosts', []):
        if host and host.strip():
            system_result = _process_known_system(host.strip(), case_id, username)
            if system_result:
                known_systems_results.append(system_result)
    
    # Process affected users from summary
    for user in summary.get('affected_users', []):
        if isinstance(user, dict):
            username_val = user.get('username', '').strip()
            sid = user.get('sid', '')
        else:
            username_val = str(user).strip()
            sid = ''
        
        if username_val:
            user_result = _process_known_user(username_val, sid, case_id, username, 'From extraction summary')
            if user_result:
                known_users_results.append(user_result)
    
    return {
        'iocs_to_import': iocs_to_import,
        'known_systems_results': known_systems_results,
        'known_users_results': known_users_results,
        'extraction_summary': extraction.get('extraction_summary', {}),
        'mitre_indicators': iocs_data.get('mitre_indicators', []),
        'raw_artifacts': extraction.get('raw_artifacts', {})
    }


def _create_ioc_entry(
    value: str,
    ioc_type: str,
    category: str,
    context: str,
    case_id: int
) -> Optional[Dict[str, Any]]:
    """
    Create an IOC entry, checking for existing IOCs
    
    Returns dict with ioc data and existing_ioc_id if duplicate found.
    Includes auto-detected match_type for proper IOC matching.
    """
    from models.ioc import IOC, detect_match_type, get_match_type_recommendation
    
    if not value:
        return None
    
    # Check for existing IOC
    existing_ioc = IOC.find_by_value(value, ioc_type, case_id=case_id)
    
    # Auto-detect match type for this IOC
    detected_match_type = detect_match_type(value, ioc_type)
    match_info = get_match_type_recommendation(value, ioc_type)
    
    entry = {
        'value': value,
        'ioc_type': ioc_type,
        'category': category,
        'context': context,
        'is_new': existing_ioc is None,
        'match_type': detected_match_type,
        'match_type_reason': match_info.get('reason', '')
    }
    
    if existing_ioc:
        entry['existing_ioc_id'] = existing_ioc.id
        entry['existing_notes'] = existing_ioc.notes
        entry['existing_match_type'] = existing_ioc.get_effective_match_type()
        # Existing IOC matches are now always scoped to this case.
        entry['already_linked'] = True
    
    return entry


def _create_ioc_entry_with_type_awareness(
    primary_value: str,
    primary_type: str,
    aliases: List[str],
    original_type: str,
    category: str,
    context: str,
    case_id: int
) -> Optional[Dict[str, Any]]:
    """
    Create an IOC entry with smart type-aware deduplication.
    
    Handles the case where:
    - A File Name IOC exists (broad matcher)
    - We're adding a Command Line that generates the same primary value
    
    Logic:
    1. If File Name IOC exists with same value:
       - Check if Command Line IOC also exists
       - If yes: add aliases to Command Line IOC
       - If no: create new Command Line IOC (keep File Name as broad matcher)
    2. If no File Name conflict: normal flow
    
    Returns dict with ioc data and metadata.
    Includes auto-detected match_type for proper IOC matching.
    """
    from models.ioc import IOC, detect_match_type, get_match_type_recommendation
    
    if not primary_value:
        return None
    
    # Check for existing IOCs
    existing_filename = IOC.find_by_value(primary_value, 'File Name', case_id=case_id)
    existing_command = IOC.find_by_value(primary_value, 'Command Line', case_id=case_id)
    
    # Auto-detect match type
    detected_match_type = detect_match_type(primary_value, primary_type)
    match_info = get_match_type_recommendation(primary_value, primary_type)
    
    entry = {
        'value': primary_value,
        'ioc_type': primary_type,
        'category': category,
        'context': context,
        'aliases': aliases,
        'is_new': True,
        'merge_into_existing': False,
        'match_type': detected_match_type,
        'match_type_reason': match_info.get('reason', '')
    }
    
    # CASE A: Adding a Command Line IOC
    if original_type == 'Command Line':
        if existing_command:
            # Command Line IOC already exists - merge aliases into it
            entry['existing_ioc_id'] = existing_command.id
            entry['existing_notes'] = existing_command.notes
            entry['ioc_type'] = 'Command Line'
            entry['category'] = 'Process'
            entry['is_new'] = False
            entry['merge_into_existing'] = True
            
            entry['already_linked'] = True
        elif existing_filename:
            # File Name exists but no Command Line - create NEW Command Line IOC
            # This keeps File Name as broad matcher, Command Line for specific matching
            entry['ioc_type'] = 'Command Line'
            entry['category'] = 'Process'
            entry['is_new'] = True
            entry['preserve_filename_ioc'] = True
        else:
            # No existing IOCs - create new Command Line IOC
            entry['ioc_type'] = 'Command Line'
            entry['category'] = 'Process'
            entry['is_new'] = True
        
        return entry
    
    # CASE B: Adding a File Path IOC
    if original_type == 'File Path':
        if existing_filename:
            # File Name exists - add path as alias to it
            entry['existing_ioc_id'] = existing_filename.id
            entry['existing_notes'] = existing_filename.notes
            entry['ioc_type'] = 'File Name'
            entry['is_new'] = False
            entry['merge_into_existing'] = True
            
            entry['already_linked'] = True
        else:
            # No File Name exists - create new File Name IOC with path as alias
            entry['ioc_type'] = 'File Name'
            entry['category'] = 'File'
            entry['is_new'] = True
        
        return entry
    
    # CASE C: Other IOC types (direct File Name, etc.)
    existing_same_type = IOC.find_by_value(primary_value, primary_type, case_id=case_id)
    if existing_same_type:
        entry['existing_ioc_id'] = existing_same_type.id
        entry['existing_notes'] = existing_same_type.notes
        entry['is_new'] = False
        entry['merge_into_existing'] = True
        
        entry['already_linked'] = True
        return entry
    
    # No conflicts - create new IOC
    entry['is_new'] = True
    return entry


def _process_known_system(
    hostname: str,
    case_id: int,
    username: str
) -> Optional[Dict[str, Any]]:
    """
    Process a hostname for Known Systems integration
    
    - If system exists: mark as compromised, link to case
    - If system doesn't exist: create new system, mark compromised
    """
    from models.known_system import KnownSystem, KnownSystemAudit
    from models.database import db
    
    if not hostname:
        return None
    
    # Find existing system within this case
    system, match_type = KnownSystem.find_by_hostname_or_alias(hostname, case_id=case_id)
    
    result = {
        'hostname': hostname,
        'action': None,
        'system_id': None,
        'was_compromised': False,
        'now_compromised': True
    }
    
    if system:
        result['system_id'] = system.id
        result['was_compromised'] = system.compromised
        
        if not system.compromised:
            result['action'] = 'mark_compromised'
        else:
            result['action'] = 'already_compromised'
        
        # Link to case if not already
        system.link_to_case(case_id)
    else:
        result['action'] = 'create_new'
    
    return result


def _process_known_user(
    username_val: str,
    sid: str,
    case_id: int,
    changed_by: str,
    context: str = ''
) -> Optional[Dict[str, Any]]:
    """
    Process a username for Known Users integration
    
    - If user exists: mark as compromised, link to case
    - If user doesn't exist: create new user, mark compromised
    """
    from models.known_user import KnownUser
    
    if not username_val:
        return None
    
    # Find existing user within this case
    user, match_type = KnownUser.find_by_username_sid_alias_or_email(
        username=username_val,
        sid=sid if sid else None,
        case_id=case_id
    )
    
    result = {
        'username': username_val,
        'sid': sid,
        'context': context,
        'action': None,
        'user_id': None,
        'was_compromised': False,
        'now_compromised': True
    }
    
    if user:
        result['user_id'] = user.id
        result['was_compromised'] = user.compromised
        
        if not user.compromised:
            result['action'] = 'mark_compromised'
        else:
            result['action'] = 'already_compromised'
        
        # Link to case if not already
        user.link_to_case(case_id)
        
        # Add SID if we have it and user doesn't
        if sid and not user.sid:
            result['add_sid'] = True
    else:
        result['action'] = 'create_new'
    
    return result


# ============================================
# Save Extracted IOCs
# ============================================

def save_extracted_iocs(
    iocs_data: List[Dict[str, Any]],
    case_id: int,
    username: str,
    known_systems: List[Dict[str, Any]] = None,
    known_users: List[Dict[str, Any]] = None
) -> Dict[str, int]:
    """
    Save extracted IOCs to the database
    
    Args:
        iocs_data: List of IOC entries from process_extraction_for_import
        case_id: Case ID
        username: Username performing the save
        known_systems: List of system results to process
        known_users: List of user results to process
    
    Returns:
        Dict with created, updated, and existing counts
    """
    from models.ioc import IOC, IOCAudit, get_category_for_type
    from models.known_system import KnownSystem, KnownSystemAudit
    from models.known_user import KnownUser, KnownUserAudit
    from models.database import db
    
    created_count = 0
    updated_count = 0
    existing_count = 0
    systems_created = 0
    systems_updated = 0
    users_created = 0
    users_updated = 0
    
    try:
        # Process IOCs
        for ioc_entry in iocs_data:
            if ioc_entry.get('skip', False):
                continue
            
            if ioc_entry.get('existing_ioc_id'):
                # Update existing IOC
                existing_ioc = IOC.query.get(ioc_entry['existing_ioc_id'])
                if existing_ioc:
                    existing_count += 1
                    # Add context to notes if provided
                    if ioc_entry.get('context'):
                        if existing_ioc.notes:
                            existing_ioc.notes += f"\n\nExtracted context: {ioc_entry['context']}"
                        else:
                            existing_ioc.notes = f"Extracted context: {ioc_entry['context']}"
                        updated_count += 1
                    
                    # Merge any new aliases
                    if ioc_entry.get('aliases'):
                        for alias in ioc_entry['aliases']:
                            existing_ioc.add_alias(alias)
            else:
                # Create new IOC
                value = ioc_entry['value']
                ioc_type = ioc_entry['ioc_type']
                category = ioc_entry['category']
                aliases = ioc_entry.get('aliases', [])
                match_type = ioc_entry.get('match_type')  # Auto-detected or explicit
                
                try:
                    ioc, created = IOC.get_or_create(
                        value=value,
                        ioc_type=ioc_type,
                        category=category,
                        created_by=username,
                        case_id=case_id,
                        aliases=aliases,
                        match_type=match_type,
                        source='ai_extraction'
                    )
                    
                    if created:
                        created_count += 1
                        if ioc_entry.get('context'):
                            ioc.notes = f"Extracted context: {ioc_entry['context']}"
                        
                        IOCAudit.log_change(
                            ioc_id=ioc.id,
                            changed_by=username,
                            field_name='ioc',
                            action='create',
                            new_value=f'{ioc_type}: {value} (match: {ioc.get_effective_match_type()})'
                        )
                        
                        if aliases:
                            IOCAudit.log_change(
                                ioc_id=ioc.id,
                                changed_by=username,
                                field_name='aliases',
                                action='create',
                                new_value=f'{len(aliases)} aliases added'
                            )
                    else:
                        existing_count += 1
                        
                except ValueError as e:
                    logger.warning(f"Failed to create IOC {ioc_type}: {value} - {e}")
        
        # Process known systems
        if known_systems:
            for sys_result in known_systems:
                if sys_result.get('skip', False):
                    continue
                
                action = sys_result.get('action')
                hostname = sys_result.get('hostname')
                
                # Helper to create Hostname IOC
                def create_hostname_ioc(hostname_value):
                    try:
                        hostname_ioc, created = IOC.get_or_create(
                            value=hostname_value,
                            ioc_type='Hostname',
                            category=get_category_for_type('Hostname'),
                            created_by=username,
                            case_id=case_id,
                            source='ai_extraction'
                        )
                        if created:
                            logger.info(f"Created Hostname IOC for compromised system: {hostname_value}")
                    except ValueError as e:
                        logger.debug(f"Hostname IOC error: {e}")
                
                if action == 'create_new':
                    # Create new system - use get_or_create pattern to handle race conditions
                    netbios, fqdn = KnownSystem.extract_netbios_name(hostname)
                    target_hostname = netbios or hostname
                    
                    # Re-check if system exists (might have been created by another report)
                    existing_system, _ = KnownSystem.find_by_hostname_or_alias(target_hostname, case_id=case_id)
                    if existing_system:
                        # System was created between check and save
                        if not existing_system.compromised:
                            existing_system.compromised = True
                            systems_updated += 1
                        # Still create the IOC even if system existed
                        create_hostname_ioc(target_hostname)
                        continue
                    
                    try:
                        new_system = KnownSystem(
                            case_id=case_id,
                            hostname=target_hostname,
                            compromised=True,
                            notes=f"Created from EDR report extraction by {username}"
                        )
                        db.session.add(new_system)
                        db.session.flush()
                        
                        # Add FQDN as alias if different
                        if fqdn and fqdn != target_hostname:
                            new_system.add_alias(fqdn)
                    except Exception as e:
                        # Handle race condition - system was created by another process
                        db.session.rollback()
                        logger.warning(f"Race condition creating system {target_hostname}: {e}")
                        existing_system, _ = KnownSystem.find_by_hostname_or_alias(target_hostname, case_id=case_id)
                        # Still create the IOC even on race condition
                        create_hostname_ioc(target_hostname)
                        continue
                    
                    # Create Hostname IOC for compromised system
                    create_hostname_ioc(target_hostname)
                    
                    KnownSystemAudit.log_change(
                        system_id=new_system.id,
                        changed_by=username,
                        field_name='system',
                        action='create',
                        new_value=f'{target_hostname} (from EDR extraction)'
                    )
                    systems_created += 1
                    
                elif action == 'mark_compromised':
                    # Update existing system
                    system = KnownSystem.query.get(sys_result.get('system_id'))
                    if system and not system.compromised:
                        system.compromised = True
                        if system.notes:
                            system.notes += f"\n\nMarked compromised from EDR report extraction by {username}"
                        else:
                            system.notes = f"Marked compromised from EDR report extraction by {username}"
                        
                        # Create Hostname IOC for compromised system
                        create_hostname_ioc(system.hostname)
                        
                        KnownSystemAudit.log_change(
                            system_id=system.id,
                            changed_by=username,
                            field_name='compromised',
                            action='update',
                            old_value='False',
                            new_value='True'
                        )
                        systems_updated += 1
                
                elif action == 'already_compromised':
                    # System already compromised - still create/link IOC for this case
                    system = KnownSystem.query.get(sys_result.get('system_id'))
                    if system:
                        create_hostname_ioc(system.hostname)
        
        # Process known users
        if known_users:
            for user_result in known_users:
                if user_result.get('skip', False):
                    continue
                
                action = user_result.get('action')
                username_val = user_result.get('username')
                sid = user_result.get('sid')
                
                # Helper to create Username IOC
                def create_username_ioc(username_value, user_sid=None):
                    user_aliases = [user_sid] if user_sid else None
                    try:
                        user_ioc, created = IOC.get_or_create(
                            value=username_value,
                            ioc_type='Username',
                            category=get_category_for_type('Username'),
                            created_by=username,
                            case_id=case_id,
                            aliases=user_aliases,
                            source='ai_extraction'
                        )
                        if created:
                            logger.info(f"Created Username IOC for compromised user: {username_value}")
                    except ValueError as e:
                        logger.debug(f"Username IOC error: {e}")
                
                if action == 'create_new':
                    # Create new user - use get_or_create pattern to handle race conditions
                    normalized, domain = KnownUser.normalize_username(username_val)
                    target_username = normalized or username_val
                    
                    # Re-check if user exists (might have been created by another report)
                    existing_user, _ = KnownUser.find_by_username_sid_alias_or_email(
                        username=target_username,
                        sid=sid if sid else None,
                        case_id=case_id
                    )
                    if existing_user:
                        # User was created between check and save
                        if not existing_user.compromised:
                            existing_user.compromised = True
                            users_updated += 1
                        # Still create the IOC even if user existed
                        create_username_ioc(target_username, sid)
                        continue
                    
                    try:
                        new_user = KnownUser(
                            case_id=case_id,
                            username=target_username,
                            sid=sid if sid else None,
                            compromised=True,
                            added_by=username,
                            notes=f"Created from EDR report extraction"
                        )
                        db.session.add(new_user)
                        db.session.flush()
                        
                        # Add original format as alias if different
                        if username_val.upper() != target_username.upper():
                            new_user.add_alias(username_val)
                    except Exception as e:
                        # Handle race condition - user was created by another process
                        db.session.rollback()
                        logger.warning(f"Race condition creating user {target_username}: {e}")
                        existing_user, _ = KnownUser.find_by_username_sid_alias_or_email(
                            username=target_username,
                            sid=sid if sid else None,
                            case_id=case_id
                        )
                        # Still create the IOC even on race condition
                        create_username_ioc(target_username, sid)
                        continue
                    
                    # Create Username IOC for compromised user
                    create_username_ioc(target_username, sid)
                    
                    KnownUserAudit.log_change(
                        user_id=new_user.id,
                        changed_by=username,
                        field_name='user',
                        action='create',
                        new_value=f'{target_username} (from EDR extraction)'
                    )
                    users_created += 1
                    
                elif action == 'mark_compromised':
                    # Update existing user
                    user = KnownUser.query.get(user_result.get('user_id'))
                    if user and not user.compromised:
                        user.compromised = True
                        if user.notes:
                            user.notes += f"\n\nMarked compromised from EDR report extraction by {username}"
                        else:
                            user.notes = f"Marked compromised from EDR report extraction by {username}"
                        
                        # Create Username IOC for compromised user
                        user_sid = sid or user.sid
                        create_username_ioc(user.username, user_sid)
                        
                        KnownUserAudit.log_change(
                            user_id=user.id,
                            changed_by=username,
                            field_name='compromised',
                            action='update',
                            old_value='False',
                            new_value='True'
                        )
                        users_updated += 1
                        
                        # Add SID if we have it
                        if user_result.get('add_sid') and sid:
                            user.sid = sid
                            KnownUserAudit.log_change(
                                user_id=user.id,
                                changed_by=username,
                                field_name='sid',
                                action='update',
                                new_value=sid
                            )
                
                elif action == 'already_compromised':
                    # User already compromised - still create/link IOC for this case
                    user = KnownUser.query.get(user_result.get('user_id'))
                    if user:
                        user_sid = sid or user.sid
                        create_username_ioc(user.username, user_sid)
        
        db.session.commit()
        
        return {
            'iocs_created': created_count,
            'iocs_updated': updated_count,
            'iocs_existing': existing_count,
            'iocs_linked': 0,
            'systems_created': systems_created,
            'systems_updated': systems_updated,
            'users_created': users_created,
            'users_updated': users_updated
        }
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to save extracted IOCs: {e}")
        raise


# ============================================
# Report Splitting
# ============================================

def split_edr_reports(edr_report_text: str) -> List[str]:
    """
    Split EDR report text by the *** NEW REPORT *** separator
    
    Returns list of individual report texts (trimmed, non-empty)
    """
    if not edr_report_text:
        return []
    
    reports = [r.strip() for r in edr_report_text.split('*** NEW REPORT ***') if r.strip()]
    return reports


def get_report_preview(report_text: str, max_length: int = 200) -> str:
    """Get a preview of a report for display"""
    if not report_text:
        return ''
    
    # Get first non-empty line
    lines = [l.strip() for l in report_text.split('\n') if l.strip()]
    if not lines:
        return report_text[:max_length]
    
    preview = lines[0]
    if len(preview) > max_length:
        return preview[:max_length] + '...'
    return preview
