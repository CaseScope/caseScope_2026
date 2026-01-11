"""IOC Extraction from EDR Reports

Extracts Indicators of Compromise from EDR reports using AI (Ollama)
with regex fallback. Handles deduplication and integration with 
Known Systems and Known Users.
"""
import re
import json
import logging
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
    'password': 'Password Hash',
    'ssh_key': 'SSH Key Fingerprint',
    'api_key': 'API Key',
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
    'password': 'Authentication',
    'ssh_key': 'Authentication',
    'api_key': 'Authentication',
}


# ============================================
# AI IOC Extraction Prompt
# ============================================

SYSTEM_PROMPT = """You are a SOC analyst extracting Indicators of Compromise from security incident reports.

CRITICAL: Return ONLY valid JSON matching EXACTLY this structure. No markdown, no explanation.

{
  "extraction_summary": {
    "report_date": "YYYY-MM-DD HH:MM:SS UTC",
    "affected_host": "hostname if mentioned",
    "severity_indicators": ["list of threat types mentioned"]
  },
  "iocs": {
    "hashes": [{"value": "", "type": "md5|sha1|sha256|sha512", "context": ""}],
    "ip_addresses": [{"value": "", "port": null, "direction": "source|destination|unknown", "context": ""}],
    "domains": [{"value": "", "context": ""}],
    "urls": [{"value": "", "type": "report|c2|exfil|malicious", "context": ""}],
    "file_paths": [{"value": "", "action": "created|deleted|executed|modified|accessed", "context": ""}],
    "file_names": [],
    "users": [{"value": "", "sid": null, "context": ""}],
    "sids": [],
    "registry_keys": [{"value": "", "action": "created|modified|deleted|queried", "context": ""}],
    "commands": [{"value": "", "executable": "", "context": ""}],
    "processes": [{"name": "", "path": "", "pid": "", "parent": "", "user": ""}],
    "credentials": [{"type": "password|ssh_key|api_key|certificate", "username": "", "value": "", "context": ""}],
    "hostnames": [],
    "timestamps": [{"value": "ISO8601", "event": ""}],
    "network_shares": [{"value": "", "context": ""}],
    "email_addresses": [],
    "mitre_indicators": [{"technique_id": "T####", "technique_name": "", "evidence": ""}]
  },
  "raw_artifacts": {
    "full_commands": [],
    "filemasks": []
  }
}

EXTRACTION RULES:
1. De-obfuscate URLs: hxxp→http, hxxps→https, [.]→., [:]→:, [@]→@
2. Extract credentials from URLs: sftp://USER:PASSWORD@IP:PORT/ → extract username AND password
3. Extract SSH keys from -hostkey="..." parameters
4. Network shares: \\\\server\\share format (UNC paths)
5. Huntress/security vendor portal URLs → type="report"
6. C2/exfil destination URLs → type="c2" or "exfil"
7. Full command lines go in BOTH commands array AND raw_artifacts.full_commands
8. File exclusion patterns (filemasks) → raw_artifacts.filemasks
9. Empty arrays are fine - do NOT add null or placeholder values
10. Preserve original casing for paths and commands

MITRE ATT&CK MAPPING:
- RDP/remote desktop → T1021.001 Remote Desktop Protocol
- WinSCP/rclone/SFTP exfil → T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
- Admin shares (c$, admin$) → T1021.002 SMB/Windows Admin Shares
- Firewall rule changes → T1562.004 Disable or Modify System Firewall
- Defender exclusions → T1562.001 Disable or Modify Tools
- Credentials in command → T1552.001 Credentials In Files
- Renamed executables → T1036.005 Match Legitimate Name or Location
- Registry modification → T1112 Modify Registry
- Network share data → T1039 Data from Network Shared Drive"""


# ============================================
# Regex-based IOC Extraction (Fallback)
# ============================================

class RegexIOCExtractor:
    """Regex-based IOC extractor as fallback when AI is unavailable"""
    
    # De-obfuscation patterns
    DEFANG_PATTERNS = [
        (re.compile(r'hxxps?://', re.I), lambda m: m.group().lower().replace('xx', 'tt')),
        (re.compile(r'\[:\]//'), '://'),
        (re.compile(r'\[\.+\]'), '.'),
        (re.compile(r'\(\.+\)'), '.'),
        (re.compile(r'\[dot\]', re.I), '.'),
        (re.compile(r'\(dot\)', re.I), '.'),
        (re.compile(r'\[at\]', re.I), '@'),
        (re.compile(r'\(at\)', re.I), '@'),
        (re.compile(r'\[@\]'), '@'),
        (re.compile(r'\[:\]'), ':'),
    ]
    
    # IOC Patterns
    PATTERNS = {
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'ip_v4': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        'ip_v6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
        'email': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
        'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.I),
        'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
        'file_path_windows': re.compile(r'[A-Za-z]:\\[^\s<>"|?*\n]+'),
        'file_path_unc': re.compile(r'\\\\[^\s<>"|?*\n]+'),
        'registry_key': re.compile(r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR)\\[^\s\n]+', re.I),
        'sid': re.compile(r'S-1-\d+-\d+(?:-\d+)*'),
    }
    
    def __init__(self):
        pass
    
    def defang(self, text: str) -> str:
        """De-obfuscate/defang indicators in text"""
        for pattern, replacement in self.DEFANG_PATTERNS:
            if callable(replacement):
                text = pattern.sub(replacement, text)
            else:
                text = pattern.sub(replacement, text)
        return text
    
    def extract(self, text: str) -> Dict[str, Any]:
        """Extract IOCs from text using regex patterns"""
        # De-obfuscate first
        clean_text = self.defang(text)
        
        results = {
            'extraction_summary': {
                'method': 'regex',
                'report_date': None,
                'affected_host': None,
                'severity_indicators': []
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
                'mitre_indicators': []
            },
            'raw_artifacts': {
                'full_commands': [],
                'filemasks': []
            }
        }
        
        # Extract hashes
        for match in self.PATTERNS['md5'].findall(clean_text):
            results['iocs']['hashes'].append({'value': match.lower(), 'type': 'md5', 'context': ''})
        for match in self.PATTERNS['sha1'].findall(clean_text):
            results['iocs']['hashes'].append({'value': match.lower(), 'type': 'sha1', 'context': ''})
        for match in self.PATTERNS['sha256'].findall(clean_text):
            results['iocs']['hashes'].append({'value': match.lower(), 'type': 'sha256', 'context': ''})
        
        # Extract IP addresses
        for match in self.PATTERNS['ip_v4'].findall(clean_text):
            # Skip private/local IPs for IOC purposes (keep them but flag)
            results['iocs']['ip_addresses'].append({
                'value': match, 
                'port': None, 
                'direction': 'unknown',
                'context': ''
            })
        
        # Extract URLs
        for match in self.PATTERNS['url'].findall(clean_text):
            url_type = 'unknown'
            if 'huntress' in match.lower() or 'portal' in match.lower():
                url_type = 'report'
            results['iocs']['urls'].append({'value': match, 'type': url_type, 'context': ''})
        
        # Extract file paths
        for match in self.PATTERNS['file_path_windows'].findall(clean_text):
            results['iocs']['file_paths'].append({
                'value': match.rstrip('.,;:'),
                'action': 'unknown',
                'context': ''
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
        
        # Deduplicate
        results['iocs']['hashes'] = self._dedupe_list_of_dicts(results['iocs']['hashes'], 'value')
        results['iocs']['ip_addresses'] = self._dedupe_list_of_dicts(results['iocs']['ip_addresses'], 'value')
        results['iocs']['urls'] = self._dedupe_list_of_dicts(results['iocs']['urls'], 'value')
        results['iocs']['file_paths'] = self._dedupe_list_of_dicts(results['iocs']['file_paths'], 'value')
        results['iocs']['network_shares'] = self._dedupe_list_of_dicts(results['iocs']['network_shares'], 'value')
        results['iocs']['registry_keys'] = self._dedupe_list_of_dicts(results['iocs']['registry_keys'], 'value')
        results['iocs']['sids'] = list(set(results['iocs']['sids']))
        results['iocs']['email_addresses'] = list(set(results['iocs']['email_addresses']))
        
        return results
    
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

def _detect_gpu_vram() -> Optional[int]:
    """Detect GPU VRAM in MB using nvidia-smi"""
    try:
        import subprocess
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=memory.total', '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return int(float(result.stdout.strip().split('\n')[0]))
    except Exception:
        pass
    return None


def extract_iocs_with_ai(report_text: str, model: str = None) -> Tuple[Dict[str, Any], bool]:
    """
    Extract IOCs from report text using AI (Ollama)
    
    Returns:
        Tuple of (extraction_result, used_ai_bool)
    """
    try:
        import ollama
        from models.system_settings import SystemSettings, SettingKeys, get_ai_model_config
        
        # Check if AI is enabled
        ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
        if not ai_enabled:
            logger.info("AI extraction disabled, using regex fallback")
            return RegexIOCExtractor().extract(report_text), False
        
        # Get model from config if not specified
        if not model:
            # Detect GPU VRAM to select appropriate model
            vram_mb = _detect_gpu_vram()
            if vram_mb:
                model_config = get_ai_model_config(vram_mb)
                if model_config:
                    model = model_config.get('ioc_extraction', 'qwen2.5:7b-instruct-q4_k_m')
                else:
                    model = 'qwen2.5:7b-instruct-q4_k_m'
            else:
                # Default to 7b model if VRAM detection fails
                model = 'qwen2.5:7b-instruct-q4_k_m'
        
        # Truncate filemask if present (can be very long)
        truncated_text = report_text
        if '-filemask="' in truncated_text:
            idx = truncated_text.find('-filemask="')
            end = truncated_text.find('"', idx + 100)
            if end > idx:
                truncated_text = truncated_text[:idx+50] + '...[FILEMASK TRUNCATED]...' + truncated_text[end:]
        
        # Call Ollama
        response = ollama.chat(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Extract all IOCs from this security report:\n\n{truncated_text}"}
            ],
            format="json",
            options={
                "temperature": 0,
                "top_p": 0.1,
                "num_ctx": 8192
            }
        )
        
        extraction = json.loads(response['message']['content'])
        extraction['extraction_summary'] = extraction.get('extraction_summary', {})
        extraction['extraction_summary']['method'] = 'ai'
        extraction['extraction_summary']['model'] = model
        
        return extraction, True
        
    except Exception as e:
        logger.warning(f"AI extraction failed, using regex fallback: {e}")
        return RegexIOCExtractor().extract(report_text), False


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
    from models.ioc import IOC, IOCCase, get_category_for_type
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
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type=ioc_type,
            category=category,
            context=hash_item.get('context', ''),
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
        ioc_type = 'IP Address (IPv6)' if ':' in value else 'IP Address (IPv4)'
        
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
        if url_type == 'report':
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
    
    # Process file paths
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
        
        context_with_action = f"Action: {action}" if action else ""
        if context:
            context_with_action += f" | {context}" if context_with_action else context
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='File Path',
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
        else:
            value = str(reg_item).strip()
            action = ''
            context = ''
        
        if not value or value.lower() in seen_values:
            continue
        seen_values.add(value.lower())
        
        context_with_action = f"Action: {action}" if action else ""
        if context:
            context_with_action += f" | {context}" if context_with_action else context
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Registry Key',
            category='Registry',
            context=context_with_action,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(ioc_entry)
    
    # Process commands
    for cmd_item in iocs_data.get('commands', []):
        if isinstance(cmd_item, dict):
            value = cmd_item.get('value', '').strip()
            executable = cmd_item.get('executable', '')
            context = cmd_item.get('context', '')
        else:
            value = str(cmd_item).strip()
            executable = ''
            context = ''
        
        if not value or value.lower() in seen_values:
            continue
        seen_values.add(value.lower())
        
        context_with_exe = f"Executable: {executable}" if executable else ""
        if context:
            context_with_exe += f" | {context}" if context_with_exe else context
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Command Line',
            category='Process',
            context=context_with_exe,
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
        
        ioc_type = IOC_TYPE_MAP.get(cred_type, 'Password Hash')
        
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
    
    # Process hostnames (for Known Systems integration)
    for hostname in iocs_data.get('hostnames', []):
        if isinstance(hostname, dict):
            hostname_val = hostname.get('value', '') if isinstance(hostname, dict) else str(hostname)
        else:
            hostname_val = str(hostname)
        hostname_val = hostname_val.strip()
        
        if not hostname_val:
            continue
        
        # Find or create known system
        system_result = _process_known_system(hostname_val, case_id, username)
        if system_result:
            known_systems_results.append(system_result)
    
    # Also process affected_host from summary
    affected_host = extraction.get('extraction_summary', {}).get('affected_host', '')
    if affected_host and affected_host.strip():
        system_result = _process_known_system(affected_host.strip(), case_id, username)
        if system_result:
            known_systems_results.append(system_result)
    
    return {
        'iocs_to_import': iocs_to_import,
        'known_systems_results': known_systems_results,
        'known_users_results': known_users_results,
        'extraction_summary': extraction.get('extraction_summary', {}),
        'mitre_indicators': iocs_data.get('mitre_indicators', [])
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
    
    Returns dict with ioc data and existing_ioc_id if duplicate found
    """
    from models.ioc import IOC, IOCCase
    
    if not value:
        return None
    
    # Check for existing IOC
    existing_ioc = IOC.find_by_value(value, ioc_type)
    
    entry = {
        'value': value,
        'ioc_type': ioc_type,
        'category': category,
        'context': context,
        'is_new': existing_ioc is None
    }
    
    if existing_ioc:
        entry['existing_ioc_id'] = existing_ioc.id
        entry['existing_notes'] = existing_ioc.notes
        # Check if already linked to this case
        existing_link = IOCCase.query.filter_by(
            ioc_id=existing_ioc.id,
            case_id=case_id
        ).first()
        entry['already_linked'] = existing_link is not None
    
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
    
    # Find existing system
    system, match_type = KnownSystem.find_by_hostname_or_alias(hostname)
    
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
    
    # Find existing user
    user, match_type = KnownUser.find_by_username_sid_alias_or_email(
        username=username_val,
        sid=sid if sid else None
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
        Dict with created, updated, and linked counts
    """
    from models.ioc import IOC, IOCCase, IOCAudit, get_category_for_type
    from models.known_system import KnownSystem, KnownSystemAudit
    from models.known_user import KnownUser, KnownUserAudit
    from models.database import db
    
    created_count = 0
    updated_count = 0
    linked_count = 0
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
                    # Add context to notes if provided
                    if ioc_entry.get('context'):
                        if existing_ioc.notes:
                            existing_ioc.notes += f"\n\nExtracted context: {ioc_entry['context']}"
                        else:
                            existing_ioc.notes = f"Extracted context: {ioc_entry['context']}"
                        updated_count += 1
                    
                    # Link to case if not already
                    if not ioc_entry.get('already_linked'):
                        if existing_ioc.link_to_case(case_id):
                            linked_count += 1
            else:
                # Create new IOC
                value = ioc_entry['value']
                ioc_type = ioc_entry['ioc_type']
                category = ioc_entry['category']
                
                try:
                    ioc, created = IOC.get_or_create(
                        value=value,
                        ioc_type=ioc_type,
                        category=category,
                        created_by=username
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
                            new_value=f'{ioc_type}: {value}'
                        )
                    
                    # Link to case
                    if ioc.link_to_case(case_id):
                        linked_count += 1
                        
                except ValueError as e:
                    logger.warning(f"Failed to create IOC {ioc_type}: {value} - {e}")
        
        # Process known systems
        if known_systems:
            for sys_result in known_systems:
                if sys_result.get('skip', False):
                    continue
                
                action = sys_result.get('action')
                hostname = sys_result.get('hostname')
                
                if action == 'create_new':
                    # Create new system
                    netbios, fqdn = KnownSystem.extract_netbios_name(hostname)
                    new_system = KnownSystem(
                        hostname=netbios or hostname,
                        compromised=True,
                        notes=f"Created from EDR report extraction by {username}"
                    )
                    db.session.add(new_system)
                    db.session.flush()
                    
                    # Add FQDN as alias if different
                    if fqdn and fqdn != (netbios or hostname):
                        new_system.add_alias(fqdn)
                    
                    new_system.link_to_case(case_id)
                    
                    KnownSystemAudit.log_change(
                        system_id=new_system.id,
                        changed_by=username,
                        field_name='system',
                        action='create',
                        new_value=f'{netbios or hostname} (from EDR extraction)'
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
                        
                        KnownSystemAudit.log_change(
                            system_id=system.id,
                            changed_by=username,
                            field_name='compromised',
                            action='update',
                            old_value='False',
                            new_value='True'
                        )
                        systems_updated += 1
        
        # Process known users
        if known_users:
            for user_result in known_users:
                if user_result.get('skip', False):
                    continue
                
                action = user_result.get('action')
                username_val = user_result.get('username')
                sid = user_result.get('sid')
                
                if action == 'create_new':
                    # Create new user
                    normalized, domain = KnownUser.normalize_username(username_val)
                    new_user = KnownUser(
                        username=normalized or username_val,
                        sid=sid if sid else None,
                        compromised=True,
                        added_by=username,
                        notes=f"Created from EDR report extraction"
                    )
                    db.session.add(new_user)
                    db.session.flush()
                    
                    # Add original format as alias if different
                    if username_val.upper() != (normalized or username_val).upper():
                        new_user.add_alias(username_val)
                    
                    new_user.link_to_case(case_id)
                    
                    KnownUserAudit.log_change(
                        user_id=new_user.id,
                        changed_by=username,
                        field_name='user',
                        action='create',
                        new_value=f'{normalized or username_val} (from EDR extraction)'
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
        
        db.session.commit()
        
        return {
            'iocs_created': created_count,
            'iocs_updated': updated_count,
            'iocs_linked': linked_count,
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
