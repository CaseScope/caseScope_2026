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

def extract_iocs_with_ai(report_text: str, model: str = None) -> Tuple[Dict[str, Any], bool]:
    """
    Extract IOCs from report text using AI (Ollama)
    
    Returns:
        Tuple of (extraction_result, used_ai_bool)
    """
    try:
        from ollama import Client
        from models.system_settings import SystemSettings, SettingKeys, AI_MODEL_CONFIG
        
        # Check if AI is enabled
        ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
        if not ai_enabled:
            logger.info("AI extraction disabled, using regex fallback")
            return RegexIOCExtractor().extract(report_text), False
        
        # Get model from stored GPU tier setting
        if not model:
            gpu_tier = SystemSettings.get(SettingKeys.AI_GPU_TIER, '8gb')
            model_config = AI_MODEL_CONFIG.get(gpu_tier, AI_MODEL_CONFIG['8gb'])
            model = model_config.get('ioc_extraction', 'qwen2.5:7b-instruct-q4_k_m')
        
        # Truncate report if very long (keep under ~12000 chars for context window)
        MAX_REPORT_LENGTH = 12000
        truncated_text = report_text
        if len(truncated_text) > MAX_REPORT_LENGTH:
            truncated_text = truncated_text[:MAX_REPORT_LENGTH] + "\n\n[... REPORT TRUNCATED FOR PROCESSING ...]"
            logger.info(f"Report truncated from {len(report_text)} to {MAX_REPORT_LENGTH} chars")
        
        # Truncate filemask if present (can be very long)
        if '-filemask="' in truncated_text:
            idx = truncated_text.find('-filemask="')
            end = truncated_text.find('"', idx + 100)
            if end > idx:
                truncated_text = truncated_text[:idx+50] + '...[FILEMASK TRUNCATED]...' + truncated_text[end:]
        
        # Create client with timeout (3 minutes should be plenty)
        client = Client(timeout=180.0)
        
        # Call Ollama
        response = client.chat(
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
    
    # Process file paths - generate primary IOC (filename) with path as alias
    # Uses type-aware deduplication to handle existing File Name IOCs
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
        
        # Use type-aware deduplication
        # For file paths, if File Name IOC exists, add path as alias to it
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
    
    # Process commands - generate primary IOC (executable) with command aliases
    # Uses type-aware deduplication to handle File Name / Command Line overlap
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
        
        # Generate primary IOC (executable) with full command as alias
        alias_result = generate_ioc_with_aliases(value, 'Command Line')
        primary_value = alias_result['primary_value']
        aliases = alias_result['aliases']
        
        # Skip if we've already seen this primary value in THIS extraction
        if primary_value.lower() in seen_values:
            # But still add the aliases to the existing IOC entry if possible
            for entry in iocs_to_import:
                if entry.get('value', '').lower() == primary_value.lower():
                    existing_aliases = entry.get('aliases', [])
                    entry['aliases'] = list(set(existing_aliases + aliases))
                    break
            continue
        seen_values.add(primary_value.lower())
        
        context_with_exe = f"Executable: {executable}" if executable else ""
        if context:
            context_with_exe += f" | {context}" if context_with_exe else context
        context_with_exe += f" | Original command: {value[:200]}..." if len(value) > 200 else f" | Original command: {value}"
        
        # Use type-aware deduplication
        # This checks if File Name IOC exists and handles Command Line separately
        ioc_entry = _create_ioc_entry_with_type_awareness(
            primary_value=primary_value,
            primary_type=alias_result['primary_type'],
            aliases=aliases,
            original_type='Command Line',
            category='File',
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
    
    Returns dict with ioc data and metadata
    """
    from models.ioc import IOC, IOCCase
    
    if not primary_value:
        return None
    
    # Check for existing IOCs
    existing_filename = IOC.find_by_value(primary_value, 'File Name')
    existing_command = IOC.find_by_value(primary_value, 'Command Line')
    
    entry = {
        'value': primary_value,
        'ioc_type': primary_type,
        'category': category,
        'context': context,
        'aliases': aliases,
        'is_new': True,
        'merge_into_existing': False
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
            
            existing_link = IOCCase.query.filter_by(
                ioc_id=existing_command.id,
                case_id=case_id
            ).first()
            entry['already_linked'] = existing_link is not None
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
            
            existing_link = IOCCase.query.filter_by(
                ioc_id=existing_filename.id,
                case_id=case_id
            ).first()
            entry['already_linked'] = existing_link is not None
        else:
            # No File Name exists - create new File Name IOC with path as alias
            entry['ioc_type'] = 'File Name'
            entry['category'] = 'File'
            entry['is_new'] = True
        
        return entry
    
    # CASE C: Other IOC types (direct File Name, etc.)
    existing_same_type = IOC.find_by_value(primary_value, primary_type)
    if existing_same_type:
        entry['existing_ioc_id'] = existing_same_type.id
        entry['existing_notes'] = existing_same_type.notes
        entry['is_new'] = False
        entry['merge_into_existing'] = True
        
        existing_link = IOCCase.query.filter_by(
            ioc_id=existing_same_type.id,
            case_id=case_id
        ).first()
        entry['already_linked'] = existing_link is not None
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
                    
                    # Merge any new aliases
                    if ioc_entry.get('aliases'):
                        for alias in ioc_entry['aliases']:
                            existing_ioc.add_alias(alias)
                    
                    # Link to case if not already
                    if not ioc_entry.get('already_linked'):
                        if existing_ioc.link_to_case(case_id):
                            linked_count += 1
            else:
                # Create new IOC
                value = ioc_entry['value']
                ioc_type = ioc_entry['ioc_type']
                category = ioc_entry['category']
                aliases = ioc_entry.get('aliases', [])
                
                try:
                    ioc, created = IOC.get_or_create(
                        value=value,
                        ioc_type=ioc_type,
                        category=category,
                        created_by=username,
                        aliases=aliases
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
                        
                        if aliases:
                            IOCAudit.log_change(
                                ioc_id=ioc.id,
                                changed_by=username,
                                field_name='aliases',
                                action='create',
                                new_value=f'{len(aliases)} aliases added'
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
                    
                    # Create Hostname IOC for compromised system
                    try:
                        hostname_ioc, created = IOC.get_or_create(
                            value=netbios or hostname,
                            ioc_type='Hostname',
                            category=get_category_for_type('Hostname'),
                            created_by=username
                        )
                        hostname_ioc.link_to_case(case_id)
                        if created:
                            logger.info(f"Created Hostname IOC for compromised system: {netbios or hostname}")
                    except ValueError as e:
                        logger.debug(f"Hostname IOC error: {e}")
                    
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
                        
                        # Create Hostname IOC for compromised system
                        try:
                            hostname_ioc, created = IOC.get_or_create(
                                value=system.hostname,
                                ioc_type='Hostname',
                                category=get_category_for_type('Hostname'),
                                created_by=username
                            )
                            hostname_ioc.link_to_case(case_id)
                            if created:
                                logger.info(f"Created Hostname IOC for compromised system: {system.hostname}")
                        except ValueError as e:
                            logger.debug(f"Hostname IOC error: {e}")
                        
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
                    
                    # Create Username IOC for compromised user
                    try:
                        user_ioc, created = IOC.get_or_create(
                            value=normalized or username_val,
                            ioc_type='Username',
                            category=get_category_for_type('Username'),
                            created_by=username
                        )
                        user_ioc.link_to_case(case_id)
                        if created:
                            logger.info(f"Created Username IOC for compromised user: {normalized or username_val}")
                    except ValueError as e:
                        logger.debug(f"Username IOC error: {e}")
                    
                    # Create SID IOC if available
                    if sid:
                        try:
                            sid_ioc, created = IOC.get_or_create(
                                value=sid,
                                ioc_type='SID',
                                category=get_category_for_type('SID'),
                                created_by=username
                            )
                            sid_ioc.link_to_case(case_id)
                            if created:
                                logger.info(f"Created SID IOC: {sid}")
                        except ValueError as e:
                            logger.debug(f"SID IOC error: {e}")
                    
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
                        
                        # Create Username IOC for compromised user
                        try:
                            user_ioc, created = IOC.get_or_create(
                                value=user.username,
                                ioc_type='Username',
                                category=get_category_for_type('Username'),
                                created_by=username
                            )
                            user_ioc.link_to_case(case_id)
                            if created:
                                logger.info(f"Created Username IOC for compromised user: {user.username}")
                        except ValueError as e:
                            logger.debug(f"Username IOC error: {e}")
                        
                        # Create SID IOC if available
                        user_sid = sid or user.sid
                        if user_sid:
                            try:
                                sid_ioc, created = IOC.get_or_create(
                                    value=user_sid,
                                    ioc_type='SID',
                                    category=get_category_for_type('SID'),
                                    created_by=username
                                )
                                sid_ioc.link_to_case(case_id)
                                if created:
                                    logger.info(f"Created SID IOC: {user_sid}")
                            except ValueError as e:
                                logger.debug(f"SID IOC error: {e}")
                        
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
