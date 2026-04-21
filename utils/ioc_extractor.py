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
import importlib.util
import os
import sys
from collections import Counter
from copy import deepcopy
from urllib.parse import urlsplit
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _LazyModuleProxy:
    """Load sibling IOC modules only when a path actually needs them."""

    def __init__(self, name: str, filename: str):
        self._module_name = name
        self._filename = filename
        self._loaded_module = None
        self._module_shims = {
            module_name: sys.modules[module_name]
            for module_name in ("utils", "utils.ai", "utils.ai.router", "utils.ai_training")
            if module_name in sys.modules
        }

    def _load(self):
        if self._loaded_module is None:
            previous_modules = {
                module_name: sys.modules.get(module_name)
                for module_name in self._module_shims
            }
            try:
                for module_name, module in self._module_shims.items():
                    sys.modules[module_name] = module
                self._loaded_module = _load_local_module(self._module_name, self._filename)
            finally:
                for module_name, previous_module in previous_modules.items():
                    if previous_module is None:
                        sys.modules.pop(module_name, None)
                    else:
                        sys.modules[module_name] = previous_module
        return self._loaded_module

    def __getattr__(self, item: str):
        return getattr(self._load(), item)


_ioc_contract = _LazyModuleProxy("ioc_contract_shared", "ioc_contract.py")
_ai_review = _LazyModuleProxy("ai_review_shared", "ai_review.py")
_report_normalizer = _LazyModuleProxy("ioc_report_normalizer_shared", "report_normalizer.py")
_ioc_schema = _LazyModuleProxy("ioc_schema_shared", "ioc_schema.py")
_ioc_merge = _LazyModuleProxy("ioc_merge_shared", "ioc_merge.py")
_deterministic_stage = _LazyModuleProxy("deterministic_ioc_extractor_shared", "deterministic_ioc_extractor.py")
_semantic_stage = _LazyModuleProxy("semantic_ioc_extractor_shared", "semantic_ioc_extractor.py")
_audit_stage = _LazyModuleProxy("ioc_audit_shared", "ioc_audit.py")
_ioc_aliasing = _LazyModuleProxy("ioc_aliasing_shared", "ioc_aliasing.py")
_ioc_import_entries = _LazyModuleProxy("ioc_import_entries_shared", "ioc_import_entries.py")
_ioc_known_entities = _LazyModuleProxy("ioc_known_entities_shared", "ioc_known_entities.py")
_ioc_text = _LazyModuleProxy("ioc_text_shared", "ioc_text.py")
_ioc_normalizer = _LazyModuleProxy("ioc_normalizer_shared", "ioc_normalizer.py")
_ioc_contract_adapter = _LazyModuleProxy("ioc_contract_adapter_shared", "ioc_contract_adapter.py")
_ai_router = _LazyModuleProxy("ai_router_shared", "ai/router.py")
_ioc_regex_catalog = _load_local_module("ioc_regex_catalog_shared", "ioc_regex_catalog.py")

logger = logging.getLogger(__name__)

__all__ = [
    "RegexIOCExtractor",
    "extract_derived_indicator_candidates",
    "run_deterministic_ioc_extraction",
    "run_ioc_pipeline_with_provider",
    "extract_iocs_with_ai",
    "process_extraction_for_import",
    "save_extracted_iocs",
    "split_edr_reports",
    "get_report_preview",
]

INVALID_HASH_PLACEHOLDERS = (
    'file is no longer on disk',
    'not available',
    'not present',
    'unknown',
    'n/a',
    'none',
)
INVALID_AI_PLACEHOLDERS = {
    '',
    '...',
    '…',
    'unknown',
    'n/a',
    'none',
    'null',
    'nil',
    'tbd',
}
COMPROMISE_EVIDENCE_HINTS = (
    'credential theft',
    'credentials stolen',
    'compromised account',
    'compromised user',
    'password observed',
    'password reset',
    'password spray',
    'unauthorized login',
    'account takeover',
    'stolen credentials',
)

SEMANTIC_TASK_ALLOWED_FIELDS = {
    'semantic_users_and_accounts': {
        'affected_users': None,
        'authentication_iocs': (
            'compromised_users',
            'created_users',
            'passwords_observed',
        ),
    },
    'semantic_process_relationships': {
        'process_iocs': (
            'commands',
            'services',
            'scheduled_tasks',
        ),
    },
    'semantic_persistence_actions': {
        'persistence_iocs': (
            'registry',
            'credential_theft_indicators',
        ),
        'vulnerability_iocs': (
            'webshells',
        ),
    },
    'semantic_credentials_and_auth': {
        'affected_users': None,
        'authentication_iocs': (
            'compromised_users',
            'created_users',
            'passwords_observed',
        ),
    },
}

SECTION_HEADER_PATTERN = re.compile(r'^[A-Za-z0-9 /()\[\]_-]+:?$')
AI_CHUNK_OVERLAP_CHARS = 400
AI_CONTEXT_CHUNK_CAP_CHARS = 160000
AI_REVIEW_MAX_TOKENS = 3000

# ============================================
# IOC Type Mappings
# ============================================

IOC_TYPE_MAP = _ioc_regex_catalog.IOC_TYPE_MAP
IOC_CATEGORY_MAP = _ioc_regex_catalog.IOC_CATEGORY_MAP


# ============================================
# Regex-based IOC Extraction (Fallback)
# ============================================

class RegexIOCExtractor:
    """Regex-based IOC extractor as fallback when AI is unavailable"""

    # IOC Patterns - expanded based on 75 reports
    PATTERNS = _ioc_regex_catalog.REGEX_IOC_PATTERNS

    # Known RMM tools to flag
    RMM_TOOLS = _ioc_regex_catalog.REGEX_EXTRACTOR_RMM_TOOLS

    # Known malware families from reports
    MALWARE_FAMILIES = _ioc_regex_catalog.REGEX_EXTRACTOR_MALWARE_FAMILIES
    
    def __init__(self):
        pass
    
    def defang(self, text: str) -> str:
        """De-obfuscate/defang indicators in text"""
        return _ioc_text._defang_text(text)

    def _line_context_hint(self, text: str) -> str:
        lowered = (text or '').lower()
        if any(token in lowered for token in ('delete ', 'remove ', 'kill process', 'reboot', 'recommended action', 'remediation', 'response guidance')):
            return 'Remediation reference'
        if any(token in lowered for token in ('observed', 'detected', 'evidence', 'storyline', 'incident', 'execution', 'activity')):
            return 'Observed activity'
        return ''

    def _extract_structured_entities(self, original_text: str, results: Dict[str, Any]) -> None:
        host_patterns = (
            re.compile(r'^\s*(?:Host Name|Host|Endpoint|Device)\s*[:=]\s*(.+?)\s*$', re.I),
        )
        user_patterns = (
            re.compile(r'^\s*(?:User Account|User|Actor User)\s*[:=]\s*(.+?)\s*$', re.I),
        )
        sid_pattern = re.compile(r'(S-1-\d+(?:-\d+)+)')
        seen_hosts = {str(host).strip().lower() for host in results['extraction_summary'].get('affected_hosts', [])}
        seen_users = {
            (
                str((item or {}).get('username', '')).strip().lower(),
                str((item or {}).get('sid', '')).strip(),
            )
            for item in results['extraction_summary'].get('affected_users', [])
            if isinstance(item, dict)
        }
        lines = original_text.splitlines()
        for index, line in enumerate(lines):
            stripped = line.strip().strip('"')
            if not stripped:
                continue
            for pattern in host_patterns:
                match = pattern.match(stripped)
                if match:
                    host = match.group(1).strip().strip('"').split()[0]
                    if host and host.lower() not in seen_hosts and not self.PATTERNS['ip_v4'].match(host):
                        seen_hosts.add(host.lower())
                        results['extraction_summary']['affected_hosts'].append(host)
                        results['iocs']['hostnames'].append({'value': host, 'context': self._line_context_hint(line)})
            for pattern in user_patterns:
                match = pattern.match(stripped)
                if not match:
                    continue
                username = match.group(1).strip().strip('"')
                if ':' in username:
                    continue
                window = "\n".join(lines[max(0, index - 1): min(len(lines), index + 3)])
                sid_match = sid_pattern.search(window)
                sid = sid_match.group(1) if sid_match else ''
                dedupe_key = (username.lower(), sid)
                if username and dedupe_key not in seen_users:
                    seen_users.add(dedupe_key)
                    user_item = {'username': username, 'sid': sid}
                    results['extraction_summary']['affected_users'].append(user_item)
                    results['iocs']['users'].append({'value': username, 'context': self._line_context_hint(window)})
                    if sid:
                        results['iocs']['sids'].append(sid)

    def _extract_structured_activity(self, original_text: str, results: Dict[str, Any]) -> None:
        lines = original_text.splitlines()
        command_patterns = (
            re.compile(r'^\s*(?:- )?(?:Command Line|Command|ProcessCommandLine|Execution chain)\s*[:=]\s*(.+?)\s*$', re.I),
        )
        parent_pattern = re.compile(r'^\s*(?:Parent Process)\s*[:=]\s*(.+?)\s*$', re.I)
        user_pattern = re.compile(r'^\s*(?:User|Actor User)\s*[:=]\s*(.+?)\s*$', re.I)
        pid_pattern = re.compile(r'^\s*(?:Process ID|PID)\s*[:=]\s*(.+?)\s*$', re.I)
        service_patterns = (
            re.compile(r'^\s*(?:Service Name|Service Display Name|Service|service)\s*(?:=>|[:=])\s*(.+?)\s*$', re.I),
            re.compile(r'^\s*(?:- )?(?:Delete Service|Create Service)\s*-\s*name:\s*(.+?)\s*$', re.I),
        )
        task_patterns = (
            re.compile(r'^\s*(?:Scheduled Task|ScheduledTask|TaskName|task)\s*(?:=>|[:=])\s*(.+?)\s*$', re.I),
        )
        registry_patterns = (
            re.compile(r'^\s*(?:RegistryKey|Registry Key|registry)\s*(?:=>|[:=])\s*(.+?)\s*$', re.I),
        )
        seen_commands = {
            str((item or {}).get('value', '')).strip().lower()
            for item in results['iocs'].get('commands', [])
            if isinstance(item, dict)
        }
        seen_services = {
            str((item or {}).get('name', '')).strip().lower()
            for item in results['iocs'].get('services', [])
            if isinstance(item, dict)
        }
        seen_tasks = {
            str((item or {}).get('name', '') or (item or {}).get('path', '')).strip().lower()
            for item in results['iocs'].get('scheduled_tasks', [])
            if isinstance(item, dict)
        }
        seen_registry = {
            str((item or {}).get('value', '')).strip().lower()
            for item in results['iocs'].get('registry_keys', [])
            if isinstance(item, dict)
        }

        for index, raw_line in enumerate(lines):
            line = raw_line.strip()
            if not line:
                continue
            window_lines = lines[max(0, index - 1): min(len(lines), index + 4)]
            window_text = "\n".join(window_lines)
            context = self._line_context_hint(window_text)

            for pattern in command_patterns:
                match = pattern.match(line)
                if not match:
                    continue
                command = self.defang(match.group(1).strip().strip('"'))
                lowered_command = command.lower()
                if not command or lowered_command in seen_commands:
                    continue
                seen_commands.add(lowered_command)
                parent_match = parent_pattern.search(window_text)
                user_match = user_pattern.search(window_text)
                pid_match = pid_pattern.search(window_text)
                results['iocs']['commands'].append({
                    'value': command,
                    'parent': self.defang(parent_match.group(1).strip()) if parent_match else '',
                    'user': user_match.group(1).strip() if user_match else '',
                    'pid': pid_match.group(1).strip() if pid_match else '',
                    'context': context,
                })
                results['raw_artifacts']['full_commands'].append(command)

            for pattern in service_patterns:
                match = pattern.match(line)
                if not match:
                    continue
                service_name = self.defang(match.group(1).strip().strip('"'))
                lowered_name = service_name.lower()
                if not service_name or lowered_name in seen_services:
                    continue
                seen_services.add(lowered_name)
                action = 'delete' if 'delete service' in line.lower() else 'create' if 'create' in line.lower() else 'unknown'
                results['iocs']['services'].append({
                    'name': service_name,
                    'action': action,
                    'context': context,
                })

            for pattern in task_patterns:
                match = pattern.match(line)
                if not match:
                    continue
                task_name = self.defang(match.group(1).strip().strip('"'))
                lowered_name = task_name.lower()
                if not task_name or lowered_name in seen_tasks:
                    continue
                seen_tasks.add(lowered_name)
                results['iocs']['scheduled_tasks'].append({
                    'name': task_name,
                    'action': 'delete' if 'delete' in line.lower() else 'unknown',
                    'context': context,
                })

            for pattern in registry_patterns:
                match = pattern.match(line)
                if not match:
                    continue
                registry_key = self.defang(match.group(1).strip().strip('"'))
                lowered_key = registry_key.lower()
                if not registry_key or lowered_key in seen_registry:
                    continue
                seen_registry.add(lowered_key)
                results['iocs']['registry_keys'].append({
                    'value': registry_key,
                    'action': 'delete' if 'delete' in line.lower() or 'remove' in line.lower() else 'unknown',
                    'context': context,
                })
    
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
            path, note = _normalize_extracted_file_path(match)
            if not path:
                continue
            results['iocs']['file_paths'].append({
                'value': path,
                'action': 'unknown',
                'context': note
            })
        
        # Extract file paths (Unix/macOS)
        for match in self.PATTERNS['file_path_unix'].findall(clean_text):
            path, note = _normalize_extracted_file_path(match)
            if not path:
                continue
            results['iocs']['file_paths'].append({
                'value': path,
                'action': 'unknown',
                'context': ' | '.join(part for part in ('Unix/macOS path', note) if part)
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

        # Extract explicit threat-name and malware-family statements
        for match in self.PATTERNS['threat_name'].findall(original_text):
            value = match.strip().strip('"').strip("'")
            if value:
                results['iocs']['threat_names'].append(value)
        for match in self.PATTERNS['malware_family'].findall(original_text):
            value = match.strip().strip('"').strip("'")
            if value:
                results['iocs']['threat_names'].append(value)
                results['extraction_summary']['threat_families'].append(value)
        
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

        self._extract_structured_entities(original_text, results)
        self._extract_structured_activity(original_text, results)
        
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
        results['iocs']['commands'] = self._dedupe_list_of_dicts(results['iocs']['commands'], 'value')
        results['iocs']['services'] = self._dedupe_list_of_dicts(results['iocs']['services'], 'name')
        results['iocs']['scheduled_tasks'] = self._dedupe_list_of_dicts(results['iocs']['scheduled_tasks'], 'name')
        results['iocs']['hostnames'] = self._dedupe_list_of_dicts(results['iocs']['hostnames'], 'value')
        results['iocs']['sids'] = list(set(results['iocs']['sids']))
        results['iocs']['email_addresses'] = list(set(results['iocs']['email_addresses']))
        results['iocs']['cves'] = list(set(results['iocs']['cves']))
        results['extraction_summary']['threat_families'] = list(set(results['extraction_summary']['threat_families']))
        results['raw_artifacts']['full_commands'] = list(dict.fromkeys(results['raw_artifacts']['full_commands']))
        results['extraction_summary']['affected_hosts'] = list(dict.fromkeys(results['extraction_summary']['affected_hosts']))
        seen_users = set()
        deduped_users = []
        for item in results['extraction_summary']['affected_users']:
            if not isinstance(item, dict):
                continue
            key = (
                str(item.get('username', '')).strip().lower(),
                str(item.get('sid', '')).strip(),
            )
            if key in seen_users:
                continue
            seen_users.add(key)
            deduped_users.append(item)
        results['extraction_summary']['affected_users'] = deduped_users
        
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


def _defang_text(value: str) -> str:
    """Normalize common defanged IOC encodings."""
    return _ioc_text._defang_text(value)


def extract_derived_indicator_candidates(
    ioc_value: str,
    context_values: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    """Extract related IOC candidates from the canonical IOC boundary.

    This keeps downstream enrichers on the public IOC orchestration surface
    instead of reaching into regex internals or maintaining their own import
    fallback logic.
    """
    extractor = RegexIOCExtractor()
    candidate_map: Dict[str, Dict[str, str]] = {}
    values = [ioc_value]
    values.extend(context_values or [])

    def _add_candidate(source_value: str, value: str, indicator_type: str) -> None:
        normalized_value = _defang_text(value).strip()
        if not normalized_value:
            return
        key = f"{indicator_type}::{normalized_value.lower()}"
        if key in candidate_map:
            return
        candidate_map[key] = {
            "source_value": source_value[:300],
            "extracted_value": normalized_value,
            "extracted_type": indicator_type,
        }

    for source_value in values:
        if not isinstance(source_value, str) or not source_value.strip():
            continue
        clean_source = _defang_text(source_value)
        extracted = extractor.extract(clean_source)
        iocs = extracted.get("iocs", {})

        for hash_item in iocs.get("hashes", []):
            hash_type = str(hash_item.get("type", "")).lower()
            mapped_type = {
                "md5": "MD5 Hash",
                "sha1": "SHA1 Hash",
                "sha256": "SHA256 Hash",
            }.get(hash_type)
            if mapped_type:
                _add_candidate(source_value, hash_item.get("value", ""), mapped_type)

        for url_item in iocs.get("urls", []):
            _add_candidate(source_value, url_item.get("value", ""), "URL")

        for domain_item in iocs.get("domains", []):
            _add_candidate(source_value, domain_item.get("value", ""), "Domain")

        for ip_item in iocs.get("ip_addresses", []):
            value = ip_item.get("value", "")
            if ":" in value:
                _add_candidate(source_value, value, "IP Address (IPv6)")
            else:
                _add_candidate(source_value, value, "IP Address (IPv4)")

        for email_item in iocs.get("email_addresses", []):
            _add_candidate(source_value, email_item.get("value", ""), "Email Address")

    return list(candidate_map.values())[:10]


def run_deterministic_ioc_extraction(report_text: str) -> Dict[str, Any]:
    """Run the canonical deterministic IOC extraction stage."""
    return _deterministic_stage.run_deterministic_stage(
        report_text,
        RegexIOCExtractor,
    )


def _normalize_extracted_file_path(value: Any) -> Tuple[Optional[str], str]:
    """Strip Huntress remediation/status annotations from a captured file path."""
    return _ioc_text._normalize_extracted_file_path(value)


def _is_placeholder_value(value: Any) -> bool:
    """Return True for schema placeholders and model filler values."""
    return _ioc_normalizer._is_placeholder_value(value)


def _is_huntress_portal_value(value: str) -> bool:
    """Return True when the value points at Huntress portal infrastructure."""
    return _ioc_normalizer._is_huntress_portal_value(value)


def _normalize_ai_network_item(item: Any, item_type: str) -> Optional[Dict[str, Any]]:
    """Normalize AI-provided network IOC items into saveable values."""
    return _ioc_normalizer._normalize_ai_network_item(item, item_type)


def _normalize_ai_hash_item(item: Any) -> Optional[Dict[str, Any]]:
    """Drop placeholder hashes and keep only valid hash values."""
    return _ioc_normalizer._normalize_ai_hash_item(item)


def _normalize_ai_file_path_item(item: Any) -> Optional[Dict[str, Any]]:
    """Normalize AI-provided file path items."""
    return _ioc_normalizer._normalize_ai_file_path_item(item)


def _normalize_ai_file_name(value: Any) -> Optional[str]:
    """Collapse path-like file names to basenames."""
    return _ioc_normalizer._normalize_ai_file_name(value)


def _normalize_ai_user_item(item: Any, context: str = '') -> Optional[Dict[str, Any]]:
    """Map AI user objects into the importer's expected value shape."""
    return _ioc_normalizer._normalize_ai_user_item(item, context=context)


def _extract_report_urls(report_text: str) -> List[str]:
    """Extract defanged non-Huntress URLs from the source report."""
    return _ioc_normalizer._extract_report_urls(report_text)


def _reconcile_url_against_report(url_value: str, report_urls: List[str]) -> str:
    """Prefer the exact scheme and path observed in the report text."""
    return _ioc_normalizer._reconcile_url_against_report(url_value, report_urls)


def _report_supports_compromised_users(report_text: str) -> bool:
    """Require explicit compromise language before trusting compromised_users."""
    return _ioc_normalizer._report_supports_compromised_users(report_text)


def _apply_ai_guardrails(normalized: Dict[str, Any], report_text: str) -> Dict[str, Any]:
    """Apply model-family guardrails against the original report text."""
    return _ioc_normalizer._apply_ai_guardrails(normalized, report_text)


def _dedupe_mixed_list(*sequences: List[Any]) -> List[Any]:
    """Deduplicate strings and dict-like values while preserving order."""
    return _ioc_normalizer._dedupe_mixed_list(*sequences)


def _as_list(value: Any) -> List[Any]:
    """Normalize optional schema values into lists."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _coerce_ioc_contract_payload(payload: Any) -> Dict[str, Any]:
    """Coerce model output into the canonical IOC contract shape."""
    return _ioc_contract_adapter.coerce_ioc_contract_payload(payload)


def _ioc_schema_metrics(extraction: Any) -> Dict[str, bool]:
    """Validate the top-level IOC extraction schema shape."""
    return _ioc_contract_adapter.ioc_schema_metrics(extraction)


def _is_valid_ioc_schema(extraction: Any) -> bool:
    """Return True when the payload matches the expected contract keys."""
    return _ioc_contract_adapter.is_valid_ioc_schema(extraction)


def _iter_contract_key_violations(
    payload: Any,
    contract: Any,
    *,
    path: str = '',
) -> List[str]:
    """Return unexpected nested keys that fall outside the IOC contract."""
    return _ioc_contract_adapter.iter_contract_key_violations(
        payload,
        contract,
        path=path,
    )


def _list_has_suspicious_repetition(items: List[Any], *, min_repeats: int = 3) -> bool:
    """Return True when the same exact entry repeats enough to suggest degeneration."""
    if not isinstance(items, list) or len(items) < min_repeats:
        return False

    counts: Counter[str] = Counter()
    for item in items:
        try:
            signature = json.dumps(item, sort_keys=True, default=str)
        except Exception:
            signature = str(item)
        counts[signature] += 1
        if counts[signature] >= min_repeats:
            return True
    return False


def _iter_payload_lists(payload: Any) -> List[Tuple[str, List[Any]]]:
    """Collect nested list fields from a JSON-like payload."""
    collected: List[Tuple[str, List[Any]]] = []

    def _walk(value: Any, path: str) -> None:
        if isinstance(value, list):
            collected.append((path, value))
            return
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else key
                _walk(child, child_path)

    _walk(payload, '')
    return collected


def _find_invalid_hash_entries(payload: Any) -> List[str]:
    """Return JSON paths for hash items that fail the existing hash validators."""
    return _ioc_contract_adapter.find_invalid_hash_entries(payload)


def _is_semantically_empty(value: Any) -> bool:
    """Return True when a JSON-like value contains no meaningful data."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set)):
        return all(_is_semantically_empty(item) for item in value)
    if isinstance(value, dict):
        return all(_is_semantically_empty(item) for item in value.values())
    return False


def _payload_semantic_review_reasons(
    payload: Any,
    *,
    task_name: Optional[str] = None,
) -> List[str]:
    """Return semantic-quality reasons to trigger IOC payload review."""
    return _ioc_contract_adapter.payload_semantic_review_reasons(
        payload,
        task_name=task_name,
        semantic_task_allowed_fields=SEMANTIC_TASK_ALLOWED_FIELDS,
    )


def _has_repetitive_long_substring(text: str, *, window: int = 80, min_repeats: int = 3) -> bool:
    """Detect long repeated substrings that often indicate model looping."""
    normalized = re.sub(r'\s+', ' ', str(text or '')).strip()
    if len(normalized) < window * min_repeats:
        return False

    long_lines = [
        line.strip()
        for line in str(text or '').splitlines()
        if len(line.strip()) >= window
    ]
    if long_lines:
        line_counts = Counter(long_lines)
        if any(count >= min_repeats for count in line_counts.values()):
            return True

    counts: Counter[str] = Counter()
    step = max(5, window // 8)
    for index in range(0, len(normalized) - window + 1, step):
        chunk = normalized[index:index + window]
        counts[chunk] += 1
        if counts[chunk] >= min_repeats:
            return True
    return False


def _validate_ai_result_metadata(ai_result: Dict[str, Any]) -> Optional[str]:
    """Return a fail-fast error for empty, truncated, or repetitive AI output."""
    return _ioc_contract_adapter.validate_ai_result_metadata(ai_result)


def _prepare_ai_extraction_payload(
    provider: Any,
    payload: Any,
    *,
    max_tokens: int,
    task_name: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Validate and lightly repair AI JSON before normalization."""
    return _ioc_contract_adapter.prepare_ai_extraction_payload(
        provider,
        payload,
        max_tokens=max_tokens,
        ai_review_max_tokens=AI_REVIEW_MAX_TOKENS,
        task_name=task_name,
        semantic_task_allowed_fields=SEMANTIC_TASK_ALLOWED_FIELDS,
        review_structured_output=_ai_review.review_structured_output,
    )


def _filter_semantic_payload_for_task(task_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only the schema fields owned by the semantic task."""
    return _ioc_contract_adapter.filter_semantic_payload_for_task(
        task_name,
        payload,
        semantic_task_allowed_fields=SEMANTIC_TASK_ALLOWED_FIELDS,
    )


def _split_large_section_blocks(
    section_name: str,
    section_text: str,
    max_chars: int,
    overlap_chars: int = AI_CHUNK_OVERLAP_CHARS,
) -> List[Dict[str, Any]]:
    """Split oversized sections into paragraph-aware blocks with overlap."""
    return _report_normalizer.split_large_section_blocks(
        section_name,
        section_text,
        max_chars,
        overlap_chars=overlap_chars,
    )


def _split_report_sections(report_text: str) -> List[Tuple[str, str]]:
    """Split a Huntress-style report into section title/body pairs."""
    return _report_normalizer.split_report_sections(report_text)


def _split_large_section(section_name: str, section_text: str, max_chars: int) -> List[str]:
    """Split oversized sections into paragraph-aware chunks."""
    return [
        block['text']
        for block in _report_normalizer.split_large_section_blocks(
            section_name,
            section_text,
            max_chars,
            overlap_chars=AI_CHUNK_OVERLAP_CHARS,
        )
    ]


def _chunk_report_for_ai_with_metadata(report_text: str, max_chars: int) -> List[Dict[str, Any]]:
    """Chunk a report for AI extraction and preserve section provenance."""
    return _report_normalizer.chunk_report_for_ai_with_metadata(report_text, max_chars)


def _chunk_report_for_ai(report_text: str, max_chars: int) -> List[str]:
    """Chunk a report for AI extraction without blunt front-only truncation."""
    return _report_normalizer.chunk_report_for_ai(report_text, max_chars)


def _resolve_ai_chunk_config(batch_config: Dict[str, Any]) -> Dict[str, int]:
    """Estimate safe input chunk sizing from the provider context window."""
    context_window = max(8192, int(batch_config.get('context_window', 16384) or 16384))
    max_response_tokens = min(8000, max(2000, int(batch_config.get('max_tokens', 6000) or 6000)))
    reserved_tokens = min(
        max(max_response_tokens + 2048, 4096),
        max(context_window // 2, 4096),
    )
    available_input_tokens = max(2000, context_window - reserved_tokens)
    chars_per_token = 3 if context_window >= 64000 else 2
    max_chunk_chars = min(
        AI_CONTEXT_CHUNK_CAP_CHARS,
        max(8000, available_input_tokens * chars_per_token),
    )
    return {
        'max_chunk_chars': max_chunk_chars,
        'max_response_tokens': max_response_tokens,
    }


def _build_ioc_chunk_prompt(chunk_meta: Dict[str, Any]) -> str:
    """Render the user prompt for one AI extraction chunk."""
    chunk_text = chunk_meta.get('text', '')
    total_chunks = int(chunk_meta.get('chunk_count') or 1)
    if total_chunks == 1:
        return _ioc_contract.IOC_USER_PROMPT_TEMPLATE.format(chunk_text)

    sections = ', '.join(chunk_meta.get('sections') or ['Full Report'])
    overlap_note = ''
    if chunk_meta.get('overlap_applied'):
        overlap_note = '\n[Context overlap from the previous chunk is included for boundary continuity.]'
    chunk_label = (
        f"[Chunk {chunk_meta.get('chunk_index', 1)} of {total_chunks} | "
        f"Sections: {sections}]{overlap_note}"
    )
    return _ioc_contract.IOC_USER_PROMPT_TEMPLATE.format(f"{chunk_label}\n\n{chunk_text}")


def _merge_summary_dicts(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
    """Merge extraction summaries from multiple AI chunk passes."""
    return _ioc_merge.merge_extraction_summaries(primary, secondary)


def _merge_ai_extractions(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
    """Merge multiple normalized AI extractions before regex enrichment."""
    return _ioc_merge.merge_ai_extractions(primary, secondary)


# ============================================
# AI IOC Extraction
# ============================================

def _resolve_ioc_pipeline_mode(explicit_mode: Optional[str] = None) -> str:
    """Resolve the active IOC AI pipeline mode with a safe default."""
    mode = explicit_mode
    if not mode:
        try:
            from config import Config

            mode = getattr(Config, 'AI_IOC_PIPELINE_MODE', 'semantic')
        except Exception:
            mode = 'semantic'

    try:
        from models.system_settings import SettingKeys, SystemSettings

        mode = SystemSettings.get(SettingKeys.AI_IOC_PIPELINE_MODE, mode or 'semantic')
    except Exception:
        pass

    normalized = str(mode or 'semantic').strip().lower()
    return 'audit' if normalized == 'audit' else 'semantic'


def run_ioc_pipeline_with_provider(
    report_text: str,
    provider: Any,
    *,
    pipeline_mode: Optional[str] = None,
    model_name: Optional[str] = None,
) -> Tuple[Dict[str, Any], bool]:
    """Run the configured IOC pipeline using an already resolved provider."""
    deterministic_extraction = run_deterministic_ioc_extraction(report_text)
    prepared_text = _report_normalizer.prepare_ioc_report_text(report_text)
    batch_config = provider.get_batch_config()
    chunk_config = _resolve_ai_chunk_config(batch_config)
    max_chunk_chars = chunk_config['max_chunk_chars']
    max_response_tokens = chunk_config['max_response_tokens']
    resolved_mode = _resolve_ioc_pipeline_mode(pipeline_mode)

    if resolved_mode == 'audit':
        audit_stage = _audit_stage.run_audit_stage(
            provider,
            prepared_text,
            deterministic_extraction,
            max_chunk_chars=max_chunk_chars,
            max_response_tokens=max_response_tokens,
            validate_result=_validate_ai_result_metadata,
        )
        audited_extraction = _apply_ai_guardrails(
            audit_stage.get('audited_extraction', deterministic_extraction),
            report_text,
        )
        audited_extraction['deterministic_extraction'] = deepcopy(deterministic_extraction)
        audited_extraction['audit_overlay'] = {
            'validated_deltas': deepcopy(audit_stage.get('validated_deltas', [])),
            'reviewed_chunks': audit_stage.get('reviewed_chunks', 0),
            'candidate_count': audit_stage.get('candidate_count', 0),
            'rejected_delta_count': audit_stage.get('rejected_delta_count', 0),
            'task_failures': audit_stage.get('task_failures', []),
            'task_provenance': audit_stage.get('task_provenance', []),
        }
        audited_extraction.setdefault('extraction_summary', {})
        audited_extraction['extraction_summary']['audit_chunk_count'] = audit_stage.get('reviewed_chunks', 0)
        audited_extraction['extraction_summary']['audit_candidate_count'] = audit_stage.get('candidate_count', 0)
        audited_extraction['extraction_summary']['audit_rejected_delta_count'] = audit_stage.get('rejected_delta_count', 0)
        audited_extraction['extraction_summary']['audit_task_failures'] = audit_stage.get('task_failures', [])
        audited_extraction['extraction_summary']['audit_task_provenance'] = audit_stage.get('task_provenance', [])
        audited_extraction['_ioc_records'] = _ioc_merge.merge_record_lists(
            deterministic_extraction.get('_ioc_records', []),
            _ioc_schema.records_from_extraction(
                audited_extraction,
                source='llm_audit',
                trust_tier=_ioc_schema.TRUST_LOW,
            ),
        )
        audited_extraction['extraction_summary']['model'] = model_name or getattr(provider, 'model', '')
        if audited_extraction['extraction_summary'].get('audit_task_failures'):
            audited_extraction['extraction_summary']['method'] = 'deterministic_plus_audit_degraded'
            audited_extraction['extraction_summary']['method_detail'] = (
                'Extraction used deterministic parsing first, then chunk-level audit deltas. '
                'One or more audit chunks failed, so corrections or suppression may be incomplete. '
                'The pre-audit deterministic candidate set is preserved separately.'
            )
            audited_extraction['extraction_summary']['ai_degraded'] = True
        else:
            audited_extraction['extraction_summary']['method'] = 'deterministic_plus_audit'
            audited_extraction['extraction_summary']['method_detail'] = (
                'Extraction used deterministic parsing first, then vendor-agnostic chunk-level '
                'LLM auditing to add, correct, or drop candidates before final assembly. '
                'The pre-audit deterministic candidate set is preserved separately.'
            )
        used_ai = bool(audit_stage.get('reviewed_chunks'))
        return audited_extraction, used_ai

    semantic_stage = _semantic_stage.run_semantic_stage(
        provider,
        prepared_text,
        deterministic_extraction,
        max_chunk_chars=max_chunk_chars,
        max_response_tokens=max_response_tokens,
        validate_result=_validate_ai_result_metadata,
        prepare_payload=_prepare_ai_extraction_payload,
        filter_payload_for_task=_filter_semantic_payload_for_task,
        normalize_extraction=_normalize_ai_extraction,
    )
    normalized_chunks = semantic_stage.get('normalized_results', [])
    ai_extraction = deterministic_extraction

    if not semantic_stage.get('planned_tasks'):
        ai_extraction.setdefault('extraction_summary', {})
        ai_extraction['extraction_summary']['semantic_task_count'] = 0
        ai_extraction['extraction_summary']['semantic_task_successes'] = 0
        ai_extraction['extraction_summary']['semantic_task_failures'] = []
        ai_extraction['extraction_summary']['semantic_schema_reviews'] = 0
        ai_extraction['extraction_summary']['semantic_task_provenance'] = []

    if normalized_chunks:
        ai_extraction = _ioc_merge.merge_semantic_results(
            deterministic_extraction,
            normalized_chunks,
            merge_func=_merge_extractions,
            merge_summary_func=_merge_summary_dicts,
        )
        ai_extraction.setdefault('extraction_summary', {})
        ai_extraction['extraction_summary']['semantic_task_count'] = len(semantic_stage.get('planned_tasks', []))
        ai_extraction['extraction_summary']['semantic_task_successes'] = len(normalized_chunks)
        ai_extraction['extraction_summary']['semantic_task_failures'] = semantic_stage.get('task_failures', [])
        ai_extraction['extraction_summary']['semantic_schema_reviews'] = semantic_stage.get('schema_reviews', 0)
        ai_extraction['extraction_summary']['semantic_task_provenance'] = semantic_stage.get('task_provenance', [])
        semantic_records: List[Dict[str, Any]] = []
        for normalized_chunk in normalized_chunks:
            semantic_records = _ioc_merge.merge_record_lists(
                semantic_records,
                _ioc_schema.records_from_extraction(
                    normalized_chunk,
                    source='llm',
                    trust_tier=_ioc_schema.TRUST_LOW,
                ),
            )
        ai_extraction['_ioc_records'] = _ioc_merge.merge_record_lists(
            deterministic_extraction.get('_ioc_records', []),
            semantic_records,
        )

    ai_extraction.setdefault('extraction_summary', {})
    ai_extraction['extraction_summary']['model'] = model_name or getattr(provider, 'model', '')
    if ai_extraction['extraction_summary'].get('semantic_task_failures'):
        ai_extraction['extraction_summary']['method'] = 'deterministic_plus_semantic_degraded'
        ai_extraction['extraction_summary']['method_detail'] = (
            'Extraction used deterministic parsing plus targeted semantic passes, but one or more '
            'semantic tasks failed. Concrete artifact coverage should still be present, but some '
            'semantic IOC relationships may be incomplete.'
        )
        ai_extraction['extraction_summary']['ai_degraded'] = True
    else:
        ai_extraction['extraction_summary']['method'] = 'deterministic_plus_semantic'
        ai_extraction['extraction_summary']['method_detail'] = (
            'Extraction used deterministic parsing first, then targeted semantic analysis '
            'and a residual review pass for contextual IOC coverage.'
        )
    used_ai = bool(ai_extraction['extraction_summary'].get('semantic_task_count'))
    return ai_extraction, used_ai

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
    from utils.feature_availability import FeatureAvailability

    deterministic_extraction = _deterministic_stage.run_deterministic_stage(
        report_text,
        RegexIOCExtractor,
    )

    if not FeatureAvailability.is_ai_enabled():
        logger.info("AI extraction disabled, using regex only")
        result = deterministic_extraction
        result['extraction_summary']['method'] = 'regex_only'
        result['extraction_summary']['method_detail'] = (
            'AI is not currently available. Extraction used pattern matching only. '
            'Restore a valid activation and AI availability for richer contextual extraction.'
        )
        return result, False

    # --- AI is enabled, attempt the call ---
    ai_extraction = None
    resolved_model = model or ''
    try:
        provider = _ai_router.resolve_provider(
            model_override=model,
            function='ioc_extraction',
        )
        resolved_model = getattr(provider, 'model', '') or model or ''
        ai_extraction, used_ai = run_ioc_pipeline_with_provider(
            report_text,
            provider,
            model_name=resolved_model,
        )

    except Exception as e:
        logger.warning(f"AI extraction call failed: {e}")

    # --- AI failed entirely -> regex fallback ---
    if ai_extraction is None:
        logger.info("AI unavailable, falling back to deterministic extraction only")
        result = deterministic_extraction
        result['extraction_summary']['method'] = 'regex_fallback'
        result['extraction_summary']['method_detail'] = (
            'AI extraction failed. Fell back to pattern matching only. '
            'Check AI provider settings and connectivity.'
        )
        return result, False

    return ai_extraction, used_ai


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
    return _ioc_merge.merge_extractions(ai, regex)


def _extract_dedup_key(item) -> Optional[str]:
    """
    Get a normalised deduplication key from an IOC item.
    Handles dicts (with 'value', 'name', or 'path' keys) and plain strings.
    """
    return _ioc_merge.extract_dedup_key(item)


def _normalize_ai_extraction(extraction: Dict[str, Any], report_text: str = '') -> Dict[str, Any]:
    """
    Normalize AI extraction output to our expected format.
    Handles variations in AI response structure.
    """
    return _ioc_normalizer._normalize_ai_extraction(extraction, report_text)


# ============================================
# Alias Generation for Contextual Matching
# ============================================

def generate_ioc_with_aliases(value: str, ioc_type: str) -> Dict[str, Any]:
    """Generate primary IOC values and aliases for contextual matching."""
    return _ioc_aliasing.generate_ioc_with_aliases(value, ioc_type)


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
    from utils.opencti import maybe_auto_enrich_iocs
    
    iocs_to_import = []
    known_systems_results = []
    known_users_results = []
    seen_values = set()  # Track seen values for deduplication by field or IOC type
    
    iocs_data = extraction.get('iocs', {})
    record_list = extraction.get('_ioc_records')
    if not isinstance(record_list, list):
        record_list = _ioc_schema.records_from_extraction(
            extraction,
            source='merged',
            trust_tier=_ioc_schema.TRUST_HIGH,
        )
    record_lookup = _ioc_schema.build_record_lookup(record_list)

    def _annotate_entry(entry: Optional[Dict[str, Any]], lookup_type: str, lookup_value: str) -> Optional[Dict[str, Any]]:
        if not entry:
            return entry
        return _ioc_schema.annotate_import_entry(
            entry,
            record_lookup,
            lookup_type=lookup_type,
            lookup_value=lookup_value,
        )

    def _dedupe_known_results(
        results: List[Dict[str, Any]],
        *,
        key_builder,
    ) -> List[Dict[str, Any]]:
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for result in results:
            if not isinstance(result, dict):
                continue
            key = key_builder(result)
            if not key or key in seen:
                continue
            seen.add(key)
            deduped.append(result)
        return deduped
    
    def _seen_key(namespace: str, value: Any) -> Tuple[str, str]:
        return (namespace, str(value or '').strip().lower())

    def _has_seen(namespace: str, value: Any) -> bool:
        key = _seen_key(namespace, value)
        return bool(key[1]) and key in seen_values

    def _mark_seen(namespace: str, value: Any) -> bool:
        key = _seen_key(namespace, value)
        if not key[1]:
            return False
        seen_values.add(key)
        return True

    # Process hashes
    for hash_item in iocs_data.get('hashes', []):
        value = hash_item.get('value', '').strip().lower()
        hash_type = hash_item.get('type', 'sha256').lower()
        ioc_type = IOC_TYPE_MAP.get(hash_type, 'SHA256 Hash')
        category = IOC_CATEGORY_MAP.get(hash_type, 'File')
        if not value or _has_seen(ioc_type, value):
            continue
        _mark_seen(ioc_type, value)
        
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
            iocs_to_import.append(_annotate_entry(ioc_entry, ioc_type, value))
    
    # Process IP addresses
    for ip_item in iocs_data.get('ip_addresses', []):
        value = ip_item.get('value', '').strip()
        # Determine IPv4 or IPv6
        ip_type = ip_item.get('type', 'ipv4')
        ioc_type = 'IP Address (IPv6)' if ip_type == 'ipv6' or ':' in value else 'IP Address (IPv4)'
        if not value or _has_seen(ioc_type, value):
            continue
        _mark_seen(ioc_type, value)
        
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
            iocs_to_import.append(_annotate_entry(ioc_entry, ioc_type, value))
    
    # Process domains
    for domain_item in iocs_data.get('domains', []):
        if isinstance(domain_item, dict):
            value = domain_item.get('value', '').strip().lower()
            context = domain_item.get('context', '')
        else:
            value = str(domain_item).strip().lower()
            context = ''
        
        if not value or _has_seen('Domain', value):
            continue
        _mark_seen('Domain', value)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Domain',
            category='Network',
            context=context,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, 'Domain', value))
    
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
        
        if not value or _has_seen('URL', value):
            continue
        _mark_seen('URL', value)
        
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
            iocs_to_import.append(_annotate_entry(ioc_entry, 'URL', value))
    
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
        
        if not value or _has_seen('file_path_raw', value):
            continue
        _mark_seen('file_path_raw', value)
        
        # Generate primary IOC (filename) with full path as alias
        alias_result = generate_ioc_with_aliases(value, 'File Path')
        primary_value = alias_result['primary_value']
        aliases = alias_result['aliases']
        
        # Check if we've already seen this primary value in THIS extraction
        if _has_seen(alias_result['primary_type'], primary_value):
            # Add the new path alias to the existing IOC entry
            for entry in iocs_to_import:
                if (
                    entry.get('ioc_type') == alias_result['primary_type']
                    and entry.get('value', '').lower() == primary_value.lower()
                ):
                    existing_aliases = entry.get('aliases', [])
                    entry['aliases'] = list(set(existing_aliases + aliases))
                    break
            continue
        _mark_seen(alias_result['primary_type'], primary_value)
        
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
            iocs_to_import.append(_annotate_entry(ioc_entry, 'file_paths', value))
    
    # Process file names
    for fn in iocs_data.get('file_names', []):
        value = str(fn).strip() if fn else ''
        if not value or _has_seen('File Name', value):
            continue
        _mark_seen('File Name', value)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='File Name',
            category='File',
            context='',
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, 'File Name', value))
    
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
        
        if not value or _has_seen('Registry Key', value):
            continue
        _mark_seen('Registry Key', value)
        
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
            iocs_to_import.append(_annotate_entry(ioc_entry, 'Registry Key', value))
    
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
        
        if not value or _has_seen('Service Name', value):
            continue
        _mark_seen('Service Name', value)
        
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
            iocs_to_import.append(_annotate_entry(ioc_entry, 'Service Name', value))
    
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
        
        if not value or _has_seen('Scheduled Task', value):
            continue
        _mark_seen('Scheduled Task', value)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Scheduled Task',
            category='Process',
            context=f"Action: {action} | {context}" if action else context,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, 'Scheduled Task', value))
    
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
        
        if not value or _has_seen('command_raw', value):
            continue
        _mark_seen('command_raw', value)
        
        # Generate primary IOC (executable) with full command as alias
        alias_result = generate_ioc_with_aliases(value, 'Command Line')
        primary_value = alias_result['primary_value']
        aliases = alias_result['aliases']
        
        # Allow a Command Line IOC even when a File Name IOC for the same executable
        # was already created from file path extraction. Only merge if we already
        # staged a Command Line entry for this executable in this same extraction.
        existing_command_entry = None
        for entry in iocs_to_import:
            if (
                entry.get('value', '').lower() == primary_value.lower()
                and entry.get('ioc_type') == 'Command Line'
            ):
                existing_command_entry = entry
                break

        if existing_command_entry:
            existing_aliases = existing_command_entry.get('aliases', [])
            existing_command_entry['aliases'] = list(set(existing_aliases + aliases))
            for entry in iocs_to_import:
                if entry is existing_command_entry and context:
                    existing_context = entry.get('context', '')
                    if context and context not in existing_context:
                        entry['context'] = f"{existing_context} | {context}" if existing_context else context
            continue
        
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
            iocs_to_import.append(_annotate_entry(ioc_entry, 'commands', value))
    
    # Process credentials (passwords, SSH keys, API keys)
    for cred_item in iocs_data.get('credentials', []):
        cred_type = cred_item.get('type', 'password')
        cred_value = cred_item.get('value', '').strip()
        cred_user = cred_item.get('username', '')
        context = cred_item.get('context', '')
        ioc_type = IOC_TYPE_MAP.get(cred_type, 'Password')
        
        if not cred_value or _has_seen(ioc_type, cred_value):
            continue
        _mark_seen(ioc_type, cred_value)
        
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
            iocs_to_import.append(_annotate_entry(ioc_entry, ioc_type, cred_value))
    
    # Process CVEs
    for cve in iocs_data.get('cves', []):
        value = str(cve).strip().upper()
        if not value or _has_seen('CVE', value):
            continue
        _mark_seen('CVE', value)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='CVE',
            category='Vulnerability',
            context='',
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, 'CVE', value))
    
    # Process threat names
    for threat_name in iocs_data.get('threat_names', []):
        value = str(threat_name).strip()
        if not value or _has_seen('Threat Name', value):
            continue
        _mark_seen('Threat Name', value)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Threat Name',
            category='Threat Intel',
            context='',
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, 'Threat Name', value))
    
    # Process email addresses
    for email in iocs_data.get('email_addresses', []):
        value = str(email).strip().lower() if email else ''
        if not value or _has_seen('Email Address', value):
            continue
        _mark_seen('Email Address', value)
        
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type='Email Address',
            category='Email',
            context='',
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, 'Email Address', value))
    
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
        
        if not hostname_val or _has_seen('Hostname', hostname_val):
            continue
        _mark_seen('Hostname', hostname_val)
        
        # Create IOC entry for the hostname
        ioc_entry = _create_ioc_entry(
            value=hostname_val,
            ioc_type='Hostname',
            category='Network',
            context=f"FQDN: {fqdn}" if fqdn else context,
            case_id=case_id
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, 'Hostname', hostname_val))
        
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

    known_systems_results = _dedupe_known_results(
        known_systems_results,
        key_builder=lambda result: (
            str(result.get('hostname') or '').strip().lower(),
            str(result.get('system_id') or '').strip().lower(),
        ),
    )
    known_users_results = _dedupe_known_results(
        known_users_results,
        key_builder=lambda result: (
            str(result.get('username') or '').strip().lower(),
            str(result.get('sid') or '').strip().lower(),
        ),
    )

    return {
        'iocs_to_import': iocs_to_import,
        'known_systems_results': known_systems_results,
        'known_users_results': known_users_results,
        'extraction_summary': extraction.get('extraction_summary', {}),
        'deterministic_extraction': extraction.get('deterministic_extraction'),
        'audit_overlay': extraction.get('audit_overlay'),
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
    """Create one IOC import entry with case-scoped duplicate metadata."""
    return _ioc_import_entries.create_ioc_entry(
        value=value,
        ioc_type=ioc_type,
        category=category,
        context=context,
        case_id=case_id,
    )


def _create_ioc_entry_with_type_awareness(
    primary_value: str,
    primary_type: str,
    aliases: List[str],
    original_type: str,
    category: str,
    context: str,
    case_id: int
) -> Optional[Dict[str, Any]]:
    """Create one IOC import entry while preserving file-vs-command semantics."""
    return _ioc_import_entries.create_ioc_entry_with_type_awareness(
        primary_value=primary_value,
        primary_type=primary_type,
        aliases=aliases,
        original_type=original_type,
        category=category,
        context=context,
        case_id=case_id,
    )


def _process_known_system(
    hostname: str,
    case_id: int,
    username: str
) -> Optional[Dict[str, Any]]:
    """Return the case-scoped known-system action implied by one hostname."""
    return _ioc_known_entities.process_known_system(
        hostname=hostname,
        case_id=case_id,
        username=username,
    )


def _process_known_user(
    username_val: str,
    sid: str,
    case_id: int,
    changed_by: str,
    context: str = ''
) -> Optional[Dict[str, Any]]:
    """Return the case-scoped known-user action implied by one user IOC."""
    return _ioc_known_entities.process_known_user(
        username_val=username_val,
        sid=sid,
        case_id=case_id,
        changed_by=changed_by,
        context=context,
    )


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
    from utils.opencti import maybe_auto_enrich_iocs
    
    created_count = 0
    updated_count = 0
    existing_count = 0
    systems_created = 0
    systems_updated = 0
    users_created = 0
    users_updated = 0
    created_iocs = []
    
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
                        created_iocs.append(ioc)
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
                            created_iocs.append(hostname_ioc)
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
                            created_iocs.append(user_ioc)
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
        auto_enrichment = maybe_auto_enrich_iocs(created_iocs)
        
        return {
            'iocs_created': created_count,
            'iocs_updated': updated_count,
            'iocs_existing': existing_count,
            'iocs_linked': 0,
            'systems_created': systems_created,
            'systems_updated': systems_updated,
            'users_created': users_created,
            'users_updated': users_updated,
            'auto_enrichment': auto_enrichment,
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
    return _report_normalizer.split_edr_reports(edr_report_text)


def get_report_preview(report_text: str, max_length: int = 200) -> str:
    """Get a preview of a report for display"""
    return _report_normalizer.get_report_preview(report_text, max_length)
