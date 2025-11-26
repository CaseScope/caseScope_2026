#!/usr/bin/env python3
"""
CaseScope AI Search Module (RAG Implementation) - V4 ATTACK PATTERN DETECTION
Provides semantic search using embeddings + LLM-powered question answering

Key features in V4:
- MITRE ATT&CK mapped attack patterns and detection logic
- Attack chain correlation (find related events across kill chain)
- Multi-query expansion (search same concept multiple ways)
- Step-back prompting (abstract questions for broader context)
- Gap analysis (identify missing evidence in attack chain)
- Cross-encoder re-ranking for better relevance
- All V3 features (exclusions, DFIR expansion, diversification)

Based on:
- MITRE ATT&CK Framework (https://attack.mitre.org/)
- Splunk Threat Hunter's Cookbook patterns
- RAG Survey paper (arXiv:2312.10997v5) techniques

Version: 4.0 (November 2025)
"""

import requests
import json
import logging
import re
import numpy as np
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Generator, Set
from collections import defaultdict
from logging_config import get_logger

logger = get_logger('app')

# Ollama API endpoints
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"

# Embedding model configuration
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
DEFAULT_LLM_MODEL = "dfir-llama:latest"

# Lazy-loaded models
_embedding_model = None
_embedding_model_load_attempted = False
_cross_encoder = None
_cross_encoder_load_attempted = False


# =============================================================================
# MITRE ATT&CK MAPPING - Techniques to Detection Indicators
# =============================================================================

MITRE_ATTACK_PATTERNS = {
    # =========================================================================
    # INITIAL ACCESS (TA0001)
    # =========================================================================
    'T1566': {  # Phishing
        'name': 'Phishing',
        'tactic': 'Initial Access',
        'indicators': [
            'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
            'macro', 'vba', 'enable content', 'enable editing',
            '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm',
        ],
        'event_ids': ['4688', '1'],
        'parent_child': [('winword.exe', 'powershell.exe'), ('excel.exe', 'cmd.exe')],
        'description': 'Malicious Office documents executing code',
    },
    'T1190': {  # Exploit Public-Facing Application
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'indicators': [
            'w3wp.exe', 'httpd', 'nginx', 'tomcat', 'webshell',
            'aspx', 'jsp', 'php', 'cmd.exe', 'powershell.exe',
        ],
        'event_ids': ['4688', '1'],
        'parent_child': [('w3wp.exe', 'cmd.exe'), ('w3wp.exe', 'powershell.exe')],
        'description': 'Web server spawning suspicious processes',
    },
    
    # =========================================================================
    # EXECUTION (TA0002)
    # =========================================================================
    'T1059.001': {  # PowerShell
        'name': 'PowerShell Execution',
        'tactic': 'Execution',
        'indicators': [
            'powershell', 'pwsh', 'encodedcommand', '-enc', '-e ', '-ec ',
            'bypass', 'noprofile', 'hidden', 'windowstyle',
            'invoke-expression', 'iex', 'invoke-command',
            'downloadstring', 'downloadfile', 'webclient',
            'frombase64string', 'decompress', 'gzipstream',
        ],
        'event_ids': ['4688', '4104', '4103', '1'],
        'suspicious_args': ['-enc', '-e ', 'bypass', 'hidden', 'iex', 'downloadstring'],
        'description': 'Suspicious PowerShell execution patterns',
    },
    'T1059.003': {  # Windows Command Shell
        'name': 'Command Shell',
        'tactic': 'Execution',
        'indicators': [
            'cmd.exe', '/c ', '/k ', 'cmd /c', 'comspec',
        ],
        'event_ids': ['4688', '1'],
        'description': 'Command shell execution',
    },
    'T1047': {  # WMI
        'name': 'WMI Execution',
        'tactic': 'Execution',
        'indicators': [
            'wmic', 'wmiprvse.exe', 'scrcons.exe',
            'process call create', 'invoke-wmimethod',
            '__eventfilter', 'commandlineeventconsumer',
        ],
        'event_ids': ['4688', '1', '5857', '5858', '5859', '5860', '5861'],
        'description': 'WMI-based execution or persistence',
    },
    'T1218': {  # Signed Binary Proxy Execution (LOLBAS)
        'name': 'LOLBAS Execution',
        'tactic': 'Execution',
        'indicators': [
            'certutil', 'bitsadmin', 'mshta', 'regsvr32', 'rundll32',
            'msiexec', 'installutil', 'regasm', 'regsvcs', 'cmstp',
            'msconfig', 'msbuild', 'ieexec', 'dnscmd', 'ftp.exe',
            'urlcache', 'decode', 'scrobj.dll', 'javascript:',
        ],
        'event_ids': ['4688', '1'],
        'description': 'Living-off-the-land binary abuse',
    },
    
    # =========================================================================
    # PERSISTENCE (TA0003)
    # =========================================================================
    'T1053.005': {  # Scheduled Task
        'name': 'Scheduled Task',
        'tactic': 'Persistence',
        'indicators': [
            'schtasks', '/create', '/run', '/change',
            'at.exe', 'taskschd.msc',
        ],
        'event_ids': ['4698', '4699', '4700', '4701', '4702', '106', '200', '201'],
        'description': 'Scheduled task creation or modification',
    },
    'T1543.003': {  # Windows Service
        'name': 'Windows Service',
        'tactic': 'Persistence',
        'indicators': [
            'sc create', 'sc config', 'new-service', 'install-service',
            'binpath=', 'services.exe',
        ],
        'event_ids': ['4697', '7045', '7034', '7035', '7036', '7040'],
        'description': 'Service installation or modification',
    },
    'T1547.001': {  # Registry Run Keys
        'name': 'Registry Run Keys',
        'tactic': 'Persistence',
        'indicators': [
            'currentversion\\run', 'currentversion\\runonce',
            'currentversion\\policies\\explorer\\run',
            'winlogon', 'userinit', 'shell',
            'reg add', 'set-itemproperty',
        ],
        'event_ids': ['4688', '1', '13', '12'],
        'description': 'Registry-based persistence',
    },
    
    # =========================================================================
    # PRIVILEGE ESCALATION (TA0004)
    # =========================================================================
    'T1134': {  # Access Token Manipulation
        'name': 'Token Manipulation',
        'tactic': 'Privilege Escalation',
        'indicators': [
            'impersonate', 'token', 'runas', 'createprocessasuser',
            'duplicatetoken', 'setthreadtoken', 'adjusttokenprivileges',
        ],
        'event_ids': ['4672', '4673', '4674', '4688', '1'],
        'description': 'Token manipulation for privilege escalation',
    },
    'T1068': {  # Exploitation for Privilege Escalation
        'name': 'Privilege Escalation Exploit',
        'tactic': 'Privilege Escalation',
        'indicators': [
            'exploit', 'cve-', 'ms17-', 'ms16-', 'ms15-',
            'juicypotato', 'printspoofer', 'godpotato',
        ],
        'event_ids': ['4688', '1'],
        'description': 'Known privilege escalation exploits',
    },
    
    # =========================================================================
    # DEFENSE EVASION (TA0005)
    # =========================================================================
    'T1070.001': {  # Clear Windows Event Logs
        'name': 'Log Clearing',
        'tactic': 'Defense Evasion',
        'indicators': [
            'wevtutil cl', 'clear-eventlog', 'remove-eventlog',
            'wevtutil.exe', 'auditpol /clear',
        ],
        'event_ids': ['1102', '104', '4688', '1'],
        'description': 'Security log clearing (anti-forensics)',
    },
    'T1562.001': {  # Disable Security Tools
        'name': 'Disable Security Tools',
        'tactic': 'Defense Evasion',
        'indicators': [
            'set-mppreference', 'disablerealtimemonitoring',
            'disablebehaviormonitoring', 'disableioavprotection',
            'stop-service', 'sc stop', 'net stop',
            'defender', 'antivirus', 'firewall',
            'tamper', 'disable', 'exclusion',
        ],
        'event_ids': ['4688', '1', '5001', '5007', '5010', '5012'],
        'description': 'Disabling security controls',
    },
    'T1055': {  # Process Injection
        'name': 'Process Injection',
        'tactic': 'Defense Evasion',
        'indicators': [
            'createremotethread', 'virtualalloc', 'writeprocessmemory',
            'ntmapviewofsection', 'queueuserapc', 'setthreadcontext',
            'hollowing', 'injection', 'inject',
        ],
        'event_ids': ['8', '10', '1'],  # Sysmon CreateRemoteThread, ProcessAccess
        'description': 'Process injection techniques',
    },
    
    # =========================================================================
    # CREDENTIAL ACCESS (TA0006)
    # =========================================================================
    'T1003.001': {  # LSASS Memory
        'name': 'LSASS Credential Dumping',
        'tactic': 'Credential Access',
        'indicators': [
            'lsass', 'mimikatz', 'sekurlsa', 'logonpasswords',
            'procdump', 'comsvcs.dll', 'minidump', 'sqldumper',
            'taskmgr', 'processhacker', 'processdump',
        ],
        'event_ids': ['10', '4688', '1'],  # Sysmon ProcessAccess to lsass
        'target_process': 'lsass.exe',
        'description': 'Credential dumping from LSASS memory',
    },
    'T1003.002': {  # SAM Database
        'name': 'SAM Credential Dumping',
        'tactic': 'Credential Access',
        'indicators': [
            'sam', 'system', 'security', 'reg save', 'reg export',
            'vssadmin', 'shadow copy', 'ntds.dit',
        ],
        'event_ids': ['4688', '1', '4663'],
        'description': 'SAM/SYSTEM registry hive extraction',
    },
    'T1003.006': {  # DCSync
        'name': 'DCSync Attack',
        'tactic': 'Credential Access',
        'indicators': [
            'dcsync', 'drsuapi', 'drs replication', 'lsadump::dcsync',
            'replicating directory changes',
        ],
        'event_ids': ['4662', '4624'],
        'description': 'DCSync attack against domain controller',
    },
    'T1558.003': {  # Kerberoasting
        'name': 'Kerberoasting',
        'tactic': 'Credential Access',
        'indicators': [
            'kerberoast', 'invoke-kerberoast', 'getuserspns',
            'tgs-req', 'rc4-hmac', 'serviceprincipalname',
        ],
        'event_ids': ['4769'],  # TGS requests with RC4 encryption
        'description': 'Kerberos service ticket requests for offline cracking',
    },
    'T1110': {  # Brute Force / Password Spray
        'name': 'Brute Force / Password Spray',
        'tactic': 'Credential Access',
        'indicators': [
            'failed logon', 'bad password', 'account lockout',
            'password spray', 'brute force',
        ],
        'event_ids': ['4625', '4771', '4776'],  # Failed logons
        'threshold': {'count': 10, 'window_minutes': 5},  # Multiple failures
        'description': 'Multiple failed authentication attempts',
    },
    
    # =========================================================================
    # DISCOVERY (TA0007)
    # =========================================================================
    'T1087': {  # Account Discovery
        'name': 'Account Discovery',
        'tactic': 'Discovery',
        'indicators': [
            'net user', 'net group', 'net localgroup',
            'get-aduser', 'get-adgroup', 'get-adcomputer',
            'dsquery', 'whoami /all', 'query user',
        ],
        'event_ids': ['4688', '1'],
        'description': 'Enumeration of user and group accounts',
    },
    'T1018': {  # Remote System Discovery
        'name': 'Remote System Discovery',
        'tactic': 'Discovery',
        'indicators': [
            'net view', 'net share', 'ping', 'arp -a',
            'nslookup', 'nltest', 'nbtstat', 'portscan',
        ],
        'event_ids': ['4688', '1'],
        'description': 'Network and system enumeration',
    },
    
    # =========================================================================
    # LATERAL MOVEMENT (TA0008)
    # =========================================================================
    'T1021.002': {  # SMB/Windows Admin Shares
        'name': 'SMB Lateral Movement',
        'tactic': 'Lateral Movement',
        'indicators': [
            'admin$', 'c$', 'ipc$', 'd$',
            'net use', '\\\\', 'psexec', 'paexec',
            'smbexec', 'smbclient',
        ],
        'event_ids': ['5140', '5145', '4648', '4624'],
        'logon_types': ['3'],  # Network logon
        'description': 'Lateral movement via SMB shares',
    },
    'T1021.001': {  # RDP
        'name': 'RDP Lateral Movement',
        'tactic': 'Lateral Movement',
        'indicators': [
            'mstsc', 'rdp', 'remote desktop', '3389',
            'termsrv', 'rdpclip', 'tscon',
        ],
        'event_ids': ['4624', '4778', '4779', '1149'],
        'logon_types': ['10', '7'],  # RDP, Unlock
        'description': 'Remote Desktop Protocol lateral movement',
    },
    'T1021.006': {  # Windows Remote Management
        'name': 'WinRM Lateral Movement',
        'tactic': 'Lateral Movement',
        'indicators': [
            'winrm', 'winrs', 'enter-pssession', 'invoke-command',
            'wsman', 'psremoting', 'new-pssession',
        ],
        'event_ids': ['4624', '4688', '1', '91', '168'],
        'logon_types': ['3'],
        'description': 'PowerShell Remoting / WinRM lateral movement',
    },
    'T1550.002': {  # Pass the Hash
        'name': 'Pass the Hash',
        'tactic': 'Lateral Movement',
        'indicators': [
            'pass the hash', 'pth', 'ntlm', 'sekurlsa::pth',
            'mimikatz', 'overpass', 'impacket',
        ],
        'event_ids': ['4624', '4648', '4672'],
        'logon_types': ['3', '9'],  # Network, NewCredentials
        'special_logon': True,  # 4672 follows 4624
        'description': 'NTLM hash reuse for authentication',
    },
    'T1550.003': {  # Pass the Ticket
        'name': 'Pass the Ticket',
        'tactic': 'Lateral Movement',
        'indicators': [
            'pass the ticket', 'ptt', 'kerberos', 'kirbi',
            'golden ticket', 'silver ticket', 'rubeus',
        ],
        'event_ids': ['4768', '4769', '4770', '4624'],
        'description': 'Kerberos ticket reuse/forgery',
    },
    
    # =========================================================================
    # COLLECTION (TA0009)
    # =========================================================================
    'T1560': {  # Archive Collected Data
        'name': 'Data Staging/Archive',
        'tactic': 'Collection',
        'indicators': [
            'zip', 'rar', '7z', 'tar', 'compress-archive',
            'makecab', 'compact', 'archive',
        ],
        'event_ids': ['4688', '1'],
        'description': 'Data compression for exfiltration',
    },
    
    # =========================================================================
    # COMMAND AND CONTROL (TA0011)
    # =========================================================================
    'T1071': {  # Application Layer Protocol
        'name': 'C2 Communication',
        'tactic': 'Command and Control',
        'indicators': [
            'http', 'https', 'dns', 'beacon', 'callback',
            'cobalt', 'empire', 'meterpreter', 'covenant',
        ],
        'event_ids': ['3', '22'],  # Sysmon Network, DNS
        'description': 'Command and control communication',
    },
    
    # =========================================================================
    # EXFILTRATION (TA0010)
    # =========================================================================
    'T1048': {  # Exfiltration Over Alternative Protocol
        'name': 'Data Exfiltration',
        'tactic': 'Exfiltration',
        'indicators': [
            'curl', 'wget', 'invoke-webrequest', 'invoke-restmethod',
            'ftp', 'sftp', 'scp', 'rclone', 'mega', 'dropbox',
            'onedrive', 'gdrive', 'transfer.sh', 'pastebin',
        ],
        'event_ids': ['4688', '1', '3'],
        'description': 'Data transfer to external locations',
    },
}


# =============================================================================
# ATTACK CHAIN DEFINITIONS - Common Attack Sequences
# =============================================================================

ATTACK_CHAINS = {
    'ransomware': {
        'name': 'Ransomware Attack Chain',
        'description': 'Typical ransomware attack progression',
        'stages': [
            {'stage': 'Initial Access', 'techniques': ['T1566', 'T1190'], 'required': True},
            {'stage': 'Execution', 'techniques': ['T1059.001', 'T1047'], 'required': True},
            {'stage': 'Discovery', 'techniques': ['T1087', 'T1018'], 'required': False},
            {'stage': 'Credential Access', 'techniques': ['T1003.001'], 'required': False},
            {'stage': 'Lateral Movement', 'techniques': ['T1021.002', 'T1021.001'], 'required': False},
            {'stage': 'Defense Evasion', 'techniques': ['T1562.001', 'T1070.001'], 'required': False},
            {'stage': 'Impact', 'techniques': [], 'indicators': ['encrypt', 'ransom', 'bitcoin', 'decrypt']},
        ],
    },
    'apt_intrusion': {
        'name': 'APT-Style Intrusion',
        'description': 'Advanced persistent threat attack pattern',
        'stages': [
            {'stage': 'Initial Access', 'techniques': ['T1566', 'T1190']},
            {'stage': 'Execution', 'techniques': ['T1059.001', 'T1218']},
            {'stage': 'Persistence', 'techniques': ['T1053.005', 'T1543.003', 'T1547.001']},
            {'stage': 'Privilege Escalation', 'techniques': ['T1134', 'T1068']},
            {'stage': 'Defense Evasion', 'techniques': ['T1562.001', 'T1055']},
            {'stage': 'Credential Access', 'techniques': ['T1003.001', 'T1003.006']},
            {'stage': 'Discovery', 'techniques': ['T1087', 'T1018']},
            {'stage': 'Lateral Movement', 'techniques': ['T1021.002', 'T1550.002']},
            {'stage': 'Collection', 'techniques': ['T1560']},
            {'stage': 'Exfiltration', 'techniques': ['T1048']},
        ],
    },
    'credential_theft': {
        'name': 'Credential Theft Campaign',
        'description': 'Focused credential harvesting attack',
        'stages': [
            {'stage': 'Initial Access', 'techniques': ['T1566']},
            {'stage': 'Execution', 'techniques': ['T1059.001']},
            {'stage': 'Credential Access', 'techniques': ['T1003.001', 'T1003.002', 'T1558.003', 'T1110']},
            {'stage': 'Lateral Movement', 'techniques': ['T1550.002', 'T1550.003']},
        ],
    },
    'domain_dominance': {
        'name': 'Domain Dominance',
        'description': 'Active Directory takeover pattern',
        'stages': [
            {'stage': 'Credential Access', 'techniques': ['T1003.001', 'T1558.003']},
            {'stage': 'Privilege Escalation', 'techniques': ['T1134']},
            {'stage': 'Lateral Movement', 'techniques': ['T1550.002', 'T1550.003', 'T1021.002']},
            {'stage': 'Credential Access', 'techniques': ['T1003.006']},  # DCSync
            {'stage': 'Persistence', 'techniques': ['T1053.005', 'T1543.003']},
        ],
    },
}


# =============================================================================
# MULTI-QUERY EXPANSION - Search same concept multiple ways
# =============================================================================

MULTI_QUERY_TEMPLATES = {
    'lateral movement': [
        "remote logon type 3 type 10 network authentication",
        "psexec wmic winrm remote execution admin$",
        "4624 4648 network logon explicit credentials",
        "rdp mstsc 3389 remote desktop connection",
        "smb share access c$ admin$ ipc$",
    ],
    'credential theft': [
        "lsass mimikatz sekurlsa credential dump",
        "procdump comsvcs minidump memory",
        "sam ntds.dit registry hive export",
        "kerberoast tgs ticket service principal",
        "dcsync drsuapi replication domain controller",
    ],
    'malware execution': [
        "powershell encodedcommand bypass hidden",
        "certutil bitsadmin urlcache decode download",
        "regsvr32 rundll32 mshta scrobj javascript",
        "wmic process call create wmiprvse",
        "cmd /c whoami net user systeminfo",
    ],
    'persistence': [
        "schtasks scheduled task create 4698",
        "service install sc create 7045",
        "registry run key autorun startup",
        "wmi subscription eventfilter consumer",
    ],
    'exfiltration': [
        "curl wget invoke-webrequest upload transfer",
        "zip rar 7z archive compress staging",
        "ftp sftp scp cloud storage",
        "dns tunnel large query encoded",
    ],
    'password spray': [
        "4625 failed logon multiple accounts",
        "4771 kerberos pre-authentication failure",
        "bad password account lockout",
        "authentication failure same source different users",
    ],
    'pass the hash': [
        "4624 logon type 3 ntlm network",
        "4648 explicit credentials runas",
        "4672 special privileges admin logon",
        "sekurlsa pth overpass the hash",
    ],
}


# =============================================================================
# STEP-BACK PROMPTS - Abstract questions for broader context
# =============================================================================

STEP_BACK_PROMPTS = {
    r'was there .*(malware|virus|infection)': 
        "What suspicious process executions with unusual command lines occurred?",
    r'did .*(attacker|adversary|threat).*(lateral|move|spread)':
        "What remote authentication and share access events occurred?",
    r'any .*(persist|backdoor|maintain)':
        "What scheduled tasks, services, or registry modifications were made?",
    r'credential.*(theft|dump|steal|compromise)':
        "What processes accessed LSASS or sensitive registry hives?",
    r'(pass the hash|pth|ntlm)':
        "What network logons (type 3) with special privileges (4672) occurred?",
    r'(password spray|brute force)':
        "What patterns of failed authentication attempts exist?",
    r'(exfil|data theft|steal.*data)':
        "What archive creation and network transfer activity occurred?",
    r'(c2|command and control|beacon)':
        "What processes made unusual network connections?",
    r'account.*(compromise|takeover)':
        "What authentication anomalies and privilege changes occurred?",
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_attack_pattern(technique_id: str) -> Optional[Dict]:
    """Get MITRE ATT&CK pattern details by technique ID."""
    return MITRE_ATTACK_PATTERNS.get(technique_id)


def get_techniques_for_tactic(tactic: str) -> List[str]:
    """Get all technique IDs for a given tactic."""
    return [
        tid for tid, pattern in MITRE_ATTACK_PATTERNS.items()
        if pattern.get('tactic', '').lower() == tactic.lower()
    ]


def expand_to_multi_query(question: str) -> List[str]:
    """Generate multiple query variations for the same question."""
    queries = [question]
    question_lower = question.lower()
    
    for pattern, variations in MULTI_QUERY_TEMPLATES.items():
        if pattern in question_lower or any(word in question_lower for word in pattern.split()):
            queries.extend(variations)
    
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for q in queries:
        if q.lower() not in seen:
            seen.add(q.lower())
            unique.append(q)
    
    return unique[:7]  # Limit to 7 variations


def get_step_back_question(question: str) -> Optional[str]:
    """Generate a higher-level question to retrieve broader context."""
    question_lower = question.lower()
    
    for pattern, step_back in STEP_BACK_PROMPTS.items():
        if re.search(pattern, question_lower):
            return step_back
    
    return None


def identify_attack_techniques(events: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Analyze events and identify potential MITRE ATT&CK techniques.
    
    Returns dict mapping technique IDs to matching events.
    """
    technique_matches = defaultdict(list)
    
    for event in events:
        source = event.get('_source', event)
        search_blob = source.get('search_blob', '').lower()
        event_id = str(source.get('normalized_event_id', ''))
        command_line = source.get('EventData', {}).get('CommandLine', '').lower() if isinstance(source.get('EventData'), dict) else ''
        
        for technique_id, pattern in MITRE_ATTACK_PATTERNS.items():
            # Check event IDs
            if event_id in pattern.get('event_ids', []):
                # Check indicators
                indicators = pattern.get('indicators', [])
                matching_indicators = [ind for ind in indicators if ind.lower() in search_blob or ind.lower() in command_line]
                
                if matching_indicators:
                    technique_matches[technique_id].append({
                        'event': event,
                        'matching_indicators': matching_indicators,
                        'technique_name': pattern['name'],
                        'tactic': pattern['tactic'],
                    })
    
    return dict(technique_matches)


def analyze_attack_chain(events: List[Dict], chain_name: str = 'apt_intrusion') -> Dict:
    """
    Analyze events against a known attack chain to identify gaps.
    
    Returns analysis with found stages and missing stages.
    """
    chain = ATTACK_CHAINS.get(chain_name, ATTACK_CHAINS['apt_intrusion'])
    technique_matches = identify_attack_techniques(events)
    
    analysis = {
        'chain_name': chain['name'],
        'description': chain['description'],
        'stages_found': [],
        'stages_missing': [],
        'coverage_percent': 0,
        'recommendations': [],
    }
    
    stages_found = 0
    total_stages = len(chain['stages'])
    
    for stage in chain['stages']:
        stage_name = stage['stage']
        stage_techniques = stage.get('techniques', [])
        stage_indicators = stage.get('indicators', [])
        
        # Check if any techniques from this stage were found
        found_techniques = [t for t in stage_techniques if t in technique_matches]
        
        # Also check for direct indicator matches
        found_indicators = []
        if stage_indicators:
            for event in events:
                search_blob = event.get('_source', event).get('search_blob', '').lower()
                found_indicators.extend([ind for ind in stage_indicators if ind in search_blob])
        
        if found_techniques or found_indicators:
            stages_found += 1
            analysis['stages_found'].append({
                'stage': stage_name,
                'techniques_found': found_techniques,
                'indicators_found': list(set(found_indicators))[:5],
                'event_count': sum(len(technique_matches.get(t, [])) for t in found_techniques),
            })
        else:
            analysis['stages_missing'].append({
                'stage': stage_name,
                'expected_techniques': stage_techniques,
                'search_suggestion': f"Search for: {', '.join(stage_techniques[:3])}",
            })
            
            # Add recommendation
            if stage.get('required'):
                analysis['recommendations'].append(
                    f"⚠️ Missing required stage: {stage_name}. "
                    f"Look for events with IDs: {', '.join(MITRE_ATTACK_PATTERNS.get(stage_techniques[0], {}).get('event_ids', [])[:3]) if stage_techniques else 'N/A'}"
                )
    
    analysis['coverage_percent'] = round((stages_found / total_stages) * 100) if total_stages > 0 else 0
    
    return analysis


def generate_gap_analysis_prompt(events: List[Dict], question: str) -> str:
    """
    Generate a prompt that helps the LLM identify gaps in the attack chain.
    """
    technique_matches = identify_attack_techniques(events)
    
    techniques_found = []
    for tid, matches in technique_matches.items():
        pattern = MITRE_ATTACK_PATTERNS.get(tid, {})
        techniques_found.append(f"- {pattern.get('name', tid)} ({tid}): {len(matches)} events")
    
    # Determine which chain to analyze based on question
    chain_name = 'apt_intrusion'  # default
    if 'ransom' in question.lower():
        chain_name = 'ransomware'
    elif 'credential' in question.lower() or 'password' in question.lower():
        chain_name = 'credential_theft'
    elif 'domain' in question.lower() or 'active directory' in question.lower():
        chain_name = 'domain_dominance'
    
    chain_analysis = analyze_attack_chain(events, chain_name)
    
    gap_prompt = f"""
## ATTACK PATTERN ANALYSIS

### Detected Techniques (MITRE ATT&CK):
{chr(10).join(techniques_found) if techniques_found else "No specific techniques identified"}

### Attack Chain Analysis ({chain_analysis['chain_name']}):
- Coverage: {chain_analysis['coverage_percent']}%
- Stages Found: {', '.join([s['stage'] for s in chain_analysis['stages_found']]) or 'None'}
- Stages Missing: {', '.join([s['stage'] for s in chain_analysis['stages_missing']]) or 'None'}

### Recommendations:
{chr(10).join(chain_analysis['recommendations']) if chain_analysis['recommendations'] else "Analysis complete - review findings above"}

### Gap Analysis Questions:
"""
    
    # Add specific questions based on what's missing
    if chain_analysis['stages_missing']:
        for missing in chain_analysis['stages_missing'][:3]:
            gap_prompt += f"- Do we have evidence of {missing['stage']}? ({missing['search_suggestion']})\n"
    
    return gap_prompt


# =============================================================================
# CROSS-ENCODER RE-RANKING (More accurate than bi-encoder similarity)
# =============================================================================

def _load_cross_encoder():
    """Lazy-load cross-encoder for re-ranking."""
    global _cross_encoder, _cross_encoder_load_attempted
    
    if _cross_encoder_load_attempted:
        return _cross_encoder
    
    _cross_encoder_load_attempted = True
    
    try:
        from sentence_transformers import CrossEncoder
        logger.info("[AI_SEARCH] Loading cross-encoder for re-ranking...")
        _cross_encoder = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2', device='cpu')
        logger.info("[AI_SEARCH] Cross-encoder loaded successfully")
        return _cross_encoder
    except ImportError:
        logger.warning("[AI_SEARCH] sentence-transformers not available for cross-encoder")
        return None
    except Exception as e:
        logger.warning(f"[AI_SEARCH] Failed to load cross-encoder: {e}")
        return None


def rerank_with_cross_encoder(question: str, events: List[Dict], top_k: int = 20) -> List[Dict]:
    """
    Re-rank events using cross-encoder for more accurate relevance scoring.
    
    Cross-encoders are more accurate than bi-encoders because they process
    the query and document together, allowing for better semantic matching.
    """
    cross_encoder = _load_cross_encoder()
    
    if cross_encoder is None or len(events) <= 1:
        return events
    
    try:
        # Create query-document pairs
        pairs = []
        for event in events:
            summary = create_event_summary_for_rerank(event)
            pairs.append([question, summary])
        
        # Get cross-encoder scores
        scores = cross_encoder.predict(pairs)
        
        # Combine with existing scores (if available)
        for i, event in enumerate(events):
            event['_cross_encoder_score'] = float(scores[i])
            
            # Weighted combination: 60% cross-encoder, 40% original
            original_score = event.get('_combined_score', event.get('_score', 0.5))
            event['_final_score'] = 0.6 * scores[i] + 0.4 * (original_score / max(original_score, 1))
        
        # Sort by final score
        events = sorted(events, key=lambda x: x.get('_final_score', 0), reverse=True)
        
        logger.info(f"[AI_SEARCH] Re-ranked {len(events)} events with cross-encoder")
        return events[:top_k]
        
    except Exception as e:
        logger.warning(f"[AI_SEARCH] Cross-encoder re-ranking failed: {e}")
        return events


def create_event_summary_for_rerank(event: Dict) -> str:
    """Create a concise event summary optimized for cross-encoder re-ranking."""
    source = event.get('_source', event)
    
    parts = []
    
    # Event type
    event_id = source.get('normalized_event_id', '')
    event_title = source.get('event_title', '')
    if event_title:
        parts.append(event_title)
    elif event_id:
        parts.append(f"Event {event_id}")
    
    # Key data
    event_data = source.get('EventData', {})
    if isinstance(event_data, dict):
        if event_data.get('CommandLine'):
            parts.append(f"CommandLine: {event_data['CommandLine'][:200]}")
        if event_data.get('TargetUserName'):
            parts.append(f"User: {event_data['TargetUserName']}")
        if event_data.get('NewProcessName') or event_data.get('Image'):
            process = event_data.get('NewProcessName') or event_data.get('Image')
            parts.append(f"Process: {process}")
    
    # Fallback to search_blob
    if len(parts) <= 1:
        blob = source.get('search_blob', '')[:300]
        if blob:
            parts.append(blob)
    
    return ' | '.join(parts)[:500]


# =============================================================================
# ENHANCED LLM PROMPT WITH ATTACK PATTERN CONTEXT
# =============================================================================

def generate_attack_aware_prompt(
    question: str,
    events: List[Dict],
    case_name: str,
    include_gap_analysis: bool = True
) -> str:
    """
    Generate an LLM prompt that includes MITRE ATT&CK context and gap analysis.
    """
    from ai_search import create_event_summary  # Import from main module
    
    MAX_CONTEXT_TOKENS = 6000
    CHARS_PER_TOKEN = 4
    
    # Build event context
    event_context = []
    total_length = 0
    events_included = 0
    
    for i, event in enumerate(events[:15], 1):
        summary = create_event_summary(event)
        event_text = f"### Event {i}\n{summary}"
        
        est_tokens = len(event_text) // CHARS_PER_TOKEN
        if total_length + est_tokens > MAX_CONTEXT_TOKENS:
            break
        
        event_context.append(event_text)
        total_length += est_tokens
        events_included = i
    
    events_text = "\n\n".join(event_context)
    
    # Generate gap analysis if enabled
    gap_analysis = ""
    if include_gap_analysis:
        gap_analysis = generate_gap_analysis_prompt(events, question)
    
    # Count detection flags
    tagged_count = sum(1 for e in events if e.get('_source', {}).get('is_tagged'))
    sigma_count = sum(1 for e in events if e.get('_source', {}).get('has_sigma'))
    ioc_count = sum(1 for e in events if e.get('_source', {}).get('has_ioc'))
    
    prompt = f"""You are a senior Digital Forensics and Incident Response (DFIR) analyst with expertise in the MITRE ATT&CK framework. You are investigating a security incident and helping an analyst understand the attack.

## CASE: {case_name}

## ANALYST'S QUESTION
{question}

## EVIDENCE SUMMARY
- {events_included} events retrieved
- {tagged_count} analyst-tagged (⭐ = manually verified as important)
- {sigma_count} SIGMA detections (⚠️ = matches threat detection rule)
- {ioc_count} IOC matches (🎯 = matches known bad indicator)

{gap_analysis}

## MITRE ATT&CK QUICK REFERENCE
| Technique | Event IDs | What to Look For |
|-----------|-----------|------------------|
| T1059.001 PowerShell | 4688, 4104, 1 | -enc, bypass, downloadstring, iex |
| T1003.001 LSASS Dump | 10, 4688 | lsass access, procdump, mimikatz |
| T1021.002 SMB Lateral | 5140, 5145, 4624 | admin$, c$, type 3 logon |
| T1550.002 Pass the Hash | 4624, 4648, 4672 | type 3 + special privs, explicit creds |
| T1053.005 Sched Task | 4698, 4699 | schtasks /create |
| T1543.003 Service | 7045, 4697 | sc create, new-service |
| T1070.001 Log Clear | 1102 | Security log cleared |

## WINDOWS EVENT ID CHEAT SHEET
- **4624** = Successful logon (Type 2=Interactive, 3=Network, 10=RDP)
- **4625** = Failed logon (brute force/spray indicator)
- **4648** = Explicit credential logon (pass-the-hash indicator)
- **4672** = Special privileges assigned (admin logon)
- **4688** = Process created (look at CommandLine!)
- **4698** = Scheduled task created
- **5140/5145** = Network share accessed
- **7045** = Service installed
- **1102** = Security log cleared (CRITICAL - anti-forensics)
- **Sysmon 1** = Process with full command line
- **Sysmon 3** = Network connection
- **Sysmon 10** = Process access (credential dumping)

## EVIDENCE EVENTS

{events_text}

## YOUR ANALYSIS

Based on the evidence above, answer the analyst's question. Follow these guidelines:

1. **Map to MITRE ATT&CK**: Identify techniques you see (e.g., "This appears to be T1059.001 PowerShell execution")
2. **Reference Events**: Cite specific events (e.g., "Event 3 shows...")
3. **Identify Attack Chains**: Connect related events into a timeline/sequence
4. **Highlight Gaps**: Note what evidence is missing to confirm suspicions
5. **Prioritize Flagged Events**: ⭐ tagged events are analyst-verified important
6. **Be Specific**: Quote usernames, IPs, command lines, timestamps
7. **NO Fabrication**: Only cite what's in the events above

If you identify a potential attack pattern, structure your response as:
- **Attack Hypothesis**: What type of attack this might be
- **Supporting Evidence**: Events that support this hypothesis
- **Missing Evidence**: What we'd need to confirm
- **Recommended Actions**: What to investigate next

YOUR ANALYSIS:
"""
    
    return prompt


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # MITRE ATT&CK data
    'MITRE_ATTACK_PATTERNS',
    'ATTACK_CHAINS',
    'MULTI_QUERY_TEMPLATES',
    'STEP_BACK_PROMPTS',
    
    # Functions
    'get_attack_pattern',
    'get_techniques_for_tactic',
    'expand_to_multi_query',
    'get_step_back_question',
    'identify_attack_techniques',
    'analyze_attack_chain',
    'generate_gap_analysis_prompt',
    'rerank_with_cross_encoder',
    'generate_attack_aware_prompt',
]

