#!/usr/bin/env python3
"""
CaseScope AI Search Module (RAG Implementation) - V5 INTELLIGENT SAMPLING
Provides semantic search using embeddings + LLM-powered question answering

Key features in V5:
- Three Query Modes: big_picture, focused (user-specific), pattern (aggregation)
- IntelligentSampler: Tiered allocation (priority/pattern/medium/random)
- Aggregation-based pattern detection (password spray, lateral movement)
- Full Gap Analysis Engine with if_found/if_not_found guidance
- Kill Chain Mapping (12 phases with progression tracking)
- Enhanced Prompts (BIG_PICTURE_PROMPT, FOCUSED_PROMPT, PATTERN_PROMPT)
- User-focused investigation support
- All V4 features (MITRE ATT&CK, multi-query, step-back, exclusions)

Based on:
- MITRE ATT&CK Framework (https://attack.mitre.org/)
- RAG Survey paper (arXiv:2312.10997v5) techniques
- RAG_V3_V4_CONSOLIDATED_IMPLEMENTATION.md

Version: 5.0 (November 2025)
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

# Ollama API endpoints (for LLM generation)
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"

# Embedding model configuration
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# LLM model for generating answers (uses your existing DFIR models on GPU)
DEFAULT_LLM_MODEL = "dfir-llama:latest"

# Lazy-loaded embedding model (loaded on first use, not at import)
_embedding_model = None
_embedding_model_load_attempted = False


# =============================================================================
# DFIR QUERY EXPANSION - Maps analyst concepts to actual indicators
# =============================================================================

DFIR_QUERY_EXPANSION = {
    'malware': [
        'powershell', 'encodedcommand', 'enc', 'base64', 'frombase64string',
        'invoke-expression', 'iex', 'downloadstring', 'downloadfile', 'webclient',
        'certutil', 'decode', 'urlcache', 'bitsadmin', 'mshta', 'wscript',
        'cscript', 'regsvr32', 'rundll32', 'msiexec',
        'hidden', 'bypass', 'noprofile', 'windowstyle',
        'shellcode', 'payload', 'dropper', 'loader',
        '4688', '1',
    ],
    
    'lateral movement': [
        'psexec', 'paexec', 'remcom', 'wmic', 'wmiexec', 'smbexec', 'wmiprvse',
        'winrm', 'winrs', 'enter-pssession', 'invoke-command', 'invoke-wmimethod',
        'mstsc', '3389', 'rdp', 'remote desktop',
        'admin$', 'c$', 'ipc$', 'net use',
        '4624', '4648', '5140', '5145', 'type 3', 'type 10',
    ],
    
    'persistence': [
        'schtasks', 'scheduled task', 'at.exe', 'taskschd',
        'currentversion\\run', 'runonce', 'userinit', 'shell',
        'sc create', 'sc config', 'new-service',
        'startup', 'appinit_dlls',
        '__eventfilter', 'commandlineeventconsumer', 'wmi subscription',
        'dll hijack', 'com hijack', 'image file execution',
        '4698', '4699', '4702', '7045', '4697', '13',
    ],
    
    'credential': [
        'lsass', 'mimikatz', 'sekurlsa', 'logonpasswords', 'wdigest',
        'sam', 'ntds', 'ntds.dit', 'dcsync', 'drsuapi', 'secretsdump',
        'kerberos', 'krbtgt', 'golden ticket', 'silver ticket', 'kerberoast',
        'procdump', 'comsvcs', 'minidump', 'sqldumper',
        'credential manager', 'vault', 'dpapi',
        '4768', '4769', '4776', '4672', '10',
        # VPN/NPS events
        '6272', '6273', '6274', '6275', '6276', '6277', '6278', '6279',
        'nps', 'radius', 'network policy server',
    ],
    
    'exfiltration': [
        'upload', 'transfer', 'curl', 'wget', 'invoke-webrequest', 'invoke-restmethod',
        'ftp', 'sftp', 'scp', 'pscp', 'winscp',
        'onedrive', 'dropbox', 'gdrive', 'mega', 'pastebin', 'transfer.sh',
        'archive', 'zip', 'rar', '7z', 'compress-archive', 'tar',
        'dns tunnel', 'icmp', 'dnscat',
    ],
    
    'discovery': [
        'whoami', 'hostname', 'ipconfig', 'ifconfig', 'netstat', 'arp',
        'net user', 'net group', 'net localgroup', 'net share', 'net view', 'net session',
        'nltest', 'dsquery', 'get-aduser', 'get-adcomputer', 'get-adgroup',
        'systeminfo', 'tasklist', 'query user', 'quser', 'qprocess',
        'nslookup', 'dig', 'ping', 'tracert', 'pathping',
        'dir /s', 'tree', 'findstr', 'where',
    ],
    
    'defense evasion': [
        'disable', 'stop', 'tamper', 'defender', 'antivirus', 'av', 'realtime',
        'amsi', 'etw', 'clear-eventlog', 'wevtutil cl', 'remove-eventlog',
        'firewall', 'netsh advfirewall', 'set-mppreference',
        'process hollow', 'process inject', 'createremotethread',
        'timestomp', 'touch', 'attrib +h',
        '1102', '4688',
    ],
    
    'execution': [
        'powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta',
        'regsvr32', 'rundll32', 'msiexec', 'certutil', 'installutil',
        'wmic process call', 'invoke-wmimethod',
        'at.exe', 'schtasks /run',
        '4688', '1',
    ],
    
    'initial access': [
        'phishing', 'macro', 'vba', 'winword', 'excel', 'powerpnt',
        'outlook', 'msg', 'eml', 'attachment',
        'exploit', 'cve', 'vulnerability',
        'webshell', 'aspx', 'jsp', 'php',
    ],
}

# Question patterns to expansion categories
QUESTION_PATTERNS = [
    (r'malware|virus|trojan|ransomware|infection|compromis|malicious|suspicious|bad', 'malware'),
    (r'lateral|spread|pivot|move.*between|hop|remote\s+exec', 'lateral_movement'),
    (r'persist|backdoor|maintain.*access|survive.*reboot|autorun|startup', 'persistence'),
    (r'credential|password|hash|ticket|authenticat|logon.*as|steal.*cred|dump|ntlm|brute|spray|failed.*logon|lockout', 'credential_access'),
    (r'exfil|steal.*data|data.*theft|upload|send.*out|leak|extract', 'exfiltration'),
    (r'recon|discover|enumerat|scan|map.*network|survey|footprint', 'discovery'),
    (r'evad|bypass|disable|hide|obfuscat|tamper|kill.*av|blind', 'defense_evasion'),
    (r'execut|run|launch|spawn|start.*process|command|invoke', 'execution'),
    (r'initial|entry|phish|deliver|land|foothold', 'initial_access'),
    (r'brute\s*force|password\s*spray|spray|failed\s*logon|lockout|4625', 'brute_force'),
]


# =============================================================================
# QUERY MODE DETECTION - Determines how to search based on question type
# =============================================================================

def determine_query_mode(question: str, keywords: List[str]) -> str:
    """
    Determine the appropriate query mode based on the question.
    
    Returns:
        'big_picture' - Broad analysis, need representative sample
        'focused' - Specific user, time, or entity investigation
        'pattern' - Looking for attack patterns
    """
    question_lower = question.lower()
    
    # First check if there's a username pattern in the question (indicates focused)
    username_patterns = [
        r'\b[a-zA-Z]+\.[a-zA-Z]+\b',  # john.doe format
        r'\\[a-zA-Z][a-zA-Z0-9]+',     # DOMAIN\user format
    ]
    has_username = any(re.search(p, question) for p in username_patterns)
    
    # Focused mode indicators - user-specific investigation
    focused_patterns = [
        r'\buser\s+[a-zA-Z]',                          # "user john" or "user admin"
        r'\baccount\s+[a-zA-Z]',                       # "account admin"
        r'how\s+did\s+[a-zA-Z]+.*\s+get\s+compromised',  # "how did X get compromised"
        r'what\s+happened\s+to\s+[a-zA-Z]',           # "what happened to X"
        r'trace\s+[a-zA-Z]',                          # "trace X"
        r'timeline\s+for\s+',                         # "timeline for X"
        r'specifically\s+',
        r'\bonly\s+',
        r'what\s+did\s+[a-zA-Z]+.*\s+do',             # "what did X do"
        r'investigate\s+[a-zA-Z]',                    # "investigate X"
    ]
    
    # If has username AND matches a focused pattern, it's focused
    if has_username:
        for pattern in focused_patterns:
            if re.search(pattern, question_lower):
                return 'focused'
        # Even without focused pattern, username with "compromised" suggests focused
        if 'compromised' in question_lower or 'hacked' in question_lower:
            return 'focused'
    
    for pattern in focused_patterns:
        if re.search(pattern, question_lower):
            return 'focused'
    
    # Pattern mode indicators - aggregation-first for attack patterns
    pattern_patterns = [
        r'password\s+spray',
        r'brute\s+force',
        r'failed\s+logins?',
        r'lateral\s+movement\s+pattern',
        r'how\s+many\s+systems',
        r'spread\s+through',
        r'attack\s+path',
        r'all\s+logons?\s+from',
        r'all\s+connections?\s+to',
        r'cluster',
        r'pattern',
    ]
    
    for pattern in pattern_patterns:
        if re.search(pattern, question_lower):
            return 'pattern'
    
    # Default to big picture
    return 'big_picture'


def extract_target_user(question: str) -> Optional[str]:
    """
    Extract username from question for user-specific investigation.
    
    Examples:
        "How did john.doe get compromised?" → "john.doe"
        "What did user admin do?" → "admin"
        "Trace DOMAIN\\jsmith activity" → "jsmith"
    """
    patterns = [
        # "user john.doe" or "user jsmith"
        (r'\buser\s+([a-zA-Z][a-zA-Z0-9._-]+)', 1),
        # "account admin"
        (r'\baccount\s+([a-zA-Z][a-zA-Z0-9._-]+)', 1),
        # "john.doe got/was/get compromised"
        (r'\b([a-zA-Z]+\.[a-zA-Z]+)\s+(?:got|was|get|became)\s+compromised', 1),
        # "how did john.doe" or "what did john.doe"
        (r'(?:how|what)\s+did\s+([a-zA-Z]+\.[a-zA-Z]+)', 1),
        # "trace jsmith" or "investigate jsmith"
        (r'(?:trace|investigate|follow|track)\s+([a-zA-Z][a-zA-Z0-9._-]+)', 1),
        # "DOMAIN\username"
        (r'\\([a-zA-Z][a-zA-Z0-9._-]+)', 1),
        # "timeline for jsmith"
        (r'timeline\s+(?:for\s+)?([a-zA-Z][a-zA-Z0-9._-]+)', 1),
        # Username with domain prefix
        (r'\b([a-zA-Z]+\.[a-zA-Z]+)\b', 1),
    ]
    
    # Common false positives to filter out (but NOT admin - that's a valid username)
    false_positives = {
        'the', 'this', 'that', 'user', 'account', 'system', 'local', 
        'domain', 'network', 'service', 'any', 'all', 'some', 'events', 'event',
        'lateral', 'movement', 'password', 'spray', 'brute', 'force', 'malware',
        'suspicious', 'activity', 'logon', 'logoff', 'failed', 'success',
    }
    
    for pattern, group in patterns:
        match = re.search(pattern, question, re.IGNORECASE)
        if match:
            username = match.group(group)
            if username.lower() not in false_positives and len(username) >= 3:
                logger.info(f"[AI_SEARCH] Extracted target user: {username}")
                return username
    
    return None


# =============================================================================
# KILL CHAIN MAPPING - Track attack progression through phases
# =============================================================================

KILL_CHAIN_PHASES = {
    'reconnaissance': {
        'order': 1,
        'name': 'Reconnaissance',
        'description': 'Attacker gathering information about the target',
        'mitre_tactic': 'TA0043',
        'example_techniques': ['T1595', 'T1592', 'T1589'],
        'typical_next': 'initial_access',
        'typical_previous': None,
    },
    'initial_access': {
        'order': 2,
        'name': 'Initial Access',
        'description': 'Attacker gaining first foothold in the environment',
        'mitre_tactic': 'TA0001',
        'example_techniques': ['T1566', 'T1190', 'T1133'],
        'typical_next': 'execution',
        'typical_previous': 'reconnaissance',
    },
    'execution': {
        'order': 3,
        'name': 'Execution',
        'description': 'Attacker running malicious code',
        'mitre_tactic': 'TA0002',
        'example_techniques': ['T1059.001', 'T1059.003', 'T1204', 'T1047'],
        'typical_next': 'persistence',
        'typical_previous': 'initial_access',
    },
    'persistence': {
        'order': 4,
        'name': 'Persistence',
        'description': 'Attacker maintaining access across reboots/credential changes',
        'mitre_tactic': 'TA0003',
        'example_techniques': ['T1053.005', 'T1543.003', 'T1547.001'],
        'typical_next': 'privilege_escalation',
        'typical_previous': 'execution',
    },
    'privilege_escalation': {
        'order': 5,
        'name': 'Privilege Escalation',
        'description': 'Attacker gaining higher-level permissions',
        'mitre_tactic': 'TA0004',
        'example_techniques': ['T1134', 'T1068', 'T1548'],
        'typical_next': 'defense_evasion',
        'typical_previous': 'persistence',
    },
    'defense_evasion': {
        'order': 6,
        'name': 'Defense Evasion',
        'description': 'Attacker avoiding detection',
        'mitre_tactic': 'TA0005',
        'example_techniques': ['T1070.001', 'T1562.001', 'T1027', 'T1055'],
        'typical_next': 'credential_access',
        'typical_previous': 'privilege_escalation',
    },
    'credential_access': {
        'order': 7,
        'name': 'Credential Access',
        'description': 'Attacker stealing credentials',
        'mitre_tactic': 'TA0006',
        'example_techniques': ['T1003.001', 'T1550.002', 'T1558', 'T1110'],
        'typical_next': 'discovery',
        'typical_previous': 'defense_evasion',
    },
    'discovery': {
        'order': 8,
        'name': 'Discovery',
        'description': 'Attacker learning about the environment',
        'mitre_tactic': 'TA0007',
        'example_techniques': ['T1087', 'T1082', 'T1018', 'T1083'],
        'typical_next': 'lateral_movement',
        'typical_previous': 'credential_access',
    },
    'lateral_movement': {
        'order': 9,
        'name': 'Lateral Movement',
        'description': 'Attacker moving through the network',
        'mitre_tactic': 'TA0008',
        'example_techniques': ['T1021.001', 'T1021.002', 'T1021.006', 'T1570'],
        'typical_next': 'collection',
        'typical_previous': 'discovery',
    },
    'collection': {
        'order': 10,
        'name': 'Collection',
        'description': 'Attacker gathering data to steal',
        'mitre_tactic': 'TA0009',
        'example_techniques': ['T1560', 'T1039', 'T1005', 'T1114'],
        'typical_next': 'exfiltration',
        'typical_previous': 'lateral_movement',
    },
    'exfiltration': {
        'order': 11,
        'name': 'Exfiltration',
        'description': 'Attacker stealing data from the environment',
        'mitre_tactic': 'TA0010',
        'example_techniques': ['T1041', 'T1567', 'T1048'],
        'typical_next': 'impact',
        'typical_previous': 'collection',
    },
    'impact': {
        'order': 12,
        'name': 'Impact',
        'description': 'Attacker achieving objective (ransomware, destruction)',
        'mitre_tactic': 'TA0040',
        'example_techniques': ['T1486', 'T1490', 'T1489'],
        'typical_next': None,
        'typical_previous': 'exfiltration',
    },
}

# Mapping from MITRE tactic to kill chain phase
TACTIC_TO_PHASE = {
    'Reconnaissance': 'reconnaissance',
    'Initial Access': 'initial_access',
    'Execution': 'execution',
    'Persistence': 'persistence',
    'Privilege Escalation': 'privilege_escalation',
    'Defense Evasion': 'defense_evasion',
    'Credential Access': 'credential_access',
    'Discovery': 'discovery',
    'Lateral Movement': 'lateral_movement',
    'Collection': 'collection',
    'Command and Control': 'collection',  # Map to collection
    'Exfiltration': 'exfiltration',
    'Impact': 'impact',
}


def determine_kill_chain_phase(detected_techniques: Dict) -> Optional[Dict]:
    """
    Determine current kill chain phase based on detected techniques.
    Returns dict with phase info or None if no techniques detected.
    """
    if not detected_techniques:
        return None
    
    detected_phases = {}
    
    for tech_id, matches in detected_techniques.items():
        if matches and len(matches) > 0:
            # Get tactic from the match
            tactic = matches[0].get('tactic', '')
            phase = TACTIC_TO_PHASE.get(tactic)
            if phase:
                if phase not in detected_phases:
                    detected_phases[phase] = []
                detected_phases[phase].append(tech_id)
    
    if not detected_phases:
        return None
    
    # Find the furthest phase in the kill chain
    max_phase = max(detected_phases.keys(), 
                    key=lambda p: KILL_CHAIN_PHASES[p]['order'])
    
    return {
        'current_phase': max_phase,
        'phase_name': KILL_CHAIN_PHASES[max_phase]['name'],
        'phase_description': KILL_CHAIN_PHASES[max_phase]['description'],
        'all_detected_phases': list(detected_phases.keys()),
        'techniques_by_phase': detected_phases,
        'typical_next': KILL_CHAIN_PHASES[max_phase].get('typical_next'),
        'order': KILL_CHAIN_PHASES[max_phase]['order'],
    }


def get_kill_chain_context(kill_chain_result: Optional[Dict]) -> str:
    """Generate kill chain context for LLM prompt."""
    if not kill_chain_result:
        return "Kill chain phase: Unable to determine from available events."
    
    lines = ["\n## KILL CHAIN POSITION"]
    lines.append(f"")
    lines.append(f"**Current Phase**: {kill_chain_result['phase_name']} (Phase {kill_chain_result['order']}/12)")
    lines.append(f"**Description**: {kill_chain_result['phase_description']}")
    
    if len(kill_chain_result['all_detected_phases']) > 1:
        phases = [KILL_CHAIN_PHASES[p]['name'] for p in sorted(
            kill_chain_result['all_detected_phases'],
            key=lambda p: KILL_CHAIN_PHASES[p]['order']
        )]
        lines.append(f"**All phases detected**: {' → '.join(phases)}")
    
    if kill_chain_result.get('typical_next'):
        next_phase = KILL_CHAIN_PHASES[kill_chain_result['typical_next']]
        lines.append(f"")
        lines.append(f"**Typical next phase**: {next_phase['name']}")
        lines.append(f"**What to look for**: {next_phase['description']}")
    
    return '\n'.join(lines)


# =============================================================================
# GAP ANALYSIS ENGINE - What to investigate next based on findings
# =============================================================================

GAP_ANALYSIS = {
    'lateral_movement': {
        'if_found': {
            'summary': 'Lateral movement detected - attacker is spreading through the network',
            'severity': 'high',
            'critical_questions': [
                'Which account(s) were used for lateral movement?',
                'How did the attacker get credentials to move laterally?',
                'What systems were accessed via lateral movement?',
                'What activity occurred on the target systems?',
            ],
            'look_for_before': [
                'Credential theft (LSASS dump, DCSync, Kerberoasting)',
                'Initial access vector (phishing, exploitation)',
                'Discovery activity (network enumeration)',
            ],
            'look_for_after': [
                'Persistence mechanisms on target systems (scheduled tasks, services)',
                'Further lateral movement to additional systems',
                'Data collection and staging',
                'Credential theft on target systems',
            ],
        },
        'if_not_found': {
            'summary': 'No lateral movement detected in retrieved events',
            'possible_explanations': [
                'Attacker may have stayed on the initially compromised system',
                'Lateral movement occurred but via different technique not searched',
                'Movement occurred via cloud services (Azure AD, O365) not in Windows logs',
                'Network logon events (4624 Type 3/10) may not be logged or retained',
            ],
            'verification_steps': [
                'Verify Event 4624 logging is enabled with logon types',
                'Check Event 5140/5145 for share access (may indicate movement)',
                'Review cloud authentication logs (Azure AD, Okta)',
                'Check for RDP connections (Event 1149 in Terminal Services)',
                'Look for PsExec service installations (Event 7045 with PSEXESVC)',
            ],
        },
    },
    'credential_access': {
        'if_found': {
            'summary': 'Credential theft detected - attacker has harvested credentials',
            'severity': 'critical',
            'critical_questions': [
                'What type of credentials were stolen (local hashes, domain creds, tickets)?',
                'Which accounts were compromised?',
                'Were any privileged accounts (Domain Admin, etc.) affected?',
                'What was the credential theft method?',
            ],
            'look_for_before': [
                'Initial compromise (how did attacker get admin to dump creds?)',
                'Privilege escalation (did they escalate before stealing creds?)',
            ],
            'look_for_after': [
                'Lateral movement using stolen credentials',
                'Access to sensitive systems (Domain Controllers, file servers)',
                'Creation of new accounts or modification of existing',
                'Golden Ticket or DCSync (if krbtgt was compromised)',
            ],
        },
        'if_not_found': {
            'summary': 'No credential theft detected in retrieved events',
            'possible_explanations': [
                'Attacker may have brought valid credentials (phishing, password reuse)',
                'Credential theft occurred on a different system',
                'Sysmon Event 10 (ProcessAccess to LSASS) may not be configured',
                'Memory-only tools may have avoided detection',
            ],
            'verification_steps': [
                'Check for password spray/brute force patterns (4625 clusters)',
                'Review phishing indicators in email logs',
                'Verify Sysmon Event 10 is configured for LSASS monitoring',
                'Check for credential theft on Domain Controllers specifically',
                'Look for Kerberoasting (4769 with RC4 encryption)',
            ],
        },
    },
    'persistence': {
        'if_found': {
            'summary': 'Persistence mechanism detected - attacker has established backdoor access',
            'severity': 'high',
            'critical_questions': [
                'What is the persistence mechanism (scheduled task, service, registry)?',
                'What does the persistence mechanism execute?',
                'What account/privileges does it run as?',
                'When/how often does it trigger?',
            ],
            'look_for_before': [
                'Initial access and execution that led to persistence',
                'Privilege escalation needed to create persistence',
            ],
            'look_for_after': [
                'Execution events when persistence triggers',
                'Defense evasion around the persistence (AV exclusions)',
                'Additional persistence mechanisms for redundancy',
                'Network callbacks when persistence executes',
            ],
        },
        'if_not_found': {
            'summary': 'No persistence mechanisms detected in retrieved events',
            'possible_explanations': [
                'May be a smash-and-grab attack (no need for persistence)',
                'Attacker still in initial access phase',
                'Persistence may be in unmonitored location (firmware, cloud)',
                'Events for persistence may not be logged (registry, WMI)',
            ],
            'verification_steps': [
                'Check scheduled task events (4698, 4699)',
                'Verify service installation logging (7045)',
                'Review Sysmon Event 13 (Registry modifications)',
                'Check for WMI subscriptions (Sysmon 19-21)',
                'Look for startup folder modifications',
            ],
        },
    },
    'exfiltration': {
        'if_found': {
            'summary': 'Data exfiltration detected - attacker is stealing data',
            'severity': 'critical',
            'critical_questions': [
                'What data was exfiltrated?',
                'How much data was taken (volume/count)?',
                'Where was the data sent (destination)?',
                'Is exfiltration ongoing or complete?',
            ],
            'look_for_before': [
                'Data staging (archive creation, collection)',
                'Discovery activity (finding data to steal)',
                'Access to sensitive file shares or databases',
            ],
            'look_for_after': [
                'Ransomware deployment (double extortion)',
                'Cover tracks (log clearing, file deletion)',
                'Continued access for future exfiltration',
            ],
        },
        'if_not_found': {
            'summary': 'No data exfiltration detected in retrieved events',
            'possible_explanations': [
                'Attacker still in collection/staging phase',
                'Exfiltration via encrypted channel not visible in logs',
                'Data may have been exfiltrated outside logging coverage',
                'Attack objective may not be data theft (ransomware, BEC)',
            ],
            'verification_steps': [
                'Look for archive creation (zip, rar, 7z)',
                'Check network logs for large outbound transfers',
                'Review web proxy logs for cloud upload services',
                'Look for staging directories with collected files',
                'Check DNS logs for data exfiltration via DNS',
            ],
        },
    },
    'brute_force': {
        'if_found': {
            'summary': 'Brute force or password spray attack detected',
            'severity': 'high',
            'critical_questions': [
                'Did any attempts succeed? (4624/6272 after 4625/6273 cluster)',
                'Which accounts were targeted?',
                'Is the attack ongoing or historical?',
                'What is the source of the attack (IP address)?',
            ],
            'look_for_before': [
                'Reconnaissance that identified target accounts',
                'Harvesting of username lists',
            ],
            'look_for_after': [
                'Successful authentication from same source (4624 or 6272)',
                'Activity using any compromised accounts',
                'Lateral movement if account had network access',
            ],
        },
        'if_not_found': {
            'summary': 'No brute force or password spray detected',
            'possible_explanations': [
                'Attacker may have used valid credentials from another source',
                'Attack may have targeted cloud authentication (Azure AD, Okta)',
                'Failed logon logging may not be enabled',
                'Attack may have occurred on different system/DC',
            ],
            'verification_steps': [
                'Check Azure AD / Okta / cloud identity provider logs',
                'Verify Event 4625 logging is enabled',
                'Check VPN/NPS logs for Event 6273 (NPS denied access)',
                'Review email for phishing that may have captured credentials',
            ],
        },
    },
    'malware': {
        'if_found': {
            'summary': 'Malicious execution detected',
            'severity': 'high',
            'critical_questions': [
                'What malware/payload was executed?',
                'What was the initial execution vector?',
                'What is the parent process chain?',
                'What network connections were made?',
            ],
            'look_for_before': [
                'Delivery method (email attachment, download, exploit)',
                'User interaction that triggered execution',
            ],
            'look_for_after': [
                'Persistence mechanisms created',
                'Network callbacks (C2 communication)',
                'Child processes spawned',
                'Defense evasion activity',
                'Credential theft',
            ],
        },
        'if_not_found': {
            'summary': 'No obvious malicious execution detected',
            'possible_explanations': [
                'Attack may use living-off-the-land techniques (LOLBins)',
                'Malware may be fileless (memory-only)',
                'Execution may have been via legitimate tools',
                'Process logging may be incomplete',
            ],
            'verification_steps': [
                'Check for LOLBin abuse (certutil, mshta, regsvr32)',
                'Review PowerShell logging (Event 4104)',
                'Look for encoded commands',
                'Check for script-based execution',
            ],
        },
    },
    'defense_evasion': {
        'if_found': {
            'summary': 'Defense evasion activity detected',
            'severity': 'high',
            'critical_questions': [
                'What defensive measures were evaded/disabled?',
                'What account performed the evasion?',
                'What happened after defenses were weakened?',
            ],
            'look_for_before': [
                'Initial compromise that required evasion',
                'Privilege escalation to disable defenses',
            ],
            'look_for_after': [
                'CRITICAL: Activity that occurred AFTER defenses disabled',
                'This is likely the "real" attack hidden by the evasion',
            ],
        },
        'if_not_found': {
            'summary': 'No defense evasion detected',
            'possible_explanations': [
                'Attack may have avoided triggering security tools',
                'Tools may have been disabled before logging started',
                'Attacker may be using techniques that bypass detection',
            ],
            'verification_steps': [
                'Check security tool status/health logs',
                'Look for gaps in logging that might indicate tampering',
                'Review any log cleared events (1102)',
            ],
        },
    },
}


def get_gap_analysis(detected_attack_types: List[str], 
                     detected_techniques: Dict) -> str:
    """
    Generate gap analysis guidance based on what was found/not found.
    """
    lines = ["\n## GAP ANALYSIS & INVESTIGATION GUIDANCE\n"]
    
    # Determine what attack types were actually detected
    found_types = set()
    not_found_types = set()
    
    # Map techniques to attack types based on tactic
    tactic_to_type = {
        'Lateral Movement': 'lateral_movement',
        'Credential Access': 'credential_access',
        'Persistence': 'persistence',
        'Exfiltration': 'exfiltration',
        'Execution': 'malware',
        'Defense Evasion': 'defense_evasion',
    }
    
    for tech_id, matches in detected_techniques.items():
        if matches:
            tactic = matches[0].get('tactic', '')
            attack_type = tactic_to_type.get(tactic)
            if attack_type:
                found_types.add(attack_type)
    
    # Add types from query expansion that were searched for but not found
    for attack_type in detected_attack_types:
        if attack_type not in found_types and attack_type in GAP_ANALYSIS:
            not_found_types.add(attack_type)
    
    # Generate guidance for found types
    for attack_type in found_types:
        if attack_type in GAP_ANALYSIS:
            gap = GAP_ANALYSIS[attack_type]['if_found']
            lines.append(f"### ✅ {attack_type.upper().replace('_', ' ')} DETECTED")
            lines.append(f"**{gap['summary']}**")
            lines.append(f"")
            lines.append(f"**What to investigate next:**")
            for item in gap.get('look_for_after', [])[:3]:
                lines.append(f"- {item}")
            lines.append("")
    
    # Generate guidance for not found types (only top 2)
    for attack_type in list(not_found_types)[:2]:
        if attack_type in GAP_ANALYSIS:
            gap = GAP_ANALYSIS[attack_type]['if_not_found']
            lines.append(f"### ❓ {attack_type.upper().replace('_', ' ')} NOT DETECTED")
            lines.append(f"**{gap['summary']}**")
            lines.append(f"")
            lines.append(f"**Possible reasons:**")
            for item in gap.get('possible_explanations', [])[:2]:
                lines.append(f"- {item}")
            lines.append(f"")
            lines.append(f"**Verification steps:**")
            for item in gap.get('verification_steps', [])[:2]:
                lines.append(f"- {item}")
            lines.append("")
    
    return '\n'.join(lines)


# =============================================================================
# INTELLIGENT SAMPLER - Tiered allocation for 3-20M event cases
# =============================================================================

class IntelligentSampler:
    """
    Intelligent event sampling for 3-20M event cases.
    Uses tiered allocation to get the most relevant events for LLM analysis.
    """
    
    # Maximum events to return to LLM
    MAX_FINAL_EVENTS = 25
    
    # Allocation for different priority tiers
    TIER_ALLOCATION = {
        'priority': 10,      # Tagged, SIGMA critical/high, IOC
        'pattern': 4,        # Events from aggregation detection
        'medium': 8,         # SIGMA medium/low, interesting event types
        'random': 3,         # Random sample for baseline coverage
    }
    
    # Event types that are particularly interesting for DFIR
    INTERESTING_EVENT_IDS = {
        # Critical security events
        4688, 4689,  # Process creation/termination
        4624, 4625, 4648, 4672,  # Logon events
        7045, 4697,  # Service installation
        4698, 4699, 4700, 4701, 4702,  # Scheduled tasks
        1102, 104,  # Log cleared
        # Sysmon
        1, 3, 7, 8, 10, 11, 12, 13, 22,
        # PowerShell
        4103, 4104,
        # NPS/VPN events (v1.32.0)
        6272, 6273, 6274, 6275, 6276, 6277, 6278, 6279,
    }
    
    def __init__(self, opensearch_client, case_id: int):
        self.client = opensearch_client
        self.case_id = case_id
        self.index_name = f"case_{case_id}"
    
    def sample_events(self, 
                      question: str,
                      keywords: List[str],
                      dfir_terms: List[str],
                      exclusions: List[Dict],
                      mode: str = 'big_picture') -> Tuple[List[Dict], Dict]:
        """
        Intelligently sample events based on query mode.
        
        Args:
            question: Original question
            keywords: Extracted keywords
            dfir_terms: DFIR expansion terms
            exclusions: must_not clauses for exclusions
            mode: 'big_picture', 'focused', or 'pattern'
            
        Returns:
            (sampled_events, sampling_stats)
        """
        all_events = []
        event_ids_seen = set()
        stats = {
            'total_events_in_case': 0,
            'priority_events': 0,
            'medium_events': 0,
            'pattern_events': 0,
            'random_events': 0,
            'sampling_mode': mode,
            'patterns_detected': [],
        }
        
        # Get total event count
        try:
            count_response = self.client.count(index=self.index_name)
            stats['total_events_in_case'] = count_response['count']
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Could not get count: {e}")
            stats['total_events_in_case'] = 0
        
        # 1. Priority Tier: Tagged, SIGMA critical/high, IOC matches
        priority_events = self._get_priority_events(
            keywords, dfir_terms, exclusions, 
            limit=self.TIER_ALLOCATION['priority']
        )
        for e in priority_events:
            if e['_id'] not in event_ids_seen:
                all_events.append(e)
                event_ids_seen.add(e['_id'])
        stats['priority_events'] = len(priority_events)
        
        # 2. Pattern Tier: Aggregation-based pattern detection
        if mode in ['big_picture', 'pattern']:
            pattern_events, patterns_found = self._get_pattern_events(
                keywords, exclusions,
                limit=self.TIER_ALLOCATION['pattern']
            )
            for e in pattern_events:
                if e['_id'] not in event_ids_seen:
                    all_events.append(e)
                    event_ids_seen.add(e['_id'])
            stats['pattern_events'] = len([e for e in pattern_events if e['_id'] not in event_ids_seen or True])
            stats['patterns_detected'] = patterns_found
        
        # 3. Medium Tier: SIGMA medium/low, interesting event types
        medium_events = self._get_medium_priority_events(
            keywords, dfir_terms, exclusions,
            limit=self.TIER_ALLOCATION['medium'],
            existing_ids=event_ids_seen
        )
        for e in medium_events:
            if e['_id'] not in event_ids_seen:
                all_events.append(e)
                event_ids_seen.add(e['_id'])
        stats['medium_events'] = len(medium_events)
        
        # 4. Random Tier: Representative sample for coverage
        if mode == 'big_picture':
            random_events = self._get_stratified_random_sample(
                exclusions,
                limit=self.TIER_ALLOCATION['random'],
                existing_ids=event_ids_seen
            )
            for e in random_events:
                if e['_id'] not in event_ids_seen:
                    all_events.append(e)
                    event_ids_seen.add(e['_id'])
            stats['random_events'] = len(random_events)
        
        # Limit to maximum
        all_events = all_events[:self.MAX_FINAL_EVENTS]
        
        logger.info(f"[AI_SEARCH] IntelligentSampler: {len(all_events)} events "
                   f"(priority={stats['priority_events']}, pattern={stats['pattern_events']}, "
                   f"medium={stats['medium_events']}, random={stats['random_events']})")
        
        return all_events, stats
    
    def _get_priority_events(self, keywords: List[str], dfir_terms: List[str], 
                            exclusions: List[Dict], limit: int) -> List[Dict]:
        """Get highest priority events: tagged, SIGMA critical/high, IOC."""
        try:
            should_clauses = [
                # Tagged events - highest priority
                {"term": {"is_tagged": {"value": True, "boost": 100}}},
                # SIGMA critical/high
                {"bool": {
                    "must": [
                        {"term": {"has_sigma": True}},
                        {"terms": {"sigma_level.keyword": ["critical", "high"]}}
                    ],
                    "boost": 50
                }},
                # IOC matches
                {"term": {"has_ioc": {"value": True, "boost": 30}}},
            ]
            
            # Add keyword matches
            search_fields = ["search_blob^1.5", "event_title^3", "command_line^2"]
            for kw in (keywords + dfir_terms)[:15]:
                should_clauses.append({
                    "multi_match": {
                        "query": kw,
                        "fields": search_fields,
                        "boost": 10
                    }
                })
            
            query = {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            }
            if exclusions:
                query["bool"]["must_not"] = exclusions
            
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "size": limit * 2,  # Get extra for deduplication
                    "sort": [{"_score": "desc"}, {"normalized_timestamp": "desc"}],
                    "_source": True,
                },
                request_timeout=15
            )
            
            return self._hits_to_events(response)[:limit]
            
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Priority events query failed: {e}")
            return []
    
    def _get_pattern_events(self, keywords: List[str], exclusions: List[Dict], 
                           limit: int) -> Tuple[List[Dict], List[str]]:
        """Get events representing attack patterns via aggregation."""
        all_pattern_events = []
        patterns_found = []
        
        # Pattern 1: Password spray detection
        spray_events, spray_detected = self._detect_password_spray(exclusions, limit=2)
        all_pattern_events.extend(spray_events)
        if spray_detected:
            patterns_found.append('password_spray')
        
        # Pattern 2: Lateral movement clusters
        lateral_events, lateral_detected = self._detect_lateral_movement(exclusions, limit=2)
        all_pattern_events.extend(lateral_events)
        if lateral_detected:
            patterns_found.append('lateral_movement')
        
        # Pattern 3: Suspicious process chains
        process_events = self._detect_suspicious_processes(keywords, exclusions, limit=2)
        all_pattern_events.extend(process_events)
        if process_events:
            patterns_found.append('suspicious_process')
        
        return all_pattern_events[:limit], patterns_found
    
    def _detect_password_spray(self, exclusions: List[Dict], limit: int) -> Tuple[List[Dict], bool]:
        """Detect password spray patterns via aggregation (4625 Windows + 6273 NPS)."""
        try:
            # Search for both Windows failed logon (4625) AND NPS denied (6273)
            query = {
                "bool": {
                    "filter": [{
                        "bool": {
                            "should": [
                                {"term": {"normalized_event_id": 4625}},
                                {"term": {"normalized_event_id": "4625"}},
                                {"term": {"normalized_event_id": 6273}},
                                {"term": {"normalized_event_id": "6273"}},
                            ],
                            "minimum_should_match": 1
                        }
                    }],
                }
            }
            if exclusions:
                query["bool"]["must_not"] = exclusions
            
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "size": 0,
                    "aggs": {
                        "by_source": {
                            "terms": {"field": "IpAddress.keyword", "size": 10},
                            "aggs": {
                                "unique_targets": {
                                    "cardinality": {"field": "TargetUserName.keyword"}
                                },
                                "sample_events": {
                                    "top_hits": {"size": 2, "_source": True}
                                }
                            }
                        }
                    }
                },
                request_timeout=15
            )
            
            events = []
            spray_detected = False
            for bucket in response.get('aggregations', {}).get('by_source', {}).get('buckets', []):
                unique_targets = bucket.get('unique_targets', {}).get('value', 0)
                if unique_targets >= 5:  # 5+ targets = likely spray
                    spray_detected = True
                    for hit in bucket.get('sample_events', {}).get('hits', {}).get('hits', []):
                        event = self._hit_to_event(hit)
                        event['_source']['_pattern'] = 'password_spray'
                        event['_source']['_pattern_context'] = f"Source IP {bucket['key']} targeted {unique_targets} unique accounts"
                        events.append(event)
            
            return events[:limit], spray_detected
            
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Password spray detection failed: {e}")
            return [], False
    
    def _detect_lateral_movement(self, exclusions: List[Dict], limit: int) -> Tuple[List[Dict], bool]:
        """Detect lateral movement patterns via aggregation."""
        try:
            query = {
                "bool": {
                    "filter": [
                        {"term": {"normalized_event_id": 4624}},
                        {"terms": {"LogonType.keyword": ["3", "10"]}}
                    ],
                }
            }
            if exclusions:
                query["bool"]["must_not"] = exclusions
            
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "size": 0,
                    "aggs": {
                        "by_target": {
                            "terms": {"field": "normalized_computer.keyword", "size": 10},
                            "aggs": {
                                "unique_sources": {
                                    "cardinality": {"field": "IpAddress.keyword"}
                                },
                                "sample_events": {
                                    "top_hits": {"size": 2, "_source": True}
                                }
                            }
                        }
                    }
                },
                request_timeout=15
            )
            
            events = []
            lateral_detected = False
            for bucket in response.get('aggregations', {}).get('by_target', {}).get('buckets', []):
                unique_sources = bucket.get('unique_sources', {}).get('value', 0)
                if unique_sources >= 3:  # 3+ sources = interesting
                    lateral_detected = True
                    for hit in bucket.get('sample_events', {}).get('hits', {}).get('hits', []):
                        event = self._hit_to_event(hit)
                        event['_source']['_pattern'] = 'lateral_movement'
                        event['_source']['_pattern_context'] = f"Target {bucket['key']} received logons from {unique_sources} unique sources"
                        events.append(event)
            
            return events[:limit], lateral_detected
            
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Lateral movement detection failed: {e}")
            return [], False
    
    def _detect_suspicious_processes(self, keywords: List[str], exclusions: List[Dict], 
                                    limit: int) -> List[Dict]:
        """Detect suspicious process execution patterns."""
        suspicious_patterns = [
            'powershell.*-enc', 'powershell.*downloadstring', 'powershell.*hidden',
            'certutil.*-decode', 'certutil.*-urlcache',
            'mshta.*http', 'mshta.*javascript',
            'regsvr32.*/s.*/i',
            'rundll32.*javascript',
            'wmic.*process.*call',
        ]
        
        try:
            should_clauses = []
            for pattern in suspicious_patterns:
                should_clauses.append({
                    "regexp": {"search_blob": {"value": pattern, "case_insensitive": True}}
                })
            
            query = {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            }
            if exclusions:
                query["bool"]["must_not"] = exclusions
            
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "size": limit,
                    "sort": [{"normalized_timestamp": "desc"}],
                    "_source": True,
                },
                request_timeout=15
            )
            
            events = self._hits_to_events(response)
            for e in events:
                e['_source']['_pattern'] = 'suspicious_process'
            return events
            
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Suspicious process detection failed: {e}")
            return []
    
    def _get_medium_priority_events(self, keywords: List[str], dfir_terms: List[str],
                                   exclusions: List[Dict], limit: int, 
                                   existing_ids: Set[str]) -> List[Dict]:
        """Get medium priority events: SIGMA medium/low, interesting event types."""
        try:
            should_clauses = [
                # SIGMA medium/low
                {"bool": {
                    "must": [
                        {"term": {"has_sigma": True}},
                        {"terms": {"sigma_level.keyword": ["medium", "low"]}}
                    ],
                    "boost": 5
                }},
                # Interesting event types
                {"terms": {"normalized_event_id": list(self.INTERESTING_EVENT_IDS), "boost": 3}},
            ]
            
            # Add keyword matches
            search_fields = ["search_blob", "command_line"]
            for kw in (keywords + dfir_terms)[:10]:
                should_clauses.append({
                    "multi_match": {
                        "query": kw,
                        "fields": search_fields,
                        "boost": 2
                    }
                })
            
            must_not = list(exclusions) if exclusions else []
            if existing_ids:
                must_not.append({"ids": {"values": list(existing_ids)[:1000]}})
            
            query = {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            }
            if must_not:
                query["bool"]["must_not"] = must_not
            
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "size": limit * 3,  # Get extra for diversity
                    "sort": [{"_score": "desc"}],
                    "_source": True,
                },
                request_timeout=15
            )
            
            # Manual diversity: max 2 per event type
            events = []
            type_counts = defaultdict(int)
            for hit in response['hits']['hits']:
                event_type = str(hit['_source'].get('normalized_event_id', 'unknown'))
                if type_counts[event_type] < 2:
                    events.append(self._hit_to_event(hit))
                    type_counts[event_type] += 1
                if len(events) >= limit:
                    break
            
            return events
            
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Medium priority query failed: {e}")
            return []
    
    def _get_stratified_random_sample(self, exclusions: List[Dict], limit: int,
                                     existing_ids: Set[str]) -> List[Dict]:
        """Get stratified random sample across time and event types."""
        try:
            must_not = list(exclusions) if exclusions else []
            if existing_ids:
                must_not.append({"ids": {"values": list(existing_ids)[:1000]}})
            
            query = {
                "bool": {
                    "must": [
                        {"function_score": {
                            "random_score": {"seed": 42, "field": "_seq_no"}
                        }}
                    ],
                }
            }
            if must_not:
                query["bool"]["must_not"] = must_not
            
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": query,
                    "size": limit,
                    "_source": True,
                },
                request_timeout=15
            )
            
            events = self._hits_to_events(response)
            for e in events:
                e['_source']['_sample_type'] = 'random_baseline'
            return events
            
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Random sampling failed: {e}")
            return []
    
    def _hits_to_events(self, response: Dict) -> List[Dict]:
        """Convert OpenSearch hits to event dicts."""
        return [self._hit_to_event(hit) for hit in response.get('hits', {}).get('hits', [])]
    
    def _hit_to_event(self, hit: Dict) -> Dict:
        """Convert single hit to event dict."""
        return {
            '_id': hit['_id'],
            '_index': hit.get('_index', self.index_name),
            '_score': hit.get('_score', 0),
            '_source': hit.get('_source', {}),
        }


# =============================================================================
# USER-FOCUSED INVESTIGATION - Timeline and analysis for specific users
# =============================================================================

def get_user_timeline(opensearch_client, case_id: int, username: str, 
                      limit: int = 50) -> List[Dict]:
    """
    Build a timeline of events for a specific user.
    """
    index_name = f"case_{case_id}"
    
    query = {
        "bool": {
            "should": [
                {"term": {"TargetUserName.keyword": username}},
                {"term": {"SubjectUserName.keyword": username}},
                {"wildcard": {"TargetUserName": f"*{username}*"}},
                {"wildcard": {"SubjectUserName": f"*{username}*"}},
                {"match_phrase": {"search_blob": username}},
            ],
            "minimum_should_match": 1
        }
    }
    
    try:
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": limit,
                "sort": [{"normalized_timestamp": "asc"}],  # Chronological
                "_source": True,
            },
            request_timeout=20
        )
        
        return [{
            '_id': hit['_id'],
            '_index': hit['_index'],
            '_source': hit['_source'],
            '_score': hit.get('_score', 0),
        } for hit in response['hits']['hits']]
        
    except Exception as e:
        logger.warning(f"[AI_SEARCH] User timeline query failed: {e}")
        return []


def analyze_user_compromise(events: List[Dict], username: str) -> Dict:
    """
    Analyze how a user may have been compromised.
    """
    analysis = {
        'username': username,
        'first_event': None,
        'first_suspicious_event': None,
        'event_count': len(events),
        'logon_sources': set(),
        'processes_run': [],
        'possible_compromise_vector': None,
        'timeline_summary': [],
    }
    
    if not events:
        return analysis
    
    analysis['first_event'] = events[0].get('_source', {}).get('normalized_timestamp')
    
    for event in events:
        source = event.get('_source', {})
        event_id = str(source.get('normalized_event_id', ''))
        event_data = source.get('EventData', {})
        if isinstance(event_data, str):
            event_data = {}
        
        # Track logon sources
        if event_id in ['4624', '4625']:
            ip = event_data.get('IpAddress') if isinstance(event_data, dict) else None
            if ip and ip not in ['-', '::1', '127.0.0.1', '', 'LOCAL']:
                analysis['logon_sources'].add(ip)
        
        # Track processes
        if event_id in ['4688', '1']:
            proc = event_data.get('NewProcessName') or event_data.get('Image') if isinstance(event_data, dict) else None
            if proc:
                analysis['processes_run'].append(proc)
        
        # Find first suspicious event
        if analysis['first_suspicious_event'] is None:
            if source.get('has_sigma') or source.get('has_ioc'):
                analysis['first_suspicious_event'] = {
                    'timestamp': source.get('normalized_timestamp'),
                    'event_id': event_id,
                    'description': source.get('event_title', 'Suspicious activity'),
                }
    
    analysis['logon_sources'] = list(analysis['logon_sources'])
    
    return analysis


def format_user_analysis(user_analysis: Dict) -> str:
    """Format user analysis for LLM prompt."""
    if not user_analysis or not user_analysis.get('username'):
        return ""
    
    lines = [f"\n## USER ANALYSIS: {user_analysis['username']}"]
    lines.append(f"- Total events: {user_analysis.get('event_count', 0)}")
    lines.append(f"- First event: {user_analysis.get('first_event', 'Unknown')}")
    
    if user_analysis.get('first_suspicious_event'):
        fse = user_analysis['first_suspicious_event']
        lines.append(f"- First suspicious event: {fse.get('timestamp')} - {fse.get('description')}")
    
    if user_analysis.get('logon_sources'):
        lines.append(f"- Logon sources: {', '.join(user_analysis['logon_sources'][:5])}")
    
    return '\n'.join(lines)


# =============================================================================
# CASE OVERVIEW - Big picture context for LLM
# =============================================================================

def generate_case_overview(opensearch_client, case_id: int) -> Dict:
    """
    Generate a big-picture overview of the case for context.
    """
    index_name = f"case_{case_id}"
    
    overview = {
        'total_events': 0,
        'time_range': {'start': None, 'end': None},
        'top_event_types': [],
        'top_computers': [],
        'top_users': [],
        'sigma_summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'ioc_count': 0,
        'tagged_count': 0,
    }
    
    try:
        response = opensearch_client.search(
            index=index_name,
            body={
                "size": 0,
                "aggs": {
                    "min_time": {"min": {"field": "normalized_timestamp"}},
                    "max_time": {"max": {"field": "normalized_timestamp"}},
                    "event_types": {
                        "terms": {"field": "normalized_event_id", "size": 10}
                    },
                    "computers": {
                        "terms": {"field": "normalized_computer.keyword", "size": 10}
                    },
                    "users": {
                        "terms": {"field": "username.keyword", "size": 10}
                    },
                    "sigma_levels": {
                        "filter": {"term": {"has_sigma": True}},
                        "aggs": {
                            "levels": {
                                "terms": {"field": "sigma_level.keyword", "size": 10}
                            }
                        }
                    },
                    "ioc_events": {
                        "filter": {"term": {"has_ioc": True}}
                    },
                    "tagged_events": {
                        "filter": {"term": {"is_tagged": True}}
                    },
                }
            },
            request_timeout=20
        )
        
        aggs = response.get('aggregations', {})
        total = response.get('hits', {}).get('total', {})
        overview['total_events'] = total.get('value', 0) if isinstance(total, dict) else total
        overview['time_range']['start'] = aggs.get('min_time', {}).get('value_as_string')
        overview['time_range']['end'] = aggs.get('max_time', {}).get('value_as_string')
        
        overview['top_event_types'] = [
            {'event_id': b['key'], 'count': b['doc_count']}
            for b in aggs.get('event_types', {}).get('buckets', [])
        ]
        
        overview['top_computers'] = [
            {'computer': b['key'], 'count': b['doc_count']}
            for b in aggs.get('computers', {}).get('buckets', [])
        ]
        
        overview['top_users'] = [
            {'user': b['key'], 'count': b['doc_count']}
            for b in aggs.get('users', {}).get('buckets', [])
        ]
        
        for level_bucket in aggs.get('sigma_levels', {}).get('levels', {}).get('buckets', []):
            level = level_bucket['key'].lower()
            if level in overview['sigma_summary']:
                overview['sigma_summary'][level] = level_bucket['doc_count']
        
        overview['ioc_count'] = aggs.get('ioc_events', {}).get('doc_count', 0)
        overview['tagged_count'] = aggs.get('tagged_events', {}).get('doc_count', 0)
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Failed to generate case overview: {e}")
    
    return overview


def get_case_context_for_prompt(overview: Dict) -> str:
    """Generate case context for LLM prompt."""
    lines = ["## CASE OVERVIEW"]
    lines.append(f"- **Total events**: {overview.get('total_events', 0):,}")
    
    time_range = overview.get('time_range', {})
    if time_range.get('start') and time_range.get('end'):
        lines.append(f"- **Time range**: {time_range['start']} to {time_range['end']}")
    
    sigma = overview.get('sigma_summary', {})
    sigma_total = sum(sigma.values())
    if sigma_total > 0:
        lines.append(f"- **SIGMA detections**: {sigma_total} total "
                    f"(Critical: {sigma.get('critical', 0)}, High: {sigma.get('high', 0)})")
    
    if overview.get('ioc_count', 0) > 0:
        lines.append(f"- **IOC matches**: {overview['ioc_count']}")
    
    if overview.get('tagged_count', 0) > 0:
        lines.append(f"- **Analyst tagged**: {overview['tagged_count']}")
    
    if overview.get('top_computers'):
        top_computers = ', '.join(c['computer'] for c in overview['top_computers'][:3])
        lines.append(f"- **Top computers**: {top_computers}")
    
    return '\n'.join(lines)


# =============================================================================
# ENHANCED LLM PROMPTS - Specialized for different query modes
# =============================================================================

BIG_PICTURE_PROMPT = """You are a senior Digital Forensics and Incident Response (DFIR) analyst with expertise in the MITRE ATT&CK framework.

## CASE: {case_name}

{case_overview}

## ANALYST'S QUESTION
{question}

## SAMPLING INFORMATION
This case contains **{total_events:,}** events. To give you the best overview, we intelligently sampled:
- {priority_events} high-priority events (tagged by analyst, SIGMA critical/high, IOC matches)
- {pattern_events} events showing attack patterns (password spray, lateral movement clusters)
- {medium_events} medium-priority events (SIGMA medium/low, interesting event types)
- {random_events} random baseline events (for coverage)

{patterns_detected}

{technique_context}

{kill_chain_context}

{gap_analysis}

## EVIDENCE EVENTS (showing {event_count} of {total_events:,})

{events_text}

## WINDOWS EVENT ID QUICK REFERENCE
- **4624** = Successful logon (Type 2=Interactive, 3=Network, 10=RDP)
- **4625** = Failed logon (brute force/spray indicator)
- **6272** = NPS granted VPN/RDP access (successful VPN logon)
- **6273** = NPS denied VPN/RDP access (failed VPN logon - brute force indicator!)
- **4648** = Explicit credential logon (pass-the-hash indicator)
- **4672** = Special privileges assigned (admin logon)
- **4688** = Process created (look at CommandLine!)
- **4698** = Scheduled task created
- **5140/5145** = Network share accessed
- **7045** = Service installed
- **1102** = Security log cleared (CRITICAL - anti-forensics)

## YOUR ANALYSIS

Based on the sampled evidence above:

1. **Answer the question** with specific evidence citations [Event N]
2. **Identify attack patterns** visible in the sampled events
3. **Note the kill chain phase** and what typically comes next
4. **Flag critical findings** that need immediate attention
5. **Acknowledge sampling limitations** - what might we be missing?
6. **Suggest follow-up queries** for deeper investigation

Be specific with usernames, IPs, timestamps, and commands. Reference events by number.

YOUR ANALYSIS:
"""

FOCUSED_PROMPT = """You are a senior DFIR analyst investigating a specific user or entity.

## CASE: {case_name}

## INVESTIGATION TARGET
**{target_type}**: {target_value}

## ANALYST'S QUESTION
{question}

{user_analysis}

{technique_context}

## TIMELINE OF EVENTS FOR {target_value}

{events_text}

## WINDOWS EVENT ID QUICK REFERENCE
- **4624** = Successful logon (Type 2=Interactive, 3=Network, 10=RDP)
- **4625** = Failed logon
- **4648** = Explicit credential logon
- **4672** = Special privileges assigned
- **4688** = Process created
- **4698** = Scheduled task created

## YOUR ANALYSIS

Build a narrative of what happened to/by {target_value}:

1. **Timeline reconstruction** - What sequence of events occurred?
2. **Compromise vector** - How did the compromise start?
3. **Attacker actions** - What did the attacker do after compromise?
4. **Lateral movement** - Did the attack spread from this account?
5. **Current status** - Is the compromise ongoing or contained?

Reference specific events and timestamps.

YOUR ANALYSIS:
"""

PATTERN_PROMPT = """You are a senior DFIR analyst analyzing attack patterns.

## CASE: {case_name}

## ANALYST'S QUESTION
{question}

## DETECTED PATTERNS

{pattern_summary}

{technique_context}

{kill_chain_context}

## PATTERN EVIDENCE

{events_text}

## YOUR ANALYSIS

Analyze the detected patterns:

1. **Pattern confirmation** - Is this a real attack or false positive?
2. **Attack scope** - How widespread is the pattern?
3. **Timeline** - When did the pattern start/stop?
4. **Success rate** - Did the attack achieve its objective?
5. **Recommendations** - What actions should be taken?

YOUR ANALYSIS:
"""


def format_pattern_summary(patterns_detected: List[str], events: List[Dict]) -> str:
    """Format detected patterns for the prompt."""
    if not patterns_detected:
        return "No specific attack patterns detected via aggregation."
    
    lines = []
    for pattern in patterns_detected:
        if pattern == 'password_spray':
            lines.append("### 🔴 PASSWORD SPRAY DETECTED")
            lines.append("Multiple failed logon attempts from single source to multiple accounts.")
            # Find pattern context from events
            for e in events:
                ctx = e.get('_source', {}).get('_pattern_context')
                if ctx and 'targeted' in ctx:
                    lines.append(f"- {ctx}")
                    break
        elif pattern == 'lateral_movement':
            lines.append("### 🔴 LATERAL MOVEMENT CLUSTER DETECTED")
            lines.append("Multiple source systems connecting to same target.")
            for e in events:
                ctx = e.get('_source', {}).get('_pattern_context')
                if ctx and 'logons from' in ctx:
                    lines.append(f"- {ctx}")
                    break
        elif pattern == 'suspicious_process':
            lines.append("### ⚠️ SUSPICIOUS PROCESS EXECUTION")
            lines.append("Process execution matching known attack patterns (LOLBins, encoded commands).")
    
    return '\n'.join(lines) if lines else "No specific patterns detected."


# =============================================================================
# COMMON NOISE TERMS - Suggestions for users
# =============================================================================

COMMON_EXCLUSIONS = {
    'security_tools': ['sentinelone', 'crowdstrike', 'defender', 'symantec', 'mcafee', 
                       'kaspersky', 'sophos', 'cylance', 'carbon black', 'cortex'],
    'backup_software': ['veeam', 'acronis', 'commvault', 'veritas', 'arcserve', 'backup exec'],
    'system_accounts': ['system', 'local service', 'network service', 'dwm-', 'umfd-'],
    'management_tools': ['sccm', 'intune', 'bigfix', 'tanium', 'altiris', 'landesk'],
    'monitoring': ['splunk', 'elastic', 'logstash', 'filebeat', 'winlogbeat', 'nxlog'],
}


# =============================================================================
# MITRE ATT&CK TECHNIQUE PATTERNS - Key techniques with detection indicators
# =============================================================================

MITRE_ATTACK_PATTERNS = {
    # EXECUTION
    'T1059.001': {
        'name': 'PowerShell',
        'tactic': 'Execution',
        'indicators': ['powershell', 'pwsh', 'encodedcommand', '-enc', 'bypass', 'hidden', 
                       'downloadstring', 'iex', 'invoke-expression', 'frombase64string'],
        'event_ids': ['4688', '4104', '1'],
    },
    'T1218': {
        'name': 'LOLBAS',
        'tactic': 'Execution',
        'indicators': ['certutil', 'bitsadmin', 'mshta', 'regsvr32', 'rundll32', 
                       'msiexec', 'installutil', 'cmstp', 'msbuild'],
        'event_ids': ['4688', '1'],
    },
    
    # PERSISTENCE
    'T1053.005': {
        'name': 'Scheduled Task',
        'tactic': 'Persistence',
        'indicators': ['schtasks', '/create', 'at.exe', 'taskschd'],
        'event_ids': ['4698', '4699', '4702'],
    },
    'T1543.003': {
        'name': 'Windows Service',
        'tactic': 'Persistence',
        'indicators': ['sc create', 'sc config', 'new-service', 'binpath'],
        'event_ids': ['7045', '4697'],
    },
    
    # CREDENTIAL ACCESS
    'T1003.001': {
        'name': 'LSASS Credential Dump',
        'tactic': 'Credential Access',
        'indicators': ['lsass', 'mimikatz', 'sekurlsa', 'procdump', 'comsvcs', 'minidump'],
        'event_ids': ['10', '4688', '1'],
    },
    'T1110': {
        'name': 'Brute Force / Password Spray',
        'tactic': 'Credential Access',
        'indicators': ['failed logon', 'bad password', 'account lockout', 'denied access', 
                       'nps', 'radius', 'network policy server'],
        'event_ids': ['4625', '4771', '4776', '6273', '6274'],  # Added NPS denied events
    },
    'T1558.003': {
        'name': 'Kerberoasting',
        'tactic': 'Credential Access',
        'indicators': ['kerberoast', 'tgs-req', 'serviceprincipalname', 'rc4-hmac'],
        'event_ids': ['4769'],
    },
    
    # LATERAL MOVEMENT
    'T1021.002': {
        'name': 'SMB/Admin Shares',
        'tactic': 'Lateral Movement',
        'indicators': ['admin$', 'c$', 'ipc$', 'net use', 'psexec', 'smbexec'],
        'event_ids': ['5140', '5145', '4624'],
    },
    'T1021.001': {
        'name': 'RDP',
        'tactic': 'Lateral Movement',
        'indicators': ['mstsc', 'rdp', '3389', 'remote desktop', 'termsrv'],
        'event_ids': ['4624', '4778', '4779', '1149'],
    },
    'T1550.002': {
        'name': 'Pass the Hash',
        'tactic': 'Lateral Movement',
        'indicators': ['pass the hash', 'pth', 'ntlm', 'sekurlsa::pth', 'overpass'],
        'event_ids': ['4624', '4648', '4672'],
    },
    'T1550.003': {
        'name': 'Pass the Ticket',
        'tactic': 'Lateral Movement',
        'indicators': ['pass the ticket', 'ptt', 'golden ticket', 'silver ticket', 'kirbi'],
        'event_ids': ['4768', '4769', '4770'],
    },
    
    # DEFENSE EVASION
    'T1070.001': {
        'name': 'Log Clearing',
        'tactic': 'Defense Evasion',
        'indicators': ['wevtutil cl', 'clear-eventlog', 'remove-eventlog'],
        'event_ids': ['1102', '104'],
    },
    'T1562.001': {
        'name': 'Disable Security Tools',
        'tactic': 'Defense Evasion',
        'indicators': ['set-mppreference', 'disablerealtimemonitoring', 'tamper', 
                       'sc stop', 'net stop', 'defender', 'antivirus'],
        'event_ids': ['4688', '1', '5001'],
    },
    
    # EXFILTRATION
    'T1048': {
        'name': 'Exfiltration',
        'tactic': 'Exfiltration',
        'indicators': ['curl', 'wget', 'invoke-webrequest', 'ftp', 'rclone', 
                       'mega', 'dropbox', 'transfer.sh'],
        'event_ids': ['4688', '1', '3'],
    },
}


# =============================================================================
# ATTACK CHAIN DEFINITIONS - Common attack sequences
# =============================================================================

ATTACK_CHAINS = {
    'credential_theft': {
        'name': 'Credential Theft Campaign',
        'stages': ['Execution', 'Credential Access', 'Lateral Movement'],
        'techniques': ['T1059.001', 'T1003.001', 'T1110', 'T1550.002', 'T1021.002'],
    },
    'ransomware': {
        'name': 'Ransomware Attack',
        'stages': ['Execution', 'Defense Evasion', 'Lateral Movement', 'Impact'],
        'techniques': ['T1059.001', 'T1218', 'T1562.001', 'T1021.002', 'T1486'],
    },
    'apt_intrusion': {
        'name': 'APT-Style Intrusion',
        'stages': ['Execution', 'Persistence', 'Credential Access', 'Lateral Movement', 'Exfiltration'],
        'techniques': ['T1059.001', 'T1053.005', 'T1543.003', 'T1003.001', 'T1021.002', 'T1048'],
    },
}


# =============================================================================
# MULTI-QUERY EXPANSION - Search same concept multiple ways
# =============================================================================

MULTI_QUERY_TEMPLATES = {
    'lateral movement': [
        "remote logon type 3 type 10 network authentication 4624",
        "psexec wmic winrm remote execution admin$ c$",
        "rdp mstsc 3389 remote desktop connection",
    ],
    'credential': [
        "lsass mimikatz sekurlsa credential dump procdump",
        "sam ntds.dit registry hive export",
        "kerberoast tgs ticket service principal 4769",
    ],
    'malware': [
        "powershell encodedcommand bypass hidden iex",
        "certutil bitsadmin urlcache decode download",
        "regsvr32 rundll32 mshta scrobj javascript",
    ],
    'persistence': [
        "schtasks scheduled task create 4698 4699",
        "service install sc create 7045 4697",
        "registry run key autorun startup",
    ],
    'pass the hash': [
        "4624 logon type 3 ntlm network",
        "4648 explicit credentials runas",
        "4672 special privileges admin logon",
    ],
    'password spray': [
        "4625 failed logon multiple accounts",
        "4771 kerberos pre-authentication failure",
        "authentication failure same source different users",
    ],
}


# =============================================================================
# STEP-BACK PROMPTS - Abstract questions for broader context
# =============================================================================

STEP_BACK_PROMPTS = {
    r'was there .*(malware|virus|infection)': 
        "What suspicious process executions with unusual command lines occurred?",
    r'did .*(attacker|adversary).*(lateral|move|spread)':
        "What remote authentication and share access events occurred?",
    r'any .*(persist|backdoor)':
        "What scheduled tasks, services, or registry modifications were made?",
    r'credential.*(theft|dump|steal|compromise)':
        "What processes accessed LSASS or sensitive registry hives?",
    r'(pass the hash|pth|ntlm)':
        "What network logons (type 3) with special privileges (4672) occurred?",
    r'(password spray|brute force)':
        "What patterns of failed authentication attempts exist?",
    r'(exfil|data theft)':
        "What archive creation and network transfer activity occurred?",
    r'account.*(compromise|takeover)':
        "What authentication anomalies and privilege changes occurred?",
}


def expand_query_for_dfir(question: str) -> List[str]:
    """
    Expand a natural language question into DFIR-relevant search terms.
    
    Example:
        "Do you see signs of malware?" 
        → ['powershell', 'encodedcommand', 'certutil', 'base64', ...]
    """
    expanded_terms = []
    question_lower = question.lower()
    
    # Check which categories match the question
    matched_categories = set()
    for pattern, category in QUESTION_PATTERNS:
        if re.search(pattern, question_lower):
            matched_categories.add(category)
    
    # Add expansion terms
    for category in matched_categories:
        if category in DFIR_QUERY_EXPANSION:
            expanded_terms.extend(DFIR_QUERY_EXPANSION[category])
    
    # Deduplicate
    seen = set()
    unique_terms = []
    for term in expanded_terms:
        if term.lower() not in seen:
            seen.add(term.lower())
            unique_terms.append(term)
    
    if matched_categories:
        logger.info(f"[AI_SEARCH] Query expansion matched categories: {matched_categories}")
        logger.info(f"[AI_SEARCH] Expanded to {len(unique_terms)} DFIR terms")
    
    return unique_terms[:30]


def expand_to_multi_query(question: str) -> List[str]:
    """
    Generate multiple query variations for the same question.
    Based on RAG Survey paper (arXiv:2312.10997v5) multi-query technique.
    """
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
    
    return unique[:5]  # Limit to 5 variations


def get_step_back_question(question: str) -> Optional[str]:
    """
    Generate a higher-level question to retrieve broader context.
    Based on RAG Survey paper step-back prompting technique.
    """
    question_lower = question.lower()
    
    for pattern, step_back in STEP_BACK_PROMPTS.items():
        if re.search(pattern, question_lower):
            logger.info(f"[AI_SEARCH] Step-back question: {step_back}")
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
        
        # Get command line if available
        event_data = source.get('EventData', {})
        command_line = ''
        if isinstance(event_data, dict):
            command_line = (event_data.get('CommandLine', '') or 
                           event_data.get('command_line', '')).lower()
        
        for technique_id, pattern in MITRE_ATTACK_PATTERNS.items():
            # Check event IDs
            if event_id in pattern.get('event_ids', []):
                # Check indicators
                indicators = pattern.get('indicators', [])
                matching = [ind for ind in indicators 
                           if ind.lower() in search_blob or ind.lower() in command_line]
                
                if matching:
                    technique_matches[technique_id].append({
                        'event': event,
                        'matching_indicators': matching,
                        'technique_name': pattern['name'],
                        'tactic': pattern['tactic'],
                    })
    
    return dict(technique_matches)


def generate_attack_analysis(events: List[Dict]) -> str:
    """
    Generate MITRE ATT&CK analysis summary for LLM context.
    """
    technique_matches = identify_attack_techniques(events)
    
    if not technique_matches:
        return ""
    
    lines = ["## DETECTED ATTACK TECHNIQUES (MITRE ATT&CK)"]
    
    # Group by tactic
    by_tactic = defaultdict(list)
    for tid, matches in technique_matches.items():
        tactic = MITRE_ATTACK_PATTERNS[tid]['tactic']
        by_tactic[tactic].append((tid, matches))
    
    # Order tactics by kill chain
    tactic_order = ['Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion',
                    'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 
                    'Command and Control', 'Exfiltration']
    
    for tactic in tactic_order:
        if tactic in by_tactic:
            lines.append(f"\n**{tactic}:**")
            for tid, matches in by_tactic[tactic]:
                name = MITRE_ATTACK_PATTERNS[tid]['name']
                count = len(matches)
                indicators = set()
                for m in matches[:3]:
                    indicators.update(m['matching_indicators'][:2])
                lines.append(f"- {name} ({tid}): {count} events - indicators: {', '.join(list(indicators)[:4])}")
    
    return '\n'.join(lines)


# =============================================================================
# EMBEDDING MODEL
# =============================================================================

def _load_embedding_model():
    """Lazy-load the sentence-transformers embedding model"""
    global _embedding_model, _embedding_model_load_attempted
    
    if _embedding_model_load_attempted:
        return _embedding_model
    
    _embedding_model_load_attempted = True
    
    try:
        from sentence_transformers import SentenceTransformer
        
        logger.info(f"[AI_SEARCH] Loading embedding model: {EMBEDDING_MODEL_NAME}")
        _embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME, device='cpu')
        logger.info(f"[AI_SEARCH] Embedding model loaded successfully (CPU mode)")
        return _embedding_model
        
    except ImportError:
        logger.error("[AI_SEARCH] sentence-transformers not installed")
        return None
    except Exception as e:
        logger.error(f"[AI_SEARCH] Failed to load embedding model: {e}")
        return None


def check_embedding_model_available() -> Dict[str, Any]:
    """Check if the embedding model can be loaded"""
    try:
        import sentence_transformers
        model = _load_embedding_model()
        
        if model is not None:
            return {
                'available': True,
                'model': EMBEDDING_MODEL_NAME,
                'type': 'sentence-transformers',
                'device': 'cpu',
                'error': None
            }
        else:
            return {
                'available': False,
                'model': EMBEDDING_MODEL_NAME,
                'type': 'sentence-transformers',
                'device': 'cpu',
                'error': "Failed to load embedding model"
            }
            
    except ImportError:
        return {
            'available': False,
            'model': EMBEDDING_MODEL_NAME,
            'type': 'sentence-transformers',
            'device': 'cpu',
            'error': "sentence-transformers not installed"
        }
    except Exception as e:
        return {
            'available': False,
            'model': EMBEDDING_MODEL_NAME,
            'type': 'sentence-transformers',
            'device': 'cpu',
            'error': str(e)
        }


def get_embedding(text: str) -> Optional[np.ndarray]:
    """Generate embedding vector for text"""
    model = _load_embedding_model()
    if model is None:
        return None
    
    try:
        text = text[:2000] if len(text) > 2000 else text
        embedding = model.encode(text, convert_to_numpy=True, show_progress_bar=False)
        return embedding
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Error generating embedding: {e}")
        return None


def get_embeddings_batch(texts: List[str]) -> Optional[np.ndarray]:
    """Generate embeddings for multiple texts efficiently"""
    model = _load_embedding_model()
    if model is None:
        return None
    
    try:
        texts = [t[:2000] if len(t) > 2000 else t for t in texts]
        embeddings = model.encode(
            texts, 
            convert_to_numpy=True, 
            show_progress_bar=False,
            batch_size=32
        )
        return embeddings
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Error generating batch embeddings: {e}")
        return None


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Calculate cosine similarity between two vectors"""
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


def cosine_similarity_batch(query_embedding: np.ndarray, embeddings: np.ndarray) -> np.ndarray:
    """Calculate cosine similarity between query and multiple embeddings"""
    query_norm = query_embedding / np.linalg.norm(query_embedding)
    embeddings_norm = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)
    similarities = np.dot(embeddings_norm, query_norm)
    return similarities


# =============================================================================
# EVENT SUMMARY - Rich context for LLM
# =============================================================================

def create_event_summary(event: Dict[str, Any]) -> str:
    """
    Create DFIR-aware event summary with attack context.
    
    Key improvements:
    - Shows SIGMA rule NAME (not just "detected")
    - Shows event_title (human readable)
    - Structured key fields (process chain, command line)
    - Truncated intelligently
    """
    source = event.get('_source', event)
    parts = []
    
    # === HEADER ===
    timestamp = source.get('normalized_timestamp') or source.get('@timestamp', 'Unknown')
    computer = source.get('normalized_computer') or source.get('Computer', 'Unknown')
    event_id = source.get('normalized_event_id') or source.get('EventID', '?')
    event_title = source.get('event_title', '')
    
    header = f"**{timestamp}** | {computer} | Event {event_id}"
    if event_title:
        header += f" ({event_title})"
    parts.append(header)
    
    # === DETECTION FLAGS (critical for analyst) ===
    if source.get('is_tagged'):
        parts.append("⭐ **ANALYST TAGGED**")
    
    if source.get('has_sigma'):
        sigma_level = source.get('sigma_level', 'unknown').upper()
        sigma_rules = source.get('sigma_rules', [])
        if sigma_rules and isinstance(sigma_rules, list):
            rule_names = []
            for r in sigma_rules[:3]:
                if isinstance(r, dict):
                    rule_names.append(r.get('title') or r.get('name', 'Unknown rule'))
                elif isinstance(r, str):
                    rule_names.append(r)
            if rule_names:
                parts.append(f"⚠️ **SIGMA {sigma_level}**: {', '.join(rule_names)}")
            else:
                parts.append(f"⚠️ **SIGMA {sigma_level}**")
        else:
            parts.append(f"⚠️ **SIGMA {sigma_level}**")
    
    if source.get('has_ioc'):
        ioc_count = source.get('ioc_count', 1)
        ioc_matches = source.get('ioc_matches', [])
        if ioc_matches and isinstance(ioc_matches, list):
            match_vals = [str(m.get('value', ''))[:30] for m in ioc_matches[:2] if isinstance(m, dict)]
            if match_vals:
                parts.append(f"🎯 **IOC**: {', '.join(match_vals)}")
            else:
                parts.append(f"🎯 **IOC MATCH** ({ioc_count})")
        else:
            parts.append(f"🎯 **IOC MATCH** ({ioc_count})")
    
    # === KEY FORENSIC FIELDS ===
    event_data = source.get('EventData', {})
    if not event_data:
        event_data = source.get('Event', {}).get('EventData', {})
    if isinstance(event_data, str):
        event_data = {}
    
    if isinstance(event_data, dict):
        # User
        user = (event_data.get('TargetUserName') or 
                event_data.get('SubjectUserName') or 
                event_data.get('User'))
        if user and user not in ['-', '']:
            parts.append(f"User: {user}")
        
        # Process chain (CRITICAL for malware detection)
        process = (event_data.get('NewProcessName') or 
                   event_data.get('Image') or 
                   event_data.get('ProcessName'))
        parent = (event_data.get('ParentProcessName') or 
                  event_data.get('ParentImage'))
        if process:
            if parent:
                # Show the spawn chain
                parent_short = parent.split('\\')[-1] if '\\' in parent else parent
                process_short = process.split('\\')[-1] if '\\' in process else process
                parts.append(f"Process: {parent_short} → {process_short}")
            else:
                parts.append(f"Process: {process}")
        
        # Command line (THE KEY for detecting malware)
        cmdline = event_data.get('CommandLine') or event_data.get('command_line')
        if cmdline:
            parts.append(f"CommandLine: {cmdline[:600]}")
        
        # Network
        src_ip = event_data.get('IpAddress') or event_data.get('SourceNetworkAddress')
        if src_ip and src_ip not in ['-', '::1', '127.0.0.1', '', 'LOCAL']:
            parts.append(f"Source IP: {src_ip}")
        
        # Logon type
        logon_type = event_data.get('LogonType')
        if logon_type:
            logon_map = {
                '2': 'Interactive', '3': 'Network', '4': 'Batch',
                '5': 'Service', '7': 'Unlock', '10': 'RDP', '11': 'Cached'
            }
            lt_desc = logon_map.get(str(logon_type), '')
            parts.append(f"LogonType: {logon_type} ({lt_desc})" if lt_desc else f"LogonType: {logon_type}")
        
        # Target file/object
        target = (event_data.get('TargetFilename') or 
                  event_data.get('ObjectName') or 
                  event_data.get('ShareName'))
        if target:
            parts.append(f"Target: {target[:200]}")
        
        # Service/Task
        service = event_data.get('ServiceName')
        if service:
            parts.append(f"Service: {service}")
        task = event_data.get('TaskName')
        if task:
            parts.append(f"Task: {task}")
    
    # === FALLBACK to search_blob if no structured data ===
    if len(parts) <= 2:
        blob = source.get('search_blob', '')
        if blob:
            parts.append(f"Data: {blob[:1000]}")
    
    summary = '\n'.join(parts)
    
    # Truncate to fit context budget
    if len(summary) > 2500:
        summary = summary[:2500] + "..."
    
    return summary


# =============================================================================
# EXCLUSION EXTRACTION - Parse "excluding X and Y" from questions
# =============================================================================

def extract_keywords_with_exclusions(question: str) -> Tuple[List[str], List[str]]:
    """
    Extract keywords AND exclusion terms from question.
    
    Supports patterns like:
    - "malware excluding veeam and sentinelone"
    - "suspicious processes except defender"
    - "powershell activity but not from system32"
    - "lateral movement ignore service accounts"
    - "logon events without SYSTEM"
    - "skip backup software"
    - "filter out known good"
    
    Returns:
        (include_terms, exclude_terms)
    """
    question_lower = question.lower()
    exclude_terms = []
    
    # Patterns that indicate exclusion (order matters - more specific first)
    exclusion_patterns = [
        # "excluding X and Y and Z"
        r'exclud(?:e|ing)\s+(.+?)(?:\.|$)',
        # "except for X, Y, Z"
        r'except(?:\s+for)?\s+(.+?)(?:\.|$)',
        # "but not X or Y"
        r'but\s+not\s+(.+?)(?:\.|$)',
        # "ignoring X and Y"
        r'ignor(?:e|ing)\s+(.+?)(?:\.|$)',
        # "without X"
        r'without\s+(.+?)(?:\.|$)',
        # "not from X"
        r'not\s+(?:from|including|related\s+to|involving)\s+(.+?)(?:\.|$)',
        # "skip X"
        r'skip(?:ping)?\s+(.+?)(?:\.|$)',
        # "filter out X"
        r'filter(?:ing)?\s+out\s+(.+?)(?:\.|$)',
        # "remove X"
        r'remov(?:e|ing)\s+(.+?)(?:\.|$)',
        # "hide X"
        r'hid(?:e|ing)\s+(.+?)(?:\.|$)',
        # "no X"
        r'\bno\s+(.+?)(?:\s+events?|\s+activity|\s+logs?|$)',
    ]
    
    # Find all exclusion terms
    for pattern in exclusion_patterns:
        matches = re.findall(pattern, question_lower, re.IGNORECASE)
        for match in matches:
            # Clean up the match
            match = match.strip()
            # Remove trailing punctuation
            match = re.sub(r'[.,;:!?]+$', '', match)
            
            # Split on "and", "or", comma for multiple exclusions
            terms = re.split(r'\s+and\s+|\s+or\s+|\s*,\s*', match)
            for term in terms:
                term = term.strip()
                # Clean up common prefixes
                term = re.sub(r'^(?:any|all|the)\s+', '', term)
                if term and len(term) > 1 and term not in exclude_terms:
                    exclude_terms.append(term)
    
    # Build cleaned question (remove exclusion phrases)
    cleaned_question = question_lower
    for pattern in exclusion_patterns:
        cleaned_question = re.sub(pattern, ' ', cleaned_question, flags=re.IGNORECASE)
    
    # Also remove standalone exclusion keywords
    exclusion_keywords = ['excluding', 'except', 'ignore', 'ignoring', 'without', 
                          'skip', 'skipping', 'filter out', 'filtering out',
                          'but not', 'not from', 'remove', 'removing', 'hide', 'hiding']
    for kw in exclusion_keywords:
        cleaned_question = cleaned_question.replace(kw, ' ')
    
    # Extract include terms from cleaned question
    include_terms = extract_keywords_from_question(cleaned_question)
    
    # Remove any exclude terms that accidentally got into include terms
    exclude_lower = {e.lower() for e in exclude_terms}
    include_terms = [t for t in include_terms if t.lower() not in exclude_lower]
    
    # Also expand exclude terms to catch variations
    expanded_excludes = []
    for term in exclude_terms:
        expanded_excludes.append(term)
        # Add common variations
        if term.endswith('one'):  # sentinelone -> sentinel
            expanded_excludes.append(term[:-3])
        if not term.endswith('.exe') and ' ' not in term:
            expanded_excludes.append(f"{term}.exe")  # veeam -> veeam.exe
    
    exclude_terms = list(set(expanded_excludes))
    
    if exclude_terms:
        logger.info(f"[AI_SEARCH] Include terms: {include_terms}")
        logger.info(f"[AI_SEARCH] Exclude terms: {exclude_terms}")
    
    return include_terms, exclude_terms


# =============================================================================
# KEYWORD EXTRACTION
# =============================================================================

def extract_keywords_from_question(question: str) -> List[str]:
    """Extract search keywords from natural language question (cleaned of exclusions)"""
    
    preserve_terms = {
        'lateral movement', 'brute force', 'pass the hash', 'pass the ticket',
        'golden ticket', 'silver ticket', 'command line', 'scheduled task', 
        'privilege escalation', 'defense evasion', 'initial access',
        '4624', '4625', '4648', '4672', '4688', '4697', '4698', '4699',
        '5140', '5145', '1102', '7045', '7036',
    }
    
    stop_words = {
        'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
        'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
        'should', 'may', 'might', 'must', 'can', 'to', 'of', 'in', 'for',
        'on', 'with', 'at', 'by', 'from', 'as', 'into', 'through', 'during',
        'before', 'after', 'above', 'below', 'between', 'under', 'again',
        'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how',
        'all', 'each', 'few', 'more', 'most', 'other', 'some', 'such',
        'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too',
        'very', 'just', 'and', 'but', 'if', 'or', 'because', 'until',
        'while', 'what', 'which', 'who', 'whom', 'this', 'that', 'these',
        'those', 'am', 'show', 'me', 'find', 'get', 'see', 'look', 'tell',
        'give', 'any', 'events', 'event', 'logs', 'log', 'please', 'i',
        'you', 'my', 'your', 'we', 'our', 'they', 'their', 'it', 'its',
        'summarize', 'summary', 'describe', 'explain', 'activity',
        'involved', 'happened', 'occurred', 'about', 'signs', 'evidence',
        'did', 'anything', 'something', 'everything',
    }
    
    question_lower = question.lower()
    keywords = []
    
    # Preserve multi-word DFIR terms
    for term in preserve_terms:
        if term in question_lower:
            keywords.append(term)
    
    # Extract quoted strings
    quoted = re.findall(r'"([^"]+)"', question)
    keywords.extend([q.lower() for q in quoted])
    
    # Extract usernames (e.g., rachel.b, admin.user)
    usernames = re.findall(r'\b([A-Za-z][A-Za-z0-9]*\.[A-Za-z]+)\b', question)
    for u in usernames:
        keywords.append(u.lower())
    
    # Extract individual words
    words = re.findall(r'[A-Za-z][A-Za-z0-9]*', question)
    for word in words:
        w = word.lower()
        if w not in stop_words and len(w) >= 3 and w not in keywords:
            keywords.append(w)
    
    # Deduplicate
    seen = set()
    unique = []
    for k in keywords:
        if k not in seen:
            seen.add(k)
            unique.append(k)
    
    return unique[:15]


# =============================================================================
# MAIN SEARCH FUNCTION - V5 with Intelligent Sampling
# =============================================================================

def semantic_search_events(
    opensearch_client,
    case_id: int,
    question: str,
    max_results: int = 25,
    include_sigma: bool = True,
    include_ioc: bool = True,
    boost_tagged: bool = True
) -> Tuple[List[Dict], str, Dict]:
    """
    V5 Enhanced semantic search with intelligent sampling, exclusions, and MITRE ATT&CK.
    
    Now returns (events, explanation, metadata) where metadata contains:
    - sampling_stats: Tier allocation breakdown
    - detected_techniques: MITRE ATT&CK techniques found
    - kill_chain: Current kill chain phase
    - detected_attack_types: Categories from question patterns
    - target_user: Extracted username for focused queries
    - query_mode: 'big_picture', 'focused', or 'pattern'
    - patterns_detected: Aggregation-detected patterns
    - case_overview: Case-level statistics
    """
    index_name = f"case_{case_id}"
    
    # Initialize metadata
    metadata = {
        'sampling_stats': {},
        'detected_techniques': {},
        'kill_chain': None,
        'detected_attack_types': [],
        'target_user': None,
        'query_mode': 'big_picture',
        'patterns_detected': [],
        'case_overview': {},
        'exclusions_applied': False,
    }
    
    # Step 1: Extract keywords WITH exclusions
    include_terms, exclude_terms = extract_keywords_with_exclusions(question)
    dfir_terms = expand_query_for_dfir(question)
    
    # Track exclusions in metadata
    if exclude_terms:
        metadata['exclusions_applied'] = True
        metadata['exclusions'] = exclude_terms
    
    # Step 2: Determine query mode and extract target user
    query_mode = determine_query_mode(question, include_terms)
    target_user = extract_target_user(question)
    
    if target_user:
        query_mode = 'focused'
        metadata['target_user'] = target_user
        logger.info(f"[AI_SEARCH] User-focused query for: {target_user}")
    
    metadata['query_mode'] = query_mode
    logger.info(f"[AI_SEARCH] Query mode: {query_mode}")
    
    # Step 3: Get detected attack types from question patterns
    question_lower = question.lower()
    for pattern, category in QUESTION_PATTERNS:
        if re.search(pattern, question_lower):
            metadata['detected_attack_types'].append(category)
    
    # Step 4: Generate case overview (for context)
    try:
        metadata['case_overview'] = generate_case_overview(opensearch_client, case_id)
    except Exception as e:
        logger.warning(f"[AI_SEARCH] Failed to generate case overview: {e}")
        metadata['case_overview'] = {'total_events': 0}
    
    # Multi-query expansion (RAG Survey technique)
    multi_queries = expand_to_multi_query(question)
    if len(multi_queries) > 1:
        logger.info(f"[AI_SEARCH] Multi-query expansion: {len(multi_queries)} variations")
        # Extract keywords from additional queries
        for mq in multi_queries[1:]:
            mq_keywords = extract_keywords_from_question(mq)
            dfir_terms.extend(mq_keywords)
    
    # Step-back prompting for broader context
    step_back = get_step_back_question(question)
    if step_back:
        step_back_keywords = extract_keywords_from_question(step_back)
        dfir_terms.extend(step_back_keywords)
    
    # Combine include terms (user keywords + DFIR expansion + multi-query)
    all_include = include_terms + [t for t in dfir_terms if t.lower() not in {k.lower() for k in include_terms}]
    
    # Deduplicate
    seen = set()
    unique_include = []
    for t in all_include:
        if t.lower() not in seen:
            seen.add(t.lower())
            unique_include.append(t)
    all_include = unique_include
    
    if not all_include:
        logger.warning("[AI_SEARCH] No search terms extracted")
        return [], "Could not extract search terms from your question. Try being more specific.", metadata
    
    logger.info(f"[AI_SEARCH] Search terms: {all_include[:15]}...")
    if exclude_terms:
        logger.info(f"[AI_SEARCH] Excluding: {exclude_terms}")
    
    # Step 5: Build exclusion clauses for must_not
    search_fields = ["search_blob^1.5", "event_title^3", "command_line^2", "process_name^1.5"]
    must_not_clauses = []
    for term in exclude_terms:
        must_not_clauses.append({
            "multi_match": {
                "query": term,
                "fields": search_fields,
                "type": "phrase" if ' ' in term else "best_fields"
            }
        })
    
    # Step 6: Use IntelligentSampler for tiered event retrieval
    try:
        sampler = IntelligentSampler(opensearch_client, case_id)
        candidates, sampling_stats = sampler.sample_events(
            question=question,
            keywords=include_terms,
            dfir_terms=dfir_terms,
            exclusions=must_not_clauses,
            mode=query_mode
        )
        metadata['sampling_stats'] = sampling_stats
        metadata['patterns_detected'] = sampling_stats.get('patterns_detected', [])
        
        total_hits = sampling_stats.get('total_events_in_case', len(candidates))
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] IntelligentSampler failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        
        # Fallback to simple search
        try:
            fallback_query = {
                "bool": {
                    "should": [{"query_string": {"query": " OR ".join(all_include[:10]), "lenient": True}}],
                    "minimum_should_match": 1
                }
            }
            if must_not_clauses:
                fallback_query["bool"]["must_not"] = must_not_clauses
                
            response = opensearch_client.search(
                index=index_name,
                body={
                    "query": fallback_query,
                    "size": max_results * 2,
                    "_source": True
                }
            )
            candidates = [
                {'_id': h['_id'], '_index': h['_index'], '_score': h.get('_score', 0), '_source': h['_source']}
                for h in response['hits']['hits']
            ]
            total_hits = len(candidates)
        except Exception as e2:
            logger.error(f"[AI_SEARCH] Fallback also failed: {e2}")
            return [], f"Search error: {str(e)}", metadata
    
    # Step 7: For focused queries, add user timeline events
    if target_user:
        try:
            user_events = get_user_timeline(opensearch_client, case_id, target_user, limit=30)
            existing_ids = {e['_id'] for e in candidates}
            for ue in user_events:
                if ue['_id'] not in existing_ids:
                    candidates.append(ue)
            
            # Analyze user compromise
            user_analysis = analyze_user_compromise(candidates, target_user)
            metadata['user_analysis'] = user_analysis
            
        except Exception as e:
            logger.warning(f"[AI_SEARCH] User timeline failed: {e}")
    
    # Step 8: Fetch tagged events from database (they may not match keywords)
    event_ids_seen = {c['_id'] for c in candidates}
    if boost_tagged:
        try:
            from models import TimelineTag
            from sqlalchemy import and_
            tagged_records = TimelineTag.query.filter(
                and_(TimelineTag.case_id == case_id, TimelineTag.index_name == index_name)
            ).limit(15).all()
            
            tagged_ids = [t.event_id for t in tagged_records]
            new_tagged_ids = [tid for tid in tagged_ids if tid not in event_ids_seen]
            
            if new_tagged_ids:
                tagged_response = opensearch_client.mget(index=index_name, body={"ids": new_tagged_ids})
                for doc in tagged_response.get('docs', []):
                    if doc.get('found') and doc['_id'] not in event_ids_seen:
                        doc_source = doc.get('_source', {})
                        search_blob = doc_source.get('search_blob', '').lower()
                        excluded = any(ex.lower() in search_blob for ex in exclude_terms)
                        
                        if not excluded:
                            candidates.insert(0, {
                                '_id': doc['_id'],
                                '_index': doc['_index'],
                                '_score': 100.0,
                                '_source': doc_source
                            })
                            event_ids_seen.add(doc['_id'])
                logger.info(f"[AI_SEARCH] Added tagged events from database")
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Failed to fetch tagged events: {e}")
    
    if not candidates:
        return [], f"No events found matching your query{' (after exclusions)' if exclude_terms else ''}.", metadata
    
    # Step 9: Semantic re-ranking
    embedding_available = _load_embedding_model() is not None
    
    if embedding_available and len(candidates) > 1:
        try:
            question_embedding = get_embedding(question)
            if question_embedding is not None:
                summaries = [create_event_summary(c) for c in candidates]
                event_embeddings = get_embeddings_batch(summaries)
                
                if event_embeddings is not None:
                    similarities = cosine_similarity_batch(question_embedding, event_embeddings)
                    
                    os_scores = np.array([c.get('_score', 0) for c in candidates])
                    os_scores_norm = os_scores / (os_scores.max() + 0.001)
                    
                    base_scores = 0.5 * os_scores_norm + 0.5 * similarities
                    
                    combined_scores = np.zeros(len(candidates))
                    for i, c in enumerate(candidates):
                        src = c.get('_source', {})
                        boost = 1.0
                        
                        if src.get('is_tagged'):
                            boost *= 3.0
                        if src.get('has_sigma'):
                            level = src.get('sigma_level', 'medium')
                            boost *= {'critical': 2.5, 'high': 2.0, 'medium': 1.5, 'low': 1.2}.get(level, 1.3)
                        if src.get('has_ioc'):
                            boost *= 1.5
                        
                        combined_scores[i] = base_scores[i] * boost
                    
                    ranked_idx = np.argsort(combined_scores)[::-1]
                    candidates = [candidates[i] for i in ranked_idx]
                    
                    for i, idx in enumerate(ranked_idx):
                        if i < len(candidates):
                            candidates[i]['_semantic_score'] = float(similarities[idx])
                            candidates[i]['_combined_score'] = float(combined_scores[idx])
                    
                    logger.info("[AI_SEARCH] Re-ranked with semantic similarity")
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Semantic re-ranking failed: {e}")
    
    # Step 10: Detect MITRE ATT&CK techniques in results
    detected_techniques = identify_attack_techniques(candidates[:max_results])
    metadata['detected_techniques'] = detected_techniques
    
    # Step 11: Determine kill chain phase
    kill_chain = determine_kill_chain_phase(detected_techniques)
    metadata['kill_chain'] = kill_chain
    
    # Build explanation
    sampling_stats = metadata.get('sampling_stats', {})
    excluded_msg = f", excluded: {', '.join(exclude_terms[:3])}" if exclude_terms else ""
    mode_msg = f", mode: {query_mode}"
    patterns_msg = f", patterns: {metadata['patterns_detected']}" if metadata.get('patterns_detected') else ""
    
    explanation = f"Found {total_hits:,} events, showing {min(len(candidates), max_results)} via intelligent sampling ({query_mode}{excluded_msg}{patterns_msg})"
    
    return candidates[:max_results], explanation, metadata


# =============================================================================
# LLM ANSWER GENERATION - V5 with Enhanced Prompts
# =============================================================================

def generate_ai_answer(
    question: str,
    events: List[Dict],
    case_name: str,
    metadata: Optional[Dict] = None,
    model: str = DEFAULT_LLM_MODEL,
    stream: bool = True
) -> Generator[str, None, None]:
    """
    Generate AI answer with V5 enhanced prompts based on query mode.
    
    Uses three specialized prompts:
    - BIG_PICTURE_PROMPT: For broad overview questions
    - FOCUSED_PROMPT: For user-specific investigations
    - PATTERN_PROMPT: For attack pattern analysis
    """
    if metadata is None:
        metadata = {}
    
    MAX_CONTEXT_TOKENS = 6000
    CHARS_PER_TOKEN = 4
    
    event_context = []
    total_length = 0
    events_included = 0
    
    for i, event in enumerate(events[:20], 1):
        summary = create_event_summary(event)
        event_text = f"### Event {i}\n{summary}"
        
        est_tokens = len(event_text) // CHARS_PER_TOKEN
        if total_length + est_tokens > MAX_CONTEXT_TOKENS:
            break
        
        event_context.append(event_text)
        total_length += est_tokens
        events_included = i
    
    events_text = "\n\n".join(event_context)
    logger.info(f"[AI_SEARCH] LLM context: {events_included} events, ~{total_length} tokens")
    
    # Get query mode and metadata
    query_mode = metadata.get('query_mode', 'big_picture')
    sampling_stats = metadata.get('sampling_stats', {})
    detected_techniques = metadata.get('detected_techniques', {})
    kill_chain = metadata.get('kill_chain')
    detected_attack_types = metadata.get('detected_attack_types', [])
    patterns_detected = metadata.get('patterns_detected', [])
    target_user = metadata.get('target_user')
    case_overview = metadata.get('case_overview', {})
    user_analysis = metadata.get('user_analysis', {})
    
    # Generate context strings
    technique_context = generate_attack_analysis(events)
    kill_chain_context = get_kill_chain_context(kill_chain)
    gap_analysis = get_gap_analysis(detected_attack_types, detected_techniques)
    case_context = get_case_context_for_prompt(case_overview)
    pattern_summary = format_pattern_summary(patterns_detected, events)
    user_analysis_text = format_user_analysis(user_analysis) if user_analysis else ""
    
    # Select appropriate prompt based on query mode
    if query_mode == 'focused' and target_user:
        prompt = FOCUSED_PROMPT.format(
            case_name=case_name,
            target_type='User',
            target_value=target_user,
            question=question,
            user_analysis=user_analysis_text,
            technique_context=technique_context,
            events_text=events_text,
        )
    elif query_mode == 'pattern':
        prompt = PATTERN_PROMPT.format(
            case_name=case_name,
            question=question,
            pattern_summary=pattern_summary,
            technique_context=technique_context,
            kill_chain_context=kill_chain_context,
            events_text=events_text,
        )
    else:
        # Default: big_picture
        prompt = BIG_PICTURE_PROMPT.format(
            case_name=case_name,
            case_overview=case_context,
            question=question,
            total_events=sampling_stats.get('total_events_in_case', len(events)),
            priority_events=sampling_stats.get('priority_events', 0),
            pattern_events=sampling_stats.get('pattern_events', 0),
            medium_events=sampling_stats.get('medium_events', 0),
            random_events=sampling_stats.get('random_events', 0),
            patterns_detected=pattern_summary,
            technique_context=technique_context,
            kill_chain_context=kill_chain_context,
            gap_analysis=gap_analysis,
            event_count=events_included,
            events_text=events_text,
        )

    try:
        response = requests.post(
            OLLAMA_GENERATE_URL,
            json={
                "model": model,
                "prompt": prompt,
                "stream": stream,
                "options": {
                    "temperature": 0.3,
                    "num_ctx": 8192,
                    "num_thread": 8
                }
            },
            stream=stream,
            timeout=300
        )
        response.raise_for_status()
        
        if stream:
            for line in response.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line.decode('utf-8'))
                        if 'response' in chunk:
                            yield chunk['response']
                        if chunk.get('done', False):
                            break
                    except json.JSONDecodeError:
                        continue
        else:
            data = response.json()
            yield data.get('response', '')
            
    except Exception as e:
        logger.error(f"[AI_SEARCH] LLM error: {e}")
        yield f"\n\n❌ Error: {str(e)}"


def ai_question_search(
    opensearch_client,
    case_id: int,
    case_name: str,
    question: str,
    model: str = DEFAULT_LLM_MODEL,
    max_events: int = 25
) -> Generator[Dict, None, None]:
    """
    Main entry point for AI Question feature - V5 with intelligent sampling.
    
    Yields:
        status: Progress messages
        info: Query mode and sampling information
        events: Retrieved events
        chunk: LLM response chunks
        done: Completion signal
    """
    
    yield {"type": "status", "data": "Analyzing question and determining query mode..."}
    
    # Get events with metadata
    events, explanation, metadata = semantic_search_events(
        opensearch_client, case_id, question, max_results=max_events
    )
    
    if not events:
        yield {"type": "error", "data": "No relevant events found. Try rephrasing or using DFIR terms like 'powershell', 'lateral movement', 'persistence'."}
        return
    
    # Send query mode and sampling info
    query_mode = metadata.get('query_mode', 'big_picture')
    sampling_stats = metadata.get('sampling_stats', {})
    patterns_detected = metadata.get('patterns_detected', [])
    
    info_msg = f"Query mode: {query_mode}"
    if patterns_detected:
        info_msg += f" | Patterns detected: {', '.join(patterns_detected)}"
    if metadata.get('target_user'):
        info_msg += f" | Target user: {metadata['target_user']}"
    
    yield {"type": "info", "data": info_msg}
    yield {"type": "status", "data": f"Found {len(events)} relevant events via intelligent sampling. Generating analysis..."}
    yield {"type": "events", "data": events}
    
    # Pass metadata to generate_ai_answer for enhanced prompts
    for chunk in generate_ai_answer(question, events, case_name, metadata, model):
        yield {"type": "chunk", "data": chunk}
    
    yield {"type": "done", "data": "Analysis complete"}


# =============================================================================
# EXPORTS
# =============================================================================

def get_exclusion_suggestions() -> Dict[str, List[str]]:
    """
    Return common exclusion suggestions for UI hints.
    
    Usage in frontend: Show these as clickable suggestions when user types "excluding"
    """
    return COMMON_EXCLUSIONS


def get_attack_techniques() -> Dict[str, Dict]:
    """Return MITRE ATT&CK technique patterns for reference."""
    return MITRE_ATTACK_PATTERNS


def get_attack_chains() -> Dict[str, Dict]:
    """Return attack chain definitions for reference."""
    return ATTACK_CHAINS


__all__ = [
    # Core functions
    'check_embedding_model_available',
    'get_embedding',
    'get_embeddings_batch',
    'semantic_search_events',
    'generate_ai_answer',
    'ai_question_search',
    'create_event_summary',
    
    # V5 Query mode and sampling
    'determine_query_mode',
    'extract_target_user',
    'IntelligentSampler',
    
    # Query expansion
    'expand_query_for_dfir',
    'expand_to_multi_query',
    'get_step_back_question',
    'extract_keywords_with_exclusions',
    
    # Attack pattern detection
    'identify_attack_techniques',
    'generate_attack_analysis',
    'get_attack_techniques',
    'get_attack_chains',
    
    # V5 Kill chain and gap analysis
    'determine_kill_chain_phase',
    'get_kill_chain_context',
    'get_gap_analysis',
    'KILL_CHAIN_PHASES',
    'GAP_ANALYSIS',
    
    # V5 User-focused investigation
    'get_user_timeline',
    'analyze_user_compromise',
    'generate_case_overview',
    
    # Helpers
    'get_exclusion_suggestions',
    
    # Constants
    'EMBEDDING_MODEL_NAME',
    'DEFAULT_LLM_MODEL',
    'DFIR_QUERY_EXPANSION',
    'COMMON_EXCLUSIONS',
    'MITRE_ATTACK_PATTERNS',
    'ATTACK_CHAINS',
    'MULTI_QUERY_TEMPLATES',
    'STEP_BACK_PROMPTS',
    
    # V5 Enhanced prompts
    'BIG_PICTURE_PROMPT',
    'FOCUSED_PROMPT',
    'PATTERN_PROMPT',
]
