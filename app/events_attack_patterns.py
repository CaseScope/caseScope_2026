"""
Attack Patterns Module
======================

Centralized repository of ALL attack patterns used throughout CaseScope.
This module consolidates patterns from AI Triage, AI Search, and other detection systems.

Usage:
    from events_attack_patterns import (
        TIER1_PATTERNS,           # High confidence malicious
        TIER2_PATTERNS,           # Strong indicators
        TIER3_PATTERNS,           # Context dependent
        RECON_COMMANDS,           # Recon/enumeration
        KILL_CHAIN_PHASES,        # Attack progression
        AV_DETECTION_EVENT_IDS,   # AV/EDR event IDs
        get_all_attack_keywords,  # Flat list of all keywords
    )

Author: CaseScope
Version: 1.0.0
"""

import re
from typing import Dict, List, Set, Tuple, Optional


# =============================================================================
# TIER 1 - HIGH CONFIDENCE MALICIOUS (Tag immediately, HIGH priority)
# =============================================================================
# These patterns are almost always malicious - tag without hesitation

TIER1_PATTERNS = {
    'encoded_powershell': [
        '-enc',
        '-encodedcommand',
        '-e ',
        'frombase64string',
        'invoke-expression',
        ' iex ',
        '[convert]::',
        'decompress',
        'gzipstream',
        'memorystream',
        'io.compression',
    ],
    'credential_dumping': [
        'mimikatz',
        'sekurlsa',
        'logonpasswords',
        'lsadump',
        'procdump.*lsass',
        'comsvcs.*minidump',
        'sqldumper',
        'ntds.dit',
        'secretsdump',
        'pypykatz',
        'lazagne',
        'dcsync',
        'kerberoast',
        'asreproast',
    ],
    'attack_tools': [
        'bloodhound',
        'sharphound',
        'adfind',
        'rubeus',
        'crackmapexec',
        'impacket',
        'cobalt',
        'beacon',
        'meterpreter',
        'empire',
        'covenant',
        'sliver',
        'poshc2',
        'havoc',
        'brute ratel',
    ],
    'ransomware_indicators': [
        'vssadmin delete shadows',
        'bcdedit.*recoveryenabled.*no',
        'wbadmin delete catalog',
        'delete shadowcopy',
        '.onion',
        'your files have been encrypted',
        'decrypt.*bitcoin',
        'ransom',
    ],
}


# =============================================================================
# TIER 2 - STRONG INDICATORS (Tag, MEDIUM priority)
# =============================================================================
# These patterns are suspicious and warrant investigation

TIER2_PATTERNS = {
    'recon_commands': [
        'nltest',
        'net group',
        'net user /domain',
        'net localgroup',
        'whoami /all',
        'whoami /priv',
        'systeminfo',
        'ipconfig /all',
        'netstat -ano',
        'quser',
        'query user',
        'arp -a',
        'dsquery',
        'csvde',
        'ldifde',
        'adfind',
        'get-aduser',
        'get-adcomputer',
        'get-adgroup',
        'get-addomain',
        'get-adforest',
        'dclist',
        'domain trust',
    ],
    'lateral_movement_tools': [
        'psexec',
        'paexec',
        'wmic /node',
        'winrm',
        'winrs',
        'enter-pssession',
        'invoke-command',
        'invoke-wmimethod',
        'smbexec',
        'wmiexec',
        'atexec',
        'dcomexec',
        'smbclient',
        'evil-winrm',
    ],
    'persistence_mechanisms': [
        'schtasks /create',
        'sc create',
        'new-service',
        r'currentversion\\run',
        'startup',
        'userinit',
        'wmic startup',
        'at \\\\',
        'new-scheduledtask',
        'register-scheduledjob',
    ],
    'suspicious_downloads': [
        'certutil.*urlcache',
        'certutil.*decode',
        'bitsadmin.*transfer',
        'invoke-webrequest',
        'wget',
        'curl.*-o',
        'iwr.*-outfile',
        'downloadstring',
        'downloadfile',
        'start-bitstransfer',
    ],
    'process_injection': [
        'createremotethread',
        'virtualallocex',
        'writeprocessmemory',
        'ntqueueapcthread',
        'setthreadcontext',
        'reflective',
        'shellcode',
        'inject',
    ],
}


# =============================================================================
# TIER 3 - CONTEXT DEPENDENT (Tag if near other indicators)
# =============================================================================
# These may be legitimate depending on context

TIER3_PATTERNS = {
    'remote_access_if_unexpected': [
        'anydesk',
        'teamviewer',
        'screenconnect',
        'splashtop',
        'logmein',
        'gotoassist',
        'bomgar',
        'connectwise',
        'dameware',
        'vnc',
        'radmin',
    ],
    'archive_with_password': [
        '7z a -p',
        'rar a -hp',
        'zip -e',
        'compress-archive',
        'encrypted.*archive',
    ],
    'log_clearing': [
        'wevtutil cl',
        'clear-eventlog',
        'del.*\\.evtx',
        'remove-eventlog',
    ],
    'defense_evasion': [
        'set-mppreference -disablerealtimemonitoring',
        'sc stop',
        'taskkill.*defender',
        'netsh advfirewall set',
        'disable-windowsoptionalfeature',
        'uninstall-windowsfeature',
        'remove-mppreference',
    ],
    'data_staging': [
        'compress-archive',
        'tar -c',
        'rar a',
        '7z a',
        'makecab',
    ],
    'network_scanning': [
        'nmap',
        'masscan',
        'angry ip',
        'advanced ip scanner',
        'network scanner',
        'port scan',
        'ping sweep',
    ],
}


# =============================================================================
# RECON COMMANDS - Used for discovery hunting
# =============================================================================

RECON_COMMANDS = [
    'nltest',
    'net group',
    'net user',
    'net localgroup',
    'whoami',
    'ipconfig',
    'systeminfo',
    'domain trust',
    'quser',
    'query user',
    'dclist',
    'net view',
    'net share',
    'net session',
    'net accounts',
    'nslookup',
    'ping',
    'tracert',
    'route print',
    'netstat',
    'arp -a',
    'tasklist',
    'wmic process',
    'wmic service',
    'reg query',
    'dir /s',
    'tree /f',
    'get-process',
    'get-service',
    'get-childitem',
    'get-wmiobject',
    'get-ciminstance',
]


# =============================================================================
# AV/EDR DETECTION EVENT IDS
# =============================================================================

AV_DETECTION_EVENT_IDS = [
    # Windows Defender Detection Events
    '1116',  # Malware detection
    '1117',  # Malware protection action taken
    '1118',  # Malware protection action failed
    '1119',  # Critical malware action
    '1006',  # Scan detected malware
    '1007',  # Scan action taken
    '1008',  # Scan action failed
    '1015',  # Behavior detection
    '5001',  # Real-time protection disabled
    '5004',  # Configuration changed
    '5007',  # Platform state changed
    '5010',  # Scanning disabled
    '5012',  # Virus scanning disabled
    
    # Generic AV Events
    '3004',  # Trend Micro detection
    '4',     # Generic AV detection
]

AV_DETECTION_KEYWORDS = [
    'threat',
    'malware',
    'quarantine',
    'blocked',
    'detected',
    'trojan',
    'virus',
    'ransomware',
    'backdoor',
    'exploit',
    'suspicious',
    'malicious',
    'potentially unwanted',
    'pua',
    'pup',
    'hacktool',
]


# =============================================================================
# AUTHENTICATION EVENT IDS
# =============================================================================

AUTH_EVENT_IDS = {
    # Windows Security Events
    '4624': 'Successful Logon',
    '4625': 'Failed Logon',
    '4634': 'Logoff',
    '4647': 'User Initiated Logoff',
    '4648': 'Explicit Credentials Logon (potential PTH)',
    '4672': 'Special Privileges Assigned',
    '4768': 'Kerberos TGT Request',
    '4769': 'Kerberos Service Ticket Request',
    '4770': 'Kerberos Service Ticket Renewed',
    '4771': 'Kerberos Pre-Auth Failed',
    '4776': 'Credential Validation',
    
    # NPS/RADIUS Events
    '6272': 'NPS Granted Access',
    '6273': 'NPS Denied Access',
    '6274': 'NPS Discarded Request',
    '6275': 'NPS Discarded Accounting',
    '6276': 'NPS Quarantined User',
    '6277': 'NPS Access Granted (Challenge)',
    '6278': 'NPS Connection Terminated',
    '6279': 'NPS Account Locked',
    '6280': 'NPS Account Unlocked',
}

# Failed auth event IDs (for brute force/spray detection)
FAILED_AUTH_EVENT_IDS = ['4625', '4771', '6273', '6274', '6276']

# Successful auth event IDs (for lateral movement detection)
SUCCESS_AUTH_EVENT_IDS = ['4624', '4648', '6272']


# =============================================================================
# LOGON TYPES - For Windows 4624 events
# =============================================================================

LOGON_TYPES = {
    '2': 'Interactive (Console)',
    '3': 'Network (SMB/Share)',
    '4': 'Batch',
    '5': 'Service',
    '7': 'Unlock',
    '8': 'NetworkCleartext',
    '9': 'NewCredentials (RunAs /netonly, PTH)',
    '10': 'RemoteInteractive (RDP)',
    '11': 'CachedInteractive',
    '12': 'CachedRemoteInteractive',
    '13': 'CachedUnlock',
}

# Suspicious logon types (potential lateral movement or PTH)
SUSPICIOUS_LOGON_TYPES = ['3', '9', '10']


# =============================================================================
# KILL CHAIN PHASES - MITRE ATT&CK Framework
# =============================================================================

KILL_CHAIN_PHASES = {
    'reconnaissance': {
        'order': 1,
        'name': 'Reconnaissance',
        'description': 'Attacker gathering information about the target',
        'mitre_tactic': 'TA0043',
        'example_techniques': ['T1595', 'T1592', 'T1589'],
        'typical_next': 'initial_access',
        'keywords': ['scan', 'enumerate', 'discover', 'gather', 'fingerprint'],
    },
    'initial_access': {
        'order': 2,
        'name': 'Initial Access',
        'description': 'Attacker gaining first foothold in the environment',
        'mitre_tactic': 'TA0001',
        'example_techniques': ['T1566', 'T1190', 'T1133'],
        'typical_next': 'execution',
        'keywords': ['phish', 'exploit', 'initial', 'entry', 'compromise'],
    },
    'execution': {
        'order': 3,
        'name': 'Execution',
        'description': 'Attacker running malicious code',
        'mitre_tactic': 'TA0002',
        'example_techniques': ['T1059.001', 'T1059.003', 'T1204', 'T1047'],
        'typical_next': 'persistence',
        'keywords': ['execute', 'run', 'launch', 'spawn', 'invoke'],
    },
    'persistence': {
        'order': 4,
        'name': 'Persistence',
        'description': 'Attacker maintaining access across reboots/credential changes',
        'mitre_tactic': 'TA0003',
        'example_techniques': ['T1053.005', 'T1543.003', 'T1547.001'],
        'typical_next': 'privilege_escalation',
        'keywords': ['persist', 'backdoor', 'maintain', 'survive', 'autorun'],
    },
    'privilege_escalation': {
        'order': 5,
        'name': 'Privilege Escalation',
        'description': 'Attacker gaining higher-level permissions',
        'mitre_tactic': 'TA0004',
        'example_techniques': ['T1134', 'T1068', 'T1548'],
        'typical_next': 'defense_evasion',
        'keywords': ['escalate', 'admin', 'system', 'root', 'bypass uac'],
    },
    'defense_evasion': {
        'order': 6,
        'name': 'Defense Evasion',
        'description': 'Attacker avoiding detection',
        'mitre_tactic': 'TA0005',
        'example_techniques': ['T1070.001', 'T1562.001', 'T1027', 'T1055'],
        'typical_next': 'credential_access',
        'keywords': ['evade', 'bypass', 'disable', 'hide', 'obfuscate'],
    },
    'credential_access': {
        'order': 7,
        'name': 'Credential Access',
        'description': 'Attacker stealing credentials',
        'mitre_tactic': 'TA0006',
        'example_techniques': ['T1003.001', 'T1550.002', 'T1558', 'T1110'],
        'typical_next': 'discovery',
        'keywords': ['credential', 'password', 'hash', 'dump', 'steal'],
    },
    'discovery': {
        'order': 8,
        'name': 'Discovery',
        'description': 'Attacker learning about the environment',
        'mitre_tactic': 'TA0007',
        'example_techniques': ['T1087', 'T1082', 'T1018', 'T1083'],
        'typical_next': 'lateral_movement',
        'keywords': ['discover', 'enumerate', 'list', 'query', 'recon'],
    },
    'lateral_movement': {
        'order': 9,
        'name': 'Lateral Movement',
        'description': 'Attacker moving through the network',
        'mitre_tactic': 'TA0008',
        'example_techniques': ['T1021.001', 'T1021.002', 'T1021.006', 'T1570'],
        'typical_next': 'collection',
        'keywords': ['lateral', 'spread', 'pivot', 'move', 'remote'],
    },
    'collection': {
        'order': 10,
        'name': 'Collection',
        'description': 'Attacker gathering data to steal',
        'mitre_tactic': 'TA0009',
        'example_techniques': ['T1560', 'T1039', 'T1005', 'T1114'],
        'typical_next': 'exfiltration',
        'keywords': ['collect', 'gather', 'archive', 'stage', 'compress'],
    },
    'exfiltration': {
        'order': 11,
        'name': 'Exfiltration',
        'description': 'Attacker stealing data from the environment',
        'mitre_tactic': 'TA0010',
        'example_techniques': ['T1041', 'T1567', 'T1048'],
        'typical_next': 'impact',
        'keywords': ['exfil', 'steal', 'upload', 'send', 'transfer'],
    },
    'impact': {
        'order': 12,
        'name': 'Impact',
        'description': 'Attacker achieving objective (ransomware, destruction)',
        'mitre_tactic': 'TA0040',
        'example_techniques': ['T1486', 'T1490', 'T1489'],
        'typical_next': None,
        'keywords': ['encrypt', 'destroy', 'ransom', 'wipe', 'delete'],
    },
}

# Mapping from MITRE tactic names to kill chain phases
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
    'Command and Control': 'collection',  # Map C2 to collection
    'Exfiltration': 'exfiltration',
    'Impact': 'impact',
}


# =============================================================================
# QUESTION CLASSIFICATION PATTERNS - For AI Search
# =============================================================================

QUESTION_PATTERNS = [
    (r'malware|virus|trojan|ransomware|infection|compromis|malicious|suspicious|bad', 'malware'),
    (r'lateral|spread|pivot|move.*between|hop|remote\s+exec', 'lateral_movement'),
    (r'persist|backdoor|maintain.*access|survive.*reboot|autorun|startup', 'persistence'),
    (r'credential|password|hash|ticket|authenticat|logon.*as|steal.*cred|dump|ntlm|brute|spray|failed.*logon|lockout', 'credential_access'),
    (r'exfil|steal.*data|data.*theft|upload|send.*out|leak|extract', 'exfiltration'),
    (r'c2|command.*control|beacon|callback|phone.*home', 'command_control'),
    (r'evad|bypass|disable|hide|obfuscat|tamper|kill.*av|blind', 'defense_evasion'),
    (r'execut|run|launch|spawn|start.*process|command|invoke', 'execution'),
    (r'initial|entry|phish|deliver|land|foothold', 'initial_access'),
    (r'brute\s*force|password\s*spray|spray|failed\s*logon|lockout|4625', 'brute_force'),
    (r'escalat|privilege|admin|root|system|uac', 'privilege_escalation'),
    (r'discover|enum|recon|gather|scan|survey', 'discovery'),
]


# =============================================================================
# DETECTION THRESHOLDS
# =============================================================================

DETECTION_THRESHOLDS = {
    'password_spray': {
        'unique_targets_min': 5,     # 5+ unique users from same IP
        'time_window_hours': 24,
    },
    'brute_force': {
        'attempts_min': 10,          # 10+ failed attempts against single user
        'time_window_hours': 24,
    },
    'lateral_movement': {
        'systems_min': 3,            # 3+ systems accessed by same user
        'time_window_hours': 24,
    },
    'auth_chain_tolerance_seconds': 2,  # Events within 2 sec = same chain
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_all_attack_keywords() -> Set[str]:
    """
    Get a flat set of all attack keywords from all tiers.
    Useful for broad searching.
    """
    keywords = set()
    
    for pattern_dict in [TIER1_PATTERNS, TIER2_PATTERNS, TIER3_PATTERNS]:
        for category, patterns in pattern_dict.items():
            for pattern in patterns:
                # Clean up regex patterns for simple keyword matching
                clean = pattern.lower().replace('.*', ' ').replace('\\\\', '\\')
                keywords.add(clean)
    
    for cmd in RECON_COMMANDS:
        keywords.add(cmd.lower())
    
    for kw in AV_DETECTION_KEYWORDS:
        keywords.add(kw.lower())
    
    return keywords


def get_tier1_keywords() -> Set[str]:
    """Get only Tier 1 (high confidence malicious) keywords."""
    keywords = set()
    for category, patterns in TIER1_PATTERNS.items():
        for pattern in patterns:
            clean = pattern.lower().replace('.*', ' ').replace('\\\\', '\\')
            keywords.add(clean)
    return keywords


def get_tier2_keywords() -> Set[str]:
    """Get only Tier 2 (strong indicator) keywords."""
    keywords = set()
    for category, patterns in TIER2_PATTERNS.items():
        for pattern in patterns:
            clean = pattern.lower().replace('.*', ' ').replace('\\\\', '\\')
            keywords.add(clean)
    return keywords


def classify_question(question: str) -> Optional[str]:
    """
    Classify a question into an attack category.
    Returns category name or None if no match.
    """
    question_lower = question.lower()
    
    for pattern, category in QUESTION_PATTERNS:
        if re.search(pattern, question_lower):
            return category
    
    return None


def get_kill_chain_phase(phase_name: str) -> Optional[Dict]:
    """Get kill chain phase info by name."""
    return KILL_CHAIN_PHASES.get(phase_name.lower().replace(' ', '_'))


def get_phase_by_order(order: int) -> Optional[Dict]:
    """Get kill chain phase by order number (1-12)."""
    for phase_id, phase_info in KILL_CHAIN_PHASES.items():
        if phase_info['order'] == order:
            return {**phase_info, 'id': phase_id}
    return None


def determine_kill_chain_position(detected_phases: List[str]) -> Optional[Dict]:
    """
    Given a list of detected phase names, determine current position in kill chain.
    
    Returns dict with current phase info and next expected phase.
    """
    if not detected_phases:
        return None
    
    # Find the furthest phase
    max_order = 0
    current_phase = None
    
    for phase_name in detected_phases:
        phase_id = phase_name.lower().replace(' ', '_')
        if phase_id in KILL_CHAIN_PHASES:
            order = KILL_CHAIN_PHASES[phase_id]['order']
            if order > max_order:
                max_order = order
                current_phase = phase_id
    
    if not current_phase:
        return None
    
    phase_info = KILL_CHAIN_PHASES[current_phase]
    
    return {
        'current_phase': current_phase,
        'current_phase_name': phase_info['name'],
        'current_order': phase_info['order'],
        'description': phase_info['description'],
        'all_detected': detected_phases,
        'next_phase': phase_info.get('typical_next'),
        'next_phase_name': KILL_CHAIN_PHASES.get(phase_info.get('typical_next'), {}).get('name') if phase_info.get('typical_next') else None,
    }


def is_suspicious_logon_type(logon_type: str) -> bool:
    """Check if a Windows logon type is suspicious."""
    return str(logon_type) in SUSPICIOUS_LOGON_TYPES


def is_failed_auth_event(event_id: str) -> bool:
    """Check if event ID indicates failed authentication."""
    return str(event_id) in FAILED_AUTH_EVENT_IDS


def is_success_auth_event(event_id: str) -> bool:
    """Check if event ID indicates successful authentication."""
    return str(event_id) in SUCCESS_AUTH_EVENT_IDS


def match_pattern_tier(search_blob: str) -> Optional[Tuple[int, str, str]]:
    """
    Check if search_blob matches any pattern tier.
    
    Returns:
        Tuple of (tier_number, category, matched_pattern) or None
    """
    blob_lower = search_blob.lower()
    
    # Check Tier 1 first (highest priority)
    for category, patterns in TIER1_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern.lower(), blob_lower):
                return (1, category, pattern)
    
    # Check Tier 2
    for category, patterns in TIER2_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern.lower(), blob_lower):
                return (2, category, pattern)
    
    # Check Tier 3
    for category, patterns in TIER3_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern.lower(), blob_lower):
                return (3, category, pattern)
    
    return None


def get_patterns_for_category(category: str) -> List[str]:
    """
    Get all patterns for a specific category across all tiers.
    
    Examples: 'credential_dumping', 'recon_commands', 'lateral_movement_tools'
    """
    patterns = []
    
    for tier_dict in [TIER1_PATTERNS, TIER2_PATTERNS, TIER3_PATTERNS]:
        if category in tier_dict:
            patterns.extend(tier_dict[category])
    
    return patterns

