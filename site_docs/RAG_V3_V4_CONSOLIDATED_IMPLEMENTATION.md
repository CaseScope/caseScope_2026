# CaseScope RAG V3+V4 Consolidated Implementation Plan

**Version**: 1.1  
**Date**: November 27, 2025  
**Target Scale**: 3-20 Million Events Per Case  
**Current State**: V5 Implemented (ai_search.py - 3064 lines)  

---

## Implementation Status

| Feature | Status | Version |
|---------|--------|---------|
| V3: Exclusion Support | ✅ Complete | 1.30.0 |
| V4: MITRE ATT&CK Integration | ✅ Complete | 1.31.0 |
| V4: Gap Analysis Engine | ✅ Complete | 1.32.0 |
| V4: Kill Chain Mapping | ✅ Complete | 1.32.0 |
| Intelligent Sampling | ✅ Complete | 1.32.0 |
| Query Mode Detection | ✅ Complete | 1.32.0 |
| User-Focused Investigation | ✅ Complete | 1.32.0 |
| Enhanced LLM Prompts | ✅ Complete | 1.32.0 |
| **NPS/VPN Event Support** | ✅ Complete | **1.32.1** |

### v1.32.1 Update: NPS/VPN Events
Added support for Network Policy Server (NPS) events in brute force detection:
- **6272**: NPS granted VPN/RDP access (successful)
- **6273**: NPS denied VPN/RDP access (failed - brute force indicator)
- **6274-6279**: Other NPS events

The `_detect_password_spray()` aggregation now queries both Event 4625 (Windows) AND 6273 (NPS).

---

## Executive Summary

This document provides a complete implementation plan for upgrading CaseScope's RAG system from V2 to V4, combining:

- **V3**: Exclusion support for noise filtering
- **V4**: MITRE ATT&CK integration, gap analysis, kill chain mapping
- **NEW**: Intelligent sampling strategies for 3-20M event cases
- **NEW**: Big-picture analysis + focused investigation support

**Expected Outcome**: Transform RAG from B+ (6.5/10) to A+ (9.5/10) quality

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [V3: Exclusion Support](#2-v3-exclusion-support)
3. [V4: MITRE ATT&CK Integration](#3-v4-mitre-attck-integration)
4. [V4: Gap Analysis Engine](#4-v4-gap-analysis-engine)
5. [V4: Kill Chain Mapping](#5-v4-kill-chain-mapping)
6. [Intelligent Sampling Strategies](#6-intelligent-sampling-strategies)
7. [User-Specific Investigation](#7-user-specific-investigation)
8. [Big Picture Analysis](#8-big-picture-analysis)
9. [Enhanced LLM Prompts](#9-enhanced-llm-prompts)
10. [Implementation Roadmap](#10-implementation-roadmap)
11. [Complete Code Changes](#11-complete-code-changes)
12. [Testing Plan](#12-testing-plan)

---

## 1. Architecture Overview

### Current V2 Flow (What We Have)
```
Question → Keywords + DFIR Expansion → OpenSearch (200 candidates) → Semantic Re-rank → Top 20 → LLM
```

### Target V4 Flow (What We Need)
```
Question
    │
    ├─→ Extract: Keywords, Exclusions, Username, Attack Type, Time Range
    │
    ├─→ Determine Query Mode:
    │       ├─ BIG PICTURE: Broad sampling across all events
    │       ├─ FOCUSED: User-specific or technique-specific
    │       └─ PATTERN: Aggregation-first for attack patterns
    │
    ├─→ Intelligent Sampling (based on mode):
    │       ├─ Priority Events (tagged, SIGMA critical/high, IOC)
    │       ├─ Stratified by Event Type (max N per type)
    │       ├─ Time-Window Sampling (around flagged events)
    │       ├─ Aggregation Patterns (password spray, lateral movement)
    │       └─ Random Baseline (for completeness)
    │
    ├─→ Apply Exclusions (must_not clauses)
    │
    ├─→ MITRE ATT&CK Enrichment:
    │       ├─ Map detected events to techniques
    │       ├─ Get detection guidance
    │       └─ Suggest next steps
    │
    ├─→ Gap Analysis:
    │       ├─ What was found → What to check next
    │       └─ What wasn't found → Why and where else to look
    │
    ├─→ Kill Chain Positioning:
    │       └─ Current phase → Typical next phase
    │
    └─→ Enhanced LLM Prompt with full context
            │
            └─→ Streaming Response with Attack Intelligence
```

---

## 2. V3: Exclusion Support

### 2.1 Exclusion Pattern Detection

```python
# Patterns that indicate exclusion intent
EXCLUSION_PATTERNS = [
    (r'\bexcluding\s+', 'excluding'),
    (r'\bexcept\s+(?:for\s+)?', 'except'),
    (r'\bbut\s+not\s+', 'but not'),
    (r'\bignore\s+', 'ignore'),
    (r'\bignoring\s+', 'ignoring'),
    (r'\bwithout\s+', 'without'),
    (r'\bskip(?:ping)?\s+', 'skip'),
    (r'\bfilter(?:ing)?\s+out\s+', 'filter out'),
    (r'\bremove\s+', 'remove'),
    (r'\bhide\s+', 'hide'),
    (r'\bnot\s+from\s+', 'not from'),
    (r'\bno\s+', 'no'),  # "no defender events"
    (r'\bnot\s+including\s+', 'not including'),
]
```

### 2.2 Common Exclusion Categories

```python
EXCLUSION_CATEGORIES = {
    # Security Tools (most common exclusion request)
    'security_tools': {
        'keywords': ['sentinelone', 'crowdstrike', 'defender', 'carbonblack', 
                     'symantec', 'mcafee', 'sophos', 'kaspersky', 'eset',
                     'trend micro', 'bitdefender', 'malwarebytes', 'cylance',
                     'falcon', 'cb defense', 'sep', 'edr', 'xdr', 'av'],
        'process_names': ['MsSense.exe', 'SentinelAgent.exe', 'CrowdStrike*',
                          'MsMpEng.exe', 'NisSrv.exe', 'cbdefense.exe',
                          'RepMgr.exe', 'RepUtils.exe', 'CSFalconService.exe'],
        'paths': ['C:\\Program Files\\Windows Defender\\',
                  'C:\\Program Files\\SentinelOne\\',
                  'C:\\Program Files\\CrowdStrike\\'],
    },
    
    # Backup Software
    'backup_software': {
        'keywords': ['veeam', 'acronis', 'commvault', 'veritas', 'backup exec',
                     'arcserve', 'nakivo', 'datto', 'carbonite', 'backblaze',
                     'shadow copies', 'vss'],
        'process_names': ['VeeamAgent.exe', 'VeeamBackup*', 'AcronisAgent.exe',
                          'cvd.exe', 'clBackup.exe'],
    },
    
    # System Accounts (high volume, usually noise)
    'system_accounts': {
        'keywords': ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 
                     'NT AUTHORITY', 'ANONYMOUS LOGON', 'DWM-', 'UMFD-',
                     'DefaultAppPool', 'IIS APPPOOL', 'IUSR', 'DefaultAccount'],
        'account_patterns': [r'^S-1-5-18$', r'^S-1-5-19$', r'^S-1-5-20$'],
    },
    
    # Management Tools (SCCM, Intune, etc.)
    'management_tools': {
        'keywords': ['sccm', 'mecm', 'intune', 'landesk', 'ivanti', 'bigfix',
                     'wsus', 'pdq', 'altiris', 'tanium', 'jamf', 'chef',
                     'puppet', 'ansible', 'saltstack', 'dsc'],
        'process_names': ['CcmExec.exe', 'IntuneManagementExtension.exe',
                          'BigFixAgent.exe', 'TaniumClient.exe'],
    },
    
    # Monitoring/SIEM (avoid recursion)
    'monitoring': {
        'keywords': ['splunk', 'elastic', 'logstash', 'filebeat', 'winlogbeat',
                     'datadog', 'prometheus', 'grafana', 'zabbix', 'nagios',
                     'solarwinds', 'prtg', 'new relic', 'dynatrace'],
        'process_names': ['splunkd.exe', 'filebeat.exe', 'winlogbeat.exe',
                          'metricbeat.exe', 'auditbeat.exe'],
    },
    
    # Windows Noise (common high-volume benign events)
    'windows_noise': {
        'keywords': ['wuauserv', 'windows update', 'bits', 'trustedinstaller',
                     'tiworker', 'msiexec', 'wusa', 'cleanmgr'],
        'event_ids': [4656, 4658, 4660, 4663],  # Object access (very high volume)
        'paths': ['C:\\Windows\\SoftwareDistribution\\', 
                  'C:\\Windows\\WinSxS\\'],
    },
    
    # Scheduled Tasks (often noisy)
    'scheduled_tasks': {
        'keywords': ['scheduled task', 'task scheduler'],
        'task_names': ['GoogleUpdate*', 'Adobe*', 'Microsoft\\Windows\\*'],
    },
}
```

### 2.3 Exclusion Extraction Function

```python
def extract_exclusions_from_question(question: str) -> Tuple[str, List[str], List[str]]:
    """
    Extract exclusion terms from a question.
    
    Args:
        question: Natural language question
        
    Returns:
        Tuple of (clean_question, explicit_exclusions, category_exclusions)
        - clean_question: Question with exclusion clause removed
        - explicit_exclusions: Terms explicitly mentioned for exclusion
        - category_exclusions: Expanded terms from matched categories
        
    Examples:
        "malware excluding veeam and defender" 
            → ("malware", ["veeam", "defender"], ["VeeamAgent.exe", "MsMpEng.exe", ...])
        
        "lateral movement ignore security tools"
            → ("lateral movement", [], [all security_tools expansions])
    """
    question_lower = question.lower()
    
    # Find exclusion marker
    exclusion_start = None
    exclusion_type = None
    
    for pattern, name in EXCLUSION_PATTERNS:
        match = re.search(pattern, question_lower)
        if match:
            if exclusion_start is None or match.start() < exclusion_start:
                exclusion_start = match.start()
                exclusion_type = name
    
    if exclusion_start is None:
        return question, [], []
    
    # Split question
    clean_question = question[:exclusion_start].strip()
    exclusion_clause = question[exclusion_start:].lower()
    
    # Remove the exclusion keyword itself
    for pattern, _ in EXCLUSION_PATTERNS:
        exclusion_clause = re.sub(pattern, '', exclusion_clause)
    
    # Parse exclusion terms (handle "X and Y", "X, Y, Z", "X or Y")
    exclusion_clause = re.sub(r'\s+and\s+', ', ', exclusion_clause)
    exclusion_clause = re.sub(r'\s+or\s+', ', ', exclusion_clause)
    
    explicit_exclusions = []
    category_exclusions = []
    
    terms = [t.strip() for t in exclusion_clause.split(',') if t.strip()]
    
    for term in terms:
        # Clean the term
        term = re.sub(r'[^\w\s\-\.]', '', term).strip()
        if not term:
            continue
            
        # Check if it matches a category name
        matched_category = False
        for category_name, category_data in EXCLUSION_CATEGORIES.items():
            # Match category name (e.g., "security tools" matches security_tools)
            if term.replace(' ', '_') == category_name or term.replace('_', ' ') == category_name.replace('_', ' '):
                # Add all keywords from this category
                category_exclusions.extend(category_data.get('keywords', []))
                category_exclusions.extend(category_data.get('process_names', []))
                matched_category = True
                break
            
            # Check if term is in category keywords
            if term in [k.lower() for k in category_data.get('keywords', [])]:
                category_exclusions.extend(category_data.get('keywords', []))
                category_exclusions.extend(category_data.get('process_names', []))
                matched_category = True
                break
        
        if not matched_category:
            explicit_exclusions.append(term)
    
    # Deduplicate
    explicit_exclusions = list(set(explicit_exclusions))
    category_exclusions = list(set(category_exclusions))
    
    return clean_question, explicit_exclusions, category_exclusions
```

### 2.4 Building Query with Exclusions

```python
def build_must_not_clauses(explicit_exclusions: List[str], 
                           category_exclusions: List[str]) -> List[Dict]:
    """
    Build OpenSearch must_not clauses for exclusions.
    
    Returns list of clauses to add to query["bool"]["must_not"]
    """
    must_not = []
    
    all_exclusions = explicit_exclusions + category_exclusions
    
    for term in all_exclusions:
        # Skip very short terms (likely parsing errors)
        if len(term) < 2:
            continue
            
        # Use wildcard for process names with wildcards
        if '*' in term:
            must_not.append({
                "wildcard": {
                    "search_blob": {
                        "value": f"*{term.lower()}*",
                        "case_insensitive": True
                    }
                }
            })
        else:
            # Multi-match for regular terms
            must_not.append({
                "multi_match": {
                    "query": term,
                    "fields": ["search_blob", "process_name", "command_line", 
                               "file_path", "username", "event_title"],
                    "type": "phrase"
                }
            })
    
    return must_not
```

---

## 3. V4: MITRE ATT&CK Integration

### 3.1 Comprehensive Technique Database

```python
MITRE_TECHNIQUES = {
    # =========================================================================
    # RECONNAISSANCE (TA0043)
    # =========================================================================
    'T1595': {
        'id': 'T1595',
        'name': 'Active Scanning',
        'tactic': 'Reconnaissance',
        'description': 'Adversaries scan victim IP blocks to gather information',
        'indicators': ['nmap', 'masscan', 'zmap', 'nessus', 'openvas'],
        'event_ids': [3],  # Sysmon network connections
        'detection': 'Look for high-volume outbound connections to sequential IPs',
        'next_steps': ['Check target IPs for pattern (sequential?)', 
                       'Verify if scanning tool is authorized',
                       'Look for follow-up exploitation attempts'],
    },
    
    # =========================================================================
    # INITIAL ACCESS (TA0001)
    # =========================================================================
    'T1566.001': {
        'id': 'T1566.001',
        'name': 'Spearphishing Attachment',
        'tactic': 'Initial Access',
        'description': 'Malicious attachments sent via email',
        'indicators': ['outlook.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe',
                       '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pdf', '.zip'],
        'event_ids': [4688, 1],  # Process creation
        'detection': 'Office app spawning script interpreters or making network connections',
        'parent_child_patterns': [
            ('outlook.exe', 'winword.exe'),
            ('winword.exe', 'powershell.exe'),
            ('winword.exe', 'cmd.exe'),
            ('excel.exe', 'powershell.exe'),
        ],
        'next_steps': ['Identify the attachment and sender',
                       'Check for macro execution (4688 with Office parent)',
                       'Look for download activity after Office launch'],
    },
    
    'T1190': {
        'id': 'T1190',
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'description': 'Exploiting vulnerabilities in internet-facing apps',
        'indicators': ['w3wp.exe', 'httpd', 'nginx', 'tomcat', 'weblogic',
                       'exchange', 'sharepoint', 'proxylogon', 'proxyshell'],
        'event_ids': [4688, 1, 17, 18],
        'detection': 'Web server process spawning unusual child processes',
        'parent_child_patterns': [
            ('w3wp.exe', 'cmd.exe'),
            ('w3wp.exe', 'powershell.exe'),
            ('httpd.exe', 'cmd.exe'),
        ],
        'next_steps': ['Identify the vulnerable application',
                       'Check web logs for exploit signatures',
                       'Look for webshell creation'],
    },
    
    # =========================================================================
    # EXECUTION (TA0002)
    # =========================================================================
    'T1059.001': {
        'id': 'T1059.001',
        'name': 'PowerShell',
        'tactic': 'Execution',
        'description': 'Abuse of PowerShell for execution',
        'indicators': ['powershell', 'pwsh', 'powershell_ise', '-enc', '-encodedcommand',
                       '-e ', '-ec ', 'invoke-expression', 'iex', 'invoke-command',
                       'downloadstring', 'downloadfile', 'webclient', 'invoke-webrequest',
                       'bypass', 'noprofile', 'hidden', 'noninteractive', '-w hidden',
                       'frombase64string', 'convertto-securestring', 'reflection.assembly'],
        'event_ids': [4688, 1, 4104, 4103],  # Process + PowerShell logging
        'detection': 'Look for encoded commands, download cradles, or suspicious cmdlets',
        'suspicious_patterns': [
            r'-enc[odedcommand]*\s+[A-Za-z0-9+/=]{50,}',  # Encoded command
            r'invoke-expression.*downloadstring',  # Download cradle
            r'\$env:.*\+.*\$env:',  # Environment variable concatenation
        ],
        'next_steps': ['Decode any encoded commands',
                       'Identify what was downloaded/executed',
                       'Check for persistence mechanisms created',
                       'Look for child processes spawned'],
    },
    
    'T1059.003': {
        'id': 'T1059.003',
        'name': 'Windows Command Shell',
        'tactic': 'Execution',
        'description': 'Use of cmd.exe for execution',
        'indicators': ['cmd.exe', 'cmd /c', 'cmd /k', '/c ', '/k '],
        'event_ids': [4688, 1],
        'detection': 'cmd.exe with suspicious arguments or unusual parent',
        'next_steps': ['Examine full command line',
                       'Check parent process legitimacy',
                       'Trace child processes'],
    },
    
    'T1047': {
        'id': 'T1047',
        'name': 'Windows Management Instrumentation',
        'tactic': 'Execution',
        'description': 'WMI for remote or local execution',
        'indicators': ['wmic', 'wmiprvse', 'scrcons', 'mofcomp', 'winmgmt',
                       'wmic process call create', 'wmic /node:'],
        'event_ids': [4688, 1, 5857, 5858, 5859, 5860, 5861],
        'detection': 'wmic.exe process creation or WMI event subscriptions',
        'next_steps': ['Check if remote execution (look for /node:)',
                       'Identify what process was created',
                       'Look for WMI persistence (event subscriptions)'],
    },
    
    'T1218.011': {
        'id': 'T1218.011',
        'name': 'Rundll32',
        'tactic': 'Defense Evasion',
        'description': 'Abuse of rundll32 for proxy execution',
        'indicators': ['rundll32', 'rundll32.exe'],
        'event_ids': [4688, 1],
        'detection': 'rundll32.exe with unusual DLL paths or JavaScript/VBScript',
        'suspicious_patterns': [
            r'rundll32.*javascript:',
            r'rundll32.*vbscript:',
            r'rundll32.*\\temp\\',
            r'rundll32.*\\users\\.*\\appdata\\',
        ],
        'next_steps': ['Identify the DLL being loaded',
                       'Check if DLL is in unusual location',
                       'Analyze the export function being called'],
    },
    
    # =========================================================================
    # PERSISTENCE (TA0003)
    # =========================================================================
    'T1053.005': {
        'id': 'T1053.005',
        'name': 'Scheduled Task',
        'tactic': 'Persistence',
        'description': 'Scheduled tasks for persistence or execution',
        'indicators': ['schtasks', 'at.exe', 'taskschd', 'Schedule', 'Register-ScheduledTask'],
        'event_ids': [4698, 4699, 4700, 4701, 4702, 106, 140, 141, 200, 201],
        'detection': 'Look for task creation (4698) with suspicious actions',
        'suspicious_patterns': [
            r'schtasks.*/create.*/sc\s+(minute|hourly|onstart|onlogon)',
            r'schtasks.*/create.*powershell',
            r'schtasks.*/create.*cmd',
        ],
        'next_steps': ['Examine task action (what does it run?)',
                       'Check task schedule (when does it run?)',
                       'Identify who created it (SubjectUserName)',
                       'Look for the payload/script being executed'],
    },
    
    'T1543.003': {
        'id': 'T1543.003',
        'name': 'Windows Service',
        'tactic': 'Persistence',
        'description': 'Creating or modifying services for persistence',
        'indicators': ['sc create', 'sc config', 'New-Service', 'services.exe', 
                       'sc.exe', 'binpath=', 'imagefilename'],
        'event_ids': [7045, 4697, 7034, 7035, 7036, 7040],
        'detection': 'Service installation (7045) with unusual binary paths',
        'suspicious_patterns': [
            r'binpath=.*\\temp\\',
            r'binpath=.*\\users\\',
            r'binpath=.*powershell',
            r'binpath=.*cmd\.exe',
        ],
        'next_steps': ['Check the service binary location',
                       'Verify if service is signed/legitimate',
                       'Look for service start events',
                       'Identify what account the service runs as'],
    },
    
    'T1547.001': {
        'id': 'T1547.001',
        'name': 'Registry Run Keys',
        'tactic': 'Persistence',
        'description': 'Registry modifications for persistence',
        'indicators': ['currentversion\\run', 'currentversion\\runonce', 
                       'winlogon\\shell', 'winlogon\\userinit', 'reg add',
                       'Set-ItemProperty', 'New-ItemProperty'],
        'event_ids': [4657, 4663, 13],  # 13 = Sysmon registry
        'detection': 'Registry modifications to Run keys',
        'registry_paths': [
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
        ],
        'next_steps': ['Identify what executable is being persisted',
                       'Check if the executable exists and is legitimate',
                       'Look for when the registry was modified'],
    },
    
    'T1546.003': {
        'id': 'T1546.003',
        'name': 'WMI Event Subscription',
        'tactic': 'Persistence',
        'description': 'WMI permanent event subscriptions for persistence',
        'indicators': ['__eventfilter', '__eventconsumer', '__filtertoconsumerbinding',
                       'commandlineeventconsumer', 'activescripteventconsumer',
                       'wmic /namespace:', 'Set-WmiInstance'],
        'event_ids': [5857, 5858, 5859, 5860, 5861, 19, 20, 21],
        'detection': 'WMI subscription creation events',
        'next_steps': ['Identify the trigger condition',
                       'Examine what command/script is executed',
                       'Check if subscription is new or modified'],
    },
    
    # =========================================================================
    # PRIVILEGE ESCALATION (TA0004)
    # =========================================================================
    'T1134': {
        'id': 'T1134',
        'name': 'Access Token Manipulation',
        'tactic': 'Privilege Escalation',
        'description': 'Token theft or impersonation',
        'indicators': ['impersonation', 'token', 'runas', 'createprocessasuser',
                       'duplicatetoken', 'setthreadtoken'],
        'event_ids': [4624, 4648, 4672, 4688],
        'detection': 'Look for 4624 with elevated privileges or 4648 explicit creds',
        'next_steps': ['Check which privileges were enabled (4672)',
                       'Identify source of token',
                       'Look for sensitive operations after impersonation'],
    },
    
    'T1068': {
        'id': 'T1068',
        'name': 'Exploitation for Privilege Escalation',
        'tactic': 'Privilege Escalation',
        'description': 'Exploiting vulnerabilities for elevation',
        'indicators': ['potato', 'juicypotato', 'rottenpotato', 'sweetpotato',
                       'printspoofer', 'godpotato', 'localse'],
        'event_ids': [4688, 1],
        'detection': 'Known exploit tools or unusual privilege patterns',
        'next_steps': ['Identify which exploit was used',
                       'Check what privileges were gained',
                       'Look for follow-up malicious activity'],
    },
    
    # =========================================================================
    # DEFENSE EVASION (TA0005)
    # =========================================================================
    'T1070.001': {
        'id': 'T1070.001',
        'name': 'Clear Windows Event Logs',
        'tactic': 'Defense Evasion',
        'description': 'Clearing event logs to cover tracks',
        'indicators': ['wevtutil cl', 'wevtutil clear-log', 'Clear-EventLog',
                       'Remove-EventLog', 'auditpol /clear'],
        'event_ids': [1102, 104, 1100],  # Security log cleared, System cleared
        'detection': 'Event 1102 (Security) or 104 (System) log cleared',
        'next_steps': ['CRITICAL: What happened BEFORE the clear is likely gone',
                       'Check other log sources (Sysmon, PowerShell, application)',
                       'Identify who cleared the logs',
                       'Look for backup log files'],
        'severity': 'critical',
    },
    
    'T1562.001': {
        'id': 'T1562.001',
        'name': 'Disable or Modify Tools',
        'tactic': 'Defense Evasion',
        'description': 'Disabling security tools',
        'indicators': ['stop-service', 'sc stop', 'sc delete', 'net stop',
                       'taskkill', 'disable-windowsoptionalfeature', 'set-mppreference',
                       'add-mppreference -exclusionpath', 'tamperprotection'],
        'event_ids': [7036, 7040, 4688, 1, 5001, 5010, 5012],
        'detection': 'Service stops for security tools or Defender exclusion additions',
        'next_steps': ['Which security tool was disabled?',
                       'What was the source process?',
                       'What happened AFTER the tool was disabled?'],
    },
    
    'T1027': {
        'id': 'T1027',
        'name': 'Obfuscated Files or Information',
        'tactic': 'Defense Evasion',
        'description': 'Encoding/encrypting payloads',
        'indicators': ['base64', 'certutil -decode', 'certutil -encode',
                       '-encodedcommand', 'frombase64string', 'gzipstream',
                       'deflatestream', 'xor', 'rot13'],
        'event_ids': [4688, 1, 4104],
        'detection': 'Commands with encoding/decoding operations',
        'next_steps': ['Decode the payload',
                       'Identify what was being hidden',
                       'Check for persistence after decoding'],
    },
    
    'T1055': {
        'id': 'T1055',
        'name': 'Process Injection',
        'tactic': 'Defense Evasion',
        'description': 'Injecting code into legitimate processes',
        'indicators': ['createremotethread', 'virtualallocex', 'writeprocessmemory',
                       'ntmapviewofsection', 'queueuserapc', 'setthreadcontext'],
        'event_ids': [8, 10],  # Sysmon CreateRemoteThread, ProcessAccess
        'detection': 'Sysmon Event 8 (CreateRemoteThread) or suspicious Event 10',
        'next_steps': ['Identify source process (injector)',
                       'Identify target process (victim)',
                       'Check target process for unusual behavior after injection'],
    },
    
    # =========================================================================
    # CREDENTIAL ACCESS (TA0006)
    # =========================================================================
    'T1003.001': {
        'id': 'T1003.001',
        'name': 'LSASS Memory Dumping',
        'tactic': 'Credential Access',
        'description': 'Dumping LSASS memory to extract credentials',
        'indicators': ['lsass', 'procdump', 'mimikatz', 'sekurlsa', 'comsvcs',
                       'minidump', 'Out-Minidump', 'sqldumper', 'rundll32 comsvcs'],
        'event_ids': [4656, 4663, 4688, 10],  # 10 = Sysmon ProcessAccess
        'detection': 'Sysmon 10 with TargetImage=lsass.exe and suspicious GrantedAccess',
        'granted_access_suspicious': ['0x1010', '0x1038', '0x1418', '0x143a'],
        'next_steps': ['Identify the dumping tool used',
                       'Which account performed the dump?',
                       'ASSUME ALL LOGGED-IN CREDENTIALS COMPROMISED',
                       'Look for lateral movement AFTER this event'],
        'severity': 'critical',
    },
    
    'T1003.002': {
        'id': 'T1003.002',
        'name': 'SAM Database',
        'tactic': 'Credential Access',
        'description': 'Extracting local account hashes from SAM',
        'indicators': ['sam', 'system', 'reg save', 'reg.exe save',
                       'hklm\\sam', 'hklm\\system', 'vssadmin', 'shadow copy'],
        'event_ids': [4656, 4663, 8222, 4688],
        'detection': 'Access to SAM or SYSTEM registry hives, or shadow copy access',
        'next_steps': ['Check if attacker used shadow copies',
                       'Local accounts are compromised',
                       'Look for pass-the-hash with local admin'],
    },
    
    'T1003.003': {
        'id': 'T1003.003',
        'name': 'NTDS.dit',
        'tactic': 'Credential Access',
        'description': 'Extracting AD database for offline cracking',
        'indicators': ['ntds.dit', 'ntdsutil', 'vssadmin create shadow',
                       'diskshadow', 'esentutl', 'ifm', 'install from media'],
        'event_ids': [4662, 8222, 4688],
        'detection': 'Access to ntds.dit or creation of shadow copies on DC',
        'next_steps': ['DOMAIN COMPROMISED - All AD credentials at risk',
                       'Plan for domain-wide password reset',
                       'Check for Golden Ticket creation'],
        'severity': 'critical',
    },
    
    'T1003.006': {
        'id': 'T1003.006',
        'name': 'DCSync',
        'tactic': 'Credential Access',
        'description': 'Simulating DC replication to steal credentials',
        'indicators': ['dcsync', 'drsuapi', 'drsr', 'GetNCChanges',
                       'lsadump::dcsync', 'mimikatz dcsync'],
        'event_ids': [4662],
        'detection': 'Event 4662 with DS-Replication-Get-Changes from non-DC',
        'next_steps': ['DOMAIN COMPROMISED - Can extract any credential',
                       'Identify the source of the DCSync request',
                       'Check for Golden Ticket usage'],
        'severity': 'critical',
    },
    
    'T1558.001': {
        'id': 'T1558.001',
        'name': 'Golden Ticket',
        'tactic': 'Credential Access',
        'description': 'Forged Kerberos TGT using krbtgt hash',
        'indicators': ['krbtgt', 'golden ticket', 'kerberos::golden',
                       'mimikatz golden', 'ticketer'],
        'event_ids': [4768, 4769, 4770],
        'detection': 'TGT requests for non-existent users or with anomalous lifetime',
        'next_steps': ['ASSUME FULL DOMAIN COMPROMISE',
                       'krbtgt password must be reset TWICE',
                       'All Kerberos tickets are suspect'],
        'severity': 'critical',
    },
    
    'T1558.003': {
        'id': 'T1558.003',
        'name': 'Kerberoasting',
        'tactic': 'Credential Access',
        'description': 'Requesting service tickets for offline cracking',
        'indicators': ['kerberoast', 'invoke-kerberoast', 'getuserspns',
                       'request-spnticket', 'rc4-hmac', '0x17'],
        'event_ids': [4769],
        'detection': 'High volume of TGS requests, especially with RC4 encryption',
        'next_steps': ['Identify targeted service accounts',
                       'Service account passwords may be cracked offline',
                       'Check for use of compromised service accounts'],
    },
    
    'T1550.002': {
        'id': 'T1550.002',
        'name': 'Pass-the-Hash',
        'tactic': 'Credential Access',
        'description': 'Using NTLM hash without cracking password',
        'indicators': ['pass the hash', 'pth', 'ntlm', 'sekurlsa::pth',
                       'mimikatz pth', 'wmiexec', 'psexec'],
        'event_ids': [4624, 4648, 4672],
        'logon_types': [3, 9],
        'detection': 'Network logon (Type 3 or 9) with NTLM and KeyLength=0',
        'next_steps': ['Identify source of the hash (credential theft event)',
                       'Check what the account accessed after authentication',
                       'Look for lateral movement to other systems'],
    },
    
    'T1550.003': {
        'id': 'T1550.003',
        'name': 'Pass-the-Ticket',
        'tactic': 'Credential Access',
        'description': 'Using stolen Kerberos tickets',
        'indicators': ['pass the ticket', 'ptt', 'kerberos::ptt',
                       'rubeus ptt', 'mimikatz ptt', 'kirbi'],
        'event_ids': [4768, 4769, 4770, 4624],
        'detection': 'Ticket usage from unexpected source or impossible travel',
        'next_steps': ['Identify where the ticket was stolen from',
                       'Check all systems accessed with the ticket',
                       'Revoke the compromised ticket (reset account password)'],
    },
    
    'T1110.001': {
        'id': 'T1110.001',
        'name': 'Password Guessing',
        'tactic': 'Credential Access',
        'description': 'Attempting common passwords against single account',
        'indicators': ['4625', 'failed logon', 'login failed', 'invalid password'],
        'event_ids': [4625, 4771, 4776],
        'detection': 'Multiple 4625 events against SAME account from single source',
        'aggregation': {
            'group_by': ['TargetUserName', 'IpAddress'],
            'count_threshold': 5,
            'time_window': '5m',
        },
        'next_steps': ['Did any attempts succeed? (4624 after burst)',
                       'Block/investigate source IP',
                       'Is the targeted account privileged?'],
    },
    
    'T1110.003': {
        'id': 'T1110.003',
        'name': 'Password Spraying',
        'tactic': 'Credential Access',
        'description': 'Attempting single password against many accounts',
        'indicators': ['password spray', 'spray', '4625', 'failed logon'],
        'event_ids': [4625, 4771, 4776],
        'detection': 'Multiple 4625 from single source to DIFFERENT accounts',
        'aggregation': {
            'group_by': 'IpAddress',
            'count_field': 'TargetUserName',
            'distinct_threshold': 5,
            'time_window': '10m',
        },
        'next_steps': ['Did any account succeed? (4624 after spray)',
                       'Which accounts were targeted (domain admins?)',
                       'Block source IP immediately if ongoing'],
    },
    
    # =========================================================================
    # DISCOVERY (TA0007)
    # =========================================================================
    'T1087.001': {
        'id': 'T1087.001',
        'name': 'Local Account Discovery',
        'tactic': 'Discovery',
        'description': 'Enumerating local accounts',
        'indicators': ['net user', 'net localgroup', 'get-localuser', 
                       'get-localgroupmember', 'wmic useraccount'],
        'event_ids': [4688, 1],
        'detection': 'Commands for enumerating local users/groups',
        'next_steps': ['What account ran the enumeration?',
                       'Was this expected admin activity?',
                       'Look for follow-up privilege escalation'],
    },
    
    'T1087.002': {
        'id': 'T1087.002',
        'name': 'Domain Account Discovery',
        'tactic': 'Discovery',
        'description': 'Enumerating AD accounts',
        'indicators': ['net user /domain', 'net group /domain', 'get-aduser',
                       'get-adgroup', 'dsquery', 'ldapsearch', 'adfind',
                       'get-adgroupmember', 'bloodhound', 'sharphound'],
        'event_ids': [4688, 1, 4661, 4662],
        'detection': 'AD enumeration commands or tools',
        'next_steps': ['Is this authorized IT activity?',
                       'Check for lateral movement after enumeration',
                       'Look for targeting of discovered high-value accounts'],
    },
    
    'T1082': {
        'id': 'T1082',
        'name': 'System Information Discovery',
        'tactic': 'Discovery',
        'description': 'Gathering system info',
        'indicators': ['systeminfo', 'hostname', 'ver', 'set', 'wmic os',
                       'get-computerinfo', 'get-wmiobject win32_operatingsystem'],
        'event_ids': [4688, 1],
        'detection': 'System enumeration commands',
        'next_steps': ['Part of normal scripting?',
                       'Look for what they do with the info gathered'],
    },
    
    'T1018': {
        'id': 'T1018',
        'name': 'Remote System Discovery',
        'tactic': 'Discovery',
        'description': 'Discovering other systems on network',
        'indicators': ['net view', 'ping', 'arp', 'nslookup', 'nltest',
                       'get-adcomputer', 'dsquery computer', 'nbtstat'],
        'event_ids': [4688, 1],
        'detection': 'Network enumeration commands',
        'next_steps': ['Which systems were discovered?',
                       'Look for lateral movement to those systems'],
    },
    
    # =========================================================================
    # LATERAL MOVEMENT (TA0008)
    # =========================================================================
    'T1021.001': {
        'id': 'T1021.001',
        'name': 'Remote Desktop Protocol',
        'tactic': 'Lateral Movement',
        'description': 'Using RDP for lateral movement',
        'indicators': ['mstsc', 'rdp', '3389', 'termsrv', 'rdpclip', 
                       'tscon', 'remote desktop'],
        'event_ids': [4624, 4625, 4648, 1149, 21, 22, 24, 25],
        'logon_types': [10, 7],  # 10=RemoteInteractive, 7=Unlock (RDP reconnect)
        'detection': 'Event 4624 with LogonType=10 from unusual source',
        'next_steps': ['Is RDP expected from that source IP?',
                       'Check for process execution after RDP session starts',
                       'Look for file transfers during session'],
    },
    
    'T1021.002': {
        'id': 'T1021.002',
        'name': 'SMB/Windows Admin Shares',
        'tactic': 'Lateral Movement',
        'description': 'Using SMB shares for lateral movement',
        'indicators': ['psexec', 'paexec', 'remcom', 'smbexec', 'admin$',
                       'c$', 'ipc$', 'net use', '\\\\', 'copy \\\\'],
        'event_ids': [4624, 4648, 4672, 5140, 5145],
        'logon_types': [3],  # Network
        'detection': 'Network logon followed by admin share access',
        'next_steps': ['What was accessed on the share?',
                       'Was a service or file created?',
                       'Check for PSEXESVC or similar service creation'],
    },
    
    'T1021.003': {
        'id': 'T1021.003',
        'name': 'DCOM',
        'tactic': 'Lateral Movement',
        'description': 'Distributed COM for remote execution',
        'indicators': ['dcom', 'mmc20', 'shellbrowserwindow', 'shellwindows',
                       'excel.application', 'outlook.application'],
        'event_ids': [4624, 4688, 1],
        'detection': 'Network logon followed by COM object instantiation',
        'next_steps': ['Identify the COM object used',
                       'Check for command execution via the COM object'],
    },
    
    'T1021.006': {
        'id': 'T1021.006',
        'name': 'Windows Remote Management',
        'tactic': 'Lateral Movement',
        'description': 'WinRM/PowerShell Remoting',
        'indicators': ['winrm', 'winrs', 'enter-pssession', 'invoke-command',
                       'new-pssession', 'wsman', '5985', '5986'],
        'event_ids': [4624, 4648, 4688, 91, 6, 168],
        'logon_types': [3],
        'detection': 'WinRM connection events or PowerShell remoting',
        'next_steps': ['What commands were executed remotely?',
                       'Check PowerShell logging (4104) on target'],
    },
    
    'T1570': {
        'id': 'T1570',
        'name': 'Lateral Tool Transfer',
        'tactic': 'Lateral Movement',
        'description': 'Transferring tools between systems',
        'indicators': ['copy', 'xcopy', 'robocopy', 'scp', 'pscp', 'winscp',
                       'admin$', 'c$', '\\\\*\\c$'],
        'event_ids': [4663, 5140, 5145, 11],  # 11 = Sysmon FileCreate
        'detection': 'File copy to admin shares or remote systems',
        'next_steps': ['What files were transferred?',
                       'Check if files are malware/tools',
                       'Look for execution after transfer'],
    },
    
    # =========================================================================
    # COLLECTION (TA0009)
    # =========================================================================
    'T1560.001': {
        'id': 'T1560.001',
        'name': 'Archive Collected Data',
        'tactic': 'Collection',
        'description': 'Compressing data for exfiltration',
        'indicators': ['7z', 'zip', 'rar', 'tar', 'winrar', 'winzip',
                       'compress-archive', 'makecab', '.zip', '.rar', '.7z'],
        'event_ids': [4688, 1, 11],
        'detection': 'Archive tool execution or creation of archive files',
        'next_steps': ['What files were archived?',
                       'Where was the archive created?',
                       'Was the archive exfiltrated?'],
    },
    
    'T1005': {
        'id': 'T1005',
        'name': 'Data from Local System',
        'tactic': 'Collection',
        'description': 'Collecting data from local drives',
        'indicators': ['type', 'cat', 'more', 'findstr', 'dir /s', 
                       'get-content', 'get-childitem -recurse'],
        'event_ids': [4663, 4656, 4688, 1],
        'detection': 'File access patterns or enumeration commands',
        'next_steps': ['What files were accessed?',
                       'Look for staging before exfiltration'],
    },
    
    # =========================================================================
    # EXFILTRATION (TA0010)
    # =========================================================================
    'T1041': {
        'id': 'T1041',
        'name': 'Exfiltration Over C2 Channel',
        'tactic': 'Exfiltration',
        'description': 'Sending data over existing C2 connection',
        'indicators': ['beacon', 'cobaltstrike', 'meterpreter', 'reverse shell'],
        'event_ids': [3, 22],  # Sysmon network, DNS
        'detection': 'Large outbound data transfers to C2 infrastructure',
        'next_steps': ['Identify the C2 destination',
                       'Quantify data exfiltrated',
                       'Identify what data was taken'],
    },
    
    'T1567': {
        'id': 'T1567',
        'name': 'Exfiltration Over Web Service',
        'tactic': 'Exfiltration',
        'description': 'Using cloud services for exfiltration',
        'indicators': ['onedrive', 'dropbox', 'drive.google', 'mega.nz',
                       'pastebin', 'hastebin', 'transfer.sh', 'wetransfer',
                       'anonfiles', 'gofile', 'sendspace'],
        'event_ids': [3, 22, 4688],
        'detection': 'Connections to cloud storage services or file sharing sites',
        'next_steps': ['What was uploaded?',
                       'Can the upload be recovered/blocked?',
                       'Check cloud service logs if available'],
    },
    
    'T1048': {
        'id': 'T1048',
        'name': 'Exfiltration Over Alternative Protocol',
        'tactic': 'Exfiltration',
        'description': 'Using DNS, ICMP, or other protocols for exfil',
        'indicators': ['dns tunnel', 'iodine', 'dnscat', 'icmp tunnel',
                       'dns txt', 'nslookup -type=txt'],
        'event_ids': [22],  # Sysmon DNS
        'detection': 'Unusual DNS query patterns or high-volume DNS',
        'next_steps': ['Analyze DNS queries for encoded data',
                       'Check query destinations',
                       'Block malicious DNS servers'],
    },
    
    # =========================================================================
    # IMPACT (TA0040)
    # =========================================================================
    'T1486': {
        'id': 'T1486',
        'name': 'Data Encrypted for Impact',
        'tactic': 'Impact',
        'description': 'Ransomware encryption',
        'indicators': ['ransomware', 'encrypt', '.encrypted', '.locked',
                       'vssadmin delete', 'wmic shadowcopy delete',
                       'bcdedit /set', 'recoveryenabled no'],
        'event_ids': [4688, 1, 11],
        'detection': 'Mass file modifications or shadow copy deletion',
        'next_steps': ['CONTAIN IMMEDIATELY - Isolate affected systems',
                       'Identify ransomware variant',
                       'Check for data exfiltration BEFORE encryption',
                       'Preserve evidence for law enforcement'],
        'severity': 'critical',
    },
    
    'T1490': {
        'id': 'T1490',
        'name': 'Inhibit System Recovery',
        'tactic': 'Impact',
        'description': 'Deleting backups and recovery options',
        'indicators': ['vssadmin delete shadows', 'wmic shadowcopy delete',
                       'bcdedit /set', 'wbadmin delete', 'delete catalog'],
        'event_ids': [4688, 1],
        'detection': 'Commands to delete shadow copies or backups',
        'next_steps': ['Ransomware imminent or in progress',
                       'Protect remaining backups',
                       'Isolate affected systems'],
        'severity': 'critical',
    },
}
```

### 3.2 Technique Matching Function

```python
def detect_techniques_in_events(events: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Analyze events and detect MITRE ATT&CK techniques.
    
    Returns dict mapping technique IDs to matching events.
    """
    detected = {}
    
    for event in events:
        source = event.get('_source', event)
        event_id = str(source.get('normalized_event_id', ''))
        search_blob = source.get('search_blob', '').lower()
        command_line = (source.get('EventData', {}).get('CommandLine', '') or '').lower()
        process_name = (source.get('EventData', {}).get('NewProcessName', '') or 
                       source.get('EventData', {}).get('Image', '') or '').lower()
        
        combined_text = f"{search_blob} {command_line} {process_name}"
        
        for tech_id, tech_data in MITRE_TECHNIQUES.items():
            matched = False
            
            # Check event ID match
            if event_id and int(event_id) in tech_data.get('event_ids', []):
                # Check indicator match
                for indicator in tech_data.get('indicators', []):
                    if indicator.lower() in combined_text:
                        matched = True
                        break
            
            # Check for suspicious patterns (regex)
            for pattern in tech_data.get('suspicious_patterns', []):
                if re.search(pattern, combined_text, re.IGNORECASE):
                    matched = True
                    break
            
            if matched:
                if tech_id not in detected:
                    detected[tech_id] = []
                detected[tech_id].append({
                    'event_id': event.get('_id'),
                    'event': event,
                    'technique': tech_data,
                })
    
    return detected


def get_technique_context_for_prompt(detected_techniques: Dict) -> str:
    """
    Generate technique context for LLM prompt.
    """
    if not detected_techniques:
        return "No specific MITRE ATT&CK techniques detected in retrieved events."
    
    lines = ["**MITRE ATT&CK Techniques Detected:**\n"]
    
    for tech_id, matches in detected_techniques.items():
        tech = MITRE_TECHNIQUES.get(tech_id, {})
        count = len(matches)
        lines.append(f"- **{tech_id}** - {tech.get('name', 'Unknown')} ({tech.get('tactic', '')})")
        lines.append(f"  - Found in {count} event(s)")
        lines.append(f"  - Detection: {tech.get('detection', 'N/A')}")
        if tech.get('next_steps'):
            lines.append(f"  - Next steps: {tech['next_steps'][0]}")
        if tech.get('severity') == 'critical':
            lines.append(f"  - ⚠️ **CRITICAL SEVERITY**")
    
    return '\n'.join(lines)
```

---

## 4. V4: Gap Analysis Engine

### 4.1 Gap Analysis Database

```python
GAP_ANALYSIS = {
    # =========================================================================
    # LATERAL MOVEMENT
    # =========================================================================
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
            'recommended_filters': [
                'Same source IP/account on other target systems',
                'Process execution (4688) on target systems after logon',
                'Service creation (7045) on target systems',
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
            'alternative_questions': [
                'Was there data exfiltration from the initial system?',
                'Did the attacker establish persistence before moving?',
                'Is there evidence of command and control from one system?',
            ],
        },
    },
    
    # =========================================================================
    # CREDENTIAL ACCESS
    # =========================================================================
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
            'immediate_actions': [
                'Identify all accounts that were logged in during LSASS access',
                'Consider those accounts compromised and reset passwords',
                'If Domain Admin compromised, prepare for domain-wide remediation',
                'Check for Golden Ticket indicators if krbtgt was accessed',
            ],
        },
        'if_not_found': {
            'summary': 'No credential theft detected in retrieved events',
            'possible_explanations': [
                'Attacker may have brought valid credentials (phishing, password reuse)',
                'Credential theft occurred on a different system',
                'Sysmon Event 10 (ProcessAccess to LSASS) may not be configured',
                'Memory-only tools may have avoided detection',
                'Credentials may have been stolen via keylogging instead of dumping',
            ],
            'verification_steps': [
                'Check for password spray/brute force patterns (4625 clusters)',
                'Review phishing indicators in email logs',
                'Verify Sysmon Event 10 is configured for LSASS monitoring',
                'Check for credential theft on Domain Controllers specifically',
                'Look for Kerberoasting (4769 with RC4 encryption)',
            ],
            'alternative_questions': [
                'Did the attacker already have valid credentials?',
                'Was there phishing that captured credentials?',
                'Are there signs of password reuse from breached databases?',
            ],
        },
    },
    
    # =========================================================================
    # PERSISTENCE
    # =========================================================================
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
            'immediate_actions': [
                'Document the persistence mechanism fully',
                'Check if it is currently active/running',
                'Identify the payload/command being executed',
                'Look for same persistence on other systems',
            ],
        },
        'if_not_found': {
            'summary': 'No persistence mechanisms detected in retrieved events',
            'possible_explanations': [
                'May be a smash-and-grab attack (no need for persistence)',
                'Attacker still in initial access phase',
                'Persistence may be in unmonitored location (firmware, cloud)',
                'Events for persistence may not be logged (registry, WMI)',
                'Attacker may be using "living off the land" techniques',
            ],
            'verification_steps': [
                'Check scheduled task events (4698, 4699)',
                'Verify service installation logging (7045)',
                'Review Sysmon Event 13 (Registry modifications)',
                'Check for WMI subscriptions (Sysmon 19-21)',
                'Look for startup folder modifications',
            ],
            'alternative_questions': [
                'Is this an ongoing attack vs. completed attack?',
                'Did the attacker achieve their objective without needing persistence?',
                'Is persistence in cloud/SaaS instead of on-premise?',
            ],
        },
    },
    
    # =========================================================================
    # EXFILTRATION
    # =========================================================================
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
            'immediate_actions': [
                'Block exfiltration destination if ongoing',
                'Quantify what was taken for breach notification',
                'Check for data in other destinations',
                'Assess sensitivity of exfiltrated data',
            ],
        },
        'if_not_found': {
            'summary': 'No data exfiltration detected in retrieved events',
            'possible_explanations': [
                'Attacker still in collection/staging phase',
                'Exfiltration via encrypted channel not visible in logs',
                'Data may have been exfiltrated outside logging coverage',
                'Attack objective may not be data theft (ransomware, BEC)',
                'Exfiltration via alternative channels (USB, print)',
            ],
            'verification_steps': [
                'Look for archive creation (zip, rar, 7z)',
                'Check network logs for large outbound transfers',
                'Review web proxy logs for cloud upload services',
                'Look for staging directories with collected files',
                'Check DNS logs for data exfiltration via DNS',
            ],
            'alternative_questions': [
                'Is the attack objective ransomware instead of theft?',
                'Was this a BEC/fraud attack rather than data theft?',
                'Is data still being staged but not yet exfiltrated?',
            ],
        },
    },
    
    # =========================================================================
    # BRUTE FORCE / PASSWORD SPRAY
    # =========================================================================
    'brute_force': {
        'if_found': {
            'summary': 'Brute force or password spray attack detected',
            'severity': 'high',
            'critical_questions': [
                'Did any attempts succeed? (4624 after 4625 cluster)',
                'Which accounts were targeted?',
                'Is the attack ongoing or historical?',
                'What is the source of the attack?',
            ],
            'look_for_before': [
                'Reconnaissance that identified target accounts',
                'Harvesting of username lists',
            ],
            'look_for_after': [
                'Successful authentication from same source',
                'Activity using any compromised accounts',
                'Lateral movement if account had network access',
            ],
            'immediate_actions': [
                'Block source IP if attack is ongoing',
                'Lock targeted accounts if they are privileged',
                'Check for successful authentications',
                'Reset passwords for any potentially compromised accounts',
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
                'Check VPN authentication logs',
                'Review email for phishing that may have captured credentials',
            ],
        },
    },
    
    # =========================================================================
    # MALWARE / EXECUTION
    # =========================================================================
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
            'immediate_actions': [
                'Identify the malware/payload',
                'Check for indicators of compromise (IOCs)',
                'Look for lateral spread',
                'Contain affected systems',
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
    
    # =========================================================================
    # DEFENSE EVASION
    # =========================================================================
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
            'immediate_actions': [
                'Re-enable disabled security tools',
                'Check what happened in the window when defenses were down',
                'Look for malware execution during the gap',
            ],
        },
        'if_not_found': {
            'summary': 'No defense evasion detected',
            'possible_explanations': [
                'Attack may have avoided triggering security tools',
                'Tools may have been disabled before logging started',
                'Attacker may be using techniques that bypass detection',
            ],
        },
    },
}


def get_gap_analysis(detected_attack_types: List[str], 
                     detected_techniques: Dict) -> str:
    """
    Generate gap analysis guidance based on what was found/not found.
    """
    lines = ["\n**GAP ANALYSIS & INVESTIGATION GUIDANCE:**\n"]
    
    # Determine what attack types were actually detected
    found_types = set()
    not_found_types = set()
    
    # Map techniques to attack types
    technique_to_type = {
        'T1021': 'lateral_movement',
        'T1570': 'lateral_movement',
        'T1003': 'credential_access',
        'T1550': 'credential_access',
        'T1558': 'credential_access',
        'T1110': 'brute_force',
        'T1053': 'persistence',
        'T1543': 'persistence',
        'T1547': 'persistence',
        'T1546': 'persistence',
        'T1041': 'exfiltration',
        'T1567': 'exfiltration',
        'T1048': 'exfiltration',
        'T1059': 'malware',
        'T1204': 'malware',
        'T1218': 'malware',
        'T1070': 'defense_evasion',
        'T1562': 'defense_evasion',
        'T1027': 'defense_evasion',
    }
    
    for tech_id in detected_techniques:
        for prefix, attack_type in technique_to_type.items():
            if tech_id.startswith(prefix):
                found_types.add(attack_type)
    
    # Add types from query expansion that were searched for
    for attack_type in detected_attack_types:
        if attack_type not in found_types:
            not_found_types.add(attack_type)
    
    # Generate guidance for found types
    for attack_type in found_types:
        if attack_type in GAP_ANALYSIS:
            gap = GAP_ANALYSIS[attack_type]['if_found']
            lines.append(f"\n✅ **{attack_type.upper().replace('_', ' ')} DETECTED**")
            lines.append(f"   {gap['summary']}")
            lines.append(f"   ")
            lines.append(f"   **What to investigate next:**")
            for item in gap.get('look_for_after', [])[:3]:
                lines.append(f"   - {item}")
    
    # Generate guidance for not found types
    for attack_type in not_found_types:
        if attack_type in GAP_ANALYSIS:
            gap = GAP_ANALYSIS[attack_type]['if_not_found']
            lines.append(f"\n❓ **{attack_type.upper().replace('_', ' ')} NOT DETECTED**")
            lines.append(f"   {gap['summary']}")
            lines.append(f"   ")
            lines.append(f"   **Possible reasons:**")
            for item in gap.get('possible_explanations', [])[:2]:
                lines.append(f"   - {item}")
            lines.append(f"   **Verification steps:**")
            for item in gap.get('verification_steps', [])[:2]:
                lines.append(f"   - {item}")
    
    return '\n'.join(lines)
```

---

## 5. V4: Kill Chain Mapping

### 5.1 Kill Chain Phases

```python
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


def determine_kill_chain_phase(detected_techniques: Dict) -> Dict:
    """
    Determine current kill chain phase based on detected techniques.
    """
    technique_to_phase = {}
    for phase_id, phase_data in KILL_CHAIN_PHASES.items():
        for tech in phase_data.get('example_techniques', []):
            technique_to_phase[tech] = phase_id
    
    detected_phases = {}
    for tech_id in detected_techniques:
        # Match by prefix (T1021.001 -> T1021)
        tech_prefix = tech_id.split('.')[0] if '.' in tech_id else tech_id
        
        for tech_pattern, phase in technique_to_phase.items():
            if tech_id == tech_pattern or tech_id.startswith(tech_pattern):
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


def get_kill_chain_context(kill_chain_result: Dict) -> str:
    """Generate kill chain context for LLM prompt."""
    if not kill_chain_result:
        return "Kill chain phase: Unable to determine from available events."
    
    lines = ["\n**KILL CHAIN POSITION:**"]
    lines.append(f"")
    lines.append(f"Current Phase: **{kill_chain_result['phase_name']}** (Phase {kill_chain_result['order']}/12)")
    lines.append(f"Description: {kill_chain_result['phase_description']}")
    
    if len(kill_chain_result['all_detected_phases']) > 1:
        phases = [KILL_CHAIN_PHASES[p]['name'] for p in kill_chain_result['all_detected_phases']]
        lines.append(f"All phases detected: {', '.join(phases)}")
    
    if kill_chain_result.get('typical_next'):
        next_phase = KILL_CHAIN_PHASES[kill_chain_result['typical_next']]
        lines.append(f"")
        lines.append(f"**Typical next phase:** {next_phase['name']}")
        lines.append(f"Look for: {next_phase['description']}")
    
    return '\n'.join(lines)
```

---

## 6. Intelligent Sampling Strategies

### 6.1 The Challenge

With 3-20 million events per case, we can't analyze everything. We need smart sampling to:
1. Ensure we see the **most important** events (tagged, SIGMA, IOC)
2. Get a **representative sample** across event types and time
3. Find **attack patterns** via aggregation
4. Support both **big picture** and **focused** queries

### 6.2 Multi-Strategy Sampling

```python
class IntelligentSampler:
    """
    Intelligent event sampling for 3-20M event cases.
    """
    
    # Maximum events to return to LLM
    MAX_FINAL_EVENTS = 25
    
    # Allocation for different priority tiers
    TIER_ALLOCATION = {
        'priority': 10,      # Tagged, SIGMA critical/high, IOC
        'medium': 8,         # SIGMA medium/low, interesting event types
        'pattern': 4,        # Events from aggregation patterns
        'random': 3,         # Random sample for baseline/coverage
    }
    
    # Event types that are particularly interesting
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
        stats = {
            'total_events_in_case': 0,
            'priority_events': 0,
            'medium_events': 0,
            'pattern_events': 0,
            'random_events': 0,
            'sampling_mode': mode,
        }
        
        # Get total event count
        count_response = self.client.count(index=self.index_name)
        stats['total_events_in_case'] = count_response['count']
        
        # 1. Priority Tier: Tagged, SIGMA critical/high, IOC matches
        priority_events = self._get_priority_events(
            keywords, dfir_terms, exclusions, 
            limit=self.TIER_ALLOCATION['priority']
        )
        all_events.extend(priority_events)
        stats['priority_events'] = len(priority_events)
        
        # 2. Pattern Tier: Aggregation-based pattern detection
        if mode in ['big_picture', 'pattern']:
            pattern_events = self._get_pattern_events(
                keywords, exclusions,
                limit=self.TIER_ALLOCATION['pattern']
            )
            # Deduplicate
            existing_ids = {e['_id'] for e in all_events}
            pattern_events = [e for e in pattern_events if e['_id'] not in existing_ids]
            all_events.extend(pattern_events)
            stats['pattern_events'] = len(pattern_events)
        
        # 3. Medium Tier: SIGMA medium/low, interesting event types
        medium_events = self._get_medium_priority_events(
            keywords, dfir_terms, exclusions,
            limit=self.TIER_ALLOCATION['medium'],
            existing_ids={e['_id'] for e in all_events}
        )
        all_events.extend(medium_events)
        stats['medium_events'] = len(medium_events)
        
        # 4. Random Tier: Representative sample for coverage
        if mode == 'big_picture':
            random_events = self._get_stratified_random_sample(
                exclusions,
                limit=self.TIER_ALLOCATION['random'],
                existing_ids={e['_id'] for e in all_events}
            )
            all_events.extend(random_events)
            stats['random_events'] = len(random_events)
        
        # Limit to maximum
        all_events = all_events[:self.MAX_FINAL_EVENTS]
        
        return all_events, stats
    
    def _get_priority_events(self, keywords, dfir_terms, exclusions, limit):
        """Get highest priority events: tagged, SIGMA critical/high, IOC."""
        query = {
            "bool": {
                "should": [
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
                    # Keyword matches
                    *[{"multi_match": {
                        "query": kw,
                        "fields": ["search_blob^1.5", "event_title^3", "command_line^2"],
                        "boost": 10
                    }} for kw in (keywords + dfir_terms)[:15]],
                ],
                "minimum_should_match": 1,
                "must_not": exclusions,
            }
        }
        
        response = self.client.search(
            index=self.index_name,
            body={
                "query": query,
                "size": limit * 2,  # Get extra for deduplication
                "sort": [{"_score": "desc"}, {"normalized_timestamp": "desc"}],
                "_source": True,
            }
        )
        
        return self._hits_to_events(response)[:limit]
    
    def _get_pattern_events(self, keywords, exclusions, limit):
        """Get events representing attack patterns via aggregation."""
        all_pattern_events = []
        
        # Pattern 1: Password spray detection
        spray_events = self._detect_password_spray(exclusions, limit=2)
        all_pattern_events.extend(spray_events)
        
        # Pattern 2: Lateral movement clusters
        lateral_events = self._detect_lateral_movement(exclusions, limit=2)
        all_pattern_events.extend(lateral_events)
        
        # Pattern 3: Suspicious process chains
        process_events = self._detect_suspicious_processes(keywords, exclusions, limit=2)
        all_pattern_events.extend(process_events)
        
        return all_pattern_events[:limit]
    
    def _detect_password_spray(self, exclusions, limit):
        """Detect password spray patterns via aggregation."""
        try:
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": {
                        "bool": {
                            "filter": [{"term": {"normalized_event_id": 4625}}],
                            "must_not": exclusions,
                        }
                    },
                    "size": 0,
                    "aggs": {
                        "by_source": {
                            "terms": {"field": "IpAddress.keyword", "size": 10},
                            "aggs": {
                                "unique_targets": {
                                    "cardinality": {"field": "TargetUserName.keyword"}
                                },
                                "sample_events": {
                                    "top_hits": {"size": 2}
                                }
                            }
                        }
                    }
                },
                request_timeout=15
            )
            
            events = []
            for bucket in response['aggregations']['by_source']['buckets']:
                if bucket['unique_targets']['value'] >= 5:  # 5+ targets = likely spray
                    for hit in bucket['sample_events']['hits']['hits']:
                        hit['_source']['_pattern'] = 'password_spray'
                        hit['_source']['_pattern_context'] = f"Source IP {bucket['key']} targeted {bucket['unique_targets']['value']} unique accounts"
                        events.append(self._hit_to_event(hit))
            
            return events[:limit]
        except Exception as e:
            logger.warning(f"Password spray detection failed: {e}")
            return []
    
    def _detect_lateral_movement(self, exclusions, limit):
        """Detect lateral movement patterns."""
        try:
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"normalized_event_id": 4624}},
                                {"terms": {"LogonType": ["3", "10"]}}
                            ],
                            "must_not": exclusions,
                        }
                    },
                    "size": 0,
                    "aggs": {
                        "by_target": {
                            "terms": {"field": "normalized_computer.keyword", "size": 10},
                            "aggs": {
                                "unique_sources": {
                                    "cardinality": {"field": "IpAddress.keyword"}
                                },
                                "sample_events": {
                                    "top_hits": {"size": 2}
                                }
                            }
                        }
                    }
                },
                request_timeout=15
            )
            
            events = []
            for bucket in response['aggregations']['by_target']['buckets']:
                if bucket['unique_sources']['value'] >= 3:  # 3+ sources = interesting
                    for hit in bucket['sample_events']['hits']['hits']:
                        hit['_source']['_pattern'] = 'lateral_movement'
                        hit['_source']['_pattern_context'] = f"Target {bucket['key']} received logons from {bucket['unique_sources']['value']} unique sources"
                        events.append(self._hit_to_event(hit))
            
            return events[:limit]
        except Exception as e:
            logger.warning(f"Lateral movement detection failed: {e}")
            return []
    
    def _detect_suspicious_processes(self, keywords, exclusions, limit):
        """Detect suspicious process execution."""
        suspicious_patterns = [
            'powershell.*-enc', 'powershell.*downloadstring', 'powershell.*hidden',
            'certutil.*-decode', 'certutil.*-urlcache',
            'mshta.*http', 'mshta.*javascript',
            'regsvr32.*/s.*/i.*http',
            'rundll32.*javascript', 'rundll32.*,#',
            'wmic.*process.*call',
        ]
        
        try:
            should_clauses = [
                {"regexp": {"search_blob": pattern}}
                for pattern in suspicious_patterns
            ]
            
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": {
                        "bool": {
                            "should": should_clauses,
                            "minimum_should_match": 1,
                            "must_not": exclusions,
                        }
                    },
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
            logger.warning(f"Suspicious process detection failed: {e}")
            return []
    
    def _get_medium_priority_events(self, keywords, dfir_terms, exclusions, 
                                    limit, existing_ids):
        """Get medium priority events with stratification."""
        query = {
            "bool": {
                "should": [
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
                    # Keyword matches
                    *[{"multi_match": {
                        "query": kw,
                        "fields": ["search_blob", "command_line"],
                        "boost": 2
                    }} for kw in (keywords + dfir_terms)[:10]],
                ],
                "minimum_should_match": 1,
                "must_not": exclusions + [
                    {"ids": {"values": list(existing_ids)}}
                ],
            }
        }
        
        # Use collapse to diversify by event type
        response = self.client.search(
            index=self.index_name,
            body={
                "query": query,
                "size": limit * 3,
                "collapse": {
                    "field": "normalized_event_id",
                    "inner_hits": {
                        "name": "same_type",
                        "size": 1
                    }
                },
                "sort": [{"_score": "desc"}],
                "_source": True,
            }
        )
        
        return self._hits_to_events(response)[:limit]
    
    def _get_stratified_random_sample(self, exclusions, limit, existing_ids):
        """Get stratified random sample across time and event types."""
        try:
            # Get time range
            time_response = self.client.search(
                index=self.index_name,
                body={
                    "size": 0,
                    "aggs": {
                        "min_time": {"min": {"field": "normalized_timestamp"}},
                        "max_time": {"max": {"field": "normalized_timestamp"}},
                    }
                }
            )
            
            min_time = time_response['aggregations']['min_time']['value_as_string']
            max_time = time_response['aggregations']['max_time']['value_as_string']
            
            # Sample using random_score
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"function_score": {
                                    "random_score": {"seed": 42, "field": "_seq_no"}
                                }}
                            ],
                            "must_not": exclusions + [
                                {"ids": {"values": list(existing_ids)}}
                            ],
                        }
                    },
                    "size": limit,
                    "_source": True,
                }
            )
            
            events = self._hits_to_events(response)
            for e in events:
                e['_source']['_sample_type'] = 'random_baseline'
            return events
            
        except Exception as e:
            logger.warning(f"Random sampling failed: {e}")
            return []
    
    def _hits_to_events(self, response):
        """Convert OpenSearch hits to event dicts."""
        return [self._hit_to_event(hit) for hit in response['hits']['hits']]
    
    def _hit_to_event(self, hit):
        """Convert single hit to event dict."""
        return {
            '_id': hit['_id'],
            '_index': hit['_index'],
            '_score': hit.get('_score', 0),
            '_source': hit['_source'],
        }
```

### 6.3 Sampling Mode Selection

```python
def determine_query_mode(question: str, keywords: List[str]) -> str:
    """
    Determine the appropriate query mode based on the question.
    
    Returns:
        'big_picture' - Broad analysis, need representative sample
        'focused' - Specific user, time, or entity investigation
        'pattern' - Looking for attack patterns
    """
    question_lower = question.lower()
    
    # Focused mode indicators
    focused_patterns = [
        r'\buser\s+[a-zA-Z]+\.[a-zA-Z]+',  # "user john.doe"
        r'\baccount\s+\w+',                 # "account admin"
        r'how\s+did\s+\w+\s+get\s+compromised',
        r'what\s+happened\s+to\s+\w+',
        r'trace\s+',
        r'timeline\s+for\s+',
        r'specifically\s+',
        r'\bonly\s+',
    ]
    
    for pattern in focused_patterns:
        if re.search(pattern, question_lower):
            return 'focused'
    
    # Pattern mode indicators
    pattern_patterns = [
        r'password\s+spray',
        r'brute\s+force',
        r'failed\s+logins?',
        r'lateral\s+movement\s+pattern',
        r'how\s+many\s+systems',
        r'spread\s+through',
        r'attack\s+path',
    ]
    
    for pattern in pattern_patterns:
        if re.search(pattern, question_lower):
            return 'pattern'
    
    # Default to big picture
    return 'big_picture'
```

---

## 7. User-Specific Investigation

### 7.1 Username Extraction

```python
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
    ]
    
    for pattern, group in patterns:
        match = re.search(pattern, question, re.IGNORECASE)
        if match:
            username = match.group(group)
            # Filter out common false positives
            if username.lower() not in ['the', 'this', 'that', 'user', 'account', 
                                         'admin', 'system', 'local', 'domain']:
                return username
    
    return None


def build_user_focused_query(base_query: Dict, username: str) -> Dict:
    """
    Wrap base query with user filter for focused investigation.
    """
    user_filter = {
        "bool": {
            "should": [
                # Exact matches
                {"term": {"TargetUserName.keyword": username}},
                {"term": {"SubjectUserName.keyword": username}},
                {"term": {"AccountName.keyword": username}},
                # Partial matches (for DOMAIN\user format)
                {"wildcard": {"TargetUserName": f"*{username}*"}},
                {"wildcard": {"SubjectUserName": f"*{username}*"}},
                # Search blob for any mention
                {"match_phrase": {"search_blob": username}},
            ],
            "minimum_should_match": 1
        }
    }
    
    return {
        "bool": {
            "must": [base_query, user_filter]
        }
    }


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
                {"wildcard": {"search_blob": f"*{username}*"}},
            ],
            "minimum_should_match": 1
        }
    }
    
    response = opensearch_client.search(
        index=index_name,
        body={
            "query": query,
            "size": limit,
            "sort": [{"normalized_timestamp": "asc"}],  # Chronological
            "_source": True,
        }
    )
    
    return [{
        '_id': hit['_id'],
        '_source': hit['_source'],
        '_score': hit.get('_score', 0),
    } for hit in response['hits']['hits']]


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
    
    analysis['first_event'] = events[0]['_source'].get('normalized_timestamp')
    
    for event in events:
        source = event['_source']
        event_id = str(source.get('normalized_event_id', ''))
        
        # Track logon sources
        if event_id in ['4624', '4625']:
            ip = source.get('EventData', {}).get('IpAddress')
            if ip:
                analysis['logon_sources'].add(ip)
        
        # Track processes
        if event_id in ['4688', '1']:
            proc = source.get('EventData', {}).get('NewProcessName') or source.get('EventData', {}).get('Image')
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
```

---

## 8. Big Picture Analysis

### 8.1 Case Overview Generation

```python
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
        # Get total and time range
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
            }
        )
        
        aggs = response['aggregations']
        overview['total_events'] = response['hits']['total']['value']
        overview['time_range']['start'] = aggs['min_time']['value_as_string']
        overview['time_range']['end'] = aggs['max_time']['value_as_string']
        
        overview['top_event_types'] = [
            {'event_id': b['key'], 'count': b['doc_count']}
            for b in aggs['event_types']['buckets']
        ]
        
        overview['top_computers'] = [
            {'computer': b['key'], 'count': b['doc_count']}
            for b in aggs['computers']['buckets']
        ]
        
        overview['top_users'] = [
            {'user': b['key'], 'count': b['doc_count']}
            for b in aggs['users']['buckets']
        ]
        
        for level_bucket in aggs['sigma_levels']['levels']['buckets']:
            level = level_bucket['key'].lower()
            if level in overview['sigma_summary']:
                overview['sigma_summary'][level] = level_bucket['doc_count']
        
        overview['ioc_count'] = aggs['ioc_events']['doc_count']
        overview['tagged_count'] = aggs['tagged_events']['doc_count']
        
    except Exception as e:
        logger.error(f"Failed to generate case overview: {e}")
    
    return overview


def get_case_context_for_prompt(overview: Dict) -> str:
    """Generate case context for LLM prompt."""
    lines = ["**CASE OVERVIEW:**"]
    lines.append(f"- Total events: {overview['total_events']:,}")
    lines.append(f"- Time range: {overview['time_range']['start']} to {overview['time_range']['end']}")
    lines.append(f"- SIGMA detections: {sum(overview['sigma_summary'].values())} total "
                 f"(Critical: {overview['sigma_summary']['critical']}, "
                 f"High: {overview['sigma_summary']['high']})")
    lines.append(f"- IOC matches: {overview['ioc_count']}")
    lines.append(f"- Analyst tagged: {overview['tagged_count']}")
    
    if overview['top_computers']:
        top_computers = ', '.join(c['computer'] for c in overview['top_computers'][:3])
        lines.append(f"- Top computers: {top_computers}")
    
    return '\n'.join(lines)
```

---

## 9. Enhanced LLM Prompts

### 9.1 Big Picture Prompt

```python
BIG_PICTURE_PROMPT = """You are a senior Digital Forensics and Incident Response (DFIR) analyst conducting an investigation.

## CASE: {case_name}

{case_overview}

## ANALYST'S QUESTION
{question}

## SAMPLING INFORMATION
This case contains {total_events:,} events. To give you the best overview, we sampled:
- {priority_events} high-priority events (tagged by analyst, SIGMA critical/high, IOC matches)
- {pattern_events} events showing attack patterns (password spray, lateral movement clusters)
- {medium_events} medium-priority events (SIGMA medium/low, interesting event types)
- {random_events} random baseline events (for coverage)

{technique_context}

{kill_chain_context}

{gap_analysis}

## EVIDENCE EVENTS (showing {event_count} of {total_events:,})

{events_text}

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
```

### 9.2 Focused Investigation Prompt

```python
FOCUSED_PROMPT = """You are a senior DFIR analyst investigating a specific user or entity.

## CASE: {case_name}

## INVESTIGATION TARGET
{target_type}: {target_value}

## ANALYST'S QUESTION
{question}

{user_analysis}

{technique_context}

## TIMELINE OF EVENTS FOR {target_value}

{events_text}

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
```

### 9.3 Pattern Detection Prompt

```python
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
```

---

## 10. Implementation Roadmap

### Phase 1: Core Infrastructure (4-6 hours)

| Task | Time | Priority |
|------|------|----------|
| Add `extract_exclusions_from_question()` | 45 min | Critical |
| Add `build_must_not_clauses()` | 30 min | Critical |
| Add `EXCLUSION_CATEGORIES` dictionary | 30 min | Critical |
| Add `determine_query_mode()` | 20 min | High |
| Add `extract_target_user()` | 20 min | High |
| Integrate exclusions into `semantic_search_events()` | 45 min | Critical |
| Test exclusion functionality | 60 min | Critical |

### Phase 2: MITRE ATT&CK (4-6 hours)

| Task | Time | Priority |
|------|------|----------|
| Add `MITRE_TECHNIQUES` dictionary (full) | 90 min | High |
| Add `detect_techniques_in_events()` | 45 min | High |
| Add `get_technique_context_for_prompt()` | 30 min | High |
| Test technique detection | 60 min | High |

### Phase 3: Gap Analysis & Kill Chain (3-4 hours)

| Task | Time | Priority |
|------|------|----------|
| Add `GAP_ANALYSIS` dictionary | 60 min | High |
| Add `get_gap_analysis()` | 45 min | High |
| Add `KILL_CHAIN_PHASES` dictionary | 30 min | Medium |
| Add `determine_kill_chain_phase()` | 30 min | Medium |
| Add `get_kill_chain_context()` | 20 min | Medium |

### Phase 4: Intelligent Sampling (4-6 hours)

| Task | Time | Priority |
|------|------|----------|
| Add `IntelligentSampler` class | 90 min | Critical |
| Add `_get_priority_events()` | 30 min | Critical |
| Add `_detect_password_spray()` | 45 min | High |
| Add `_detect_lateral_movement()` | 45 min | High |
| Add `_get_stratified_random_sample()` | 30 min | Medium |
| Integrate sampler into main search | 60 min | Critical |

### Phase 5: Enhanced Prompts & Integration (3-4 hours)

| Task | Time | Priority |
|------|------|----------|
| Add `BIG_PICTURE_PROMPT` | 30 min | High |
| Add `FOCUSED_PROMPT` | 20 min | High |
| Add `PATTERN_PROMPT` | 20 min | High |
| Add `generate_case_overview()` | 45 min | Medium |
| Update `generate_ai_answer()` to use new prompts | 60 min | High |
| End-to-end testing | 90 min | Critical |

### Total Estimated Time: 18-26 hours

---

## 11. Complete Code Changes

### 11.1 Files to Modify

| File | Changes |
|------|---------|
| `app/ai_search.py` | Add all new functions, update `semantic_search_events()`, update `generate_ai_answer()` |
| `app/routes/ai_search.py` | Add technique/gap/kill_chain to response stream |

### 11.2 New Functions to Add to ai_search.py

```python
# Add after existing DFIR_QUERY_EXPANSION (around line 107)

# =============================================================================
# V3: EXCLUSION SUPPORT
# =============================================================================

EXCLUSION_PATTERNS = [...]  # See Section 2.1
EXCLUSION_CATEGORIES = {...}  # See Section 2.2

def extract_exclusions_from_question(question: str) -> Tuple[str, List[str], List[str]]:
    ...  # See Section 2.3

def build_must_not_clauses(explicit_exclusions: List[str], 
                           category_exclusions: List[str]) -> List[Dict]:
    ...  # See Section 2.4


# =============================================================================
# V4: MITRE ATT&CK INTEGRATION
# =============================================================================

MITRE_TECHNIQUES = {...}  # See Section 3.1 (abbreviated for space)

def detect_techniques_in_events(events: List[Dict]) -> Dict[str, List[Dict]]:
    ...  # See Section 3.2

def get_technique_context_for_prompt(detected_techniques: Dict) -> str:
    ...  # See Section 3.2


# =============================================================================
# V4: GAP ANALYSIS
# =============================================================================

GAP_ANALYSIS = {...}  # See Section 4.1

def get_gap_analysis(detected_attack_types: List[str], 
                     detected_techniques: Dict) -> str:
    ...  # See Section 4.1


# =============================================================================
# V4: KILL CHAIN
# =============================================================================

KILL_CHAIN_PHASES = {...}  # See Section 5.1

def determine_kill_chain_phase(detected_techniques: Dict) -> Dict:
    ...  # See Section 5.1

def get_kill_chain_context(kill_chain_result: Dict) -> str:
    ...  # See Section 5.1


# =============================================================================
# INTELLIGENT SAMPLING
# =============================================================================

class IntelligentSampler:
    ...  # See Section 6.2

def determine_query_mode(question: str, keywords: List[str]) -> str:
    ...  # See Section 6.3


# =============================================================================
# USER-SPECIFIC INVESTIGATION
# =============================================================================

def extract_target_user(question: str) -> Optional[str]:
    ...  # See Section 7.1

def build_user_focused_query(base_query: Dict, username: str) -> Dict:
    ...  # See Section 7.1

def get_user_timeline(opensearch_client, case_id: int, username: str, 
                      limit: int = 50) -> List[Dict]:
    ...  # See Section 7.1

def analyze_user_compromise(events: List[Dict], username: str) -> Dict:
    ...  # See Section 7.1


# =============================================================================
# BIG PICTURE ANALYSIS
# =============================================================================

def generate_case_overview(opensearch_client, case_id: int) -> Dict:
    ...  # See Section 8.1

def get_case_context_for_prompt(overview: Dict) -> str:
    ...  # See Section 8.1


# =============================================================================
# ENHANCED PROMPTS
# =============================================================================

BIG_PICTURE_PROMPT = """..."""  # See Section 9.1
FOCUSED_PROMPT = """..."""  # See Section 9.2
PATTERN_PROMPT = """..."""  # See Section 9.3
```

### 11.3 Update semantic_search_events()

```python
def semantic_search_events(
    opensearch_client,
    case_id: int,
    question: str,
    max_results: int = 25,
    include_sigma: bool = True,
    include_ioc: bool = True,
    boost_tagged: bool = True
) -> Tuple[List[Dict], str, Dict]:  # Now returns extra metadata
    """
    V4 Enhanced semantic search with exclusions, MITRE, and intelligent sampling.
    """
    index_name = f"case_{case_id}"
    
    # Step 1: Extract exclusions from question
    clean_question, explicit_excl, category_excl = extract_exclusions_from_question(question)
    exclusion_clauses = build_must_not_clauses(explicit_excl, category_excl)
    
    if explicit_excl or category_excl:
        logger.info(f"[AI_SEARCH] Exclusions: explicit={explicit_excl}, categories={len(category_excl)} terms")
    
    # Step 2: Extract keywords from clean question
    keywords = extract_keywords_from_question(clean_question)
    dfir_terms = expand_query_for_dfir(clean_question)
    
    # Step 3: Determine query mode
    query_mode = determine_query_mode(question, keywords)
    target_user = extract_target_user(question)
    
    if target_user:
        query_mode = 'focused'
        logger.info(f"[AI_SEARCH] User-focused query for: {target_user}")
    
    logger.info(f"[AI_SEARCH] Query mode: {query_mode}")
    
    # Step 4: Use intelligent sampler
    sampler = IntelligentSampler(opensearch_client, case_id)
    events, sampling_stats = sampler.sample_events(
        question=clean_question,
        keywords=keywords,
        dfir_terms=dfir_terms,
        exclusions=exclusion_clauses,
        mode=query_mode
    )
    
    # Step 5: If focused on user, get user timeline
    if target_user:
        user_events = get_user_timeline(opensearch_client, case_id, target_user, limit=30)
        # Merge with sampled events, deduplicate
        existing_ids = {e['_id'] for e in events}
        for ue in user_events:
            if ue['_id'] not in existing_ids:
                events.append(ue)
        events = events[:max_results]
    
    # Step 6: Detect MITRE techniques
    detected_techniques = detect_techniques_in_events(events)
    
    # Step 7: Determine kill chain phase
    kill_chain = determine_kill_chain_phase(detected_techniques)
    
    # Step 8: Get detected attack types for gap analysis
    detected_attack_types = []
    for pattern, category in QUESTION_PATTERNS:
        if re.search(pattern, clean_question.lower()):
            detected_attack_types.append(category.replace(' ', '_'))
    
    # Step 9: Semantic re-ranking (existing code)
    # ... existing re-ranking logic ...
    
    # Step 10: Prepare metadata for response
    metadata = {
        'sampling_stats': sampling_stats,
        'detected_techniques': detected_techniques,
        'kill_chain': kill_chain,
        'detected_attack_types': detected_attack_types,
        'target_user': target_user,
        'query_mode': query_mode,
        'exclusions_applied': len(exclusion_clauses) > 0,
    }
    
    explanation = f"Found {sampling_stats['total_events_in_case']:,} events, showing {len(events)} via intelligent sampling ({query_mode} mode)"
    
    return events[:max_results], explanation, metadata
```

### 11.4 Update generate_ai_answer()

```python
def generate_ai_answer(
    question: str,
    events: List[Dict],
    case_name: str,
    metadata: Dict,  # New parameter
    model: str = DEFAULT_LLM_MODEL,
    stream: bool = True
) -> Generator[str, None, None]:
    """Generate AI answer with V4 enhanced prompts."""
    
    # Get technique context
    technique_context = get_technique_context_for_prompt(metadata.get('detected_techniques', {}))
    
    # Get kill chain context
    kill_chain_context = get_kill_chain_context(metadata.get('kill_chain'))
    
    # Get gap analysis
    gap_analysis = get_gap_analysis(
        metadata.get('detected_attack_types', []),
        metadata.get('detected_techniques', {})
    )
    
    # Build events text
    events_text = build_events_text(events)  # Existing function
    
    # Select appropriate prompt
    query_mode = metadata.get('query_mode', 'big_picture')
    sampling_stats = metadata.get('sampling_stats', {})
    
    if query_mode == 'focused' and metadata.get('target_user'):
        prompt = FOCUSED_PROMPT.format(
            case_name=case_name,
            target_type='User',
            target_value=metadata['target_user'],
            question=question,
            user_analysis=format_user_analysis(metadata.get('user_analysis', {})),
            technique_context=technique_context,
            events_text=events_text,
        )
    elif query_mode == 'pattern':
        prompt = PATTERN_PROMPT.format(
            case_name=case_name,
            question=question,
            pattern_summary=format_pattern_summary(events),
            technique_context=technique_context,
            kill_chain_context=kill_chain_context,
            events_text=events_text,
        )
    else:
        prompt = BIG_PICTURE_PROMPT.format(
            case_name=case_name,
            case_overview=metadata.get('case_overview', ''),
            question=question,
            total_events=sampling_stats.get('total_events_in_case', 0),
            priority_events=sampling_stats.get('priority_events', 0),
            pattern_events=sampling_stats.get('pattern_events', 0),
            medium_events=sampling_stats.get('medium_events', 0),
            random_events=sampling_stats.get('random_events', 0),
            technique_context=technique_context,
            kill_chain_context=kill_chain_context,
            gap_analysis=gap_analysis,
            event_count=len(events),
            events_text=events_text,
        )
    
    # ... rest of LLM generation code ...
```

---

## 12. Testing Plan

### 12.1 Unit Tests

```python
# tests/test_rag_v4.py

def test_exclusion_extraction():
    # Test basic exclusion
    clean, explicit, category = extract_exclusions_from_question(
        "malware excluding veeam and defender"
    )
    assert clean == "malware"
    assert "veeam" in explicit
    assert "defender" in explicit
    
    # Test category exclusion
    clean, explicit, category = extract_exclusions_from_question(
        "lateral movement ignore security tools"
    )
    assert "sentinelone" in category or "crowdstrike" in category

def test_technique_detection():
    events = [{'_source': {'search_blob': 'powershell -enc abc123'}}]
    detected = detect_techniques_in_events(events)
    assert 'T1059.001' in detected

def test_kill_chain_mapping():
    techniques = {'T1003.001': [], 'T1021.002': []}
    result = determine_kill_chain_phase(techniques)
    assert result['current_phase'] in ['credential_access', 'lateral_movement']

def test_user_extraction():
    assert extract_target_user("how did john.doe get compromised") == "john.doe"
    assert extract_target_user("what happened to user admin") == "admin"
    assert extract_target_user("trace DOMAIN\\jsmith") == "jsmith"

def test_query_mode_detection():
    assert determine_query_mode("give me the big picture", []) == 'big_picture'
    assert determine_query_mode("how did john.doe get compromised", []) == 'focused'
    assert determine_query_mode("password spray attack", []) == 'pattern'
```

### 12.2 Integration Tests

```python
def test_full_pipeline_big_picture(opensearch_client, test_case_id):
    """Test big picture analysis on a large case."""
    question = "Do you see any signs of malware or suspicious activity?"
    
    events, explanation, metadata = semantic_search_events(
        opensearch_client, test_case_id, question
    )
    
    assert len(events) <= 25
    assert metadata['query_mode'] == 'big_picture'
    assert 'sampling_stats' in metadata
    assert metadata['sampling_stats']['priority_events'] > 0

def test_full_pipeline_focused(opensearch_client, test_case_id):
    """Test user-focused investigation."""
    question = "How did user john.doe get compromised?"
    
    events, explanation, metadata = semantic_search_events(
        opensearch_client, test_case_id, question
    )
    
    assert metadata['query_mode'] == 'focused'
    assert metadata['target_user'] == 'john.doe'

def test_exclusion_integration(opensearch_client, test_case_id):
    """Test that exclusions are applied correctly."""
    question = "malware excluding defender and sentinelone"
    
    events, explanation, metadata = semantic_search_events(
        opensearch_client, test_case_id, question
    )
    
    # Verify no defender/sentinelone in results
    for event in events:
        blob = event['_source'].get('search_blob', '').lower()
        assert 'defender' not in blob
        assert 'sentinelone' not in blob
```

### 12.3 Manual Testing Scenarios

| Scenario | Question | Expected Behavior |
|----------|----------|-------------------|
| Big picture | "What suspicious activity occurred?" | Samples across all event types, shows patterns |
| Exclusion | "Malware excluding veeam" | No veeam events in results |
| User focus | "How did john.doe get compromised?" | Timeline of john.doe events |
| Pattern | "Was there password spraying?" | Aggregation detects spray pattern |
| MITRE | "Any lateral movement?" | Shows T1021.xxx techniques |
| Gap analysis | "Any credential theft?" | Shows what to look for next |

---

## Appendix A: Constants Summary

```python
# Sampling
MAX_FINAL_EVENTS = 25
TIER_ALLOCATION = {'priority': 10, 'medium': 8, 'pattern': 4, 'random': 3}

# Thresholds
PASSWORD_SPRAY_THRESHOLD = 5  # Distinct users from single IP
LATERAL_MOVEMENT_THRESHOLD = 3  # Distinct sources to single target

# Timeouts
AGGREGATION_TIMEOUT = 15  # seconds
SEARCH_TIMEOUT = 30  # seconds

# Limits
MAX_EXCLUSION_TERMS = 50
MAX_KEYWORDS = 20
MAX_DFIR_TERMS = 30
```

---

## Appendix B: Performance Considerations

### For 20M Events

| Operation | Expected Time | Notes |
|-----------|---------------|-------|
| Exclusion parsing | <5ms | Regex only |
| Priority query | 200-500ms | Uses is_tagged, has_sigma indexes |
| Aggregation (password spray) | 2-5s | Cardinality aggregation |
| Aggregation (lateral movement) | 2-5s | Terms + cardinality |
| Random sampling | 500ms-1s | function_score with random |
| Technique detection | <50ms | In-memory regex |
| Total retrieval | 5-15s | Before LLM |
| LLM generation | 10-30s | Streaming |

### Optimization Recommendations

1. **Index tuning**: Ensure `sigma_level`, `is_tagged`, `has_ioc` are indexed for fast filtering
2. **Aggregation caching**: Consider caching pattern detection results for repeated queries
3. **Parallel aggregations**: Run password spray, lateral movement, process detection in parallel
4. **Early termination**: Stop aggregation if threshold met early

---

**Document Version**: 1.0  
**Last Updated**: November 27, 2025  
**Author**: Claude (Anthropic)  
**Status**: Ready for Implementation
