# Events Attack Patterns - Technical Reference

Complete documentation for the Attack Patterns detection system. This document provides enough detail to reconstruct the entire system.

---

## Overview

The Attack Patterns module is a centralized repository of ALL attack indicators used throughout CaseScope. It consolidates patterns from AI Triage, AI Search, and detection systems into a single, importable module.

### Key Concepts

| Term | Description |
|------|-------------|
| **Tier 1** | High confidence malicious - tag immediately with HIGH priority |
| **Tier 2** | Strong indicators - tag with MEDIUM priority |
| **Tier 3** | Context dependent - tag only if near other indicators |
| **Kill Chain** | MITRE ATT&CK framework phases (1-12) |
| **Detection Threshold** | Minimum counts to trigger pattern detection |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PATTERN DEFINITIONS                              │
│  TIER1_PATTERNS: encoded_powershell, credential_dumping, attack_tools   │
│  TIER2_PATTERNS: recon_commands, lateral_movement_tools, persistence    │
│  TIER3_PATTERNS: remote_access, archive, log_clearing, defense_evasion  │
│  RECON_COMMANDS: nltest, net group, whoami, systeminfo, etc.           │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         EVENT ID DEFINITIONS                             │
│  AV_DETECTION_EVENT_IDS: 1116, 1117, 1118, 1119, 5001, etc.            │
│  AUTH_EVENT_IDS: 4624, 4625, 4648, 4776, 6272, 6273, etc.              │
│  LOGON_TYPES: 2=Interactive, 3=Network, 9=PTH, 10=RDP                  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         KILL CHAIN MAPPING                               │
│  12 phases: Recon → Initial Access → Execution → Persistence →          │
│  Priv Esc → Defense Evasion → Cred Access → Discovery →                 │
│  Lateral Movement → Collection → Exfiltration → Impact                  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         CONSUMERS                                        │
│  • AI Triage Search (triage_patterns.py, tasks.py)                     │
│  • AI Search Button (ai_search.py)                                      │
│  • Pattern Detection (triage_patterns.py)                               │
│  • Timeline Tagging                                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Pattern Tiers

### TIER1_PATTERNS - High Confidence Malicious

**File:** `app/events_attack_patterns.py` (lines 32-89)

**Priority:** HIGH - Tag immediately, almost always malicious

```python
TIER1_PATTERNS = {
    'encoded_powershell': [
        '-enc', '-encodedcommand', '-e ', 'frombase64string',
        'invoke-expression', ' iex ', '[convert]::', 'decompress',
        'gzipstream', 'memorystream', 'io.compression',
    ],
    'credential_dumping': [
        'mimikatz', 'sekurlsa', 'logonpasswords', 'lsadump',
        'procdump.*lsass', 'comsvcs.*minidump', 'sqldumper',
        'ntds.dit', 'secretsdump', 'pypykatz', 'lazagne',
        'dcsync', 'kerberoast', 'asreproast',
    ],
    'attack_tools': [
        'bloodhound', 'sharphound', 'adfind', 'rubeus',
        'crackmapexec', 'impacket', 'cobalt', 'beacon',
        'meterpreter', 'empire', 'covenant', 'sliver',
        'poshc2', 'havoc', 'brute ratel',
    ],
    'ransomware_indicators': [
        'vssadmin delete shadows', 'bcdedit.*recoveryenabled.*no',
        'wbadmin delete catalog', 'delete shadowcopy', '.onion',
        'your files have been encrypted', 'decrypt.*bitcoin', 'ransom',
    ],
}
```

### TIER2_PATTERNS - Strong Indicators

**File:** `app/events_attack_patterns.py` (lines 97-237)

**Priority:** MEDIUM - Suspicious, warrants investigation

```python
TIER2_PATTERNS = {
    'recon_commands': [
        'nltest', 'net group', 'net user /domain', 'net localgroup',
        'whoami /all', 'whoami /priv', 'systeminfo', 'ipconfig /all',
        'netstat -ano', 'quser', 'query user', 'arp -a',
        'dsquery', 'csvde', 'ldifde', 'adfind',
        'get-aduser', 'get-adcomputer', 'get-adgroup',
        'get-addomain', 'get-adforest', 'dclist', 'domain trust',
    ],
    'lateral_movement_tools': [
        'psexec', 'paexec', 'wmic /node', 'winrm', 'winrs',
        'enter-pssession', 'invoke-command', 'invoke-wmimethod',
        'smbexec', 'wmiexec', 'atexec', 'dcomexec',
        'smbclient', 'evil-winrm',
    ],
    'persistence_mechanisms': [
        'schtasks /create', 'sc create', 'new-service',
        r'currentversion\\run', 'startup', 'userinit',
        'wmic startup', 'at \\\\',
        'new-scheduledtask', 'register-scheduledjob',
    ],
    'suspicious_downloads': [
        'certutil.*urlcache', 'certutil.*decode',
        'bitsadmin.*transfer', 'invoke-webrequest',
        'wget', 'curl.*-o', 'iwr.*-outfile',
        'downloadstring', 'downloadfile', 'start-bitstransfer',
    ],
    'process_injection': [
        'createremotethread', 'virtualallocex', 'writeprocessmemory',
        'ntqueueapcthread', 'setthreadcontext', 'reflective',
        'shellcode', 'inject',
    ],
}
```

### TIER3_PATTERNS - Context Dependent

**File:** `app/events_attack_patterns.py` (lines 162-237)

**Priority:** LOW - May be legitimate, tag only with other indicators

```python
TIER3_PATTERNS = {
    'remote_access_if_unexpected': [
        'anydesk', 'teamviewer', 'screenconnect', 'splashtop',
        'logmein', 'gotoassist', 'bomgar', 'connectwise',
        'dameware', 'vnc', 'radmin',
    ],
    'archive_with_password': [
        '7z a -p', 'rar a -hp', 'zip -e',
        'compress-archive', 'encrypted.*archive',
    ],
    'log_clearing': [
        'wevtutil cl', 'clear-eventlog',
        'del.*\\.evtx', 'remove-eventlog',
    ],
    'defense_evasion': [
        'set-mppreference -disablerealtimemonitoring',
        'sc stop', 'taskkill.*defender', 'netsh advfirewall set',
        'disable-windowsoptionalfeature', 'uninstall-windowsfeature',
        'remove-mppreference',
    ],
    'data_staging': [
        'compress-archive', 'tar -c', 'rar a', '7z a', 'makecab',
    ],
    'network_scanning': [
        'nmap', 'masscan', 'angry ip', 'advanced ip scanner',
        'network scanner', 'port scan', 'ping sweep',
    ],
}
```

---

## Recon Commands

**File:** `app/events_attack_patterns.py` (lines 240-278)

Commands used for discovery/enumeration - searched in AI Triage Phase 3:

```python
RECON_COMMANDS = [
    # Domain enumeration
    'nltest', 'net group', 'net user', 'net localgroup',
    'domain trust', 'dclist',
    
    # System information
    'whoami', 'ipconfig', 'systeminfo', 'hostname',
    
    # Session enumeration
    'quser', 'query user', 'net session',
    
    # Network enumeration
    'net view', 'net share', 'nslookup', 'ping', 'tracert',
    'route print', 'netstat', 'arp -a',
    
    # Process/service enumeration
    'tasklist', 'wmic process', 'wmic service',
    'get-process', 'get-service',
    
    # File system enumeration
    'reg query', 'dir /s', 'tree /f', 'get-childitem',
    
    # WMI enumeration
    'get-wmiobject', 'get-ciminstance',
]
```

---

## Event ID Definitions

### AV Detection Event IDs

**File:** `app/events_attack_patterns.py` (lines 280-322)

```python
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
    'threat', 'malware', 'quarantine', 'blocked', 'detected',
    'trojan', 'virus', 'ransomware', 'backdoor', 'exploit',
    'suspicious', 'malicious', 'potentially unwanted',
    'pua', 'pup', 'hacktool',
]
```

### Authentication Event IDs

**File:** `app/events_attack_patterns.py` (lines 325-355)

```python
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

# For pattern detection
FAILED_AUTH_EVENT_IDS = ['4625', '4771', '6273', '6274', '6276']
SUCCESS_AUTH_EVENT_IDS = ['4624', '4648', '6272']
```

### Logon Types

**File:** `app/events_attack_patterns.py` (lines 362-377)

```python
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

# Types that indicate potential lateral movement or PTH
SUSPICIOUS_LOGON_TYPES = ['3', '9', '10']
```

---

## Kill Chain Phases

**File:** `app/events_attack_patterns.py` (lines 384-555)

Full MITRE ATT&CK kill chain with 12 phases:

| Order | Phase | MITRE Tactic | Description |
|-------|-------|--------------|-------------|
| 1 | Reconnaissance | TA0043 | Gathering information about the target |
| 2 | Initial Access | TA0001 | Gaining first foothold |
| 3 | Execution | TA0002 | Running malicious code |
| 4 | Persistence | TA0003 | Maintaining access across reboots |
| 5 | Privilege Escalation | TA0004 | Gaining higher permissions |
| 6 | Defense Evasion | TA0005 | Avoiding detection |
| 7 | Credential Access | TA0006 | Stealing credentials |
| 8 | Discovery | TA0007 | Learning about environment |
| 9 | Lateral Movement | TA0008 | Moving through network |
| 10 | Collection | TA0009 | Gathering data to steal |
| 11 | Exfiltration | TA0010 | Stealing data out |
| 12 | Impact | TA0040 | Achieving objective (ransomware, destruction) |

```python
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
    # ... 11 more phases
}

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
    'Command and Control': 'collection',
    'Exfiltration': 'exfiltration',
    'Impact': 'impact',
}
```

---

## Question Classification Patterns

**File:** `app/events_attack_patterns.py` (lines 511-527)

For classifying AI Search questions into attack categories:

```python
QUESTION_PATTERNS = [
    (r'malware|virus|trojan|ransomware|infection|compromis', 'malware'),
    (r'lateral|spread|pivot|move.*between|hop|remote\s+exec', 'lateral_movement'),
    (r'persist|backdoor|maintain.*access|survive.*reboot', 'persistence'),
    (r'credential|password|hash|ticket|authenticat|dump|ntlm', 'credential_access'),
    (r'exfil|steal.*data|data.*theft|upload|send.*out|leak', 'exfiltration'),
    (r'c2|command.*control|beacon|callback|phone.*home', 'command_control'),
    (r'evad|bypass|disable|hide|obfuscat|tamper|kill.*av', 'defense_evasion'),
    (r'execut|run|launch|spawn|start.*process|command|invoke', 'execution'),
    (r'initial|entry|phish|deliver|land|foothold', 'initial_access'),
    (r'brute\s*force|password\s*spray|spray|failed\s*logon', 'brute_force'),
    (r'escalat|privilege|admin|root|system|uac', 'privilege_escalation'),
    (r'discover|enum|recon|gather|scan|survey', 'discovery'),
]
```

---

## Detection Thresholds

**File:** `app/events_attack_patterns.py` (lines 537-555)

Thresholds for pattern detection:

```python
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
```

---

## Helper Functions

### Pattern Matching

| Function | Purpose |
|----------|---------|
| `get_all_attack_keywords()` | Flat set of ALL keywords from all tiers |
| `get_tier1_keywords()` | Only Tier 1 (high confidence) keywords |
| `get_tier2_keywords()` | Only Tier 2 (strong indicator) keywords |
| `match_pattern_tier(search_blob)` | Match blob, returns `(tier, category, pattern)` |
| `get_patterns_for_category(cat)` | Get all patterns for a category |

### Kill Chain

| Function | Purpose |
|----------|---------|
| `get_kill_chain_phase(name)` | Get phase info by name |
| `get_phase_by_order(num)` | Get phase by order (1-12) |
| `determine_kill_chain_position(phases)` | Track current position in attack |

### Event Classification

| Function | Purpose |
|----------|---------|
| `classify_question(question)` | Classify AI Search question into category |
| `is_suspicious_logon_type(type)` | Check if logon type is suspicious (3, 9, 10) |
| `is_failed_auth_event(event_id)` | Check if event is failed authentication |
| `is_success_auth_event(event_id)` | Check if event is successful authentication |

---

## Usage Examples

### Match Event Against All Tiers

```python
from events_attack_patterns import match_pattern_tier

# Check if event contains attack patterns
search_blob = "mimikatz.exe sekurlsa::logonpasswords"
result = match_pattern_tier(search_blob)

if result:
    tier, category, pattern = result
    print(f"Tier {tier} match: {category} - matched '{pattern}'")
    # Output: Tier 1 match: credential_dumping - matched 'mimikatz'
```

### Get All Keywords for Broad Search

```python
from events_attack_patterns import get_all_attack_keywords, get_tier1_keywords

# Get ALL attack keywords
all_keywords = get_all_attack_keywords()
print(f"Total keywords: {len(all_keywords)}")

# Get only high-confidence keywords
tier1 = get_tier1_keywords()
print(f"Tier 1 keywords: {len(tier1)}")
```

### Track Kill Chain Position

```python
from events_attack_patterns import determine_kill_chain_position

# Based on detected phases
detected = ['execution', 'persistence', 'credential_access']
position = determine_kill_chain_position(detected)

print(f"Current phase: {position['current_phase_name']}")
print(f"Order: {position['current_order']}/12")
print(f"Next expected: {position['next_phase_name']}")
# Output:
# Current phase: Credential Access
# Order: 7/12
# Next expected: Discovery
```

### Classify User Question

```python
from events_attack_patterns import classify_question

question = "Did the attacker move laterally through the network?"
category = classify_question(question)
print(f"Question category: {category}")
# Output: Question category: lateral_movement
```

### Check Event IDs

```python
from events_attack_patterns import (
    is_failed_auth_event,
    is_success_auth_event,
    is_suspicious_logon_type,
    AUTH_EVENT_IDS
)

event_id = '4625'
if is_failed_auth_event(event_id):
    print(f"Failed auth: {AUTH_EVENT_IDS.get(event_id)}")
    # Output: Failed auth: Failed Logon

logon_type = '9'
if is_suspicious_logon_type(logon_type):
    print("Suspicious logon type - potential PTH!")
```

### Get Patterns by Category

```python
from events_attack_patterns import get_patterns_for_category

# Get all credential dumping patterns
cred_patterns = get_patterns_for_category('credential_dumping')
print(f"Credential patterns: {cred_patterns[:5]}")
# Output: ['mimikatz', 'sekurlsa', 'logonpasswords', 'lsadump', ...]
```

---

## Integration Points

### 1. AI Triage - Pattern Detection

**File:** `app/triage_patterns.py`

```python
from events_attack_patterns import (
    TIER1_PATTERNS, TIER2_PATTERNS, TIER3_PATTERNS,
    AV_DETECTION_EVENT_IDS, AV_DETECTION_KEYWORDS
)

# Use patterns for search queries
for category, patterns in TIER1_PATTERNS.items():
    for pattern in patterns:
        search_for(pattern)  # High priority tagging
```

### 2. AI Search - Question Classification

**File:** `app/ai_search.py`

```python
from events_attack_patterns import (
    QUESTION_PATTERNS,
    KILL_CHAIN_PHASES,
    classify_question
)

# Classify user question
category = classify_question(user_question)
# Adjust search strategy based on category
```

### 3. Timeline Tagging

**File:** `app/tasks.py`

```python
from events_attack_patterns import match_pattern_tier

# During timeline event processing
result = match_pattern_tier(event['search_blob'])
if result:
    tier, category, pattern = result
    if tier == 1:
        tag_event_high_priority(event)
    elif tier == 2:
        tag_event_medium_priority(event)
```

### 4. IOC Hunting

```python
from events_attack_patterns import RECON_COMMANDS

# Hunt for recon activity
for cmd in RECON_COMMANDS:
    results = search_for(cmd)
    if results:
        mark_as_discovered(cmd, results)
```

---

## Comparison to Other Modules

| Module | Purpose | Configuration |
|--------|---------|---------------|
| `events_attack_patterns.py` | Attack detection patterns | Hardcoded (security knowledge) |
| `events_known_good.py` | Trusted tool detection | Database (System Settings) |
| `events_known_noise.py` | System noise detection | Hardcoded (noise patterns) |

---

## Version History

| Version | Changes |
|---------|---------|
| v1.39.0 | Initial patterns in ai_search.py |
| v1.44.0 | Consolidated triage_patterns.py |
| v1.44.1 | New standalone module events_attack_patterns.py |

---

## Reconstruction Checklist

To rebuild this system:

1. **Define Pattern Tiers**
   - TIER1: High confidence malicious (always tag)
   - TIER2: Strong indicators (investigate)
   - TIER3: Context dependent (tag with other indicators)

2. **Define Event ID Lists**
   - AV detection event IDs
   - Authentication event IDs (success/fail)
   - Logon types with descriptions

3. **Define Kill Chain**
   - 12 phases with MITRE tactic mappings
   - Keywords for each phase
   - Typical next/previous phase relationships

4. **Define Detection Thresholds**
   - Password spray: unique targets threshold
   - Brute force: attempts threshold
   - Lateral movement: systems threshold

5. **Helper Functions**
   - Pattern matching (return tier/category)
   - Kill chain position tracking
   - Event classification

6. **Integration**
   - Import from central module in all consumers
   - No duplicate pattern definitions
   - Single source of truth for attack knowledge

