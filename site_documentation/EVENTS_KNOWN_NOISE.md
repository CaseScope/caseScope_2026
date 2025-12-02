# Events Known Noise - Technical Reference

Complete documentation for the Known-Noise Events detection and hiding system. This document provides enough detail to reconstruct the entire system.

---

## Overview

The Known-Noise Events system identifies and hides events that are routine Windows system operations, monitoring loops, and non-security-relevant activity. Events are marked with `is_hidden: true` in OpenSearch but remain searchable when analysts enable "Show Hidden" filter.

### Key Concepts

| Term | Description |
|------|-------------|
| **Known-Noise** | Events from routine Windows operations, monitoring loops, system accounts |
| **Hidden Event** | Event with `is_hidden: true` field in OpenSearch |
| **Noise Pattern** | Hardcoded pattern identifying system noise (not configurable) |
| **hidden_reason** | Field indicating why event was hidden: `noise_process`, `noise_command`, `firewall_noise` |

### Difference from Known-Good

| System | Configuration | Purpose |
|--------|---------------|---------|
| **Known-Good** | Database (System Settings) | Hide events from TRUSTED tools (RMM, EDR) |
| **Known-Noise** | Hardcoded patterns | Hide routine SYSTEM noise (Windows processes, monitoring) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PATTERN LAYER (Hardcoded)                        │
│  NOISE_PROCESSES: ['auditpol.exe', 'conhost.exe', 'runtimebroker.exe'] │
│  NOISE_USERS: {'SYSTEM', 'NETWORK SERVICE', 'DWM-1', ...}              │
│  NOISE_COMMAND_PATTERNS: ['netstat -ano', 'ipconfig /all', ...]        │
│  NOISE_IOC_VALUES: {'.net runtime', 'microsoft-windows-*', ...}        │
│  NOT_HOSTNAMES: {'system', 'server', 'unknown', ...}                   │
│  FIREWALL_NOISE_KEYWORDS: ['deny', 'drop', 'block', 'firewall']        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         MODULE LAYER                                     │
│  app/events_known_noise.py (standalone module)                          │
│  app/tasks.py (NOISE_PROCESSES, should_exclude_event)                  │
│  app/routes/triage_report.py (NOISE_USERS, NOT_HOSTNAMES)              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         EXECUTION LAYER                                  │
│  1. AI Triage: Filters noise from timeline tagging                      │
│  2. IOC Creation: Filters noise values from becoming IOCs               │
│  3. Bulk Hide: hide_noise_events() for manual cleanup                   │
│  4. Validation: is_noise_user(), is_noise_hostname() for IOC filtering │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         STORAGE LAYER                                    │
│  OpenSearch: case_{id} index                                            │
│  Event document: { ..., "is_hidden": true, "hidden_reason": "noise_*" }│
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Noise Definitions (Hardcoded)

### NOISE_PROCESSES

**File:** `app/events_known_noise.py` (lines 35-68)

Processes that are always system noise, never attack-related:

```python
NOISE_PROCESSES = [
    # Windows system management
    'auditpol.exe',      # Windows audit policy - often run by EDR/RMM
    'gpupdate.exe',      # Group policy update
    'wuauclt.exe',       # Windows Update
    'msiexec.exe',       # Installer
    'dism.exe',          # Deployment Image Service
    'sppsvc.exe',        # Software Protection Platform
    'winmgmt.exe',       # WMI service
    
    # Console/shell infrastructure (never useful alone)
    'conhost.exe',       # Console host - spawned by every cmd.exe
    'find.exe',          # Usually part of "command | find" pipes
    'findstr.exe',       # Same as find.exe
    'sort.exe',          # Pipe utility
    'more.com',          # Pipe utility
    
    # Monitoring/health check processes
    'tasklist.exe',      # Process listing (RMM monitoring loops)
    'quser.exe',         # Session queries (RMM health checks)
    'query.exe',         # Query commands
    
    # Windows runtime/background (system noise)
    'runtimebroker.exe', # Windows Runtime Broker
    'taskhostw.exe',     # Task Host Window
    'backgroundtaskhost.exe',  # Background task host
    'wmiprvse.exe',      # WMI Provider Host
    
    # Update/maintenance processes
    'huntressupdater.exe',     # Huntress updates
    'microsoftedgeupdate.exe', # Edge updates
    'fulltrustnotifier.exe',   # Adobe notifications
    'filecoauth.exe',          # Office/OneDrive co-auth
    
    # Search indexing
    'searchprotocolhost.exe',  # Windows Search
    'searchfilterhost.exe',    # Windows Search
]
```

### NOISE_USERS

**File:** `app/events_known_noise.py` (lines 70-76)

System accounts that are never real users:

```python
NOISE_USERS = {
    'system', 'network service', 'local service', 'anonymous logon',
    'window manager', 'dwm-1', 'dwm-2', 'dwm-3', 'dwm-4',
    'umfd-0', 'umfd-1', 'umfd-2', 'umfd-3',
    '-', 'n/a', '', 'font driver host', 'defaultaccount', 
    'guest', 'wdagutilityaccount'
}
```

### NOISE_IOC_VALUES

**File:** `app/events_known_noise.py` (lines 78-98)

Values that should never become IOCs:

```python
NOISE_IOC_VALUES = {
    # Windows Event Providers
    '.net runtime', 'microsoft-windows-security-auditing',
    'microsoft-windows-powershell', 'microsoft-windows-sysmon',
    'microsoft-windows-taskscheduler', 'microsoft-windows-dns-client',
    'microsoft-windows-kernel-general', 'microsoft-windows-kernel-power',
    'microsoft-windows-winlogon', 'microsoft-windows-user profiles service',
    'microsoft-windows-groupolicy', 'microsoft-windows-windowsupdateclient',
    'microsoft-windows-bits-client', 'microsoft-windows-eventlog',
    'microsoft-windows-wmi', 'service control manager', 'schannel',
    'application error', 'windows error reporting', 'volsnap',
    
    # Generic system terms
    'security', 'system', 'application', 'setup', 'forwarded events',
    'windows powershell', 'powershell', 'microsoft', 'windows',
    
    # Common noise strings
    'n/a', 'na', 'none', 'null', 'unknown', 'undefined', '-', '--', '---',
    'true', 'false', 'yes', 'no', '0', '1',
    
    # Local/loopback
    '127.0.0.1', '::1', 'localhost',
}
```

### NOT_HOSTNAMES

**File:** `app/events_known_noise.py` (lines 100-120)

Strings that should never be treated as hostnames:

```python
NOT_HOSTNAMES = {
    # Common words
    'the', 'and', 'from', 'with', 'this', 'that', 'was', 'has', 'been', ...
    
    # IT/Security terms that aren't hostnames
    'system', 'server', 'client', 'machine', 'computer', 'endpoint', 'device',
    'domain', 'local', 'remote', 'internal', 'external', 'unknown', 'none',
    'admin', 'administrator', 'root', 'guest', 'default', 'public', 'private',
    'powershell', 'cmd', 'command', 'script', 'executed', 'execution',
    'lateral', 'movement', 'persistence', 'credential', 'access', ...
}
```

### NOISE_COMMAND_PATTERNS

**File:** `app/events_known_noise.py` (lines 122-162)

Exact command patterns that are monitoring noise (only hidden when parent is generic):

```python
NOISE_COMMAND_PATTERNS = [
    # Network monitoring commands (run thousands of times by RMM/EDR)
    'netstat -ano',
    'netstat  -ano',
    'netstat -an',
    'ipconfig /all',
    
    # System info gathering (monitoring, not attacks)
    'systeminfo',
    'hostname',
    
    # Session/user queries (RMM health checks)
    'quser',
    '"quser"',
    'query user',
    
    # Process listing (RMM monitoring loops)
    'tasklist',
    
    # Pipe output filters
    'find /i',
    'find "',
    
    # Audit policy commands (EDR continuously sets these)
    'auditpol.exe /set',
    'auditpol /set',
    
    # Console host (spawned by every cmd.exe)
    'conhost.exe 0xffffffff',
    
    # PowerShell monitoring - Defender checks
    'get-mppreference',
    'get-mpthreat',
    'get-mpcomputerstatus',
]
```

### GENERIC_PARENTS

**File:** `app/events_known_noise.py` (lines 164-168)

When command is noise AND parent is generic, it's safe to hide:

```python
GENERIC_PARENTS = {
    'cmd.exe', 'svchost.exe', 'services.exe', 'wmiprvse.exe',
    'wmi provider host', 'powershell.exe', 'pwsh.exe'
}
```

### FIREWALL_NOISE_KEYWORDS

**File:** `app/events_known_noise.py` (lines 170-174)

Keywords indicating firewall/network logs that are noise:

```python
FIREWALL_NOISE_KEYWORDS = [
    'firewall', 'fw_', 'fw-', 'deny', 'drop', 'block', 'reject',
    'netflow', 'traffic', 'conn_state', 'action:deny', 'action:drop',
]
```

---

## Detection Logic

### Core Algorithm

**File:** `app/events_known_noise.py` → `is_noise_event()`

```python
def is_noise_event(event_data: Dict) -> bool:
    """
    Check if an event is known system noise.
    
    Detection Logic:
        1. Process name is in NOISE_PROCESSES
        2. Command line matches NOISE_COMMAND_PATTERNS (with generic parent)
        3. Event is only from noise user with no meaningful activity
    """
    proc = event_data.get('process', {})
    
    # Get process details
    proc_name = (proc.get('name') or proc.get('executable') or '').lower()
    if '\\' in proc_name:
        proc_name = proc_name.split('\\')[-1]
    
    command_line = proc.get('command_line', '')
    
    # Get parent info
    parent = proc.get('parent', {})
    parent_name = (parent.get('name') or '').lower()
    
    # CHECK 1: Noise process
    if proc_name and is_noise_process(proc_name):
        return True
    
    # CHECK 2: Noise command pattern with generic parent
    if command_line and is_noise_command(command_line, parent_name):
        return True
    
    return False
```

### Command Noise Logic

Commands are only considered noise when the parent is generic:

```python
def is_noise_command(command_line: str, parent_name: str = None) -> bool:
    """
    A command is considered noise if:
    1. It matches a NOISE_COMMAND_PATTERN exactly, AND
    2. The parent process is generic (cmd.exe, svchost.exe, etc.)
    
    If parent is suspicious (e.g., powershell spawning netstat), we KEEP it.
    """
    cmd_lower = command_line.lower().strip()
    
    # Check if command matches any noise pattern
    is_noise_pattern = any(pattern in cmd_lower for pattern in NOISE_COMMAND_PATTERNS)
    
    if not is_noise_pattern:
        return False
    
    # If parent is suspicious, keep the command
    if parent_name:
        parent_lower = parent_name.lower()
        if parent_lower not in GENERIC_PARENTS:
            return False  # Suspicious parent → keep this command
    
    return True
```

### Why Parent Context Matters

| Command | Parent | Action | Reason |
|---------|--------|--------|--------|
| `netstat -ano` | `cmd.exe` | **HIDE** | Generic parent = monitoring |
| `netstat -ano` | `mimikatz.exe` | **KEEP** | Suspicious parent = attack |
| `ipconfig /all` | `svchost.exe` | **HIDE** | System service = monitoring |
| `ipconfig /all` | `evil.exe` | **KEEP** | Unknown process = investigate |

---

## Files and Functions

### 1. `app/events_known_noise.py` (Standalone Module)

Primary module for noise detection. Can be called independently.

| Function | Purpose |
|----------|---------|
| `is_noise_process(name)` | Check if process name is noise |
| `is_noise_user(username)` | Check if username is system account |
| `is_noise_hostname(hostname)` | Check if hostname is invalid/generic |
| `is_noise_ioc_value(value)` | Check if value shouldn't be IOC |
| `is_noise_command(cmd, parent)` | Check if command is monitoring noise |
| `is_noise_event(event)` | **Core detection** - combines all rules |
| `is_firewall_noise(event)` | Check for DENY/DROP/BLOCK logs |
| `hide_noise_events(case_id, callback)` | Bulk hide all noise in case |
| `get_noise_estimate(case_id)` | Preview counts before hiding |
| `is_valid_hostname(hostname, ip_set)` | Validation helper |
| `is_machine_account(username)` | Check if username ends with `$` |

### 2. `app/tasks.py`

Contains noise filtering for AI Triage.

| Constant/Function | Purpose |
|-------------------|---------|
| `NOISE_PROCESSES` | List of noise process names |
| `NOISE_COMMAND_PATTERNS` | List of noise command patterns |
| `NOISE_IOC_VALUES` | Set of noise IOC values |
| `is_noise_ioc_value()` | Filter noise from IOC creation |
| `should_exclude_event()` | Checks `NOISE_PROCESSES` for timeline filtering |

### 3. `app/routes/triage_report.py`

Contains noise definitions used during IOC extraction.

| Constant/Function | Purpose |
|-------------------|---------|
| `NOISE_USERS` | Set of noise usernames |
| `NOT_HOSTNAMES` | Set of invalid hostname strings |
| `is_machine_account()` | Check for machine accounts (ends with `$`) |
| `is_valid_hostname()` | Validate hostname strings |

---

## OpenSearch Field

Events are marked hidden with category-specific reason:

```json
{
  "_source": {
    "process": { ... },
    "host": { ... },
    "is_hidden": true,
    "hidden_reason": "noise_process"  // or "noise_command", "firewall_noise"
  }
}
```

### Hidden Reason Values

| Reason | Meaning |
|--------|---------|
| `noise_process` | Process name matched `NOISE_PROCESSES` |
| `noise_command` | Command matched `NOISE_COMMAND_PATTERNS` with generic parent |
| `firewall_noise` | Event contained firewall keywords (deny/drop/block) |

---

## Integration Points

### 1. AI Triage Timeline Filtering

**When:** AI Triage decides which events to tag for timeline

**File:** `app/tasks.py` → `should_exclude_event()`

```python
# Check 0: Noise processes (system management, not attack-related)
if proc_name.replace('.exe', '') in [p.replace('.exe', '') for p in NOISE_PROCESSES]:
    return True  # Exclude from timeline
```

### 2. IOC Creation Filtering

**When:** AI Triage creates IOCs from discovered values

**File:** `app/tasks.py` → `add_ioc_if_new()`

```python
# v1.43.13: Skip noise IOC values (system providers, generic terms)
if is_noise_ioc_value(ioc_value):
    logger.debug(f"[AI_TRIAGE] Skipping noise IOC value: {ioc_value}")
    noise_values_filtered += 1
    return
```

### 3. Username Validation

**When:** Extracting usernames from events

**File:** `app/routes/triage_report.py`

```python
if name.lower() not in NOISE_USERS and not is_machine_account(name):
    usernames.add(name)
```

### 4. Hostname Validation

**When:** Extracting hostnames from events

**File:** `app/routes/triage_report.py`

```python
if is_valid_hostname(hostname, ip_set):
    hostnames.add(hostname)
```

### 5. Bulk Hide Operation

**When:** Manual cleanup of noise events

**Usage:**
```python
from events_known_noise import hide_noise_events

result = hide_noise_events(case_id=25)
# {'success': True, 'total_hidden': 5000, 'by_category': {...}}
```

---

## Usage Examples

### Check Single Event

```python
from events_known_noise import is_noise_event

event = {
    'process': {
        'name': 'conhost.exe',
        'command_line': 'conhost.exe 0xffffffff -ForceV1'
    }
}

if is_noise_event(event):
    print("Event is noise")  # True - conhost is in NOISE_PROCESSES
```

### Check Individual Components

```python
from events_known_noise import (
    is_noise_process,
    is_noise_user,
    is_noise_command,
    is_noise_ioc_value
)

# Process check
is_noise_process('conhost.exe')  # True
is_noise_process('cmd.exe')       # False (cmd itself isn't noise)

# User check
is_noise_user('SYSTEM')           # True
is_noise_user('BButler')          # False

# Command check (requires parent context)
is_noise_command('netstat -ano', 'cmd.exe')       # True (generic parent)
is_noise_command('netstat -ano', 'mimikatz.exe')  # False (suspicious parent)

# IOC value check
is_noise_ioc_value('.NET Runtime')                # True
is_noise_ioc_value('evil.exe')                    # False
```

### Bulk Hide All Noise

```python
from events_known_noise import hide_noise_events

def progress(status, processed, total, found):
    print(f"{status}: {processed}/{total}, found {found}")

result = hide_noise_events(case_id=25, progress_callback=progress)
# {
#     'success': True,
#     'total_scanned': 150000,
#     'total_hidden': 5000,
#     'by_category': {
#         'noise_process': 3000,
#         'noise_command': 1500,
#         'firewall_noise': 500
#     },
#     'errors': []
# }
```

### Get Noise Estimate (Preview)

```python
from events_known_noise import get_noise_estimate

estimate = get_noise_estimate(case_id=25)
# {
#     'noise_process': 3000,
#     'noise_command': 1500,
#     'firewall_noise': 500,
#     'total': 5000
# }
```

### Validate Hostname

```python
from events_known_noise import is_valid_hostname

is_valid_hostname('DC01', set())        # True - valid hostname
is_valid_hostname('system', set())      # False - in NOT_HOSTNAMES
is_valid_hostname('192.168.1.1', set()) # False - IP address
is_valid_hostname('AB', set())          # False - too short
```

---

## Version History

| Version | Changes |
|---------|---------|
| v1.39.0 | Initial noise filtering in AI Triage |
| v1.41.0 | Added `NOISE_COMMAND_PATTERNS` with parent context |
| v1.43.13 | Added `NOISE_IOC_VALUES` for IOC filtering |
| v1.44.0 | New standalone module `events_known_noise.py` |

---

## Reconstruction Checklist

To rebuild this system:

1. **Define Noise Patterns** (hardcoded in module)
   - `NOISE_PROCESSES`: System management executables
   - `NOISE_USERS`: System accounts
   - `NOISE_IOC_VALUES`: Values that shouldn't be IOCs
   - `NOISE_COMMAND_PATTERNS`: Monitoring commands
   - `NOT_HOSTNAMES`: Invalid hostname strings
   - `GENERIC_PARENTS`: Parent processes that indicate monitoring
   - `FIREWALL_NOISE_KEYWORDS`: Network log keywords

2. **Detection Functions**
   - `is_noise_process()`: Match against `NOISE_PROCESSES`
   - `is_noise_user()`: Match against `NOISE_USERS` + machine accounts
   - `is_noise_command()`: Match against `NOISE_COMMAND_PATTERNS` with parent check
   - `is_noise_event()`: Combine all checks
   - `is_firewall_noise()`: Check for firewall keywords

3. **Integration**
   - AI Triage: Filter noise from timeline tagging
   - IOC Creation: Filter noise values from becoming IOCs
   - Username/Hostname extraction: Validate against noise lists

4. **Bulk Operations**
   - `hide_noise_events()`: Scroll all events, check, bulk update
   - Track categories for reporting

5. **OpenSearch**
   - Set `is_hidden: true` with `hidden_reason: noise_*`
   - Use same filtering as Known-Good events

---

## Comparison: Known-Good vs Known-Noise

| Aspect | Known-Good | Known-Noise |
|--------|------------|-------------|
| **Configuration** | Database (System Settings) | Hardcoded patterns |
| **Admin UI** | Yes (`/settings/system-tools/`) | No (code changes only) |
| **Purpose** | Trusted tools (RMM, EDR) | System noise (Windows) |
| **Examples** | LTSVC.exe, HuntressAgent.exe | conhost.exe, auditpol.exe |
| **Module** | `events_known_good.py` | `events_known_noise.py` |
| **Context-aware** | Yes (session IDs, response patterns) | Yes (parent process) |
| **hidden_reason** | `auto_hide_index` | `noise_process`, `noise_command` |

