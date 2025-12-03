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
| **hidden_reason** | Field indicating why event was hidden (see Hidden Reason Values) |

### Difference from Known-Good

| System | Configuration | Purpose |
|--------|---------------|---------|
| **Known-Good** | Database (System Settings) | Hide events from TRUSTED tools (RMM, EDR) |
| **Known-Noise** | Hardcoded patterns | Hide routine SYSTEM noise (Windows processes, monitoring) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    CENTRALIZED PATTERN LAYER                             │
│  app/noise_filters.py (Single Source of Truth)                          │
│  ├── NOISE_PROCESSES: 109 background processes                         │
│  ├── NOISE_USERS: 23 system accounts                                   │
│  ├── NOISE_IOC_VALUES: System providers, generic terms                 │
│  ├── NOT_HOSTNAMES: Invalid hostname strings                           │
│  ├── NOISE_COMMAND_PATTERNS: Monitoring commands                        │
│  ├── NOISE_PATH_PATTERNS: Common noise paths                           │
│  ├── NOISE_EVENT_IDS: Event IDs that are usually noise                 │
│  └── GENERIC_PARENTS: Generic parent processes                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────────┐
│ events_known_noise.py │ │ ai_triage_find_iocs.py│ │ ai_triage_tag_iocs.py │
│ ├── is_noise_event()  │ │ ├── IOC discovery     │ │ ├── Event tagging     │
│ ├── is_firewall_noise │ │ ├── Noise filtering   │ │ ├── Noise filtering   │
│ ├── process_slice()   │ │ └── Snowball hunting  │ │ └── High-confidence   │
│ └── bulk_hide_events()│ │                       │ │                       │
└───────────────────────┘ └───────────────────────┘ └───────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         EXECUTION LAYER                                  │
│  1. During Indexing: file_processing.apply_auto_hide_noise()           │
│     → Runs AFTER apply_auto_hide() for known-good                      │
│  2. Bulk Hide (Parallel): tasks.hide_noise_events_task()               │
│     → Dispatches 8x hide_noise_slice_task() workers                    │
│  3. AI Triage Find IOCs: Filters noise from snowball hunting           │
│  4. AI Triage Tag Events: Filters noise from auto-tagging              │
│  5. IOC Creation: Filters noise values from becoming IOCs              │
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

## Noise Definitions (Centralized)

All noise patterns are defined in **`app/noise_filters.py`** - the single source of truth.

### NOISE_PROCESSES (109 processes)

**File:** `app/noise_filters.py` (lines 51-108)

Processes that are always system noise, never attack-related:

```python
NOISE_PROCESSES: Set[str] = {
    # Windows system management
    'auditpol.exe', 'gpupdate.exe', 'wuauclt.exe', 'msiexec.exe',
    'dism.exe', 'sppsvc.exe', 'winmgmt.exe', 'dismhost.exe',
    'trustedinstaller.exe', 'tiworker.exe',
    
    # Console/shell infrastructure
    'conhost.exe', 'find.exe', 'findstr.exe', 'sort.exe', 'more.com',
    
    # Monitoring/health check
    'tasklist.exe', 'quser.exe', 'query.exe',
    
    # Windows runtime/background
    'runtimebroker.exe', 'taskhostw.exe', 'backgroundtaskhost.exe',
    'wmiprvse.exe', 'sihost.exe', 'backgroundtransferhost.exe',
    
    # Browsers (background noise)
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe',
    
    # Adobe - comprehensive list
    'adobearm.exe', 'acrord32.exe', 'acrobat.exe', 'acrocef.exe', ...
    
    # Microsoft Office
    'officebackgroundtaskhandler.exe', 'officeclicktorun.exe',
    'outlook.exe', 'excel.exe', 'winword.exe', 'powerpnt.exe',
    
    # Common software
    'dropbox.exe', 'onedrive.exe', 'teams.exe', 'slack.exe', 'zoom.exe',
    
    # AV/Security (routine operations)
    'msmpeng.exe', 'sentinelui.exe', 'sentinelagent.exe',
}
```

### NOISE_USERS (23 accounts)

**File:** `app/noise_filters.py` (lines 30-46)

System accounts that are never real users:

```python
# NOTE: Do NOT include '' - empty usernames handled by is_noise_user()
NOISE_USERS: Set[str] = {
    # Windows system accounts
    'system', 'network service', 'local service', 'anonymous logon',
    'window manager', 'font driver host', 
    # DWM/UMFD accounts
    'dwm-1', 'dwm-2', 'dwm-3', 'dwm-4',
    'umfd-0', 'umfd-1', 'umfd-2', 'umfd-3',
    # Built-in accounts
    'defaultaccount', 'guest', 'wdagutilityaccount',
    # NT Authority accounts (with domain prefix)
    'nt authority\\system', 'nt authority\\local service', 
    'nt authority\\network service', 'nt authority\\anonymous logon',
    # Placeholder values
    '-', 'n/a',
}
```

### NOISE_IOC_VALUES

**File:** `app/noise_filters.py` (lines 210-236)

Values that should never become IOCs:

```python
NOISE_IOC_VALUES: Set[str] = {
    # Windows Event Providers
    '.net runtime', 'microsoft-windows-security-auditing',
    'microsoft-windows-powershell', 'microsoft-windows-sysmon', ...
    
    # Generic system terms
    'security', 'system', 'application', 'setup', 'forwarded events',
    'windows powershell', 'powershell', 'microsoft', 'windows',
    
    # Common noise strings
    'n/a', 'na', 'none', 'null', 'unknown', 'undefined', '-', '--', '---',
    
    # Local/loopback
    '127.0.0.1', '::1', 'localhost',
}
```

### NOT_HOSTNAMES

**File:** `app/noise_filters.py` (lines 243-266)

Strings that should NOT be treated as hostnames:

```python
NOT_HOSTNAMES: Set[str] = {
    # Common words
    'the', 'and', 'from', 'with', 'this', 'that', 'was', 'has', 'been', ...
    
    # IT/Security terms
    'system', 'server', 'client', 'machine', 'computer', 'endpoint',
    'domain', 'local', 'remote', 'internal', 'external', 'unknown',
    'powershell', 'cmd', 'command', 'script', 'executed', 'execution',
    'lateral', 'movement', 'persistence', 'credential', 'access',
}
```

### NOISE_COMMAND_PATTERNS

**File:** `app/noise_filters.py` (lines 149-186)

Exact command patterns that are monitoring noise (only hidden when parent is generic):

```python
NOISE_COMMAND_PATTERNS = [
    # Network monitoring (run thousands of times by RMM/EDR)
    'netstat -ano', 'netstat -an', 'ipconfig /all',
    
    # System info gathering
    'systeminfo', 'hostname',
    
    # Session/user queries (RMM health checks)
    'quser', 'query user',
    
    # Process listing
    'tasklist',
    
    # Audit policy (EDR continuously sets these)
    'auditpol.exe /set', 'auditpol /set',
    
    # Console host
    'conhost.exe 0xffffffff',
    
    # PowerShell monitoring - Defender checks
    'get-mppreference', 'get-mpthreat', 'get-mpcomputerstatus',
]
```

### GENERIC_PARENTS

**File:** `app/noise_filters.py` (lines 200-204)

When command is noise AND parent is generic, it's safe to hide:

```python
GENERIC_PARENTS: Set[str] = {
    'cmd.exe', 'svchost.exe', 'services.exe', 'wmiprvse.exe',
    'wmi provider host', 'powershell.exe', 'pwsh.exe'
}
```

### NOISE_EVENT_IDS

**File:** `app/noise_filters.py` (lines 193-198)

Event IDs that are usually noise even with IOC matches:

```python
NOISE_EVENT_IDS: Set[int] = {
    4689,   # Process termination (just shows process ended)
    7036,   # Service state change
    7040,   # Service start type changed
    7045,   # New service installed
}
```

### FIREWALL_NOISE_KEYWORDS (Module-Specific)

**File:** `app/events_known_noise.py` (lines 47-50)

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

**File:** `app/events_known_noise.py` → `is_noise_event()` (uses functions from `noise_filters.py`)

```python
# Imports from centralized module
from noise_filters import (
    NOISE_USERS, NOISE_PROCESSES, NOISE_IOC_VALUES, NOT_HOSTNAMES,
    NOISE_COMMAND_PATTERNS, GENERIC_PARENTS,
    is_noise_user, is_noise_process, is_noise_command, is_noise_ioc_value,
    is_noise_hostname, is_machine_account,
)

def is_noise_event(event_data: Dict) -> bool:
    """
    Check if an event is known system noise.
    
    Detection Logic:
        1. Process name is in NOISE_PROCESSES
        2. Command line matches NOISE_COMMAND_PATTERNS (with generic parent)
    """
    proc = event_data.get('process', {})
    
    # Get process details
    proc_name = (proc.get('name') or proc.get('executable') or '').lower()
    if '\\' in proc_name:
        proc_name = proc_name.split('\\')[-1]
    
    command_line = proc.get('command_line', '')
    
    # Get parent info (handle None parent)
    parent = proc.get('parent') or {}
    parent_name = (parent.get('name') or parent.get('executable') or '').lower()
    
    # CHECK 1: Noise process (uses centralized is_noise_process)
    if proc_name and is_noise_process(proc_name):
        return True
    
    # CHECK 2: Noise command pattern with generic parent
    if command_line and is_noise_command(command_line, parent_name):
        return True
    
    return False
```

### Command Noise Logic

**File:** `app/noise_filters.py` → `is_noise_command()`

Commands are only considered noise when the parent is generic:

```python
def is_noise_command(cmd: str, parent_name: str = None) -> bool:
    """
    A command is considered noise if:
    1. It matches a NOISE_COMMAND_PATTERN exactly, AND
    2. The parent process is generic (cmd.exe, svchost.exe, etc.)
    
    If parent is suspicious (e.g., mimikatz spawning netstat), we KEEP it.
    """
    if not cmd:
        return False
    
    cmd_lower = cmd.lower().strip()
    
    # Check against noise patterns
    for pattern in NOISE_COMMAND_PATTERNS:
        if pattern in cmd_lower:
            break
    else:
        return False  # No pattern matched
    
    # If parent is suspicious, keep the command
    if parent_name:
        parent_lower = parent_name.lower()
        parent_base = parent_lower.split('\\')[-1]
        if parent_base not in GENERIC_PARENTS:
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

### 1. `app/noise_filters.py` (Centralized Module - Single Source of Truth)

Contains all noise pattern constants and detection functions. Other modules import from here.

| Constants | Description |
|-----------|-------------|
| `NOISE_USERS` | 23 system accounts |
| `NOISE_PROCESSES` | 109 background processes |
| `NOISE_PATH_PATTERNS` | Common noise paths |
| `NOISE_COMMAND_PATTERNS` | Monitoring commands |
| `NOISE_IOC_VALUES` | Values that shouldn't be IOCs |
| `NOT_HOSTNAMES` | Invalid hostname strings |
| `NOISE_EVENT_IDS` | Event IDs that are usually noise |
| `GENERIC_PARENTS` | Generic parent processes |

| Function | Purpose |
|----------|---------|
| `is_noise_user(username)` | Check if username is system account |
| `is_machine_account(username)` | Check if username ends with `$` |
| `is_noise_process(proc_name)` | Check if process name is noise |
| `is_noise_path(path)` | Check if path matches noise pattern |
| `is_noise_command(cmd, parent)` | Check if command is monitoring noise |
| `is_noise_hostname(hostname)` | Check if hostname is invalid/generic |
| `is_noise_ioc_value(value)` | Check if value shouldn't be IOC |
| `is_valid_ip(ip_str)` | Validate IP address format |
| `is_private_ip(ip_str)` | Check if IP is private/internal |
| `is_external_ip(ip_str)` | Check if IP is external |
| `is_ip_in_range(ip_str, cidr)` | Check if IP is in CIDR range |

### 2. `app/events_known_noise.py` (Primary Detection Module)

Imports from `noise_filters.py` and adds module-specific logic for event detection.

| Function | Purpose |
|----------|---------|
| `is_noise_event(event)` | **Core detection** - combines all rules |
| `is_firewall_noise(event)` | Check for firewall keywords |
| `process_slice(case_id, slice_id, max_slices, client)` | Process 1/N slice for parallel workers |
| `bulk_hide_events(events_list, client, index)` | Bulk update to set is_hidden=True |
| `hide_noise_events(case_id, callback)` | Legacy single-threaded bulk hide |
| `get_noise_estimate(case_id)` | Preview counts before hiding |
| `is_valid_hostname(hostname, ip_set)` | Validation helper |

| Module-Specific Constants | Purpose |
|---------------------------|---------|
| `FIREWALL_NOISE_KEYWORDS` | Keywords for firewall log detection |

### 3. `app/ai_triage_find_iocs.py` (IOC Discovery Module)

Imports from `noise_filters.py` for noise filtering during snowball hunting.

| Function | Purpose |
|----------|---------|
| `find_potential_iocs(case_id)` | Main entry point for IOC discovery |
| `search_events_with_iocs(case_id, iocs)` | Query OpenSearch for matching events |
| `extract_iocs_from_events(events, context)` | Extract new IOCs with noise filtering |
| `check_managed_tool(proc, blob, tools)` | Check RMM/EDR tool ID verification |
| `contains_existing_ioc(value, existing)` | Check if value contains existing IOC |

### 4. `app/ai_triage_tag_iocs.py` (Event Tagging Module)

Imports from `noise_filters.py` for noise filtering during auto-tagging.

| Function | Purpose |
|----------|---------|
| `tag_high_confidence_events(case_id, user_id)` | Main entry point for event tagging |
| `get_high_confidence_iocs(case_id)` | Get IOCs for tagging criteria |
| `get_actor_systems(case_id)` | Get actor system hostnames/IPs |
| `search_events_for_tagging(case_id, query)` | Query OpenSearch with scroll |
| `is_noise_event(event)` | Module-specific noise event check |
| `tag_event(case_id, user_id, event, match)` | Create TimelineTag entry |

### 5. `app/file_processing.py`

Applies auto-hide noise during file indexing.

| Function | Purpose |
|----------|---------|
| `apply_auto_hide_noise(event)` | Check event against noise patterns, set `is_hidden=True` |

**Usage in indexing loop:**
```python
from events_known_noise import is_noise_event, is_firewall_noise

# Called AFTER apply_auto_hide() for known-good
event = apply_auto_hide(event, auto_hide_exclusions)  # Known-good first
event = apply_auto_hide_noise(event)                   # Noise second (skips if already hidden)
```

**Order of operations:**
1. `apply_auto_hide()` → Check known-good patterns (RMM, EDR, IPs)
2. `apply_auto_hide_noise()` → Check noise patterns (**skips if already hidden**)

### 6. `app/tasks.py`

Contains Celery tasks for parallel bulk hide operation.

| Function/Task | Purpose |
|---------------|---------|
| `hide_noise_events_task(case_id, user_id)` | **Coordinator task** - dispatches 8 parallel workers |
| `hide_noise_slice_task(case_id, slice_id, max_slices, user_id)` | **Worker task** - processes 1/8 of events |
| `should_exclude_event(event, exclusions)` | Checks noise processes for AI Triage filtering |

**Parallel Processing:**
```python
NOISE_PARALLEL_SLICES = 8  # Use all 8 workers

# Coordinator dispatches 8 parallel slice tasks
slice_tasks = group([
    hide_noise_slice_task.s(case_id, i, NOISE_PARALLEL_SLICES, user_id)
    for i in range(NOISE_PARALLEL_SLICES)
])
group_result = slice_tasks.apply_async()

# Each slice uses OpenSearch sliced scroll
query = {
    "slice": {"id": slice_id, "max": max_slices},
    "query": {"bool": {"must_not": [{"term": {"is_hidden": True}}]}}
}
```

### 7. `app/routes/system_tools.py`

Routes for triggering bulk hide and polling status.

| Route | Method | Purpose |
|-------|--------|---------|
| `/settings/system-tools/case/<id>/hide-noise` | POST | Start parallel bulk hide task |
| `/settings/system-tools/case/<id>/hide-noise/status/<task_id>` | GET | Poll task progress |

---

## OpenSearch Field

Events are marked hidden with category-specific reason:

```json
{
  "_source": {
    "process": { ... },
    "host": { ... },
    "is_hidden": true,
    "hidden_reason": "noise_auto_index"
  }
}
```

### Hidden Reason Values

| Reason | Source | Meaning |
|--------|--------|---------|
| `noise_auto_index` | Indexing | Process/command noise detected during file indexing |
| `firewall_noise_auto_index` | Indexing | Firewall noise detected during file indexing |
| `noise_noise_process` | Bulk Hide | Process matched `NOISE_PROCESSES` via button |
| `noise_noise_command` | Bulk Hide | Command matched `NOISE_COMMAND_PATTERNS` via button |
| `noise_firewall_noise` | Bulk Hide | Firewall keywords detected via button |

---

## Integration Points

### 1. File Indexing (Automatic)

**When:** Initial index, reindex, bulk reindex

**File:** `app/file_processing.py` → `apply_auto_hide_noise()`

```python
def apply_auto_hide_noise(event: dict) -> dict:
    """
    Check if event should be auto-hidden as noise.
    Called AFTER apply_auto_hide() - skips if already hidden.
    """
    # Skip if already hidden (don't overwrite known-good reason)
    if event.get('is_hidden'):
        return event
    
    # Check for noise process/command
    if is_noise_event(event):
        event['is_hidden'] = True
        event['hidden_reason'] = 'noise_auto_index'
        return event
    
    # Check for firewall noise
    if is_firewall_noise(event):
        event['is_hidden'] = True
        event['hidden_reason'] = 'firewall_noise_auto_index'
        return event
    
    return event
```

**Indexing locations:**
- CSV file processing (line ~1020)
- JSON/NDJSON file processing (line ~1090)
- EVTX file processing (line ~1220)

### 2. Bulk Hide Task (Manual Trigger - Parallel)

**When:** User clicks "Hide Noise" button on Search Events page

**Flow:**
1. `POST /settings/system-tools/case/{id}/hide-noise` → `routes/system_tools.py`
2. Starts Celery task `tasks.hide_noise_events_task` (coordinator)
3. Coordinator dispatches 8 parallel `hide_noise_slice_task` workers
4. Each worker uses OpenSearch sliced scroll to process 1/8 of events
5. Workers call `is_noise_event()` and `is_firewall_noise()` from `events_known_noise.py`
6. Results aggregated with category breakdown
7. Progress updates sent as each worker completes

### 3. AI Triage Timeline Filtering

**When:** AI Triage decides which events to tag for timeline

**File:** `app/tasks.py` → `should_exclude_event()`

```python
# Check noise processes (system management, not attack-related)
if proc_name.replace('.exe', '') in [p.replace('.exe', '') for p in NOISE_PROCESSES]:
    return True  # Exclude from timeline
```

### 4. IOC Creation Filtering

**When:** AI Triage creates IOCs from discovered values

**File:** `app/tasks.py` → `add_ioc_if_new()`

```python
# v1.43.13: Skip noise IOC values (system providers, generic terms)
if is_noise_ioc_value(ioc_value):
    logger.debug(f"[AI_TRIAGE] Skipping noise IOC value: {ioc_value}")
    return
```

### 5. Username Validation

**When:** Extracting usernames from events

**File:** `app/routes/triage_report.py`

```python
if name.lower() not in NOISE_USERS and not is_machine_account(name):
    usernames.add(name)
```

### 6. Hostname Validation

**When:** Extracting hostnames from events

**File:** `app/routes/triage_report.py`

```python
if is_valid_hostname(hostname, ip_set):
    hostnames.add(hostname)
```

---

## Templates

### Search Events Page

**File:** `app/templates/search_events.html`

- "Hide Noise" button (🔇) triggers modal
- Modal shows noise categories summary
- Progress display with worker completion tracking
- Results show events hidden count with category breakdown

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

### Bulk Hide All Noise (Parallel)

The parallel bulk hide is triggered via the UI button, which calls:

```python
# In routes/system_tools.py
from tasks import hide_noise_events_task

task = hide_noise_events_task.delay(case_id=25, user_id=1)
# Returns task_id for progress polling
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
| v1.46.0 | Parallel processing with 8 Celery workers, UI button, routes |
| v1.46.1 | Auto-hide noise during indexing (after known-good) |
| v1.46.3 | Centralized noise_filters.py as single source of truth |

---

## Reconstruction Checklist

To rebuild this system:

1. **Centralized Noise Filters** (`noise_filters.py`)
   - `NOISE_USERS`: 23 system accounts
   - `NOISE_PROCESSES`: 109 background processes
   - `NOISE_PATH_PATTERNS`: Common noise paths
   - `NOISE_COMMAND_PATTERNS`: Monitoring commands
   - `NOISE_IOC_VALUES`: Values that shouldn't be IOCs
   - `NOT_HOSTNAMES`: Invalid hostname strings
   - `NOISE_EVENT_IDS`: Event IDs that are usually noise
   - `GENERIC_PARENTS`: Parent processes that indicate monitoring
   - All `is_noise_*()` detection functions
   - All `is_*_ip()` validation functions

2. **Detection Module** (`events_known_noise.py`)
   - Import constants and functions from `noise_filters.py`
   - Add `FIREWALL_NOISE_KEYWORDS` (module-specific)
   - `is_noise_event()`: Combine all checks for events
   - `is_firewall_noise()`: Check for firewall keywords
   - `process_slice()`: Parallel processing with sliced scroll
   - `bulk_hide_events()`: Batch update events

3. **Triage Modules** (use centralized filters)
   - `ai_triage_find_iocs.py`: Import from `noise_filters.py`
   - `ai_triage_tag_iocs.py`: Import from `noise_filters.py`

4. **Indexing Integration** (`file_processing.py`)
   - Add `apply_auto_hide_noise()` function
   - Call after `apply_auto_hide()` in all 3 indexing locations
   - Skip if event already hidden (preserve known-good reason)

5. **Celery Tasks** (`tasks.py`)
   - `hide_noise_events_task`: Coordinator dispatches 8 workers
   - `hide_noise_slice_task`: Worker processes 1/8 of events

6. **Routes** (`system_tools.py`)
   - `POST /settings/system-tools/case/<id>/hide-noise`: Start task
   - `GET /settings/system-tools/case/<id>/hide-noise/status/<task_id>`: Poll progress

7. **Frontend** (`search_events.html`)
   - "Hide Noise" button on Search Events page
   - Modal with progress and results display

8. **OpenSearch**
   - Set `is_hidden: true` with `hidden_reason: noise_*`
   - Use same filtering as Known-Good events

---

## Comparison: Known-Good vs Known-Noise

| Aspect | Known-Good | Known-Noise |
|--------|------------|-------------|
| **Configuration** | Database (System Settings) | Hardcoded patterns (`noise_filters.py`) |
| **Admin UI** | Yes (`/settings/system-tools/`) | No (code changes only) |
| **Purpose** | Trusted tools (RMM, EDR) | System noise (Windows) |
| **Examples** | LTSVC.exe, HuntressAgent.exe | conhost.exe, auditpol.exe |
| **Primary Module** | `events_known_good.py` | `events_known_noise.py` |
| **Centralized Constants** | N/A | `noise_filters.py` (shared with triage) |
| **Context-aware** | Yes (session IDs, response patterns) | Yes (parent process) |
| **Auto-hide on Index** | Yes (`apply_auto_hide`) | Yes (`apply_auto_hide_noise`) |
| **Indexing Order** | First | Second (skips if already hidden) |
| **hidden_reason** | `auto_hide_index` | `noise_auto_index`, `firewall_noise_auto_index` |
| **Parallel Workers** | 8 (sliced scroll) | 8 (sliced scroll) |
| **UI Button** | "Hide Known Good" (🛡️) | "Hide Noise" (🔇) |
