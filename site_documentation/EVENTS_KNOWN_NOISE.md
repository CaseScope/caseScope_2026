# Events Known Noise - Technical Reference

Complete documentation for the Known-Noise Events detection and marking system. This document provides enough detail to reconstruct the entire system.

---

## Overview

The Known-Noise Events system identifies and marks events that are routine Windows system operations, monitoring loops, and non-security-relevant activity. Events are marked with `event_status='noise'` in both OpenSearch and the database, and remain searchable when analysts enable the "Noise" status filter.

### Key Concepts

| Term | Description |
|------|-------------|
| **Known-Noise** | Events from routine Windows operations, monitoring loops, system accounts |
| **Noise Event** | Event with `event_status='noise'` in OpenSearch AND `status='noise'` in database |
| **Noise Pattern** | Hardcoded pattern identifying system noise (not configurable) |
| **status_reason** | Field indicating why event was marked as noise (see Status Reason Values) |

### Difference from Known-Good

| System | Configuration | Purpose |
|--------|---------------|---------|
| **Known-Good** | Database (System Settings) | Mark events from TRUSTED tools (RMM, EDR) |
| **Known-Noise** | Hardcoded patterns | Mark routine SYSTEM noise (Windows processes, monitoring) |

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
│  2. Reindex Phase 5 (Parallel v2.1.0): hide_noise_all_task()          │
│     → Dispatches 8x hide_noise_slice_task() workers                    │
│  3. Manual Hide Button: Same as Phase 5                                │
│  4. AI Triage Find IOCs: Filters noise from snowball hunting           │
│  5. AI Triage Tag Events: Filters noise from auto-tagging              │
│  6. IOC Creation: Filters noise values from becoming IOCs              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         STORAGE LAYER (DUAL SYSTEM)                      │
│  OpenSearch: case_{id} index                                            │
│  └─ Event doc: { ..., "event_status": "noise", "status_reason": "..." }│
│  PostgreSQL: event_status table                                         │
│  └─ Record: { case_id, event_id, status: "noise", notes: "..." }      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Noise Definitions (Centralized)

All noise patterns are defined in **`app/noise_filters.py`** - the single source of truth.

### NOISE_PROCESSES (109 processes)

**File:** `app/noise_filters.py`

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

**File:** `app/noise_filters.py`

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

### NOISE_COMMAND_PATTERNS

**File:** `app/noise_filters.py`

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

**File:** `app/noise_filters.py`

When command is noise AND parent is generic, it's safe to hide:

```python
GENERIC_PARENTS: Set[str] = {
    'cmd.exe', 'svchost.exe', 'services.exe', 'wmiprvse.exe',
    'wmi provider host', 'powershell.exe', 'pwsh.exe'
}
```

### FIREWALL_NOISE_KEYWORDS (Module-Specific)

**File:** `app/events_known_noise.py`

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

### 2. `app/events_known_noise.py` (Primary Detection Module)

Imports from `noise_filters.py` and adds module-specific logic for event detection.

| Function | Purpose |
|----------|---------|
| `is_noise_event(event)` | **Core detection** - combines all rules |
| `is_firewall_noise(event)` | Check for firewall keywords |
| `process_slice(case_id, slice_id, max_slices, client)` | Process 1/N slice for parallel workers |
| `bulk_hide_events(events_list, client, index, case_id)` | Bulk update to set event_status='noise' in both OpenSearch and database |
| `hide_noise_all_task(case_id)` | Celery coordinator task - dispatches 8 workers (v2.1.0) |
| `hide_noise_slice_task(case_id, slice_id, max_slices)` | Celery worker task - processes 1/8 of events (v2.1.0) |
| `get_noise_estimate(case_id)` | Preview counts before hiding |

| Module-Specific Constants | Purpose |
|---------------------------|---------|
| `FIREWALL_NOISE_KEYWORDS` | Keywords for firewall log detection |

### 3. `app/file_processing.py`

Applies auto-hide noise during file indexing.

| Function | Purpose |
|----------|---------|
| `apply_auto_hide_noise(event)` | Check event against noise patterns, set `event_status='noise'` |

**Usage in indexing loop:**
```python
from events_known_noise import is_noise_event, is_firewall_noise

# Called AFTER apply_auto_hide() for known-good
event = apply_auto_hide(event, auto_hide_exclusions)  # Known-good first
event = apply_auto_hide_noise(event)                   # Noise second (skips if already marked)
```

**Order of operations:**
1. `apply_auto_hide()` → Check known-good patterns (RMM, EDR, IPs)
2. `apply_auto_hide_noise()` → Check noise patterns (**skips if event_status already set**)

### 4. `app/coordinator_index.py`

| Function | Purpose |
|----------|---------|
| `index_new_files(case_id)` | Main indexing coordinator - calls Known-Noise phase |

**Known-Noise Phase Call (v2.1.0):**
```python
# PHASE 4: HIDE KNOWN-NOISE EVENTS
from events_known_noise import hide_noise_all_task

noise_task = hide_noise_all_task.delay(case_id)

# Poll for completion
while get_progress_status(case_id, 'known_noise_all_task')['status'] == 'running':
    update_phase_progress_from_task(case_id, 'reindex', 6, 'Known-Noise Filter', 'running', noise_task.id)
    time.sleep(5)

noise_result = noise_task.get()  # Get final result
```

---

## OpenSearch and Database Fields

Events are marked as noise with category-specific reason in BOTH systems:

### OpenSearch Document
```json
{
  "_source": {
    "process": { ... },
    "host": { ... },
    "event_status": "noise",
    "status_reason": "noise_auto_index"
  }
}
```

### PostgreSQL EventStatus Record
```sql
INSERT INTO event_status (case_id, event_id, status, notes, user_id, created_at)
VALUES (25, 'abc123...', 'noise', 'Auto-hidden as noise', NULL, NOW());
```

### Status Reason Values

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

**When:** Initial index, reindex Phase 2

**File:** `app/file_processing.py` → `apply_auto_hide_noise()`

```python
def apply_auto_hide_noise(event: dict) -> dict:
    """
    Check if event should be auto-hidden as noise.
    Called AFTER apply_auto_hide() - skips if event_status already set.
    """
    # Skip if already marked as noise (don't overwrite known-good reason)
    if event.get('event_status') == 'noise':
        return event
    
    # Check for noise process/command
    if is_noise_event(event):
        event['event_status'] = 'noise'
        event['status_reason'] = 'noise_auto_index'
        return event
    
    # Check for firewall noise
    if is_firewall_noise(event):
        event['event_status'] = 'noise'
        event['status_reason'] = 'firewall_noise_auto_index'
        return event
    
    return event
```

### 2. Reindex Phase 5 (Parallel - v2.1.0)

**When:** User clicks "Re-Index All Files" button

**Flow:**
1. Coordinator: `coordinator_index.py` → calls `hide_noise_all_task.delay(case_id)`
2. Celery Task: `hide_noise_all_task(case_id)` - Coordinator
3. Dispatches 8 parallel `hide_noise_slice_task` workers
4. Each worker processes 1/8 of events using OpenSearch sliced scroll
5. Workers call `is_noise_event()` and `is_firewall_noise()`
6. For matched events:
   - Update OpenSearch: set `event_status='noise'` and `status_reason`
   - Update database: create `EventStatus` record with `status='noise'`
7. Progress tracked via `progress_tracker.py`
8. Coordinator polls for completion

**Performance:** Processes ~800K events in 2-3 minutes (8 parallel workers)

### 3. Manual Hide Noise Button

**When:** User clicks "Hide Known Noise" button on Case Files page

**Flow:**
1. `POST /case/<case_id>/hide-noise` → `routes/files.py` → `hide_noise_route()`
2. Calls same parallel processing as reindex Phase 5
3. Progress displayed in modal via Redis polling

---

## Version History

| Version | Changes |
|---------|---------|
| v2.1.0 | **Parallel processing with 8 Celery workers** - `hide_noise_all_task` coordinator dispatches sliced workers |
| v2.0.0 | **Modular processing system** - Known-Noise is Phase 5 of reindex workflow |
| v1.46.3 | Centralized noise_filters.py as single source of truth |
| v1.46.1 | Auto-hide noise during indexing (after known-good) |
| v1.46.0 | Parallel processing with 8 Celery workers, UI button, routes |
| v1.46.0 | **BREAKING: Removed all `is_hidden` references** |
| v1.46.0 | **Now uses `event_status='noise'` exclusively in both OpenSearch and PostgreSQL** |
| v1.44.0 | New standalone module `events_known_noise.py` |
| v1.43.13 | Added `NOISE_IOC_VALUES` for IOC filtering |
| v1.41.0 | Added `NOISE_COMMAND_PATTERNS` with parent context |
| v1.39.0 | Initial noise filtering in AI Triage |

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
| **Auto-mark on Index** | Yes (`apply_auto_hide`) | Yes (`apply_auto_hide_noise`) |
| **Indexing Order** | First | Second (skips if already marked) |
| **status_reason** | `auto_known_good` | `noise_auto_index`, `firewall_noise_auto_index` |
| **Parallel Workers (v2.1.0)** | 8 (sliced scroll) | 8 (sliced scroll) |
| **Reindex Phase** | Phase 4 | Phase 5 |
| **UI Button** | "Hide Known Good" (🛡️) | "Hide Known Noise" (🔇) |
| **Storage** | OpenSearch `event_status` + Database `EventStatus` | OpenSearch `event_status` + Database `EventStatus` |
