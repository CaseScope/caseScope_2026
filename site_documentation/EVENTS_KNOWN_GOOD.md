# Events Known Good - Technical Reference

Complete documentation for the Known-Good Events detection and hiding system. This document provides enough detail to reconstruct the entire system.

---

## Overview

The Known-Good Events system identifies and hides events that originate from trusted tools and sources, reducing noise in security investigations. Events are marked with `is_hidden: true` in OpenSearch but remain searchable when analysts enable "Show Hidden" filter.

### Key Concepts

| Term | Description |
|------|-------------|
| **Known-Good** | Events from trusted RMM tools, EDR health checks, remote sessions with valid IDs |
| **Hidden Event** | Event with `is_hidden: true` field in OpenSearch |
| **Exclusion** | A pattern defined in System Settings that identifies known-good events |
| **search_blob** | Flattened text field containing all event data for pattern matching |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CONFIGURATION LAYER                              │
│  SystemToolsSetting (PostgreSQL)                                         │
│  ├── rmm_tool: "LTSVC.exe,LTSvcMon.exe"                                │
│  ├── remote_tool: "screenconnect" + ["session-id-1", "session-id-2"]   │
│  ├── edr_tool: "huntressagent.exe" + routine: ["whoami.exe"]           │
│  └── known_good_ip: "192.168.1.0/24"                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         MODULE LAYER                                     │
│  app/events_known_good.py (Primary - standalone module)                 │
│  ├── is_known_good_event() - core detection                            │
│  ├── process_slice() - parallel worker processing                      │
│  └── bulk_hide_events() - OpenSearch bulk updates                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         EXECUTION LAYER                                  │
│  1. During Indexing: file_processing.apply_auto_hide()                  │
│     → Uses events_known_good.is_known_good_event()                      │
│  2. Bulk Hide (Parallel): tasks.hide_known_good_events_task()           │
│     → Dispatches 8x hide_known_good_slice_task() workers                │
│  3. AI Triage: tasks.should_exclude_event()                             │
│  4. Manual Hide: main.hide_event() / unhide_event()                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         STORAGE LAYER                                    │
│  OpenSearch: case_{id} index                                            │
│  Event document: { ..., "is_hidden": true, "hidden_reason": "..." }    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Database Model

### Table: `system_tools_setting`

**File:** `app/models.py` (lines 548-596)

```python
class SystemToolsSetting(db.Model):
    __tablename__ = 'system_tools_setting'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Type: 'rmm_tool', 'remote_tool', 'edr_tool', 'known_good_ip'
    setting_type = db.Column(db.String(50), nullable=False, index=True)
    
    # For RMM, Remote, and EDR tools
    tool_name = db.Column(db.String(100))           # 'ConnectWise Automate', 'Huntress'
    executable_pattern = db.Column(db.String(500))  # 'LTSVC.exe,LTSvcMon.exe'
    
    # For Remote tools (ScreenConnect, TeamViewer)
    known_good_ids = db.Column(db.Text)  # JSON: ["session-id-1", "session-id-2"]
    
    # For IP exclusions
    ip_or_cidr = db.Column(db.String(50))  # '192.168.1.0/24' or '10.0.0.50'
    
    # For EDR tools (v1.40.0)
    exclude_routine = db.Column(db.Boolean, default=True)   # Hide health checks
    keep_responses = db.Column(db.Boolean, default=True)    # Keep response actions
    routine_commands = db.Column(db.Text)   # JSON: ["whoami", "systeminfo", "ipconfig"]
    response_patterns = db.Column(db.Text)  # JSON: ["isolat", "quarantin", "block"]
    
    description = db.Column(db.String(500))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, index=True)
```

### Setting Types

| Type | Purpose | Key Fields |
|------|---------|------------|
| `rmm_tool` | RMM tools (LabTech, Datto) | `tool_name`, `executable_pattern` |
| `remote_tool` | Remote access with session IDs | `tool_name`, `executable_pattern`, `known_good_ids` |
| `edr_tool` | EDR/AV tools | `tool_name`, `executable_pattern`, `routine_commands`, `response_patterns` |
| `known_good_ip` | Trusted IP/CIDR | `ip_or_cidr` |

---

## Detection Logic

### Core Algorithm

**File:** `app/events_known_good.py` → `is_known_good_event()` (line 145)

The detection uses `search_blob` - a flattened text field containing all event data. This allows matching patterns anywhere in the event (process name, parent, grandparent, command line, paths, etc.).

```python
def is_known_good_event(event_data: Dict, search_blob: str, exclusions: Dict) -> bool:
    blob = (search_blob or '').lower()
    
    # CHECK 1: RMM Tools - Executable patterns
    for rmm_pattern in exclusions.get('rmm_executables', []):
        if '*' in rmm_pattern:
            # Wildcard: "labtech*.exe" → need prefix + .exe in blob
            prefix = rmm_pattern.split('*')[0]
            if prefix and prefix in blob and '.exe' in blob:
                return True
        else:
            # Exact: "ltsvc.exe" must be in blob
            if rmm_pattern in blob:
                return True
    
    # CHECK 1b: RMM Path Indicators (v1.44.2)
    RMM_PATH_INDICATORS = [
        '\\ltsvc\\',       # LabTech/ConnectWise Automate path
        '\\labtech\\',     # Alternative LabTech path
        '\\datto\\',       # Datto RMM
        '\\aemag\\',       # Datto AEM Agent
        '\\kaseya\\',      # Kaseya
        '\\ninjarmmag\\',  # NinjaRMM
        '\\syncro\\',      # Syncro
        '\\atera\\',       # Atera
        '\\n-central\\',   # N-able
    ]
    for path_indicator in RMM_PATH_INDICATORS:
        if path_indicator in blob:
            return True
    
    # CHECK 1c: RMM Service Names (v1.44.2)
    RMM_SERVICE_NAMES = [
        'ltservice',       # LabTech service
        'ltsvcmon',        # LabTech service monitor  
        'lttray',          # LabTech tray
        'labvnc',          # LabTech VNC
        'dattoservice',    # Datto
        'kaseyaservice',   # Kaseya
    ]
    for svc_name in RMM_SERVICE_NAMES:
        if f'{svc_name} running' in blob or f'{svc_name} stopped' in blob:
            return True
    
    # CHECK 2: Remote Tools (requires BOTH pattern AND session ID)
    for tool_config in exclusions.get('remote_tools', []):
        pattern = tool_config.get('pattern', '')
        if pattern and pattern in blob:
            for known_id in tool_config.get('known_good_ids', []):
                if known_id and known_id in blob:
                    return True
    
    # CHECK 3: EDR Tools (hide routine, keep responses)
    for edr_config in exclusions.get('edr_tools', []):
        # Check if EDR executable in blob (with .exe context)
        for exe in edr_config.get('executables', []):
            if exe in blob or (exe.split('*')[0] in blob and '.exe' in blob):
                # Check for response action → DON'T hide (attacker activity!)
                if any(p in blob for p in edr_config.get('response_patterns', [])):
                    continue
                # Check for routine command → HIDE
                for routine in edr_config.get('routine_commands', []):
                    if f"{routine}.exe" in blob:
                        return True
    
    # CHECK 4: Known-Good IP
    source_ip = _extract_source_ip(event_data)
    if source_ip:
        for ip_range in exclusions.get('known_good_ips', []):
            if ip_in_range(source_ip, ip_range):
                return True
    
    return False
```

### Why `.exe` Context Matters

Without `.exe` context, patterns match URLs incorrectly:

| Pattern | Without Context | With Context |
|---------|-----------------|--------------|
| `huntress` | ❌ Matches `huntress.io` URL | ✅ Only `huntressagent.exe` |
| `labtech*` | ❌ Matches `labtech.com` | ✅ Only `labtechservice.exe` |

---

## Exclusion Data Structure

Loaded from database into this structure:

```python
exclusions = {
    'rmm_executables': [
        'ltsvc.exe',
        'ltsvcmon.exe', 
        'labtech*.exe',      # Wildcard
        'dattoagent.exe'
    ],
    'remote_tools': [
        {
            'name': 'ScreenConnect',
            'pattern': 'screenconnect',
            'known_good_ids': ['abc123-session', 'def456-session']
        },
        {
            'name': 'TeamViewer',
            'pattern': 'teamviewer',
            'known_good_ids': ['tv-1234567890']
        }
    ],
    'edr_tools': [
        {
            'name': 'Huntress',
            'executables': ['huntressagent.exe', 'huntressupdater.exe'],
            'exclude_routine': True,
            'keep_responses': True,
            'routine_commands': ['whoami', 'systeminfo', 'ipconfig', 'net'],
            'response_patterns': ['isolat', 'quarantin', 'block', 'kill']
        }
    ],
    'known_good_ips': [
        '192.168.1.0/24',
        '10.0.0.50'
    ]
}
```

---

## Files and Functions

### 1. `app/events_known_good.py` (Primary Module)

Standalone module for known-good detection. Used by all integration points.

| Function | Purpose |
|----------|---------|
| `load_exclusions()` | Load patterns from `SystemToolsSetting` table |
| `get_cached_exclusions(max_age=60)` | Cached loading for bulk operations |
| `clear_cache()` | Clear cache after settings change |
| `has_exclusions_configured()` | Check if any exclusions exist |
| `is_known_good_event(event, blob, exclusions)` | **Core detection logic** |
| `process_slice(case_id, slice_id, max_slices, exclusions, client)` | Process 1/N slice for parallel workers |
| `bulk_hide_events(events_list, client, index)` | Bulk update to set is_hidden=True |
| `hide_known_good_events(case_id, callback)` | Legacy single-threaded bulk hide |
| `unhide_all_events(case_id)` | Reset all hidden events |
| `hide_event(case_id, event_id)` | Hide single event |
| `unhide_event(case_id, event_id)` | Unhide single event |
| `get_hidden_count(case_id)` | Count hidden events |
| `get_visible_count(case_id)` | Count visible events |

### 2. `app/file_processing.py`

Applies auto-hide during file indexing using `events_known_good` module.

| Function | Purpose |
|----------|---------|
| `apply_auto_hide(event, exclusions)` | Calls `is_known_good_event()` and sets `is_hidden=True` |

**Usage in indexing loop (v1.45.0):**
```python
from events_known_good import get_cached_exclusions, has_exclusions_configured, is_known_good_event

auto_hide_exclusions = get_cached_exclusions() if has_exclusions_configured() else None

for event in events:
    event = normalize_event(event)
    event = apply_auto_hide(event, auto_hide_exclusions)  # Sets is_hidden=True if match
    bulk_actions.append({'_index': index_name, '_source': event})
```

### 3. `app/tasks.py`

Contains Celery tasks for parallel bulk hide operation.

| Function/Task | Purpose |
|---------------|---------|
| `hide_known_good_events_task(case_id, user_id)` | **Coordinator task** - dispatches 8 parallel workers |
| `hide_known_good_slice_task(case_id, slice_id, max_slices, user_id)` | **Worker task** - processes 1/8 of events |
| `should_exclude_event(event, exclusions)` | Detection for AI Triage filtering |

**Parallel Processing (v1.45.0):**
```python
HIDE_PARALLEL_SLICES = 8  # Use all 8 Celery workers

# Coordinator dispatches 8 parallel slice tasks
slice_tasks = group([
    hide_known_good_slice_task.s(case_id, i, HIDE_PARALLEL_SLICES, user_id)
    for i in range(HIDE_PARALLEL_SLICES)
])
group_result = slice_tasks.apply_async()

# Each slice uses OpenSearch sliced scroll
query = {
    "slice": {"id": slice_id, "max": max_slices},
    "query": {"bool": {"must_not": [{"term": {"is_hidden": True}}]}}
}
```

### 4. `app/main.py`

Manual hide/unhide routes.

| Route | Method | Purpose |
|-------|--------|---------|
| `/case/<id>/search/hide` | POST | Hide single event |
| `/case/<id>/search/unhide` | POST | Unhide single event |
| `/case/<id>/search/bulk-hide` | POST | Bulk hide selected events |
| `/case/<id>/search/bulk-unhide` | POST | Bulk unhide selected events |

### 5. `app/routes/system_tools.py`

Admin UI for configuring exclusions and triggering bulk hide.

| Route | Method | Purpose |
|-------|--------|---------|
| `/settings/system-tools/` | GET | Admin UI page |
| `/settings/system-tools/rmm/add` | POST | Add RMM tool |
| `/settings/system-tools/remote/add` | POST | Add remote tool |
| `/settings/system-tools/edr/add` | POST | Add EDR tool |
| `/settings/system-tools/ip/save` | POST | Add known-good IP |
| `/settings/system-tools/api/exclusions` | GET | Get exclusions summary for modal |
| `/settings/system-tools/api/has-exclusions` | GET | Check if exclusions configured |
| `/settings/system-tools/case/<id>/hide-known-good` | POST | Start parallel bulk hide task |
| `/settings/system-tools/case/<id>/hide-known-good/status/<task_id>` | GET | Poll task progress |

---

## OpenSearch Field

Events are marked hidden by adding this field:

```json
{
  "_source": {
    "process": { ... },
    "host": { ... },
    "is_hidden": true,
    "hidden_reason": "auto_hide_index"
  }
}
```

### Hidden Reason Values

| Value | When Set |
|-------|----------|
| `auto_hide_index` | During file indexing |
| `bulk_task` | Via "Hide Known Good" button |
| `manual` | Via single event hide action |

### Query Patterns

**Exclude hidden events (default):**
```json
{
  "query": {
    "bool": {
      "must_not": [
        {"term": {"is_hidden": true}}
      ]
    }
  }
}
```

**Show only hidden events:**
```json
{
  "query": {
    "bool": {
      "filter": [
        {"term": {"is_hidden": true}}
      ]
    }
  }
}
```

**Count hidden events:**
```python
opensearch_client.count(
    index=f"case_{case_id}",
    body={"query": {"term": {"is_hidden": True}}}
)
```

---

## Integration Points

### 1. File Indexing (Automatic)

**When:** Initial index, reindex, bulk reindex

**File:** `app/file_processing.py`

```python
from events_known_good import get_cached_exclusions, has_exclusions_configured, is_known_good_event

exclusions = get_cached_exclusions() if has_exclusions_configured() else None

for event in events:
    event = normalize_event(event)
    event = apply_auto_hide(event, exclusions)  # Uses is_known_good_event()
    bulk_actions.append({'_index': index_name, '_source': event})
```

### 2. Bulk Hide Task (Manual Trigger - Parallel)

**When:** User clicks "Hide Known Good Events" button

**Flow:**
1. `POST /settings/system-tools/case/{id}/hide-known-good` → `routes/system_tools.py`
2. Starts Celery task `tasks.hide_known_good_events_task` (coordinator)
3. Coordinator dispatches 8 parallel `hide_known_good_slice_task` workers
4. Each worker uses OpenSearch sliced scroll to process 1/8 of events
5. Workers call `is_known_good_event()` from `events_known_good.py`
6. Results aggregated and bulk updates applied
7. Progress updates sent as each worker completes

### 3. AI Triage Filtering

**When:** AI Triage runs, excludes known-good from anchor events

**File:** `app/tasks.py` → `should_exclude_event()`

```python
def should_exclude_event(event, exclusions):
    # Same logic as is_known_good_event
    # Returns True → event excluded from triage tagging
```

### 4. Search Results Filtering

**When:** User searches events

**File:** `app/search_utils.py`

```python
if hidden_filter == "hide":
    # Exclude hidden events (default)
elif hidden_filter == "only":
    # Show ONLY hidden events
else:
    # Show all events (both hidden and visible)
```

---

## Usage Examples

### Check Single Event

```python
from events_known_good import is_known_good_event, get_cached_exclusions

exclusions = get_cached_exclusions()
event = {'process': {'name': 'LTSVC.exe'}, 'search_blob': 'ltsvc.exe c:\\program files\\labtech\\'}

if is_known_good_event(event, event['search_blob'], exclusions):
    print("Event is known-good")
```

### Bulk Hide All Known-Good (Parallel)

The parallel bulk hide is triggered via the UI button, which calls:

```python
# In routes/system_tools.py
from tasks import hide_known_good_events_task

task = hide_known_good_events_task.delay(case_id=25, user_id=1)
# Returns task_id for progress polling
```

### Get Statistics

```python
from events_known_good import get_hidden_count, get_visible_count

hidden = get_hidden_count(case_id=25)   # 3500
visible = get_visible_count(case_id=25)  # 146500
```

### Unhide All

```python
from events_known_good import unhide_all_events

result = unhide_all_events(case_id=25)
# {'success': True, 'total_unhidden': 3500, 'errors': []}
```

---

## Templates

### Admin Settings UI

**File:** `app/templates/system_tools.html`

Displays configuration forms for:
- RMM tools (dropdown + custom)
- Remote tools (pattern + session IDs)
- EDR tools (executables + routine commands + response patterns)
- Known-good IPs (IP/CIDR input)

### Search Events Page

**File:** `app/templates/search_events.html`

- "Hide Known Good" button triggers modal
- Modal shows configured exclusions summary
- Progress display with worker completion tracking
- Results show events hidden count

### Case Files Dashboard

**File:** `app/templates/case_files.html`

Displays "Hidden Events" counter in statistics panel (auto-updates).

---

## Predefined Tool Lists

**File:** `app/routes/system_tools.py` (lines 23-180)

```python
RMM_TOOLS = {
    'labtech': {
        'name': 'ConnectWise Automate (LabTech)',
        'executables': ['LTSVC.exe', 'LTSvcMon.exe', 'LTTray.exe', 'LabTechService.exe']
    },
    'datto': {
        'name': 'Datto RMM',
        'executables': ['AEMAgent.exe', 'CagService.exe']
    },
    # ... more tools
}

EDR_TOOLS = {
    'huntress': {
        'name': 'Huntress',
        'executables': ['HuntressAgent.exe', 'HuntressUpdater.exe'],
        'routine_commands': ['whoami', 'systeminfo', 'ipconfig', 'net', 'nltest'],
        'response_patterns': ['isolat', 'quarantin', 'block', 'kill', 'terminat']
    },
    'sentinelone': { ... },
    'crowdstrike': { ... }
}
```

---

## Version History

| Version | Changes |
|---------|---------|
| v1.38.0 | Initial implementation - RMM, Remote, IP exclusions |
| v1.40.0 | Added EDR tools with routine/response patterns |
| v1.43.15 | Switched to `search_blob` matching (catches grandparent processes) |
| v1.43.16 | Added `.exe` context requirement for wildcards |
| v1.43.17 | Auto-hide during indexing |
| v1.44.0 | New standalone module `events_known_good.py` |
| v1.44.2 | Added RMM path indicators and service name matching |
| v1.45.0 | Parallel processing with 8 Celery workers (~8x faster) |

---

## Reconstruction Checklist

To rebuild this system:

1. **Database Model**
   - Create `SystemToolsSetting` table with fields above
   - Add indexes on `setting_type` and `is_active`

2. **Core Detection Module** (`events_known_good.py`)
   - Implement `load_exclusions()` to query database
   - Implement `is_known_good_event()` with 4-check logic
   - Add `RMM_PATH_INDICATORS` and `RMM_SERVICE_NAMES` for robust RMM detection
   - Add caching for bulk performance
   - Implement `process_slice()` for parallel workers

3. **Integration Points**
   - Add `apply_auto_hide()` call in file indexing loop (uses `events_known_good`)
   - Add Celery tasks: coordinator + 8 slice workers
   - Add `should_exclude_event()` for AI Triage filtering

4. **Routes**
   - Admin UI at `/settings/system-tools/`
   - API endpoints for exclusions summary
   - Task trigger and status polling endpoints

5. **Search Filtering**
   - Add `is_hidden` filter to search query builder
   - Default to excluding hidden events

6. **OpenSearch**
   - No schema changes needed (dynamic field)
   - Add `is_hidden: true` to events via update
