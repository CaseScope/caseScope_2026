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
│  app/events_known_good.py (NEW - standalone module)                     │
│  app/auto_hide.py (legacy, used during indexing)                        │
│  app/tasks.py (_should_hide_event_task, should_exclude_event)          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         EXECUTION LAYER                                  │
│  1. During Indexing: file_processing.apply_auto_hide()                  │
│  2. Bulk Hide Task: tasks.hide_known_good_events_task()                 │
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

**File:** `app/events_known_good.py` → `is_known_good_event()`

The detection uses `search_blob` - a flattened text field containing all event data. This allows matching patterns anywhere in the event (process name, parent, grandparent, command line, paths, etc.).

```python
def is_known_good_event(event_data: Dict, search_blob: str, exclusions: Dict) -> bool:
    blob = (search_blob or '').lower()
    
    # CHECK 1: RMM Tools
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
                # Check for response action → DON'T hide
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

### 1. `app/events_known_good.py` (NEW - Standalone Module)

Primary module for known-good detection. Can be called independently.

| Function | Purpose |
|----------|---------|
| `load_exclusions()` | Load patterns from `SystemToolsSetting` |
| `get_cached_exclusions(max_age=60)` | Cached loading for bulk operations |
| `clear_cache()` | Clear cache after settings change |
| `has_exclusions_configured()` | Check if any exclusions exist |
| `is_known_good_event(event, blob, exclusions)` | **Core detection logic** |
| `hide_known_good_events(case_id, callback)` | Bulk hide all known-good in case |
| `unhide_all_events(case_id)` | Reset all hidden events |
| `hide_event(case_id, event_id)` | Hide single event |
| `unhide_event(case_id, event_id)` | Unhide single event |
| `get_hidden_count(case_id)` | Count hidden events |
| `get_visible_count(case_id)` | Count visible events |

### 2. `app/auto_hide.py` (Legacy - Used During Indexing)

Used by `file_processing.py` during event indexing.

| Function | Purpose |
|----------|---------|
| `load_exclusions_for_auto_hide()` | Same as `load_exclusions()` |
| `should_auto_hide_event(event, blob, exclusions)` | Same as `is_known_good_event()` |
| `get_cached_exclusions()` | Cached loading |
| `has_exclusions_configured()` | Check if enabled |

### 3. `app/file_processing.py`

Applies auto-hide during file indexing.

| Function | Purpose |
|----------|---------|
| `apply_auto_hide(event, exclusions)` | Wrapper that calls `should_auto_hide_event()` |

**Usage in indexing loop:**
```python
# Lines ~899-970
auto_hide_exclusions = get_cached_exclusions() if has_exclusions_configured() else None

for event in events:
    event = normalize_event(event)
    event = apply_auto_hide(event, auto_hide_exclusions)  # Sets is_hidden=True if match
    bulk_actions.append({'_index': index_name, '_source': event})
```

### 4. `app/tasks.py`

Contains Celery task and AI Triage filtering.

| Function | Purpose |
|----------|---------|
| `hide_known_good_events_task(case_id, user_id)` | Celery task for bulk hide |
| `_should_hide_event_task(hit, exclusions)` | Detection for bulk task |
| `should_exclude_event(event, exclusions)` | Detection for AI Triage |

### 5. `app/main.py`

Manual hide/unhide routes.

| Route | Method | Purpose |
|-------|--------|---------|
| `/case/<id>/search/hide` | POST | Hide single event |
| `/case/<id>/search/unhide` | POST | Unhide single event |
| `/case/<id>/search/bulk-hide` | POST | Bulk hide events |
| `/case/<id>/search/bulk-unhide` | POST | Bulk unhide events |

### 6. `app/routes/system_tools.py`

Admin UI for configuring exclusions.

| Route | Method | Purpose |
|-------|--------|---------|
| `/settings/system-tools/` | GET | Admin UI page |
| `/settings/system-tools/rmm/add` | POST | Add RMM tool |
| `/settings/system-tools/remote/add` | POST | Add remote tool |
| `/settings/system-tools/edr/add` | POST | Add EDR tool |
| `/settings/system-tools/ip/add` | POST | Add known-good IP |
| `/case/<id>/hide-known-good` | POST | Start bulk hide task |
| `/case/<id>/hide-known-good/status/<task_id>` | GET | Poll task progress |

---

## OpenSearch Field

Events are marked hidden by adding this field:

```json
{
  "_source": {
    "process": { ... },
    "host": { ... },
    "is_hidden": true,
    "hidden_reason": "auto_hide_index"  // or "manual", "bulk_task"
  }
}
```

### Query Patterns

**Exclude hidden events (default):**
```json
{
  "query": {
    "bool": {
      "filter": [{
        "bool": {
          "should": [
            {"bool": {"must_not": [{"exists": {"field": "is_hidden"}}]}},
            {"term": {"is_hidden": false}}
          ],
          "minimum_should_match": 1
        }
      }]
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
from auto_hide import get_cached_exclusions, should_auto_hide_event

exclusions = get_cached_exclusions()
for event in events:
    event = normalize_event(event)
    if should_auto_hide_event(event, event.get('search_blob', ''), exclusions):
        event['is_hidden'] = True
```

### 2. Bulk Hide Task (Manual Trigger)

**When:** User clicks "Hide Known Good Events" button

**Flow:**
1. `POST /case/{id}/hide-known-good` → `routes/system_tools.py`
2. Starts Celery task `tasks.hide_known_good_events_task`
3. Task scrolls all events, checks `_should_hide_event_task()`
4. Bulk updates matching events with `is_hidden: true`

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
    # Exclude hidden events
elif hidden_filter == "only":
    # Show ONLY hidden events
else:
    # Show all events
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

### Bulk Hide All Known-Good

```python
from events_known_good import hide_known_good_events

def progress(status, processed, total, found):
    print(f"{status}: {processed}/{total}, found {found}")

result = hide_known_good_events(case_id=25, progress_callback=progress)
# {'success': True, 'total_scanned': 150000, 'total_hidden': 3500, 'errors': []}
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

### Case Files Dashboard

**File:** `app/templates/case_files.html`

Displays "Hidden Events" counter in statistics panel.

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

---

## Reconstruction Checklist

To rebuild this system:

1. **Database Model**
   - Create `SystemToolsSetting` table with fields above
   - Add indexes on `setting_type` and `is_active`

2. **Core Detection Module** (`events_known_good.py`)
   - Implement `load_exclusions()` to query database
   - Implement `is_known_good_event()` with 4-check logic
   - Add caching for bulk performance

3. **Integration Points**
   - Add `apply_auto_hide()` call in file indexing loop
   - Add Celery task for bulk hide operation
   - Add `should_exclude_event()` for AI Triage filtering

4. **Routes**
   - Admin UI for configuring exclusions
   - API endpoints for hide/unhide operations
   - Status polling for bulk task

5. **Search Filtering**
   - Add `is_hidden` filter to search query builder
   - Default to excluding hidden events

6. **OpenSearch**
   - No schema changes needed (dynamic field)
   - Add `is_hidden: true` to events via update

