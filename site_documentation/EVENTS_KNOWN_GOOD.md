# Events Known Good - Technical Reference

Complete documentation for the Known-Good Events detection system that marks events as `status: noise`.

---

## Overview

The Known-Good Events system identifies events from trusted tools and sources, marking them with `status: noise` to reduce clutter in security investigations. Events remain fully searchable and visible when the "Noise" status filter is enabled.

### Key Concepts

| Term | Description |
|------|-------------|
| **Known-Good** | Events from trusted RMM tools, EDR health checks, remote sessions with valid IDs |
| **Noise Status** | Event with `event_status='noise'` in OpenSearch AND `status='noise'` in database |
| **Exclusion** | A pattern defined in System Settings that identifies known-good events |
| **search_blob** | Flattened text field containing all event data for pattern matching |
| **event_status** | Field in OpenSearch: 'new', 'noise', 'hunted', or 'confirmed' |
| **EventStatus Table** | PostgreSQL table tracking event status for dashboard statistics |

---

## Detection Logic - The Three Rules

The system uses these **exact** rules to identify known-good events:

### Rule 1: RMM Tools
**If RMM EXE OR RMM PATH found in blob → status: noise**

- Checks for RMM executable patterns (e.g., `ltsvc.exe`, `dattoagent.exe`)
- Checks for RMM installation paths (e.g., `c:\program files\labtech\`)
- Both EXE list and PATH are configured per-RMM tool in System Settings

### Rule 2: Remote Tools
**If Remote Tool EXE AND Session ID found in blob → status: noise**

- BOTH the remote tool executable pattern AND a known-good session ID must be present
- Example: `screenconnect` + `abc123-session-id`
- Session IDs are configured per-tool in System Settings

### Rule 3: EDR Tools
**If EDR Tool EXE AND Routine Keyword(s) found in blob → status: noise**

- EDR executable must be present (e.g., `huntressagent.exe`)
- Routine command keyword must be present (e.g., `whoami`, `ipconfig`)
- UNLESS a response pattern is also present (e.g., `isolat`, `quarantin`) → then keep it (not noise!)
- Routine keywords and response patterns configured per-EDR tool in System Settings

---

## Database Model

### Table: `system_tools_setting`

**File:** `app/models.py` (lines 616-665)

```python
class SystemToolsSetting(db.Model):
    __tablename__ = 'system_tools_setting'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Type: 'rmm_tool', 'remote_tool', 'edr_tool', 'known_good_ip'
    setting_type = db.Column(db.String(50), nullable=False, index=True)
    
    # For RMM, Remote, and EDR tools
    tool_name = db.Column(db.String(100))           # 'ConnectWise Automate', 'Huntress'
    executable_pattern = db.Column(db.String(500))  # 'LTSVC.exe,LTSvcMon.exe'
    rmm_path = db.Column(db.String(500))           # 'C:\\Program Files\\LabTech\\'
    
    # For Remote tools (ScreenConnect, TeamViewer)
    known_good_ids = db.Column(db.Text)  # JSON: ["session-id-1", "session-id-2"]
    
    # For IP exclusions
    ip_or_cidr = db.Column(db.String(50))  # '192.168.1.0/24' or '10.0.0.50'
    
    # For EDR tools
    exclude_routine = db.Column(db.Boolean, default=True)   # Hide routine checks
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
| `rmm_tool` | RMM tools (LabTech, Datto) | `tool_name`, `executable_pattern`, `rmm_path` |
| `remote_tool` | Remote access with session IDs | `tool_name`, `executable_pattern`, `known_good_ids` |
| `edr_tool` | EDR/AV tools | `tool_name`, `executable_pattern`, `routine_commands`, `response_patterns` |
| `known_good_ip` | Trusted IP/CIDR | `ip_or_cidr` |

---

## How Status is Set

### During File Indexing (Automatic)
When events are indexed, the system:
1. Checks each event against exclusion rules using `is_known_good_event()`
2. If matched, sets `event_status='noise'` in the OpenSearch document
3. Sets `status_reason='auto_known_good'` for tracking
4. No database update during indexing (for performance)

### During "Hide Known Good" Operation (Manual)
When user clicks "Hide Known Good Events":
1. Scans all events using parallel workers (8 workers via Celery)
2. Checks each event against exclusion rules
3. For matched events:
   - Sets `event_status='noise'` in OpenSearch document
   - Sets `status_reason='auto_known_good'` in OpenSearch document
   - Creates/updates database records in `event_status` table with `status='noise'`
4. Uses `bulk_set_status()` from `event_status` module for database updates

### Status Storage (Dual System)
- **OpenSearch Document:** `event_status='noise'` field + `status_reason` field
- **PostgreSQL EventStatus Table:** Record with `status='noise'` + notes
- Both layers are kept in sync during manual hide operations
- Queries filter by `event_status='noise'` (not the old `is_hidden` field)

---

## Core Detection Function

**File:** `app/events_known_good.py` → `is_known_good_event()` (line 145)

```python
def is_known_good_event(event_data: Dict, search_blob: str, exclusions: Optional[Dict] = None) -> bool:
    """
    Check if an event matches known-good patterns.
    
    Returns True if event should be marked as noise, False otherwise.
    
    Detection Logic (THE THREE RULES):
        1. RMM: If EXE pattern OR path in search_blob → NOISE
        2. Remote: If tool pattern AND session ID in search_blob → NOISE
        3. EDR: If executable AND routine keyword in search_blob → NOISE
               (unless response pattern also present → NOT NOISE, keep it)
        4. IPs: If source IP matches known-good range → NOISE
    """
    blob = (search_blob or '').lower()
    
    # CHECK 1: RMM Tools - EXE or PATH
    for rmm_pattern in exclusions.get('rmm_executables', []):
        if rmm_pattern in blob:
            return True
    
    for rmm_path in exclusions.get('rmm_paths', []):
        if rmm_path and rmm_path in blob:
            return True
    
    # CHECK 2: Remote Tools - EXE + ID
    for tool_config in exclusions.get('remote_tools', []):
        pattern = tool_config.get('pattern', '')
        if pattern and pattern in blob:
            for known_id in tool_config.get('known_good_ids', []):
                if known_id and known_id in blob:
                    return True
    
    # CHECK 3: EDR Tools - EXE + Routine Keyword
    for edr_config in exclusions.get('edr_tools', []):
        # Check EDR executable present
        edr_in_blob = any(exe in blob for exe in edr_config.get('executables', []))
        
        if edr_in_blob:
            # Check for response action - DON'T mark as noise
            if any(p in blob for p in edr_config.get('response_patterns', [])):
                continue
            
            # Check for routine command - MARK AS NOISE
            if any(r in blob for r in edr_config.get('routine_commands', [])):
                return True
    
    # CHECK 4: Known-Good Source IPs
    source_ip = _extract_source_ip(event_data)
    if source_ip and any(ip_in_range(source_ip, ip_range) 
                        for ip_range in exclusions.get('known_good_ips', [])):
        return True
    
    return False
```

---

## Files and Functions

### 1. `app/events_known_good.py` (Primary Module)

| Function | Purpose |
|----------|---------|
| `load_exclusions()` | Load patterns from `SystemToolsSetting` table including RMM paths |
| `get_cached_exclusions(max_age=60)` | Cached loading for bulk operations |
| `is_known_good_event(event, blob, exclusions)` | **Core detection logic - The Three Rules** |
| `bulk_hide_events(events_list, client, index, case_id)` | Update both OpenSearch and database to set status='noise' |
| `process_slice(case_id, slice_id, ...)` | Process 1/N slice for parallel workers |
| `hide_event(case_id, event_id)` | Mark single event as noise (OpenSearch + database) |
| `unhide_event(case_id, event_id)` | Reset single event to 'new' status (OpenSearch + database) |
| `unhide_all_events(case_id)` | Reset all noise events back to 'new' status |
| `get_hidden_count(case_id)` | Count events with status='noise' |
| `get_visible_count(case_id)` | Count events without status='noise' |

### 2. `app/file_processing.py`

| Function | Purpose |
|----------|---------|
| `apply_auto_hide(event, exclusions)` | Calls `is_known_good_event()` and sets `event_status='noise'` during indexing |
| `apply_auto_hide_noise(event, exclusions)` | Additional noise detection for specific patterns |

### 3. `app/tasks.py`

| Function/Task | Purpose |
|---------------|---------|
| `hide_known_good_events_task(case_id, user_id)` | Coordinator task - dispatches 8 parallel workers |
| `hide_known_good_slice_task(case_id, slice_id, ...)` | Worker task - processes 1/8 of events, updates both OpenSearch and database |

### 4. `app/event_status.py`

| Function | Purpose |
|----------|---------|
| `bulk_set_status(case_id, event_ids, STATUS_NOISE, ...)` | Creates/updates PostgreSQL records with status='noise' |
| `get_event_ids_by_status(case_id, [STATUS_NOISE])` | Get all event IDs with noise status |

---

## Integration Points

### Important Note on Dual Updates

**CRITICAL:** When marking events as noise, you MUST update BOTH systems:

1. **OpenSearch Document:** Set `event_status='noise'` (for query filtering and display)
2. **PostgreSQL Database:** Set `status='noise'` in `event_status` table (for statistics and tracking)

**Why both?**
- OpenSearch filtering is fast for large-scale queries
- PostgreSQL provides reliable counts for dashboard statistics
- Both must stay synchronized for accurate results

### 1. File Indexing (Automatic)
**When:** Initial index, reindex, bulk reindex

```python
from events_known_good import get_cached_exclusions, is_known_good_event

exclusions = get_cached_exclusions()

for event in events:
    event = normalize_event(event)
    event = apply_auto_hide(event, exclusions)  # Sets event_status='noise' if matched
    bulk_actions.append({'_index': index_name, '_source': event})
```

### 2. Bulk Hide Task (Manual Trigger - Parallel)
**When:** User clicks "Hide Known Good Events" button

**Flow:**
1. `POST /settings/system-tools/case/{id}/hide-known-good`
2. Starts Celery task `hide_known_good_events_task` (coordinator)
3. Dispatches 8 parallel `hide_known_good_slice_task` workers
4. Each worker processes 1/8 of events using OpenSearch sliced scroll
5. Each worker:
   - Uses query filter `must_not: {"term": {"event_status": "noise"}}` to skip already-processed events
   - Identifies matched events using `is_known_good_event()`
   - Updates OpenSearch: sets `event_status='noise'` and `status_reason='auto_known_good'`
   - Updates database: sets `status='noise'` via `bulk_set_status()`
6. Progress updates sent as each worker completes

### 3. Search Results Filtering
**When:** User searches events

Status filter checkboxes control which events are shown:
- ☑ New ☑ Hunted ☑ Confirmed ☐ Noise (default - noise hidden)
- Check "Noise" box to show noise events
- Filter uses OpenSearch query: `must_not: {"term": {"event_status": "noise"}}` when Noise is unchecked

**Query Logic:**
- Events are filtered based on `event_status` field in OpenSearch
- No `is_hidden` field is used (deprecated as of v1.46.0)
- Dashboard counts use the `event_status` table in PostgreSQL

---

## Version History

| Version | Changes |
|---------|---------|
| v1.38.0 | Initial implementation - RMM, Remote, IP exclusions |
| v1.40.0 | Added EDR tools with routine/response patterns |
| v1.43.15 | Switched to `search_blob` matching |
| v1.44.0 | Standalone module `events_known_good.py` |
| v1.45.0 | Parallel processing with 8 Celery workers |
| v1.46.0 | **BREAKING: Removed all `is_hidden` references** |
| v1.46.0 | **Now uses `event_status='noise'` exclusively in both OpenSearch and PostgreSQL** |
| v1.46.0 | **Added `rmm_path` field to RMM tool configuration** |
| v1.46.0 | **Query filters changed from `is_hidden: true` to `event_status: 'noise'`** |

---

## Admin UI (System Settings)

### RMM Tools
- Tool Name (dropdown or custom)
- Executable Pattern (comma-separated, e.g., `LTSVC.exe,LTSvcMon.exe`)
- **RMM Path** (e.g., `C:\Program Files\LabTech\`)
- Edit button (to modify existing entries)

### Remote Tools
- Tool Name
- Executable Pattern (e.g., `screenconnect`)
- Known-Good Session IDs (list)
- Edit button

### EDR Tools
- Tool Name
- Executable Pattern (comma-separated)
- Routine Commands (keywords to mark as noise)
- Response Patterns (keywords to keep, not mark as noise)
- Edit button

---

## Summary

**The system works in 3 simple steps:**

1. **Define exclusions** in System Settings (RMM paths/exes, Remote tool IDs, EDR routines)
2. **Detection** uses the Three Rules to identify known-good events
3. **Status** is set to `noise` (in both OpenSearch `event_status` field and PostgreSQL `event_status` table)

**Key Implementation Details:**

- **During Indexing:** Events get `event_status='noise'` set in OpenSearch document only (for performance)
- **During Manual Hide:** Events get updated in BOTH OpenSearch (`event_status='noise'`) AND database (`status='noise'`)
- **Query Filtering:** All queries filter by `event_status='noise'`, NOT the deprecated `is_hidden` field
- **Statistics:** Dashboard counts query the PostgreSQL `event_status` table

**Critical Change in v1.46.0:**
- ❌ **REMOVED:** `is_hidden: true/false` field (deprecated, no longer used)
- ✅ **NOW USES:** `event_status: 'noise'` / 'new' / 'hunted' / 'confirmed'

This unified status system allows events to remain searchable while being properly categorized as noise from trusted tools.
