# Events Known Good - Technical Reference

Complete documentation for the Known-Good Events detection system that marks events as `event_status: noise`.

---

## Overview

The Known-Good Events system identifies events from trusted tools and sources, marking them with `event_status='noise'` to reduce clutter in security investigations. Events remain fully searchable and visible when the "Noise" status filter is enabled.

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

**File:** `app/models.py`

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
4. **No database update during indexing** (for performance)

**File:** `app/file_processing.py` → `apply_auto_hide()`

### During Reindex Phase 4 (Parallel - v2.1.0)
When reindex runs the Known-Good filtering phase:
1. Coordinator task dispatches 8 parallel worker slices
2. Each worker processes 1/8 of events using OpenSearch sliced scroll
3. For matched events:
   - Sets `event_status='noise'` in OpenSearch document
   - Sets `status_reason='auto_known_good'` in OpenSearch document
   - Creates/updates database records in `event_status` table with `status='noise'`
4. Uses `bulk_set_status()` from `event_status` module for database updates

**Celery Tasks:**
- `hide_known_good_all_task(case_id)` - Coordinator (dispatches 8 workers)
- `hide_known_good_slice_task(case_id, slice_id, max_slices)` - Worker task

**Performance:** Processes ~800K events in 2-3 minutes (8 parallel workers)

### Manual "Hide Known Good" Button
When user clicks "Hide Known Good Events" on Case Files page:
1. Triggers the same parallel processing as reindex Phase 4
2. Progress tracked via Redis and displayed in modal
3. Both OpenSearch and database updated

### Status Storage (Dual System)
- **OpenSearch Document:** `event_status='noise'` field + `status_reason` field
- **PostgreSQL EventStatus Table:** Record with `status='noise'` + notes
- Both layers are kept in sync during bulk hide operations
- Queries filter by `event_status='noise'`

---

## Core Detection Function

**File:** `app/events_known_good.py` → `is_known_good_event()`

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
| `process_slice(case_id, slice_id, max_slices, exclusions, client)` | Process 1/N slice for parallel workers |
| `hide_known_good_all_task(case_id)` | Celery coordinator task - dispatches 8 workers (v2.1.0) |
| `hide_known_good_slice_task(case_id, slice_id, max_slices)` | Celery worker task - processes 1/8 of events (v2.1.0) |
| `get_hidden_count(case_id)` | Count events with status='noise' |
| `get_visible_count(case_id)` | Count events without status='noise' |

### 2. `app/file_processing.py`

| Function | Purpose |
|----------|---------|
| `apply_auto_hide(event, exclusions)` | Calls `is_known_good_event()` and sets `event_status='noise'` during indexing |

### 3. `app/coordinator_index.py`

| Function | Purpose |
|----------|---------|
| `index_new_files(case_id)` | Main indexing coordinator - calls Known-Good phase |

**Known-Good Phase Call (v2.1.0):**
```python
# PHASE 3: HIDE KNOWN-GOOD EVENTS
from events_known_good import has_exclusions_configured, hide_known_good_all_task

if has_exclusions_configured():
    kg_task = hide_known_good_all_task.delay(case_id)
    
    # Poll for completion
    while get_progress_status(case_id, 'known_good_all_task')['status'] == 'running':
        update_phase_progress_from_task(case_id, 'reindex', 5, 'Known-Good Filter', 'running', kg_task.id)
        time.sleep(5)
    
    kg_result = kg_task.get()  # Get final result
```

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
**When:** Initial index, reindex Phase 2

```python
from events_known_good import get_cached_exclusions, is_known_good_event

exclusions = get_cached_exclusions()

for event in events:
    event = normalize_event(event)
    event = apply_auto_hide(event, exclusions)  # Sets event_status='noise' if matched
    bulk_actions.append({'_index': index_name, '_source': event})
```

### 2. Reindex Phase 4 (Parallel - v2.1.0)
**When:** User clicks "Re-Index All Files" button

**Flow:**
1. Coordinator: `coordinator_index.py` → calls `hide_known_good_all_task.delay(case_id)`
2. Celery Task: `hide_known_good_all_task(case_id)` - Coordinator
3. Dispatches 8 parallel `hide_known_good_slice_task` workers
4. Each worker processes 1/8 of events using OpenSearch sliced scroll:
   - Query filter: `must_not: {"term": {"event_status": "noise"}}` (skip already-processed)
   - Identifies matched events using `is_known_good_event()`
   - Updates OpenSearch: sets `event_status='noise'` and `status_reason='auto_known_good'`
   - Updates database: sets `status='noise'` via `bulk_set_status()`
5. Progress tracked via `progress_tracker.py`
6. Coordinator polls for completion

### 3. Manual Hide Known Good Button
**When:** User clicks "Hide Known Good" button on Case Files page

**Flow:**
1. `POST /case/<case_id>/hide-known-good` → `routes/files.py` → `hide_known_good_route()`
2. Calls same parallel processing as reindex Phase 4
3. Progress displayed in modal via Redis polling

### 4. Search Results Filtering
**When:** User searches events

Status filter checkboxes control which events are shown:
- ☑ New ☑ Hunted ☑ Confirmed ☐ Noise (default - noise hidden)
- Check "Noise" box to show noise events
- Filter uses OpenSearch query: `must_not: {"term": {"event_status": "noise"}}` when Noise is unchecked

**Query Logic:**
- Events are filtered based on `event_status` field in OpenSearch
- Dashboard counts use the `event_status` table in PostgreSQL

---

## Version History

| Version | Changes |
|---------|---------|
| v2.1.0 | **Parallel processing with 8 Celery workers** - `hide_known_good_all_task` coordinator dispatches sliced workers |
| v2.0.0 | **Modular processing system** - Known-Good is Phase 4 of reindex workflow |
| v1.46.0 | **BREAKING: Removed all `is_hidden` references** |
| v1.46.0 | **Now uses `event_status='noise'` exclusively in both OpenSearch and PostgreSQL** |
| v1.46.0 | **Added `rmm_path` field to RMM tool configuration** |
| v1.45.0 | Parallel processing with 8 Celery workers (old task structure) |
| v1.44.0 | Standalone module `events_known_good.py` |
| v1.43.15 | Switched to `search_blob` matching |
| v1.40.0 | Added EDR tools with routine/response patterns |
| v1.38.0 | Initial implementation - RMM, Remote, IP exclusions |

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
- **During Reindex Phase 4 (v2.1.0):** 8 parallel workers update BOTH OpenSearch (`event_status='noise'`) AND database (`status='noise'`)
- **Query Filtering:** All queries filter by `event_status='noise'`
- **Statistics:** Dashboard counts query the PostgreSQL `event_status` table

**Critical Change in v2.1.0:**
- ✅ **Parallel Processing:** 8 workers process events in 2-3 minutes (vs. 16 minutes single-threaded)
- ✅ **Task-based Progress:** Real-time progress tracking via `progress_tracker.py`

This unified status system allows events to remain searchable while being properly categorized as noise from trusted tools.
