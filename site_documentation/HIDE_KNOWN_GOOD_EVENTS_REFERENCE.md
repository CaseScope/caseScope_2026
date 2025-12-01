# Hide Known Good Events - Technical Reference

**Version**: 1.43.17  
**Last Updated**: December 1, 2025  
**Feature Introduced**: v1.38.0  
**EDR Tools Added**: v1.40.0  
**Simplified search_blob Matching**: v1.43.15  
**Auto-Hide During Indexing**: v1.43.17

---

## 📋 Overview

The "Hide Known Good Events" feature automatically hides events from known-good sources (RMM tools, EDR health checks, approved remote sessions, internal IPs) to reduce noise during investigations.

### Two Modes of Operation

1. **Auto-Hide During Indexing** (v1.43.17) - Events are hidden automatically when files are uploaded/reindexed
2. **Manual Hide Known Good** - Button in Search Events to hide events in already-indexed files

### Key Design Principles (v1.43.15+)

- **search_blob based matching** - All pattern checks use the flattened `search_blob` field
- **Catches full process chain** - Works regardless of parent/grandparent depth
- **Requires .exe context** (v1.43.16) - Prevents matching URLs like `huntress.io`
- **Hidden, not deleted** - Events remain in database, viewable via Hidden Events filter

---

## 🏗️ Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         FRONTEND                                     │
├─────────────────────────────────────────────────────────────────────┤
│  case_files.html                                                     │
│  └── Event Statistics tile: Shows "Hidden Events" count (v1.43.17) │
│                                                                      │
│  search_events.html                                                  │
│  ├── "Hide Known Good" button                                       │
│  ├── hideKnownGoodModal (confirm/progress/results phases)           │
│  └── JavaScript: showHideKnownGoodModal(), pollHideKnownGoodStatus()│
│                                                                      │
│  system_tools.html                                                   │
│  └── Admin settings UI for configuring exclusions                   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         BACKEND                                      │
├─────────────────────────────────────────────────────────────────────┤
│  app/auto_hide.py (v1.43.17 - NEW)                                  │
│  ├── load_exclusions_for_auto_hide()                                │
│  ├── should_auto_hide_event()                                       │
│  ├── get_cached_exclusions()                                        │
│  └── has_exclusions_configured()                                    │
│                                                                      │
│  app/file_processing.py                                              │
│  └── apply_auto_hide() - Called during indexing                     │
│                                                                      │
│  app/tasks.py                                                        │
│  ├── hide_known_good_events_task() - Manual hide Celery task        │
│  └── _should_hide_event_task() - Check event for manual hide        │
│                                                                      │
│  app/hidden_files.py                                                 │
│  └── get_hidden_events_count() - Dashboard counter                  │
│                                                                      │
│  routes/system_tools.py                                              │
│  └── API endpoints for exclusion management                         │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         STORAGE                                      │
├─────────────────────────────────────────────────────────────────────┤
│  PostgreSQL: system_tools_setting table                              │
│  OpenSearch: case_<id> index (is_hidden, hidden_reason fields)      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Files Reference

| File | Purpose | Key Functions |
|------|---------|---------------|
| `app/auto_hide.py` | **Modular exclusion logic** (v1.43.17) | `should_auto_hide_event()`, `get_cached_exclusions()` |
| `app/file_processing.py` | Auto-hide during indexing | `apply_auto_hide()` |
| `app/tasks.py` | Manual hide Celery task | `hide_known_good_events_task()`, `_should_hide_event_task()` |
| `app/hidden_files.py` | Dashboard hidden events count | `get_hidden_events_count()` |
| `app/models.py` | Database model | `SystemToolsSetting` |
| `routes/system_tools.py` | API endpoints | Exclusion CRUD operations |
| `templates/case_files.html` | Dashboard display | Hidden Events counter |
| `templates/search_events.html` | Manual hide UI | Modal and progress display |
| `templates/system_tools.html` | Admin settings | Exclusion configuration forms |

---

## 🗄️ Database Schema

### Table: `system_tools_setting`

```sql
CREATE TABLE system_tools_setting (
    id SERIAL PRIMARY KEY,
    
    -- Type: 'rmm_tool', 'remote_tool', 'edr_tool', 'known_good_ip'
    setting_type VARCHAR(50) NOT NULL,
    
    -- For RMM, Remote, EDR tools
    tool_name VARCHAR(100),              -- 'ConnectWise Automate', 'Huntress'
    executable_pattern VARCHAR(500),     -- 'LTSVC.exe,LTSvcMon.exe'
    
    -- For Remote tools
    known_good_ids TEXT,                 -- JSON: ["session-id-1", "session-id-2"]
    
    -- For IP exclusions
    ip_or_cidr VARCHAR(50),              -- '192.168.1.0/24' or '10.0.0.50'
    
    -- For EDR tools
    exclude_routine BOOLEAN DEFAULT TRUE,  -- Hide health checks
    keep_responses BOOLEAN DEFAULT TRUE,   -- Keep isolation/response actions
    routine_commands TEXT,                 -- JSON: ["whoami", "systeminfo"]
    response_patterns TEXT,                -- JSON: ["isolat", "quarantin"]
    
    -- Metadata
    description VARCHAR(500),
    created_by INTEGER REFERENCES "user"(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);
```

### OpenSearch Event Fields (added when hidden)

```json
{
  "is_hidden": true,
  "hidden_reason": "auto_hide_index"
}
```

Hidden reason values:
- `auto_hide_index` - Hidden during file indexing (v1.43.17)
- `known_good_exclusion` - Hidden via manual "Hide Known Good" button

---

## 🔧 Matching Logic (v1.43.16)

All matching uses the **search_blob** field - a flattened text representation of the entire event. This ensures patterns are found regardless of where they appear in the JSON structure (process, parent, grandparent, command line, paths, etc.).

### Critical: .exe Context Requirement

To prevent false matches on URLs (e.g., `huntress.io` matching "huntress"), pattern matching requires `.exe` context for wildcard patterns:

```python
# Wildcard pattern: "labtech*.exe"
if prefix in blob and '.exe' in blob:
    return True  # Match

# Exact pattern: "ltsvc.exe" 
if pattern in blob:
    return True  # Match (already has .exe)
```

### 1. RMM Tools (Full Exclusion)

**Behavior**: Hide events where RMM executable pattern appears in search_blob.

**Matching Logic** (`auto_hide.py`):
```python
for rmm_pattern in exclusions.get('rmm_executables', []):
    if '*' in rmm_pattern:
        prefix = rmm_pattern.split('*')[0]
        if prefix and f"{prefix}" in blob and '.exe' in blob:
            return True
    else:
        if rmm_pattern in blob:
            return True
```

**Example Patterns**: `ltsvc.exe`, `labtech*.exe`, `aem*.exe`, `ninjarmmag*.exe`

### 2. Remote Tools (Session ID Matching)

**Behavior**: Hide events where BOTH tool executable AND known-good session ID appear in search_blob.

**Matching Logic**:
```python
for tool_config in exclusions.get('remote_tools', []):
    pattern = tool_config.get('pattern', '')
    if pattern and pattern in blob:
        for known_id in tool_config.get('known_good_ids', []):
            if known_id and known_id in blob:
                return True  # HIDE
```

**Example**: ScreenConnect with session ID `abc123-def456` - both must be present.

### 3. EDR Tools (Context-Aware)

**Behavior**: 
- **HIDE** if EDR executable AND routine command both in search_blob
- **KEEP** if response/isolation keyword present (critical for incident understanding)

**Matching Logic**:
```python
for edr_config in exclusions.get('edr_tools', []):
    # Check if EDR executable in blob (with .exe context for wildcards)
    edr_in_blob = False
    for exe in edr_config.get('executables', []):
        if '*' in exe:
            prefix = exe.split('*')[0]
            if prefix and f"{prefix}" in blob and '.exe' in blob:
                edr_in_blob = True
                break
        else:
            if exe in blob:
                edr_in_blob = True
                break
    
    if edr_in_blob:
        # Check for response action - DON'T hide
        if any(pattern in blob for pattern in edr_config.get('response_patterns', [])):
            continue  # Skip - keep this event visible
        
        # Check for routine command - HIDE
        for routine in edr_config.get('routine_commands', []):
            if routine and f"{routine}.exe" in blob:
                return True  # HIDE
```

**Example**: `snapagent.exe` + `ipconfig.exe` → HIDE (routine health check)
**Example**: `snapagent.exe` + `isolat` → KEEP (response action)

### 4. Known-Good IPs

**Behavior**: Hide events from specified IP addresses or CIDR ranges.

**Matching Logic**:
```python
source_ip = _extract_source_ip(event_data)
if source_ip:
    for ip_range in exclusions.get('known_good_ips', []):
        ip_obj = ipaddress.ip_address(source_ip)
        if '/' in ip_range:
            network = ipaddress.ip_network(ip_range, strict=False)
            if ip_obj in network:
                return True
        else:
            if ip_obj == ipaddress.ip_address(ip_range):
                return True
```

---

## 🔄 Auto-Hide During Indexing (v1.43.17)

Events matching exclusion rules are automatically hidden when files are uploaded or reindexed.

### Integration in file_processing.py

```python
# Pre-load exclusions (cached for bulk performance)
from auto_hide import get_cached_exclusions, has_exclusions_configured
auto_hide_exclusions = get_cached_exclusions() if has_exclusions_configured() else None

# After normalize_event() is called...
event = apply_auto_hide(event, auto_hide_exclusions)
```

### apply_auto_hide() Function

```python
def apply_auto_hide(event: dict, exclusions: dict = None) -> dict:
    """
    Check if event should be auto-hidden based on exclusion rules.
    Called during indexing to automatically hide known-good events.
    """
    search_blob = event.get('search_blob', '')
    if not search_blob:
        return event
    
    if exclusions is None:
        from auto_hide import get_cached_exclusions
        exclusions = get_cached_exclusions()
    
    from auto_hide import should_auto_hide_event
    if should_auto_hide_event(event, search_blob, exclusions):
        event['is_hidden'] = True
        event['hidden_reason'] = 'auto_hide_index'
    
    return event
```

### Log Output

```
[INDEX FILE] Auto-hide enabled: will hide known-good events during indexing
[INDEX FILE] ✓ Parsed 50,000 events, indexed 50,000 to case_18 (3,250 auto-hidden)
```

### Supported Operations

- ✅ Initial file upload
- ✅ Single file reindex
- ✅ Bulk reindex (all files)
- ✅ Select reindex (multiple files)

---

## 📊 Hidden Events Dashboard Counter (v1.43.17)

The Case Files page shows hidden events count in the Event Statistics tile.

### Display

| Total Events | SIGMA Violations | IOC Events | **Hidden Events** |
|--------------|------------------|------------|-------------------|
| 6,589,717 | 71,148 | 41,786 | 216,692 |

### Implementation

**hidden_files.py**:
```python
def get_hidden_events_count(case_id: int) -> int:
    """Get count of hidden EVENTS in OpenSearch for a case."""
    from opensearchpy import OpenSearch
    client = OpenSearch(hosts=[{'host': 'localhost', 'port': 9200}])
    
    index_name = f"case_{case_id}"
    if not client.indices.exists(index=index_name):
        return 0
    
    result = client.count(
        index=index_name,
        body={"query": {"term": {"is_hidden": True}}}
    )
    return result.get('count', 0)
```

---

## 🔄 Manual Hide Task Flow

For already-indexed files, use the "Hide Known Good" button in Search Events.

### 1. User Initiates Hide

```
User clicks "Hide Known Good" button
         │
         ▼
showHideKnownGoodModal()
├── Calls /api/has-exclusions
├── If no exclusions: Show "No Exclusions" phase
└── If has exclusions: Show confirmation with summary
         │
         ▼
User clicks "Start Hiding"
         │
         ▼
POST /case/<id>/hide-known-good
├── Returns task_id
└── Starts polling pollHideKnownGoodStatus()
```

### 2. Celery Task Execution

```python
@celery_app.task(bind=True, name='tasks.hide_known_good_events')
def hide_known_good_events_task(self, case_id, user_id):
    """
    Phase 1: Load Exclusions from SystemToolsSetting
    Phase 2: Scan Events (scroll API, check each event)
    Phase 3: Hide Events (bulk update in batches)
    Phase 4: Complete (refresh index, return counts)
    """
```

### 3. Progress Updates

| State | Frontend Display |
|-------|------------------|
| `scanning` | "Scanning Events... X% (Y events scanned, Z matches found)" |
| `hiding` | "Hiding Events... X% (Y / Z hidden)" |
| `complete` | Results with summary |

---

## 🧪 Testing & Troubleshooting

### Test Exclusion Matching

```python
# Test in Python console
cd /opt/casescope && source venv/bin/activate
python3 << 'EOF'
from app.auto_hide import should_auto_hide_event, load_exclusions_for_auto_hide

exclusions = load_exclusions_for_auto_hide()
print(f"Loaded: {len(exclusions['rmm_executables'])} RMM, {len(exclusions['edr_tools'])} EDR")

# Test event
event = {'process': {'name': 'ipconfig.exe'}}
blob = "snapagent.exe cmd.exe ipconfig.exe /all"

result = should_auto_hide_event(event, blob, exclusions)
print(f"Should hide: {result}")  # True if EDR+routine configured
EOF
```

### Check Hidden Events Count

```bash
# Direct OpenSearch query
curl -s "localhost:9200/case_18/_count" -H 'Content-Type: application/json' -d '{
  "query": {"term": {"is_hidden": true}}
}' | jq '.count'
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No auto-hide during indexing | No exclusions configured | Configure in Settings → System Tools |
| URL matches (huntress.io) | Pattern too broad | Use full executable names with .exe |
| Hidden count shows 0 | Query error | Check `get_hidden_events_count()` logs |
| Events not hiding | Pattern mismatch | Check search_blob contains pattern |

### Log Locations

- **Workers log**: `/opt/casescope/logs/workers.log`
- **Search patterns**: `[AUTO_HIDE]`, `[INDEX FILE]`, `[HIDE KNOWN GOOD]`

```bash
grep "auto-hidden" /opt/casescope/logs/workers.log | tail -20
grep "AUTO_HIDE" /opt/casescope/logs/workers.log | tail -20
```

---

## 📈 Performance

### Auto-Hide During Indexing
- Uses cached exclusions (60-second TTL)
- Negligible overhead per event
- Logged in index completion message

### Manual Hide Task
- Scroll API: 1000 events per batch
- Bulk updates: 500 events per batch
- Progress updates every batch

### Benchmarks (10M event case)

| Phase | Duration |
|-------|----------|
| Load exclusions | <1 sec (cached) |
| Scan events | 5-15 min |
| Hide events | 2-10 min |

---

## 📝 Version History

| Version | Changes |
|---------|---------|
| v1.38.0 | Initial implementation: RMM tools, Remote tools, Known-good IPs |
| v1.40.0 | Added EDR tools with context-aware exclusion |
| v1.43.8 | Added progress tracking during hiding phase |
| v1.43.15 | **Simplified search_blob matching** - Checks patterns anywhere in search_blob instead of specific JSON paths. Catches grandparent processes. |
| v1.43.16 | **Fixed URL false matches** - Added .exe context requirement. Prevents `huntress.io` matching "huntress" pattern. |
| v1.43.17 | **Auto-hide during indexing** - Events hidden at index time. Created modular `auto_hide.py`. Added Hidden Events dashboard counter. |

---

## 📎 Quick Reference

### API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/settings/system-tools/` | GET | Admin UI |
| `/settings/system-tools/api/exclusions` | GET | Get all active exclusions |
| `/settings/system-tools/api/has-exclusions` | GET | Check if any exclusions exist |
| `/settings/system-tools/case/<id>/hide-known-good` | POST | Start manual hide task |
| `/settings/system-tools/case/<id>/hide-known-good/status/<tid>` | GET | Poll task status |

### Key Functions

| Function | File | Purpose |
|----------|------|---------|
| `should_auto_hide_event()` | auto_hide.py | Core matching logic |
| `get_cached_exclusions()` | auto_hide.py | Load exclusions with caching |
| `apply_auto_hide()` | file_processing.py | Integration during indexing |
| `hide_known_good_events_task()` | tasks.py | Manual hide Celery task |
| `get_hidden_events_count()` | hidden_files.py | Dashboard counter |

### Exclusion Types Summary

| Type | Matching Rule | Example |
|------|---------------|---------|
| RMM Tool | Pattern in search_blob | `ltsvc.exe` anywhere in event |
| Remote Tool | Pattern + Session ID both in blob | `screenconnect` + `abc123` |
| EDR Tool | Executable + Routine (no response) | `snapagent.exe` + `ipconfig.exe` |
| Known IP | Source IP in range | `192.168.1.0/24` |

---

## Cross References

### USES

- `app/models.py` - SystemToolsSetting model
- OpenSearch bulk API for event updates
- `app/event_normalization.py` - Creates search_blob field

### USED BY

- `AI_TRIAGE_SEARCH_DOCUMENTATION.md` - Loads exclusions for event filtering

---

**✅ VERIFIED**: All information extracted from live codebase (December 1, 2025, v1.43.17)
