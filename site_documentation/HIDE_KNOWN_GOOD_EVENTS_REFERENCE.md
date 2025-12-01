# Hide Known Good Events - Technical Reference

**Version**: 1.43.8  
**Last Updated**: December 1, 2025  
**Feature Introduced**: v1.38.0  
**EDR Tools Added**: v1.40.0  
**Progress Tracking Added**: v1.43.8

---

## 📋 Overview

The "Hide Known Good Events" feature allows analysts to automatically hide events from known-good sources (RMM tools, EDR health checks, approved remote sessions, internal IPs) to reduce noise during investigations. Hidden events remain in the database and can be viewed by changing the Hidden Events filter.

### Purpose
- Reduce noise from legitimate IT management tools
- Focus analyst attention on truly suspicious activity
- Handle large cases (10M+ events) without manual filtering
- Preserve data integrity (events are hidden, not deleted)

---

## 🏗️ Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         FRONTEND                                     │
├─────────────────────────────────────────────────────────────────────┤
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
│                         BACKEND ROUTES                               │
├─────────────────────────────────────────────────────────────────────┤
│  routes/system_tools.py                                              │
│  ├── /settings/system-tools/ (admin UI)                             │
│  ├── /settings/system-tools/rmm/add (POST)                          │
│  ├── /settings/system-tools/remote/add (POST)                       │
│  ├── /settings/system-tools/edr/add (POST)                          │
│  ├── /settings/system-tools/ip/save (POST)                          │
│  ├── /settings/system-tools/api/exclusions (GET)                    │
│  ├── /settings/system-tools/api/has-exclusions (GET)                │
│  ├── /settings/system-tools/case/<id>/hide-known-good (POST)        │
│  └── /settings/system-tools/case/<id>/hide-known-good/status/<tid>  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         CELERY TASK                                  │
├─────────────────────────────────────────────────────────────────────┤
│  tasks.py                                                            │
│  ├── hide_known_good_events_task(case_id, user_id)                  │
│  └── _should_hide_event_task(hit, exclusions)                       │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         DATABASE/STORAGE                             │
├─────────────────────────────────────────────────────────────────────┤
│  PostgreSQL: system_tools_setting table                              │
│  OpenSearch: case_<id> index (is_hidden, hidden_by, hidden_at)      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Files Reference

| File | Purpose | Key Functions/Elements |
|------|---------|------------------------|
| `app/routes/system_tools.py` | Route handlers, API endpoints | `hide_known_good_events()`, `_get_exclusions_dict()`, `_should_hide_event()` |
| `app/tasks.py` | Celery background task | `hide_known_good_events_task()`, `_should_hide_event_task()` |
| `app/models.py` | Database model | `SystemToolsSetting` class |
| `app/templates/system_tools.html` | Admin settings UI | RMM/Remote/EDR/IP configuration forms |
| `app/templates/search_events.html` | Search page with hide modal | `hideKnownGoodModal`, JavaScript functions |

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
    
    -- For EDR tools (v1.40.0)
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

CREATE INDEX idx_setting_type ON system_tools_setting(setting_type);
CREATE INDEX idx_is_active ON system_tools_setting(is_active);
```

### OpenSearch Event Fields (added when hidden)

```json
{
  "is_hidden": true,
  "hidden_by": 1,
  "hidden_at": "2025-12-01T14:30:00.000Z",
  "hidden_reason": "known_good_exclusion"
}
```

---

## 🔧 Exclusion Types

### 1. RMM Tools (Full Exclusion)

**Behavior**: Hide ALL events where parent process matches the pattern.

**Predefined Tools** (in `system_tools.py`):
- ConnectWise Automate (LabTech): `LTSVC.exe,LTSvcMon.exe,LTTray.exe,LabTech*.exe`
- Datto RMM: `AEMAgent.exe,Datto*.exe,CagService.exe`
- Kaseya VSA: `AgentMon.exe,Kaseya*.exe,KaseyaD.exe`
- NinjaRMM: `NinjaRMMAgent.exe,NinjaRMM*.exe`
- Syncro: `Syncro*.exe,SyncroLive.exe`
- Atera: `AteraAgent.exe,Atera*.exe`
- N-able: `N-central*.exe,BASupSrvc*.exe`
- Pulseway: `PCMonitorSrv.exe,Pulseway*.exe`

**Matching Logic** (`_should_hide_event_task`):
```python
parent_name = parent.get('name') or parent.get('executable')
parent_name_only = parent_name.split('\\')[-1]  # Extract filename

for rmm_pattern in exclusions['rmm_executables']:
    if fnmatch.fnmatch(parent_name_only, rmm_pattern):
        return True  # HIDE
    if fnmatch.fnmatch(parent_name, f'*{rmm_pattern}'):
        return True  # HIDE
```

### 2. Remote Tools (Session ID Matching)

**Behavior**: Hide events only if BOTH the tool executable is present AND a known-good session ID is found.

**Predefined Tools**:
- ScreenConnect / ConnectWise Control
- TeamViewer
- AnyDesk
- Splashtop
- GoTo Assist
- BeyondTrust (Bomgar)

**Matching Logic**:
```python
proc_name = proc.get('name') or proc.get('executable')
cmd_line = proc.get('command_line')
search_blob = src.get('search_blob')

for tool_config in exclusions['remote_tools']:
    pattern = tool_config['pattern']
    if pattern in proc_name or pattern in search_blob:
        for known_id in tool_config['known_good_ids']:
            if known_id in cmd_line or known_id in search_blob:
                return True  # HIDE
```

### 3. EDR Tools (Context-Aware - v1.40.0)

**Behavior**: 
- **HIDE** routine health checks (whoami, systeminfo, ipconfig)
- **KEEP** response/isolation actions (critical for incident understanding)

**Predefined Tools**:
- Huntress: `HuntressAgent.exe,HuntressUpdater.exe`
- Blackpoint (SNAP): `SnapAgent.exe`
- SentinelOne: `SentinelAgent.exe,SentinelCtl.exe`
- CrowdStrike Falcon: `CSAgent.exe,CSFalconService.exe`
- Microsoft Defender ATP: `MsSense.exe,SenseIR.exe`
- Sophos Intercept X: `SophosAgent.exe`
- Carbon Black: `CbDefense*.exe,RepMgr.exe`

**Matching Logic**:
```python
for edr_config in exclusions['edr_tools']:
    parent_is_edr = any(
        fnmatch.fnmatch(parent_name_only, exe) or exe in parent_name
        for exe in edr_config['executables']
    )
    
    if parent_is_edr:
        # FIRST: Check for response action - DON'T HIDE
        if edr_config['keep_responses']:
            if any(pattern in cmd_line or pattern in search_blob 
                   for pattern in edr_config['response_patterns']):
                return False  # DON'T hide - response action!
        
        # SECOND: Check for routine command - HIDE
        if edr_config['exclude_routine']:
            if any(routine in cmd_line 
                   for routine in edr_config['routine_commands']):
                return True  # HIDE - routine health check
```

### 4. Known-Good IPs

**Behavior**: Hide events from specified IP addresses or CIDR ranges.

**Format**: 
- Single IP: `192.168.1.50`
- CIDR range: `10.0.0.0/8`
- One entry per line in the UI

**Matching Logic**:
```python
source_ip = None
# Try various IP fields
if src.get('source', {}).get('ip'):
    source_ip = src['source']['ip']
elif src.get('host', {}).get('ip'):
    source_ip = src['host']['ip']
elif proc.get('user_logon', {}).get('ip'):
    source_ip = proc['user_logon']['ip']

if source_ip:
    for ip_range in exclusions['known_good_ips']:
        ip = ipaddress.ip_address(source_ip)
        if '/' in ip_range:
            network = ipaddress.ip_network(ip_range, strict=False)
            if ip in network:
                return True  # HIDE
        else:
            if ip == ipaddress.ip_address(ip_range):
                return True  # HIDE
```

---

## 🔄 Task Execution Flow

### 1. User Initiates Hide

```
User clicks "Hide Known Good" button
         │
         ▼
showHideKnownGoodModal()
├── Calls /api/has-exclusions
├── If no exclusions: Show "No Exclusions" phase
├── If has exclusions: Show confirmation phase
│   └── Loads exclusion summary via /api/exclusions
         │
         ▼
User clicks "Start Hiding"
         │
         ▼
startHideKnownGood()
├── POST /case/<id>/hide-known-good
├── Returns task_id
└── Starts polling pollHideKnownGoodStatus()
```

### 2. Celery Task Execution

```python
@celery_app.task(bind=True, name='tasks.hide_known_good_events')
def hide_known_good_events_task(self, case_id, user_id):
    """
    Phase 1: Load Exclusions
    - Query SystemToolsSetting where is_active=True
    - Build exclusions dict: rmm_executables, remote_tools, edr_tools, known_good_ips
    
    Phase 2: Scan Events (PROGRESS state: 'scanning')
    - Use OpenSearch scroll API (batch_size=1000)
    - Query: {"must_not": [{"term": {"is_hidden": True}}]}
    - For each event: _should_hide_event_task(hit, exclusions)
    - Build events_to_hide list
    - Update progress: {status: 'scanning', percent: X, found: Y}
    
    Phase 3: Hide Events (PROGRESS state: 'hiding')
    - Bulk update in batches of 500
    - Set: is_hidden=true, hidden_by, hidden_at, hidden_reason
    - Update progress: {status: 'hiding', percent: X, hidden: Y}
    - Track actual successes from bulk response
    
    Phase 4: Complete (SUCCESS state)
    - Refresh OpenSearch index
    - Return: {status: 'success', hidden: X, found: Y, processed: Z}
    """
```

### 3. Progress Polling

Frontend polls `/case/<id>/hide-known-good/status/<task_id>` every 500-1000ms:

| State | Frontend Display |
|-------|------------------|
| `pending` | "Queued..." |
| `starting` | "Initializing..." |
| `scanning` | "Scanning Events... X% (Y events scanned, Z matches found)" |
| `hiding` | "Hiding Events... X% (Y / Z hidden)" |
| `complete` | Results phase with summary |
| `error` | Error message |

---

## 🧪 Testing & Troubleshooting

### Test Exclusion Matching

```python
# Test in Python console
cd /opt/casescope/app && source ../venv/bin/activate
python3 << 'EOF'
from main import app
from routes.system_tools import _get_exclusions_dict, _should_hide_event

with app.app_context():
    exclusions = _get_exclusions_dict()
    print("Loaded exclusions:")
    print(f"  RMM: {len(exclusions['rmm_executables'])} patterns")
    print(f"  Remote: {len(exclusions['remote_tools'])} tools")
    print(f"  EDR: {len(exclusions['edr_tools'])} tools")
    print(f"  IPs: {len(exclusions['known_good_ips'])} ranges")
    
    # Test a mock event
    test_event = {
        '_source': {
            'process': {
                'name': 'cmd.exe',
                'parent': {'name': 'LTSVC.exe'},
                'command_line': 'whoami'
            }
        }
    }
    
    result = _should_hide_event(test_event, exclusions)
    print(f"\nTest event should hide: {result}")
EOF
```

### Check Task Status

```python
from celery.result import AsyncResult
task = AsyncResult('task-id-here')
print(f"State: {task.state}")
print(f"Info: {task.info}")
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "No exclusions defined" | No active settings | Configure in Settings → System Tools |
| Events not hiding | Pattern mismatch | Check executable patterns, case sensitivity |
| Progress stuck at scanning | Large case | Normal - scroll API processing millions of events |
| Progress stuck at hiding | Bulk update slow | Normal - OpenSearch bulk operations |
| Count mismatch (found vs hidden) | Bulk errors | Check workers.log for specific failures |

### Log Locations

- **Workers log**: `/opt/casescope/logs/workers.log`
- **Search pattern**: `[HIDE KNOWN GOOD]`

```bash
grep "HIDE KNOWN GOOD" /opt/casescope/logs/workers.log | tail -20
```

---

## 🔗 Related Features

| Feature | Relationship |
|---------|--------------|
| **Hidden Events Filter** | View hidden events by changing filter to "Show" or "Only Hidden" |
| **Manual Hide/Unhide** | Bulk actions in search results to hide/unhide selected events |
| **AI Triage Search** | Can reference exclusions via `/api/exclusions` endpoint |
| **System Tools Settings** | Admin UI for configuring exclusions |

---

## 📈 Performance Characteristics

### Benchmarks (10M event case)

| Phase | Duration | Notes |
|-------|----------|-------|
| Load exclusions | <1 sec | Single DB query |
| Scan events | 5-15 min | Scroll API, 1000/batch |
| Hide events | 2-10 min | Bulk update, 500/batch |
| Index refresh | 5-30 sec | OpenSearch refresh |

### Optimization Notes

1. **Scroll API**: Uses 10-minute scroll timeout, 1000 events per batch
2. **Bulk updates**: 500 events per batch, no refresh until complete
3. **Query optimization**: Only fetches required `_source` fields: `["process", "parent", "host", "source", "search_blob"]`
4. **Skip hidden**: Query includes `must_not: [term: is_hidden: true]` to skip already-hidden events

---

## 🔮 Future Improvements

1. **Index-time hiding**: Check exclusions during `index_file()` to hide events on ingest
2. **Exclusion inheritance**: Case-level exclusion overrides
3. **Exclusion testing**: UI to test patterns against sample events before applying
4. **Bulk unhide by rule**: Unhide all events hidden by a specific rule

---

## 📝 Version History

| Version | Changes |
|---------|---------|
| v1.38.0 | Initial implementation: RMM tools, Remote tools, Known-good IPs |
| v1.40.0 | Added EDR tools with context-aware exclusion (routine vs response) |
| v1.43.8 | Added progress tracking during hiding phase, accurate success counting |

---

## 📎 Quick Reference

### API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/settings/system-tools/` | GET | Admin UI |
| `/settings/system-tools/api/exclusions` | GET | Get all active exclusions |
| `/settings/system-tools/api/has-exclusions` | GET | Check if any exclusions exist |
| `/settings/system-tools/case/<id>/hide-known-good` | POST | Start hide task |
| `/settings/system-tools/case/<id>/hide-known-good/status/<tid>` | GET | Poll task status |

### Key Functions

| Function | File | Purpose |
|----------|------|---------|
| `hide_known_good_events_task()` | tasks.py | Main Celery task |
| `_should_hide_event_task()` | tasks.py | Check if event matches exclusions |
| `_get_exclusions_dict()` | routes/system_tools.py | Load exclusions from DB |
| `showHideKnownGoodModal()` | search_events.html | Open modal |
| `pollHideKnownGoodStatus()` | search_events.html | Poll task progress |

### Database Model

```python
class SystemToolsSetting(db.Model):
    __tablename__ = 'system_tools_setting'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_type = db.Column(db.String(50))      # 'rmm_tool', 'remote_tool', 'edr_tool', 'known_good_ip'
    tool_name = db.Column(db.String(100))
    executable_pattern = db.Column(db.String(500))
    known_good_ids = db.Column(db.Text)          # JSON list
    ip_or_cidr = db.Column(db.String(50))
    exclude_routine = db.Column(db.Boolean)      # EDR only
    keep_responses = db.Column(db.Boolean)       # EDR only
    routine_commands = db.Column(db.Text)        # EDR only, JSON
    response_patterns = db.Column(db.Text)       # EDR only, JSON
    description = db.Column(db.String(500))
    created_by = db.Column(db.Integer)
    is_active = db.Column(db.Boolean)
```

---

**✅ VERIFIED**: All information extracted from live codebase (December 1, 2025)

