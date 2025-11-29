# AI Triage Search - Complete Technical Documentation

**Version:** 1.39.0  
**Last Updated:** 2025-11-29  
**Author:** CaseScope Development Team

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [The 9-Phase Methodology](#the-9-phase-methodology)
4. [File Structure](#file-structure)
5. [Database Schema](#database-schema)
6. [API Endpoints](#api-endpoints)
7. [Frontend Components](#frontend-components)
8. [Celery Task Workflow](#celery-task-workflow)
9. [Helper Functions](#helper-functions)
10. [Configuration & Constants](#configuration--constants)
11. [Error Handling](#error-handling)
12. [Testing & Debugging](#testing--debugging)
13. [Common Issues & Fixes](#common-issues--fixes)
14. [Future Improvements](#future-improvements)

---

## Overview

The **AI Triage Search** is an automated attack chain analysis system that:

1. Extracts IOCs (Indicators of Compromise) from EDR/MDR reports
2. Hunts those IOCs across all case events to discover related indicators
3. Builds process trees and matches MITRE ATT&CK patterns
4. Auto-tags key timeline events for analyst review

### Key Features

- **9-phase automated analysis** running as a background Celery task
- **Real-time progress updates** via polling
- **IOC classification** into SPECIFIC (auto-tag) vs BROAD (aggregation only)
- **MITRE ATT&CK pattern matching** for technique identification
- **Process tree building** from EDR parent/child relationships
- **Timeline auto-tagging** with purple color for AI-discovered events

### Entry Points

The system supports three entry points:

| Entry Point | Trigger | Description |
|-------------|---------|-------------|
| `full_triage` | Case has EDR report | Full 9-phase analysis starting from report |
| `ioc_hunt` | Case has IOCs but no report | Hunt using existing IOCs + user-provided date |
| `tag_hunt` | Case has tagged events only | Use tagged events as anchor points |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           FRONTEND                                   │
│  search_events.html                                                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐ │
│  │ Triage Button   │───▶│ Modal (9 phases)│───▶│ Results Display │ │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘ │
│           │                      │                                   │
│           │ startAITriageSearch()│ pollAITriageStatus()              │
│           ▼                      ▼                                   │
└───────────┼──────────────────────┼──────────────────────────────────┘
            │                      │
            ▼                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           BACKEND                                    │
│  routes/triage_report.py                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐ │
│  │ /run (POST)     │───▶│ Create Record   │───▶│ Start Celery    │ │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘ │
│  ┌─────────────────┐                                                │
│  │ /status (GET)   │◀── Poll for progress                           │
│  └─────────────────┘                                                │
└───────────┼─────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        CELERY WORKER                                 │
│  tasks.py - run_ai_triage_search()                                   │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │ Phase 1: IOC Extraction                                          ││
│  │ Phase 2: IOC Classification                                      ││
│  │ Phase 3: Snowball Hunting                                        ││
│  │ Phase 4: Malware/Recon Hunting                                   ││
│  │ Phase 5: SPECIFIC IOC Search                                     ││
│  │ Phase 6: BROAD IOC Aggregation                                   ││
│  │ Phase 7: Time Window Analysis                                    ││
│  │ Phase 8: Process Trees + MITRE                                   ││
│  │ Phase 9: Timeline Auto-Tagging                                   ││
│  └─────────────────────────────────────────────────────────────────┘│
└───────────┼─────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         DATA STORES                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │
│  │ PostgreSQL  │    │ OpenSearch  │    │ Redis       │             │
│  │ (AITriage   │    │ (Events)    │    │ (Celery)    │             │
│  │  Search)    │    │             │    │             │             │
│  └─────────────┘    └─────────────┘    └─────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## The 9-Phase Methodology

### Phase 1: IOC Extraction from Report

**Purpose:** Extract all IOCs from the EDR/MDR report text.

**Functions Used:**
- `extract_iocs_with_llm()` - Primary extraction using Ollama LLM
- `extract_iocs_with_regex()` - Fallback if LLM fails

**IOC Types Extracted:**
| Type | Description | Example |
|------|-------------|---------|
| `ips` | IP addresses | `192.168.1.100` |
| `hostnames` | Computer names | `WORKSTATION-01` |
| `usernames` | User accounts | `jsmith`, `admin` |
| `sids` | Security Identifiers | `S-1-5-21-...` |
| `paths` | File paths | `C:\Windows\Temp\malware.exe` |
| `processes` | Executable names | `rundll32.exe` |
| `hashes` | File hashes | `a1b2c3d4...` (MD5/SHA1/SHA256) |
| `commands` | Command lines | `nltest /dclist:` |
| `tools` | Attack tools | `Cobalt Strike`, `Mimikatz` |

**Progress Update:** 5-10%

---

### Phase 2: IOC Classification

**Purpose:** Classify IOCs as SPECIFIC (auto-tag) or BROAD (aggregation only).

**Classification Logic:**

```python
# SPECIFIC IOCs - Low event count, high value, will be auto-tagged
specific_iocs = {
    'processes': [...],   # Executable names
    'paths': [...],       # File paths
    'hashes': [...],      # File hashes
    'commands': [...],    # Command lines
    'tools': [...]        # Attack tools
}

# BROAD IOCs - High event count, used for discovery only
broad_iocs = {
    'usernames': [...],   # User accounts
    'hostnames': [...],   # Computer names
    'ips': [...],         # IP addresses
    'sids': [...]         # Security Identifiers
}
```

**Why This Matters:**
- SPECIFIC IOCs are rare and directly indicate malicious activity
- BROAD IOCs (like usernames) may appear in thousands of events
- Auto-tagging BROAD IOCs would flood the timeline with noise

**Progress Update:** 12-15%

---

### Phase 3: Snowball Hunting

**Purpose:** Hunt extracted IOCs to discover NEW related indicators.

**Algorithm:**
```
FOR each IP in known_ips (limit 10):
    results = search_ioc(IP)
    discovered_ips += extract_ips(results) - known_ips
    discovered_hostnames += extract_hostnames(results) - known_hostnames
    discovered_usernames += extract_usernames(results) - known_usernames

FOR each hostname in known_hostnames (limit 10):
    results = search_ioc(hostname)
    discovered_ips += extract_ips(results) - known_ips
    discovered_usernames += extract_usernames(results) - known_usernames
```

**Functions Used:**
- `search_ioc()` - Search OpenSearch for IOC matches
- `extract_from_search_results()` - Extract IPs, hostnames, users from results

**Progress Update:** 20-40%

---

### Phase 4: Malware/Recon Hunting

**Purpose:** Search for reconnaissance commands and malware indicators.

**Recon Search Terms (RECON_SEARCH_TERMS):**
```python
RECON_SEARCH_TERMS = [
    'nltest', 'net group', 'net user', 'whoami',
    'ipconfig', 'systeminfo', 'netstat', 'quser',
    'tasklist', 'wmic', 'ping', 'nslookup', 'route'
]
```

**Functions Used:**
- `extract_recon_from_results()` - Extract command lines and executables

**Progress Update:** 42-50%

---

### Phase 5: SPECIFIC IOC Search

**Purpose:** Find all events matching SPECIFIC IOCs for auto-tagging.

**Process:**
```python
specific_anchors = []
for ioc_type, values in specific_iocs.items():
    for value in values:
        results = search_ioc(value)
        for hit in results[:100]:  # Limit per IOC
            specific_anchors.append({
                'event_id': hit['_id'],
                'event': hit,
                'ioc_type': ioc_type,
                'matched_ioc': value,
                'timestamp': hit['_source']['@timestamp'],
                'hostname': hit['_source']['normalized_computer']
            })
```

**Progress Update:** 52-55%

---

### Phase 6: BROAD IOC Aggregation

**Purpose:** Discover additional IOCs via OpenSearch aggregations.

**Aggregation Query:**
```python
agg_query = {
    "size": 0,
    "query": {"query_string": {"query": f'"{value}"'}},
    "aggs": {
        "hosts": {"terms": {"field": "normalized_computer.keyword", "size": 50}},
        "users": {"terms": {"field": "process.user.name.keyword", "size": 50}},
        "ips": {"terms": {"field": "host.ip.keyword", "size": 50}}
    }
}
```

**Why Aggregations:**
- Avoids retrieving thousands of individual events
- Returns unique values with counts
- Much faster than full event retrieval

**Progress Update:** 57-60%

---

### Phase 7: Time Window Analysis

**Purpose:** Analyze ±5 minute windows around anchor events.

**Process:**
```python
for anchor in specific_anchors[:30]:
    hostname = anchor['hostname']
    timestamp = anchor['timestamp']
    
    # Create unique window key to avoid duplicates
    window_key = f"{hostname}|{timestamp[:16]}"
    
    # Search ±5 minutes on same host
    time_query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"normalized_computer.keyword": hostname}},
                    {"range": {"@timestamp": {
                        "gte": timestamp - 5min,
                        "lte": timestamp + 5min
                    }}}
                ]
            }
        }
    }
    
    window_events.extend(results)
```

**Progress Update:** 62-72%

---

### Phase 8: Process Tree Building + MITRE Pattern Matching

**Purpose:** Build process trees and identify MITRE ATT&CK techniques.

**MITRE Patterns (MITRE_PATTERNS):**
```python
MITRE_PATTERNS = {
    'T1033': {
        'name': 'System Owner/User Discovery',
        'processes': ['whoami.exe', 'quser.exe'],
        'indicators': ['whoami', '/all']
    },
    'T1482': {
        'name': 'Domain Trust Discovery',
        'processes': ['nltest.exe'],
        'indicators': ['domain_trusts', '/all_trusts']
    },
    'T1018': {
        'name': 'Remote System Discovery',
        'processes': ['nltest.exe', 'ping.exe', 'nslookup.exe'],
        'indicators': ['dclist', 'ping', 'net view']
    },
    # ... more patterns
}
```

**Process Tree Building:**
```python
for event in window_events:
    parent = event['process']['parent']
    if parent['name'] in ['cmd.exe', 'powershell.exe']:
        key = f"{hostname}|{parent['pid']}"
        suspicious_parents[key]['children'].append({
            'name': process_name,
            'command_line': cmd,
            'timestamp': timestamp
        })
```

**Progress Update:** 75-85%

---

### Phase 9: Timeline Event Auto-Tagging

**Purpose:** Filter and auto-tag key timeline events.

**Timeline-Worthy Processes (TIMELINE_PROCESSES):**
```python
TIMELINE_PROCESSES = [
    'nltest.exe', 'whoami.exe', 'ipconfig.exe', 'ping.exe',
    'net.exe', 'net1.exe', 'netstat.exe', 'systeminfo.exe',
    'quser.exe', 'query.exe', 'nslookup.exe', 'route.exe',
    'cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe',
    'mshta.exe', 'wscript.exe', 'cscript.exe',
    'advanced_ip_scanner.exe', 'psexec.exe', 'winscp.exe',
    'notepad.exe', 'wordpad.exe'
]
```

**Auto-Tagging Process:**
```python
for event in timeline_events:
    if event_id not in existing_tag_ids:
        tag = TimelineTag(
            case_id=case_id,
            user_id=user_id,
            event_id=event_id,
            index_name=f"case_{case_id}",
            event_data=json.dumps(event['_source']),
            tag_color='purple',  # AI-tagged events are purple
            notes=f"[AI Triage Timeline Event]\n..."
        )
        db.session.add(tag)
```

**Progress Update:** 87-100%

---

## File Structure

```
/opt/casescope/app/
├── tasks.py                          # Celery task: run_ai_triage_search()
│   ├── TIMELINE_PROCESSES            # List of timeline-worthy processes
│   ├── MITRE_PATTERNS                # MITRE ATT&CK pattern definitions
│   └── run_ai_triage_search()        # Main 9-phase task
│
├── routes/triage_report.py           # API routes + helper functions
│   ├── IOC_TYPE_MAP                  # IOC type mappings
│   ├── NOISE_USERS                   # Filtered user accounts
│   ├── NOT_HOSTNAMES                 # Blocklist for hostname extraction
│   ├── RECON_SEARCH_TERMS            # Reconnaissance search terms
│   ├── extract_iocs_with_llm()       # LLM-based extraction
│   ├── extract_iocs_with_regex()     # Regex-based extraction
│   ├── extract_from_search_results() # Extract IPs/hosts/users from results
│   ├── extract_recon_from_results()  # Extract commands/executables
│   ├── search_ioc()                  # Search OpenSearch for IOC
│   ├── is_valid_hostname()           # Hostname validation
│   ├── is_machine_account()          # Check for machine accounts ($)
│   ├── run_ai_triage_search()        # POST /run endpoint
│   ├── get_ai_triage_status()        # GET /status endpoint
│   └── list_ai_triage_searches()     # GET /list endpoint
│
├── models.py                         # Database models
│   └── AITriageSearch                # Main model for search results
│
├── templates/search_events.html      # Frontend template
│   ├── triageReportModal             # Modal HTML structure
│   ├── showTriageModal()             # Open modal function
│   ├── startAITriageSearch()         # Start search function
│   ├── pollAITriageStatus()          # Poll for progress
│   ├── showTriageResults()           # Display results
│   └── showTriageError()             # Display errors
│
└── migrations/add_ai_triage_search.py # Database migration
```

---

## Database Schema

### AITriageSearch Table

```sql
CREATE TABLE ai_triage_search (
    -- Primary Key
    id SERIAL PRIMARY KEY,
    
    -- Foreign Keys
    case_id INTEGER NOT NULL REFERENCES "case"(id),
    generated_by INTEGER NOT NULL REFERENCES "user"(id),
    
    -- Task Tracking
    status VARCHAR(20) DEFAULT 'pending',  -- pending, running, completed, failed
    celery_task_id VARCHAR(255),
    
    -- Entry Point
    entry_point VARCHAR(50),  -- full_triage, ioc_hunt, tag_hunt
    search_date TIMESTAMP,
    
    -- Results (JSON)
    iocs_extracted_json TEXT,      -- IOCs from report
    iocs_discovered_json TEXT,     -- IOCs discovered via hunting
    timeline_json TEXT,            -- Attack timeline events
    process_trees_json TEXT,       -- Process tree structures
    mitre_techniques_json TEXT,    -- MITRE techniques found
    summary_json TEXT,             -- Full summary for display
    
    -- Counts
    iocs_extracted_count INTEGER DEFAULT 0,
    iocs_discovered_count INTEGER DEFAULT 0,
    events_analyzed_count INTEGER DEFAULT 0,
    timeline_events_count INTEGER DEFAULT 0,
    auto_tagged_count INTEGER DEFAULT 0,
    techniques_found_count INTEGER DEFAULT 0,
    process_trees_count INTEGER DEFAULT 0,
    
    -- Progress Tracking
    current_phase INTEGER DEFAULT 0,       -- 1-9
    current_phase_name VARCHAR(100),
    progress_message VARCHAR(500),
    progress_percent INTEGER DEFAULT 0,
    
    -- Timing
    generation_time_seconds FLOAT,
    error_message TEXT,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

-- Indexes
CREATE INDEX idx_ai_triage_search_case_id ON ai_triage_search(case_id);
CREATE INDEX idx_ai_triage_search_status ON ai_triage_search(status);
CREATE INDEX idx_ai_triage_search_celery_task_id ON ai_triage_search(celery_task_id);
CREATE INDEX idx_ai_triage_search_created_at ON ai_triage_search(created_at);
```

### Related Tables

| Table | Relationship | Description |
|-------|--------------|-------------|
| `case` | FK: case_id | Parent case for the search |
| `user` | FK: generated_by | User who initiated the search |
| `timeline_tag` | Created by Phase 9 | Auto-tagged events |
| `ioc` | Referenced in extraction | Existing IOCs used for ioc_hunt |

---

## API Endpoints

### Start AI Triage Search

```
POST /case/<case_id>/ai-triage-search/run
```

**Request:** None (uses case's EDR report)

**Response:**
```json
{
    "success": true,
    "search_id": 123,
    "task_id": "abc123-def456-..."
}
```

**Error Response:**
```json
{
    "error": "Case not found"
}
```

---

### Get Search Status

```
GET /case/<case_id>/ai-triage-search/<search_id>/status
```

**Response (Running):**
```json
{
    "status": "running",
    "phase": 3,
    "phase_name": "Snowball Hunting",
    "message": "Searching IP: 192.168.1.100",
    "percent": 25,
    "error_message": null
}
```

**Response (Completed):**
```json
{
    "status": "completed",
    "phase": 9,
    "phase_name": "Complete",
    "message": "AI Triage Search complete! Tagged 15 events",
    "percent": 100,
    "iocs_extracted": 12,
    "iocs_discovered": 8,
    "events_analyzed": 1500,
    "timeline_events": 25,
    "auto_tagged": 15,
    "techniques_found": 5,
    "process_trees": 3,
    "generation_time": 45.2
}
```

---

### List All Searches

```
GET /case/<case_id>/ai-triage-searches
```

**Response:**
```json
[
    {
        "id": 123,
        "status": "completed",
        "entry_point": "full_triage",
        "iocs_extracted": 12,
        "iocs_discovered": 8,
        "auto_tagged": 15,
        "techniques_found": 5,
        "timeline_events": 25,
        "generation_time": 45.2,
        "created_at": "2025-11-29T18:00:00",
        "completed_at": "2025-11-29T18:00:45",
        "generated_by": "admin",
        "error_message": null
    }
]
```

---

## Frontend Components

### Modal Structure

```html
<div id="triageReportModal" class="modal-overlay">
    <div class="modal-container">
        <div class="modal-header">
            <!-- Purple gradient header -->
        </div>
        <div class="modal-body">
            <!-- No Report Phase -->
            <div id="triageNoReportPhase">...</div>
            
            <!-- Input Phase (EDR report preview) -->
            <div id="triageInputPhase">...</div>
            
            <!-- Progress Phase (9-phase display) -->
            <div id="triageProgressPhase">
                <!-- Progress bar -->
                <div id="triageProgressBar">...</div>
                
                <!-- Phase indicators (9 bars) -->
                <div id="phaseInd1">...</div>
                ...
                <div id="phaseInd9">...</div>
                
                <!-- Current status -->
                <div id="triageProgressTitle">...</div>
                <div id="triageProgressMessage">...</div>
                
                <!-- Progress log -->
                <div id="triageProgressLog">...</div>
            </div>
            
            <!-- Results Phase -->
            <div id="triageResultsPhase">
                <div id="triageResultsContent">...</div>
            </div>
        </div>
        <div class="modal-footer">
            <button id="triageCloseBtn">Close</button>
            <button id="triageStartBtn">Start AI Triage Search</button>
            <a id="triageViewResultsBtn">View Results</a>
        </div>
    </div>
</div>
```

### JavaScript Functions

| Function | Purpose |
|----------|---------|
| `showTriageModal()` | Open modal, check for EDR report |
| `closeTriageModal()` | Close modal |
| `startAITriageSearch()` | POST to /run, start polling |
| `pollAITriageStatus()` | GET /status every 1 second |
| `getPhaseColor()` | Return color for phase number |
| `showTriageResults()` | Display completion results |
| `showTriageError()` | Display error message |

---

## Celery Task Workflow

### Task Registration

```python
# tasks.py
@celery_app.task(bind=True, name='tasks.run_ai_triage_search')
def run_ai_triage_search(self, search_id):
    ...
```

### State Updates

```python
def update_progress(phase: int, phase_name: str, message: str, percent: int = 0):
    """Update search progress in database."""
    search.current_phase = phase
    search.current_phase_name = phase_name
    search.progress_message = message
    search.progress_percent = percent
    db.session.commit()
    
    # Also update Celery state for monitoring
    self.update_state(state='PROGRESS', meta={
        'phase': phase,
        'phase_name': phase_name,
        'message': message,
        'percent': percent
    })
```

### Error Handling

```python
try:
    # ... 9 phases ...
except Exception as e:
    logger.error(f"[AI_TRIAGE] Error: {e}", exc_info=True)
    search.status = 'failed'
    search.error_message = str(e)
    db.session.commit()
    return {'status': 'error', 'message': str(e)}
```

---

## Helper Functions

### extract_iocs_with_llm()

**Location:** `routes/triage_report.py`

**Purpose:** Extract IOCs using Ollama LLM

**Parameters:**
- `report_text: str` - The EDR/MDR report text

**Returns:** `Dict` with IOC lists

**Configuration:**
- Uses `SystemSettings.ollama_host` (default: `http://localhost:11434`)
- Uses `SystemSettings.ollama_model` (default: `mistral`)

---

### extract_iocs_with_regex()

**Location:** `routes/triage_report.py`

**Purpose:** Fallback regex-based IOC extraction

**Key Patterns:**
```python
# IP addresses
r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# Hostnames (quoted or standalone)
r'["\']([A-Z][A-Z0-9_-]{2,14})["\']'
r'\b([A-Z][A-Z0-9_-]{2,14})\b'

# SIDs
r'\bS-1-5-21-\d+-\d+-\d+-\d+\b'

# File paths
r'[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+'

# Hashes
r'\b[a-fA-F0-9]{32}\b'  # MD5
r'\b[a-fA-F0-9]{40}\b'  # SHA1
r'\b[a-fA-F0-9]{64}\b'  # SHA256
```

---

### search_ioc()

**Location:** `routes/triage_report.py`

**Purpose:** Search OpenSearch for IOC matches

**Parameters:**
- `opensearch_client` - OpenSearch client instance
- `case_id: int` - Case ID
- `search_term: str` - IOC value to search
- `max_results: int = 500` - Maximum results to return

**Returns:** `Tuple[List[Dict], int]` - (results, total_count)

---

### extract_from_search_results()

**Location:** `routes/triage_report.py`

**Purpose:** Extract IPs, hostnames, and usernames from search results

**Returns:** `Tuple[Set[str], Set[str], Set[str]]` - (ips, hostnames, usernames)

**Extraction Logic:**
- **IPs:** From `host.ip`, `source.ip`, `process.user_logon.ip`
- **Hostnames:** From `normalized_computer`, `host.hostname`, `host.name`
- **Usernames:** From `process.user.name`, `user.name`, `winlog.event_data.TargetUserName`

---

### is_valid_hostname()

**Location:** `routes/triage_report.py`

**Purpose:** Validate extracted hostname

**Checks:**
1. Not in `NOT_HOSTNAMES` blocklist
2. Contains at least one letter
3. Length between 3 and 15 characters
4. Not all digits

---

## Configuration & Constants

### NOT_HOSTNAMES Blocklist

Located in `routes/triage_report.py`:

```python
NOT_HOSTNAMES = {
    # Common words
    'the', 'and', 'for', 'with', 'from', 'that', 'this', 'was', 'are',
    
    # IT/Security terms
    'admin', 'administrator', 'security', 'firewall', 'router', 'switch',
    'server', 'client', 'domain', 'network', 'system', 'service',
    
    # Status words
    'enabled', 'disabled', 'active', 'inactive', 'running', 'stopped',
    
    # Attack/MITRE terms
    'powershell', 'cobalt', 'strike', 'malware', 'ransomware',
    
    # ... 100+ more terms
}
```

### NOISE_USERS Blocklist

```python
NOISE_USERS = {
    'system', 'network service', 'local service', 'anonymous logon',
    'window manager', 'dwm-1', 'dwm-2', 'umfd-0', 'umfd-1', '-', 'n/a', '',
    'font driver host', 'defaultaccount', 'guest', 'wdagutilityaccount'
}
```

### RECON_SEARCH_TERMS

```python
RECON_SEARCH_TERMS = [
    'nltest', 'net group', 'net user', 'whoami',
    'ipconfig', 'systeminfo', 'netstat', 'quser',
    'tasklist', 'wmic', 'ping', 'nslookup', 'route'
]
```

---

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `Case not found` | Invalid case_id | Check case exists in database |
| `Search record not found` | Invalid search_id | Check AITriageSearch record |
| `OpenSearch connection error` | OpenSearch down | Check OpenSearch service |
| `LLM extraction failed` | Ollama not running | Falls back to regex extraction |

### Logging

All errors are logged with:
```python
logger.error(f"[AI_TRIAGE] Error: {e}", exc_info=True)
```

Log file: `/opt/casescope/logs/workers.log`

---

## Testing & Debugging

### Manual Testing

1. **Check Celery Worker:**
   ```bash
   sudo systemctl status casescope-worker
   ```

2. **Watch Celery Logs:**
   ```bash
   sudo journalctl -u casescope-worker -f
   ```

3. **Check Database:**
   ```sql
   SELECT * FROM ai_triage_search ORDER BY created_at DESC LIMIT 5;
   ```

4. **Check Redis (Celery Broker):**
   ```bash
   redis-cli KEYS "celery*" | head -10
   ```

### Debug Mode

Add to `tasks.py`:
```python
logger.setLevel(logging.DEBUG)
```

### Test Script

```python
# test_triage.py
from main import app, db
from models import AITriageSearch, Case
from tasks import run_ai_triage_search

with app.app_context():
    case = Case.query.filter_by(id=25).first()
    print(f"Case: {case.name}")
    print(f"EDR Report: {case.edr_report[:200] if case.edr_report else 'None'}...")
    
    # Create search record
    search = AITriageSearch(case_id=25, generated_by=1, status='pending')
    db.session.add(search)
    db.session.commit()
    
    # Run synchronously for debugging
    result = run_ai_triage_search(search.id)
    print(f"Result: {result}")
```

---

## Common Issues & Fixes

### Issue: Modal stuck on "Starting..."

**Cause:** Celery worker not running or task failed silently

**Fix:**
1. Check worker: `sudo systemctl status casescope-worker`
2. Check logs: `sudo journalctl -u casescope-worker -f`
3. Restart worker: `sudo systemctl restart casescope-worker`

---

### Issue: No IOCs extracted

**Cause:** LLM failed and regex patterns didn't match

**Fix:**
1. Check Ollama is running: `curl http://localhost:11434/api/tags`
2. Review regex patterns in `extract_iocs_with_regex()`
3. Add missing patterns for specific report format

---

### Issue: Too many events tagged

**Cause:** BROAD IOCs being auto-tagged

**Fix:**
1. Verify IOC classification in Phase 2
2. Check `specific_iocs` vs `broad_iocs` logic
3. Ensure only SPECIFIC IOCs create anchors in Phase 5

---

### Issue: Process trees empty

**Cause:** EDR events don't have parent process info

**Fix:**
1. Check event structure has `process.parent` field
2. Verify `normalized_computer` field exists
3. Check time window is finding events

---

## Future Improvements

1. **Configurable Thresholds**
   - Max IOCs per type
   - Time window size (currently ±5 min)
   - Max events per window

2. **Additional Entry Points**
   - Start from specific timestamp
   - Start from specific event ID

3. **Enhanced MITRE Mapping**
   - More technique patterns
   - Sub-technique detection
   - Kill chain phase identification

4. **Export Options**
   - Export timeline to CSV
   - Export to STIX/TAXII
   - Generate PDF report

5. **Performance Optimization**
   - Parallel phase execution
   - Caching of aggregation results
   - Incremental updates

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.39.0 | 2025-11-29 | Initial 9-phase implementation |
| 1.36.0 | 2025-11-28 | 4-phase triage (predecessor) |

---

## Contact

For issues or questions, contact the CaseScope development team or create an issue in the GitHub repository.

