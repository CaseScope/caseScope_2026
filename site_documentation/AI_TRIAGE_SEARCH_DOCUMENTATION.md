# AI Triage Search - Complete Technical Documentation

**Version:** 1.40.0  
**Last Updated:** 2025-11-29  
**Author:** CaseScope Development Team

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [The 9-Phase Methodology](#the-9-phase-methodology)
4. [Exclusion System](#exclusion-system)
5. [File Structure](#file-structure)
6. [Database Schema](#database-schema)
7. [API Endpoints](#api-endpoints)
8. [Frontend Components](#frontend-components)
9. [Celery Task Workflow](#celery-task-workflow)
10. [Helper Functions](#helper-functions)
11. [Configuration & Constants](#configuration--constants)
12. [Error Handling](#error-handling)
13. [Testing & Debugging](#testing--debugging)
14. [Common Issues & Fixes](#common-issues--fixes)

---

## Overview

The **AI Triage Search** is an automated attack chain analysis system that:

1. Extracts IOCs (Indicators of Compromise) from EDR/MDR reports
2. Hunts those IOCs across all case events to discover related indicators
3. Creates IOCs and Systems in the database
4. Builds process trees and matches MITRE ATT&CK patterns
5. Auto-tags key timeline events for analyst review

### Key Features

- **9-phase automated analysis** running as a background Celery task
- **Real-time progress updates** via polling
- **IOC classification** into SPECIFIC (auto-tag) vs BROAD (aggregation only)
- **System Tools exclusions** for RMM, Remote Tools, EDR Tools, and Known-Good IPs
- **EDR context-aware exclusion** - excludes routine health checks but KEEPS response actions
- **MITRE ATT&CK pattern matching** for technique identification
- **Process tree building** from EDR parent/child relationships
- **Timeline auto-tagging** with purple color for AI-discovered events
- **Automatic IOC and System creation** in the database

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
│  │ Phase 2: IOC Classification + Load Exclusions                    ││
│  │ Phase 3: Snowball Hunting                                        ││
│  │ Phase 4: Malware/Recon Hunting                                   ││
│  │ Phase 5: SPECIFIC IOC Search                                     ││
│  │ Phase 6: BROAD IOC Aggregation + Create IOCs/Systems             ││
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
│  │  Search,    │    │             │    │             │             │
│  │  IOC,       │    │             │    │             │             │
│  │  System)    │    │             │    │             │             │
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

### Phase 2: IOC Classification + Load Exclusions

**Purpose:** Classify IOCs as SPECIFIC (auto-tag) or BROAD (aggregation only), and load System Tools exclusions.

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

**Exclusions Loaded:**
- RMM tool executables (full exclusion)
- Remote tool session IDs (known-good exclusion)
- EDR tools with context-aware exclusion (routine excluded, responses kept)
- Known-good IP addresses/CIDR blocks

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
    'nltest', 'net group', 'net user', 'net localgroup',
    'whoami', 'ipconfig', 'systeminfo', 'domain trust',
    'quser', 'query user', 'dclist'
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
        # Extract filename from path for better matching
        search_value = value.split('\\')[-1] if '\\' in value else value
        results = search_ioc(search_value)
        for hit in results[:100]:  # Limit per IOC
            # Filter out known-good events EARLY
            if should_exclude_event(hit, exclusions):
                continue
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

### Phase 6: BROAD IOC Aggregation + Create IOCs/Systems

**Purpose:** Discover additional IOCs via OpenSearch aggregations and persist to database.

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

**Database Creation:**
```python
# Helper to add IOC if not exists
def add_ioc_if_new(ioc_type, ioc_value, is_active=True):
    if (ioc_type, ioc_value.lower()) not in existing_iocs:
        ioc = IOC(
            case_id=search.case_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            is_active=is_active,
            description='Created by AI Triage Search'
        )
        db.session.add(ioc)

# Helper to add System if not exists
def add_system_if_new(hostname):
    if hostname.upper() not in existing_systems:
        system = System(
            case_id=search.case_id,
            system_name=hostname.upper(),  # Field is system_name
            system_type='workstation',
            added_by='AI Triage Search'
        )
        db.session.add(system)
```

**Noise Filtering Applied:**
- `is_noise_user()` - Filters DWM-N, UMFD-N, SYSTEM, machine accounts ($)
- `is_noise_hostname()` - Filters common words, short names
- `normalize_hostname()` - Strips FQDN to hostname (e.g., `CM-DC01.domain.local` → `CM-DC01`)

**Progress Update:** 57-61%

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
                    {"range": {"@timestamp": {"gte": start, "lte": end}}}
                ],
                "must_not": [
                    {"term": {"is_hidden": True}}  # Exclude pre-hidden events
                ]
            }
        }
    }
    
    for hit in results:
        # Filter out known-good events
        if should_exclude_event(hit, exclusions):
            excluded_early_count += 1
            continue
        window_events.append(hit)
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
        'indicators': ['dclist', 'ping', 'net view', 'advanced_ip_scanner']
    },
    'T1016': {
        'name': 'System Network Config Discovery',
        'processes': ['ipconfig.exe', 'netsh.exe', 'route.exe'],
        'indicators': ['ipconfig', 'netsh', 'route']
    },
    'T1087': {
        'name': 'Account Discovery',
        'indicators': ['AdUsers', 'net user', 'net group', 'AdComp']
    },
    'T1078': {
        'name': 'Valid Accounts',
        'indicators': ['logon', 'authentication']
    },
    'T1059.001': {
        'name': 'PowerShell',
        'processes': ['powershell.exe'],
        'indicators': ['-enc', '-encodedcommand']
    },
    'T1218.011': {
        'name': 'Rundll32',
        'processes': ['rundll32.exe'],
        'indicators': ['rundll32', '.dll,']
    }
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
    'powershell.exe', 'rundll32.exe', 'regsvr32.exe',
    'mshta.exe', 'wscript.exe', 'cscript.exe',
    'advanced_ip_scanner.exe', 'psexec.exe', 'winscp.exe',
    'notepad.exe', 'wordpad.exe'
]
```

**Noise Processes Excluded (NOISE_PROCESSES):**
```python
NOISE_PROCESSES = [
    'auditpol.exe',      # Windows audit policy - often run by RMM
    'gpupdate.exe',      # Group policy update
    'schtasks.exe',      # Task scheduler (when parent is RMM)
    'wuauclt.exe',       # Windows Update
    'msiexec.exe',       # Installer
    'dism.exe',          # Deployment Image Service
]
```

**RMM Path Patterns Excluded (RMM_PATH_PATTERNS):**
```python
RMM_PATH_PATTERNS = [
    'ltsvc', 'labtech', 'automate',  # ConnectWise Automate/LabTech
    'aem', 'datto',                   # Datto RMM
    'kaseya', 'agentmon',             # Kaseya
    'ninjarmmag',                     # NinjaRMM
    'syncro',                         # Syncro
    'atera',                          # Atera
    'n-central', 'basupsrvc',         # N-able
]
```

**Auto-Tagging Process:**
```python
for event in timeline_events:
    proc_name = event['_source']['process']['name'].lower()
    
    # Skip if not a timeline-worthy process
    if not any(p.lower().replace('.exe', '') in proc_name for p in TIMELINE_PROCESSES):
        continue
    
    # Skip if already tagged
    if event_id in existing_tag_ids:
        already_tagged += 1
        continue
    
    # Create tag with purple color
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

**Deduplication:**
- Uses `cmd.lower()` for case-insensitive command deduplication
- Key format: `f"{timestamp}|{cmd.lower()}"`

**Progress Update:** 87-100%

---

## Exclusion System

### Overview

The exclusion system prevents known-good events from polluting the analysis:

| Tool Type | Behavior | Example |
|-----------|----------|---------|
| **RMM Tools** | Full exclusion | LabTech running `whoami` |
| **Remote Tools** | Exclude known-good session IDs | ScreenConnect with known GUID |
| **EDR Tools** | Context-aware: exclude routine, KEEP responses | Huntress isolation kept |
| **Known-Good IPs** | Full exclusion | Internal network ranges |

### EDR Tools Context-Aware Exclusion

Unlike RMM tools (fully excluded), EDR tools get intelligent filtering:

```python
for edr_config in exclusions.get('edr_tools', []):
    parent_is_edr = any(exe in parent_name for exe in edr_config['executables'])
    
    if parent_is_edr:
        # FIRST: Check if this is a response action - ALWAYS KEEP
        if any(pattern in cmd_line for pattern in edr_config['response_patterns']):
            return False  # DON'T exclude - this is important!
        
        # SECOND: Check if this is a routine health check - exclude
        if any(routine in cmd_line for routine in edr_config['routine_commands']):
            return True  # Exclude - just noise
```

**Predefined EDR Tools:**

| Tool | Executables | Routine Commands | Response Patterns |
|------|-------------|------------------|-------------------|
| Huntress | `HuntressAgent.exe` | whoami, systeminfo, ipconfig | isolat, quarantin, block, mass isolation |
| Blackpoint | `SnapAgent.exe` | whoami, systeminfo | isolat, snap, block |
| SentinelOne | `SentinelAgent.exe` | whoami, systeminfo, tasklist | isolat, quarantin, mitigat, kill |
| CrowdStrike | `CSAgent.exe` | whoami, systeminfo | contain, isolat, block |

### should_exclude_event() Function

```python
def should_exclude_event(event, exclusions):
    """Check if event should be excluded from tagging (known-good)."""
    
    # Check 0: Already hidden
    if src.get('is_hidden'):
        return True
    
    # Check 1: Noise processes (auditpol, gpupdate, etc.)
    if proc_name in NOISE_PROCESSES:
        return True
    
    # Check 2: Parent is RMM tool (full exclusion)
    for rmm_pattern in exclusions['rmm_executables']:
        if fnmatch.fnmatch(parent_name, rmm_pattern):
            return True
    
    # Check 3: Command line contains RMM paths
    for rmm_path in RMM_PATH_PATTERNS:
        if rmm_path in cmd_line:
            return True
    
    # Check 4: EDR tools - context-aware
    for edr_config in exclusions['edr_tools']:
        if parent_is_edr:
            # Keep response actions
            if any(pattern in cmd_line for pattern in edr_config['response_patterns']):
                return False
            # Exclude routine
            if any(routine in cmd_line for routine in edr_config['routine_commands']):
                return True
    
    # Check 5: Remote tool with known-good session ID
    # Check 6: Known-good IP
    
    return False
```

---

## File Structure

```
/opt/casescope/app/
├── tasks.py                          # Celery task: run_ai_triage_search()
│   ├── TIMELINE_PROCESSES            # List of timeline-worthy processes
│   ├── NOISE_PROCESSES               # Processes to exclude
│   ├── RMM_PATH_PATTERNS             # RMM path patterns to exclude
│   ├── MITRE_PATTERNS                # MITRE ATT&CK pattern definitions
│   ├── run_ai_triage_search()        # Main 9-phase task (line 2755)
│   ├── is_noise_user()               # Filter noise usernames
│   ├── is_noise_hostname()           # Filter noise hostnames
│   ├── normalize_hostname()          # Strip FQDN to hostname
│   ├── load_exclusions()             # Load from SystemToolsSetting
│   └── should_exclude_event()        # Check if event is known-good
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
│   └── is_machine_account()          # Check for machine accounts ($)
│
├── routes/system_tools.py            # System Tools settings
│   ├── RMM_TOOLS                     # Predefined RMM tools
│   ├── REMOTE_TOOLS                  # Predefined remote tools
│   ├── EDR_TOOLS                     # Predefined EDR tools
│   └── add_edr_tool()                # Add EDR tool route
│
├── models.py                         # Database models
│   ├── AITriageSearch                # Main model for search results
│   ├── IOC                           # IOC storage
│   ├── System                        # System storage (system_name field)
│   ├── TimelineTag                   # Tagged events
│   └── SystemToolsSetting            # Exclusion settings
│
├── templates/search_events.html      # Frontend template
│   ├── triageReportModal             # Modal HTML structure
│   ├── showTriageModal()             # Open modal function
│   ├── startAITriageSearch()         # Start search function
│   ├── pollAITriageStatus()          # Poll for progress
│   └── showTriageResults()           # Display results
│
└── templates/system_tools.html       # System Tools settings page
    └── EDR Tools section             # Add/manage EDR tools
```

---

## Database Schema

### AITriageSearch Table

```sql
CREATE TABLE ai_triage_search (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES "case"(id),
    generated_by INTEGER NOT NULL REFERENCES "user"(id),
    
    status VARCHAR(20) DEFAULT 'pending',  -- pending, running, completed, failed
    celery_task_id VARCHAR(255),
    entry_point VARCHAR(50),  -- full_triage, ioc_hunt, tag_hunt
    search_date TIMESTAMP,
    
    -- Results (JSON)
    iocs_extracted_json TEXT,
    iocs_discovered_json TEXT,
    timeline_json TEXT,
    process_trees_json TEXT,
    mitre_techniques_json TEXT,
    summary_json TEXT,
    
    -- Counts
    iocs_extracted_count INTEGER DEFAULT 0,
    iocs_discovered_count INTEGER DEFAULT 0,
    events_analyzed_count INTEGER DEFAULT 0,
    timeline_events_count INTEGER DEFAULT 0,
    auto_tagged_count INTEGER DEFAULT 0,
    techniques_found_count INTEGER DEFAULT 0,
    process_trees_count INTEGER DEFAULT 0,
    
    -- Progress
    current_phase INTEGER DEFAULT 0,
    current_phase_name VARCHAR(100),
    progress_message VARCHAR(500),
    progress_percent INTEGER DEFAULT 0,
    
    -- Timing
    generation_time_seconds FLOAT,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);
```

### System Table (for hostname storage)

```sql
CREATE TABLE system (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES "case"(id),
    system_name VARCHAR(255) NOT NULL,  -- NOTE: Field is system_name, not hostname
    ip_address VARCHAR(45),
    system_type VARCHAR(50) DEFAULT 'workstation',
    added_by VARCHAR(100) DEFAULT 'CaseScope',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    hidden BOOLEAN DEFAULT FALSE,
    
    UNIQUE(case_id, system_name)
);
```

### SystemToolsSetting Table (for exclusions)

```sql
CREATE TABLE system_tools_setting (
    id SERIAL PRIMARY KEY,
    setting_type VARCHAR(50) NOT NULL,  -- rmm_tool, remote_tool, edr_tool, known_good_ip
    tool_name VARCHAR(100),
    executable_pattern VARCHAR(500),
    known_good_ids TEXT,  -- JSON list for remote tools
    ip_or_cidr VARCHAR(50),
    
    -- EDR-specific fields (v1.40.0)
    exclude_routine BOOLEAN DEFAULT TRUE,
    keep_responses BOOLEAN DEFAULT TRUE,
    routine_commands TEXT,  -- JSON list: ["whoami", "systeminfo"]
    response_patterns TEXT,  -- JSON list: ["isolat", "quarantin"]
    
    description VARCHAR(500),
    created_by INTEGER REFERENCES "user"(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);
```

---

## API Endpoints

### Start AI Triage Search

```
POST /case/<case_id>/ai-triage-search/run
```

**Response:**
```json
{
    "success": true,
    "search_id": 123,
    "task_id": "abc123-def456-..."
}
```

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
    "percent": 25
}
```

**Response (Completed):**
```json
{
    "status": "completed",
    "phase": 9,
    "phase_name": "Complete",
    "percent": 100,
    "iocs_extracted": 12,
    "iocs_discovered": 8,
    "events_analyzed": 1500,
    "auto_tagged": 15,
    "techniques_found": 5,
    "generation_time": 45.2
}
```

---

## Common Issues & Fixes

### Issue: Systems not being created

**Cause:** Code was using `hostname` field but model uses `system_name`

**Fix (v1.40.0):**
```python
# WRONG
system = System(case_id=id, hostname=name, notes='...')

# CORRECT
system = System(case_id=id, system_name=name, added_by='AI Triage Search')
```

### Issue: Duplicate hostnames with FQDNs

**Cause:** `CM-DC01.domain.local` and `CM-DC01` treated as different

**Fix:** Use `normalize_hostname()` to strip FQDN:
```python
def normalize_hostname(hostname):
    if '.' in hostname:
        hostname = hostname.split('.')[0]
    return hostname.upper()
```

### Issue: Noise usernames being created as IOCs

**Cause:** DWM-2, UMFD-1, NETWORK SERVICE not filtered

**Fix:** Use `is_noise_user()` before creating IOCs:
```python
def is_noise_user(username):
    if username.lower() in NOISE_USERS:
        return True
    if re.match(r'^(dwm|umfd)-\d+$', username.lower()):
        return True
    return False
```

### Issue: RMM events polluting timeline

**Cause:** LabTech/Datto running `whoami` being tagged

**Fix:** Check `RMM_PATH_PATTERNS` in command line:
```python
for rmm_path in RMM_PATH_PATTERNS:
    if rmm_path in cmd_line.lower():
        return True  # Exclude
```

### Issue: Huntress isolation events being hidden

**Cause:** EDR tools were fully excluded like RMM

**Fix (v1.40.0):** Context-aware EDR exclusion - check response patterns FIRST:
```python
if any(pattern in cmd_line for pattern in edr_config['response_patterns']):
    return False  # KEEP - this is a response action!
```

---

## Testing & Debugging

### Check Celery Worker

```bash
sudo systemctl status casescope-worker
sudo journalctl -u casescope-worker -f
```

### Watch Triage Logs

```bash
tail -f /opt/casescope/logs/workers.log | grep -E "AI_TRIAGE|Phase"
```

### Check Database

```sql
SELECT id, status, current_phase, progress_message, iocs_extracted_count, 
       auto_tagged_count, error_message 
FROM ai_triage_search 
ORDER BY created_at DESC LIMIT 5;
```

### Verify IOCs Created

```sql
SELECT ioc_type, ioc_value, is_active, description 
FROM ioc 
WHERE case_id = 25 AND description LIKE '%AI Triage%';
```

### Verify Systems Created

```sql
SELECT system_name, system_type, added_by 
FROM system 
WHERE case_id = 25 AND added_by = 'AI Triage Search';
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.40.0 | 2025-11-29 | EDR context-aware exclusion, fixed System creation (system_name field) |
| 1.39.0 | 2025-11-29 | Initial 9-phase implementation |
| 1.38.0 | 2025-11-28 | System Tools settings, Hide Known Good |
| 1.36.0 | 2025-11-27 | 4-phase triage (predecessor) |

---

## Contact

For issues or questions, contact the CaseScope development team or create an issue in the GitHub repository.
