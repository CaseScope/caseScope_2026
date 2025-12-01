# AI Triage Search - Complete Technical Documentation

**Version:** 1.43.9  
**Last Updated:** 2025-12-01  
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
- **Pre-flight checks** (v1.43.0) - validates systems discovered and EDR report exists before running
- **IOC classification** into SPECIFIC (auto-tag) vs BROAD (aggregation only)
- **System Tools exclusions** for RMM, Remote Tools, EDR Tools, and Known-Good IPs
- **Known System/IP filtering** (v1.43.4) - skips IOCs for known systems (non-unknown types)
- **Context-based IP filtering** (v1.43.9) - filters noise IPs from firewall/network logs
- **EDR context-aware exclusion** - excludes routine health checks but KEEPS response actions
- **Noise command pattern detection** (v1.41.0) - filters monitoring noise with empty/generic parents
- **Frequency-based deduplication** (v1.41.0) - limits repeated commands per host
- **Unknown system type** (v1.43.3) - new systems from triage set to 'unknown' for analyst review
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
│  │ Phase 9: Timeline Auto-Tagging (with noise filtering)            ││
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

### Phase 9: Timeline Event Auto-Tagging (Updated v1.41.0)

**Purpose:** Filter and auto-tag key timeline events with noise reduction.

**Timeline-Worthy Processes (TIMELINE_PROCESSES):**
```python
TIMELINE_PROCESSES = [
    # Recon commands
    'nltest.exe', 'whoami.exe', 'ipconfig.exe', 'ping.exe',
    'net.exe', 'net1.exe', 'netstat.exe', 'systeminfo.exe',
    'nslookup.exe', 'route.exe', 'arp.exe', 'tracert.exe',
    'hostname.exe', 'nbtstat.exe',
    
    # Scripting/execution
    'powershell.exe', 'pwsh.exe', 'cmd.exe',
    'rundll32.exe', 'regsvr32.exe', 'mshta.exe',
    'wscript.exe', 'cscript.exe', 'certutil.exe',
    'bitsadmin.exe', 'msbuild.exe',
    
    # Lateral movement / tools
    'psexec.exe', 'psexec64.exe', 'wmic.exe',
    'schtasks.exe', 'sc.exe', 'reg.exe',
    
    # Remote access tools
    'winscp.exe', 'putty.exe', 'plink.exe',
    'advanced_ip_scanner.exe', 'nmap.exe', 'masscan.exe',
    
    # Data access
    'notepad.exe', 'wordpad.exe',
]
```

**Noise Processes Excluded (NOISE_PROCESSES) - v1.42.0:**
```python
NOISE_PROCESSES = [
    # Windows system management
    'auditpol.exe',      # Audit policy - run by EDR/RMM
    'gpupdate.exe',      # Group policy update
    'wuauclt.exe',       # Windows Update
    'msiexec.exe',       # Installer
    'dism.exe',          # Deployment Image Service
    'sppsvc.exe',        # Software Protection Platform
    'winmgmt.exe',       # WMI service
    
    # Console/shell infrastructure
    'conhost.exe',       # Console host - spawned by every cmd.exe
    'find.exe',          # Usually part of "command | find" pipes
    'findstr.exe',       # Same as find.exe
    'sort.exe',          # Pipe utility
    'more.com',          # Pipe utility
    
    # Monitoring/health check processes
    'tasklist.exe',      # Process listing (RMM monitoring)
    'quser.exe',         # Session queries (RMM health checks)
    'query.exe',         # Query commands
    
    # Windows runtime/background
    'runtimebroker.exe', # Windows Runtime Broker
    'taskhostw.exe',     # Task Host Window
    'backgroundtaskhost.exe',  # Background task host
    'wmiprvse.exe',      # WMI Provider Host
    
    # Update/maintenance
    'huntressupdater.exe',     # Huntress updates
    'microsoftedgeupdate.exe', # Edge updates
    'fulltrustnotifier.exe',   # Adobe notifications
    'filecoauth.exe',          # Office/OneDrive co-auth
    
    # Search indexing
    'searchprotocolhost.exe',  # Windows Search
    'searchfilterhost.exe',    # Windows Search
]
```

**Noise Command Patterns (v1.42.0) - NOISE_COMMAND_PATTERNS:**

Commands excluded ONLY when parent is empty/generic:
```python
NOISE_COMMAND_PATTERNS = [
    # Network monitoring (run thousands of times by RMM/EDR)
    'netstat -ano', 'netstat  -ano',
    'netstat -an', 'netstat  -an',
    'ipconfig /all', 'ipconfig  /all',
    
    # System info (monitoring, not attacks)
    'systeminfo', 'hostname',
    
    # Session/user queries (RMM health checks)
    'quser', '"quser"', 'query user',
    
    # Process listing (RMM monitoring loops)
    'tasklist',
    
    # Pipe output filters (from "netstat | find" chains)
    'find /i', 'find "', 'find  /i', 'find  "',
    
    # Audit policy commands (EDR continuously sets these)
    'auditpol.exe /set', 'auditpol /set', 'auditpol.exe  /set',
    
    # Console host (spawned by every cmd.exe)
    'conhost.exe 0xffffffff', 'conhost.exe  0xffffffff',
    
    # PowerShell monitoring - Defender checks (Huntress, RMM)
    'get-mppreference',        # Defender preference queries
    'get-mpthreat',            # Defender threat queries
    'get-mpcomputerstatus',    # Defender status checks
    
    # PowerShell monitoring - WMI queries (LabTech, RMM)
    'get-wmiobject -class win32_operatingsystem',
    'get-wmiobject -query',
    'get-wmiobject -namespace root',
    
    # Windows service/system processes
    'runtimebroker.exe -embedding',
    'backgroundtaskhost.exe', 'taskhostw.exe',
    'wmiprvse.exe -secured', 'svchost.exe -k', 'sppsvc.exe',
    
    # Application update processes
    'huntressupdater.exe', 'microsoftedgeupdate.exe',
]
```

**Generic/Benign Parents (v1.41.0) - GENERIC_PARENTS:**

Parents that trigger noise command filtering:
```python
GENERIC_PARENTS = [
    '',                       # Empty parent (EDR didn't capture it)
    'cmd.exe',                # Generic - could be anything
    'svchost.exe',            # Windows service host
    'services.exe',           # Service control manager
    'wmiprvse.exe',           # WMI provider (often used by monitoring)
    'taskhostw.exe',          # Task scheduler host
]
```

**Frequency-Based Deduplication (v1.41.0):**
```python
MAX_EVENTS_PER_COMMAND = 3  # Max events to tag per unique command per host
```

If `netstat -ano` runs 1000 times on a host, only 3 instances are tagged.

**RMM Path Patterns Excluded (RMM_PATH_PATTERNS) - v1.42.0:**
```python
RMM_PATH_PATTERNS = [
    'ltsvc', 'labtech', 'automate',  # ConnectWise Automate/LabTech
    'aem', 'datto',                   # Datto RMM
    'kaseya', 'agentmon',             # Kaseya
    'ninjarmmag',                     # NinjaRMM
    'syncro',                         # Syncro
    'atera',                          # Atera
    'n-central', 'basupsrvc',         # N-able
    'huntress',                       # Huntress EDR
    'screenconnect',                  # ConnectWise ScreenConnect
]
```

**Auto-Tagging Process (Updated v1.41.0):**
```python
# Filter to timeline-worthy events with noise reduction
timeline_events = []
seen_keys = set()           # Exact timestamp+command dedup
command_frequency = {}       # Track {host|command: count} for frequency dedup
excluded_count = 0
frequency_skipped = 0

for event in all_window_events:
    src = event.get('_source', {})
    proc = src.get('process', {})
    proc_name = (proc.get('name') or '').lower()
    
    # Check if timeline-worthy
    if not any(p.lower().replace('.exe', '') in proc_name for p in TIMELINE_PROCESSES):
        continue
    
    # Check exclusions (known-good RMM, remote tools, IPs, noise commands)
    if should_exclude_event(event, exclusions):
        excluded_count += 1
        continue
    
    # Timestamp+command deduplication
    cmd = (proc.get('command_line') or '').lower()
    ts = src.get('@timestamp', '')
    key = f"{ts}|{cmd}"
    if key in seen_keys:
        continue
    seen_keys.add(key)
    
    # Frequency-based deduplication (v1.41.0)
    hostname = src.get('normalized_computer', 'unknown')
    cmd_base = cmd.split()[0] if cmd else ''  # Just the executable
    freq_key = f"{hostname}|{cmd_base}"
    
    current_count = command_frequency.get(freq_key, 0)
    if current_count >= MAX_EVENTS_PER_COMMAND:
        frequency_skipped += 1
        continue  # Already have enough samples
    
    command_frequency[freq_key] = current_count + 1
    timeline_events.append(event)
```

---

## Phase 6: IOC Creation (v1.43.4+)

### Overview

Phase 6 creates IOCs and Systems in the database from extracted and discovered indicators.

### Known System Filtering (v1.43.4)

**Problem:** AI Triage was creating hostname IOCs for known systems (workstations, servers, DCs) that analysts had already identified.

**Solution:** Check if hostname/IP belongs to a known system with a non-'unknown' type before creating IOC.

```python
# v1.43.4: Skip hostname IOCs for known systems with non-unknown types
if ioc_type == 'hostname':
    hostname_lower = ioc_value.lower()
    if hostname_lower in known_system_types:
        sys_type = known_system_types[hostname_lower]
        if sys_type != 'unknown':
            logger.debug(f"Skipping known {sys_type} hostname IOC: {ioc_value}")
            return

# v1.43.4: Skip IP IOCs for known system IPs
if ioc_type == 'ip':
    if ioc_value in known_system_ips:
        logger.debug(f"Skipping known system IP IOC: {ioc_value}")
        return
```

### Unknown System Type (v1.43.3)

**Problem:** When AI Triage discovered new hostnames, they were added as 'workstation' type, which caused them to be skipped as IOCs on subsequent runs.

**Solution:** New systems from AI Triage are set to `system_type='unknown'`:
- Systems stay as IOCs until analyst reviews and categorizes them
- Once categorized (workstation, server, etc.), they're filtered out of IOC list

```python
system = System(
    case_id=case_id,
    system_name=hostname.upper(),
    system_type='unknown',  # v1.43.3: Analyst must review
    added_by='AI Triage Search'
)
```

### Context-Based IP Filtering (v1.43.9)

**Problem:** Firewall logs generate thousands of noise IPs (internet scanners, geo-blocked traffic, CDN/cloud). These IPs were being added as IOCs during snowball hunting.

**Solution:** Filter discovered IPs based on event context:

```python
# IPs from EDR report: ALWAYS create IOC (analyst/EDR flagged them)
# Discovered IPs: Only create IOC if they appear in meaningful events

MEANINGFUL_IP_EVENT_IDS = {
    # Authentication events
    '4624', '4625', '4648', '4768', '4769', '4771', '4776',
    # RDP/Remote
    '4778', '4779', '21', '22', '24', '25',
    # VPN/NPS
    '6272', '6273', '6274', '6275', '6278', '6279',
    # Sysmon process/network
    '1', '3',
}

FIREWALL_NOISE_KEYWORDS = [
    'firewall', 'fw_', 'fw-', 'deny', 'drop', 'block', 'reject',
    'netflow', 'traffic', 'conn_state', 'action:deny', 'action:drop',
]
```

**Filtering Logic:**
1. IPs from EDR report → Always create IOC (analyst flagged)
2. Discovered IPs with authentication events → Create IOC (someone tried to log in)
3. Discovered IPs with SIGMA/IOC hits → Create IOC (correlated threat)
4. Discovered IPs in process.user_logon.ip → Create IOC (lateral movement)
5. Discovered IPs only in firewall logs → Skip (perimeter noise)
6. Discovered IPs in EDR events → Create IOC (endpoint activity)

```python
def is_ip_in_meaningful_context(ip, case_id):
    # Search for events containing this IP
    for hit in search_results:
        # Check for SIGMA/IOC hits (always meaningful)
        if src.get('has_sigma') or src.get('has_ioc'):
            meaningful_count += 1
            continue
        
        # Check for authentication event IDs
        if event_id in MEANINGFUL_IP_EVENT_IDS:
            meaningful_count += 1
            continue
        
        # Check for firewall noise keywords
        if any(kw in blob for kw in FIREWALL_NOISE_KEYWORDS):
            noise_count += 1
            continue
        
        # EDR events are generally meaningful
        if source_type == 'EDR':
            meaningful_count += 1
    
    return meaningful_count > 0
```

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
| **Noise Commands** (v1.41.0) | Exclude when parent is empty/generic | `netstat -ano` with no parent |

### The Empty Parent Problem (v1.41.0)

**Issue:** Many EDR tools don't capture parent process information. When parent is empty, we can't determine if a command was launched by RMM/EDR or by an attacker.

**Example from Case 25:**
- 8,537 `netstat -ano` events on ATN71575
- 8,410 (98%) had **empty parent** - couldn't be filtered by parent-based exclusion
- Only 22 had SnapAgent.exe as parent (would be excluded)

**Solution:** Noise command pattern detection for events with empty/generic parents.

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
| Huntress | `HuntressAgent.exe` | whoami, systeminfo, ipconfig, netstat | isolat, quarantin, block, mass isolation |
| Blackpoint | `SnapAgent.exe` | whoami, systeminfo, ipconfig, netstat | isolat, snap, block |
| SentinelOne | `SentinelAgent.exe` | whoami, systeminfo, tasklist | isolat, quarantin, mitigat, kill |
| CrowdStrike | `CSAgent.exe` | whoami, systeminfo | contain, isolat, block |

### should_exclude_event() Function (Updated v1.41.0)

```python
def should_exclude_event(event, exclusions):
    """Check if event should be excluded from tagging (known-good).
    
    v1.41.0: Added noise command pattern detection for events with empty/generic parents.
    """
    src = event.get('_source', event)
    
    # Already hidden?
    if src.get('is_hidden'):
        return True
    
    proc = src.get('process', {})
    parent = proc.get('parent', {})
    parent_name = (parent.get('name') or '').lower()
    proc_name = (proc.get('name') or '').lower()
    cmd_line = (proc.get('command_line') or '').lower()
    parent_cmd = (parent.get('command_line') or '').lower()
    
    # Check 0: Noise processes (system management, not attack-related)
    if proc_name.replace('.exe', '') in [p.replace('.exe', '') for p in NOISE_PROCESSES]:
        return True
    
    # Check 0.5 (v1.41.0): Noise command patterns with empty/generic parent
    # If parent is empty or generic AND command matches noise pattern, exclude
    parent_is_generic = parent_name in [p.lower() for p in GENERIC_PARENTS] or not parent_name
    if parent_is_generic:
        cmd_normalized = ' '.join(cmd_line.split()).strip()
        for noise_pattern in NOISE_COMMAND_PATTERNS:
            noise_normalized = ' '.join(noise_pattern.lower().split()).strip()
            if cmd_normalized == noise_normalized or cmd_normalized.startswith(noise_normalized + ' '):
                return True  # Exclude - monitoring noise with no suspicious parent
    
    # Check 1: Parent is a known RMM tool (full exclusion)
    for rmm_pattern in exclusions.get('rmm_executables', []):
        if fnmatch.fnmatch(parent_name, rmm_pattern) or fnmatch.fnmatch(proc_name, rmm_pattern):
            return True
    
    # Check 1.5: Command line or parent command contains RMM paths
    for rmm_path in RMM_PATH_PATTERNS:
        if rmm_path in cmd_line or rmm_path in parent_cmd:
            return True
    
    # Check 2: EDR tools - CONTEXT-AWARE exclusion
    for edr_config in exclusions.get('edr_tools', []):
        parent_is_edr = any(
            fnmatch.fnmatch(parent_name, exe) or exe in parent_name
            for exe in edr_config.get('executables', [])
        )
        
        if parent_is_edr:
            # FIRST: Check if this is a response action - ALWAYS KEEP
            if edr_config.get('keep_responses', True):
                response_patterns = edr_config.get('response_patterns', [])
                if any(pattern in cmd_line for pattern in response_patterns):
                    return False  # DON'T exclude - response action!
            
            # SECOND: Check if this is a routine health check - exclude
            if edr_config.get('exclude_routine', True):
                routine_commands = edr_config.get('routine_commands', [])
                if any(routine in cmd_line for routine in routine_commands):
                    return True  # Exclude - routine health check
    
    # Check 3: Remote tool with known-good session ID
    for tool_config in exclusions.get('remote_tools', []):
        pattern = tool_config.get('pattern', '')
        if pattern and pattern in proc_name:
            for known_id in tool_config.get('known_good_ids', []):
                if known_id in cmd_line:
                    return True
    
    # Check 4: Source IP is known-good
    source_ip = src.get('source', {}).get('ip') or src.get('host', {}).get('ip')
    if source_ip:
        if isinstance(source_ip, list):
            source_ip = source_ip[0] if source_ip else None
        if source_ip:
            for ip_range in exclusions.get('known_good_ips', []):
                try:
                    if '/' in ip_range:
                        if ipaddress.ip_address(source_ip) in ipaddress.ip_network(ip_range, strict=False):
                            return True
                    elif source_ip == ip_range:
                        return True
                except:
                    pass
    
    return False
```

---

## File Structure

```
/opt/casescope/app/
├── tasks.py                          # Celery task: run_ai_triage_search()
│   ├── TIMELINE_PROCESSES            # List of timeline-worthy processes
│   ├── NOISE_PROCESSES               # Processes to exclude
│   ├── NOISE_COMMAND_PATTERNS        # (v1.41.0) Command lines to exclude
│   ├── GENERIC_PARENTS               # (v1.41.0) Parents that trigger noise filtering
│   ├── MAX_EVENTS_PER_COMMAND        # (v1.41.0) Frequency limit per host
│   ├── RMM_PATH_PATTERNS             # RMM path patterns to exclude
│   ├── MITRE_PATTERNS                # MITRE ATT&CK pattern definitions
│   ├── run_ai_triage_search()        # Main 9-phase task
│   ├── is_noise_user()               # Filter noise usernames
│   ├── is_noise_hostname()           # Filter noise hostnames
│   ├── normalize_hostname()          # Strip FQDN to hostname
│   ├── load_exclusions()             # Load from SystemToolsSetting
│   └── should_exclude_event()        # Check if event is known-good
│
├── routes/triage_report.py           # API routes + helper functions
├── routes/system_tools.py            # System Tools settings
├── models.py                         # Database models
├── templates/search_events.html      # Frontend template
└── templates/system_tools.html       # System Tools settings page
```

---

## Database Schema

### AITriageSearch Table

```sql
CREATE TABLE ai_triage_search (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES "case"(id),
    generated_by INTEGER NOT NULL REFERENCES "user"(id),
    
    status VARCHAR(20) DEFAULT 'pending',
    celery_task_id VARCHAR(255),
    entry_point VARCHAR(50),
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

### SystemToolsSetting Table (for exclusions)

```sql
CREATE TABLE system_tools_setting (
    id SERIAL PRIMARY KEY,
    setting_type VARCHAR(50) NOT NULL,  -- rmm_tool, remote_tool, edr_tool, known_good_ip
    tool_name VARCHAR(100),
    executable_pattern VARCHAR(500),
    known_good_ids TEXT,
    ip_or_cidr VARCHAR(50),
    
    -- EDR-specific fields
    exclude_routine BOOLEAN DEFAULT TRUE,
    keep_responses BOOLEAN DEFAULT TRUE,
    routine_commands TEXT,
    response_patterns TEXT,
    
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

### Get Search Status

```
GET /case/<case_id>/ai-triage-search/<search_id>/status
```

---

## Common Issues & Fixes

### Issue: Monitoring noise flooding timeline (v1.41.0)

**Symptoms:** Thousands of `netstat -ano`, `ipconfig /all` events tagged

**Root Cause:** EDR data has empty parent field for 84%+ of events, so parent-based exclusion can't work.

**Example (Case 25 - ATN71575):**
- 8,537 netstat events total
- 8,410 (98%) had empty parent
- 22 from SnapAgent.exe (would be excluded)
- Without fix: 89+ events tagged as noise

**Fix (v1.41.0):** 
1. Added `NOISE_COMMAND_PATTERNS` - exact commands excluded when parent is generic
2. Added `GENERIC_PARENTS` - parents that trigger noise filtering
3. Added `MAX_EVENTS_PER_COMMAND` - frequency limit per host (default: 3)

```python
# Noise detection for empty/generic parent
parent_is_generic = parent_name in GENERIC_PARENTS or not parent_name
if parent_is_generic:
    cmd_normalized = ' '.join(cmd_line.split()).strip()
    for noise_pattern in NOISE_COMMAND_PATTERNS:
        if cmd_normalized == noise_pattern:
            return True  # Exclude
```

### Issue: Systems not being created

**Cause:** Code was using `hostname` field but model uses `system_name`

**Fix:**
```python
system = System(case_id=id, system_name=name, added_by='AI Triage Search')
```

### Issue: Huntress isolation events being hidden

**Cause:** EDR tools were fully excluded like RMM

**Fix:** Context-aware EDR exclusion - check response patterns FIRST:
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
tail -f /opt/casescope/logs/workers.log | grep -E "AI_TRIAGE|Phase|frequency"
```

### Check Database

```sql
SELECT id, status, current_phase, progress_message, 
       auto_tagged_count, error_message 
FROM ai_triage_search 
ORDER BY created_at DESC LIMIT 5;
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.43.9 | 2025-12-01 | **Context-based IP filtering:** Filters noise IPs from firewall/network logs. IPs only in deny/drop events are skipped. IPs with auth, SIGMA, or EDR context become IOCs. |
| 1.43.8 | 2025-12-01 | Search optimization (10x faster), Hide Known Good progress tracking. Hybrid search routing for query types. |
| 1.43.4 | 2025-12-01 | **Known System/IP filtering:** Skip hostname IOCs for known systems (non-unknown types). Skip IP IOCs for known system IPs. |
| 1.43.3 | 2025-12-01 | **Unknown system type:** New systems from triage set to 'unknown'. Ensures IOCs until analyst categorizes. |
| 1.43.0 | 2025-11-30 | **Pre-flight checks:** Validates systems discovered and EDR report exists before running triage. VPN IP range field added to cases. |
| 1.42.0 | 2025-11-29 | **Comprehensive noise analysis:** Expanded NOISE_PROCESSES (29 entries), NOISE_COMMAND_PATTERNS (30+ patterns), RMM_PATH_PATTERNS (huntress, screenconnect). Analyzed Cases 14, 16, 22, 25 - eliminates 2.5-13% noise per case. Added PowerShell monitoring patterns (Get-Mp*, Get-WmiObject). |
| 1.41.0 | 2025-11-29 | **Noise reduction:** Added NOISE_COMMAND_PATTERNS, GENERIC_PARENTS, frequency-based deduplication (MAX_EVENTS_PER_COMMAND=3) to handle EDR data with empty parent fields |
| 1.40.0 | 2025-11-29 | EDR context-aware exclusion, fixed System creation (system_name field) |
| 1.39.0 | 2025-11-29 | Initial 9-phase implementation |
| 1.38.0 | 2025-11-28 | System Tools settings, Hide Known Good |
| 1.36.0 | 2025-11-27 | 4-phase triage (predecessor) |

---

## Cross References

### USES

These documentation files describe features that AI Triage depends on:

- `HIDE_KNOWN_GOOD_EVENTS_REFERENCE.md` - System Tools exclusions loaded by AI Triage
- *(Future)* `SEARCH_FUNCTION_REFERENCE.md` - Event search used for IOC hunting

### USED BY

These documentation files describe features that depend on AI Triage:

- *(Future)* `IOC_MANAGEMENT_REFERENCE.md` - IOCs created by AI Triage
- *(Future)* `SYSTEMS_MANAGEMENT_REFERENCE.md` - Systems created by AI Triage

---

## Contact

For issues or questions, contact the CaseScope development team.
