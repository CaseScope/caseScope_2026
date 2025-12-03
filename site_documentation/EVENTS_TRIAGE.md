# Events Triage - Technical Reference

Complete documentation for the Triage system. Each phase is documented separately for easy reference and updates.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Triage Page & Prerequisites](#triage-page--prerequisites)
4. [Phase 1: EDR IOC Extraction](#phase-1-edr-ioc-extraction)
5. [Phase 2: Find Potential IOCs (Snowball Hunting)](#phase-2-find-potential-iocs-snowball-hunting)
6. [Phase 3: Tag Highly Likely Events](#phase-3-tag-highly-likely-events)
7. [Routes Reference](#routes-reference)
8. [Database Models](#database-models)
9. [Reconstruction Checklist](#reconstruction-checklist)
10. [Version History](#version-history)

---

## Overview

The Triage system provides a guided workflow for AI-powered attack chain analysis. Instead of a monolithic "run everything" approach, it breaks triage into individual phases that can be run manually as prerequisites are met.

### Key Concepts

| Term | Description |
|------|-------------|
| **Triage** | Automated analysis to identify attack chains from event data |
| **Prerequisites** | Required configuration before running triage phases |
| **Phase** | An individual triage step (IOC Extraction, Snowball Hunting, etc.) |
| **EDR Report** | Analyst-pasted security report from EDR/MDR vendor |
| **IOC** | Indicator of Compromise (IP, hash, hostname, username, etc.) |
| **Snowball Hunting** | Using known IOCs to discover new related indicators |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PREREQUISITES LAYER                              │
│  Triage Page (triage.html)                                              │
│  ├── System Scan Check: Are systems defined?                            │
│  ├── EDR Report Check: Is there an EDR report?                         │
│  ├── IOCs Defined Check: Are there active IOCs?                        │
│  ├── Tagged Events Check: Are there timeline tags?                     │
│  └── Triage Date Check: Is a focus date set?                           │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      CENTRALIZED NOISE FILTERS                           │
│  app/noise_filters.py (Single Source of Truth)                          │
│  ├── NOISE_USERS, NOISE_PROCESSES, NOISE_PATH_PATTERNS                 │
│  ├── is_noise_user(), is_noise_process(), is_external_ip()             │
│  └── Imported by all triage modules below                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         MODULE LAYER                                     │
│                                                                          │
│  Phase 1: app/ai_triage_edr_ioc.py                                      │
│  ├── is_ai_enabled() - Check AI system setting                         │
│  ├── extract_iocs_with_llm() - AI extraction (QWEN)                    │
│  ├── extract_iocs_with_regex() - Regex fallback                        │
│  └── extract_iocs_from_report() - Main entry point                     │
│                                                                          │
│  Phase 2: app/ai_triage_find_iocs.py                                    │
│  ├── get_case_context() - Load case data for filtering                 │
│  ├── search_events_with_iocs() - OpenSearch query (scroll API)         │
│  ├── extract_iocs_from_events() - Extract from matched events          │
│  ├── check_managed_tool() - RMM/EDR tool ID verification               │
│  └── find_potential_iocs() - Main entry point                          │
│                                                                          │
│  Phase 3: app/ai_triage_tag_iocs.py                                     │
│  ├── get_high_confidence_iocs() - Get IOCs for tagging                 │
│  ├── get_actor_systems() - Get actor system hostnames/IPs              │
│  ├── search_events_for_tagging() - OpenSearch query (scroll API)       │
│  ├── is_noise_event() - Filter noise events                            │
│  └── tag_high_confidence_events() - Main entry point                   │
│                                                                          │
│  Future phases:                                                         │
│  ├── ai_triage_patterns.py (Attack Pattern Detection)                  │
│  └── ai_triage_timeline.py (Timeline Generation)                       │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ROUTES LAYER                                     │
│  app/main.py                                                            │
│  ├── GET  /case/<id>/triage - Triage page                              │
│  ├── POST /case/<id>/triage/extract-iocs - Phase 1: Extract IOCs       │
│  ├── POST /case/<id>/triage/add-extracted-iocs - Save extracted IOCs   │
│  ├── POST /case/<id>/triage/find-iocs - Phase 2: Find potential IOCs   │
│  ├── POST /case/<id>/triage/add-found-iocs - Save found IOCs           │
│  └── POST /case/<id>/triage/tag-events - Phase 3: Tag events           │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         STORAGE LAYER                                    │
│  PostgreSQL: IOC table (extracted & discovered IOCs)                    │
│  PostgreSQL: TimelineTag table (tagged events from Phase 3)             │
│  PostgreSQL: AITriageSearch table (triage history)                      │
│  OpenSearch: case_{id} index (event data for hunting)                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Triage Page & Prerequisites

### File: `app/templates/triage.html`

### Template Variables

| Variable | Type | Description |
|----------|------|-------------|
| `case` | Case | The current case object |
| `systems_configured` | bool | True if systems are defined |
| `system_count` | int | Number of systems |
| `has_edr_report` | bool | True if EDR report exists |
| `has_iocs` | bool | True if active IOCs exist |
| `ioc_count` | int | Number of active IOCs |
| `has_tagged_events` | bool | True if timeline tags exist |
| `tag_count` | int | Number of tagged events |
| `has_triage_date` | bool | True if triage date is set |
| `ai_enabled` | bool | True if AI is enabled in settings |

### Prerequisite Cards

Each prerequisite displays:
- **Status icon**: ✅ (complete), ⚠️ (warning), ❌ (missing)
- **Status badge**: Pill badge with count (`.badge-pill` CSS class)
- **Action button**: Link to configure or view
- **Conditional styling**: Border color indicates status

---

## Phase 1: EDR IOC Extraction

### File: `app/ai_triage_edr_ioc.py`

Extracts IOCs from EDR/MDR reports. Supports AI extraction (QWEN) with regex fallback.

### Functions

| Function | Purpose |
|----------|---------|
| `is_ai_enabled()` | Check if AI is enabled in system settings |
| `get_ollama_host()` | Get configured Ollama host from settings |
| `is_valid_hostname(hostname, ip_set)` | Validate hostname format |
| `extract_iocs_with_llm(report_text)` | AI extraction using QWEN model |
| `extract_iocs_with_regex(report_text)` | Regex-based extraction (fallback) |
| `extract_iocs_from_report(report_text, force_regex)` | **Main entry point** |
| `get_ioc_summary(iocs)` | Generate summary for UI display |

### Flow Logic

```python
def extract_iocs_from_report(report_text: str, force_regex: bool = False) -> Dict:
    """
    1. If force_regex=True → skip AI, use regex
    2. Check is_ai_enabled() from system settings
    3. If AI enabled → try LLM, fall back to regex on failure
    4. If AI disabled → use regex directly
    """
```

### LLM Extraction

**Model:** `dfir-qwen:latest`

**Prompt extracts:**
- usernames, sids, ips, hostnames, domains
- processes, paths, commands, hashes
- timestamps, registry_keys, tools, services
- threat_types, malware_indicated

### Regex Extraction Patterns

| Type | Example |
|------|---------|
| `ips` | `192.168.1.50` |
| `hashes` | SHA256 (64 hex), SHA1 (40 hex), MD5 (32 hex) |
| `sids` | `S-1-5-21-123456-789` |
| `usernames` | Context: `user "BButler"` |
| `hostnames` | Context: `host "SERVER01"` |
| `paths` | `C:\Users\Admin\Documents\` |
| `processes` | `nltest.exe` |
| `commands` | `nltest /dclist` |
| `tools` | WinSCP, Mimikatz, etc. |

### Output Structure

```python
{
    'usernames': ['BButler'],
    'ips': ['192.168.1.50'],
    'hostnames': ['SERVER01'],
    'processes': ['nltest.exe'],
    'paths': ['C:\\Users\\Admin\\'],
    'commands': ['nltest /dclist'],
    'tools': ['WinSCP'],
    'extraction_method': 'llm'  # or 'regex', 'regex_fallback'
}
```

### Routes

| Route | Method | Function |
|-------|--------|----------|
| `/case/<id>/triage/extract-iocs` | POST | Extract IOCs from EDR report |
| `/case/<id>/triage/add-extracted-iocs` | POST | Save extracted IOCs to database |

### JavaScript Function

```javascript
function extractIOCs() {
    // 1. Show modal with progress spinner
    // 2. POST to /case/{id}/triage/extract-iocs
    // 3. Display results in modal
    // 4. User clicks "Add IOCs" to save
}
```

---

## Phase 2: Find Potential IOCs (Snowball Hunting)

### File: `app/ai_triage_find_iocs.py`

Searches events containing existing IOCs and extracts additional potential IOCs from those events. This is "snowball hunting" - using known IOCs to discover new related indicators.

### Functions

| Function | Purpose |
|----------|---------|
| `get_case_context(case_id)` | Load case data: systems, IOCs, known IPs, managed tools |
| `search_events_with_iocs(case_id, iocs)` | Query OpenSearch for events matching IOCs |
| `extract_iocs_from_events(events, context)` | Extract potential IOCs with filtering |
| `check_managed_tool(proc, blob, tools)` | Verify RMM/EDR/Remote tool session IDs |
| `contains_existing_ioc(value, existing)` | Check if value contains existing IOC |
| `find_potential_iocs(case_id)` | **Main entry point** |
| `get_ioc_discovery_summary(result)` | Generate summary for UI display |

### Flow Logic

```python
def find_potential_iocs(case_id: int) -> Dict:
    """
    1. Load case context (systems, existing IOCs, managed tools, etc.)
    2. Build OpenSearch query for events matching existing IOCs
    3. Query excludes hidden events (is_hidden: true)
    4. Use scroll API to get ALL matching events (no limit)
    5. Extract potential IOCs from matched events
    6. Apply extensive filtering (see below)
    7. Return results (max 100 per IOC type)
    """
```

### Filtering Logic

The module applies extensive filtering to avoid noise. **All noise constants are imported from `app/noise_filters.py`** (centralized source of truth).

#### 1. Hidden Events
- OpenSearch query includes `"must_not": [{"term": {"is_hidden": True}}]`
- Events marked by "Hide Known Good" or "Hide Noise" are excluded

#### 2. Known Systems Filtering
- Systems with type other than `actor_system` are filtered
- Their associated IPs are also filtered
- Actor systems are NOT filtered (they're interesting)

#### 3. Known-Good IP Filtering
- IPs from `SystemToolsSetting.known_good_ips` are filtered
- Example: DNS servers, domain controllers

#### 4. Existing IOC Filtering
- Values already in the case's IOC list are filtered
- Uses `contains_existing_ioc()` for commands/paths (substring match)
- Uses exact match for usernames/hostnames/processes

#### 5. Managed Tool Filtering (RMM/EDR/Remote)
Loads from `SystemToolsSetting`:
- `rmm_tools`, `edr_tools`, `remote_tools`

For each tool with `executable_pattern` and optional `known_good_ids`:
- If process matches tool pattern:
  - If `known_good_ids` configured AND ID found in event → **SKIP** (legitimate use)
  - If `known_good_ids` configured AND ID NOT found → **KEEP** (attacker using tool!)
  - If no `known_good_ids` configured → **SKIP** (trust the tool)

#### 6. Noise Filtering (from `noise_filters.py`)

**Noise Users (23 accounts):**
- System accounts: `system`, `network service`, `local service`
- DWM/UMFD accounts: `dwm-1`, `dwm-2`, `umfd-0`, etc.
- NT Authority accounts: `nt authority\\system`, etc.
- Machine accounts (ending with `$`) are also filtered

**Noise Processes (109 processes):**
- Browser processes (chrome.exe, msedge.exe, firefox.exe)
- Adobe processes (acrord32.exe, acrobat.exe, adobearm.exe)
- Windows background (runtimebroker.exe, taskhostw.exe, searchindexer.exe)
- Common apps (teams.exe, slack.exe, zoom.exe, spotify.exe)

**Noise Paths:**
- `c:\windows\system32\`, `c:\windows\syswow64\`
- `appdata\local\google\chrome`, `appdata\local\microsoft\edge`
- Adobe, Office, browser paths

### Extraction Fields

| IOC Type | Source Fields |
|----------|---------------|
| `usernames` | `forensic_SubjectUserName`, `forensic_TargetUserName`, `Event.EventData.*` |
| `hostnames` | `forensic_Workstation`, `Event.EventData.Workstation`, `computer_name` |
| `ips` | `forensic_IpAddress`, `Event.EventData.IpAddress` (excludes link-local IPv6) |
| `processes` | Process name extracted from path |
| `commands` | `command_line` (>20 chars, not noise) |
| `paths` | Extracted from command_line via regex |

### Output Structure

```python
{
    'success': True,
    'potential_iocs': {
        'usernames': ['abecirovic', 'ckern'],
        'hostnames': ['PACKERP-8162S11'],
        'ips': ['10.5.2.100'],
        'processes': ['Made2Manage.exe'],
        'commands': ['C:\\Windows\\System32\\logoff.exe'],
        'paths': ['Z:\\IT\\Network\\TFC']
    },
    'events_searched': 3206,
    'existing_ioc_count': 16,
    'total_found': 45
}
```

### Routes

| Route | Method | Function |
|-------|--------|----------|
| `/case/<id>/triage/find-iocs` | POST | Find potential IOCs from events |
| `/case/<id>/triage/add-found-iocs` | POST | Save found IOCs to database |

### JavaScript Function

```javascript
function findPotentialIOCs() {
    // 1. Show modal with progress spinner
    // 2. POST to /case/{id}/triage/find-iocs
    // 3. Display categorized results in modal
    // 4. User reviews and clicks "Add Selected IOCs"
}
```

---

## Phase 3: Tag Highly Likely Events

### File: `app/ai_triage_tag_iocs.py`

Automatically tags events containing high-confidence IOCs. Creates `TimelineTag` entries for events that match commands, external IPs, actor systems, and other definitive indicators.

### High-Confidence IOC Criteria

| IOC Type | Criteria |
|----------|----------|
| `command` | Always high confidence (specific attack indicators) |
| `command_complex` | Always high confidence (obfuscated commands) |
| `hash` | Always high confidence (file hashes are definitive) |
| `malware_name` | Always high confidence |
| `url` | Always high confidence |
| `domain` | Always high confidence (C2 domains) |
| `filename` | Always high confidence (attack tools like nltest.exe, WinSCP.exe) |
| `tool` | Always high confidence (known attack tools) |
| `ip` | High confidence **only if external** (not private/loopback) |
| `hostname` | High confidence **only if threat_level is high/critical** |
| `filepath` | High confidence **only if threat_level is high/critical** |
| `username` | High confidence **only if threat_level is high/critical** |

**Actor Systems:** Systems marked as `actor_system` type in the database are always included.

### Functions

| Function | Purpose |
|----------|---------|
| `get_high_confidence_iocs(case_id)` | Get IOCs meeting high-confidence criteria |
| `get_actor_systems(case_id)` | Get hostnames/IPs of actor systems |
| `search_events_for_tagging(case_id, query)` | Query OpenSearch with scroll API (no limit) |
| `is_noise_event(event)` | Check if event should be filtered as noise |
| `tag_event(case_id, user_id, event, match)` | Create TimelineTag entry |
| `tag_high_confidence_events(case_id, user_id)` | **Main entry point** |

### Flow Logic

```python
def tag_high_confidence_events(case_id: int, user_id: int) -> Dict:
    """
    1. Get high-confidence IOCs from database
    2. Get actor system hostnames/IPs
    3. Build OpenSearch query for events matching IOCs
    4. Query excludes hidden events (is_hidden: true)
    5. Use scroll API to get ALL matching events (no limit)
    6. Filter noise events (system users, background processes)
    7. Skip already-tagged events
    8. Create TimelineTag entries for remaining events
    9. Return summary with tagged count
    """
```

### Filtering Logic (from `noise_filters.py`)

#### 1. Hidden Events
- OpenSearch query includes `"must_not": [{"term": {"is_hidden": True}}]`

#### 2. Already Tagged Events
- Events with existing `TimelineTag` entries are skipped

#### 3. Noise Event Filtering

**IMPORTANT:** Parent process is NOT filtered! Attackers run commands from `cmd.exe` and `powershell.exe` - this is expected behavior. Filtering by parent would incorrectly filter legitimate attack activity.

**Noise Event IDs:**
- Imported from `noise_filters.NOISE_EVENT_IDS`
- Event IDs 4689, 7036, 7040, 7045 (process termination, service changes)

**Noise Users (only if NO process info):**
- Events are only filtered as noise if ALL of these are true:
  1. ALL users in the event are system/noise users (from `NOISE_USERS`)
  2. AND the event has no process name or command line
- If an IOC matched, we keep the event even with noise users

### Output Structure

```python
{
    'success': True,
    'tagged_count': 42,
    'events_found': 156,
    'events_filtered': 114,
    'already_tagged': 12,
    'iocs_used': 18,
    'tags_created': [
        {
            'event_id': 'abc123',
            'timestamp': '2024-01-15T10:30:00',
            'matched_ioc': 'nltest.exe /dclist',
            'ioc_type': 'command'
        },
        ...
    ]
}
```

### Routes

| Route | Method | Function |
|-------|--------|----------|
| `/case/<id>/triage/tag-events` | POST | Tag events with high-confidence IOCs |

### JavaScript Function

```javascript
function tagHighlyLikelyEvents() {
    // 1. Show modal with progress spinner
    // 2. POST to /case/{id}/triage/tag-events
    // 3. Display results in modal (tagged count, filters applied)
    // 4. Refresh page to update tagged events count
}
```

---

## Routes Reference

### File: `app/main.py`

### GET `/case/<int:case_id>/triage`

**Function:** `triage_page(case_id)` (line ~2157)

Renders the triage prerequisites page.

### POST `/case/<int:case_id>/triage/extract-iocs`

**Function:** `triage_extract_iocs(case_id)` (line ~2239)

**Response:**
```json
{
    "success": true,
    "iocs": { "usernames": [...], "ips": [...], ... },
    "summary": { "total_count": 25, "by_type": {...}, "extraction_method": "llm" }
}
```

### POST `/case/<int:case_id>/triage/add-extracted-iocs`

**Function:** `triage_add_extracted_iocs(case_id)` (line ~2272)

**Type Mapping:**
```python
type_mapping = {
    'ips': 'ip', 'hostnames': 'hostname', 'usernames': 'username',
    'sids': 'user_sid', 'paths': 'filepath', 'processes': 'filename',
    'hashes': 'hash', 'commands': 'command', 'tools': 'tool', 'domains': 'domain'
}
```

**IOC Creation:**
```python
new_ioc = IOC(
    case_id=case_id,
    ioc_type=ioc_type_db,
    ioc_value=value[:500],
    description='Extracted from EDR Report',  # NOT 'ioc_source'
    is_active=True,
    created_by=current_user.id
)
```

### POST `/case/<int:case_id>/triage/find-iocs`

**Function:** `triage_find_iocs(case_id)` (line ~2344)

**Response:**
```json
{
    "success": true,
    "potential_iocs": { "usernames": [...], "hostnames": [...], ... },
    "summary": { "total_found": 45, "by_type": {...} },
    "events_searched": 3206,
    "existing_ioc_count": 16
}
```

### POST `/case/<int:case_id>/triage/add-found-iocs`

**Function:** `triage_add_found_iocs(case_id)` (line ~2381)

**Description field:** `'Discovered via IOC hunting'`

### POST `/case/<int:case_id>/triage/tag-events`

**Function:** `triage_tag_events(case_id)`

Triggers Phase 3 event tagging.

**Response:**
```json
{
    "success": true,
    "tagged_count": 42,
    "events_found": 156,
    "events_filtered": 114,
    "already_tagged": 12,
    "iocs_used": 18,
    "message": "Tagged 42 events with high-confidence IOCs"
}
```

---

## Database Models

### IOC Table

**File:** `app/models.py`

```python
class IOC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), index=True)
    ioc_type = db.Column(db.String(50))  # ip, username, hostname, command, etc.
    ioc_value = db.Column(db.String(500), index=True)
    description = db.Column(db.Text)  # 'Extracted from EDR Report' or 'Discovered via IOC hunting'
    threat_level = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

**Threat Level Values:**
- `low` - Informational indicator
- `medium` - Default, requires investigation
- `high` - Likely attack-related (included in Phase 3 tagging)
- `critical` - Definitive attack indicator (included in Phase 3 tagging)

### TimelineTag Table

**File:** `app/models.py`

```python
class TimelineTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), index=True)
    event_id = db.Column(db.String(100), index=True)  # OpenSearch _id
    event_timestamp = db.Column(db.DateTime)
    tag_type = db.Column(db.String(50))  # 'ioc_match', 'actor_system', 'manual'
    tag_value = db.Column(db.String(500))  # The matched IOC value
    tag_reason = db.Column(db.Text)  # Why this event was tagged
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

**Used by:** Phase 3 event tagging to mark events for timeline generation.

### AITriageSearch Table

```python
class AITriageSearch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'))
    status = db.Column(db.String(50))  # 'running', 'completed', 'failed'
    search_date = db.Column(db.DateTime)
    iocs_extracted_count = db.Column(db.Integer, default=0)
    iocs_discovered_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

---

## Reconstruction Checklist

To rebuild this system:

### 0. Centralized Noise Filters (`noise_filters.py`)
- [ ] Create `app/noise_filters.py` as single source of truth
- [ ] Define `NOISE_USERS`, `NOISE_PROCESSES`, `NOISE_PATH_PATTERNS`
- [ ] Define `is_noise_user()`, `is_noise_process()`, `is_external_ip()` functions
- [ ] All triage modules import from this file

### 1. Triage Page (`templates/triage.html`)
- [ ] Prerequisite cards with conditional styling
- [ ] Badge pills for status indicators
- [ ] Phase 1 button: "Extract IOCs from EDR Report"
- [ ] Phase 2 button: "Find Potential IOCs"
- [ ] Phase 3 button: "Tag Highly Likely Events"
- [ ] Modals for progress and results

### 2. Phase 1 Module (`ai_triage_edr_ioc.py`)
- [ ] `is_ai_enabled()` to check system settings
- [ ] `extract_iocs_with_llm()` with QWEN prompt
- [ ] `extract_iocs_with_regex()` with pattern matching
- [ ] `extract_iocs_from_report()` flow logic

### 3. Phase 2 Module (`ai_triage_find_iocs.py`)
- [ ] Import from `noise_filters.py`
- [ ] `get_case_context()` to load filtering data
- [ ] `search_events_with_iocs()` with scroll API
- [ ] `extract_iocs_from_events()` with all filters
- [ ] `check_managed_tool()` for RMM/EDR ID verification
- [ ] `contains_existing_ioc()` for duplicate detection

### 4. Phase 3 Module (`ai_triage_tag_iocs.py`)
- [ ] Import from `noise_filters.py`
- [ ] `get_high_confidence_iocs()` to get IOCs for tagging
- [ ] `get_actor_systems()` to get actor hostnames/IPs
- [ ] `search_events_for_tagging()` with scroll API (no limit)
- [ ] `is_noise_event()` for noise filtering
- [ ] `tag_event()` to create TimelineTag entries
- [ ] `tag_high_confidence_events()` main entry point

### 5. Routes (`main.py`)
- [ ] `triage_page()` route
- [ ] `triage_extract_iocs()` route
- [ ] `triage_add_extracted_iocs()` route
- [ ] `triage_find_iocs()` route
- [ ] `triage_add_found_iocs()` route
- [ ] `triage_tag_events()` route
- [ ] **Important:** Use `description` field, NOT `ioc_source`

### 6. JavaScript
- [ ] `extractIOCs()` for Phase 1
- [ ] `addExtractedIOCs()` to save Phase 1 results
- [ ] `findPotentialIOCs()` for Phase 2
- [ ] `addFoundIOCs()` to save Phase 2 results
- [ ] `tagHighlyLikelyEvents()` for Phase 3

---

## Version History

| Version | Changes |
|---------|---------|
| v1.46.0 | Initial triage page with prerequisites |
| v1.46.0 | Created `ai_triage_edr_ioc.py` (Phase 1) |
| v1.46.0 | Added IOC extraction routes and UI |
| v1.46.2 | Fixed IOC creation: use `description` not `ioc_source` |
| v1.46.3 | Created `ai_triage_find_iocs.py` (Phase 2) |
| v1.46.3 | Added snowball hunting with managed tool filtering |
| v1.46.3 | Added scroll API for unlimited event search |
| v1.46.3 | Added `contains_existing_ioc()` for duplicate filtering |
| v1.46.3 | Created `ai_triage_tag_iocs.py` (Phase 3) |
| v1.46.3 | Added high-confidence event tagging with TimelineTag |
| v1.46.3 | Centralized noise filters into `noise_filters.py` |
| v1.46.3 | All triage modules now import from centralized filters |
| v1.46.4 | **FIX:** Moved `filename` and `tool` to HIGH_CONFIDENCE_IOC_TYPES |
| v1.46.4 | **FIX:** Removed parent process filtering from is_noise_event() |
| v1.46.4 | **FIX:** Attack commands from cmd.exe/powershell.exe now correctly tagged |
