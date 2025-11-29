# AI Triage Search - Implementation Plan

**Created**: 2025-11-29  
**Last Updated**: 2025-11-29  
**Purpose**: Blueprint for implementing the fully automated AI Triage Search feature by reusing existing code.

---

## Overview

The AI Triage Search combines:
1. **Triage IOC Discovery** (exists in `triage_report.py`)
2. **Tagged Events as Anchors** (exists in `TimelineTag` model)
3. **MITRE Pattern Matching** (exists in `ai_search.py`)
4. **Time Window Analysis** (NEW - ~10 lines)
5. **Process Tree Building** (NEW - ~10 lines)
6. **Orchestration** (NEW - ties it together)

**Goal**: User clicks "AI Search" button → system automatically finds anchor events (from IOCs + analyst-tagged events), hunts related activity, builds process trees, identifies MITRE techniques, and generates attack narrative.

---

## Flexible Entry Points (No EDR Report Fallback)

The AI Triage Search supports multiple entry points depending on what data is available:

### Decision Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    USER CLICKS "AI TRIAGE SEARCH"                   │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────┐
                    │  Does case have EDR report? │
                    └─────────────────────────────┘
                           │              │
                          YES            NO
                           │              │
                           ▼              ▼
              ┌──────────────────┐  ┌──────────────────────────────┐
              │ ENTRY POINT 1:   │  │ Check existing IOCs...       │
              │ Full Triage      │  └──────────────────────────────┘
              │ Extract IOCs     │              │
              │ from report      │              ▼
              └──────────────────┘    ┌─────────────────────────────┐
                           │          │  Does case have IOCs?       │
                           │          └─────────────────────────────┘
                           │                 │              │
                           │                YES            NO
                           │                 │              │
                           │                 ▼              ▼
                           │    ┌─────────────────┐  ┌─────────────────────┐
                           │    │ ENTRY POINT 2:  │  │ Check tagged events │
                           │    │ IOC-Based Hunt  │  └─────────────────────┘
                           │    │ Prompt for      │           │
                           │    │ date/time       │    ┌──────┴──────┐
                           │    └─────────────────┘   YES           NO
                           │           │               │              │
                           │           │               ▼              ▼
                           │           │    ┌─────────────────┐  ┌─────────────────┐
                           │           │    │ ENTRY POINT 3:  │  │ ERROR:          │
                           │           │    │ Tag-Based Hunt  │  │ Must define     │
                           │           │    │ Use tagged      │  │ 1 IOC or tag    │
                           │           │    │ events as       │  │ 1 event         │
                           │           │    │ anchors         │  └─────────────────┘
                           │           │    └─────────────────┘
                           │           │               │
                           └───────────┴───────────────┘
                                       │
                                       ▼
                           ┌──────────────────────────┐
                           │ Continue with Phases:    │
                           │ IOC Classification,      │
                           │ Hunting, Time Windows,   │
                           │ Process Trees, MITRE     │
                           └──────────────────────────┘
```

### Entry Points Summary

| Entry Point | Has Report | Has IOCs | Has Tags | User Prompt | Action |
|-------------|------------|----------|----------|-------------|--------|
| **1. Full Triage** | ✅ | - | - | None | Extract IOCs from report, proceed normally |
| **2. IOC-Based Hunt** | ❌ | ✅ | - | Date/Time | Hunt existing IOCs from specified date |
| **3. Tag-Based Hunt** | ❌ | ❌ | ✅ | None | Use tagged events as anchors |
| **4. Error** | ❌ | ❌ | ❌ | N/A | Show error: "Add 1 IOC or tag 1 event" |

### Entry Point 1: Full Triage (EDR Report Available)

When an EDR report exists:
- Extract IOCs from report using LLM/regex
- Merge with any existing IOCs (deduplicated)
- Include tagged events as high-priority anchors
- Proceed with all phases

### Entry Point 2: IOC-Based Hunt (No Report, IOCs Exist)

When no report but IOCs exist:
- **Prompt user for date/time** of the incident
- Use existing IOCs as hunt targets
- Default date suggestion: earliest IOC creation date or case creation date
- Hunt within ±24h of the specified date

**Modal UI:**
```
┌──────────────────────────────────────────────────────────────┐
│  🔍 AI Triage Search                                         │
├──────────────────────────────────────────────────────────────┤
│  No EDR report found, but 5 IOCs exist for this case.        │
│                                                              │
│  Enter incident date/time to begin hunting:                  │
│  ┌────────────────────────────────────────┐                  │
│  │ 2025-11-03 15:00                       │                  │
│  └────────────────────────────────────────┘                  │
│                                                              │
│  IOCs to hunt:                                               │
│  • IP: 192.168.1.50 (active)                                │
│  • Hostname: ATN81960 (active)                              │
│  • Process: statements546.exe (active)                      │
│                                                              │
│  [Start Hunt]  [Cancel]                                      │
└──────────────────────────────────────────────────────────────┘
```

### Entry Point 3: Tag-Based Hunt (No Report, No IOCs, Tags Exist)

When only tagged events exist:
- **No date prompt needed** - use timestamps from tagged events
- Tagged events ARE the anchors (high confidence)
- Skip IOC extraction phase
- Proceed directly to time window analysis

**Modal UI:**
```
┌──────────────────────────────────────────────────────────────┐
│  🔍 AI Triage Search                                         │
├──────────────────────────────────────────────────────────────┤
│  No EDR report or IOCs found.                                │
│  Using 12 tagged events as anchor points.                    │
│                                                              │
│  Tagged events span: 2025-11-03 14:00 - 2025-11-03 16:30     │
│                                                              │
│  [Start Analysis]  [Cancel]                                  │
└──────────────────────────────────────────────────────────────┘
```

### Entry Point 4: Error State (Nothing Available)

When nothing is available:
- Show clear error message
- Provide action buttons to add data

**Modal UI:**
```
┌──────────────────────────────────────────────────────────────┐
│  🔍 AI Triage Search                                         │
├──────────────────────────────────────────────────────────────┤
│  ⚠️ Cannot start AI Triage Search                            │
│                                                              │
│  This case has no:                                           │
│  • EDR Report                                                │
│  • IOCs defined                                              │
│  • Tagged events                                             │
│                                                              │
│  To use AI Triage Search, please either:                     │
│  1. Add an EDR report to the case                            │
│  2. Add at least one IOC                                     │
│  3. Tag at least one event in the search results             │
│                                                              │
│  [Add EDR Report]  [Add IOC]  [Go to Search]  [Cancel]       │
└──────────────────────────────────────────────────────────────┘
```

### Priority When Multiple Sources Exist

| Priority | Source | Reason |
|----------|--------|--------|
| 1 | **EDR Report** | Most complete, has context and IOCs together |
| 2 | **Tagged Events** | Analyst-confirmed, high confidence |
| 3 | **Existing IOCs** | May be from prior analysis or manual entry |

**Hybrid Mode**: When multiple sources exist, use ALL of them:
- Extract IOCs from report (if available)
- Merge with existing IOCs (deduplicated)
- Include tagged events as high-priority anchors

---

## Critical Design Decisions (Updated 2025-11-29)

### Auto-Tagging Strategy

After testing on Case 18 (10M+ events), we established these rules:

| Rule | Decision | Rationale |
|------|----------|-----------|
| **Auto-tag SPECIFIC IOCs** | ✅ YES | Malware, hashes, suspicious commands = low count, high value |
| **Auto-tag BROAD IOCs** | ❌ NO | Usernames, hostnames = too many events (40K+), use aggregations |
| **Time constraint** | ❌ NO | Attacks can span days/weeks, don't limit |
| **Max auto-tag limit** | ❌ NO | Might miss key events |
| **Use scroll API** | ✅ YES | Needed for >10K results |

### IOC Classification

**SPECIFIC IOCs** (auto-tag all matches):
- `process` - Malware executables (e.g., statements546.exe)
- `hash` - File hashes (SHA256, MD5)
- `filepath` - Suspicious file paths
- `command` - Encoded PowerShell, suspicious commands
- `threat` - Defender threat names

**BROAD IOCs** (discovery via aggregations only, NO auto-tag):
- `username` - User accounts (can match 40K+ events)
- `hostname` - Computer names (can match 380K+ events)
- `ip` - IP addresses (variable)
- `sid` - Windows SIDs

### Why This Split?

From Case 18 dry run:
```
SPECIFIC IOCs:
  - statements546.exe: 2 events ✅ AUTO-TAG
  - SHA256 hash: 1 event ✅ AUTO-TAG
  - Encoded PowerShell: 1 event ✅ AUTO-TAG
  TOTAL: 4 events

BROAD IOCs:
  - jwilliams (username): 41,784 events ❌ AGGREGATION ONLY
  - ATN81960 (hostname): 381,151 events ❌ AGGREGATION ONLY
```

Auto-tagging 400K+ events would flood the timeline. Instead, we use aggregations to **discover** related IOCs without tagging every match.

---

## Known Good Exclusions (System Tools Settings)

### The Problem

Many events that match suspicious patterns are actually **legitimate**:
- RMM tools (LabTech, Datto, Kaseya) running health checks (`whoami`, `systeminfo`)
- Analyst tools (ScreenConnect with known-good IDs)
- Internal IP ranges (office networks, VPN pools)

Without exclusions, we'd auto-tag thousands of false positives.

### Solution: System Tools Settings

A new settings area allows administrators to define "known good" items that should be **excluded from auto-tagging**.

#### Database Model: `SystemToolsSetting`

```python
class SystemToolsSetting(db.Model):
    """Known-good tools and IPs to exclude from hunting/tagging"""
    __tablename__ = 'system_tools_setting'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_type = db.Column(db.String(50), nullable=False, index=True)
    # Types: 'rmm_tool', 'remote_tool', 'known_good_ip'
    
    # For RMM/Remote tools
    tool_name = db.Column(db.String(100))  # 'ConnectWise Automate', 'ScreenConnect', etc.
    executable_pattern = db.Column(db.String(200))  # 'LTSVC.exe', 'ScreenConnect*.exe'
    
    # For Remote tools with IDs (e.g., ScreenConnect session IDs)
    known_good_ids = db.Column(db.Text)  # JSON list of known-good session IDs
    
    # For IP exclusions
    ip_or_cidr = db.Column(db.String(50))  # '192.168.1.0/24' or '10.0.0.50'
    
    # Metadata
    description = db.Column(db.String(500))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
```

#### Settings Categories

##### 1. RMM Tools (Legitimate Management Software)

| Tool | Executable Pattern | Notes |
|------|-------------------|-------|
| ConnectWise Automate | `LTSVC.exe`, `LTSvcMon.exe`, `LabTech*.exe` | MSP management |
| Datto RMM | `AEMAgent.exe`, `Datto*.exe` | MSP management |
| Kaseya VSA | `AgentMon.exe`, `Kaseya*.exe` | MSP management |
| NinjaRMM | `NinjaRMMAgent.exe` | MSP management |
| Syncro | `Syncro*.exe` | MSP management |
| Atera | `AteraAgent.exe` | MSP management |
| N-able | `N-central*.exe`, `BASupSrvc*.exe` | MSP management |
| **Other** | User-defined | Custom executable pattern |

**Exclusion Logic**: Events where `process.parent.name` matches an RMM executable are excluded from auto-tagging.

##### 2. Remote Connectivity Tools (Dual-Use)

These tools can be legitimate OR malicious. We allow defining "known good" instances:

| Tool | Identifier Field | Example |
|------|-----------------|---------|
| ScreenConnect | Session ID | `24a22b9fc261d141` (legitimate IT support) |
| TeamViewer | Partner ID | `123456789` |
| AnyDesk | Address | `123 456 789` |
| GoTo Assist | Session ID | Custom |
| **Other** | User-defined | Custom pattern |

**Exclusion Logic**: Events matching the tool BUT with a known-good ID are excluded. Events with unknown IDs are still flagged.

##### 3. Known Good IPs/Networks

| Format | Example | Notes |
|--------|---------|-------|
| Single IP | `192.168.1.50` | Specific host |
| CIDR Range | `10.0.0.0/8` | Internal network |
| CIDR Range | `172.16.0.0/12` | Internal network |

**Exclusion Logic**: Events with source/destination IP in known-good ranges are excluded from auto-tagging.

#### UI Design: System Tools Settings Page

```
┌──────────────────────────────────────────────────────────────────────────┐
│  ⚙️ System Tools Settings                                                │
│  Define known-good tools and networks to exclude from hunting            │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  🔧 RMM TOOLS (Remote Monitoring & Management)                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ ┌──────────────────────────┐  ┌──────────────────────────────────┐ │  │
│  │ │ Select RMM Tool ▼        │  │ Executable Pattern               │ │  │
│  │ │ ○ ConnectWise Automate   │  │ LTSVC.exe, LTSvcMon.exe          │ │  │
│  │ │ ○ Datto RMM              │  │ (auto-filled based on selection) │ │  │
│  │ │ ○ Kaseya VSA             │  └──────────────────────────────────┘ │  │
│  │ │ ○ NinjaRMM               │                                      │  │
│  │ │ ○ Other (custom)         │  [+ Add RMM Tool]                    │  │
│  │ └──────────────────────────┘                                      │  │
│  │                                                                    │  │
│  │ Current RMM Exclusions:                                           │  │
│  │ • ConnectWise Automate (LTSVC.exe, LTSvcMon.exe) ✓ Active [🗑️]   │  │
│  │ • Custom: MyRMM.exe ✓ Active [🗑️]                                │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  🖥️ REMOTE CONNECTIVITY TOOLS                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ ┌──────────────────────────┐  ┌──────────────────────────────────┐ │  │
│  │ │ Select Tool ▼            │  │ Known Good IDs (one per line)    │ │  │
│  │ │ ○ ScreenConnect          │  │ 24a22b9fc261d141                 │ │  │
│  │ │ ○ TeamViewer             │  │ 98f7c3a2b1e45678                 │ │  │
│  │ │ ○ AnyDesk                │  │                                  │ │  │
│  │ │ ○ GoTo Assist            │  └──────────────────────────────────┘ │  │
│  │ │ ○ Other (custom)         │                                      │  │
│  │ └──────────────────────────┘  [+ Add Remote Tool]                 │  │
│  │                                                                    │  │
│  │ Current Remote Tool Exclusions:                                   │  │
│  │ • ScreenConnect IDs: 24a22b9fc261d141, 98f7c3a2... ✓ Active [🗑️] │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  🌐 KNOWN GOOD IP ADDRESSES/NETWORKS                                     │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ Enter IPs or CIDR ranges (one per line):                          │  │
│  │ ┌──────────────────────────────────────────────────────────────┐  │  │
│  │ │ 192.168.1.0/24                                               │  │  │
│  │ │ 10.0.0.0/8                                                   │  │  │
│  │ │ 172.16.0.0/12                                                │  │  │
│  │ │ 203.0.113.50                                                 │  │  │
│  │ └──────────────────────────────────────────────────────────────┘  │  │
│  │                                                                    │  │
│  │ [Save IP Exclusions]                                              │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

#### How Exclusions Are Applied

During AI Triage Search, before auto-tagging an event:

```python
def should_exclude_event(event: Dict, exclusions: Dict) -> bool:
    """
    Check if event should be excluded from auto-tagging.
    
    Args:
        event: Event dict from OpenSearch
        exclusions: Dict with 'rmm_executables', 'remote_tool_ids', 'known_good_ips'
    
    Returns:
        True if event should be excluded (known good)
    """
    src = event.get('_source', event)
    proc = src.get('process', {})
    parent = proc.get('parent', {})
    
    # Check 1: Parent process is a known RMM tool
    parent_name = (parent.get('name') or '').lower()
    for rmm_pattern in exclusions.get('rmm_executables', []):
        if fnmatch.fnmatch(parent_name, rmm_pattern.lower()):
            return True  # Exclude - spawned by legitimate RMM
    
    # Check 2: Process is a remote tool with known-good ID
    proc_name = (proc.get('name') or '').lower()
    cmd_line = (proc.get('command_line') or '').lower()
    for tool_config in exclusions.get('remote_tools', []):
        if tool_config['pattern'].lower() in proc_name:
            # Check if session ID is in known-good list
            for known_id in tool_config.get('known_good_ids', []):
                if known_id.lower() in cmd_line:
                    return True  # Exclude - known good session
    
    # Check 3: Source/destination IP is in known-good range
    source_ip = src.get('source', {}).get('ip') or src.get('host', {}).get('ip')
    if source_ip:
        if isinstance(source_ip, list):
            source_ip = source_ip[0]
        for ip_range in exclusions.get('known_good_ips', []):
            if ip_in_range(source_ip, ip_range):
                return True  # Exclude - known good IP
    
    return False  # Don't exclude - potentially suspicious
```

#### Loading Exclusions

```python
def get_system_tools_exclusions() -> Dict:
    """Load all active exclusions from database."""
    from models import SystemToolsSetting
    
    exclusions = {
        'rmm_executables': [],
        'remote_tools': [],
        'known_good_ips': []
    }
    
    settings = SystemToolsSetting.query.filter_by(is_active=True).all()
    
    for s in settings:
        if s.setting_type == 'rmm_tool':
            if s.executable_pattern:
                exclusions['rmm_executables'].extend(
                    s.executable_pattern.split(',')
                )
        
        elif s.setting_type == 'remote_tool':
            ids = json.loads(s.known_good_ids) if s.known_good_ids else []
            exclusions['remote_tools'].append({
                'name': s.tool_name,
                'pattern': s.executable_pattern,
                'known_good_ids': ids
            })
        
        elif s.setting_type == 'known_good_ip':
            if s.ip_or_cidr:
                exclusions['known_good_ips'].append(s.ip_or_cidr)
    
    return exclusions
```

### "Hide Known Good" Button (v1.38.0)

In addition to excluding events during AI Triage Search, analysts can **pre-hide** known-good events using the "Hide Known Good" button on the search page.

#### How It Works

1. **Button Location**: Search page, next to "Triage Report" button
2. **Pre-check**: Verifies exclusions are configured (prompts to configure if not)
3. **Scanning**: Uses scroll API to check ALL events in the case
4. **Matching**: Same logic as `should_exclude_event()` - checks parent process, remote tool IDs, source IPs
5. **Hiding**: Sets `is_hidden=true`, `hidden_reason='known_good_exclusion'` on matching events
6. **Progress**: Real-time progress updates via Server-Sent Events

#### Benefits

- **Pre-filter noise**: Run once after case setup to hide RMM/analyst activity
- **Cleaner searches**: Hidden events excluded by default from search results
- **AI Triage Integration**: Hidden events automatically excluded from AI Triage Search
- **Reversible**: Events can be viewed/unhidden using "Hidden Events" filter

#### Code Location

- Button: `app/templates/search_events.html` (line ~160)
- Modal: `app/templates/search_events.html` (after Triage modal)
- Route: `app/routes/system_tools.py` → `hide_known_good_events()`
- JavaScript: `showHideKnownGoodModal()`, `startHideKnownGood()`

---

## AI Triage Search: Exclusion Integration

The AI Triage Search uses **two layers** of exclusion:

### Layer 1: Hidden Events Filter

When searching OpenSearch, exclude events where `is_hidden=true`:

```python
query = {
    "bool": {
        "must": [...],
        "must_not": [
            {"term": {"is_hidden": True}}  # Exclude pre-hidden events
        ]
    }
}
```

### Layer 2: Real-Time Exclusion Check

For events that aren't pre-hidden, check against exclusion rules before auto-tagging:

```python
def should_auto_tag_event(event, exclusions):
    """Check if event should be auto-tagged (not excluded)."""
    
    # If already hidden, skip
    if event.get('_source', {}).get('is_hidden'):
        return False
    
    # Check against real-time exclusion rules
    if should_exclude_event(event, exclusions):
        return False
    
    return True
```

### Why Two Layers?

1. **Hidden Events**: Pre-filtered, reduces query load, analyst has already reviewed
2. **Real-Time Exclusions**: Catches new patterns, allows immediate exclusion updates without re-hiding

---

## Anchor Event Sources

Anchor events are the starting points for investigation. We use TWO sources:

### 1. Auto-Discovered Anchors (from Triage)
- Events matching **SPECIFIC IOCs** extracted from EDR report
- Events matching discovered IOCs (snowball hunting)
- Events matching malware/recon indicators

### 2. Analyst-Tagged Anchors (from TimelineTag)
- Events the analyst has manually tagged as important
- These are HIGH CONFIDENCE anchors - analyst has already reviewed them
- Stored in `timeline_tag` table with `event_id`, `event_data`, `notes`

**Priority**: Tagged events should be processed FIRST since they're analyst-confirmed.

---

## Existing Code to Reuse

### From `app/ai_search.py`

```python
from app.ai_search import (
    # Attack Detection
    identify_attack_techniques,      # Returns {technique_id: [matching_events]}
    generate_attack_analysis,        # Returns formatted attack analysis string
    MITRE_ATTACK_PATTERNS,           # Dict of technique indicators
    
    # Kill Chain Analysis
    determine_kill_chain_phase,      # Maps techniques → kill chain phase
    get_kill_chain_context,          # Context string for LLM
    get_gap_analysis,                # What to look for if not found
    KILL_CHAIN_PHASES,               # Full kill chain definition
    GAP_ANALYSIS,                    # Gap analysis templates
    
    # User Investigation
    get_user_timeline,               # Timeline for specific user
    analyze_user_compromise,         # Compromise analysis
    
    # Query Expansion
    expand_query_for_dfir,           # "malware" → 30+ search terms
    DFIR_QUERY_EXPANSION,            # Expansion dictionary
    
    # Pattern Detection
    IntelligentSampler,              # Class with detection methods:
                                     #   ._detect_suspicious_processes()
                                     #   ._detect_lateral_movement()
                                     #   ._detect_password_spray()
    
    # Exclusions
    COMMON_EXCLUSIONS,               # Known-good processes
)
```

### From `app/routes/triage_report.py`

```python
from app.routes.triage_report import (
    # IOC Extraction
    extract_iocs_with_llm,           # LLM-based IOC extraction
    extract_iocs_with_regex,         # Regex fallback
    
    # Search Functions
    search_ioc,                      # Search OpenSearch for IOC term
    extract_from_search_results,     # Extract IPs/hostnames/users from results
    extract_recon_from_results,      # Extract commands/executables from results
    extract_defender_threats,        # Get Defender threat names
    
    # Validation
    is_valid_hostname,               # Filter invalid hostnames
    is_machine_account,              # Filter machine accounts (ending in $)
    
    # Constants
    RECON_SEARCH_TERMS,              # ['nltest', 'whoami', 'ipconfig', ...]
    NOT_HOSTNAMES,                   # Blocklist for hostname validation
    NOT_USERNAMES,                   # Blocklist for username validation
)
```

### From `app/search_utils.py`

```python
from app.search_utils import (
    build_search_query,              # Build OpenSearch query with filters
    execute_search,                  # Execute query and return results
)
```

### From `app/models.py`

```python
from app.models import (
    TimelineTag,                     # Analyst-tagged events
    Case,                            # Case with edr_report
    IOC,                             # IOCs for the case
    System,                          # Systems/hostnames
)
```

---

## New Code to Add (~350 lines total)

### 1. Classify IOCs as Specific vs Broad

```python
def classify_iocs(iocs: Dict) -> Tuple[Dict, Dict]:
    """
    Split IOCs into SPECIFIC (auto-tag) and BROAD (aggregation only).
    
    Returns:
        (specific_iocs, broad_iocs) - both are dicts with ioc_type: [values]
    """
    specific_iocs = {
        'processes': iocs.get('processes', []),
        'paths': iocs.get('paths', []),
        'hashes': iocs.get('hashes', []),
        'commands': iocs.get('commands', []),
        'threats': iocs.get('threats', [])
    }
    
    broad_iocs = {
        'usernames': iocs.get('usernames', []),
        'hostnames': iocs.get('hostnames', []),
        'ips': iocs.get('ips', []),
        'sids': iocs.get('sids', [])
    }
    
    return specific_iocs, broad_iocs
```

### 2. Get Tagged Events as Anchors

```python
def get_tagged_event_anchors(case_id: int) -> List[Dict]:
    """
    Get all analyst-tagged events as anchor points.
    These are HIGH CONFIDENCE anchors - analyst has already reviewed them.
    
    Args:
        case_id: Case ID
    
    Returns:
        List of anchor dicts with event data, timestamp, hostname, notes
    """
    from app.models import TimelineTag
    import json
    
    tags = TimelineTag.query.filter_by(case_id=case_id).order_by(TimelineTag.created_at).all()
    
    anchors = []
    for tag in tags:
        try:
            event_data = json.loads(tag.event_data) if tag.event_data else {}
            
            # Extract key fields from the stored event snapshot
            timestamp = event_data.get('@timestamp')
            hostname = (event_data.get('normalized_computer') or 
                       event_data.get('host', {}).get('hostname') or
                       event_data.get('computer_name'))
            
            anchors.append({
                'event_id': tag.event_id,
                'event': event_data,
                'timestamp': timestamp,
                'hostname': hostname,
                'notes': tag.notes,
                'tag_color': tag.tag_color,
                'source': 'analyst_tagged',
                'confidence': 'high'  # Analyst-confirmed
            })
        except Exception as e:
            logger.warning(f"Failed to parse tagged event {tag.event_id}: {e}")
    
    return anchors
```

### 3. Search SPECIFIC IOCs and Get Events (for auto-tagging)

```python
def search_specific_iocs(opensearch_client, case_id: int, 
                         specific_iocs: Dict) -> Tuple[List[Dict], int]:
    """
    Search for SPECIFIC IOCs and return matching events for auto-tagging.
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID
        specific_iocs: Dict of specific IOC types to values
    
    Returns:
        (list of anchor events, total count)
    """
    anchors = []
    total_count = 0
    
    for ioc_type, values in specific_iocs.items():
        for ioc_value in values:
            if not ioc_value:
                continue
            
            query_dsl = build_search_query(search_text=ioc_value)
            
            # Get count first
            count_response = opensearch_client.count(
                index=f"case_{case_id}", 
                body={"query": query_dsl.get("query", {})}
            )
            count = count_response['count']
            
            if count == 0:
                continue
            
            total_count += count
            
            # Fetch events (use scroll for >10K)
            if count <= 10000:
                response = opensearch_client.search(
                    index=f"case_{case_id}", 
                    body=query_dsl, 
                    size=min(count, 1000)
                )
                for hit in response['hits']['hits']:
                    anchors.append({
                        'event_id': hit['_id'],
                        'event': hit,
                        'ioc_type': ioc_type,
                        'matched_ioc': ioc_value,
                        'timestamp': hit['_source'].get('@timestamp'),
                        'hostname': (hit['_source'].get('normalized_computer') or
                                   hit['_source'].get('host', {}).get('hostname')),
                        'source': 'specific_ioc_match',
                        'confidence': 'medium'
                    })
            else:
                # Use scroll API for large result sets
                anchors.extend(scroll_search_ioc(opensearch_client, case_id, 
                                                  ioc_value, ioc_type))
    
    return anchors, total_count
```

### 4. Discover IOCs via Aggregations (for BROAD IOCs)

```python
def discover_iocs_via_aggregations(opensearch_client, case_id: int,
                                    broad_iocs: Dict) -> Dict:
    """
    Use aggregations to discover related IOCs from BROAD IOC searches.
    Does NOT return events - just discovers new IOCs.
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID
        broad_iocs: Dict of broad IOC types to values
    
    Returns:
        Dict of discovered IOCs: {hostnames: set, usernames: set, ips: set}
    """
    discovered = {
        'hostnames': set(),
        'usernames': set(),
        'ips': set()
    }
    
    for ioc_type, values in broad_iocs.items():
        for ioc_value in values:
            if not ioc_value:
                continue
            
            agg_query = {
                "size": 0,
                "query": build_search_query(search_text=ioc_value).get("query", {}),
                "aggs": {
                    "unique_hosts": {
                        "terms": {"field": "host.hostname.keyword", "size": 50}
                    },
                    "unique_computers": {
                        "terms": {"field": "normalized_computer.keyword", "size": 50}
                    },
                    "unique_users": {
                        "terms": {"field": "process.user.name.keyword", "size": 50}
                    },
                    "unique_ips": {
                        "terms": {"field": "host.ip.keyword", "size": 50}
                    }
                }
            }
            
            try:
                response = opensearch_client.search(
                    index=f"case_{case_id}", 
                    body=agg_query
                )
                
                aggs = response.get('aggregations', {})
                
                # Extract discovered values
                for bucket in aggs.get('unique_hosts', {}).get('buckets', []):
                    if bucket['key'] and bucket['key'] not in ['', '-']:
                        discovered['hostnames'].add(bucket['key'])
                
                for bucket in aggs.get('unique_computers', {}).get('buckets', []):
                    if bucket['key'] and bucket['key'] not in ['', '-']:
                        discovered['hostnames'].add(bucket['key'])
                
                for bucket in aggs.get('unique_users', {}).get('buckets', []):
                    key = bucket['key']
                    if key and key not in ['', '-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE']:
                        discovered['usernames'].add(key)
                
                for bucket in aggs.get('unique_ips', {}).get('buckets', []):
                    ip = bucket['key']
                    if ip and not ip.startswith('127.') and not ip.startswith('::'):
                        discovered['ips'].add(ip)
                        
            except Exception as e:
                logger.warning(f"Aggregation failed for {ioc_type}={ioc_value}: {e}")
    
    return discovered
```

### 5. Time Window Search Function

```python
from datetime import datetime, timedelta

def search_time_window(opensearch_client, case_id: int, hostname: str, 
                       anchor_time: datetime, minutes: int = 5) -> List[Dict]:
    """
    Search for all events ±N minutes around an anchor timestamp.
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID
        hostname: Computer name to filter by
        anchor_time: Center timestamp
        minutes: Window size (default ±5 minutes)
    
    Returns:
        List of events sorted by timestamp
    """
    start = (anchor_time - timedelta(minutes=minutes)).isoformat()
    end = (anchor_time + timedelta(minutes=minutes)).isoformat()
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"normalized_computer.keyword": hostname}},
                    {"range": {"@timestamp": {"gte": start, "lte": end}}}
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "size": 500,
        "_source": ["@timestamp", "process.name", "process.command_line", 
                   "process.parent.name", "process.parent.pid", "process.pid",
                   "process.user.name", "process.user.domain", "process.hash.sha256",
                   "has_ioc", "matched_iocs", "has_sigma", "sigma_rules", "search_blob"]
    }
    
    result = opensearch_client.search(index=f"case_{case_id}", body=query)
    return [hit['_source'] for hit in result['hits']['hits']]
```

### 6. Process Tree Builder Function

```python
def build_process_tree(opensearch_client, case_id: int, parent_pid: str, 
                       hostname: str, time_window_hours: int = 24) -> List[Dict]:
    """
    Find all child processes spawned by a parent PID.
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID
        parent_pid: Parent process ID to find children of
        hostname: Computer name to filter by
        time_window_hours: How far back to search
    
    Returns:
        List of child process events sorted by timestamp
    """
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"process.parent.pid": str(parent_pid)}},
                    {"term": {"normalized_computer.keyword": hostname}}
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "size": 100,
        "_source": ["@timestamp", "process.name", "process.command_line",
                   "process.pid", "process.parent.pid", "process.parent.name",
                   "process.user.name", "process.user.domain"]
    }
    
    result = opensearch_client.search(index=f"case_{case_id}", body=query)
    return [hit['_source'] for hit in result['hits']['hits']]
```

### 7. Auto-Tag Anchor Events (SPECIFIC IOCs only)

```python
def auto_tag_anchor_events_batch(case_id: int, user_id: int, 
                                  anchors: List[Dict]) -> Dict[str, int]:
    """
    Batch auto-tag anchor events from SPECIFIC IOC matches.
    
    Args:
        case_id: Case ID
        user_id: User who initiated the search
        anchors: List of anchor dicts with 'event', 'matched_ioc', 'ioc_type'
    
    Returns:
        Dict with counts: {tagged: N, skipped: N, errors: N}
    """
    from app.models import TimelineTag
    from main import db
    import json
    
    index_name = f"case_{case_id}"
    counts = {'tagged': 0, 'skipped': 0, 'errors': 0}
    
    # Get existing tags for this case to avoid duplicates
    existing_event_ids = set(
        t.event_id for t in TimelineTag.query.filter_by(
            case_id=case_id, index_name=index_name
        ).all()
    )
    
    tags_to_add = []
    for anchor in anchors:
        try:
            event = anchor.get('event', {})
            event_id = anchor.get('event_id') or event.get('_id')
            
            if not event_id:
                counts['errors'] += 1
                continue
            
            if event_id in existing_event_ids:
                counts['skipped'] += 1
                continue
            
            # Build reason string
            ioc_value = anchor.get('matched_ioc', '')
            ioc_type = anchor.get('ioc_type', 'unknown')
            reason = f"{ioc_type} match: {ioc_value}" if ioc_value else "AI Triage anchor"
            
            notes = f"[AI Triage Auto-Tagged]\nReason: {reason}"
            if ioc_value:
                notes += f"\nIOC Type: {ioc_type}\nIOC Value: {ioc_value}"
            
            tag = TimelineTag(
                case_id=case_id,
                user_id=user_id,
                event_id=event_id,
                index_name=index_name,
                event_data=json.dumps(event.get('_source', event)),
                tag_color='purple',  # AI-discovered = purple
                notes=notes
            )
            tags_to_add.append(tag)
            existing_event_ids.add(event_id)  # Prevent duplicates in same batch
            counts['tagged'] += 1
            
        except Exception as e:
            logger.warning(f"[AI_TRIAGE] Failed to prepare tag for anchor: {e}")
            counts['errors'] += 1
    
    # Bulk insert
    if tags_to_add:
        db.session.add_all(tags_to_add)
        db.session.commit()
        logger.info(f"[AI_TRIAGE] Batch auto-tagged {len(tags_to_add)} events")
    
    return counts
```

### Tag Colors Convention

| Color | Meaning |
|-------|---------|
| `blue` | Default - analyst manually tagged |
| `red` | Critical - analyst marked as high priority |
| `yellow` | Warning - needs review |
| `green` | Benign - confirmed not malicious |
| `purple` | **AI Triage Auto-Tagged** - discovered by automated search |
| `orange` | Suspicious - analyst flagged for follow-up |

### 8. Determine Entry Point Function

```python
def determine_entry_point(case_id: int) -> Dict:
    """
    Determine which entry point to use based on available data.
    
    Returns:
        Dict with:
        - entry_point: 'full_triage' | 'ioc_hunt' | 'tag_hunt' | 'error'
        - has_report: bool
        - has_iocs: bool
        - has_tags: bool
        - ioc_count: int
        - tag_count: int
        - suggested_date: datetime or None
        - message: str (for UI display)
    """
    from app.models import Case, IOC, TimelineTag
    
    case = Case.query.get(case_id)
    
    has_report = bool(case.edr_report)
    existing_iocs = IOC.query.filter_by(case_id=case_id, is_active=True).all()
    tagged_events = TimelineTag.query.filter_by(case_id=case_id).all()
    
    has_iocs = len(existing_iocs) > 0
    has_tags = len(tagged_events) > 0
    
    # Determine suggested date from IOCs or tags
    suggested_date = None
    if existing_iocs:
        # Use earliest IOC creation date
        earliest_ioc = min(existing_iocs, key=lambda x: x.created_at or datetime.max)
        suggested_date = earliest_ioc.created_at
    elif tagged_events:
        # Use earliest tagged event timestamp
        for tag in tagged_events:
            try:
                event_data = json.loads(tag.event_data) if tag.event_data else {}
                ts = event_data.get('@timestamp')
                if ts:
                    event_time = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    if suggested_date is None or event_time < suggested_date:
                        suggested_date = event_time
            except:
                pass
    
    # Determine entry point
    if has_report:
        return {
            'entry_point': 'full_triage',
            'has_report': True,
            'has_iocs': has_iocs,
            'has_tags': has_tags,
            'ioc_count': len(existing_iocs),
            'tag_count': len(tagged_events),
            'suggested_date': None,  # Not needed - will extract from report
            'message': f'EDR report found. Will extract IOCs and hunt.'
        }
    elif has_iocs:
        return {
            'entry_point': 'ioc_hunt',
            'has_report': False,
            'has_iocs': True,
            'has_tags': has_tags,
            'ioc_count': len(existing_iocs),
            'tag_count': len(tagged_events),
            'iocs': [{'type': ioc.ioc_type, 'value': ioc.ioc_value} for ioc in existing_iocs[:10]],
            'suggested_date': suggested_date,
            'message': f'No EDR report. Found {len(existing_iocs)} IOCs. Enter date/time to begin hunt.'
        }
    elif has_tags:
        return {
            'entry_point': 'tag_hunt',
            'has_report': False,
            'has_iocs': False,
            'has_tags': True,
            'ioc_count': 0,
            'tag_count': len(tagged_events),
            'suggested_date': suggested_date,
            'message': f'No EDR report or IOCs. Using {len(tagged_events)} tagged events as anchors.'
        }
    else:
        return {
            'entry_point': 'error',
            'has_report': False,
            'has_iocs': False,
            'has_tags': False,
            'ioc_count': 0,
            'tag_count': 0,
            'suggested_date': None,
            'message': 'Cannot start AI Triage Search. Please add an EDR report, IOC, or tag an event.'
        }
```

### 9. Convert Existing IOCs to Hunt Format

```python
def convert_existing_iocs_to_hunt_format(iocs: List) -> Dict:
    """
    Convert IOC model objects to the format expected by the hunting functions.
    
    Args:
        iocs: List of IOC model objects
    
    Returns:
        Dict in same format as extract_iocs_with_regex returns
    """
    result = {
        'ips': [],
        'hostnames': [],
        'usernames': [],
        'sids': [],
        'hashes': [],
        'paths': [],
        'processes': [],
        'commands': [],
        'threats': [],
        'domains': []
    }
    
    type_mapping = {
        'ip': 'ips',
        'hostname': 'hostnames',
        'username': 'usernames',
        'user_sid': 'sids',
        'sid': 'sids',
        'hash': 'hashes',
        'filepath': 'paths',
        'filename': 'processes',
        'process': 'processes',
        'command': 'commands',
        'threat': 'threats',
        'domain': 'domains',
        'url': 'domains'
    }
    
    for ioc in iocs:
        ioc_type = ioc.ioc_type.lower()
        target_key = type_mapping.get(ioc_type)
        if target_key and ioc.ioc_value:
            result[target_key].append(ioc.ioc_value)
    
    return result
```

### 10. Auto-Tag Timeline Events (Phase 9)

```python
TIMELINE_PROCESSES = [
    # Recon
    'nltest.exe', 'whoami.exe', 'ipconfig.exe', 'ping.exe', 
    'net.exe', 'net1.exe', 'netstat.exe', 'systeminfo.exe',
    'quser.exe', 'query.exe', 'nslookup.exe',
    
    # Execution
    'cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe',
    'mshta.exe', 'wscript.exe', 'cscript.exe',
    
    # Tools
    'advanced_ip_scanner.exe', 'psexec.exe', 'winscp.exe',
    
    # File access (when accessing suspicious paths)
    'notepad.exe', 'wordpad.exe', 'explorer.exe'
]

def filter_timeline_events(window_events: List[Dict]) -> List[Dict]:
    """
    Filter window events to only those that should appear in the timeline.
    These are the attack chain events.
    """
    timeline_events = []
    seen_keys = set()
    
    for event in window_events:
        src = event.get('_source', event)
        proc = src.get('process', {})
        proc_name = (proc.get('name') or '').lower()
        
        # Check if this is a timeline-worthy process
        if not any(p in proc_name for p in [x.lower().replace('.exe', '') for x in TIMELINE_PROCESSES]):
            continue
        
        # Deduplicate by timestamp + command
        cmd = proc.get('command_line') or ''
        ts = src.get('@timestamp', '')
        key = f"{ts}|{cmd}"
        
        if key in seen_keys:
            continue
        seen_keys.add(key)
        
        timeline_events.append(event)
    
    # Sort by timestamp
    timeline_events.sort(key=lambda x: x.get('_source', x).get('@timestamp', ''))
    
    return timeline_events


def auto_tag_timeline_events(case_id: int, user_id: int, 
                              timeline_events: List[Dict]) -> Dict:
    """
    Auto-tag the final timeline events with purple tags.
    These are the confirmed attack chain events.
    
    Args:
        case_id: Case ID
        user_id: User who ran the search
        timeline_events: List of events that made the final timeline
    
    Returns:
        Dict with counts: {tagged: N, skipped: N}
    """
    from app.models import TimelineTag
    from main import db
    import json
    
    index_name = f"case_{case_id}"
    counts = {'tagged': 0, 'skipped': 0}
    
    # Get existing tags to avoid duplicates
    existing_ids = set(
        t.event_id for t in TimelineTag.query.filter_by(
            case_id=case_id, index_name=index_name
        ).all()
    )
    
    tags_to_add = []
    for event in timeline_events:
        event_id = event.get('_id') or event.get('event_id')
        
        if not event_id or event_id in existing_ids:
            counts['skipped'] += 1
            continue
        
        # Build descriptive note
        src = event.get('_source', event)
        proc = src.get('process', {})
        proc_name = proc.get('name', 'Unknown')
        cmd = (proc.get('command_line') or '')[:100]
        timestamp = src.get('@timestamp', '')[:19]
        
        notes = f"[AI Triage Timeline Event]\n"
        notes += f"Timestamp: {timestamp}\n"
        notes += f"Process: {proc_name}\n"
        if cmd:
            notes += f"Command: {cmd}\n"
        notes += f"\nThis event is part of the reconstructed attack timeline."
        
        tag = TimelineTag(
            case_id=case_id,
            user_id=user_id,
            event_id=event_id,
            index_name=index_name,
            event_data=json.dumps(src),
            tag_color='purple',  # AI-discovered = purple
            notes=notes
        )
        tags_to_add.append(tag)
        existing_ids.add(event_id)
        counts['tagged'] += 1
    
    if tags_to_add:
        db.session.add_all(tags_to_add)
        db.session.commit()
    
    return counts
```

### 11. Main Orchestrator Function (with Flexible Entry Points)

```python
def ai_triage_search(case_id: int, user_id: int, 
                     search_date: datetime = None) -> Dict:
    """
    Full automated AI Triage Search with flexible entry points.
    
    Entry Points:
    1. EDR Report exists → extract IOCs, proceed normally
    2. No report, IOCs exist → use existing IOCs + search_date
    3. No report, no IOCs, tags exist → use tags as anchors
    4. Nothing exists → raise error
    
    Phases:
    1. Determine entry point and get initial data
    2. Get analyst-tagged events as anchors (HIGH PRIORITY)
    3. Get/Extract IOCs (from report OR existing IOCs)
    4. Classify IOCs as SPECIFIC vs BROAD
    5. Search SPECIFIC IOCs → get events for auto-tagging
    6. Discover via aggregations for BROAD IOCs
    7. Auto-tag SPECIFIC IOC matches (purple tags)
    8. Search time windows around ALL anchors
    9. Build process trees
    10. Apply MITRE pattern matching
    11. Generate attack narrative
    
    Args:
        case_id: Case ID
        user_id: User ID who initiated the search
        search_date: Optional date for IOC-based hunt (required if no report)
    
    Returns:
        Dict with iocs, anchors, timeline, process_trees, mitre_techniques, narrative
    
    Raises:
        ValueError: If no data sources available (no report, IOCs, or tags)
    """
    from app.ai_search import (
        identify_attack_techniques,
        determine_kill_chain_phase,
        generate_attack_analysis
    )
    from app.routes.triage_report import (
        extract_iocs_with_llm,
        extract_iocs_with_regex
    )
    from app.models import Case, IOC, TimelineTag
    
    # Get case
    case = Case.query.get(case_id)
    
    # Check what we have to work with
    has_report = bool(case.edr_report)
    existing_iocs = IOC.query.filter_by(case_id=case_id, is_active=True).all()
    tagged_events = TimelineTag.query.filter_by(case_id=case_id).all()
    
    results = {
        'entry_point': None,
        'iocs': {'from_report': {}, 'from_existing': {}, 'discovered': {}},
        'anchors': {
            'tagged': [],      # Analyst-tagged (high confidence)
            'discovered': []   # SPECIFIC IOC matches (auto-discovered)
        },
        'auto_tag_counts': {},
        'time_windows': [],
        'process_trees': [],
        'mitre_techniques': {},
        'kill_chain_phase': None,
        'narrative': '',
        'timeline': []
    }
    
    # =========================================================================
    # PHASE 1: DETERMINE ENTRY POINT
    # =========================================================================
    
    if has_report:
        # ENTRY POINT 1: Full Triage
        results['entry_point'] = 'full_triage'
        report_text = case.edr_report
        
        # Extract IOCs from report
        iocs = extract_iocs_with_llm(report_text)
        if not iocs or not any(iocs.values()):
            iocs = extract_iocs_with_regex(report_text)
        
        results['iocs']['from_report'] = iocs
        
        # Merge with existing IOCs (if any)
        if existing_iocs:
            existing_iocs_dict = convert_existing_iocs_to_hunt_format(existing_iocs)
            for key in iocs:
                if key in existing_iocs_dict:
                    # Deduplicate
                    combined = list(set(iocs.get(key, []) + existing_iocs_dict.get(key, [])))
                    iocs[key] = combined
            results['iocs']['from_existing'] = existing_iocs_dict
        
    elif existing_iocs:
        # ENTRY POINT 2: IOC-Based Hunt
        results['entry_point'] = 'ioc_hunt'
        
        if not search_date:
            raise ValueError("search_date required when no EDR report exists. "
                           "Please specify the approximate incident date/time.")
        
        # Convert existing IOCs to hunt format
        iocs = convert_existing_iocs_to_hunt_format(existing_iocs)
        results['iocs']['from_existing'] = iocs
        
    elif tagged_events:
        # ENTRY POINT 3: Tag-Based Hunt
        results['entry_point'] = 'tag_hunt'
        
        # No IOCs to hunt - will use tags as anchors
        iocs = {}
        
    else:
        # ENTRY POINT 4: Error - Nothing to work with
        raise ValueError("No EDR report, IOCs, or tagged events found. "
                        "Please add at least one IOC or tag one event to use AI Triage Search.")
    
    # =========================================================================
    # PHASE 2: GET ANALYST-TAGGED ANCHORS (High Confidence)
    # =========================================================================
    
    tagged_anchors = get_tagged_event_anchors(case_id)
    results['anchors']['tagged'] = tagged_anchors
    
    # For tag-based hunt, if no IOCs, we're done with IOC extraction
    if results['entry_point'] == 'tag_hunt':
        logger.info(f"[AI_TRIAGE] Tag-based hunt: Using {len(tagged_anchors)} tagged events as anchors")
        # Skip to time window analysis (Phase 7)
        # ... continue with phases 7-11
    
    # =========================================================================
    # PHASE 3: (Already done in Phase 1 for report/IOC entry points)
    # =========================================================================
    
    results['iocs']['combined'] = iocs
    
    # =========================================================================
    # PHASE 3: CLASSIFY IOCs AS SPECIFIC VS BROAD
    # =========================================================================
    
    specific_iocs, broad_iocs = classify_iocs(iocs)
    
    # =========================================================================
    # PHASE 4: SEARCH SPECIFIC IOCs → GET EVENTS FOR AUTO-TAGGING
    # =========================================================================
    
    specific_anchors, specific_count = search_specific_iocs(
        opensearch_client, case_id, specific_iocs
    )
    results['anchors']['discovered'] = specific_anchors
    
    # =========================================================================
    # PHASE 5: DISCOVER VIA AGGREGATIONS FOR BROAD IOCs
    # =========================================================================
    
    discovered = discover_iocs_via_aggregations(
        opensearch_client, case_id, broad_iocs
    )
    results['iocs']['discovered'] = {
        'hostnames': list(discovered['hostnames']),
        'usernames': list(discovered['usernames']),
        'ips': list(discovered['ips'])
    }
    
    # =========================================================================
    # PHASE 6: AUTO-TAG SPECIFIC IOC MATCHES
    # =========================================================================
    
    if specific_anchors:
        tag_counts = auto_tag_anchor_events_batch(
            case_id=case_id,
            user_id=user_id,
            anchors=specific_anchors
        )
        results['auto_tag_counts'] = tag_counts
    
    # =========================================================================
    # PHASE 7: TIME WINDOW ANALYSIS
    # =========================================================================
    
    all_anchors = tagged_anchors + specific_anchors
    all_window_events = []
    processed_windows = set()
    
    for anchor in all_anchors[:30]:  # Limit to top 30 anchors
        hostname = anchor.get('hostname')
        timestamp = anchor.get('timestamp')
        
        if not hostname or not timestamp:
            continue
        
        window_key = f"{hostname}|{timestamp[:16]}"
        if window_key in processed_windows:
            continue
        processed_windows.add(window_key)
        
        try:
            anchor_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            window_events = search_time_window(opensearch_client, case_id, 
                                               hostname, anchor_time, minutes=5)
            all_window_events.extend(window_events)
        except Exception as e:
            logger.warning(f"Failed to search window: {e}")
    
    # =========================================================================
    # PHASE 8: PROCESS TREE BUILDING
    # =========================================================================
    
    # Find suspicious parent PIDs
    suspicious_parents = set()
    for event in all_window_events:
        proc = event.get('process', {})
        parent = proc.get('parent', {})
        parent_name = (parent.get('name') or '').lower()
        proc_name = (proc.get('name') or '').lower()
        
        if parent_name in ['cmd.exe', 'powershell.exe']:
            if proc_name in ['nltest.exe', 'whoami.exe', 'net.exe', 'ipconfig.exe']:
                suspicious_parents.add((parent.get('pid'), event.get('normalized_computer')))
    
    for parent_pid, hostname in suspicious_parents:
        if parent_pid and hostname:
            tree = build_process_tree(opensearch_client, case_id, parent_pid, hostname)
            if tree:
                results['process_trees'].append({
                    'parent_pid': parent_pid,
                    'hostname': hostname,
                    'children': tree
                })
    
    # =========================================================================
    # PHASE 9: MITRE PATTERN MATCHING
    # =========================================================================
    
    formatted_events = [{'_source': e, '_id': str(hash(str(e)))} for e in all_window_events]
    techniques = identify_attack_techniques(formatted_events)
    results['mitre_techniques'] = techniques
    results['kill_chain_phase'] = determine_kill_chain_phase(techniques)
    
    # =========================================================================
    # PHASE 10: GENERATE NARRATIVE
    # =========================================================================
    
    results['narrative'] = generate_attack_analysis(formatted_events)
    
    # =========================================================================
    # PHASE 11: FILTER AND AUTO-TAG TIMELINE EVENTS
    # =========================================================================
    
    # Filter to only timeline-worthy events
    timeline_events = filter_timeline_events(
        [{'_source': e, '_id': str(hash(str(e)))} for e in all_window_events]
    )
    
    # Build timeline for results
    for event in timeline_events:
        src = event.get('_source', event)
        proc = src.get('process', {})
        results['timeline'].append({
            'timestamp': src.get('@timestamp'),
            'process': proc.get('name'),
            'command': proc.get('command_line'),
            'user': f"{proc.get('user', {}).get('domain', '')}\\{proc.get('user', {}).get('name', '')}",
            'parent': proc.get('parent', {}).get('name'),
            'event_id': event.get('_id')
        })
    
    # Auto-tag timeline events (Phase 9)
    timeline_tag_counts = auto_tag_timeline_events(
        case_id=case_id,
        user_id=user_id,
        timeline_events=timeline_events
    )
    results['timeline_tag_counts'] = timeline_tag_counts
    
    return results
```

---

## File Structure

```
app/
├── ai_search.py              # Existing - MITRE patterns, attack analysis
├── routes/
│   ├── triage_report.py      # Existing - IOC extraction, hunting
│   └── ai_triage_search.py   # NEW - Orchestrator + time window + process tree
├── templates/
│   └── search_events.html    # Add "AI Search" button to existing modal
```

---

## Database Model: `AITriageSearch`

```python
class AITriageSearch(db.Model):
    """AI Triage Search results - stored for analyst review"""
    __tablename__ = 'ai_triage_search'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', index=True)
    
    # Results summary (JSON)
    summary_json = db.Column(db.Text)
    results_json = db.Column(db.Text)
    
    # Counts for quick display
    tagged_anchors_count = db.Column(db.Integer, default=0)      # Pre-existing analyst tags
    ioc_anchors_count = db.Column(db.Integer, default=0)         # SPECIFIC IOC matches
    auto_tagged_count = db.Column(db.Integer, default=0)         # Events auto-tagged this run
    total_events_analyzed = db.Column(db.Integer, default=0)
    techniques_found = db.Column(db.Integer, default=0)
    
    # Timing
    generation_time_seconds = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    case = db.relationship('Case', backref='ai_triage_searches')
    generator = db.relationship('User', backref='triage_searches')
```

---

## API Endpoints

### New Blueprint: `app/routes/ai_triage_search.py`

```python
@ai_triage_search_bp.route('/case/<int:case_id>/ai-triage-searches')
def list_triage_searches(case_id):
    """List all AI Triage Searches for the AI Analysis section."""

@ai_triage_search_bp.route('/case/<int:case_id>/ai-triage-search/run', methods=['POST'])
def run_triage_search(case_id):
    """Start a new AI Triage Search for the case."""

@ai_triage_search_bp.route('/ai-triage-search/<int:search_id>')
def view_triage_search(search_id):
    """View AI Triage Search results page."""

@ai_triage_search_bp.route('/ai-triage-search/<int:search_id>/api')
def get_triage_search(search_id):
    """Get triage search status/results as JSON."""
```

---

## Celery Task

```python
@celery_app.task(bind=True, name='tasks.run_ai_triage_search')
def run_ai_triage_search(self, search_id):
    """Run AI Triage Search and store results."""
    search = AITriageSearch.query.get(search_id)
    search.status = 'running'
    db.session.commit()
    
    try:
        results = ai_triage_search(search.case_id, search.generated_by)
        
        search.results_json = json.dumps(results)
        search.tagged_anchors_count = len(results['anchors']['tagged'])
        search.ioc_anchors_count = len(results['anchors']['discovered'])
        search.auto_tagged_count = results.get('auto_tag_counts', {}).get('tagged', 0)
        search.status = 'completed'
        
    except Exception as e:
        search.status = 'failed'
        search.error_message = str(e)
    
    db.session.commit()
```

---

## Summary

| Component | Lines of Code | Source |
|-----------|---------------|--------|
| MITRE Pattern Matching | 0 | Reuse `ai_search.py` |
| Kill Chain Analysis | 0 | Reuse `ai_search.py` |
| Attack Narrative | 0 | Reuse `ai_search.py` |
| IOC Extraction | 0 | Reuse `triage_report.py` |
| Snowball Hunting | 0 | Reuse `triage_report.py` |
| IOC Classification | ~20 | NEW |
| Tagged Event Anchors | ~40 | NEW |
| SPECIFIC IOC Search | ~50 | NEW |
| BROAD IOC Aggregations | ~60 | NEW |
| Auto-Tag Anchors | ~60 | NEW |
| Time Window Search | ~25 | NEW |
| Process Tree Builder | ~20 | NEW |
| Timeline Event Filter | ~30 | NEW |
| Timeline Event Auto-Tag | ~50 | NEW |
| Orchestrator | ~120 | NEW |
| API Endpoints | ~80 | NEW |
| Celery Task | ~30 | NEW |
| **TOTAL NEW CODE** | **~585 lines** |

**75% reuse of existing code. Only ~585 lines of new code needed.**

---

## Testing Checklist

1. [x] Test on Case 17 (JELLY) - RDP compromise + recon ✅
2. [x] Test on Case 18 (JHD) - Phishing + malicious RMM (10M+ events) ✅
3. [x] Test on Case 22 (SERVU) - Phishing + ScreenConnect ✅
4. [x] Test on Case 11 (DEPCO) - Lateral movement + Cobalt Strike ✅
5. [x] Test on Case 8/25 (CM) - VPN compromise + domain enum ✅ (Full dry run 2025-11-29)

### Case 25 Dry Run Results (2025-11-29)

**Full methodology test following all 8 phases:**

| Phase | Result |
|-------|--------|
| 1. IOC Extraction | 5 IPs, 3 hostnames, 1 username, 1 SID, 2 paths, 1 command, 1 tool |
| 2. IOC Classification | SPECIFIC: 4 items, BROAD: 10 items |
| 3. Snowball Hunting | 10 new users, 8 new IPs discovered via aggregations |
| 4. Malware/Recon Hunt | Searched nltest, whoami, ipconfig, Advanced IP Scanner |
| 5. SPECIFIC IOC Search | 1 event found (Advanced IP Scanner) |
| 6. Time Window Analysis | 837 events in ±5 min windows around 5 key timestamps |
| 7. Process Trees | 72 trees built from cmd.exe/powershell.exe parents |
| 8. MITRE Techniques | 6 techniques: T1016, T1018, T1033, T1078, T1087, T1482 |
| 9. Timeline Auto-Tag | ~30 timeline events would be auto-tagged |

**Auto-Tag Counts:**
- SPECIFIC IOC matches: 1 event
- Timeline events: ~30 events (filtered from 837 window events)
- **Total: ~31 events auto-tagged**

**Attack Timeline Confirmed:**
```
07:10:57 - tabadmin session starts (Explorer.EXE)
07:10:59 - Network share mapping (net use commands)
07:11:00 - Persistent route added
07:12:36 - PowerShell launched
07:12:55 - nltest /domain_trusts (T1482)
07:13:10 - AdUsers.txt accessed (T1087)
07:13:24 - AdComp.txt accessed (T1087)
07:14:40 - Advanced IP Scanner executed (T1018)
```

**Key Validation:**
- IOC classification prevented flooding (BROAD IOCs = 10K+ events each)
- Aggregations successfully discovered new IOCs without auto-tagging
- Process tree building identified 72 suspicious parent chains
- MITRE pattern matching correctly identified 6 techniques

---

## How to Rebuild This Feature

If starting from scratch:

1. **Read the existing code**:
   - `app/ai_search.py` - MITRE patterns, attack analysis functions
   - `app/routes/triage_report.py` - IOC extraction, hunting functions
   - `app/search_utils.py` - OpenSearch query building

2. **Understand the IOC classification**:
   - SPECIFIC = low count, high value → auto-tag
   - BROAD = high count, use aggregations only

3. **Implement in order**:
   - `classify_iocs()` - split IOCs
   - `get_tagged_event_anchors()` - get analyst tags
   - `search_specific_iocs()` - find events to auto-tag
   - `discover_iocs_via_aggregations()` - discover without tagging
   - `auto_tag_anchor_events_batch()` - create purple tags
   - `search_time_window()` - context around anchors
   - `build_process_tree()` - parent/child relationships
   - `ai_triage_search()` - orchestrator

4. **Test on a large case** (10M+ events) to verify:
   - BROAD IOCs don't flood with auto-tags
   - Aggregations work for discovery
   - SPECIFIC IOCs get tagged correctly
   - Timeline events (~20-50) get auto-tagged
   - Total auto-tags are reasonable (typically 30-60 per case)
