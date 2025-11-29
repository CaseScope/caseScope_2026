# AI Triage Search Methodology

**Created**: 2025-11-29  
**Last Updated**: 2025-11-29  
**Purpose**: Document the methodology for automated attack chain analysis using IOC extraction, iterative hunting, process trees, time windows, and MITRE pattern matching.

---

## Overview

This document describes a comprehensive methodology for automated incident analysis that combines:
1. **Report IOC Extraction** - Parse EDR/MDR reports for initial IOCs using LLM + regex
2. **IOC Classification** - Split IOCs into SPECIFIC (auto-tag) vs BROAD (aggregation only)
3. **Iterative Snowball Hunting** - Discover new IOCs by searching existing ones
4. **Malware/Recon Hunting** - Search for malware indicators and reconnaissance patterns
5. **Time Window Analysis** - Capture surrounding context (±5 minutes)
6. **Process Tree Building** - Show parent/child relationships from EDR data
7. **MITRE ATT&CK Pattern Matching** - Identify attack techniques

The goal is to automate what analysts do manually: extract IOCs from a report, hunt for related activity, build a timeline, and identify attack techniques.

---

## The Problem We're Solving

When analyzing an incident, analysts typically:
1. Get a report mentioning IOCs (IPs, usernames, hostnames, malware names, commands)
2. Search for those IOCs in logs
3. Find events, then manually look at surrounding events
4. Try to understand the sequence: "What led to this? What happened after?"
5. Build a timeline of the attack
6. Identify MITRE ATT&CK techniques

This is time-consuming (hours) and requires expertise. We want to automate it.

---

## Critical Design Decision: IOC Classification

**Problem discovered during testing on Case 18 (10M+ events):**

Searching for usernames and hostnames can match 40K-400K+ events. Auto-tagging all of these would:
- Flood the timeline with tags
- Make the system unusable
- Hit OpenSearch's 10K result limit

**Solution: Split IOCs into two categories:**

### SPECIFIC IOCs (Auto-Tag All Matches)

These have LOW event counts and HIGH value:

| IOC Type | Example | Typical Count |
|----------|---------|---------------|
| `process` | statements546.exe | 1-10 |
| `hash` | SHA256 hash | 1-5 |
| `filepath` | C:\Users\Public\malware.dll | 1-10 |
| `command` | powershell -enc ... | 1-50 |
| `threat` | Trojan:MSIL/BadJoke | 1-20 |

**Action**: Search, get events, auto-tag with purple color.

### BROAD IOCs (Aggregation Only)

These have HIGH event counts:

| IOC Type | Example | Typical Count |
|----------|---------|---------------|
| `username` | jwilliams | 40,000+ |
| `hostname` | ATN81960 | 380,000+ |
| `ip` | 192.168.1.50 | 1,000-50,000 |
| `sid` | S-1-5-21-... | 10,000+ |

**Action**: Use aggregations to DISCOVER related IOCs, but do NOT auto-tag events.

### Why This Works

From Case 18 dry run:
```
SPECIFIC IOCs:
  - statements546.exe: 2 events → AUTO-TAG ✅
  - SHA256 hash: 1 event → AUTO-TAG ✅
  - Encoded PowerShell: 1 event → AUTO-TAG ✅
  TOTAL AUTO-TAGS: 4

BROAD IOCs:
  - jwilliams: 41,784 events → AGGREGATION ONLY (discovered: tabadmin, 4 hosts, 1 IP)
  - ATN81960: 381,151 events → AGGREGATION ONLY
  TOTAL AUTO-TAGS: 0 (discovery via aggregations instead)
```

---

## The 7-Phase Methodology

### Phase 1: Report IOC Extraction

**Goal**: Extract all IOCs from the analyst's report.

**Method**:
1. User pastes the EDR/MDR report (e.g., Huntress, Blackpoint, CrowdStrike)
2. Primary: Use LLM (Ollama) to extract structured IOCs
3. Fallback: Use refined regex patterns

**IOC Types Extracted**:
| Type | Examples | Database Treatment |
|------|----------|-------------------|
| IPs | 192.168.10.50, 45.143.146.80 | Active IOC |
| Hostnames | ATN68139, DEPCO-DC01 | Active IOC + System table |
| Usernames | tabadmin, jeanette, Pete | Active IOC |
| SIDs | S-1-5-21-xxx | **Inactive IOC** (too noisy) |
| Domains | willisterwinpress.net | Active IOC |
| File Hashes | SHA256, MD5 | Active IOC |
| File Paths | C:\Users\Public\Music\malware.dll | Active IOC |
| Commands | nltest /domain_trusts | **Inactive IOC** (reference) |
| Malware Names | Cobalt Strike, Trojan:MSIL/BadJoke | **Inactive IOC** (reference) |
| Tools | PSEXEC, ScreenConnect | **Inactive IOC** (reference) |

**Regex Patterns Used** (in `triage_report.py`):
```python
# IPs (IPv4)
r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

# Hostnames (various formats)
r'(?:host|machine|endpoint|computer)[:\s]+["\']?([A-Za-z0-9][-A-Za-z0-9]{2,14})["\']?'
r'\(Host name:\s*([A-Za-z0-9][-A-Za-z0-9]{2,14})\)'

# Usernames (quoted, before SIDs, etc.)
r'user\s+["\']([^"\']+)["\']'
r'account\s+["\']([^"\']+)["\']'
r"'([A-Za-z][A-Za-z0-9_]{2,19})'\s*\(S-1-5-"

# SIDs
r'\bS-1-5-21-\d+-\d+-\d+-\d+\b'

# Full command lines
r'(?:powershell\.exe|cmd\.exe)[^\n]*(?:-[Ee](?:nc|ncodedcommand)\s+[A-Za-z0-9+/=]+|/c\s+[^\n]+)'
```

**Filtering Rules**:
- Hostnames must contain at least one letter
- Hostnames cannot be common words (NOT_HOSTNAMES blocklist)
- Usernames cannot be generic terms (SYSTEM, Administrator, etc.)
- Machine accounts (ending in $) are filtered out

### Phase 2: IOC Classification

**Goal**: Split extracted IOCs into SPECIFIC (auto-tag) vs BROAD (aggregation only).

**Method**:
```python
def classify_iocs(iocs):
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

### Phase 3: Iterative Snowball Hunting

**Goal**: Discover new IOCs by searching for existing ones.

**Method**:
```
Round 1:
  For each IP from report:
    → Search all file types (EVTX, EDR, JSON, CSV, IIS)
    → Extract: new hostnames, new usernames
    
  For each hostname from report:
    → Search by computer_name/host.hostname fields
    → Extract: new IPs, new usernames

Round 2:
  For each NEW hostname from Round 1:
    → Search again
    → Extract: new IPs, new usernames
    
  Repeat until no new items discovered (or max 5 rounds)
```

**Search Function Used**: `build_search_query()` from `search_utils.py`
```python
query_dsl = build_search_query(
    search_text=ip_address,
    file_types=['EVTX', 'EDR', 'JSON', 'CSV', 'IIS']
)
results = execute_search(query_dsl, case_id)
```

**Data Extraction by File Type**:

| File Type | Where IOCs Live | Extraction Method |
|-----------|-----------------|-------------------|
| EVTX | `search_blob` | Regex patterns |
| EDR/JSON | Nested fields | Direct field access |
| CSV | `search_blob` | Regex patterns |
| IIS | `search_blob` | Regex patterns |

**EDR Nested Fields for Extraction**:
```python
# Hostnames
host.get('hostname') or host.get('name')
process.get('user', {}).get('domain')  # Sometimes contains hostname

# IPs
process.get('user_logon', {}).get('ip')
source.get('ip')
destination.get('ip')

# Usernames
process.get('user', {}).get('name')
# Filter out: machine accounts ($), SYSTEM, generic terms
```

### Phase 4: SPECIFIC IOC Search + Auto-Tagging

**Goal**: Find events matching SPECIFIC IOCs and auto-tag them.

**Method**:
```python
for ioc_type, values in specific_iocs.items():
    for ioc_value in values:
        query_dsl = build_search_query(search_text=ioc_value)
        count = opensearch_client.count(index=index_name, body={"query": query_dsl.get("query", {})})
        
        if count > 0:
            # Fetch events
            response = opensearch_client.search(index=index_name, body=query_dsl, size=1000)
            
            # Auto-tag each event
            for hit in response['hits']['hits']:
                tag = TimelineTag(
                    case_id=case_id,
                    event_id=hit['_id'],
                    tag_color='purple',  # AI-discovered = purple
                    notes=f"[AI Triage Auto-Tagged]\nIOC: {ioc_type}={ioc_value}"
                )
```

### Phase 5: BROAD IOC Discovery via Aggregations

**Goal**: Discover related IOCs from BROAD IOC searches WITHOUT auto-tagging.

**Method**:
```python
agg_query = {
    "size": 0,  # Don't return events, just aggregations
    "query": build_search_query(search_text=username).get("query", {}),
    "aggs": {
        "unique_hosts": {"terms": {"field": "host.hostname.keyword", "size": 50}},
        "unique_users": {"terms": {"field": "process.user.name.keyword", "size": 50}},
        "unique_ips": {"terms": {"field": "host.ip.keyword", "size": 50}}
    }
}

response = opensearch_client.search(index=index_name, body=agg_query)

# Extract discovered values from aggregations
for bucket in response['aggregations']['unique_hosts']['buckets']:
    discovered_hostnames.add(bucket['key'])
```

**Why Aggregations?**
- Returns unique values without fetching all events
- Works even when there are 400K+ matches
- Fast and efficient
- Provides discovery without flooding the timeline

### Phase 6: Time Window Analysis

**Goal**: Capture the context around each anchor event.

**Method**:
1. For each anchor event (IOC match or analyst-tagged), get its timestamp
2. Search for ALL events in a ±5 minute window
3. This captures:
   - What happened before (how did we get here?)
   - What happened after (what did the attacker do next?)

**Why ±5 minutes?**
- Attack chains happen in sequences (recon → exploit → persist)
- 5 minutes is enough to capture a "burst" of attacker activity
- Not so long that we get too much noise

**OpenSearch Query**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"normalized_computer.keyword": "HOSTNAME"}},
        {"range": {"@timestamp": {"gte": "2025-11-01T01:58:00Z", "lte": "2025-11-01T02:08:00Z"}}}
      ]
    }
  },
  "sort": [{"@timestamp": "asc"}],
  "size": 500
}
```

### Phase 7: Process Tree Building

**Goal**: Understand the relationships between processes.

**Method** (for EDR data):
The EDR NDJSON files contain rich process hierarchy data:

```json
{
  "process": {
    "name": "nltest.exe",
    "pid": "11908",
    "command_line": "nltest /domain_trusts /all_trusts",
    "parent": {
      "name": "cmd.exe",
      "pid": "13440",
      "command_line": "C:\\Windows\\System32\\cmd.exe",
      "parent": {
        "name": "Explorer.EXE",
        "pid": "6932",
        "command_line": "C:\\Windows\\Explorer.EXE"
      }
    }
  }
}
```

**Key Fields**:
| Field | Purpose |
|-------|---------|
| `process.pid` | Process ID |
| `process.name` | Process name |
| `process.command_line` | Full command |
| `process.parent.pid` | Parent PID (for linking) |
| `process.parent.name` | Parent name |
| `process.parent.parent.*` | Grandparent (2 levels deep!) |
| `process.entity_id` | Unique GUID for correlation |
| `process.user.name` / `process.user.domain` | Who ran it |
| `process.user_logon.type` | How they logged in (10 = RDP) |
| `process.working_directory` | Where they ran it from |

**Building the Tree**:
1. Take an anchor event
2. Extract its parent PID
3. Search for other events with the same parent PID (siblings)
4. Search for events where this process is the parent (children)
5. Repeat recursively

**Example Tree (Case 17)**:
```
Explorer.EXE (PID: 6932) - User: JJLAW\Tracy
└── cmd.exe (PID: 13440)
    ├── whoami.exe /all
    ├── nltest.exe /domain_trusts
    ├── nltest.exe /dclist:
    ├── PING.EXE JELLY-DC01
    └── ipconfig.exe
```

### Phase 8: MITRE ATT&CK Pattern Matching

**Goal**: Identify what attack techniques are being used.

**Patterns Defined**:
```python
MITRE_PATTERNS = {
    'T1033': {  # System Owner/User Discovery
        'name': 'System Owner/User Discovery',
        'processes': ['whoami.exe', 'quser.exe'],
        'indicators': ['whoami', 'query user', '/all']
    },
    'T1482': {  # Domain Trust Discovery
        'name': 'Domain Trust Discovery',
        'processes': ['nltest.exe'],
        'indicators': ['domain_trusts', 'nltest', '/all_trusts']
    },
    'T1018': {  # Remote System Discovery
        'name': 'Remote System Discovery',
        'processes': ['nltest.exe', 'ping.exe', 'nslookup.exe'],
        'indicators': ['dclist', 'ping', 'net view']
    },
    'T1016': {  # System Network Configuration Discovery
        'name': 'System Network Config Discovery',
        'processes': ['ipconfig.exe', 'netsh.exe'],
        'indicators': ['ipconfig', 'netsh', 'route print']
    },
    'T1218.011': {  # Rundll32
        'name': 'Rundll32 Execution',
        'processes': ['rundll32.exe'],
        'indicators': ['rundll32', '.dll,']
    },
    'T1219': {  # Remote Access Software
        'name': 'Remote Access Software',
        'processes': ['ScreenConnect.ClientService.exe', 'ScreenConnect.WindowsClient.exe'],
        'indicators': ['ScreenConnect', 'AnyDesk', 'TeamViewer']
    },
    'T1566.002': {  # Phishing: Spearphishing Link
        'name': 'Phishing: Spearphishing Link',
        'indicators': ['pages.dev', 'cloudflare', 'download']
    },
    'T1049': {  # System Network Connections Discovery
        'name': 'System Network Connections Discovery',
        'processes': ['netstat.exe'],
        'indicators': ['netstat', '-tnoa']
    }
}
```

**Matching Logic**:
1. For each event in the time window
2. Check if process name matches any pattern's processes
3. Check if command line contains any pattern's indicators
4. If match, tag the event with the MITRE technique ID

---

## Test Cases

### Case 18 (JHD) - Phishing + Malware (10M+ Events)

**Report Summary**: User jwilliams clicked phishing link, downloaded statements546.exe malware.

**IOCs Extracted**:
- SPECIFIC: statements546.exe, SHA256 hash, C:\Users\Jwilliams\Downloads\statements546.exe
- BROAD: jwilliams (username), ATN81960 (hostname), SID

**Auto-Tag Results**:
```
SPECIFIC IOCs (auto-tagged):
  - statements546.exe: 2 events ✅
  - SHA256 hash: 1 event ✅
  - Encoded PowerShell: 1 event ✅
  TOTAL: 4 events auto-tagged

BROAD IOCs (aggregation only):
  - jwilliams: 41,784 events → discovered: tabadmin, 4 hosts, 1 IP
  - ATN81960: 381,151 events → discovered via aggregations
  TOTAL: 0 events auto-tagged (used for discovery only)
```

**Key Learning**: This case proved the IOC classification strategy works for large cases.

### Case 17 (JELLY) - RDP Compromise + Hands-on-Keyboard

**Report Summary**: User Tracy logged in via RDP from malicious IP, opened documents, ran reconnaissance commands, executed malware via rundll32.

**IOCs Extracted**:
- Username: Tracy
- External IP: 181.214.165.70
- Malicious workstation: DESKTOP-VSU85FT
- Host: JELLY-RDS01
- Malware: WQTLib.dll

**Hunting Results**:
```
Round 1 (IP 181.214.165.70): Found JELLY-RDS01, Tracy
Round 2 (hostname JELLY-RDS01): Confirmed Tracy, found recon activity
```

**Process Tree Built**:
```
Explorer.EXE (PID: 6932) - User: JJLAW\Tracy
└── WORDPAD.EXE - Document access
└── cmd.exe (PID: 13440)
    ├── whoami.exe /all [T1033]
    ├── nltest.exe /domain_trusts [T1482]
    ├── nltest.exe /dclist: [T1018]
    ├── PING.EXE JELLY-DC01 [T1018]
    └── ipconfig.exe [T1016]
└── rundll32.exe WQTLib.dll,init [T1218.011] ← MALWARE
```

**Attack Timeline**:
```
01:41:19 - RDP login from 181.214.165.70 (DESKTOP-VSU85FT)
02:00:42 - Document access (4 legal files)
02:03:01 - whoami /all
02:03:16 - nltest /domain_trusts
02:03:22 - nltest /dclist:
02:03:31 - ping JELLY-DC01
02:03:36 - ipconfig
02:11:14 - rundll32 WQTLib.dll,init ← MALWARE EXECUTION
```

### Case 11 (DEPCO) - Lateral Movement + Cobalt Strike

**Report Summary**: Compromised users tabadmin and jeanette, lateral movement via PSEXEC, Cobalt Strike deployment, Defender evasion.

**IOCs Extracted**:
- Usernames: tabadmin, jeanette
- SIDs: S-1-5-21-3426696237-... (set inactive)
- IP: 192.168.10.50
- Hostnames: DEPCO-DC01, DESKTOP-K1PKL6P, ATN79684, accounting-DAFF0JD
- Malware: Cobalt Strike

**Hunting Results**:
- Found PSEXEC execution
- Found Defender events (DisableRealtimeMonitoring)
- Found Cobalt Strike loader PowerShell

**Attack Pattern**: Lateral movement chain across multiple hosts.

### Case 8 (CM) - VPN Compromise + Domain Enumeration

**Report Summary**: User tabadmin compromised via gateway, authenticated from suspicious workstation, ran domain enumeration, used Advanced IP Scanner.

**IOCs Extracted**:
- Username: tabadmin
- IP: 192.168.0.254, 172.16.10.25, 172.16.10.26
- Hostnames: CM-DC01, CM-VMHOST, WIN-HU67JDG9MF1
- Gateway: 96.78.213.49:60443 (SonicWall)
- Tools: Advanced IP Scanner, nltest

**Hunting Results**:
- Found nltest /domain_trusts commands
- Found Advanced IP Scanner execution
- Found file access to AdUsers.txt, AdComp.txt

**Key Learning**: nltest commands and their executables should be captured as IOCs.

### Case 22 (SERVU) - Phishing + Malicious RMM

**Report Summary**: User Pete clicked phishing link, downloaded malware (modestparty.exe), malicious ScreenConnect installed, Defender detected Trojan:MSIL/BadJoke.

**IOCs Extracted**:
```
NETWORK IOCs:
- 45.143.146.80 (C2 IP - Krixe Pte. Ltd.)
- relay.willisterwinpress.net (C2 domain)
- server.willisterwinpress.net (payload delivery)
- 3a62a61d.newmodestparty.pages.dev (phishing page)
- screenconnect.patroldog.com (legitimate SC - for comparison)

FILE IOCs:
- modestparty.exe / modestparty (1).exe (initial dropper)
- Hide-Mouse-on-blankscreen.exe (mouse hiding tool)
- ScreenConnect.ClientSetup.msi (malicious RMM installer)
- C:\Users\Pete\Downloads\modestparty.exe
- C:\Users\Pete\Documents\ScreenConnect\Temp\Hide-Mouse-on-blankscreen.exe

IDENTITY IOCs:
- Username: Pete (compromised user)
- Hostname: ATN68139 (compromised host)
- Internal IP: 192.168.16.100
- ScreenConnect ID: 1132a4b096a44934 (malicious instance)
- ScreenConnect ID: 24a22b9fc261d141 (legitimate instance)

MALWARE:
- Trojan:MSIL/BadJoke!MTB (Defender detection)
- GoTo Resolver RMM (initial payload)
- ScreenConnect (abused for C2)
```

**Process Tree Built**:
```
ScreenConnect.ClientSetup.exe (installer)
└── msiexec.exe (MSI installation)
    └── ScreenConnect.WindowsClient.exe (SYSTEM)
        └── ScreenConnect.WindowsClient.exe (Pete session)
            └── cmd.exe
                ├── NETSTAT.EXE -tnoa -p tcp [T1049]
                ├── ipconfig.exe /all [T1016]
                ├── auditpol.exe [T1562 - Defense Evasion]
                └── Hide-Mouse-on-blankscreen.exe [T1564.003]
```

**Attack Timeline**:
```
PHASE 1: Initial Compromise (2025-10-29 - NOT IN LOGS)
   └── User Pete received phishing email
       └── Clicked: hxxps://3a62a61d.newmodestparty.pages.dev/
       └── Downloaded: modestparty.exe
       └── Executed: GoTo Resolver RMM deployed
       └── Installed: Malicious ScreenConnect (ID: 1132a4b096a44934)
       └── C2: relay.willisterwinpress.net:8041 (45.143.146.80)

PHASE 2: Dormant Period (2025-10-29 to 2025-11-19)
   └── Malicious ScreenConnect installed, waiting for attacker

PHASE 3: Active Attack (2025-11-19 03:09 - 03:14 UTC)
   03:09:47 | ScreenConnect.ClientSetup.exe started
   03:09:50 | msiexec.exe installing ScreenConnect
   03:10:20 | ScreenConnect.WindowsClient.exe launched (SYSTEM)
   03:11:02 | Defender: Trojan:MSIL/BadJoke!MTB detected
   03:11:09 | Defender: Malware suspended
   03:11:11 | NETSTAT.EXE -tnoa -p tcp (recon)
   03:11:13 | ipconfig.exe /all (recon)
   03:11:37 | ipconfig.exe /all (repeated)
   03:11:40 | NETSTAT.EXE -tnoa -p tcp (repeated)
   03:11:49 | ScreenConnect.WindowsClient.exe (Pete's session) [IOC MATCH]
   ~03:14:00 | Hide-Mouse-on-blankscreen.exe (from ScreenConnect Temp)

PHASE 4: Response
   └── Host isolated by Blackpoint SOC
```

**MITRE ATT&CK Techniques**:
- T1566.002 - Phishing: Spearphishing Link
- T1219 - Remote Access Software (ScreenConnect)
- T1016 - System Network Configuration Discovery (ipconfig)
- T1049 - System Network Connections Discovery (netstat)
- T1564.003 - Hide Artifacts: Hidden Window (Hide-Mouse tool)

**Key Insight**: The initial infection (2025-10-29) was 3 weeks before the active attack (2025-11-19). EDR data only went back to 2025-11-11, so the initial dropper execution wasn't in logs - but the report provided the context.

---

## Attack Types This Works Well For

| Attack Type | Effectiveness | Why |
|-------------|---------------|-----|
| **VPN/RDP Compromise** | ⭐⭐⭐⭐⭐ | Process trees show post-auth activity, logon type 10 = RDP |
| **Hands-on-keyboard** | ⭐⭐⭐⭐⭐ | Recon commands (whoami, nltest) are distinctive |
| **Malware Execution** | ⭐⭐⭐⭐ | rundll32, regsvr32, suspicious DLLs visible |
| **Phishing/Malicious Link** | ⭐⭐⭐⭐ | Browser → Download → Execution chain visible if in logs |
| **Malicious RMM** | ⭐⭐⭐⭐⭐ | ScreenConnect, AnyDesk process trees very clear |
| **Lateral Movement** | ⭐⭐⭐⭐ | PSEXEC, RDP events trackable |
| **Defender Evasion** | ⭐⭐⭐⭐ | Set-MpPreference, DisableRealtimeMonitoring visible |
| **Data Exfiltration** | ⭐⭐⭐ | File access visible, but hard to prove actual exfil |

---

## Implementation Details

### Files in CaseScope

| File | Purpose |
|------|---------|
| `/opt/casescope/app/routes/triage_report.py` | Main triage logic, IOC extraction, hunting |
| `/opt/casescope/app/search_utils.py` | `build_search_query()`, `execute_search()` |
| `/opt/casescope/app/ai_search.py` | MITRE patterns, DFIR query expansion |
| `/opt/casescope/app/templates/search_events.html` | Frontend modal for triage |

### Key Functions

**`extract_iocs_with_llm(report_text)`**: Uses Ollama to extract structured IOCs
**`extract_iocs_with_regex(report_text)`**: Fallback regex extraction
**`classify_iocs(iocs)`**: Split into SPECIFIC vs BROAD
**`process_triage_report()`**: Main route that orchestrates all phases
**`build_search_query()`**: Builds OpenSearch queries with proper field handling
**`execute_search()`**: Executes queries and returns results

### OpenSearch Queries

**Search by IOC (using existing search infrastructure)**:
```python
query_dsl = build_search_query(
    search_text="192.168.10.50",
    file_types=['EVTX', 'EDR', 'JSON', 'CSV', 'IIS']
)
```

**Aggregation for discovery (BROAD IOCs)**:
```json
{
  "size": 0,
  "query": {"query_string": {"query": "jwilliams"}},
  "aggs": {
    "unique_hosts": {"terms": {"field": "host.hostname.keyword", "size": 50}},
    "unique_users": {"terms": {"field": "process.user.name.keyword", "size": 50}},
    "unique_ips": {"terms": {"field": "host.ip.keyword", "size": 50}}
  }
}
```

**Time window search (direct OpenSearch)**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"normalized_computer.keyword": "ATN68139"}},
        {"range": {"@timestamp": {"gte": "2025-11-19T03:00:00Z", "lte": "2025-11-19T03:20:00Z"}}}
      ]
    }
  },
  "sort": [{"@timestamp": "asc"}],
  "size": 500
}
```

**Find siblings (same parent PID)**:
```json
{
  "query": {
    "term": {"process.parent.pid": "13440"}
  },
  "sort": [{"@timestamp": "asc"}]
}
```

---

## How to Rebuild This (Step by Step)

If starting from scratch:

1. **Start with a known-bad case** (like Case 17 with the Huntress report)

2. **Extract IOCs from the report** - Use LLM or regex to get IPs, hostnames, usernames, hashes, paths

3. **Classify IOCs**:
   - SPECIFIC (processes, hashes, paths, commands, threats) → will auto-tag
   - BROAD (usernames, hostnames, IPs, SIDs) → aggregation only

4. **Search SPECIFIC IOCs** - Use `build_search_query()` to find events, auto-tag matches

5. **Aggregate BROAD IOCs** - Use aggregations to discover related IOCs without tagging

6. **Snowball discovery** - For each result, extract new IOCs and search again

7. **If malware mentioned** - Search for malware indicators (PSEXEC, Cobalt, Defender events)

8. **Pick anchor events** - Events that match SPECIFIC IOCs + analyst-tagged events

9. **Expand time window** - Search ±5 minutes around each anchor

10. **Build process trees** - Use parent.pid to link events

11. **Apply MITRE patterns** - Match processes and commands to techniques

12. **Build the narrative** - Sort by time, group by session, identify phases

---

## Future Enhancements

1. **"AI Search" Button** - User enters date, system runs full methodology automatically
2. **Session Correlation** - Link events by LogonID, not just parent PID
3. **Cross-host Correlation** - Track lateral movement between machines
4. **Confidence Scoring** - Weight patterns by severity
5. **LLM Narrative Generation** - Use AI to write the attack summary
6. **Baseline Comparison** - Flag activity unusual for this user/host
7. **Automatic Timeline Generation** - Create visual timeline from events

---

## Summary

The key insight is that **attacks are chains, not single events**. By:
1. Extracting IOCs from reports (LLM + regex)
2. Classifying IOCs (SPECIFIC = auto-tag, BROAD = aggregation)
3. Hunting iteratively (snowball discovery)
4. Looking at surrounding time (±5 minutes)
5. Building process trees (parent/child from EDR)
6. Matching known patterns (MITRE ATT&CK)

...we can automatically reconstruct what an analyst would manually piece together.

The EDR data structure with embedded parent/grandparent information makes process tree building particularly effective. The combination of the triage extraction with time-window analysis catches both the "what" (IOCs) and the "how" (attack chain).

**Critical for large cases (10M+ events)**: Use aggregations for BROAD IOCs instead of auto-tagging all matches.
