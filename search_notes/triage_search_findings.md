# Triage Report IOC Discovery System

## Overview

A multi-phase automated IOC discovery system that:
1. Extracts IOCs from analyst-pasted EDR/MDR reports
2. Classifies IOCs as SPECIFIC (auto-tag) vs BROAD (aggregation only)
3. Hunts those IOCs to discover NEW related IOCs
4. If malware is indicated, hunts malware indicators for additional IOCs
5. Extracts recon commands and tools as IOCs
6. Adds all discovered IOCs to the database with appropriate types

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     ANALYST PASTES REPORT                           │
│              (Huntress, CrowdStrike, Sentinel, etc.)                │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    PHASE 1: AI EXTRACTION                           │
│  Extract IOCs from report text using LLM + regex fallback           │
│  - IPs, Hostnames, Usernames, SIDs, Hashes, Paths, Commands         │
│  - Malware names, Tool names, Timestamps                            │
│  - Determine: MALWARE = TRUE/FALSE                                  │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    PHASE 2: IOC CLASSIFICATION                      │
│  Split IOCs into SPECIFIC vs BROAD categories                       │
│  - SPECIFIC: processes, hashes, paths, commands, threats            │
│    → Will auto-tag matching events                                  │
│  - BROAD: usernames, hostnames, IPs, SIDs                          │
│    → Use aggregations for discovery only (no auto-tag)              │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 PHASE 3: STANDARD IOC HUNTING                       │
│  For each extracted IOC, search OpenSearch and extract NEW IOCs     │
│  - SPECIFIC IOCs → search, get events, auto-tag with purple color   │
│  - BROAD IOCs → use aggregations to discover related IOCs           │
│  Iterate until no new discoveries (or max iterations)               │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│              PHASE 4: MALWARE/RECON HUNTING                         │
│  Search for malware and recon indicators, extract IOCs              │
│  - Malware: filenames, paths, Defender threats                      │
│  - Recon: commands (nltest, net group, whoami), tool executables    │
│  - LOLBins: legitimate tools used maliciously                       │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    PHASE 5: ADD TO DATABASE                         │
│  Add all discovered IOCs with appropriate types and status          │
│  - Active IOCs: hunted by IOC hunting engine                        │
│  - Inactive IOCs: not hunted (SIDs, commands - too noisy/specific)  │
│  - Ignored IOCs: informational only, never hunted                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Known Good Exclusions (v1.38.0)

### The Problem

Many events matching suspicious patterns are actually **legitimate**:
- RMM tools (LabTech, Datto, Kaseya) running health checks (`whoami`, `systeminfo`)
- Analyst tools (ScreenConnect with known-good session IDs)
- Internal IP ranges (office networks, VPN pools)

Without exclusions, we'd auto-tag thousands of false positives.

### Solution: Two-Layer Exclusion

#### Layer 1: "Hide Known Good" Button

On the search page, analysts can click **"Hide Known Good"** to:
1. Scan ALL events in the case
2. Match against configured exclusion patterns
3. Set `is_hidden=true` on matching events (with `hidden_reason='known_good_exclusion'`)

**Benefits:**
- Run once after case setup to pre-filter noise
- Hidden events excluded from search by default
- Reduces query load on subsequent searches

#### Layer 2: Real-Time Exclusion Check

During AI Triage Search, events are checked against exclusion rules before auto-tagging:
- If `is_hidden=true` → skip (already filtered)
- If parent process matches RMM pattern → skip
- If remote tool with known-good session ID → skip
- If source IP in known-good range → skip

### Configuration: System Tools Settings

Administrators configure exclusions at **Settings → System Tools**:

| Category | Examples | Matching Logic |
|----------|----------|----------------|
| **RMM Tools** | LTSVC.exe, AEMAgent.exe, AgentMon.exe | Parent process name matches |
| **Remote Tools** | ScreenConnect with session IDs | Tool + known-good ID in command line |
| **Known-Good IPs** | 192.168.1.0/24, 10.0.0.0/8 | Source IP in CIDR range |

### Predefined RMM Tools

| Tool | Executable Patterns |
|------|---------------------|
| ConnectWise Automate (LabTech) | LTSVC.exe, LTSvcMon.exe, LTTray.exe |
| Datto RMM | AEMAgent.exe, CagService.exe |
| Kaseya VSA | AgentMon.exe, KaseyaD.exe |
| NinjaRMM | NinjaRMMAgent.exe |
| Syncro | SyncroLive.exe |
| Atera | AteraAgent.exe |
| N-able | BASupSrvc*.exe |

### Code Locations

- **Settings UI**: `app/templates/system_tools.html`
- **Routes**: `app/routes/system_tools.py`
- **Hide Button**: `app/templates/search_events.html` (line ~160)
- **API Endpoint**: `/settings/system-tools/api/exclusions`

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

| IOC Type | Example | Typical Count | Action |
|----------|---------|---------------|--------|
| `process` | statements546.exe | 1-10 | AUTO-TAG |
| `hash` | SHA256 hash | 1-5 | AUTO-TAG |
| `filepath` | C:\Users\Public\malware.dll | 1-10 | AUTO-TAG |
| `command` | powershell -enc ... | 1-50 | AUTO-TAG |
| `threat` | Trojan:MSIL/BadJoke | 1-20 | AUTO-TAG |

### BROAD IOCs (Aggregation Only)

These have HIGH event counts:

| IOC Type | Example | Typical Count | Action |
|----------|---------|---------------|--------|
| `username` | jwilliams | 40,000+ | AGGREGATION |
| `hostname` | ATN81960 | 380,000+ | AGGREGATION |
| `ip` | 192.168.1.50 | 1,000-50,000 | AGGREGATION |
| `sid` | S-1-5-21-... | 10,000+ | AGGREGATION |

### Why This Works (Case 18 Example)

```
SPECIFIC IOCs:
  - statements546.exe: 2 events → AUTO-TAG ✅
  - SHA256 hash: 1 event → AUTO-TAG ✅
  - Encoded PowerShell: 1 event → AUTO-TAG ✅
  TOTAL AUTO-TAGS: 4

BROAD IOCs:
  - jwilliams: 41,784 events → AGGREGATION ONLY
    → Discovered: tabadmin (user), 4 hosts, 1 IP
  - ATN81960: 381,151 events → AGGREGATION ONLY
  TOTAL AUTO-TAGS: 0 (used for discovery instead)
```

---

## IOC Types

### Standard IOC Types (Huntable)
| Type | Description | Example |
|------|-------------|---------|
| `ip` | IP address | 192.168.10.50, 181.214.165.70, 96.78.213.49 |
| `hostname` | Computer/host name | DEPCO-DC01, JELLY-RDS01, CM-DC01 |
| `username` | User account | tabadmin, JJLAW\Tracy, CM\jose |
| `hash` | File hash (MD5/SHA1/SHA256) | a1b2c3d4... |
| `filepath` | Full file path | C:\Users\Public\Music\WQTLib.dll |
| `filename` | Executable name | PSEXESVC.exe, WQTLib.dll, nltest.exe |
| `domain` | Domain/FQDN | jjlaw.local |
| `url` | Full URL | http://evil.com/beacon |
| `registry` | Registry key | HKLM\SOFTWARE\... |
| `command` | Command line | powershell -enc ..., nltest /domain_trusts |
| `user_sid` | Windows SID | S-1-5-21-... |

### Special IOC Types (Informational)
| Type | Description | Hunted? |
|------|-------------|---------|
| `threat` | Defender threat name | No (informational) |
| `malware` | Malware family name | No (informational) |
| `tool` | Attack tool name | No (informational) |
| `ignored` | Any IOC marked as noise | No (never hunted) |

### IOC Default Status by Type
| Type | Default Status | Reason |
|------|----------------|--------|
| `ip`, `hostname`, `username` | Active | Primary hunt targets |
| `hash`, `filepath`, `filename`, `domain`, `url` | Active | Huntable indicators |
| `user_sid` | Inactive | Too noisy, many matches |
| `command` | Inactive | Too specific, use for context |
| `registry` | Inactive | Requires exact match |
| `threat`, `malware`, `tool` | Inactive | Informational only |

---

## Phase 1: AI Extraction

### LLM Prompt Structure
```
Extract the following from this investigative report:

1. IOCs:
   - IPs (IPv4/IPv6) - both internal and external
   - Hostnames/computer names
   - Usernames (including domain\user format)
   - User SIDs (S-1-5-21-...)
   - File hashes (MD5, SHA1, SHA256)
   - File paths (C:\path\to\file.exe)
   - Process/executable names
   - Domains/FQDNs
   - URLs
   - Registry keys
   - Commands (especially recon commands, encoded PowerShell)

2. Malware Analysis:
   - Is malware mentioned? (TRUE/FALSE)
   - Malware family names (Cobalt Strike, Emotet, etc.)
   - Attack tools (PSEXEC, Mimikatz, Advanced IP Scanner, etc.)
   - Initial access vector (VPN, phishing, RDP, SonicWall, etc.)

3. Recon Activity:
   - Domain enumeration commands (nltest, net group, etc.)
   - Network enumeration tools (Advanced IP Scanner, etc.)
   - Credential access attempts

4. Timeline:
   - Key timestamps mentioned
   - Attack sequence

Return as JSON.
```

### Regex Fallback Patterns
```python
# IPs
ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

# Hashes
sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
md5_pattern = r'\b[a-fA-F0-9]{32}\b'

# SIDs
sid_pattern = r'S-1-5-21-[\d-]+'

# Hostnames (from context)
hostname_patterns = [
    r'host\s*["\']([^"\']+)["\']',
    r'machine\s*["\']([^"\']+)["\']',
    r'endpoint\s+([A-Za-z0-9\-_]+)',
    r'Host\s*name[:\s]+([A-Za-z0-9\-_]+)',
]

# Usernames (from context)
username_patterns = [
    r'user\s*["\']([^"\']+)["\']',
    r'account\s*["\']([^"\']+)["\']',
    r'compromised\s+user\s*["\']([^"\']+)["\']',
]

# Paths
path_pattern = r'[A-Za-z]:\\(?:[^\s\\/:*?"<>|]+\\)+[^\s\\/:*?"<>|]*'

# Commands
encoded_ps_pattern = r'powershell[^\r\n]*-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]+'
rundll_pattern = r'rundll32[^\r\n]+'
nltest_pattern = r'nltest[^\r\n]+'
net_pattern = r'net\s+(?:group|user|localgroup)[^\r\n]+'
```

---

## Phase 2: IOC Classification

**Split extracted IOCs before hunting:**

```python
def classify_iocs(iocs):
    """Split IOCs into SPECIFIC (auto-tag) vs BROAD (aggregation only)."""
    
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

---

## Phase 3: Standard IOC Hunting

### Search Method
**ALWAYS use `build_search_query` and `execute_search` from `search_utils.py`**

```python
from search_utils import build_search_query, execute_search

def search_ioc(opensearch_client, case_id, search_term, time_start=None, time_end=None):
    query_dsl = build_search_query(
        search_text=search_term,
        filter_type="all",
        date_range="custom" if time_start else "all",
        custom_date_start=time_start,
        custom_date_end=time_end,
        file_types=['EVTX', 'EDR', 'JSON', 'CSV', 'IIS'],
        tagged_event_ids=None,
        latest_event_timestamp=None,
        hidden_filter="hide"
    )
    results, total, aggs = execute_search(
        opensearch_client,
        f"case_{case_id}",
        query_dsl,
        page=1,
        per_page=500
    )
    return results, total
```

### Aggregation for BROAD IOCs

```python
def discover_via_aggregations(opensearch_client, case_id, broad_iocs):
    """Use aggregations to discover related IOCs without fetching all events."""
    
    discovered = {'hostnames': set(), 'usernames': set(), 'ips': set()}
    
    for ioc_type, values in broad_iocs.items():
        for ioc_value in values:
            agg_query = {
                "size": 0,  # Don't return events
                "query": build_search_query(search_text=ioc_value).get("query", {}),
                "aggs": {
                    "unique_hosts": {"terms": {"field": "host.hostname.keyword", "size": 50}},
                    "unique_users": {"terms": {"field": "process.user.name.keyword", "size": 50}},
                    "unique_ips": {"terms": {"field": "host.ip.keyword", "size": 50}}
                }
            }
            
            response = opensearch_client.search(index=f"case_{case_id}", body=agg_query)
            
            # Extract from aggregations
            for bucket in response['aggregations']['unique_hosts']['buckets']:
                discovered['hostnames'].add(bucket['key'])
            # ... etc
    
    return discovered
```

### Extraction Logic

```python
NOISE_USERS = {
    'system', 'network service', 'local service', 'anonymous logon',
    'window manager', 'dwm-1', 'dwm-2', 'umfd-0', 'umfd-1', '-', 'n/a', ''
}

def is_machine_account(username):
    return username.endswith('$') if username else False

def extract_from_results(results):
    ips = set()
    hostnames = set()
    usernames = set()
    
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    
    for hit in results:
        src = hit['_source']
        blob = src.get('search_blob', '')
        
        # === IPs from blob ===
        for ip in re.findall(ip_pattern, blob):
            if not ip.startswith(('127.', '0.', '255.')):
                ips.add(ip)
        
        # === EVTX: computer_name field ===
        computer = src.get('computer_name')
        if computer and computer not in ['-', 'N/A', None, '']:
            hostnames.add(computer.upper())
        
        # === EVTX: User patterns from blob ===
        for match in re.findall(r'(?:TargetUserName|SubjectUserName|AccountName)[:\s]+([A-Za-z0-9_\-\.]+)', blob):
            if match.lower() not in NOISE_USERS and not is_machine_account(match):
                usernames.add(match)
        
        # === EVTX: Workstation from blob ===
        for ws in re.findall(r'WorkstationName[:\s]+([A-Za-z0-9\-]+)', blob):
            if ws and ws != '-' and len(ws) > 2:
                hostnames.add(ws.upper())
        
        # === EDR: Nested host field ===
        host = src.get('host', {})
        if isinstance(host, dict):
            h = host.get('hostname') or host.get('name')
            if h:
                hostnames.add(h.upper())
            host_ip = host.get('ip')
            if host_ip:
                if isinstance(host_ip, list):
                    ips.update([ip for ip in host_ip if not ip.startswith('127.')])
                elif isinstance(host_ip, str) and not host_ip.startswith('127.'):
                    ips.add(host_ip)
        
        # === EDR: Nested process.user and process.user_logon ===
        process = src.get('process', {})
        if isinstance(process, dict):
            proc_user = process.get('user', {})
            if isinstance(proc_user, dict):
                name = proc_user.get('name')
                domain = proc_user.get('domain', '')
                if name and name.lower() not in NOISE_USERS and not is_machine_account(name):
                    usernames.add(f"{domain}\\{name}" if domain else name)
            
            logon = process.get('user_logon', {})
            if isinstance(logon, dict):
                name = logon.get('username')
                domain = logon.get('domain', '')
                ws = logon.get('workstation')
                logon_ip = logon.get('ip')
                if name and name.lower() not in NOISE_USERS and not is_machine_account(name):
                    usernames.add(f"{domain}\\{name}" if domain else name)
                if ws:
                    hostnames.add(ws.upper())
                if logon_ip and not logon_ip.startswith('127.'):
                    ips.add(logon_ip)
    
    return ips, hostnames, usernames
```

---

## Phase 4: Malware & Recon Hunting

### When to Run
- **Malware hunting**: If Phase 1 determines MALWARE = TRUE
- **Recon hunting**: Always run - recon commands are IOCs

### Recon Command Extraction

**Key insight**: Recon commands and LOLBins (Living Off the Land Binaries) are IOCs!

```python
RECON_SEARCH_TERMS = [
    "nltest",           # Domain trust enumeration
    "net group",        # Group enumeration
    "net user",         # User enumeration
    "net localgroup",   # Local group enumeration
    "whoami",           # Privilege check
    "ipconfig",         # Network config
    "systeminfo",       # System enumeration
    "domain trust",     # Trust enumeration
    "quser",            # Logged-in users
    "query user",       # Logged-in users
]

RECON_LOLBINS = [
    "nltest.exe",       # Domain trust enumeration
    "net.exe",          # Network utility
    "net1.exe",         # Network utility (alternate)
    "whoami.exe",       # Privilege check
    "ipconfig.exe",     # Network config
    "systeminfo.exe",   # System info
    "quser.exe",        # User query
    "netsh.exe",        # Network shell
    "cmd.exe",          # Command shell
    "powershell.exe",   # PowerShell
]

def extract_recon_commands(results):
    """Extract recon commands from EDR process data"""
    commands = set()
    executables = set()
    
    for hit in results:
        src = hit['_source']
        process = src.get('process', {})
        
        if isinstance(process, dict):
            cmd_line = process.get('command_line', '')
            exe = process.get('executable', '')
            
            if cmd_line:
                # Look for recon patterns
                if any(term in cmd_line.lower() for term in ['nltest', 'net group', 'net user', 'whoami', 'domain_trust']):
                    commands.add(cmd_line[:200])
            
            if exe:
                executables.add(exe)
    
    return commands, executables
```

### Defender Event Extraction

**IMPORTANT**: Defender events (1116, 1117) have `EventData` as a JSON string that must be parsed.

```python
import json

def extract_defender_threats(opensearch_client, case_id, malware_filename):
    """
    Search for Defender events related to a malware file.
    Parse EventData JSON to extract threat names.
    """
    # Use query_string to search all fields
    query = {
        "query": {"query_string": {"query": f"*{malware_filename}*"}},
        "size": 50
    }
    result = opensearch_client.search(index=f"case_{case_id}", body=query)
    
    threats = set()
    paths = set()
    actions = set()
    
    for hit in result['hits']['hits']:
        src = hit['_source']
        event = src.get('Event', {})
        event_data_str = event.get('EventData', '{}')
        
        try:
            if isinstance(event_data_str, str):
                event_data = json.loads(event_data_str)
            else:
                event_data = event_data_str
            
            threat_name = event_data.get('Threat Name', '')
            category = event_data.get('Category Name', '')
            action = event_data.get('Action Name', '')
            path = event_data.get('Path', '')
            
            if threat_name:
                threats.add(threat_name)
            if action:
                actions.add(action)
            if path:
                paths.add(path)
                
        except json.JSONDecodeError:
            pass
    
    return threats, actions, paths
```

---

## Test Results

### Case 18 (JHD) - Phishing + Malware (10M+ Events)

**Starting IOCs (from report):**
- SPECIFIC: statements546.exe, SHA256 hash, filepath
- BROAD: jwilliams (username), ATN81960 (hostname), SID

**Auto-Tag Results:**
```
SPECIFIC IOCs (auto-tagged):
  - statements546.exe: 2 events ✅
  - SHA256 hash: 1 event ✅
  - Encoded PowerShell: 1 event ✅
  TOTAL: 4 events auto-tagged

BROAD IOCs (aggregation only):
  - jwilliams: 41,784 events → discovered: tabadmin, 4 hosts, 1 IP
  - ATN81960: 381,151 events → discovered via aggregations
  TOTAL: 0 events auto-tagged
```

**Key Learning**: This case proved the IOC classification strategy works for large cases.

### Case 15 (RDS Compromise with Exfiltration)

**Starting IOCs (from report):**
- 1 IP: 91.236.230.136 (BlueVPS - bulletproof hosting)
- 1 Username: BButler
- 1 SID: S-1-5-21-3129307847-4221876805-1187755365-1138
- Tools: WinSCP (exfiltration), nltest, net.exe (recon)
- Path: C:\Users\BButler\Pictures\WinSCP-6.5.3-Portable\
- Commands: nltest.exe /dclist:, net.exe group "domain computers" /dom

**Malware Indicated:** TRUE (recon commands, exfiltration tool, bulletproof hosting)

**Discovered IOCs:**

| Type | Value | Source |
|------|-------|--------|
| IP | 74.93.17.250 | Username hunting |
| Hostname | DESKTOP-K0RN0VC | IP hunting |
| Command | "C:\Windows\system32\nltest.exe" /dclist: | Recon hunting |
| Command | "C:\Windows\system32\net.exe" group "domain computers" /dom | Recon hunting |
| Filepath | C:\Users\BButler\Pictures\WinSCP-6.5.3-Portable\WinSCP.exe | Recon hunting |

**Key Findings:**
- **1.98M events** in case - large dataset
- **BlueVPS** - bulletproof hosting, commonly used by threat actors
- **WinSCP** extracted to Pictures folder - hiding technique
- **No Defender detections** - attack wasn't caught by AV
- **Domain enumeration** - nltest /dclist and net group commands

**Total IOCs Added: 18**

---

### Case 8 / Case 25 (CM) - Recon & Initial Access (Full Dry Run 2025-11-29)

**Starting IOCs (from report):**
- 5 IPs: 192.168.0.254 (gateway), 172.16.10.25, 192.168.0.8, 172.16.10.26 (malicious), 96.78.213.49 (SonicWall)
- 3 Hostnames: CM-DC01, CM-VMHOST, WIN-HU67JDG9MF1 (known malicious)
- 1 Username: tabadmin
- 1 SID: S-1-5-21-2922803321-3646860260-2870289857-1142
- 2 Paths: C:\ProgramData\AdUsers.txt, C:\ProgramData\AdComp.txt
- 1 Command: nltest /domain_trusts
- 1 Tool: Advanced IP Scanner

**IOC Classification:**
- SPECIFIC (auto-tag): 2 paths, 1 command, 1 tool = 4 items
- BROAD (aggregation only): 1 username, 3 hostnames, 5 IPs, 1 SID = 10 items

**Snowball Hunting (±24h from 07:13 UTC):**

| IOC | Events | Discovered Users | Discovered IPs |
|-----|--------|------------------|----------------|
| 192.168.0.8 | 10,000 | TABAdmin, cmadmin, DWM-2, UMFD-2 | 192.168.0.8 |
| 172.16.10.26 | 65 | tabadmin | 192.168.0.9 |
| CM-VMHOST | 10,000 | TABAdmin, cmadmin, DWM-2, UMFD-2 | 192.168.0.8 |
| CM-DC01 | 10,000 | ACardoso, ruben, jose, George, VDaCruz | 192.168.0.68, .9, .76, .70 |

**Discovered IOCs (NEW):**

| Type | Count | Values |
|------|-------|--------|
| Usernames | 10 | ACardoso, ruben, jose, George, VDaCruz, TABAdmin, UMFD-2, DWM-2, cmadmin, BDaCruz |
| IPs | 8 | 192.168.0.68, 192.168.0.9, 192.168.0.76, 192.168.0.70, 10.230.22.82, 192.168.0.131, 192.168.0.96, 192.168.0.124 |

**Time Window Analysis (±5 min around key events):**
- 06:57:00 (gateway auth): 84 events
- 07:10:00 (malicious host auth): 171 events
- 07:12:00 (domain trust enum): 178 events
- 07:13:00 (AdUsers/AdComp access): 201 events
- 07:14:00 (IP Scanner): 203 events
- **Total: 837 events in windows**

**Process Trees Built:** 72 (from cmd.exe/powershell.exe parents)

**Attack Timeline (from tabadmin activity 07:10-07:20 UTC):**
```
07:10:57 | Explorer.EXE | userinit.exe | Session start
07:10:58 | LTTray.exe | LTSvcMon.exe | LabTech RMM (legitimate)
07:10:59 | net.exe | cmd.exe | net use h: \\CM-DC\CompanyShares\Documents
07:10:59 | net.exe | cmd.exe | net use s: \\CM-DC\CompanyShares\e2
07:10:59 | net.exe | cmd.exe | net use z: \\CM-DC\CompanyShares\Documents\Quality
07:10:59 | net.exe | cmd.exe | net use i: \\CM-DC\UserShares\tabadmin
07:11:00 | ROUTE.EXE | cmd.exe | route add -p 192.168.2.0 mask 255.255.255.0 192.168.0.240
07:11:09 | NOTEPAD.EXE | Explorer.EXE | \\cm-app01\redirection$\tabadmin\Desktop\sa.txt
07:12:36 | powershell.exe | Explorer.EXE | PowerShell session started
07:12:55 | nltest.exe | powershell.exe | /domain_trusts ← RECON
07:13:10 | NOTEPAD.EXE | Explorer.EXE | C:\ProgramData\AdUsers.txt ← AD USER LIST
07:13:24 | NOTEPAD.EXE | Explorer.EXE | C:\ProgramData\AdComp.txt ← AD COMPUTER LIST
07:14:29 | Advanced_IP_Scanner_2.5.4594.1.tmp | Installer | Temp file
07:14:40 | advanced_ip_scanner.exe | Installer | NETWORK SCANNING
07:17:00 | msedge.exe | HuntressAgent.exe | Huntress opened browser
```

**MITRE ATT&CK Techniques:**
| Technique | Name | Events |
|-----------|------|--------|
| T1016 | System Network Config Discovery | 43 |
| T1018 | Remote System Discovery | 52 |
| T1033 | System Owner/User Discovery | 48 |
| T1078 | Valid Accounts | 58 |
| T1087 | Account Discovery | 8 |
| T1482 | Domain Trust Discovery | 4 |

**Auto-Tag Results:**
- SPECIFIC IOCs auto-tagged: **1 event** (Advanced IP Scanner)
- BROAD IOCs NOT auto-tagged (used for discovery only)

**Key Findings:**
- SonicWall gateway (96.78.213.49:60443) - potential initial access
- WIN-HU67JDG9MF1 - known malicious hostname from other intrusions
- Domain trust enumeration via nltest from PowerShell
- AD enumeration output files (AdUsers.txt, AdComp.txt) accessed via Notepad
- Network scanning with Advanced IP Scanner
- LTTray.exe (LabTech RMM) running - legitimate management tool (would be excluded with System Tools settings)

**Total IOCs: 23 from report + 18 discovered = 41 total**

---

### Case 11 (DEPCO) - Lateral Movement Attack

**Starting IOCs (from report):**
- 1 IP: 192.168.10.50
- 4 Hostnames: DEPCO-DC01, ATN79684, DESKTOP-K1PKL6P, accounting-DAFF0JD
- 2 Usernames: tabadmin, jeanette
- 2 SIDs

**Malware Indicated:** TRUE (Cobalt Strike, PSEXEC, Defender disabled)

**Discovered IOCs (11 NEW):**

| Type | Value | Source |
|------|-------|--------|
| IP | 192.168.1.125 | Username search |
| IP | 192.168.1.18 | Username search |
| IP | 192.168.1.19 | Hostname search |
| Hostname | ATN79685 | Username search |
| Hostname | ATN80117 | IP search |
| Hostname | ATN81301 | Username search |
| Username | DEPCO\steve | IP search |
| Threat | Behavior:Win32/ScrpService.B | Defender Event 1116 |
| Threat | Trojan:Win32/PShellCob.SA | Defender Event 1116 |
| Filename | PSEXESVC.exe | PSEXEC search |
| Command | powershell -nop -w hidden -encodedcommand... | Cobalt search |

**Key Findings:**
- Extensive lateral movement across multiple hosts
- Cobalt Strike C2 detected by Defender (but failed to block)
- Multiple new IPs and hostnames discovered through hunting

**Total IOCs: 20**

---

### Case 17 (JJLAW) - RDS Compromise

**Starting IOCs (from report):**
- 1 IP: 181.214.165.70 (external malicious)
- 3 Hostnames: JELLY-RDS01, DESKTOP-VSU85FT, JELLY-DC01
- 1 Username: JJLAW\Tracy
- 1 SID
- 1 Domain: jjlaw.local
- 1 Filename: WQTLib.dll
- 1 Filepath: C:\Users\Public\Music\WQTLib.dll
- 1 Command: rundll32 WQTLib.dll,init

**Malware Indicated:** TRUE (WQTLib.dll malicious DLL, recon commands)

**Discovered IOCs (1 NEW):**

| Type | Value | Source |
|------|-------|--------|
| Threat | Trojan:Win32/Seheq!rfn | Defender Event 1116 |

**Key Findings:**
- Contained attack on single RDS server
- Defender detected and quarantined the malware
- Known malicious workstation name (DESKTOP-VSU85FT) - threat actor reuses across orgs
- No lateral movement detected - attack was stopped early

**Total IOCs: 11**

---

## Key Differences Between Cases

| Aspect | Case 8 (CM) | Case 11 (DEPCO) | Case 15 | Case 17 (JJLAW) | Case 18 (JHD) |
|--------|-------------|-----------------|---------|-----------------|---------------|
| Attack Type | Recon & enum | Lateral movement | Exfiltration | Single host | Phishing |
| Initial Access | SonicWall VPN | SonicWall VPN | RDP (BlueVPS) | RDP/RDS | Phishing link |
| Malware | Recon tools | Cobalt Strike | WinSCP | WQTLib.dll | statements546.exe |
| Hosts Affected | Multiple (3+) | Multiple (5+) | 1 | Single | 1 |
| New IOCs Discovered | 7 | 11 | 2 | 1 | 4 (via aggregation) |
| Event Count | ~500K | ~1M | ~2M | ~500K | **10M+** |
| Strategy Used | Standard | Standard | Standard | Standard | **IOC Classification** |

---

## Data Source Notes

### EVTX Events
- Hostname: `computer_name` field
- Username patterns in `search_blob`:
  - `TargetUserName: value`
  - `SubjectUserName: value`
  - `AccountName: value`
- Workstation: `WorkstationName: value` in blob
- Defender events: Event IDs 1116, 1117 (but check Channel - not all 1116 are Defender!)

### Defender Events (Windows Defender Operational Log)
- Source file contains: `Microsoft-Windows-Windows Defender`
- `EventData` is a JSON string that must be parsed
- Key fields in EventData:
  - `Threat Name`: e.g., "Trojan:Win32/Seheq!rfn", "Trojan:Win32/PShellCob.SA"
  - `Category Name`: e.g., "Trojan"
  - `Action Name`: e.g., "Quarantine", "Not Applicable"
  - `Path`: e.g., "file:_C:\Users\Public\Music\WQTLib.dll"

### EDR Events
- **IMPORTANT**: `search_blob` may be empty for EDR data
- Data is in nested fields:
  - Hostname: `host.hostname` or `host.name`
  - Host IP: `host.ip` (can be list or string)
  - Username: `process.user.name` + `process.user.domain`
  - Username: `process.user_logon.username` + `process.user_logon.domain`
  - Workstation: `process.user_logon.workstation`
  - Source IP: `process.user_logon.ip`
  - **Command line**: `process.command_line`
  - **Executable**: `process.executable`

### Filtering Rules
1. **Exclude localhost**: IPs starting with `127.`, `0.`, `255.`
2. **Exclude noise users**: system, network service, local service, anonymous logon, window manager, dwm-*, umfd-*
3. **Exclude machine accounts**: Accounts ending with `$` (e.g., `COMPUTER$`)
4. **Normalize hostnames**: Convert to uppercase for comparison
5. **Minimum lengths**: Hostnames > 2 chars, paths > 10 chars

---

## Implementation Notes

### Searching for Malware/Recon Files
Use `query_string` with wildcards to search all fields:
```python
query = {
    "query": {"query_string": {"query": "*WQTLib* OR *nltest* OR *advanced_ip_scanner*"}},
    "size": 50
}
```

This finds events where the term appears in ANY field, not just `search_blob`.

### Event ID Collision
Event ID 1116 is used by multiple Windows components:
- Windows Defender (threat detection)
- PushNotification-Platform (errors)

Always check the `source_file` or `Event.System.Channel` to confirm it's a Defender event.

### Defender Event Parsing
```python
# EventData is a JSON string inside the Event object
event = src.get('Event', {})
event_data_str = event.get('EventData', '{}')
event_data = json.loads(event_data_str)
threat_name = event_data.get('Threat Name', '')
```

### LOLBins (Living Off the Land Binaries)
Legitimate Windows tools used maliciously. These ARE IOCs when used in attack context:
- `nltest.exe` - Domain trust enumeration
- `net.exe` / `net1.exe` - User/group enumeration
- `whoami.exe` - Privilege check
- `ipconfig.exe` - Network config
- `systeminfo.exe` - System enumeration
- `netsh.exe` - Network configuration
- `rundll32.exe` - DLL execution
- `cmd.exe` / `powershell.exe` - Command execution

---

## User Guidance: Reviewing Discovered IOCs

After the triage process completes, **review the discovered IOCs** and set appropriate status:

### Active vs Inactive IOCs
- **Active IOCs** are hunted by the IOC hunting engine when files are indexed
- **Inactive IOCs** are stored for reference but not actively hunted

### Recommended Status by IOC Type

| IOC Type | Recommended Status | Notes |
|----------|-------------------|-------|
| IP (external malicious) | **Active** | Hunt for lateral movement |
| IP (internal) | **Active** | Hunt for lateral movement |
| Hostname | **Active** | Hunt for related activity |
| Username | **Active** | Hunt for related activity |
| SID | **Inactive** | Too noisy, use for correlation |
| Command | **Inactive** | Too specific, use for context |
| Tool/Malware name | **Inactive** | Informational only |
| Threat (Defender) | **Inactive** | Informational only |
| Path (suspicious) | **Active** | Hunt for related files |
| Path (system) | **Inactive** | Too common |

### When to Set IOC to Inactive
- **False positive**: The value is not actually an IOC (e.g., legitimate internal IP)
- **Too noisy**: Matches too many events (e.g., common SID)
- **Already hunted**: You've already reviewed all matches
- **Informational**: Just for reference (e.g., Defender threat name)

### Important: Do NOT Delete IOCs
Instead of deleting, set IOCs to **Inactive**. This:
- Prevents them from being re-created on future triage runs
- Keeps a record of what was found
- Allows you to reactivate if needed later

---

## Future Enhancements

1. **Base64 Decoding**: Automatically decode encoded PowerShell and extract C2 IPs
2. **MITRE ATT&CK Mapping**: Tag discovered IOCs with ATT&CK techniques
3. **Confidence Scoring**: Rate IOCs based on how they were discovered
4. **Timeline Correlation**: Use timestamps from report to focus searches
5. **Recursive Discovery**: Multiple rounds of hunting until no new IOCs found
6. **Cross-Case Correlation**: Check if IOCs appear in other cases
7. **Threat Intel Integration**: Enrich discovered IOCs with external threat intel
8. **Recon Pattern Detection**: Identify sequences of recon commands as attack patterns
