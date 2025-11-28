# Triage Search Findings

## Date: 2025-11-28

## Test Case: Case 13 (Huntress Report)

### Report Details
- **Report Timestamp**: 2025-09-05 06:40:02 UTC
- **Search Window**: 24 hours before report (2025-09-04 06:40:02 to 2025-09-05 06:40:02)

### IOCs Extracted from Report
- **IP**: 192.168.1.150
- **Username**: tabadmin
- **SID**: S-1-5-21-393219491-1469002369-1775737052-4603
- **Processes**: WinSCP.exe, svhost.exe (renamed rclone)
- **Path**: C:\ProgramData\USOShared\
- **Hostname**: Receiving

---

## Iterative Search Results

### Round 1: Search by IP (192.168.1.150)
**911 events found** (287 EVTX, 213 EDR)

**Hostnames Discovered:**
- ENGINEERING5
- JAMES-FS1
- RECEIVING

**Usernames Discovered:**
- JAMESMFG\tabadmin

### Round 2: Search by Hostnames (ENGINEERING5, JAMES-FS1, RECEIVING)

| Hostname | Events | IPs Found | Users Found |
|----------|--------|-----------|-------------|
| ENGINEERING5 | 2,504 | 172.16.1.10, 192.168.1.20, 192.168.1.150 | tabadmin, ENGINEERING5$ |
| JAMES-FS1 | 10,000 | (none) | JAMES-FS1$ |
| RECEIVING | 2,118 | 192.168.1.87, 192.168.1.150 | tabadmin, RECEIVING$ |

**NEW IPs Discovered:**
- `172.16.1.10` - Engineering5's internal IP
- `192.168.1.20` - New internal IP (Engineering5)
- `192.168.1.87` - New internal IP (Receiving)

**Key Observations:**
1. Attacker IP `192.168.1.150` appears on BOTH Engineering5 and Receiving → lateral movement confirmed
2. `tabadmin` account active on multiple hosts → compromised account spreading
3. Machine accounts (ENGINEERING5$, JAMES-FS1$, RECEIVING$) are normal, filter these out

---

## Key Finding: Use Existing Search Mechanism

**DO NOT reinvent the wheel** - use `build_search_query` and `execute_search` from `search_utils.py`

### Working Code Pattern
```python
from search_utils import build_search_query, execute_search

query_dsl = build_search_query(
    search_text="192.168.1.150",  # The IOC to search
    filter_type="all",
    date_range="custom",
    custom_date_start=datetime(2025, 9, 4, 6, 40, 2),  # 24h before report
    custom_date_end=datetime(2025, 9, 5, 6, 40, 2),    # report time
    file_types=['EVTX', 'EDR', 'JSON', 'CSV', 'IIS'],  # All types
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
```

---

## Search Results for IP 192.168.1.150

### Event Distribution
| File Type | Count |
|-----------|-------|
| EVTX | 287 |
| EDR | 213 |
| **Total** | **911** |

### Hostnames Discovered
- ENGINEERING5 / Engineering5
- JAMES-FS1
- RECEIVING / Receiving

### Usernames Discovered
- JAMESMFG\tabadmin

---

## Data Extraction Notes

### EVTX Events
- Hostname in: `computer_name` field
- Username patterns in `search_blob`:
  - `DOMAIN\username` pattern
  - `WorkstationName` field

### EDR Events
- **Important**: `search_blob` is often EMPTY for EDR data
- Data is in nested fields:
  - Hostname: `host.hostname` or `host.name`
  - Username: `process.user.name` + `process.user.domain`
  - Username: `process.user_logon.username` + `process.user_logon.domain`
  - Workstation: `process.user_logon.workstation`
  - Source IP: `process.user_logon.ip`

### Extraction Code Pattern
```python
for r in results:
    src = r['_source']
    
    # EVTX - computer_name
    computer = src.get('computer_name')
    if computer and computer not in ['-', 'N/A', None, '']:
        hostnames.add(computer)
    
    # EDR - nested host field
    host = src.get('host', {})
    if isinstance(host, dict):
        h = host.get('hostname') or host.get('name')
        if h:
            hostnames.add(h)
    
    # EDR - nested process.user and process.user_logon
    process = src.get('process', {})
    if isinstance(process, dict):
        proc_user = process.get('user', {})
        if isinstance(proc_user, dict):
            name = proc_user.get('name')
            domain = proc_user.get('domain', '')
            if name and name.lower() not in ['system', 'network service', 'local service']:
                usernames.add(f"{domain}\\{name}" if domain else name)
        
        logon = process.get('user_logon', {})
        if isinstance(logon, dict):
            name = logon.get('username')
            domain = logon.get('domain', '')
            ws = logon.get('workstation')
            if name and name.lower() not in ['system', 'network service', 'local service']:
                usernames.add(f"{domain}\\{name}" if domain else name)
            if ws:
                hostnames.add(ws)
```

---

## Proposed Triage Flow

1. **Extract IOCs from report** (current implementation - LLM + regex)
2. **For each IP IOC**:
   - Use `build_search_query` with 24h time window
   - Execute search across ALL file types
   - Extract hostnames and usernames from results
3. **Add discovered items**:
   - New hostnames → Systems table
   - New usernames → IOC table (type: username)
   - Original IOCs → IOC table

---

## Issues Found

1. **EDR search_blob is empty** - must use nested field extraction
2. **Hostname case sensitivity** - ENGINEERING5 vs Engineering5 (normalize to uppercase?)
3. **False positives in usernames** - filter out: system, network service, local service, window manager, anonymous logon
4. **Machine accounts** - filter out accounts ending in $ (e.g., COMPUTER$)
5. **Broad hostname search** - using `build_search_query` with hostname matches too many unrelated events (file paths like `Windows\System32`). Use targeted field queries instead.

---

## Recommended Search Strategy

### For IPs - Use existing search mechanism
```python
query_dsl = build_search_query(
    search_text="192.168.1.150",
    filter_type="all",
    date_range="custom",
    custom_date_start=time_start,
    custom_date_end=time_end,
    file_types=['EVTX', 'EDR', 'JSON', 'CSV', 'IIS'],
    ...
)
```

### For Hostnames - Use targeted field queries
```python
query = {
    "query": {
        "bool": {
            "should": [
                {"term": {"computer_name.keyword": hostname}},
                {"term": {"host.hostname.keyword": hostname}},
                {"term": {"host.name.keyword": hostname}},
            ],
            "minimum_should_match": 1,
            "filter": [{"range": {"normalized_timestamp": {...}}}]
        }
    }
}
```

### Extraction Patterns for EVTX
```python
# Specific user field patterns (not generic DOMAIN\user which catches file paths)
user_patterns = re.findall(r'(?:TargetUserName|SubjectUserName|AccountName)[:\s]+([A-Za-z0-9_\-\.]+)', blob)

# Domain-qualified users (specify known domains)
domain_users = re.findall(r'(JAMESMFG|NT AUTHORITY)\\([a-zA-Z0-9_\-\.]+)', blob, re.IGNORECASE)

# Workstation names
ws_matches = re.findall(r'WorkstationName[:\s]+([A-Za-z0-9\-]+)', blob)
```

---

## Iterative Triage Algorithm

```
1. Extract IOCs from report (IPs, usernames, hostnames, hashes, etc.)

2. FOR EACH IP:
   - Search all file types within time window
   - Extract: hostnames, usernames from results
   - Add new hostnames to search queue

3. FOR EACH HOSTNAME (use targeted field queries):
   - Search by computer_name/host.hostname fields
   - Extract: IPs, usernames from results
   - Add new IPs to search queue

4. REPEAT until no new items discovered (or max iterations)

5. Add all discovered items to IOC/Systems tables
```

This creates a "snowball" effect - starting from one IP, we discover related hosts, which reveal more IPs, etc.

