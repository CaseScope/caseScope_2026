# CaseScope OpenSearch Structure

**Complete OpenSearch Schema & Index Documentation**  
**Last Updated:** December 17, 2025  
**Version:** CaseScope 2026 v1.0.0  
**OpenSearch Version:** 2.11.0

---

## Overview

CaseScope uses **OpenSearch 2.11** as the primary event storage and search engine. All log events (EVTX, JSON, CSV, IIS) are indexed into OpenSearch for fast full-text search, filtering, and analysis.

**PostgreSQL vs OpenSearch**:
- **PostgreSQL**: Stores metadata (cases, files, users, IOCs, SIGMA rules, status records)
- **OpenSearch**: Stores raw event data (millions of log entries per case)

---

## Index Architecture

### Index Naming Convention

```
Format: case_{case_id}
Examples:
  - case_1    (all events for case ID 1)
  - case_2    (all events for case ID 2)
  - case_15   (all events for case ID 15)
```

**v1.0.0 Architecture Change:**
- **OLD**: One index per file (`case_1_file123`, `case_1_file124`) → 10,458 indices = 10,458 shards
- **NEW**: One index per case (`case_1`, `case_2`) → 7 indices = 7 shards

**Benefits:**
- ✅ Reduces shard count from 10K+ to <100
- ✅ Reduces heap usage from 16GB+ to 2-4GB
- ✅ Allows millions of files per case
- ✅ Filter by `source_file` field instead of index name

---

## Document Structure

### Core Metadata Fields

Every document in OpenSearch contains these core fields:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `_id` | String (UUID) | Unique document ID | `a3f8b2c1-4d6e-8f9a-1b2c-3d4e5f6a7b8c` |
| `case_id` | Integer | Parent case ID | `15` |
| `file_id` | Integer | Source file ID (FK to PostgreSQL) | `1234` |
| `case_name` | String | Case name (denormalized) | `Acme Corp Ransomware` |
| `source_file` | String | Original filename | `Security.evtx` |
| `source_file_type` | String | File type identifier | `EVTX`, `EDR`, `CSV`, `IIS`, `JSON` |
| `event_status` | String | Event status (v1.46.0) | `new`, `noise`, `hunted`, `confirmed` |
| `status_reason` | String | Why status was set | `auto_known_good`, `phase3_ioc_match` |
| `search_blob` | Text | Flattened searchable text (v1.43.5) | All event data combined into single field |

---

## Event Status Values

**Critical for Search Filtering:**

| Status | Description | Set By | Search Behavior |
|--------|-------------|---------|-----------------|
| `new` | Fresh event, just indexed (default) | Indexing process | Included in searches |
| `noise` | Known-good or noise event | Auto-hide, Hide Known Good/Noise buttons | **Excluded from searches** by default |
| `hunted` | Potentially interesting event | Phase 3 AI Triage, IOC matches | Included in searches, highlighted |
| `confirmed` | Analyst confirmed as relevant | Manual tagging, SIGMA violations | Included in searches, priority display |

**Synchronization**: Event status is stored in **both**:
1. OpenSearch `event_status` field (for fast filtering)
2. PostgreSQL `EventStatus` table (for audit trail)

**When status changes**, BOTH are updated to stay in sync.

---

## Search Blob (v1.43.5)

**Purpose**: Single field containing ALL event data for fast full-text search.

### What is `search_blob`?

A flattened, space-separated representation of the entire event, extracting text from:
- All nested dictionaries (recursively)
- All array elements
- All key-value pairs

**Example**:
```json
Original EVTX event:
{
  "System": {
    "EventID": 4624,
    "Computer": "WS01",
    "TimeCreated": {"SystemTime": "2025-01-15T10:30:00Z"}
  },
  "EventData": {
    "TargetUserName": "john.doe",
    "WorkstationName": "LAPTOP-ABC",
    "IpAddress": "192.168.1.50"
  }
}

Generated search_blob:
"4624 WS01 2025-01-15T10:30:00Z john.doe LAPTOP-ABC 192.168.1.50 EventID Computer TimeCreated SystemTime TargetUserName WorkstationName IpAddress"
```

### Search Performance

**Benchmarks (10.5M event case)**:
- Searching all 8,759 fields: **10-15 seconds** per search
- Searching `search_blob` only: **400-600ms** per search (**20-30x faster**)

### Search Fields (Fallback)

For backward compatibility with pre-v1.43.5 data, searches also include:

```python
SEARCH_FIELDS = [
    "search_blob",                  # PRIMARY
    "process.command_line",         # EDR fallback
    "process.executable",
    "process.name",
    "process.parent.command_line",
    "user.name",
    "host.hostname",
    "source.ip",
    "destination.ip",
    "file.path",
    "forensic_CommandLine",         # EVTX forensic extraction
    # ... and more
]
```

---

## Event Types & Field Structures

### 1. EVTX Events (Windows Event Logs)

**Source**: `.evtx` files converted via `evtx_dump`

**Key Fields**:
```json
{
  "System": {
    "EventID": 4624,
    "EventRecordID": 123456,
    "Computer": "WS01.domain.local",
    "TimeCreated": {
      "@attributes": {
        "SystemTime": "2025-01-15T10:30:00.123Z"
      }
    },
    "Provider": {
      "@attributes": {
        "Name": "Microsoft-Windows-Security-Auditing"
      }
    },
    "Channel": "Security",
    "Level": 0
  },
  "EventData": {
    "TargetUserName": "john.doe",
    "TargetDomainName": "CORP",
    "LogonType": 3,
    "IpAddress": "192.168.1.50",
    "WorkstationName": "LAPTOP-ABC"
  },
  "forensic_*": {
    "forensic_Computer": "WS01",
    "forensic_TimeCreated": "2025-01-15 10:30:00",
    "forensic_EventID": "4624",
    "forensic_CommandLine": "C:\\Windows\\System32\\cmd.exe /c whoami",
    "forensic_ProcessName": "cmd.exe",
    "forensic_UserName": "john.doe"
  },
  "case_id": 15,
  "file_id": 1234,
  "case_name": "Acme Corp Ransomware",
  "source_file": "Security.evtx",
  "source_file_type": "EVTX",
  "event_status": "new",
  "search_blob": "..."
}
```

**Normalized Fields** (extracted by `event_normalization.py`):
- `forensic_Computer` - hostname
- `forensic_TimeCreated` - timestamp (ISO 8601)
- `forensic_EventID` - event ID
- `forensic_UserName` - username
- `forensic_CommandLine` - command line
- `forensic_ProcessName` - process name
- `forensic_ParentProcessName` - parent process

---

### 2. EDR Events (Elastic/EDR JSON logs)

**Source**: JSON files with Elastic Common Schema (ECS) structure

**Key Fields**:
```json
{
  "@timestamp": "2025-01-15T10:30:00.000Z",
  "ecs": {
    "version": "8.0.0"
  },
  "event": {
    "kind": "event",
    "category": ["process"],
    "type": ["start"],
    "action": "process_started"
  },
  "host": {
    "hostname": "WS01",
    "ip": ["192.168.1.100"]
  },
  "user": {
    "name": "john.doe",
    "domain": "CORP"
  },
  "process": {
    "pid": 1234,
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -enc BASE64...",
    "parent": {
      "pid": 567,
      "name": "explorer.exe",
      "command_line": "C:\\Windows\\explorer.exe"
    }
  },
  "file": {
    "path": "C:\\Users\\john.doe\\AppData\\Roaming\\malware.exe",
    "name": "malware.exe",
    "hash": {
      "sha256": "abc123..."
    }
  },
  "case_id": 15,
  "file_id": 1235,
  "source_file": "edr_events.json",
  "source_file_type": "EDR",
  "event_status": "new",
  "search_blob": "..."
}
```

**Detection**:
- Has `@timestamp` field
- Has `process`, `host`, `ecs`, or `event.kind` fields
- Follows Elastic Common Schema (ECS) structure

---

### 3. CSV Events (Firewall/SonicWall logs)

**Source**: `.csv` files (firewall logs, custom exports)

**Key Fields**:
```json
{
  "row_number": 1,
  "Time": "10/15/2025 12:35:21",
  "Src. IP": "203.0.113.50",
  "Dst. IP": "192.168.1.100",
  "Src. Port": "54321",
  "Dst. Port": "445",
  "Event": "Connection Opened",
  "Category": "Connections (IPv4)",
  "Priority": "Alert",
  "Message": "Connection opened: TCP 203.0.113.50:54321 -> 192.168.1.100:445",
  "forensic_Computer": "Firewall",
  "forensic_TimeCreated": "2025-10-15T12:35:21",
  "forensic_EventID": "CSV",
  "case_id": 15,
  "file_id": 1236,
  "source_file": "sonicwall_logs.csv",
  "source_file_type": "CSV",
  "event_status": "new",
  "search_blob": "..."
}
```

**Detection**:
- Has `row_number` field
- Contains firewall-specific fields (`Src. IP`, `Dst. IP`, `Category`)

**Normalized Fields**:
- `forensic_Computer` → `"Firewall"` (default for firewall logs)
- `forensic_TimeCreated` → Converted from CSV date format to ISO 8601
- `forensic_EventID` → `"CSV"`

---

### 4. IIS Events (Web Server Logs)

**Source**: `.log` files (IIS W3C Extended Log Format)

**Key Fields**:
```json
{
  "date": "2025-01-15",
  "time": "10:30:45",
  "s-ip": "192.168.1.100",
  "cs-method": "GET",
  "cs-uri-stem": "/api/users",
  "cs-uri-query": "id=123",
  "s-port": "443",
  "cs-username": "-",
  "c-ip": "203.0.113.45",
  "cs(User-Agent)": "Mozilla/5.0...",
  "cs(Referer)": "https://example.com/",
  "sc-status": "200",
  "sc-substatus": "0",
  "sc-win32-status": "0",
  "time-taken": "125",
  "forensic_Computer": "IIS-192.168.1.100",
  "forensic_TimeCreated": "2025-01-15T10:30:45",
  "forensic_EventID": "IIS-GET-200",
  "case_id": 15,
  "file_id": 1237,
  "source_file": "WEB-SERVER_u_ex250115.log",
  "source_file_type": "IIS",
  "event_status": "new",
  "search_blob": "..."
}
```

**Detection**:
- Has `source_file_type='IIS'` field
- Contains IIS-specific fields (`s-ip`, `cs-method`, `sc-status`)

**Normalized Fields**:
- `forensic_Computer` → Extracted from filename prefix or `s-ip` field
- `forensic_TimeCreated` → Combined `date` + `time` fields
- `forensic_EventID` → `"IIS-{method}-{status}"` (e.g., `"IIS-GET-200"`)

---

### 5. JSON Events (Generic JSON logs)

**Source**: `.json` files (custom logs, application logs)

**Key Fields**:
```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "level": "error",
  "message": "Database connection timeout",
  "service": "api-gateway",
  "user_id": "12345",
  "request_id": "abc-def-ghi",
  "duration_ms": 5000,
  "forensic_Computer": "api-gateway",
  "forensic_TimeCreated": "2025-01-15T10:30:00",
  "forensic_EventID": "error",
  "case_id": 15,
  "file_id": 1238,
  "source_file": "app_logs.json",
  "event_status": "new",
  "search_blob": "..."
}
```

**Detection**:
- No `source_file_type` field
- Not EVTX (no `System` field)
- Not EDR (no `@timestamp` + `process`/`host`/`ecs` combo)
- Not CSV (no `row_number`)

**Normalized Fields** (best-effort extraction):
- `forensic_Computer` → Extracted from `hostname`, `host`, `service`, or `"JSON-Server"`
- `forensic_TimeCreated` → Extracted from common timestamp fields
- `forensic_EventID` → Extracted from `level`, `event_type`, or `"JSON"`

---

## Index Mapping (Dynamic)

OpenSearch uses **dynamic mapping** for CaseScope indices. This means:
- Fields are automatically created when first encountered
- Field types are inferred from the data
- No predefined schema required

**Common Field Types**:
- **Text**: Full-text searchable (tokenized) - used for `search_blob`, command lines
- **Keyword**: Exact match (not tokenized) - used for `event_status`, `case_id`, `source_file`
- **Integer**: Numeric values - used for `case_id`, `file_id`, Event IDs
- **Date**: Timestamp values - used for `@timestamp`, `forensic_TimeCreated`
- **Object**: Nested structures - used for `System`, `EventData`, `process`

**Mapping Example**:
```json
{
  "case_15": {
    "mappings": {
      "properties": {
        "case_id": { "type": "integer" },
        "file_id": { "type": "integer" },
        "case_name": { "type": "keyword" },
        "source_file": { "type": "keyword" },
        "source_file_type": { "type": "keyword" },
        "event_status": { "type": "keyword" },
        "search_blob": { "type": "text" },
        "forensic_Computer": { "type": "keyword" },
        "forensic_TimeCreated": { "type": "date" },
        "forensic_EventID": { "type": "keyword" },
        "System": { "type": "object" },
        "EventData": { "type": "object" }
      }
    }
  }
}
```

---

## Indexing Pipeline

### Phase 1: File Upload & Index

```
1. User uploads file (EVTX, JSON, CSV, IIS)
   ↓
2. Duplicate check (hash + filename)
   ↓
3. File conversion (EVTX → JSON via evtx_dump)
   ↓
4. Event parsing & normalization
   ↓
5. Generate search_blob for each event
   ↓
6. Apply auto-hide (known-good events → event_status='noise')
   ↓
7. Apply auto-hide noise (system noise → event_status='noise')
   ↓
8. Bulk index to OpenSearch (1000 events per batch)
   ↓
9. Update CaseFile.event_count in PostgreSQL
```

**Auto-Hide During Indexing (v1.46.0)**:
- Known-good events (RMM tools, EDR health checks) → `event_status='noise'`
- Noise events (system processes, monitoring) → `event_status='noise'`
- All others → `event_status='new'`

---

## Search Operations

### Basic Search Query Structure

```json
{
  "query": {
    "bool": {
      "must": [
        {
          "multi_match": {
            "query": "powershell",
            "fields": ["search_blob", "process.command_line", "forensic_CommandLine"]
          }
        },
        {
          "term": {
            "case_id": 15
          }
        }
      ],
      "must_not": [
        {
          "term": {
            "event_status": "noise"
          }
        }
      ],
      "filter": [
        {
          "range": {
            "forensic_TimeCreated": {
              "gte": "2025-01-15T00:00:00",
              "lte": "2025-01-15T23:59:59"
            }
          }
        }
      ]
    }
  },
  "sort": [
    {
      "forensic_TimeCreated": {
        "order": "desc"
      }
    }
  ],
  "from": 0,
  "size": 50
}
```

### Search API Types

**1. Paginated Search** (`execute_search`):
- Default: 50 results per page
- Max: 10,000 results (OpenSearch `max_result_window`)
- Use for: UI display, quick searches

**2. Scroll Search** (`execute_search_scroll`):
- No result limit (bypasses 10,000 limit)
- Batch size: 1000-5000 events per scroll
- Use for: Export, bulk operations, IOC hunting

**3. Sliced Scroll** (`events_known_good`, `events_known_noise`):
- Parallel processing across 8 workers
- Each worker gets 1/8 of the dataset
- Use for: Hide Known Good/Noise operations

---

## Common Search Filters

### By Event Status

```json
"must_not": [
  { "term": { "event_status": "noise" } }
]
```

### By File Type

```json
"must": [
  { "term": { "source_file_type.keyword": "EVTX" } }
]
```

### By Date Range

```json
"filter": [
  {
    "range": {
      "forensic_TimeCreated": {
        "gte": "2025-01-15T00:00:00",
        "lte": "2025-01-15T23:59:59"
      }
    }
  }
]
```

### By Source File

```json
"must": [
  { "term": { "source_file.keyword": "Security.evtx" } }
]
```

### By SIGMA Violations

```json
"must": [
  { "exists": { "field": "sigma_violation" } }
]
```

### By IOC Matches

```json
"must": [
  { "exists": { "field": "ioc_matches" } }
]
```

---

## Bulk Operations

### Bulk Index (1000 events/batch)

```python
from opensearchpy.helpers import bulk

bulk_data = [
    {
        '_index': 'case_15',
        '_source': event_dict
    }
    for event_dict in events
]

success, errors = bulk(opensearch_client, bulk_data, raise_on_error=False)
```

### Bulk Update (event status sync)

```python
bulk_update = [
    {
        '_op_type': 'update',
        '_index': 'case_15',
        '_id': event_id,
        'doc': {
            'event_status': 'hunted',
            'status_reason': 'phase3_ioc_match'
        }
    }
    for event_id in event_ids
]

bulk(opensearch_client, bulk_update, raise_on_error=False)
```

### Bulk Delete (reindex cleanup)

```python
opensearch_client.delete_by_query(
    index='case_15',
    body={
        'query': {
            'term': {
                'file_id': 1234
            }
        }
    }
)
```

---

## Index Lifecycle

### Index Creation

- **Automatic**: Created on first event index
- **Naming**: `case_{case_id}`
- **Shards**: 1 primary, 0 replicas (single-node)
- **Refresh Interval**: 1s (near real-time)

### Index Settings

```json
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "refresh_interval": "1s",
    "max_result_window": 10000
  }
}
```

### Index Deletion

**When Case is Deleted**:
```python
opensearch_client.indices.delete(index=f'case_{case_id}')
```

**When Case is Archived**:
- Index is **retained** (not deleted)
- Case is marked as `archived` in PostgreSQL
- Users cannot modify data, but can still search

---

## Performance Considerations

### Shard Management

**Single-Node Optimization**:
- 1 primary shard per index
- 0 replicas (no redundancy needed)
- Total shards = number of cases
- Max shards per node: 1000 (default)

**Multi-Node Scaling** (future):
- 1 primary + 1 replica per index
- Shards distributed across nodes
- Automatic failover

### Heap Sizing

**Recommended Heap**:
- Small deployments (<10 cases): 2-4GB
- Medium deployments (10-50 cases): 8-16GB
- Large deployments (50+ cases): 32GB+

**Rule of Thumb**: 50% of total RAM (max 32GB)

### Search Performance

**Optimization Strategies**:
1. **Use `search_blob`** for fastest full-text search
2. **Filter by `case_id`** to limit search scope
3. **Use `term` queries** for exact matches (keyword fields)
4. **Use `must_not` for status='noise'** to exclude millions of events
5. **Scroll API** for large result sets (>10K)
6. **Sliced Scroll** for parallel processing (8 workers)

### Index Size Estimates

| Event Count | Index Size | Heap Usage |
|-------------|------------|------------|
| 100K events | ~50MB | <100MB |
| 1M events | ~500MB | ~500MB |
| 10M events | ~5GB | ~2GB |
| 40M events | ~20GB | ~8GB |

---

## Common Issues & Fixes

### Issue 1: "Circuit breaker tripped"

**Cause**: Heap usage exceeded 95%

**Fix**:
```bash
curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "indices.breaker.total.limit": "95%"
  }
}'
```

### Issue 2: "Too many shards"

**Cause**: Exceeded max shards per node (1000)

**Fix**: Archive old cases and delete their indices

### Issue 3: "Search too slow"

**Cause**: Searching all fields instead of `search_blob`

**Fix**: Ensure `search_blob` is populated (reindex if necessary)

### Issue 4: "Cluster status yellow"

**Cause**: Unassigned replica shards on single-node

**Fix**: Set replicas to 0
```bash
curl -X PUT "localhost:9200/case_*/_settings" -H 'Content-Type: application/json' -d'
{
  "number_of_replicas": 0
}'
```

---

## Data Retention

### Automatic Cleanup

**None** - All event data is retained indefinitely by design.

### Manual Cleanup

1. **Delete Case**: Deletes index `case_{case_id}`
2. **Archive Case**: Retains index, marks case as archived
3. **Reindex**: Deletes and recreates index for a case

---

## Configuration

### OpenSearch Settings

**Location**: `/opt/opensearch/config/opensearch.yml`

```yaml
# Single-node configuration
discovery.type: single-node
plugins.security.disabled: true

# Network
network.host: 0.0.0.0
http.port: 9200

# Heap (set via jvm.options)
# -Xms16g
# -Xmx16g

# Circuit breaker
indices.breaker.total.limit: 95%

# Index defaults
action.auto_create_index: true
```

### CaseScope Configuration

**Location**: `app/config.py`

```python
OPENSEARCH_HOST = 'localhost'
OPENSEARCH_PORT = 9200
OPENSEARCH_USE_SSL = False
OPENSEARCH_INDEX_PREFIX = 'case_'
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v1.0.0 | 2025-12-17 | Initial comprehensive documentation |
| v1.46.0 | 2024 | Added `event_status` field to all documents |
| v1.43.5 | 2024 | Added `search_blob` for all event types |
| v1.14.0 | 2024 | Added IIS log support |
| v1.0.0 | 2024 | Changed from per-file to per-case indices |

---

## Notes

1. **Dynamic Mapping**: OpenSearch automatically creates field mappings. No predefined schema required.

2. **Event Status Sync**: The `event_status` field is synced between OpenSearch and PostgreSQL `EventStatus` table.

3. **Search Blob Performance**: Using `search_blob` provides 20-30x faster searches than searching all fields.

4. **Index Per Case**: One index per case (not per file) for optimal shard management.

5. **Scroll API**: Use Scroll API for unlimited result sets (bypasses 10,000 limit).

6. **Auto-Hide**: Events are auto-marked as `noise` during indexing based on known-good and noise patterns.

7. **File Type Detection**: Automatic detection of EVTX, EDR, CSV, IIS, and JSON formats.

8. **Field Normalization**: `forensic_*` fields are extracted for consistent search across all event types.

---

**END OF DOCUMENTATION**

