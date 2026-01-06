# OpenSearch Field Structure & Mappings

**Last Updated**: December 28, 2025

## Overview

This document explains the OpenSearch field structure used in CaseScope, including field types, normalized fields, and how different log sources map to the unified schema.

**Index Structure**: Multi-index strategy (11 specialized indices)

**Existing Indices**:
- `case_{id}` - Event logs, EDR, Firewall (EVTX, NDJSON, CSV)
- `case_{id}_browser` - Browser activity (Chrome, Firefox, Edge, WebCache)
- `case_{id}_execution` - Execution artifacts (Prefetch, Activities, SRUM)
- `case_{id}_filesystem` - Filesystem timeline (MFT, Thumbcache, Windows Search)

**NEW Indices** (Jan 2026):
- `case_{id}_useractivity` - User activity (Jump Lists, LNK shortcuts) ⭐
- `case_{id}_comms` - Communications (PST/OST, Teams/Skype, Notifications) ⭐
- `case_{id}_network` - Network activity (BITS transfers) ⭐
- `case_{id}_persistence` - Persistence mechanisms (Scheduled Tasks, WMI) ⭐
- `case_{id}_devices` - Device history (USB connections, SetupAPI) ⭐
- `case_{id}_cloud` - Cloud storage (OneDrive operations) ⭐
- `case_{id}_remote` - Remote sessions (RDP bitmap cache) ⭐

**Benefits**:
- Faster targeted searches per artifact category
- Better performance on large datasets (millions of MFT entries separate from events)
- Clear separation of concerns (communications vs execution vs persistence)
- Independent retention policies per index type
- Dedicated UI pages for each artifact category
- Specialized aggregations per evidence type

---

## Core Field Categories

### 1. EVTX Fields (Windows Event Logs)

Fields extracted from Windows EVTX files:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_record_id` | long | Windows Event Record ID | 194738 |
| `event_id` | keyword | Windows Event ID | "4625" |
| `timestamp` | date | Event timestamp | "2025-04-21T07:18:43Z" |
| `system_time` | date | System generation time | "2025-04-21T07:18:43.168Z" |
| `computer` | keyword | Computer name | "ATN64025.DWTEMPS.local" |
| `channel` | keyword | Log channel | "Security", "System" |
| `provider_name` | keyword | Event provider | "Microsoft-Windows-Security-Auditing" |
| `level` | keyword | Event level | "Information", "Warning", "Error" |
| `task` | keyword | Task category | "Logon" |
| `opcode` | keyword | Operation code | "Info" |
| `keywords` | keyword | Event keywords | "Audit Failure" |
| `event_data` | object | Raw event data (nested) | `{"TargetUserName": "admin"}` |
| `event_data_fields` | object | Flattened event data | `{"Security": {...}}` |

**Notes**:
- `event_data` maintains full nested structure
- `event_data_fields` provides flattened access to common fields
- Both are stored as dynamic objects (no strict schema)

---

### 2. Normalized Fields (All Event Types)

Universal fields that work across EVTX, NDJSON, and CSV:

| Field | Type | Description | Sources | Populated By |
|-------|------|-------------|---------|--------------|
| `normalized_timestamp` | date | Standardized timestamp | All | Parsers + Backfill |
| `normalized_computer` | keyword | Computer/hostname | EVTX, NDJSON | Parsers + Backfill |
| `normalized_event_id` | keyword | Event identifier | EVTX, NDJSON | Parsers + Backfill |
| `normalized_source_ip` | ip | Source IP address | CSV, Firewall | CSV Parser |
| `normalized_dest_ip` | ip | Destination IP address | CSV, Firewall | CSV Parser |

**Purpose**: Enable unified queries, sorting, and display across different log formats

**How Populated**:
- **All parsers** use comprehensive `event_normalization.py` module (v1.5.7+)
- **Normalization Module** (`app/utils/event_normalization.py`):
  - `normalize_event_computer()`: Checks 15+ field paths including nested structures (v1.5.8: added CSV firewall detection)
  - `normalize_event_timestamp()`: Handles all timestamp formats (ISO, Unix, CSV with MM/DD/YYYY)
  - `normalize_event_id()`: Extracts event IDs from any log structure (v1.5.8: added 'id', 'fw_event' for CSV)
- **Field Path Priority for Computer Names**:
  1. `System.Computer` (standard EVTX)
  2. `Event.System.Computer` (exported EVTX - CRITICAL for ZIPs!)
  3. `computer`, `Computer`, `computer_name`, `ComputerName`
  4. `hostname`, `Hostname`, `host_name`, etc. (15+ variants)
  5. `host.hostname`, `host.name` (NDJSON/EDR)
  6. Firewall device names for CSV logs
- **Existing events**: Backfill script (`scripts/backfill_normalized_fields.py`) for historical data

**Sorting & Display**:
- Search results default sort: `normalized_timestamp` (newest first)
- Ensures chronological ordering across mixed log types (EVTX + NDJSON + CSV)
- Computer name display prioritizes `normalized_computer` with fallback to `computer`

**Example Query**:
```json
{
  "query": {
    "term": {
      "normalized_source_ip": "192.168.1.100"
    }
  }
}
```

This works for EVTX (extracted from event data), NDJSON (from `host.ip`), and CSV (from `src_ip`).

---

### 3. Firewall/CSV Fields

Fields from firewall CSV logs (SonicWall, generic firewalls):

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `log_source_type` | keyword | CSV source type | "sonicwall_csv", "firewall_csv" |
| `row_number` | long | CSV row number | 42 |
| `src_ip` | ip | Source IP | "192.168.1.100" |
| `dst_ip` | ip | Destination IP | "10.0.0.50" |
| `src_port` | integer | Source port | 54321 |
| `dst_port` | integer | Destination port | 443 |
| `src_mac` | keyword | Source MAC address | "00:1A:2B:3C:4D:5E" |
| `dst_mac` | keyword | Destination MAC address | "00:5E:4D:3C:2B:1A" |
| `src_zone` | keyword | Source zone/interface | "LAN", "WAN" |
| `dst_zone` | keyword | Destination zone/interface | "DMZ" |
| `ip_protocol` | keyword | Protocol | "TCP", "UDP", "ICMP" |
| `fw_action` | keyword | Firewall action | "Allow", "Drop", "Deny" |
| `application` | keyword | Detected application | "HTTPS", "DNS" |
| `priority` | keyword | Event priority | "High", "Medium", "Low" |
| `access_rule` | keyword | Rule name/ID | "Allow_Outbound_Web" |
| `rx_bytes` | long | Bytes received | 1024 |
| `tx_bytes` | long | Bytes transmitted | 4096 |
| `extracted_ips` | ip (array) | All IPs in event | ["192.168.1.1", "10.0.0.1"] |

**Geo-Blocking Fields**:
| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `geo_blocked_country` | keyword | Country name | "China" |
| `geo_blocked_ip` | ip | Blocked IP | "203.0.113.5" |
| `geo_block_direction` | keyword | Traffic direction | "inbound", "outbound" |

**Notes**:
- `fw_action` renamed from `action` to avoid conflicts
- `extracted_ips` is an array for IOC hunting across all IP fields
- Geo-blocking data extracted from `message` field

---

### 4. Search & Metadata Fields

| Field | Type | Description | Purpose |
|-------|------|-------------|---------|
| `search_blob` | text | Flattened searchable text | Full-text search across all fields |
| `source_file` | keyword | Original filename | Track event origin |
| `file_type` | keyword | File type | "EVTX", "NDJSON", "CSV", "IIS" |
| `case_id` | keyword | Case identifier | Link to case |
| `indexed_at` | date | Indexing timestamp | Audit trail |

#### Search Blob Details

**Purpose**: Enable fast full-text search without knowing exact field names

**Creation Process**:
1. Recursively traverse event dictionary
2. Extract all text values
3. Skip metadata fields (`has_sigma`, `has_ioc`, `file_id`)
4. Normalize whitespace
5. Limit to 100KB max

**Example**:
```json
{
  "event_id": "4625",
  "computer": "ATN64025",
  "event_data_fields": {
    "TargetUserName": "administrator",
    "FailureReason": "Bad password"
  }
}
```

**Generated search_blob**:
```
4625 ATN64025 administrator Bad password
```

**Query Usage**:
```json
{
  "query": {
    "query_string": {
      "query": "administrator AND bad password",
      "fields": ["search_blob"]
    }
  }
}
```

---

### 6. Browser Event Fields (`case_X_browser` index)

Fields from Chrome, Firefox, Edge browser history databases:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `@timestamp` | date | Event timestamp | "2020-05-19T18:44:33.481681" |
| `event_type` | keyword | Browser event type | "browser_visit", "browser_download", "browser_url", "webcache_entry" |
| `browser` | keyword | Browser name | "chrome", "firefox", "edge" |
| `url` | text | Full URL visited/downloaded | "https://example.com/page" |
| `title` | text | Page title | "Example Page - Mozilla Firefox" |
| `visit_count` | integer | Number of visits | 5 |
| `typed_count` | integer | Number of times typed | 2 |
| `domain` | keyword | Extracted domain | "example.com" |
| `file_path` | text | Download file path | "C:\\Users\\user\\Downloads\\file.exe" |
| `start_time` | date | Download start time | "2020-05-19T18:44:33.481681" |
| `end_time` | date | Download end time | "2020-05-19T18:44:33.866486" |
| `received_bytes` | long | Downloaded file size | 278092 |
| `total_bytes` | long | Total file size | 278092 |
| `state` | integer | Download state (0=in progress, 1=complete, 2=cancelled) | 1 |
| `danger_type` | integer | Download danger assessment (0=SAFE, 1=DANGEROUS, etc.) | 0 |
| `interrupt_reason` | integer | Download interrupt code | 0 |
| `mime_type` | keyword | File MIME type | "application/pdf" |
| `source_file` | keyword | Source History/WebCache file | "History", "WebCacheV01.dat" |
| `artifact_type` | keyword | Artifact classification | "browser_download", "browser_history" |
| `indexed_at` | date | Indexing timestamp | "2025-12-28T13:12:33.349417+00:00" |
| `case_id` | keyword | Case identifier | "3" |
| `file_type` | keyword | File type for filtering | "BrowserHistory" |
| `hostname` | keyword | Computer hostname (enriched from EVTX) | "Engineering5.JamesMFG.local" |

**Notes**:
- `event_type` distinguishes between visits, downloads, and cache entries
- `state` and `danger_type` are Chrome-specific integer codes
- `domain` is extracted from `url` for easier filtering
- `hostname` is enriched from main index EVTX events during display
- No `search_blob` field - searches use `url`, `title`, `file_path`

---

### 7. Analyst Tagging Fields

Fields for manual event tagging:

| Field | Type | Description |
|-------|------|-------------|
| `analyst_tagged` | boolean | Event manually tagged |
| `analyst_tagged_by` | keyword | Username who tagged |
| `analyst_tagged_at` | date | When tagged |

---

## Field Type Mapping

OpenSearch supports various field types:

| Type | Description | Used For | Example |
|------|-------------|----------|---------|
| `keyword` | Exact match | Computer names, event IDs, usernames | "ATN64025" |
| `text` | Full-text search | search_blob, descriptions | "Failed login attempt" |
| `date` | Timestamps | All timestamp fields | "2025-04-21T07:18:43Z" |
| `ip` | IP addresses | All IP fields | "192.168.1.100" |
| `long` | Large integers | Record IDs, byte counts | 194738 |
| `integer` | Small integers | Port numbers | 443 |
| `boolean` | True/false | Flags | true |
| `object` | Nested data | event_data, event_data_fields | `{"key": "value"}` |

**Key Differences**:
- **keyword**: Not analyzed, exact match only, sortable, aggregatable
- **text**: Analyzed (tokenized), full-text search, not sortable

---

## How Different Log Types Map

### EVTX → OpenSearch

```
Windows Event Log          OpenSearch Field
──────────────────         ────────────────
Event Record ID       →    event_record_id
Event ID              →    event_id, normalized_event_id
Time Created          →    timestamp, normalized_timestamp
Computer              →    computer, normalized_computer
Event Data            →    event_data, event_data_fields
                      →    search_blob (all text flattened)
```

### NDJSON → OpenSearch

```
NDJSON Field               OpenSearch Field
────────────               ────────────────
@timestamp            →    timestamp, normalized_timestamp
host.hostname         →    normalized_computer
event.code            →    normalized_event_id
host.ip               →    normalized_source_ip
destination.ip        →    normalized_dest_ip
(all fields)          →    search_blob
```

### CSV Firewall → OpenSearch

```
CSV Column                 OpenSearch Field
──────────                 ────────────────
Time                  →    time, normalized_timestamp
ID                    →    id, normalized_event_id
Message               →    message (used for event description)
Event                 →    fw_event (renamed to avoid mapping conflicts)
Src. IP               →    src_ip, normalized_source_ip
Dst. IP               →    dst_ip, normalized_dest_ip
FW Action             →    fw_action
Category              →    category
Group                 →    group
(all columns)         →    search_blob
```

**CSV Normalization (v1.5.8+)**:
- **Event ID**: Checks 'id' field (SonicWall ID column), falls back to 'fw_event'
- **Computer Name**: Firewall logs display as "Firewall" (no individual system names in firewall logs)
- **Description**: Uses 'message' field for event description display
- **Field Name Conversion**: "ID" → "id", "Message" → "message" (lowercase normalization)

---

## Index Settings

```json
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "refresh_interval": "5s"
  }
}
```

**Why These Settings?**
- **1 shard**: Case indexes are small (<10GB each), single shard performs better
- **0 replicas**: Single-node deployment, no replication needed
- **5s refresh**: Events visible within 5 seconds (balance between performance and freshness)

---

## Query Examples

### Search by IP Address (Works Across All Sources)

```json
{
  "query": {
    "bool": {
      "should": [
        {"term": {"normalized_source_ip": "192.168.1.100"}},
        {"term": {"normalized_dest_ip": "192.168.1.100"}},
        {"term": {"src_ip": "192.168.1.100"}},
        {"term": {"dst_ip": "192.168.1.100"}},
        {"term": {"extracted_ips": "192.168.1.100"}}
      ]
    }
  }
}
```

### Search by Computer Name

```json
{
  "query": {
    "bool": {
      "should": [
        {"term": {"computer": "ATN64025"}},
        {"term": {"normalized_computer": "ATN64025"}}
      ]
    }
  }
}
```

### Search by File Type

```json
{
  "query": {
    "term": {
      "file_type.keyword": "CSV"
    }
  }
}
```

### Full-Text Search

```json
{
  "query": {
    "query_string": {
      "query": "administrator AND failed",
      "fields": ["search_blob"],
      "default_operator": "AND"
    }
  }
}
```

---

## Field Name Conflicts & Resolutions

### Problem: "event" Field Conflict

**Issue**: SonicWall CSV has an "Event" column, but EVTX uses `event` as an object type.

**Error**:
```
object mapping for [event] tried to parse field [event] as object, 
but found a concrete value
```

**Solution**: Rename CSV "Event" column to `fw_event` during parsing.

**Code** (`firewall_csv_parser.py`):
```python
if 'event' in event:
    event['fw_event'] = event.pop('event')
```

---

## Performance Considerations

### Field Cardinality

High-cardinality fields (many unique values) impact performance:

**High Cardinality** (use `keyword`):
- IP addresses
- Computer names
- File hashes
- Usernames

**Low Cardinality** (use `keyword`):
- Event IDs
- File types
- Actions (Allow/Deny)
- Priorities

### Text vs Keyword

**Use `text` for**:
- Full-text search (search_blob)
- Long descriptions
- Command lines

**Use `keyword` for**:
- Exact matches
- Aggregations
- Sorting
- Filtering

### Index Size Estimates

| Events | Index Size | Query Time |
|--------|------------|------------|
| 10K | ~10 MB | <100ms |
| 100K | ~100 MB | <200ms |
| 1M | ~1 GB | <500ms |
| 10M | ~10 GB | <1s |

---

## Related Documentation

- **SEARCH_SYSTEM.md** - Search queries and interface
- **ZIP_ARCHITECTURE.md** - File parsing and processing system
- **THREAT_HUNTING.md** - IOC hunting queries
- **opensearch_indexer.py** - Implementation code

---

## Troubleshooting

### Field Not Searchable

**Problem**: Search not finding expected results

**Check**:
1. Field type: Is it `keyword` or `text`?
2. Field exists: Use `GET /case_2/_mapping` to verify
3. Case sensitivity: Keyword fields are case-sensitive

### Mapping Conflict

**Problem**: "mapper_parsing_exception" or type conflicts

**Solution**:
1. Check field type in existing mapping
2. Rename conflicting field during parsing
3. Delete and recreate index if necessary (data loss!)

### Performance Issues

**Problem**: Queries taking >5 seconds

**Check**:
1. Index size: Too large? (>50GB)
2. Query complexity: Too many wildcards?
3. Aggregations: On high-cardinality fields?

---

## Future Enhancements

- [ ] Custom analyzers for better tokenization
- [ ] Field aliases for backward compatibility
- [ ] Time-based indices (e.g., monthly)
- [ ] Hot/warm/cold tier management
- [ ] Automatic field type detection
- [ ] Dynamic templates for new fields

---

**Questions?** Check logs: `/opt/casescope/logs/celery_worker.log` for indexing errors.

