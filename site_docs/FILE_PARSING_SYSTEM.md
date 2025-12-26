# CaseScope File Parsing System

## Overview

The CaseScope parsing system transforms raw evidence files (EVTX, NDJSON) into searchable, structured events stored in OpenSearch. The system maintains complete event nesting while creating searchable representations for comprehensive analysis.

**Supported File Types:**
- ✅ **EVTX** - Windows Event Logs (Rust-based parser, 10-100x faster)
- ✅ **NDJSON** - Newline-Delimited JSON (EDR logs, Elastic Agent, etc.)
- ✅ **JSON** - JSON event files (same parser as NDJSON)
- ✅ **JSONL** - JSON Lines format (same parser as NDJSON)
- ✅ **CSV** - Firewall logs (SonicWall, generic firewall formats)

**Key Features:**
- Fast, memory-safe parsing
- Maintains complete nested structure
- Creates flattened search blob for full-text search
- Extracts source system (computer/hostname) automatically
- Normalizes timestamps and event IDs
- Handles files up to 10GB+

---

## Architecture

```
Upload → Staging → Parser → Normalizer → Indexer → Storage
                     │           │            │
                     ├─ Extract  ├─ Add      ├─ Bulk index
                     │  events   │  metadata │  to OpenSearch
                     │           │            │
                     ├─ Maintain ├─ Create   └─ Create DB
                     │  nesting  │  search_blob  record
                     │           │
                     └─ Stream   └─ Normalize
                        process     fields
```

---

## Parser Components

### 1. EVTX Parser

**File:** `app/parsers/evtx_parser.py`

**Library:** `evtx` (Rust-based Python bindings)

**Performance:**
- 10-100x faster than Python-based parsers
- Handles 1GB file in ~2 minutes
- Handles 10GB file in ~20 minutes

#### Fields Extracted

**System Section:**
- `event_record_id` - Unique record ID from EVTX file
- `event_id` - Windows Event ID (e.g., 4625, 4624, 7045)
- `computer` - Computer name from event
- `timestamp` - Event timestamp (ISO 8601)
- `system_time` - System time when event was created
- `channel` - Event log channel (Security, Application, System, etc.)
- `provider_name` - Event provider/source
- `level` - Severity level (0=Information, 2=Error, 4=Warning)

**EventData Section:**
- `event_data_fields` - Dictionary of all Name/Value pairs from EventData
- Field names preserved as-is (e.g., TargetUserName, SubjectLogonId)

**Additional Fields:**
- `raw_xml` - Complete XML for the event
- `is_from_hidden_file` - False (events from hidden files marked True)
- `search_blob` - Flattened searchable text

---

### 2. NDJSON Parser

**File:** `app/parsers/ndjson_parser.py`

**Format:** Newline-Delimited JSON (one JSON object per line)

**Purpose:** Parse EDR logs, Elastic Agent output, custom JSON exports

#### Process Tree Support

NDJSON events support complete process hierarchy tracking:

**Fields Available:**
- `process.name` - Current process name
- `process.pid` - Current process PID
- `process.command_line` - Full command line
- `process.parent.name` - Parent process name
- `process.parent.pid` - Parent PID
- `process.parent.command_line` - Parent command
- `process.parent.parent.name` - Grandparent process name
- `process.parent.parent.pid` - Grandparent PID
- `process.parent.parent.command_line` - Grandparent command

---

## Search Blob Creation

**Purpose:** Create a flattened, searchable text representation of the entire event

**Algorithm:**
1. Recursively traverse event dictionary
2. Extract all text values (skip booleans and metadata)
3. Normalize whitespace
4. Limit to 100KB max

**Example:**
```
Input: {"event_id": "4625", "computer": "ATN64025", "user": "admin"}
Output: "4625 ATN64025 admin"
```

---

## Source System Detection

**Purpose:** Automatically extract computer/hostname from events

### EVTX Detection
**Fields Checked:**
1. `computer` - Standard field
2. `Computer` - Capitalized variant
3. `computer_name` - Alternative
4. `system.computer` - Nested variant

### NDJSON Detection
**Fields Checked:**
1. `normalized_computer` - Added during normalization
2. `host.hostname` - Standard ECS field
3. `host.name` - Alternative ECS field

### CSV Detection (Firewall Logs)
**Fields Checked:**
1. `src_ip` - Source IP from SonicWall/firewall logs
2. `computer` - If present in CSV data
3. `hostname` - Alternative field
4. Note: Many firewall CSV files don't contain hostname info

**Success Rate:** 100% (after operator precedence bug fix for EVTX/NDJSON)

---

## CSV Firewall Parser

**File:** `app/parsers/firewall_csv_parser.py`

**Supported Formats:**
- SonicWall CSV logs
- Generic firewall logs (source/dest IPs, action field)

**Features:**
- Auto-detects CSV source type (SonicWall vs generic)
- Normalizes field names to snake_case
- Extracts timestamps (MM/DD/YYYY HH:MM:SS format)
- Extracts all IP addresses (source, dest, NAT IPs)
- Parses geo-blocking messages from Message field
- Creates comprehensive search_blob
- Handles empty values (0.0.0.0, "") properly

**Performance:**
- Pure Python CSV parsing
- Stream processing (no full file load)
- Handles large CSV files (100k+ rows)

**Normalization:**
```python
# Field name normalization
"Src. IP" → "src_ip"
"Src.NAT IP" → "src_nat_ip"
"FW Action" → "fw_action"

# Event field rename (to avoid OpenSearch conflict)
"Event" → "fw_event"
```

**Extracted IPs:**
- `src_ip`, `dst_ip` - Primary IPs
- `src_nat_ip`, `dst_nat_ip` - NAT IPs
- `extracted_ips` - Array of all IPs for IOC hunting

**Geo-Blocking Extraction:**
```
Message: "TCP access rule: Geo-IP Blocking inbound traffic from China (203.0.113.5)"
→ geo_blocked_country: "China"
→ geo_blocked_ip: "203.0.113.5"
→ geo_block_direction: "inbound"
```

**Success Rate:** 100% (after operator precedence bug fix)

---

## Memory-Safe Processing

**Challenge:** Large files can cause OOM errors

**Solution:** Chunk-based streaming

```python
CHUNK_SIZE = 5000  # Process 5000 events at a time

for event in parse_file(file_path):  # Stream
    chunk.append(event)
    
    if len(chunk) >= CHUNK_SIZE:
        index_chunk(chunk)
        chunk = []  # Free memory
```

**Memory Usage:**
- Without chunking: ~485MB for 194K events
- With chunking: ~15MB max

---

## Version
- **Document Version:** 1.0.0
- **Last Updated:** 2025-12-23
- **CaseScope Version:** 2026
