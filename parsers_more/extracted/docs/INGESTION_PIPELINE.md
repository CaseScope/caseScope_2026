# CaseScope Ingestion Pipeline

## Overview

The CaseScope ingestion pipeline provides modular, high-performance parsing and indexing of forensic artifacts into ClickHouse for fast threat hunting and analysis.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          INGESTION PIPELINE                                  │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │  Web Upload │     │ SFTP Upload │     │ CyLR Import │
    └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
           │                   │                   │
           └───────────────────┼───────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │   Staging Folder    │
                    │ /staging/{case_id}/ │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Parser Registry   │
                    │   (Auto-detect)     │
                    └──────────┬──────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   Hayabusa    │    │    Dissect    │    │  Log Parsers  │
│  EVTX Parser  │    │   Parsers     │    │  IIS/FW/EDR   │
│ +Sigma Rules  │    │ PF/REG/LNK    │    │               │
└───────┬───────┘    └───────┬───────┘    └───────┬───────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             ▼
                    ┌─────────────────────┐
                    │   Batch Processor   │
                    │   (10K batches)     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │     ClickHouse      │
                    │   events_buffer     │
                    │        ↓            │
                    │      events         │
                    └─────────────────────┘
```

## Components

### 1. Parsers (`/parsers/`)

#### Hayabusa EVTX Parser (`evtx_parser.py`)
- **Primary EVTX parser** using Hayabusa binary
- 4,000+ Sigma detection rules
- MITRE ATT&CK mapping
- Normalized field extraction (Details object)
- Raw EventData preservation (AllFieldInfo)

```python
from parsers import get_registry

registry = get_registry()
parser = registry.get_parser('evtx', case_id=123, source_host='DC01')
for event in parser.parse('/path/to/Security.evtx'):
    print(event.rule_title, event.mitre_tags)
```

#### Dissect Parsers (`dissect_parsers.py`)
Based on Fox-IT's [Dissect framework](https://docs.dissect.tools/):

| Parser | Artifact | Description |
|--------|----------|-------------|
| `PrefetchParser` | `.pf` files | Windows Prefetch with execution timestamps |
| `RegistryParser` | Registry hives | SAM, SECURITY, SOFTWARE, SYSTEM, NTUSER.DAT |
| `LnkParser` | `.lnk` files | Shortcut target paths and timestamps |
| `JumpListParser` | Jump Lists | Recent/pinned application destinations |
| `MFTParser` | `$MFT` | NTFS file system metadata |
| `SRUMParser` | `SRUDB.dat` | System Resource Usage Monitor |

#### Log Parsers (`log_parsers.py`)

| Parser | Format | Description |
|--------|--------|-------------|
| `IISLogParser` | W3C Extended | IIS web server logs |
| `FirewallLogParser` | Syslog/KV | SonicWall, pfSense, generic firewalls |
| `HuntressParser` | NDJSON | Huntress EDR exports |
| `GenericJSONParser` | JSON/NDJSON | Fallback for JSON logs |
| `CSVLogParser` | CSV | Generic CSV logs |

### 2. Parser Registry (`registry.py`)

Central registry for automatic file type detection and parser routing:

```python
from parsers import get_registry, process_file, process_directory

# Auto-detect and process single file
result = process_file('/path/to/artifact', case_id=123)
print(f"Parsed {result.events_count} events")

# Process entire directory
results = process_directory('/staging/case123/', case_id=123)
```

### 3. Celery Tasks (`/tasks/`)

Async processing for web-triggered operations:

```python
from tasks import parse_file_task, process_case_files_task

# Queue single file
task = parse_file_task.delay(
    file_path='/path/to/file.evtx',
    case_id=123,
    source_host='DC01'
)

# Queue all pending files for a case
task = process_case_files_task.delay(case_uuid='abc-123')
```

### 4. ClickHouse Schema (`/docs/clickhouse_schema.sql`)

Optimized schema for forensic event storage:

- **Partitioned by** `(case_id, artifact_type)` for fast pruning
- **Ordered by** `(case_id, artifact_type, source_host, timestamp)`
- **Indexed** with n-gram and bloom filters for text search
- **Buffer table** for high-speed ingestion

## Installation

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install Hayabusa

```bash
# Run installation script
chmod +x bin/install_hayabusa.sh
./bin/install_hayabusa.sh

# Or manually
wget https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-linux-x64.zip
unzip hayabusa-linux-x64.zip -d bin/
chmod +x bin/hayabusa
bin/hayabusa update-rules -r rules/hayabusa-rules
```

### 3. Create ClickHouse Schema

```bash
clickhouse-client < docs/clickhouse_schema.sql
```

### 4. Start Celery Worker

```bash
# Start worker
celery -A tasks worker --loglevel=info -Q parsing,maintenance,default

# Start beat scheduler (for rule updates)
celery -A tasks beat --loglevel=info
```

## API Endpoints

### Parsing Routes (`/api/parsing/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/detect-type` | Detect artifact type of a file |
| `GET` | `/parsers` | List available parsers |
| `POST` | `/process/file` | Queue single file for parsing |
| `POST` | `/process/case` | Queue all pending files for case |
| `POST` | `/process/staging` | Process staging directory |
| `GET` | `/task/<id>` | Get task status |
| `GET` | `/stats/<case_uuid>` | Get event statistics |
| `DELETE` | `/delete-events/<case_uuid>` | Delete case events |
| `GET` | `/files/<case_uuid>` | Get file parsing status |
| `POST` | `/update-rules` | Update Hayabusa rules |

## Configuration

Environment variables or `config.py`:

```python
# Hayabusa
HAYABUSA_BIN = '/opt/casescope/bin/hayabusa'
HAYABUSA_RULES = '/opt/casescope/rules/hayabusa-rules'
HAYABUSA_PROFILE = 'all-field-info'  # or 'super-verbose'
HAYABUSA_MIN_LEVEL = 'informational'  # informational, low, medium, high, critical

# ClickHouse
CLICKHOUSE_HOST = 'localhost'
CLICKHOUSE_PORT = 8123
CLICKHOUSE_DATABASE = 'casescope'
CLICKHOUSE_USE_BUFFER = True

# Parser
PARSER_BATCH_SIZE = 10000
PARSER_MAX_MFT_ENTRIES = 100000

# Celery
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
```

## Adding Custom Parsers

1. Create parser class inheriting from `BaseParser`:

```python
from parsers.base import BaseParser, ParsedEvent

class CustomParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'custom'
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        return file_path.endswith('.custom')
    
    def parse(self, file_path: str):
        # Parse file and yield ParsedEvent objects
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=datetime.now(),
            source_file=os.path.basename(file_path),
            source_host=self.source_host,
            # ... other fields
        )
```

2. Register in `registry.py`:

```python
from parsers.custom_parser import CustomParser

self.register(FileTypeMapping(
    artifact_type='custom',
    parser_class=CustomParser,
    extensions=['.custom'],
    priority=50,
))
```

## ClickHouse Query Examples

```sql
-- All detections for a case
SELECT timestamp, source_host, rule_title, rule_level, username, command_line
FROM events
WHERE case_id = 123 AND rule_title IS NOT NULL
ORDER BY timestamp;

-- Hunt by MITRE technique
SELECT *
FROM events
WHERE case_id = 123 AND has(mitre_tags, 'T1059.001')
ORDER BY timestamp;

-- Full-text search
SELECT *
FROM events
WHERE case_id = 123 
  AND positionCaseInsensitive(search_blob, 'mimikatz') > 0
ORDER BY timestamp;

-- Timeline by artifact type
SELECT 
    toStartOfHour(timestamp) as hour,
    artifact_type,
    count() as events
FROM events
WHERE case_id = 123
GROUP BY hour, artifact_type
ORDER BY hour;

-- Top triggered rules
SELECT rule_title, rule_level, count() as hits
FROM events
WHERE case_id = 123 AND rule_title IS NOT NULL
GROUP BY rule_title, rule_level
ORDER BY hits DESC
LIMIT 20;
```

## Performance Tuning

### Hayabusa
- Use `--min-level medium` to reduce noise
- Profile `all-field-info` balances detail vs size
- Enable GeoIP with `-G /path/to/maxmind/` for IP enrichment

### ClickHouse
- Buffer table absorbs write spikes
- Batch inserts at 10K rows
- Partition pruning: always filter by `case_id`
- Use `positionCaseInsensitive` for text search (uses n-gram index)

### Celery
- 1 task at a time per worker (`worker_prefetch_multiplier=1`)
- Separate queues for parsing vs maintenance
- Late ACK prevents lost tasks on worker crash

## Troubleshooting

### Hayabusa not found
```bash
# Check binary location
ls -la /opt/casescope/bin/hayabusa

# Test manually
/opt/casescope/bin/hayabusa --version
```

### ClickHouse connection failed
```bash
# Test connection
clickhouse-client -q "SELECT 1"

# Check events table
clickhouse-client -q "DESCRIBE casescope.events"
```

### Parser not detecting file type
```python
from parsers import get_registry

registry = get_registry()
# Check detected type
print(registry.detect_type('/path/to/file'))
# List available parsers
print(registry.list_parsers())
```

### Celery tasks stuck
```bash
# Check worker status
celery -A tasks inspect active

# Purge queue (careful!)
celery -A tasks purge
```
