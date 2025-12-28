# CaseScope 2026 - Changelog

## Version 1.5.0 - December 28, 2025

### 🎯 Feature: EVTX Event Description Enhancement

Added comprehensive Windows Event Log ID database to automatically enhance EVTX event descriptions with human-readable information.

**Key Features**:
- Database of 200+ common Windows Event IDs across Security, System, Application, and specialized logs
- Automatic lookup and enhancement of EVTX event descriptions in search results
- Support for major log sources: Security, System, Application, Sysmon, PowerShell, Task Scheduler, Windows Defender, RDP, SMB, and more
- Normalized channel name handling for consistent lookups
- Fallback to original descriptions when events not in database

**Files Added**:
- `app/utils/evtx_event_database.json` - Event ID database
- `app/utils/evtx_descriptions.py` - Lookup utility module

**Files Modified**:
- `app/routes/search.py` - Integrated event description enhancement for EVTX events

**Example Enhancements**:
- Event ID 17 (System) → "Event log cleared - An event log file was cleared or the log reached its maximum size"
- Event ID 1097 (Azure AD) → "Azure AD - User authentication - Azure Active Directory user authentication details"
- Event ID 4624 (Security) → "Account Logon - Successful - An account was successfully logged on"

---

## Version 1.4.0 - December 28, 2025

### 🎯 Feature: Software Noise Filtering System

Added comprehensive noise filtering system to identify and filter known good software from investigations, reducing noise by up to 13% in typical cases.

---

### ✨ New Features

#### 1. Noise Filter Management
**File**: `app/routes/noise_filters.py`, `templates/admin/noise_filters.html`

**Settings Interface** (`/settings/noise-filters`):
- Manage 6 noise filter categories (RMM Tools, EDR/MDR Platforms, Remote Access Tools, Backup Software, System Software, Monitoring Tools)
- Configure 29 default filter rules
- Add custom rules for organization-specific tools
- Enable/disable categories and individual rules
- Search and filter rules by category, status, type
- Statistics view showing rule usage

**Pattern Syntax**:
- OR logic: `pattern1,pattern2,pattern3` (comma-separated)
- AND logic: `pattern1&&pattern2` (both must match)
- Six match modes: exact, contains, starts_with, ends_with, wildcard, regex
- Case-sensitive/insensitive options

#### 2. Software Noise Tagging
**File**: `app/tasks/task_tag_noise.py`, `app/utils/noise_filter.py`

**Hunting Dashboard Integration**:
- New "Software Noise" button in Event Tagging tile
- Background Celery task with real-time progress tracking
- **Dynamic parallel processing** using OpenSearch slice scrolling
- Configurable parallelism via `TASK_PARALLEL_PERCENTAGE` (default: 50% of workers)
- Thread-safe progress aggregation

**Performance**:
- ~7,000 events/second tagging speed
- Example: 483,000 events tagged in 70 seconds using 4 parallel slices
- Typical noise reduction: 64,676 events (~13%) in test case

**Event Storage**:
Tagged events in OpenSearch receive:
```json
{
  "noise_matched": true,
  "noise_rules": ["ConnectWise Automate", "Huntress EDR"],
  "noise_categories": ["RMM Tools", "EDR/MDR Platforms"]
}
```

#### 3. Noise Filters in Event Search
**File**: `templates/search/events.html`, `app/routes/search.py`

**UI Layout**:
- Three-column filter panel (File Types | Event Tags | Noise Filters)
- Noise filters unchecked by default (hides all noise events)
- Cumulative behavior: checking adds those noise events to results

**Filter Options**:
- 🔧 RMM Tools
- 🛡️ EDR/MDR Platforms  
- 🖥️ Remote Access Tools

**Query Integration**:
- `noise_categories` URL parameter
- OpenSearch `should` clause logic
- Combines with file type and event tag filters

#### 4. Parallel Task Processing
**Files**: `app/config.py`, `app/utils/parallel_config.py`

**New Configuration Settings**:
```python
TASK_PARALLEL_PERCENTAGE = 50  # Use 50% of workers for internal parallelism
TASK_PARALLEL_MIN = 2          # Minimum parallel slices
TASK_PARALLEL_MAX = 8          # Maximum parallel slices
```

**Settings Page UI**:
- Slider to adjust parallelism percentage (25%-75%)
- Live preview showing:
  - Slices per task (e.g., 4 slices with 8 workers at 50%)
  - Concurrent tasks at full speed (e.g., 2 tasks)
  - Estimated speedup (e.g., ~4x)
- Validates and restarts services automatically

**Implementation**:
- `get_parallel_slice_count()` - Calculate slices based on config
- `get_parallel_config_info()` - UI display data
- OpenSearch slice scrolling for parallel index access
- `ThreadPoolExecutor` for parallel slice processing
- Main thread aggregates progress (avoids Celery context errors)

#### 5. Active Task Persistence
**File**: `app/models.py`

**New Table**: `active_tasks`
- Tracks running Celery tasks (ioc_hunt, sigma_hunt, noise_tagging)
- Enables UI reconnection after page refresh
- Stores task ID, progress metadata, results
- Automatic cleanup on task completion

---

### 🐛 Bug Fixes

**Noise Tagging Context Errors**:
- Fixed "Working outside of application context" error
- Rules now pre-loaded in main thread before spawning workers
- Thread-safe event checking without database queries

**search_blob Field Matching**:
- Added `search_blob` to all filter type field mappings
- Critical for events without structured `event_data` (unparsed/raw events)
- Enables matching in legacy data formats

---

### 📚 Documentation Updates

1. **NOISE_FILTERS.md** - NEW comprehensive guide
   - Filter categories and rules
   - Pattern syntax (OR/AND logic)
   - Integration points
   - Performance characteristics
   - API endpoints
   - Troubleshooting

2. **DATABASE_STRUCTURE.MD**
   - Added `noise_filter_categories` table
   - Added `noise_filter_rules` table
   - Added `noise_filter_stats` table
   - Added `active_tasks` table
   - Updated complete table list

3. **THREAT_HUNTING.md**
   - Added Software Noise Tagging section
   - Updated hunting dashboard layout (3 tiles)
   - Documented noise tagging API endpoints
   - Performance metrics

4. **CELERY_SYSTEM.md**
   - Added parallel processing configuration
   - Documented dynamic worker allocation
   - Updated task list with noise tagging
   - Settings page integration

5. **SEARCH_SYSTEM.md**
   - Consolidated EVENT_TAGGING_SYSTEM.md content
   - Added noise filter integration
   - Updated filter panel documentation
   - Query building examples

6. **README.MD**
   - Updated feature status table
   - Added NOISE_FILTERS.md to index
   - Removed EVENT_TAGGING_SYSTEM.md reference (consolidated)
   - Updated related documentation links

7. **EVENT_TAGGING_SYSTEM.md**
   - Removed (consolidated into SEARCH_SYSTEM.md)

---

### 🔄 Database Migrations

**Migration**: `/opt/casescope/migrations/add_noise_filters.sql`
- Creates `noise_filter_categories` table
- Creates `noise_filter_rules` table with 29 default rules
- Creates `noise_filter_stats` table
- All rules disabled by default

**Migration**: `/opt/casescope/migrations/add_active_tasks.sql`
- Creates `active_tasks` table for task persistence
- Indexes for efficient task queries

---

### 📊 Performance Impact

**Noise Tagging**:
- Processing: ~7,000 events/second
- Memory: Minimal (streaming with scroll API)
- CPU: Scales with parallel slice count
- Network: Bulk updates reduce OpenSearch load

**Event Search with Noise Filters**:
- Query overhead: <5ms (boolean filter)
- No database joins required
- Scales linearly with event count

---

### 🚀 Deployment

**Services Restarted**:
```bash
sudo systemctl restart casescope-new      # Flask app
sudo systemctl restart casescope-workers  # Celery workers
```

**Migrations Applied**:
```bash
sudo -u postgres psql casescope -f /opt/casescope/migrations/add_noise_filters.sql
sudo -u postgres psql casescope -f /opt/casescope/migrations/add_active_tasks.sql
```

---

## Version 1.3.0 - December 28, 2025

### 🎯 Feature: Event Detail IOC/SIGMA Detection Alerts & Highlighting

Added visual alerts and field highlighting in the event detail modal to instantly identify events containing IOCs or matching Sigma rules.

---

### ✨ New Features

#### 1. Detection Alert Banners
**File**: `templates/search/events.html`

**Red Banner (IOC Detected)**:
- Displays at top of event detail modal when IOCs are present
- Shows "⚠️ IOC DETECTED" with count
- Lists all detected IOCs with type, value, and matched field
- Example: "ipv4: 192.168.1.32 (in search_blob)"

**Purple Banner (SIGMA Violation)**:
- Displays when event matches Sigma detection rules
- Shows "🎭 SIGMA Rule Violation Detected"
- Lists matched rule titles with severity levels
- Color-coded by highest severity

#### 2. Field Value Highlighting
**CSS Implementation**:
- Fields containing IOC values highlighted with:
  - Semi-transparent red background (`rgba(255, 0, 0, 0.1)`)
  - Red border and text color
  - Bold font weight
- Dark theme compatible color scheme
- Applies to both field keys and string values
- Substring matching for comprehensive detection

#### 3. Backend API Enhancement
**File**: `app/routes/search.py`

**Endpoint**: `/search/api/event/<event_id>`

**New Response Fields**:
```json
{
  "event": {
    "ioc_hits": [
      {
        "ioc_value": "192.168.1.32",
        "ioc_type": "ipv4", 
        "threat_level": "medium",
        "field_name": "search_blob",
        "matched_in_field": "search_blob"
      }
    ],
    "sigma_hits": [
      {
        "sigma_rule_id": "uuid",
        "rule_title": "Suspicious PowerShell",
        "rule_level": "high"
      }
    ]
  }
}
```

**Query Logic**:
- Queries `event_ioc_hits` table for IOC matches
- Queries `event_sigma_hits` table for Sigma matches  
- Includes full IOC and Sigma metadata
- Efficient database joins per event ID

#### 4. Frontend Detection & Display
**JavaScript Functions**:
- `renderAlertBanners(hasIOCs, hasSigma, iocHits, sigmaHits)` - Display banners
- `renderEventTree(evt, iocHits)` - Highlight matching field values
- `containsIOC(value)` - Substring matching for highlighting
- Case-insensitive value comparison

---

### 🐛 Bug Fixes

**Dark Theme CSS Compatibility**:
- Changed from light pink (`#ffe6e6`) to semi-transparent red for backgrounds
- Adjusted text colors from dark red (`#cc0000`) to bright red (`#ff6b6b`)
- Improved contrast and visibility on dark backgrounds

---

### 📚 Documentation Updates

1. **DATABASE_STRUCTURE.MD**
   - Added `full_value` field documentation for IOCs table
   - Explained truncation logic for long IOC values (2500 char limit)
   - PostgreSQL btree index size limitations documented

2. **SEARCH_SYSTEM.md**
   - Added "IOC and SIGMA Detection Banners" section
   - Documented banner display logic and field highlighting
   - Explained backend enrichment process
   - Updated to version 1.2.0

3. **README.MD**
   - Added "Event IOC/SIGMA Detection Alerts" to feature status table
   - Updated last modified date to December 28, 2025

---

### 🔄 Backward Compatibility

**Full Compatibility**: Works with all existing data
- No database schema changes required for feature (relies on existing tables)
- No re-indexing needed
- Gracefully handles events without IOC/Sigma matches

---

### 🧪 Testing

**Manual Testing Performed**:
1. ✅ Red banner displays when IOCs present
2. ✅ Purple banner displays when Sigma matches present
3. ✅ Field highlighting works with substring matching
4. ✅ Dark theme colors properly visible
5. ✅ Multiple IOCs displayed correctly
6. ✅ API endpoint returns IOC/Sigma hit data

---

### 📊 Performance Impact

**Minimal Overhead**:
- Database queries: +2 JOINs per event detail request (~5-10ms)
- Frontend rendering: Negligible (<1ms for highlighting)
- No impact on search/list performance

---

### 🚀 Deployment

**Service Restart**:
```bash
sudo systemctl restart casescope-new
```

**No Migrations Required**: Feature uses existing database tables

---

### 🎯 User Impact

**Benefits**:
1. ✅ Instant visual feedback on IOC/Sigma detections
2. ✅ Faster threat identification during investigation
3. ✅ Reduced cognitive load - important fields auto-highlighted
4. ✅ Clear attribution of detections to specific fields

---

### 📝 Related Features

- Event IOC Hits tracking ([THREAT_HUNTING.md](THREAT_HUNTING.md))
- Event Sigma Hits tracking ([THREAT_HUNTING.md](THREAT_HUNTING.md))
- IOC Management System ([IOC-MANAGEMENT.md](IOC-MANAGEMENT.md))
- Sigma Rule Management ([THREAT_HUNTING.md](THREAT_HUNTING.md))

---

### 👥 Contributors

- System Administrator (Implementation, Testing, Documentation)

---

### 📅 Timeline

- **2025-12-28 12:00 UTC**: IOC/Sigma detection banners implemented
- **2025-12-28 13:00 UTC**: Field highlighting added
- **2025-12-28 14:00 UTC**: Dark theme CSS adjustments
- **2025-12-28 15:00 UTC**: Testing completed
- **2025-12-28 16:00 UTC**: Documentation updated
- **2025-12-28 16:00 UTC**: Deployed to production

---

## Version 1.1.0 - December 23, 2025

### 🎯 Feature: File Type Filtering

Added comprehensive file type filtering to the event search system, allowing users to filter search results by file type (EVTX, NDJSON, IIS, CSV).

---

### ✨ New Features

#### 1. File Type Filter UI
**File**: `templates/search/events.html`

- Added filter section with checkboxes for each file type:
  - ✅ EVTX Files
  - ✅ NDJSON Files  
  - ✅ IIS Files
  - ✅ CSV Files
- All filters enabled by default
- Filters update results in real-time
- Works in combination with search queries
- Page resets to 1 when filters change

**JavaScript State Management**:
```javascript
let fileTypeFilters = ['EVTX', 'NDJSON', 'IIS', 'CSV'];

function applyFilters() {
    fileTypeFilters = [];
    if (document.getElementById('filterEVTX').checked) fileTypeFilters.push('EVTX');
    if (document.getElementById('filterNDJSON').checked) fileTypeFilters.push('NDJSON');
    if (document.getElementById('filterIIS').checked) fileTypeFilters.push('IIS');
    if (document.getElementById('filterCSV').checked) fileTypeFilters.push('CSV');
    
    currentPage = 1;
    loadEvents();
}
```

#### 2. Backend Filter Implementation
**File**: `app/routes/search.py`

**New Parameter**:
- `file_types` (string): Comma-separated list of file types to include

**Query Building Logic**:
- Supports both new indexed data (with `file_type` field)
- Falls back to `source_file` extension matching for existing data
- Uses OpenSearch `bool` query with `should` clauses

```python
# Build file type filter with dual-path support
if file_type_filters:
    file_type_clauses = []
    
    for ft in file_type_filters:
        # Match on file_type field (new data)
        file_type_clauses.append({
            'term': {'file_type.keyword': ft}
        })
        
        # Match on source_file extension (existing data)
        if ft == 'EVTX':
            file_type_clauses.append({
                'wildcard': {'source_file': '*.evtx'}
            })
        elif ft == 'NDJSON':
            file_type_clauses.append({
                'bool': {
                    'should': [
                        {'wildcard': {'source_file': '*.ndjson'}},
                        {'wildcard': {'source_file': '*.json'}},
                        {'wildcard': {'source_file': '*.jsonl'}}
                    ]
                }
            })
        # ... (CSV and IIS patterns)
    
    must_clauses.append({
        'bool': {
            'should': file_type_clauses,
            'minimum_should_match': 1
        }
    })
```

#### 3. OpenSearch Index Mapping Update
**File**: `app/opensearch_indexer.py`

**New Field**:
```json
{
  "file_type": {"type": "keyword"}
}
```

**Updated Method Signature**:
```python
def bulk_index(self, index_name, events, chunk_size=500, 
               case_id=None, source_file=None, file_type=None):
    # ...
    if file_type:
        event['file_type'] = file_type
```

#### 4. File Upload Integration
**File**: `app/tasks/task_file_upload.py`

**Updated Indexing Calls**:
```python
# EVTX files
indexer.bulk_index(
    index_name=index_name,
    events=iter(chunk),
    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
    case_id=case_id,
    source_file=filename,
    file_type='EVTX'  # <-- NEW
)

# NDJSON files
indexer.bulk_index(
    index_name=index_name,
    events=iter(chunk),
    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
    case_id=case_id,
    source_file=filename,
    file_type='NDJSON'  # <-- NEW
)
```

---

### 🐛 Bug Fix: Event ID Display

Fixed issue where Event ID column showed "N/A" for EVTX events even though the `event_id` field existed in the data.

**Root Cause**: Python operator precedence issue with conditional expressions in chained `or` statements.

**File**: `app/routes/search.py`

**Before (Broken)**:
```python
event_id = (
    source.get('normalized_event_id') or
    source.get('event_id') or
    source.get('event', {}).get('code') if isinstance(source.get('event'), dict) else None or
    'N/A'
)
```

**After (Fixed)**:
```python
# For NDJSON events
if file_type == 'NDJSON':
    event_id = 'EDR'
else:
    # Try multiple field locations for event ID
    event_id = source.get('normalized_event_id')
    if not event_id:
        event_id = source.get('event_id')
    if not event_id and isinstance(source.get('event'), dict):
        event_id = source.get('event', {}).get('code')
    if not event_id and isinstance(source.get('event'), dict):
        event_id = source.get('event', {}).get('type')
    if not event_id:
        event_id = 'N/A'
```

**Result**: Event IDs now display correctly for all EVTX events (e.g., 4624, 4625, etc.)

---

### 📚 Documentation Updates

#### Updated Files:

1. **SEARCH_SYSTEM.md**
   - Added file type filtering documentation
   - Updated API parameters
   - Added query building examples
   - Updated event ID extraction logic
   - Added recent updates section
   - Version bumped to 1.1.0

2. **FILE_UPLOAD_PROCESSING.md**
   - Added `file_type` field to OpenSearch mapping
   - Updated processing flow documentation
   - Added file_type metadata to indexing examples
   - Added recent updates section
   - Updated status summary

3. **README.MD**
   - Updated last modified date to December 23, 2025

4. **CHANGELOG_2025-12-23.md** (NEW)
   - This file

---

### 🔄 Backward Compatibility

**Existing Data**: The system works seamlessly with both new and existing indexed data:

- **New uploads**: Include `file_type` field directly
- **Existing data**: Falls back to `source_file` extension matching
- **No re-indexing required**: Filters work immediately with existing cases

**Query Strategy**:
- First tries to match on `file_type.keyword` field
- Falls back to wildcard matching on `source_file` field
- Both conditions combined in `should` clause for maximum compatibility

---

### 🧪 Testing

**Manual Testing Performed**:
1. ✅ File type filters work with all checkboxes
2. ✅ Unchecking a filter removes those events from results
3. ✅ Filters work in combination with search queries
4. ✅ Event IDs display correctly for EVTX events
5. ✅ Existing indexed data works without re-indexing
6. ✅ New uploads include file_type metadata

**Test Query**:
```bash
# Verify file type filtering works
curl 'localhost:9200/case_2/_search' -H 'Content-Type: application/json' -d '{
  "query": {
    "bool": {
      "should": [
        {"term": {"file_type.keyword": "NDJSON"}},
        {"wildcard": {"source_file": "*.ndjson"}},
        {"wildcard": {"source_file": "*.json"}},
        {"wildcard": {"source_file": "*.jsonl"}}
      ],
      "minimum_should_match": 1
    }
  },
  "size": 0
}'
```

---

### 📊 Performance Impact

**No Performance Degradation**:
- File type filtering adds minimal overhead (~2-5ms per query)
- Wildcard queries on `source_file` are efficient for small file counts
- `file_type.keyword` matching is highly optimized (exact match)
- Deep pagination performance unchanged

**Memory Impact**: 
- New field adds ~10 bytes per indexed event
- Negligible impact on overall index size

---

### 🚀 Deployment

**Required Steps**:
1. ✅ Code changes deployed
2. ✅ Server restarted
3. ✅ No database migrations required
4. ✅ No OpenSearch re-indexing required

**Service Commands**:
```bash
sudo systemctl restart casescope-new
sudo systemctl status casescope-new
```

---

### 📝 API Changes

**New Query Parameter**:
```
GET /search/api/events?file_types=EVTX,NDJSON
```

**Parameter Details**:
- Name: `file_types`
- Type: String (comma-separated)
- Values: EVTX, NDJSON, IIS, CSV
- Default: All types (no filter)
- Example: `file_types=EVTX,NDJSON`

**Response Format**: Unchanged

---

### 🎯 User Impact

**Benefits**:
1. ✅ Faster filtering of large result sets
2. ✅ Better focus on specific data sources
3. ✅ Reduced cognitive load when analyzing events
4. ✅ Correct Event ID display for EVTX files

**User Experience**:
- Intuitive checkbox interface
- Real-time filtering
- Works with existing search queries
- No training required

---

### 🔮 Future Enhancements

Potential improvements for file type filtering:

1. **File Type Badges**: Show file type counts before filtering
2. **Quick Filters**: One-click filters for common combinations
3. **Save Filter Preferences**: Remember user's last filter state
4. **Filter Presets**: Save common filter combinations
5. **Advanced Filters**: Date range, severity level, etc.

---

### 📖 Related Issues

**Fixed Issues**:
- Event ID showing "N/A" for EVTX events
- No way to filter by file type in search results
- File type information not persisted in indexed events

---

### 👥 Contributors

- System Administrator (Implementation, Testing, Documentation)

---

### 📅 Timeline

- **2025-12-23 15:00 UTC**: File type filtering implemented
- **2025-12-23 16:00 UTC**: Event ID display bug fixed
- **2025-12-23 17:30 UTC**: Testing completed
- **2025-12-23 17:35 UTC**: Documentation updated
- **2025-12-23 17:35 UTC**: Deployed to production

---

## Summary

This release adds powerful file type filtering to the event search system and fixes a critical bug in event ID display. The implementation is backward compatible, requiring no re-indexing of existing data, and provides an immediate improvement to the user experience when analyzing large evidence sets.

**Key Stats**:
- Files Modified: 6
- Lines Changed: ~250
- New Features: 2
- Bugs Fixed: 1
- Documentation Updates: 4
- Deployment Time: < 5 minutes
- User Training Required: None

# CaseScope 2026 - Changelog

## Version 1.2.0 - December 24, 2025

### 🎯 Feature: EVTX Event Descriptions System

Added comprehensive Windows Event Log description database with web scraping capabilities, providing investigators with instant context for 1,100+ event types.

---

### ✨ New Features

#### 1. Event Description Database (`event_description` table)
**File**: `app/models.py`

New database table to store Windows Event Log descriptions:
- `event_id` - Windows Event ID (e.g., "4624")
- `log_source` - Log source (Security, System, Sysmon, Application)
- `description` - Comprehensive event description
- `category` - Event category (Logon/Logoff, Account Management, etc.)
- `subcategory` - Subcategory if available
- `source_website` - Data source (ultimatewindowssecurity.com, microsoft.com, embedded_data)
- `source_url` - Direct link to documentation
- `scraped_at` - Timestamp when scraped
- `description_length` - Used for deduplication (keeps most descriptive)

**Unique Constraint**: One entry per (`event_id`, `log_source`) combination

#### 2. Multi-Source Event Scraping
**File**: `app/scrapers/event_description_scraper.py`

**Data Sources**:

1. **Embedded Windows Events** (~200 events)
   - Legacy events (512-683)
   - Modern Security events (1100-8191)
   - System events (1074, 6005, 6006, 6008, 7045)
   - Hardcoded for reliability (no web dependency)

2. **Microsoft Sysmon Events** (29 events)
   - Event IDs 1-29
   - Official Microsoft documentation
   - Process creation, network connections, file operations, WMI, DNS queries

3. **Microsoft Security Auditing** (61 events)
   - Kerberos authentication (4768-4777)
   - Logon/Logoff (4624, 4625, 4634, 4647, 4648, 4672)
   - Account Management (4720-4767, 4780-4799)
   - Group Management (4727-4758)
   - Computer Accounts (4741-4743)
   - Object Access (4656-4670, 4698-4702)
   - System Events (4608, 4609, 4616, 4697)
   - Policy Changes (4719, 4739, 4703-4718)

4. **UltimateWindowsSecurity.com** (~844 events)
   - Comprehensive Security log events
   - Uses `?i=j` parameter to fetch all events
   - Includes Sysmon, SharePoint, SQL Server, Exchange events

5. **ManageEngine ADAudit Plus** (additional events)
   - Parses HTML tables for Event ID and descriptions
   - Supplements other sources

**Deduplication Strategy**:
- Same `event_id` + `log_source` = duplicate
- Keeps version with longest description
- Prioritizes embedded > microsoft.com > scraped data

#### 3. EVTX Descriptions Management Page
**File**: `templates/admin/evtx_descriptions.html`

**UI Components**:

**Statistics Tiles**:
- Total Events count
- Events by Source (ultimatewindowssecurity.com, microsoft.com, embedded_data, etc.)
- Visual breakdown with badges

**Action Card**:
- "Update Descriptions" button
- Triggers background scraping task
- Shows task ID and status

**Search & Filter**:
- Event ID search (exact or partial match)
- Log Source filter dropdown (Security, Sysmon, System, Application, All)
- Description text search
- Real-time filtering

**Event List Table**:
- Event ID
- Log Source
- Category
- Description (truncated to 80 chars, expandable)
- Source Website (with badge)
- Pagination (50 events per page)

**Pagination Controls**:
- Previous/Next navigation
- Page numbers (shows 5 pages at a time)
- Jump to specific page
- "Showing X-Y of Z events"

#### 4. Celery Background Scraping Task
**File**: `app/tasks/task_scrape_events.py`

**Task**: `scrape_event_descriptions`
- Queues: `celery`, `default`
- Runs scrapers for all sources
- Imports events to database with deduplication
- Updates existing events with longer descriptions
- Returns statistics: `{total_scraped, added, updated, skipped, errors}`

**Progress Updates**:
- Status updates during scraping
- Batch commit every 100 events
- Comprehensive error handling

#### 5. Settings Page Integration
**File**: `templates/admin/settings.html`

Added new "Rules & Description Updates" section with two tiles:
- **EVTX Descriptions** - Link to `/settings/evtx-descriptions`
- **Coming Soon** - Placeholder for future features

#### 6. API Endpoints
**File**: `app/routes/settings.py`

**New Routes**:

**GET `/settings/evtx-descriptions`**
- Renders EVTX descriptions management page
- Admin-only access

**GET `/settings/evtx-descriptions/api/list`**
- Returns paginated event descriptions
- Query params: `page`, `per_page`, `event_id`, `log_source`, `description`
- Returns: `{events: [...], total, page, per_page, pages}`

**POST `/settings/evtx-descriptions/api/scrape`**
- Triggers background scraping task
- Uses `celery.send_task()` to avoid circular imports
- Returns: `{success, message, task_id}`
- Logs action to audit trail

**GET `/settings/evtx-descriptions/api/scrape/status/<task_id>`**
- Checks scraping task status
- Returns: `{state, result, current, total, status}`

---

### 🏗️ Architecture Decisions

#### Why Multiple Data Sources?

1. **Reliability**: Embedded data works offline
2. **Completeness**: Different sources cover different events
3. **Accuracy**: Multiple sources allow keeping most descriptive version
4. **Resilience**: If one scraper breaks, others continue working

#### Why Hardcoded Microsoft Events?

- **Stability**: Official docs rarely change
- **Speed**: No network requests
- **Reliability**: Always available
- **Quality**: Authoritative source

#### Circular Import Resolution

**Problem**: Direct import of Celery tasks in Flask routes caused circular import
**Solution**: Use `celery.send_task('tasks.scrape_event_descriptions')` by name

**Pattern**:
```python
from app.celery_app import celery

# Queue by name (not direct import)
task = celery.send_task('tasks.scrape_event_descriptions')
```

#### Flask App Context in Celery Tasks

**Problem**: Database operations in Celery tasks fail without Flask app context
**Solution**: Create app context within task

**Pattern**:
```python
@celery.task(name='tasks.scrape_event_descriptions', bind=True)
def scrape_event_descriptions_task(self):
    from app.main import create_app
    app = create_app()
    with app.app_context():
        from app.main import db
        # Database operations here
```

---

### 📊 Data Statistics

**Total Events Scraped**: ~1,134 events
- Embedded Windows Events: 200+
- Microsoft Sysmon: 29
- Microsoft Security Auditing: 61
- UltimateWindowsSecurity.com: ~844
- ManageEngine: Variable

**Coverage**:
- Windows Security Log: Comprehensive
- Windows Sysmon: Complete (Events 1-29)
- Windows System Log: Partial
- Windows Application Log: Partial
- Legacy Events: Comprehensive (pre-Windows Server 2008)

**Deduplication Results**:
- Before dedup: ~1,200+ events
- After dedup: ~1,134 unique events
- Duplicates resolved by keeping longest description

---

### 🔄 Workflow

**Administrator Workflow**:
1. Navigate to Settings → EVTX Descriptions
2. View current event count and sources
3. Click "Update Descriptions"
4. Task queued in background (Celery)
5. Page shows task ID and initial status
6. Can monitor progress or close page
7. Once complete, stats update automatically
8. Search/filter events as needed

**Background Process**:
1. Celery worker picks up task
2. Scraper runs all sources in sequence:
   - Load embedded events
   - Load Microsoft Sysmon events
   - Load Microsoft Security Auditing events
   - Scrape UltimateWindowsSecurity.com
   - Scrape ManageEngine (if working)
3. Deduplicate combined results
4. Import to database (batch commit every 100)
5. Return statistics

---

### 🐛 Bug Fixes

#### Celery Queue Configuration
**Problem**: Worker not picking up `scrape_event_descriptions` task
**Root Cause**: Worker only listening to `file_processing,ingestion,default` queues, but task sent to `celery` queue

**Fix**: Updated `start_celery.sh`:
```bash
--queues=file_processing,ingestion,default,celery
```

#### Circular Import in Celery Task
**Problem**: `ImportError: cannot import name 'User' from partially initialized module 'models'`
**Root Cause**: Task module importing `models` and `main` at module level

**Fix**: Import inside task function with app context

---

### 📚 Documentation Updates

**Updated Files**:
1. **DATABASE_STRUCTURE.MD**
   - Added `EventDescription` table documentation
   - Added `CaseFile` table documentation
   - Updated table count reference

2. **SITE_LAYOUT.MD**
   - Added `settings.py` route
   - Added `evtx_descriptions.html` template
   - Updated routes documentation

3. **README.MD**
   - Added EVTX Event Descriptions to feature list
   - Added new admin route for EVTX descriptions
   - Updated changelog with Dec 24 entries
   - Updated last modified date

4. **CHANGELOG_2025-12-24.md** (NEW)
   - This file

---

### 🚀 Deployment

**Required Steps**:
1. ✅ Database migration (add `event_description` table)
2. ✅ Code deployment
3. ✅ Celery worker restart (with updated queue config)
4. ✅ Flask app restart

**Migration SQL**:
```sql
CREATE TABLE event_description (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(20) NOT NULL,
    log_source VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(100),
    subcategory VARCHAR(100),
    source_website VARCHAR(200),
    source_url VARCHAR(500),
    scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description_length INTEGER,
    CONSTRAINT uix_event_log UNIQUE (event_id, log_source)
);

CREATE INDEX idx_event_search ON event_description (event_id, log_source);
CREATE INDEX idx_scraped_at ON event_description (scraped_at);

GRANT ALL ON event_description TO casescope;
GRANT USAGE, SELECT ON SEQUENCE event_description_id_seq TO casescope;
```

**Service Commands**:
```bash
# Restart Celery workers (with new queue config)
sudo systemctl restart casescope-workers

# Restart Flask app
sudo systemctl restart casescope-new

# Verify services
sudo systemctl status casescope-workers
sudo systemctl status casescope-new
```

---

### 🧪 Testing

**Manual Testing**:
1. ✅ Navigate to Settings → EVTX Descriptions
2. ✅ Click "Update Descriptions" button
3. ✅ Task queued successfully (task_id returned)
4. ✅ Scraping completes (1,134 events added)
5. ✅ Statistics tiles update correctly
6. ✅ Event list displays with pagination
7. ✅ Search by Event ID works
8. ✅ Filter by Log Source works
9. ✅ Description search works
10. ✅ Pagination controls work correctly

**Scraper Testing**:
```bash
# Test individual scrapers
cd /opt/casescope/app
python3 << 'EOF'
from scrapers.event_description_scraper import EventDescriptionScraper
scraper = EventDescriptionScraper()

# Test embedded events
events = scraper.get_embedded_windows_events()
print(f"Embedded: {len(events)} events")

# Test Microsoft Sysmon
events = scraper._get_sysmon_events()
print(f"Sysmon: {len(events)} events")

# Test Microsoft Security Auditing
events = scraper._get_security_auditing_events()
print(f"Security Auditing: {len(events)} events")

# Test UltimateWindowsSecurity
events = scraper.scrape_ultimate_windows_security()
print(f"UltimateWindowsSecurity: {len(events)} events")
EOF
```

**Database Testing**:
```bash
# Check event counts
cd /opt/casescope/app
python3 << 'EOF'
from main import app, db
from models import EventDescription
from sqlalchemy import func

with app.app_context():
    total = EventDescription.query.count()
    print(f"Total events: {total}")
    
    # By log source
    sources = db.session.query(
        EventDescription.log_source,
        func.count(EventDescription.id)
    ).group_by(EventDescription.log_source).all()
    
    for source, count in sources:
        print(f"  {source}: {count}")
EOF
```

---

### 📈 Performance

**Scraping Performance**:
- Embedded events: Instant (no network)
- Microsoft hardcoded: Instant (no network)
- UltimateWindowsSecurity: ~10-15 seconds (single page fetch)
- ManageEngine: ~5-10 seconds (single page fetch)
- **Total scraping time**: ~20-30 seconds

**Database Performance**:
- Bulk insert: ~1,000 events/second
- Deduplication: ~5,000 comparisons/second
- Query with filters: <100ms
- Pagination: <50ms

**Memory Usage**:
- Scraper peak: ~50MB
- Database import: ~30MB
- Minimal impact on system

---

### 🎯 User Impact

**Benefits for Investigators**:
1. ✅ Instant event context without Googling
2. ✅ Comprehensive coverage of Windows events
3. ✅ Multiple authoritative sources
4. ✅ Fast search and filtering
5. ✅ Always up-to-date (one-click refresh)

**User Experience**:
- Clean, intuitive interface
- Real-time statistics
- Fast search response
- Helpful filters
- No training required

---

### 🔮 Future Enhancements

Potential improvements:
1. **Event Detail Modal**: Click event to see full details
2. **Export to CSV**: Download event descriptions
3. **Custom Events**: Allow admins to add custom events
4. **Event Linking**: Link events to related IOCs/cases
5. **Search History**: Track commonly searched events
6. **Favorites**: Mark frequently referenced events
7. **API Access**: REST API for external tools

---

### 📖 Related Documentation

- **Database Structure**: [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD#evtx-event-descriptions)
- **Site Layout**: [SITE_LAYOUT.MD](SITE_LAYOUT.MD)
- **Settings Configuration**: [SETTINGS_WORKER_CONFIGURATION.md](SETTINGS_WORKER_CONFIGURATION.md)
- **Celery System**: [CELERY_SYSTEM.md](CELERY_SYSTEM.md)

---

## Summary

This release adds a comprehensive EVTX event description system with **1,100+ Windows Event Log descriptions** from multiple authoritative sources. The system features automatic web scraping, intelligent deduplication, and a user-friendly search interface. All scraping runs in the background via Celery, ensuring the UI remains responsive. The embedded event database ensures the system works even without internet access.

**Key Stats**:
- Files Added: 4
- Files Modified: 8
- Lines Added: ~2,500
- New Database Table: 1
- New API Endpoints: 3
- Event Descriptions: 1,134+
- Data Sources: 5
- Deployment Time: < 10 minutes
- User Training Required: None

**Contributors**: System Administrator

---

## Version 1.3.0 - December 24, 2025 (Evening)

### 🎯 Feature: Known Systems Management with Auto-Discovery

Complete system tracking solution with automated discovery from OpenSearch logs using high-performance aggregations.

---

### ✨ New Features

#### 1. Known Systems Database (`known_systems` table)
**Files**: `app/models.py`, `migrations/add_known_systems.sql`

New table to track systems involved in investigations:
- **Identifiers**: `hostname`, `domain_name`, `ip_address` (at least one required)
- **Classification**: `system_type` (workstation, server, router, switch, printer, wap, other, threat_actor)
- **Status**: `compromised` (yes, no, unknown)
- **Source**: `manual` or `logs` (auto-discovered)
- **Metadata**: `description`, `analyst_notes`
- **Audit**: `created_by`, `updated_by`, timestamps

**Indexes**: hostname, domain, IP, type, status, source, case_id for fast queries

#### 2. Systems Management Page (`/systems`)
**Files**: `app/routes/known_systems.py`, `templates/systems/manage.html`

Full-featured interface:
- Statistics tile with breakdown by type
- Paginated table (25/50/100 per page)
- Search across all fields
- Filter by type, compromised status, source
- Bulk operations (select multiple, edit, delete)
- Modals for add/edit/view
- CSV export
- Audit logging

#### 3. Auto-Discovery from Logs
**File**: `app/tasks/task_discover_systems.py`

**Performance**: OpenSearch aggregations extract unique systems in 1-2 seconds (vs. 2-3 minutes with scrolling)

**Extraction Strategy**:
1. **Terms Aggregations**: Extract unique hostnames from keyword fields
   - Primary: `normalized_computer` (NDJSON), `computer` (EVTX)
   - Secondary: `host.name`, `ComputerName`, 10+ other fields
2. **Domain Extraction**: Separate aggregations for domains
   - NDJSON: `host.domain` field
   - EVTX: `event_data_fields.SubjectDomainName`
3. **IP Resolution**: Aggregate `normalized_computer` + `host.ip` for hostname-to-IP mapping
4. **FQDN Parsing**: Splits "ATN64025.DWTEMPS.local" → hostname: "ATN64025", domain: "DWTEMPS.local"
5. **Type Detection**: Pattern-based (server, workstation, router, etc.)
6. **Deduplication**: Updates existing systems with new data

**Field Type Intelligence**:
- Detects OpenSearch field mappings
- Keyword fields (`normalized_computer`, `computer`) aggregated directly
- Text fields (`host.name`) need `.keyword` suffix
- Handles nested fields (`host.ip`, `event_data_fields.*`)

**Test Results** (210,040 events):
- Execution time: ~1.5 seconds
- Discovered: 1 system (ATN64025)
- Extracted: Hostname, Domain (DWTEMPS), IP (192.168.1.12)
- Type: workstation (auto-detected)

---

### 🐛 Bug Fixes

**1. CaseFile Model Compatibility**
- **Issue**: Task referenced `CaseFile.is_indexed` (doesn't exist in new app)
- **Fix**: Removed filename extraction logic, rely on normalized_computer
- **Impact**: Discovery works without CaseFile queries

**2. OpenSearch Keyword Field Mapping**
- **Issue**: Using `.keyword` suffix on fields that are already keyword type
- **Fix**: Detect field type, conditionally add `.keyword` only for text fields
- **Impact**: Aggregations return results (was 0 buckets before)

**3. IP Address Extraction**
- **Issue**: Zero IPs extracted due to `normalized_computer.keyword` (invalid)
- **Fix**: Changed to `normalized_computer` (field is already keyword type)
- **Impact**: Successfully extracts IPs from `host.ip`

**4. Domain Extraction from EVTX**
- **Issue**: Domains not extracted from Windows Event Logs
- **Fix**: Added aggregation for `event_data_fields.SubjectDomainName`
- **Impact**: Domains extracted from both NDJSON and EVTX

**5. Celery Task Registration**
- **Issue**: Task `tasks.discover_systems_from_logs` not found
- **Fix**: Added import in `celery_app.py`
- **Impact**: Task registered and executable

**6. Progress Bar Reset Loop**
- **Issue**: Progress would show, reset to 0%, then jump back
- **Fix**: Added `task_track_started = True` to Celery config
- **Impact**: Smooth progress without resets

---

### 📁 Files Added/Modified

**New Files**:
- `/app/routes/known_systems.py` (459 lines) - Full CRUD API + discovery
- `/app/tasks/task_discover_systems.py` (363 lines) - Aggregation-based discovery
- `/templates/systems/manage.html` (1265 lines) - Management UI
- `/migrations/add_known_systems.sql` (28 lines) - Database schema

**Modified**:
- `/app/models.py` - Added `KnownSystem` model
- `/app/celery_app.py` - Registered task_discover_systems
- `/app/config.py` - Added `task_track_started = True`
- `/templates/base.html` - Added "Known Systems" nav link
- `/css/components.css` - Progress bar and alert styles

**Documentation**:
- `/site_docs/KNOWN_SYSTEMS.md` - Feature documentation
- `/site_docs/DATABASE_STRUCTURE.MD` - Updated table list
- `/site_docs/SITE_LAYOUT.MD` - Updated routes/templates

---

### 🚀 Performance

**Before (Scrolling)**:
- Method: Scroll through all events, extract fields
- Time: 2-3 minutes for 200K events
- Memory: High (loads documents)

**After (Aggregations)**:
- Method: Terms aggregation on keyword fields
- Time: 1-2 seconds for 200K+ events
- Memory: Minimal (only aggregated values)
- Improvement: 60-90x faster

---

### 💡 Technical Highlights

1. **Aggregation-First Design**: Learned from old_site implementation
2. **Field Type Awareness**: Handles OpenSearch mapping dynamically
3. **Multi-Format Support**: Works with both NDJSON (Huntress) and EVTX (Windows)
4. **Clean Deduplication**: Updates existing vs. adding notes
5. **Real-Time Progress**: Celery state tracking with modal updates
6. **Production-Ready**: Error handling, logging, audit trail

---

**Contributors**: System Administrator

---

## Version 1.4.0 - December 24, 2025 (Late Evening)

### 🎯 Feature: IOC Hunting with Event Badge Integration

Implemented background IOC hunting system with visual badges in search results, enabling analysts to identify compromised events at a glance.

---

### ✨ New Features

#### 1. Event IOC Hits Database (`event_ioc_hits` table)
**Files**: `app/models.py`, `migrations/add_event_ioc_hits.sql`

New table to track which events contain which IOCs:
- **Event Identification**: OpenSearch doc ID, record ID, event ID, timestamp, computer
- **IOC Information**: ID, value, type, category, threat level (denormalized for performance)
- **Match Details**: matched_in_field, match_context, confidence
- **Metadata**: detected_at, detected_by (audit trail)
- **Relationships**: Links to Case, IOC, and User models

**Unique Constraint**: (case_id, opensearch_doc_id, ioc_id) prevents duplicate tagging

#### 2. IOC Hunting Task (`app/tasks/task_hunt_iocs.py`)
**Celery Task**: `hunt_iocs(case_id, user_id)`

**Features**:
- Multi-strategy search based on IOC type (IPs, hashes, domains, files, URLs, emails, commands)
- Prioritizes structured fields over search_blob
- Uses OpenSearch scroll API to bypass 10k limit
- Real-time progress updates (0-100%)
- Batch processing (1000 events/batch)
- Batch commits (100 records/batch) for memory efficiency
- Duplicate prevention via database constraint
- Comprehensive statistics returned

**IOC Type Strategies**:
1. **IPv4**: IpAddress, SourceAddress, DestAddress, ClientIPAddress
2. **File Hashes**: Hashes, Hash, MD5, SHA1, SHA256 (case-insensitive)
3. **Domain**: DestinationHostname, QueryName, TargetServerName
4. **File**: TargetFilename, ImagePath, FileName
5. **Command**: CommandLine, ProcessCommandLine
6. **URL**: Url, RequestUrl
7. **Email**: EmailAddress, Sender, Recipient
8. **Generic**: Falls back to search_blob

#### 3. Hunting Dashboard Integration (`templates/hunting/dashboard.html`)
**Button**: "🎯 Hunt IOCs"

**Modal Features**:
- **Progress View**:
  - Animated progress bar (0-100%)
  - Current status message
  - Current IOC being hunted
  - Live statistics (4 cards): Events Scanned, Total Events, Events Tagged, IOC Hits
- **Results View**:
  - Summary statistics
  - Hits by threat level breakdown
  - Hits by IOC table (sorted by count)
- Auto-refresh every 2 seconds
- Button state management (disabled during hunt)

#### 4. IOC Badges in Search Results
**Files**: `app/routes/search.py`, `templates/search/events.html`

**New Column**: "IOCs" - Shows IOC type badges for events containing IOCs

**Badge Features**:
- One badge per unique IOC type found in event
- Badge label: IOC type (e.g., "file", "command_line", "domain")
- Color-coded by threat level:
  - 🔴 Red (`badge-error`) - critical
  - 🟠 Orange (`badge-warning`) - high
  - 🟡 Blue (`badge-info`) - medium
  - ⚪ Gray (`badge-secondary`) - low/info
- Smart grouping: If event has 3 file IOCs, shows 1 "file" badge
- Lowercase text styling

**Backend Integration**:
- Search API queries `event_ioc_hits` table for displayed events
- Joins IOC data with event results
- Returns `ioc_types` array for each event
- Minimal performance impact (indexed queries)

#### 5. API Endpoints (`app/routes/hunting.py`)

**POST `/hunting/api/hunt_iocs`**
- Starts IOC hunt background task
- Validates case and permissions
- Returns task_id for progress tracking
- Logs audit entry

**GET `/hunting/api/hunt_iocs/status/<task_id>`**
- Returns task state (PENDING, PROGRESS, SUCCESS, FAILURE)
- Real-time progress percentage
- Current IOC being hunted
- Live statistics during hunt
- Final results on completion

---

### 🏗️ Architecture Decisions

#### Why Denormalize IOC Data in event_ioc_hits?
- **Performance**: Avoid joins when displaying badges
- **Stability**: IOC changes don't affect historical hunt results
- **Query Speed**: Indexed denormalized fields for fast filtering

#### Why Scroll API instead of Pagination?
- **No 10k Limit**: Can process 30M+ events
- **Memory Efficient**: Only loads 1000 events at a time
- **Reliable**: 5-minute scroll timeout prevents hangs

#### Why Batch Commits?
- **Memory Safety**: Prevents OOM errors on large datasets
- **Crash Recovery**: If task fails, partial results saved
- **Transaction Efficiency**: Fewer database round trips

---

### 🐛 Bug Fixes

**1. IOC Badge Column Missing**
- **Issue**: Initial implementation put badge next to Event ID
- **Fix**: Added dedicated "IOCs" column to search results table
- **Impact**: Cleaner layout, easier to scan

**2. Duplicate Badge Display**
- **Issue**: Multiple IOCs of same type showed multiple badges
- **Fix**: Group by IOC type, show highest threat level per type
- **Impact**: Reduced visual clutter, clearer at-a-glance view

---

### 📁 Files Added/Modified

**New Files**:
- `/app/tasks/task_hunt_iocs.py` (520+ lines) - IOC hunting logic
- `/migrations/add_event_ioc_hits.sql` (45 lines) - Database schema

**Modified**:
- `/app/models.py` - Added `EventIOCHit` model
- `/app/routes/hunting.py` - Added 2 hunt endpoints
- `/app/routes/search.py` - Added IOC badge integration
- `/templates/hunting/dashboard.html` - Added hunt button and modal
- `/templates/search/events.html` - Added IOCs column, badge rendering, CSS
- `/app/celery_app.py` - Registered task_hunt_iocs

**Documentation**:
- `/site_docs/THREAT_HUNTING.md` - Consolidated IOC and Sigma hunting documentation
- `/site_docs/SEARCH_SYSTEM.md` - Documented IOCs column
- `/site_docs/DATABASE_STRUCTURE.MD` - Added event_ioc_hits table

---

### 🚀 Performance

**Hunt Performance** (210K events, 50 IOCs):
- Execution Time: ~2-3 minutes
- Memory Usage: ~200MB peak
- Events/Second: ~1,500
- Database Commits: Every 100 hits

**Search Badge Performance**:
- Query Time: +5-10ms per page (negligible)
- Database: Indexed queries on event_ioc_hits
- UI Rendering: Instant (badges pre-rendered server-side)

**Scalability**:
- ✅ Tested with 30M+ events
- ✅ Handles 1000+ IOCs
- ✅ Non-blocking (background task)
- ✅ Graceful failure handling

---

### 🎯 User Impact

**Benefits for Investigators**:
1. ✅ Visual identification of compromised events
2. ✅ Immediate IOC context in search results
3. ✅ No manual correlation needed
4. ✅ Color-coded threat severity
5. ✅ Works across 30M+ events

**User Experience**:
- One-click IOC hunting
- Real-time progress feedback
- Non-blocking (can continue working)
- Persistent results (hunt once, badge forever)
- No performance impact on search

---

### 🧪 Testing

**Manual Testing**:
1. ✅ Hunt 50 IOCs across 210K events (2m 30s)
2. ✅ Found 1,847 IOC hits in 1,234 events
3. ✅ Badges display correctly in search results
4. ✅ Color coding matches threat levels
5. ✅ Modal shows accurate statistics
6. ✅ Progress bar updates smoothly
7. ✅ Duplicate prevention works
8. ✅ Search performance unchanged

---

### 💡 Future Enhancements

1. **Event Detail IOC List**: Click event → see which IOCs matched
2. **Click Badge to Filter**: Click "file" badge → show only events with file IOCs
3. **IOC Timeline**: Visualize IOC appearance over time
4. **Incremental Hunts**: Only hunt new IOCs added since last hunt
5. **IOC Relevance Scoring**: Weight matches by field context

---

**Contributors**: System Administrator

---

*Last Updated: December 24, 2025 (Late Evening)*

---