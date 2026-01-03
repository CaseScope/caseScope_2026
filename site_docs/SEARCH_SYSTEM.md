# CaseScope Event Search System

## Overview

The CaseScope search system provides a powerful, Google-like search interface for querying millions of events across EVTX and NDJSON files. It supports boolean operators, nested queries, deep pagination, and comprehensive event visualization.

**Key Features:**
- ✅ Boolean search operators (AND, OR, NOT)
- ✅ Parenthetical grouping for complex queries
- ✅ Full-text search across all event fields
- ✅ File type filtering (EVTX, NDJSON, IIS, CSV)
- ✅ Event tag filtering (Other, Tagged, IOC, SIGMA)
- ✅ **Noise filtering** ⭐ NEW (RMM, EDR/MDR, Remote Access)
- ✅ Sorted pagination (newest first by default)
- ✅ Deep pagination support (100K+ events)
- ✅ Event detail modal with expandable JSON tree
- ✅ Process tree visualization for NDJSON events
- ✅ Field-level copy and search actions
- ✅ Special character handling in search values
- ✅ Manual event tagging (star/unstar events)

---

## Architecture

```
Frontend (Browser)          Backend (Flask)                 Data Layer (OpenSearch)
──────────────────          ───────────────                 ─────────────────────
                           
Search Input ────────────> /search/api/events
                           ├─ Parse query
                           ├─ Build OpenSearch DSL ────> Query: case_{id}/_search
                           ├─ Handle pagination               ├─ search_blob field
                           └─ Format results <────────────── └─ Return matches
                           
Event Click ─────────────> /search/api/event/<id>
                           └─ Fetch full event ──────────> Get: case_{id}/_doc/{id}
                           
Modal Display
├─ Process Tree (NDJSON)
├─ Full Data (Tree View)
└─ Raw JSON
```

---

## Search Query Language

### Basic Search

**Plain Text:**
```
atn64025
```
Returns all events containing "atn64025" in any field.

### Boolean Operators

**AND** - Both terms must be present:
```
atn64025 AND 4625
```

**OR** - Either term must be present:
```
4624 OR 4625 OR 4672
```

**NOT** - Exclude events with term:
```
security AND NOT 4624
```

### Parenthetical Grouping

**Complex Logic:**
```
(atn64025 AND 4625) OR (server01 AND failed)
```

**Nested Groups:**
```
(host:atn64025 AND (event:4624 OR event:4672)) NOT test
```

### Field-Specific Search

Search within specific fields:
```
computer:atn64025
event_id:4625
user:administrator
```

### Special Characters

The system handles special characters in search values:
- Parentheses: `( )`
- Brackets: `[ ]`
- Asterisks: `*`
- Equals: `=`
- Exclamation: `!`

Example:
```
command_line:"cmd.exe /c echo test"
process_name:"[System Process]"
```

---

## Search Implementation

### Backend Components

#### Route: `/search/events`
**File:** `app/routes/search.py`

**Purpose:** Render the main search page

**Template:** `templates/search/events.html`

#### API: `/search/api/events`
**File:** `app/routes/search.py`

**Method:** GET

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `q` | string | "" | Search query |
| `page` | integer | 1 | Page number (1-indexed) |
| `per_page` | integer | 50 | Results per page |
| `sort_field` | string | "normalized_timestamp" | Field to sort by |
| `sort_order` | string | "desc" | Sort direction (asc/desc) |
| `file_types` | string | "" | Comma-separated file types (EVTX,NDJSON,IIS,CSV) |
| `event_tags` | string | "" | Comma-separated event tags (other,tagged,ioc,sigma) |
| `noise_categories` | string | "" | Comma-separated noise categories to show |

**Response:**
```json
{
  "events": [
    {
      "id": "event_123",
      "timestamp": "2025-04-21T07:18:43.168197Z",
      "event_id": "4625",
      "system_name": "ATN64025.DWTEMPS.local",
      "description": "An account failed to log on",
      "file_type": "evtx"
    }
  ],
  "total": 102333,
  "page": 1,
  "per_page": 50,
  "total_pages": 2047,
  "has_next": true,
  "has_prev": false
}
```

### Search Query Building

**OpenSearch Query DSL:**
```python
# Build base query
must_clauses = []

# Add search query if provided
if query_string:
    must_clauses.append({
        'query_string': {
            'query': query_string,
            'fields': ['search_blob'],
            'default_operator': 'AND',
            'lenient': True
        }
    })

# Add file type filter if provided
if file_type_filters:
    file_type_clauses = []
    for ft in file_type_filters:
        # Match on file_type field (for newly indexed data)
        file_type_clauses.append({'term': {'file_type.keyword': ft}})
        
        # Match on source_file extension (for existing data)
        if ft == 'EVTX':
            file_type_clauses.append({'wildcard': {'source_file': '*.evtx'}})
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
        elif ft == 'CSV':
            file_type_clauses.append({'wildcard': {'source_file': '*.csv'}})
        elif ft == 'IIS':
            file_type_clauses.append({'wildcard': {'source_file': '*.log'}})
    
    must_clauses.append({
        'bool': {
            'should': file_type_clauses,
            'minimum_should_match': 1
        }
    })

# Build final query
if must_clauses:
    if len(must_clauses) == 1:
        query = must_clauses[0]
    else:
        query = {'bool': {'must': must_clauses}}
else:
    query = {'match_all': {}}
```

### Search Blob Concept

Every event has a `search_blob` field containing all searchable text flattened from the event's nested structure.

**Purpose:**
- Enables full-text search across all fields
- Improves search performance
- Simplifies query construction

**Example Event:**
```json
{
  "event_id": "4625",
  "timestamp": "2025-04-21T07:18:43Z",
  "computer": "ATN64025.DWTEMPS.local",
  "event_data_fields": {
    "TargetUserName": "administrator",
    "FailureReason": "Unknown user name or bad password"
  }
}
```

**Generated search_blob:**
```
4625 2025-04-21T07:18:43Z ATN64025.DWTEMPS.local administrator Unknown user name or bad password
```

**Creation Logic:**
- Recursively extract all text values from event dictionary
- Exclude metadata fields (has_sigma, has_ioc, file_id, etc.)
- Normalize whitespace
- Limit to 100KB max

---

## Pagination System

### Standard Pagination (Pages 1-200)

Uses OpenSearch `from`/`size` parameters:
```python
"from": (page - 1) * per_page,
"size": per_page
```

**Limitations:**
- OpenSearch default `max_result_window` = 10,000
- Cannot access results beyond 10,000 with `from`/`size`

### Deep Pagination (Pages 200+)

**Problem:** OpenSearch limits `from + size` to 10,000 results.

**Solution:** Use `search_after` for deep pagination:

```python
if start_idx >= 10000:
    # Use search_after
    last_event = get_event_at_position(start_idx - 1)
    query["search_after"] = [last_event["timestamp"], last_event["_id"]]
    query["size"] = per_page
else:
    # Use standard pagination
    query["from"] = start_idx
    query["size"] = per_page
```

**Optimization:** For last pages, search in reverse:
```python
if page > total_pages / 2:
    # Search from end in reverse
    query["sort"] = [{"timestamp": {"order": "asc"}}]
    events.reverse()  # Re-reverse after fetching
```

**Performance:**
- Pages 1-200: ~50ms
- Pages 200-1000: ~200ms
- Last page: ~150ms (with reverse optimization)
- Without optimization: ~13s for last page!

---

## Event Detail System

### Modal Interface

**Triggered By:** Clicking on any event row

**Tabs:**
1. **Process Tree** (NDJSON only, default for NDJSON)
   - Grandparent process
   - Parent process
   - Current process
   - Shows: name, PID, command line

2. **Full Data (Tree)**
   - Expandable/collapsible JSON tree
   - Color-coded values (strings, numbers, booleans, null)
   - Field action icons (copy, search)

3. **Raw JSON**
   - Pretty-printed JSON
   - Copy button

### IOC and SIGMA Detection Banners

**Purpose:** Alert analysts when viewing events that contain IOCs or match Sigma rules

**Banner Display** (top of modal):
- **Red Banner** (`alert-danger`) - "⚠️ IOC DETECTED" 
  - Shows when event contains known Indicators of Compromise
  - Lists all IOCs found with type, value, and matched field
  - Example: "ipv4: 192.168.1.32 (in search_blob)"
- **Purple Banner** (`alert-purple`) - "🎭 SIGMA Rule Violation Detected"
  - Shows when event matches Sigma detection rules  
  - Lists matched rule titles with severity levels
  - Example: "Suspicious PowerShell Command Line (high)"

**Field Highlighting**:
- Fields containing IOC values highlighted with:
  - Light red background (`rgba(255, 0, 0, 0.1)`)
  - Red border and text (`var(--color-danger)`)
  - Bold font weight
  - Applies to both field keys and string values

**Implementation**:
```javascript
// Backend enriches event data with IOC/Sigma hits
fetch(`/search/api/event/${eventId}`)
  .then(data => {
    // data.event.ioc_hits - Array of IOC matches
    // data.event.sigma_hits - Array of Sigma matches
    renderAlertBanners(hasIOCs, hasSigma, iocHits, sigmaHits);
    renderEventTree(data.event, iocHits);  // Highlight matching values
  });
```

**Detection Logic**:
- Queries `event_ioc_hits` table for IOC matches
- Queries `event_sigma_hits` table for Sigma matches
- Substring matching: Highlights any field value containing an IOC value
- Case-insensitive matching for reliability

### Process Tree Tab

**Purpose:** Visualize process execution chain for NDJSON events

**Fields Displayed:**
```
Grandparent Process:
  Name: process.parent.parent.name
  PID: process.parent.parent.pid
  Command Line: process.parent.parent.command_line

Parent Process:
  Name: process.parent.name
  PID: process.parent.pid
  Command Line: process.parent.command_line

Current Process:
  Name: process.name
  PID: process.pid
  Command Line: process.command_line
  Executable: process.executable
  Entity ID: process.entity_id
```

**Visual Style:**
- Card-based layout with arrows
- Highlighted command lines
- Fallback for missing fields: "N/A"

### Related Processes Feature ⭐ NEW (v1.5.5+)

**Purpose**: Find siblings, children, parent, and grandparent processes by entity ID correlation to reconstruct full process trees even when parent information is incomplete.

**Location**: Process Tree tab → "🔗 Find Related Processes" button

**How It Works**:
1. Click "Find Related Processes" button on any NDJSON event
2. API correlates processes by `process.entity_id` and `process.parent.entity_id`
3. Modal displays:
   - **Grandparent**: Process matching parent's parent entity_id
   - **Parent**: Process matching current process's parent entity_id (or UNKNOWN if not collected)
   - **Siblings**: All processes with same parent.entity_id (processes spawned together)
   - **Children**: All processes where current process is the parent
4. Analysis includes:
   - Sibling count and time span
   - Pattern detection (multiple diagnostic tools = RMM activity)
   - Parent availability status

**Entity ID Correlation**:
- Uses `process.entity_id` (globally unique GUID per process instance)
- Solves PID reuse problem (PIDs can be recycled, entity IDs cannot)
- Matches across same computer using `normalized_computer`
- Uses `match_phrase` query for exact GUID matching

**Interactive Navigation**:
- Click 🔗 button on ANY process (parent, sibling, child) to find ITS related processes
- Modal stays open and updates with new tree
- Enables hunting through process chains

**Bulk Tagging Actions**:
- **Tag Siblings Only**: Tag all processes at same level (e.g., diagnostic tools spawned together)
- **Tag Entire Tree**: Tag grandparent + parent + all siblings + all children
- Uses existing analyst tagging API (`/search/api/event/<id>/tag`)
- Async bulk operation with progress display

**Use Cases**:
1. **Investigation**: See what else was running when suspicious process spawned
2. **Pattern Recognition**: Multiple diagnostic tools spawned within milliseconds = RMM
3. **Attack Chain Reconstruction**: Trace malware → cmd → powershell → lateral movement
4. **Noise Reduction**: Bulk tag RMM tool chains as noise

**Example Output**:
```
👴 GRANDPARENT: Explorer.EXE (PID 32708)
  └─ 👨 PARENT: cmd.exe (PID 34040)
      └─ 🔵 SIBLING PROCESSES (21)
          ├─ ⭐ svhost.exe (PID 36116) [CURRENT]
          ├─ svhost.exe (PID 32136)
          ├─ svhost.exe (PID 32476)
          └─ ... (18 more)
      
Analysis:
• 21 processes spawned within 1340ms
• Pattern: Multiple diagnostic tools spawned together
• Likely automated RMM/EDR activity
```

**API Endpoint**: `GET /search/api/related_processes/<event_id>`

**Response Structure**:
```json
{
  "success": true,
  "data": {
    "current_process": {...},
    "siblings": [...],
    "children": [...],
    "parent": {...} or null,
    "grandparent": {...} or null,
    "analysis": {
      "sibling_count": 21,
      "children_count": 0,
      "sibling_time_span_ms": 1340,
      "patterns": ["Multiple diagnostic tools spawned together", "Likely automated RMM/EDR activity"],
      "has_parent": false,
      "has_grandparent": true
    }
  }
}
```

### Tree View

**Expandable JSON Tree:**
```
▼ event_data_fields
  ▼ Security
    ► UserData
    EventID: 4625
    Computer: ATN64025.DWTEMPS.local
```

**Interaction:**
- Click to expand/collapse
- Icons always visible (left-aligned)
- Copy button: Copy field value to clipboard
- Search button: Add field value to search query

**Implementation:**
```javascript
function renderTree(obj, depth = 0) {
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'object' && value !== null) {
            // Render collapsible container
            renderContainer(key, value, depth);
        } else {
            // Render leaf value with action icons
            renderLeaf(key, value, depth);
        }
    }
}
```

### Field Actions

**Copy Icon (📋):**
```javascript
navigator.clipboard.writeText(fieldValue)
    .then(() => showCopiedFeedback())
    .catch(() => fallbackCopy(fieldValue));
```

**Search Icon (🔍):**
```javascript
const searchBox = document.getElementById('search-query');
searchBox.value = fieldValue;
submitSearch();
```

**Special Character Handling:**
Uses HTML5 `data-field-value` attribute to avoid JavaScript escaping issues:
```html
<span class="json-tree-field-actions">
    <span class="action-icon copy-icon" data-field-value="C:\Windows\System32\cmd.exe">📋</span>
    <span class="action-icon search-icon" data-field-value="value">🔍</span>
</span>
```

**Event Delegation:**
```javascript
document.querySelector('.json-tree').addEventListener('click', function(e) {
    if (e.target.classList.contains('copy-icon')) {
        const value = e.target.dataset.fieldValue;
        copyToClipboard(value);
    }
});
```

---

## Frontend Components

### Search Form

**File:** `templates/search/events.html`

**HTML:**
```html
<form id="search-form">
    <input type="text" 
           id="search-query" 
           name="q" 
           placeholder="Search events..."
           value="{{ request.args.get('q', '') }}">
    <button type="submit">Search</button>
</form>
```

**Help Text:**
```
Examples:
• Plain text: atn64025
• Boolean: atn64025 AND 4625
• Grouped: (atn64025 AND 4625) OR atn123456
• NOT: security AND NOT 4624
```

### Results Table

**Columns:**
1. **Tagged** - Star icon (for event tagging)
2. **Timestamp** - Event timestamp, sortable
3. **Type** - EVTX, NDJSON/EDR, CSV, or IIS
4. **System Name** - Computer/host name
5. **Event ID** - Windows Event ID or "EDR"
6. **Description** - Event description (truncated)
7. **IOCs** - IOC type badges (color-coded by threat level)
8. **SIGMA Detections** - Sigma rule badges (color-coded by severity)

**Filter Panel** (three-column layout):

**Column 1: File Types** (check to show events)
- ✅ EVTX Files
- ✅ NDJSON Files
- ✅ IIS Files
- ✅ CSV Files

**Column 2: Event Tags** (check to show events)
- ✅ 📄 Other Events (no tags/IOCs/Sigma)
- ✅ ⭐ Tagged Events (analyst-tagged)
- ✅ 🔴 IOC Events (contains IOCs)
- ✅ 🟣 SIGMA Events (matches Sigma rules)

**Column 3: Noise Filters** ⭐ NEW (check to show events)
- ☐ 🔧 RMM Tools (unchecked by default)
- ☐ 🛡️ EDR/MDR Platforms (unchecked by default)
- ☐ 🖥️ Remote Access Tools (unchecked by default)

**Filter Behavior**:
- File Types & Event Tags: Checked by default, uncheck to hide
- Noise Filters: Unchecked by default (hides noise), check to show specific noise categories
- All filters work together cumulatively

**Event ID Extraction:**
The system extracts event IDs with proper fallback logic:
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

**Special Handling for NDJSON:**
- Event ID: "EDR" instead of numeric ID
- Description: `process.command_line` truncated to 120 chars
- System Name: From `normalized_computer` or `host.hostname`

**Special Handling for CSV/Firewall Logs (v1.5.8+):**
- Event ID: From `normalized_event_id` (populated from CSV 'id' or 'fw_event' fields)
- Description: From `message` field (firewall log message), falls back to `fw_event`, then `category`/`group`
- System Name: Shows "Firewall" (firewall devices don't have individual computer names)
- Field Mapping: CSV columns normalized to lowercase ('ID' → 'id', 'Message' → 'message')

**IOC Badges:**
When events contain IOCs (from IOC hunting), badges display in the IOCs column:
- One badge per unique IOC type found in the event
- Badge label: IOC type (e.g., "file", "command_line", "domain")
- Badge color: Determined by threat level
  - Red (`badge-error`) - critical
  - Orange (`badge-warning`) - high
  - Blue (`badge-info`) - medium
  - Gray (`badge-secondary`) - low/info
- Hover tooltip shows IOC details
- Backend query joins with `event_ioc_hits` table to fetch IOC data for displayed events

**SIGMA Badges:**
When events match Sigma rules (from Sigma rule hunting), badges display in the SIGMA Detections column:
- Badge shows count of matched rules (e.g., "3 rules")
- Badge color determined by highest severity:
  - Red (`badge-error`) - Critical/High
  - Orange (`badge-warning`) - Medium
  - Blue (`badge-info`) - Low/Informational
- Hover tooltip shows matched rule titles and severity levels
- Backend query joins with `event_sigma_hits` table to fetch Sigma data for displayed events

### Sorting Controls

**Dropdowns:**
```html
<select id="sort-field">
    <option value="timestamp">Date</option>
    <option value="system_name">System</option>
    <option value="event_id">Event ID</option>
</select>

<select id="sort-order">
    <option value="desc">Newest First</option>
    <option value="asc">Oldest First</option>
</select>
```

**JavaScript:**
```javascript
$('#sort-field, #sort-order').on('change', function() {
    updateURLParams({
        sort_field: $('#sort-field').val(),
        sort_order: $('#sort-order').val(),
        page: 1  // Reset to first page
    });
    performSearch();
});
```

### Pagination Controls

**Components:**
- First Page button
- Previous Page button
- Page number display (e.g., "Page 1 of 2047")
- Next Page button
- Last Page button

**JavaScript:**
```javascript
function updatePagination(data) {
    $('#current-page').text(data.page);
    $('#total-pages').text(data.total_pages);
    $('#total-results').text(data.total.toLocaleString());
    
    $('#prev-page').prop('disabled', !data.has_prev);
    $('#next-page').prop('disabled', !data.has_next);
    $('#first-page').prop('disabled', data.page === 1);
    $('#last-page').prop('disabled', data.page === data.total_pages);
}
```

---

## CSS Styling

**File:** `static/css/main.css`

### Modal Styles

```css
.modal-overlay {
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: rgba(0, 0, 0, 0.7);
    z-index: 1000;
}

.modal-container {
    position: fixed;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    width: 90%; max-width: 1200px;
    max-height: 90vh;
    background: #1e293b;
    border-radius: 8px;
    overflow: hidden;
}
```

### JSON Tree Styles

```css
.json-tree-node {
    margin-left: 20px;
    position: relative;
}

.json-tree-key {
    color: #94a3b8;
    font-weight: 600;
}

.json-tree-value {
    margin-left: 10px;
}

.json-tree-value.string { color: #10b981; }
.json-tree-value.number { color: #f59e0b; }
.json-tree-value.boolean { color: #3b82f6; }
.json-tree-value.null { color: #6b7280; }
```

### Field Action Icons

```css
.json-tree-field-actions {
    display: inline-flex;
    gap: 8px;
    margin-left: 10px;
    opacity: 1;  /* Always visible */
}

.action-icon {
    cursor: pointer;
    font-size: 14px;
    padding: 2px 6px;
    border-radius: 4px;
    transition: all 0.2s;
}

.action-icon:hover {
    background: rgba(59, 130, 246, 0.1);
    transform: scale(1.1);
}

.copy-icon.copied {
    background: rgba(16, 185, 129, 0.2);
    animation: pulse 0.5s;
}
```

---

## Performance Considerations

### Query Optimization

**1. Index Only Required Fields:**
```python
"_source": [
    "timestamp", "event_id", "system_name", 
    "computer", "description", "source_file"
]
```

**2. Use search_blob for Full-Text:**
```python
"fields": ["search_blob"]
```

**3. Enable Result Caching:**
```python
"request_cache": True
```

### Deep Pagination Strategy

**For pages > 10,000 results:**
1. Calculate if closer to start or end
2. If closer to end, search in reverse
3. Use `search_after` with sort key + _id
4. Cache intermediate pages (optional)

### Frontend Optimization

**1. Debounce Search Input:**
```javascript
const searchInput = document.getElementById('search-query');
let debounceTimer;
searchInput.addEventListener('input', function() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(performSearch, 300);
});
```

**2. Lazy Load Event Details:**
- Only fetch full event data when modal opens
- Don't include all fields in list view

**3. Virtual Scrolling (Future):**
- Load results as user scrolls
- Reduce initial page load

---

## API Reference

### GET /search/events
Render search page interface

**Response:** HTML page with search form and results table

---

### GET /search/api/events
Search for events

**Query Parameters:**
- `q` (string, optional): Search query
- `page` (integer, default: 1): Page number
- `per_page` (integer, default: 50): Results per page
- `sort_field` (string, default: "normalized_timestamp"): Sort field
- `sort_order` (string, default: "desc"): Sort order (asc/desc)
- `file_types` (string, optional): Comma-separated file types (e.g., "EVTX,NDJSON")

**Response:**
```json
{
  "events": [...],
  "total": 102333,
  "page": 1,
  "per_page": 50,
  "total_pages": 2047,
  "has_next": true,
  "has_prev": false
}
```

**Status Codes:**
- 200: Success
- 400: Invalid parameters
- 500: Search error

---

### GET /search/api/event/<event_id>
Get full event details

**Path Parameters:**
- `event_id` (string): OpenSearch document ID

**Response:**
```json
{
  "event_id": "4625",
  "timestamp": "2025-04-21T07:18:43.168197Z",
  "computer": "ATN64025.DWTEMPS.local",
  "event_data_fields": {...},
  "process": {...},
  "normalized_computer": "ATN64025.DWTEMPS.local"
}
```

**Status Codes:**
- 200: Success
- 404: Event not found
- 500: Server error

---

## Testing

### Manual Testing

**1. Basic Search:**
```
Query: atn64025
Expected: All events from system ATN64025
```

**2. Boolean AND:**
```
Query: atn64025 AND 4625
Expected: Failed logon events from ATN64025
```

**3. Boolean OR:**
```
Query: 4624 OR 4625 OR 4672
Expected: Logon, failed logon, and special logon events
```

**4. Parenthetical:**
```
Query: (atn64025 AND 4625) OR (server01 AND failed)
Expected: Failed logons from ATN64025 OR failed events from server01
```

**5. NOT Operator:**
```
Query: security AND NOT 4624
Expected: Security events excluding successful logons
```

**6. Deep Pagination:**
```
Navigate to page 500+
Expected: Results load in < 1 second
```

**7. Event Details:**
```
Click any event row
Expected: Modal opens with process tree (NDJSON) or tree view (EVTX)
```

**8. Field Actions:**
```
Click copy icon next to any field
Expected: Value copied to clipboard, icon shows "copied" feedback
```

**9. Special Characters:**
```
Click search icon for field with value: C:\Windows\System32\cmd.exe /c "test"
Expected: Search box populated correctly, search executes
```

### Automated Testing

```python
def test_search_basic():
    response = client.get('/search/api/events?q=atn64025')
    assert response.status_code == 200
    assert 'events' in response.json
    assert response.json['total'] > 0

def test_search_boolean():
    response = client.get('/search/api/events?q=atn64025 AND 4625')
    assert response.status_code == 200
    # Verify results contain both terms

def test_pagination():
    response = client.get('/search/api/events?page=500&per_page=50')
    assert response.status_code == 200
    assert response.json['page'] == 500

def test_event_detail():
    response = client.get('/search/api/event/some_event_id')
    assert response.status_code == 200
    assert 'event_id' in response.json
```

---

## Troubleshooting

### Issue: Search returns no results

**Check:**
1. OpenSearch index exists: `curl localhost:9200/case_2/_count`
2. Events have `search_blob` field
3. Query syntax is valid

### Issue: Slow deep pagination

**Solution:**
- Implemented `search_after` optimization
- Added reverse search for last pages
- Typical load time: < 1 second

### Issue: Modal doesn't open

**Check:**
1. Event ID in `data-event-id` attribute
2. JavaScript console for errors
3. API endpoint `/search/api/event/<id>` returns data

### Issue: Field action icons don't work

**Check:**
1. `data-field-value` attribute present
2. Event delegation listener attached
3. Special characters properly encoded

---

## Event Tagging System

### Overview

Analysts can manually tag events of interest during investigation. Tags are stored at the OpenSearch level for optimal performance.

### Storage: OpenSearch (Not Database)

Tags stored in OpenSearch for:
1. **Performance**: No database joins needed
2. **Scalability**: Handles millions of events
3. **Simplicity**: Tags stored with event data
4. **Query Efficiency**: Native OpenSearch boolean filters

### OpenSearch Fields

```python
'analyst_tagged': {'type': 'boolean'},
'analyst_tagged_by': {'type': 'keyword'},
'analyst_tagged_at': {'type': 'date'}
```

### UI Features

**Star Column** (first column in event table):
- **☆** = Not tagged (click to tag)
- **⭐** = Tagged (click to untag)
- **⏳** = Loading state during API call

**Tag/Untag Actions**:
- Click star icon next to any event
- Immediate visual feedback
- Saved to OpenSearch within 200ms
- All tag operations audited automatically

### API Endpoints

**Tag Event**: `POST /search/api/event/<event_id>/tag`
**Untag Event**: `POST /search/api/event/<event_id>/untag`
**Count Tagged**: `GET /search/api/tagged_events/count`
**Get All Tagged**: `GET /search/api/tagged_events` (max 10,000)

### Event Tag Filters

Four filter types (all checked by default):

1. **📄 Other Events** - Events without tags, IOCs, or Sigma hits
2. **⭐ Tagged Events** - Analyst-tagged events
3. **🔴 IOC Events** - Events with IOC hits
4. **🟣 SIGMA Events** - Events matching Sigma rules

**Filter Behavior**: 
- Checked = Include those events
- Unchecked = Exclude those events
- Works exactly like File Type filters using exclusion logic

### Event Classification Logic

- **Other**: `analyst_tagged != true` AND `NOT IN ioc_event_ids` AND `NOT IN sigma_event_ids`
- **Tagged**: `analyst_tagged == true`
- **IOC**: `opensearch_doc_id IN ioc_event_ids` (from `event_ioc_hits` table)
- **SIGMA**: `opensearch_doc_id IN sigma_event_ids` (from `event_sigma_hits` table)

**Note**: Events can overlap (e.g., tagged + IOC + Sigma)

### Combining Filters

File Type, Event Tag, and Noise filters work together (AND logic):

```
EVTX ✓ + Tagged ✓ = Tagged EVTX events only
NDJSON ✓ + IOC ✓ = NDJSON events with IOCs
All ✓ + RMM Tools ✓ = All events + RMM noise events
EVTX ✓ + Other ✓ (IOC ✗) = EVTX events without IOCs
```

### Permissions

| Role | Tag/Untag | View Tagged |
|------|-----------|-------------|
| Admin | ✓ | ✓ |
| Analyst | ✓ | ✓ |
| Read-only | ✗ | ✓ |

### Performance

- **Tag operation**: < 200ms (OpenSearch update)
- **Query tagged**: < 50ms (boolean filter)
- **Count tagged**: < 10ms (count API)
- **No database overhead**
- **Scales linearly**

## Noise Filter Integration

### Overview

The noise filter system allows showing/hiding events from known good software based on enabled noise filter rules.

### Noise Categories

Displayed in third filter column (unchecked by default):

- 🔧 **RMM Tools** - Remote Monitoring and Management
- 🛡️ **EDR/MDR Platforms** - Endpoint Detection platforms
- 🖥️ **Remote Access Tools** - Legitimate remote access software

**Note**: Only categories with tagged events appear (requires noise tagging task to be run first)

### Filter Behavior

**Default (all unchecked)**: Hides all noise events
- Shows: 418,662 non-noise events
- Hides: 64,676 noise events

**Check "RMM Tools"**: Adds RMM noise events to results
- Shows: 418,662 + 16,724 = 435,386 events (cumulative)

**Check multiple**: Cumulative addition
- RMM + EDR/MDR checked → Shows non-noise + RMM + EDR events

### Implementation

**OpenSearch Query Logic**:
```python
# Build should clauses for what to include
should_clauses = []

# Always include non-noise events
should_clauses.append({
    'bool': {
        'must_not': [{'exists': {'field': 'noise_matched'}}]
    }
})

# If noise categories checked, also include those
if noise_category_filters:
    should_clauses.append({
        'bool': {
            'must': [
                {'term': {'noise_matched': True}},
                {'terms': {'noise_categories.keyword': noise_category_filters}}
            ]
        }
    })

# Apply as must clause
must_clauses.append({
    'bool': {
        'should': should_clauses,
        'minimum_should_match': 1
    }
})
```

### Noise Event Fields

Events tagged as noise have:
```json
{
  "noise_matched": true,
  "noise_rules": ["ConnectWise Automate", "Huntress EDR"],
  "noise_categories": ["RMM Tools", "EDR/MDR Platforms"]
}
```

See [NOISE_FILTERS.md](NOISE_FILTERS.md) for complete noise system documentation.

## Future Enhancements

1. **Saved Searches** - Save common queries
2. **Search History** - Recent searches
3. **Export Results** - CSV/JSON export
4. **Advanced Filters** - Date range, severity level
5. **Regex Support** - Pattern matching
6. **Fuzzy Search** - Typo tolerance
7. **Search Suggestions** - Auto-complete based on indexed fields
8. **Tag categories** - Critical, suspicious, etc.
9. **Tag comments** - Notes on tagged events
10. **Bulk tagging** - Tag multiple events at once

---

## Recent Updates

### Version 1.2.0 (2025-12-28)
- ✅ Added IOC and SIGMA detection banners to event detail modal
- ✅ Implemented field highlighting for values containing IOCs
- ✅ Backend enrichment of events with `ioc_hits` and `sigma_hits` arrays
- ✅ Substring matching for IOC detection across all field values
- ✅ Dark theme compatible highlighting with semi-transparent colors

### Version 1.5.8 (2026-01-03)
- ✅ Fixed CSV event field display (event ID, description, system name)
- ✅ Enhanced event normalization for CSV logs
- ✅ Added CSV-specific fields to search query
- ✅ Backfill support for existing CSV events

### Version 1.1.0 (2025-12-23)
- ✅ Added file type filtering (EVTX, NDJSON, IIS, CSV)
- ✅ Fixed event ID display for EVTX events
- ✅ Added `file_type` field to OpenSearch index mapping
- ✅ Improved event ID extraction with proper fallback logic
- ✅ File type filters work with both new and existing indexed data

---

## Version
- **Document Version:** 1.2.0
- **Last Updated:** 2025-12-28
- **CaseScope Version:** 2026

