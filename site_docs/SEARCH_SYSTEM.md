# CaseScope Event Search System

## Overview

The CaseScope search system provides a powerful, Google-like search interface for querying millions of events across EVTX and NDJSON files. It supports boolean operators, nested queries, deep pagination, and comprehensive event visualization.

**Key Features:**
- ✅ Boolean search operators (AND, OR, NOT)
- ✅ Parenthetical grouping for complex queries
- ✅ Full-text search across all event fields
- ✅ File type filtering (EVTX, NDJSON, IIS, CSV)
- ✅ Sorted pagination (newest first by default)
- ✅ Deep pagination support (100K+ events)
- ✅ Event detail modal with expandable JSON tree
- ✅ Process tree visualization for NDJSON events
- ✅ Field-level copy and search actions
- ✅ Special character handling in search values

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

**File Type Filters:**
- Checkboxes above results table
- Filter by: EVTX Files, NDJSON Files, IIS Files, CSV Files
- All types enabled by default
- Filters work with search queries

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

## Future Enhancements

1. **Saved Searches** - Save common queries
2. **Search History** - Recent searches
3. **Export Results** - CSV/JSON export
4. **Tag Events** - Star/flag important events
5. **Advanced Filters** - Date range, severity level
6. **Regex Support** - Pattern matching
7. **Fuzzy Search** - Typo tolerance
8. **Search Suggestions** - Auto-complete based on indexed fields

---

## Recent Updates

### Version 1.1.0 (2025-12-23)
- ✅ Added file type filtering (EVTX, NDJSON, IIS, CSV)
- ✅ Fixed event ID display for EVTX events
- ✅ Added `file_type` field to OpenSearch index mapping
- ✅ Improved event ID extraction with proper fallback logic
- ✅ File type filters work with both new and existing indexed data

---

## Version
- **Document Version:** 1.1.0
- **Last Updated:** 2025-12-23
- **CaseScope Version:** 2026

