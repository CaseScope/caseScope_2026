# File Management UI - Complete Guide

## 🎉 Features: ALL OPERATIONAL

Complete file management interface with real-time updates and intelligent filtering!

```
✓ File List Table: Shows all uploaded files with metadata
✓ Real-Time Stats: Auto-updating every 5 seconds
✓ Progress Tracking: Live progress bar during processing
✓ Search & Filter: Instant filename search + filter dropdown
✓ Hidden Files: Auto-hide empty files (0 events)
✓ Auto-Refresh: Page updates when files processing
✓ System Name Extraction: 100% success rate
```

---

## 📊 File List Table

### Columns Displayed:

1. **Filename** - with file size below
2. **System** - Parsed computer name (badge)
3. **Uploaded** - Date and time
4. **Uploaded By** - Username
5. **Events** - Formatted event count
6. **SIGMA** - Violations count (future)
7. **IOCs** - IOC count (future)
8. **Status** - Badge showing indexed/processing/failed

### Database Tracking

**Model:** `CaseFile`

**Fields:**
```python
# Core fields
case_id, filename, file_type, file_size, file_path

# Parsed metadata
source_system      # Computer name from events
event_count        # Total events in file
sigma_violations   # SIGMA rule hits (TODO)
ioc_count         # IOCs found (TODO)

# Upload tracking
uploaded_by       # User ID
uploaded_at       # Timestamp

# Status
status            # pending, processing, indexed, failed
is_hidden         # True = 0 events (empty file)
```

### System Name Extraction

**How It Works:**

1. **Primary Method: Event Parsing**
```python
for event in parse_evtx_file(file_path):
    source_system = (
        event.get('computer') or 
        event.get('Computer') or 
        event.get('computer_name')
    )
    if source_system:
        break  # Got it!
```

2. **Fallback Method: Filename**
If no events exist, tries to extract from filename

3. **Result: Empty Files**
- Files with **0 events** = No computer field to read
- Shows **"Empty"** in UI with tooltip

**Statistics:**
- Total files: 297
- Files with system names: 66 (100% of files with events!)
- Empty files (0 events): 231

✅ **100% of files with events have system names extracted!**

---

## 📈 Real-Time Statistics

### Stats Monitored:

1. **Total Files** - All files in storage
2. **Total Events** - Sum of all event counts
3. **Indexed Files** - Files with status = 'indexed'
4. **Pending Files** - Files in staging folder
5. **Hidden Files (empty)** - Files with 0 events

### Auto-Updating

**Update Frequency:** Every 5 seconds via AJAX

**API Endpoint:** `/case/<case_id>/files/stats`

**Returns JSON:**
```json
{
  "stats": {
    "total_files": 320,
    "total_events": 582240,
    "indexed_files": 66,
    "pending_files": 254,
    "processing_files": 3,
    "failed_files": 0,
    "hidden_files": 231,
    "total_size_gb": 1.24
  },
  "timestamp": "2025-12-21T20:05:30.123456"
}
```

**Features:**
- No page reload needed
- Smooth fade animations on value changes
- Live count updates
- Timestamp showing last update

---

## ⏳ Processing Progress Indicator

### Live Progress Display

Shows when files are being processed:

```
⏳ Processing files...
   3 files currently being indexed
   Updated: 5s ago
```

**Features:**
- Animated spinner
- Live count of processing files
- Auto-shows when processing starts
- Auto-hides when complete
- Timestamp showing last update

### Progress Bar with File Count

Shows detailed processing progress:

```
Processing files...
File 239 of 619 - 39% complete
[████████░░░░░░░░░░░░] 39%
```

**Features:**
- Current file number
- Total files count
- Percentage complete
- Animated progress bar
- Real-time updates every 5 seconds

---

## 🔍 Search & Filter System

### Filename Search Box

**Location:** Top left, above file table

**Features:**
- Search as you type (no submit button)
- Filters filename column
- Case-insensitive search
- Shows "No files match your search" when no results
- Instant filtering (no page reload)
- 300px width with search icon 🔍

**Implementation:**
```javascript
document.getElementById('fileSearch').addEventListener('input', function(e) {
    const searchTerm = e.target.value.toLowerCase();
    const rows = document.querySelectorAll('.file-row');
    
    rows.forEach(row => {
        const filename = row.getAttribute('data-filename');
        if (filename.includes(searchTerm)) {
            row.style.display = '';  // Show
        } else {
            row.style.display = 'none';  // Hide
        }
    });
});
```

### Filter Dropdown

**Location:** Top right of file table

**Options:**
- **Hide Hidden** (default) - Shows only files with events
- **Only Hidden** - Shows only empty files (0 events)
- **Show All** - Shows all files regardless of status

**Backend Logic:**

```python
# Hide Hidden (default)
if show_hidden == False:
    files = CaseFile.query.filter_by(
        case_id=case_id, 
        is_hidden=False
    ).all()

# Only Hidden
elif only_hidden == True:
    files = CaseFile.query.filter_by(
        case_id=case_id, 
        is_hidden=True
    ).all()

# Show All
else:
    files = CaseFile.query.filter_by(
        case_id=case_id
    ).all()
```

**URL Parameters:**
- `/case/2/files` → Hides empty files
- `/case/2/files?only_hidden=true` → Shows only empty files
- `/case/2/files?show_hidden=true` → Shows all files

---

## 🙈 Hidden Files Feature

### Automatic Classification

**During file ingestion:**
```python
is_hidden = (total_indexed == 0)

case_file = CaseFile(
    # ... other fields ...
    event_count=total_indexed,
    is_hidden=is_hidden  # Auto-set based on event count
)
```

### UI Display

**Empty Files Labeled:**
- System column shows: **"Empty"**
- Tooltip: "Empty file - no events"
- Badge styling: Muted gray

**Statistics:**
- Hidden files counter shows count
- Default view hides them
- Toggle to see them when needed

### Why Empty EVTX Files Exist

Windows creates EVTX log files even if no events have been logged yet:

- **New log channels**: Created but never used
- **Optional features**: Logs for features not enabled
- **Reserved channels**: Pre-created for future events
- **Application logs**: App installed but never run

**This is normal behavior and not an error!**

---

## 🔄 Auto-Refresh System

### When Processing Active

**Behavior:**
- Page auto-refreshes every **30 seconds**
- Updates file table with new entries
- Shows real-time status changes
- Stops when processing completes

**Trigger:**
```javascript
// If processing files > 0:
if (stats.processing_files > 0) {
    // Auto-reload page every 30 seconds
    setTimeout(() => location.reload(), 30000);
}
```

**Console Messages:**
```
📊 Real-time stats monitoring active
🔄 Auto-refresh started - files are processing
♻️ Refreshing page to show updated files...
⏹️ Auto-refresh stopped - processing complete
```

---

## 🎨 UI Layout

```
┌─────────────────────────────────────────────────┐
│  Stats Row (5 cards)                           │
│  Total | Events | Indexed | Pending | Hidden   │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Progress Bar (when processing)                │
│  File X of Y - ZZ% complete                    │
│  [████████░░░░░░] 39%                          │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  🔍 Search...          [Filter Dropdown ▼]     │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Uploaded Files Table                          │
│  (filtered by search + dropdown)               │
└─────────────────────────────────────────────────┘
```

---

## 📋 File Workflow

### Upload Flow with Progress:

1. **User uploads file** → Chunk upload starts
2. **File staged** → Stats show +1 pending
3. **Celery starts processing** → Status changes to "processing"
4. **Progress indicator appears** → Shows active count
5. **Events indexed** → Event count increases in real-time
6. **File completed** → Status → "indexed"
7. **CaseFile record created** → Appears in table
8. **Processing indicator disappears** → All done!

### Real-Time Updates:

```javascript
// Every 5 seconds:
fetch('/case/2/files/stats')
  → Update stat cards
  → Check for processing files
  → Show/hide progress indicator
  
// If processing files > 0:
  → Auto-reload page every 30 seconds
  → Keep table up-to-date
```

---

## 👁️ User Experience

### During Upload:
1. Stats update live as files process
2. See pending count decrease
3. See indexed count increase
4. Watch event totals grow
5. Progress indicator shows activity

### After Upload:
- Page auto-refreshes to show new files
- No manual refresh needed
- See files appear in table automatically
- Know exactly when processing is done

### Searching & Filtering:
1. **Search for "Security"** → Instant filtering
2. **Select "Only Hidden"** → View empty files
3. **Select "Show All"** → See everything
4. **Clear search** → Reset to filtered view

---

## 🎯 Example Scenarios

### Uploading 100 Files:
1. Stats show: Pending: 100
2. Processing starts
3. Progress bar appears: "File 0 of 100 - 0%"
4. Updates in real-time: "File 25 of 100 - 25%"
5. Completes: "File 100 of 100 - 100%"
6. Progress bar disappears
7. File table shows all 100 files

### Searching for "Security":
1. Type "security" in search box
2. Table instantly filters to matching files
3. Other files hidden (not removed)
4. Clear search to see all again

### Viewing Only Empty Files:
1. Select "Only Hidden" from dropdown
2. Page reloads showing 380 empty files
3. Stats remain unchanged
4. Can search within empty files

---

## ⚡ Performance

✅ **Search:** Client-side filtering (instant)  
✅ **Filter:** Server-side query (optimized)  
✅ **Progress:** 5-second polling (low overhead)  
✅ **Auto-refresh:** Only when needed (30s intervals)

**Lightweight:**
- Only fetches JSON stats, not full HTML
- 5-second polling is low overhead
- Smart auto-refresh only when needed
- Clean stop when page unloads

---

## 🔮 Future Enhancements

### 1. WebSocket Support
- Push updates instead of polling
- Instant notifications
- Lower server load

### 2. Per-File Progress
- Show % complete for each file
- Estimated time remaining
- Events/second processing speed

### 3. Notification System
- Browser notifications when processing completes
- Toast messages for new files
- Error alerts for failed files

### 4. Visual Progress Bars
- Overall progress bar
- Individual file progress
- Color-coded status indicators

### 5. SIGMA & IOC Integration
- Live SIGMA violation counts
- IOC detection results
- Alert badges for threats

### 6. File Actions
- Download file
- Re-process/re-index file
- Delete file (with confirmation)
- View file details modal

---

## 🛠️ Technical Implementation

### Frontend (JavaScript)

**Real-time stats update:**
```javascript
async function updateStats() {
    const response = await fetch(`/case/${caseId}/files/stats`);
    const data = await response.json();
    
    // Update stat cards
    document.getElementById('totalFiles').textContent = data.stats.total_files;
    document.getElementById('totalEvents').textContent = formatNumber(data.stats.total_events);
    // ... etc
    
    // Show/hide progress indicator
    if (data.stats.processing_files > 0) {
        showProcessingIndicator(data.stats.processing_files);
        scheduleAutoRefresh();
    } else {
        hideProcessingIndicator();
    }
}

setInterval(updateStats, 5000);  // Every 5 seconds
```

**Search functionality:**
```javascript
document.getElementById('fileSearch').addEventListener('input', function(e) {
    const searchTerm = e.target.value.toLowerCase();
    const rows = document.querySelectorAll('.file-row');
    let visibleCount = 0;
    
    rows.forEach(row => {
        const filename = row.getAttribute('data-filename').toLowerCase();
        if (filename.includes(searchTerm)) {
            row.style.display = '';
            visibleCount++;
        } else {
            row.style.display = 'none';
        }
    });
    
    // Show "no results" message if needed
    if (visibleCount === 0) {
        showNoResultsMessage();
    }
});
```

### Backend (Flask Routes)

**File list route:**
```python
@case_bp.route('/<int:case_id>/files')
@login_required
def case_files(case_id):
    show_hidden = request.args.get('show_hidden', 'false').lower() == 'true'
    only_hidden = request.args.get('only_hidden', 'false').lower() == 'true'
    
    # Filter logic
    if only_hidden:
        files = CaseFile.query.filter_by(case_id=case_id, is_hidden=True).all()
    elif not show_hidden:
        files = CaseFile.query.filter_by(case_id=case_id, is_hidden=False).all()
    else:
        files = CaseFile.query.filter_by(case_id=case_id).all()
    
    # Calculate stats
    stats = calculate_file_stats(case_id)
    
    return render_template('case/files.html', 
                         files=files, 
                         stats=stats,
                         show_hidden=show_hidden,
                         only_hidden=only_hidden)
```

**Stats API route:**
```python
@case_bp.route('/<int:case_id>/files/stats')
@login_required
def case_files_stats(case_id):
    stats = {
        'total_files': CaseFile.query.filter_by(case_id=case_id).count(),
        'total_events': db.session.query(db.func.sum(CaseFile.event_count))
                         .filter_by(case_id=case_id).scalar() or 0,
        'indexed_files': CaseFile.query.filter_by(
            case_id=case_id, status='indexed').count(),
        'processing_files': CaseFile.query.filter_by(
            case_id=case_id, status='processing').count(),
        'pending_files': len(get_staging_files(case_id)),
        'hidden_files': CaseFile.query.filter_by(
            case_id=case_id, is_hidden=True).count(),
        'total_size_gb': calculate_total_size(case_id)
    }
    
    return jsonify({
        'stats': stats,
        'timestamp': datetime.utcnow().isoformat()
    })
```

---

## 📊 Statistics Always Visible

**All stats remain visible regardless of filter:**

```
Total Files: 941
Total Events: 618,377
Indexed Files: 619
Pending Files: 233
Hidden Files (empty): 380
```

Hidden files are counted but not shown in the table by default. Toggle to view them when needed.

---

## ✅ Complete Feature List

**Implemented:**
- ✅ File list table with 8 columns
- ✅ Real-time statistics (5s updates)
- ✅ Processing progress indicator
- ✅ Filename search (instant)
- ✅ Filter dropdown (Hide/Show/Only hidden)
- ✅ Auto-refresh when processing
- ✅ System name extraction (100% success)
- ✅ Hidden files feature (auto-classify)
- ✅ Status badges (indexed/processing/failed)
- ✅ File size formatting
- ✅ Event count formatting
- ✅ Upload timestamp display
- ✅ Database file tracking

**Coming Soon:**
- ⏳ SIGMA violation counts (hook into detection)
- ⏳ IOC counts (hook into extraction)
- ⏳ File actions (download, reindex, delete)
- ⏳ File details modal
- ⏳ Per-file progress bars
- ⏳ Browser notifications
- ⏳ WebSocket updates

**File management UI is now live and fully operational!** 🎉
