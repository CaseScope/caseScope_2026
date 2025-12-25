# IOC Hunting Implementation - Summary

## Overview
Implemented background IOC hunting with real-time progress tracking for large-scale event analysis (30M+ events). Hunt results are displayed as badges in the event search table.

## Components Added

### 1. Database Schema (`migrations/add_event_ioc_hits.sql`)
- **Table**: `event_ioc_hits` - Tracks which events contain which IOCs
- **Fields**:
  - Event identification (OpenSearch doc ID, record ID, event ID, timestamp, computer)
  - IOC information (ID, value, type, category, threat level)
  - Match details (matched field, context, confidence)
  - Metadata (detection time, detected by user)
- **Indexes**: Optimized for queries by case, IOC, event, timestamp, threat level, and type
- **Constraint**: Unique constraint prevents duplicate event-IOC pairs

### 2. Data Model (`app/models.py`)
- **Class**: `EventIOCHit` - SQLAlchemy model for IOC hits
- **Relationships**: Links to Case, IOC, and User models

### 3. Celery Task (`app/tasks/task_hunt_iocs.py`)
- **Function**: `hunt_iocs(case_id, user_id)` - Background task for IOC hunting
- **Features**:
  - Multi-strategy search based on IOC type (IPs, hashes, domains, files, URLs, emails, commands)
  - Prioritizes structured fields (event_data_fields) over search_blob
  - Uses OpenSearch scroll API for efficient iteration through large datasets
  - Real-time progress updates (0-100%)
  - Intelligent field matching to determine where IOC was found
  - Batch commits (every 100 records) to prevent memory issues
  - Handles duplicate detection (prevents re-tagging)
  - Returns comprehensive statistics:
    - Events scanned
    - Events with hits
    - Total hits
    - Hits by IOC
    - Hits by threat level

### 4. API Routes (`app/routes/hunting.py`)
- **POST /hunting/api/hunt_iocs**: Start IOC hunt
  - Validates case selection and permissions
  - Launches background Celery task
  - Returns task ID for progress tracking
  - Logs audit entry

- **GET /hunting/api/hunt_iocs/status/<task_id>**: Check hunt progress
  - Returns task state (PENDING, PROGRESS, SUCCESS, FAILURE)
  - Provides real-time progress percentage
  - Shows current IOC being hunted
  - Returns live statistics during hunt
  - Returns final results on completion

### 5. User Interface (`templates/hunting/dashboard.html`)
- **Button**: "🎯 Hunt IOCs" - Launches IOC hunt with confirmation dialog
- **Modal**: Progress and results display
  - **Progress View**:
    - Animated progress bar (0-100%)
    - Current status message
    - Current IOC being hunted
    - Live statistics (4 stat cards):
      - Events Scanned
      - Total Events
      - Events Tagged
      - IOC Hits
  - **Results View**:
    - Success message
    - Summary statistics (events scanned, tagged, total hits)
    - Hits by threat level (Critical, High, Medium, Low, Info)
    - Hits by IOC table (sorted by hit count)
- **Auto-refresh**: Progress checks every 2 seconds
- **Button state management**: Disables during hunt, re-enables on completion

### 6. IOC Badges in Search Results (`templates/search/events.html`, `app/routes/search.py`)
- **New Column**: "IOCs" column added to search results table
- **Badge Display**: Shows IOC type badges (e.g., "file", "command_line", "domain")
- **Color Coding**: Badges colored by threat level:
  - Red (critical)
  - Orange (high)
  - Blue (medium)
  - Gray (low/info)
- **Smart Grouping**: One badge per IOC type found in event
- **Database Integration**: Search results query EventIOCHit table to get IOC types for displayed events

### 7. Task Registration (`app/celery_app.py`)
- Added `task_hunt_iocs` import and registration
- Task now appears in Celery worker task list

## Smart Search Strategies

### By IOC Type:
1. **IPv4**: Searches IpAddress, SourceAddress, DestAddress, ClientIPAddress fields
2. **File Hashes**: Searches Hashes, Hash, MD5, SHA1, SHA256 fields (case-insensitive)
3. **Domain**: Searches DestinationHostname, QueryName, TargetServerName fields
4. **File Name**: Searches TargetFilename, ImagePath, FileName fields
5. **File Path**: Searches file paths and CommandLine with phrase matching
6. **URL**: Searches Url, RequestUrl fields
7. **Email**: Searches EmailAddress, Sender, Recipient fields
8. **Command**: Searches CommandLine, ProcessCommandLine fields
9. **Generic**: Falls back to search_blob for unknown types

### Match Context:
- Attempts to determine which specific field contained the match
- Records field name in `matched_in_field`
- Provides confidence level (defaults to "high")

## Performance Optimizations
1. **OpenSearch Scroll API**: Bypasses 10k result limit
2. **Batch Processing**: Processes 1000 events at a time
3. **Batch Commits**: Commits to DB every 100 records
4. **Duplicate Prevention**: Database constraint + query check
5. **Selective Field Retrieval**: Only fetches necessary fields from OpenSearch
6. **5-minute scroll timeout**: Balances performance and resource usage

## Security & Audit
- Permission checks (read-only users cannot hunt)
- Case validation
- Audit logging for hunt start
- User tracking for who initiated hunt
- Tracks who detected each hit

## User Experience
- Clear progress indication
- Real-time statistics
- Confirmation dialog before starting
- Non-blocking (runs in background)
- Handles large datasets (30M+ events) gracefully
- Visual feedback (color-coded threat levels in badges)
- Results persist in database for future analysis
- IOC badges appear automatically in search results

## Services Restarted
- `casescope-new` (Flask)
- `casescope-workers` (Celery)

## Files Modified
1. `/opt/casescope/migrations/add_event_ioc_hits.sql` (new)
2. `/opt/casescope/app/models.py` (added EventIOCHit model)
3. `/opt/casescope/app/tasks/task_hunt_iocs.py` (new)
4. `/opt/casescope/app/routes/hunting.py` (added 2 routes)
5. `/opt/casescope/templates/hunting/dashboard.html` (added button, modal, JavaScript)
6. `/opt/casescope/app/routes/search.py` (added IOC badge integration)
7. `/opt/casescope/templates/search/events.html` (added IOCs column and badge display)
8. `/opt/casescope/app/celery_app.py` (registered task)

## Status
✅ Database table created
✅ Model defined
✅ Task implemented
✅ Routes added
✅ UI implemented
✅ Task registered with Celery
✅ Services restarted
✅ IOC badges integrated into search results
✅ Ready for production use

