# New Forensic Parsers Documentation
## CaseScope Parser Extensions v2.0

This document describes the 12 new forensic artifact parsers added to CaseScope.

---

## Summary Table

| Parser | File Types | Evidence Type | Route Index |
|--------|-----------|---------------|-------------|
| thumbcache_parser | thumbcache_*.db | Images/thumbnails accessed | filesystem |
| bits_parser | qmgr.db, qmgr0.dat | Background downloads | network |
| winsearch_parser | Windows.edb | File/email search index | filesystem |
| activities_parser | ActivitiesCache.db | Windows Timeline | execution |
| notifications_parser | wpndatabase.db | Push notifications | events |
| rdp_cache_parser | Cache*.bin, *.bmc | RDP session images | filesystem |
| wmi_parser | OBJECTS.DATA | WMI persistence | events |
| pst_parser | *.pst, *.ost | Email archives | events |
| schtasks_parser | Tasks/*.xml | Scheduled tasks | events |
| teams_skype_parser | main.db, *.ldb | Communications | events |
| usb_history_parser | setupapi.dev.log | USB device history | devices |
| onedrive_parser | *.odl, *.db | Cloud sync activity | filesystem |

---

## Installation Requirements

```bash
# Required for PST parsing
sudo apt install pst-utils

# Required for ESE database parsing (SRUM, BITS, WebCache, Windows Search)
sudo apt install libesedb-utils
pip install pyesedb --break-system-packages

# Already installed dependencies
pip install dissect.util --break-system-packages
```

---

## Parser Details

### 1. Thumbcache Parser (`thumbcache_parser.py`)

**Location:** `Users\*\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db`

**Evidence Value:**
- Shows images/documents user accessed
- Evidence of files even after deletion
- Timeline of file access

**Event Fields:**
- `cache_hash`: Unique identifier for cached item
- `cache_size`: Thumbnail dimensions (32, 96, 256, 1024, etc.)
- `data_size`: Size of cached thumbnail
- `cached_filename`: Original filename (if available)

---

### 2. BITS Parser (`bits_parser.py`)

**Location:** `ProgramData\Microsoft\Network\Downloader\qmgr.db`

**Evidence Value:**
- C2 download evidence
- Malware delivery
- Data exfiltration via BITS
- Persistence mechanisms

**Event Fields:**
- `job_id`: Unique job identifier
- `job_name`: Display name of transfer job
- `remote_url`: Source URL
- `local_path`: Download destination
- `state`: Job state (QUEUED, TRANSFERRED, etc.)
- `bytes_transferred/bytes_total`: Transfer progress

---

### 3. Windows Search Parser (`winsearch_parser.py`)

**Location:** `ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`

**Evidence Value:**
- Evidence of file existence (even after deletion)
- Email content discovery
- Document metadata
- User search patterns

**Event Fields:**
- `file_path`: Full path of indexed item
- `file_name`: Filename
- `file_size`: Size in bytes
- `date_modified/created/accessed`: Timestamps
- `author`, `title`, `subject`: Document metadata
- `email_from/to/cc`: Email metadata (if Outlook indexed)

---

### 4. Activities Cache Parser (`activities_parser.py`)

**Location:** `Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db`

**Evidence Value:**
- Application usage timeline
- Files opened per application
- Focus time tracking
- Cross-device sync activity
- Clipboard history

**Event Fields:**
- `activity_type`: App_InFocus, App_Launch, Clipboard, etc.
- `app_id`: Application identifier
- `start_time/end_time`: Activity duration
- `duration_seconds`: Time spent
- `display_text`: Activity description
- `activation_uri`: Deep link to content

---

### 5. Notifications Parser (`notifications_parser.py`)

**Location:** `Users\*\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db`

**Evidence Value:**
- Communication evidence (messaging apps)
- Email arrival notifications
- Application activity
- Deleted message artifacts

**Event Fields:**
- `application`: Source application
- `notification_type`: Toast, Badge, etc.
- `notification_text`: Content (if extractable)
- `arrival_time`: When notification received
- `payload_xml/json`: Full notification content

---

### 6. RDP Bitmap Cache Parser (`rdp_cache_parser.py`)

**Location:** `Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\`

**Evidence Value:**
- Visual evidence of RDP sessions
- What attacker saw during lateral movement
- Data accessed over RDP
- Evidence of specific applications/documents viewed

**Event Fields:**
- `tile_hash`: Unique bitmap identifier
- `tile_width/height`: Dimensions
- `data_size`: Size of cached tile
- `entry_index`: Position in cache

**Note:** Use `bmc-tools` for visual reconstruction:
```bash
pip install bmc-tools --break-system-packages
bmc-tools.py -s Cache0001.bin -d ./output_tiles -b
```

---

### 7. WMI Persistence Parser (`wmi_parser.py`)

**Location:** `Windows\System32\wbem\Repository\OBJECTS.DATA`

**Evidence Value:**
- Malware persistence mechanisms
- Fileless malware detection
- Event subscription backdoors
- Lateral movement evidence

**Event Fields:**
- `wmi_class`: __EventFilter, CommandLineEventConsumer, etc.
- `commands`: Extracted command lines
- `wmi_queries`: WMI queries found
- `suspicious_patterns`: Detected red flags
- `risk_level`: high/medium/low

**Suspicious Indicators:**
- PowerShell, cmd.exe, wscript in commands
- Base64 encoded content
- Hidden/bypass flags
- Non-standard persistence locations

---

### 8. PST/OST Parser (`pst_parser.py`)

**Location:** Various user profile locations

**Evidence Value:**
- Email communication evidence
- Phishing emails
- Data exfiltration planning
- Deleted emails (partially recoverable)

**Requires:** `apt install pst-utils`

**Event Fields:**
- `email_from/to/cc/subject`: Header fields
- `body_preview`: First 1000 chars of body
- `folder`: PST folder location
- `attachments`: List of attachment metadata
- `suspicious_attachment`: Flag for dangerous extensions

---

### 9. Scheduled Tasks Parser (`schtasks_parser.py`)

**Location:** `Windows\System32\Tasks\` (and subdirectories)

**Evidence Value:**
- Persistence mechanisms
- Lateral movement (remote scheduled tasks)
- Backdoors
- Malware execution schedules

**Event Fields:**
- `task_name`: Task file name
- `author`: Task creator
- `registration_date`: When task was created
- `actions`: Commands/scripts to execute
- `command_lines`: Full command lines
- `triggers`: When task runs
- `runs_elevated`: Privilege level
- `hidden`: Whether task is hidden
- `suspicious_indicators`: Risk factors
- `risk_level`: high/medium/low

---

### 10. Teams/Skype Parser (`teams_skype_parser.py`)

**Location:** 
- Skype: `Users\*\AppData\Roaming\Skype\<username>\main.db`
- Teams: `Users\*\AppData\Roaming\Microsoft\Teams\`

**Evidence Value:**
- Communication evidence
- Collaboration on malicious activity
- File sharing evidence
- Call history

**Event Fields (Skype):**
- `author/author_display_name`: Sender
- `message_body`: Message content
- `conversation_id`: Thread identifier
- `call_id/duration_seconds`: Call details
- `file_name/file_size`: Transfer details

**Event Fields (Teams):**
- `message_id`: Unique identifier
- `message_content`: Message body
- `conversation_id`: Thread
- `from`: Sender

---

### 11. USB History Parser (`usb_history_parser.py`)

**Location:** 
- `Windows\INF\setupapi.dev.log`
- Registry exports containing USBSTOR keys

**Evidence Value:**
- Data exfiltration via USB
- Unauthorized device usage
- Timeline of device connections
- Malware delivery via USB

**Event Fields:**
- `vendor_id/product_id`: USB VID/PID
- `serial_number`: Device serial
- `vendor_name`: Resolved vendor (SanDisk, Kingston, etc.)
- `device_type`: Disk, CdRom
- `friendly_name`: Windows-assigned name
- `device_description`: Device class

---

### 12. OneDrive Parser (`onedrive_parser.py`)

**Location:** `Users\*\AppData\Local\Microsoft\OneDrive\`

**Evidence Value:**
- Data exfiltration to cloud
- File access history
- Deleted/synced files
- Account information

**Event Fields:**
- `operation`: upload, download, delete, create
- `file_path`: Synced file path
- `status`: Sync status
- `emails`: Associated accounts
- `sync_paths`: Configured sync folders

---

## Integration Guide

### Adding to task_ingest_files.py

Add detection for each new parser type in the file processing section:

```python
# Thumbcache
elif 'thumbcache' in filename.lower() and file_ext == '.db':
    from parsers.thumbcache_parser import parse_thumbcache_file
    events = list(parse_thumbcache_file(file_path))
    # Index to case_X_filesystem

# BITS
elif filename.lower() == 'qmgr.db' or filename.lower() in ['qmgr0.dat', 'qmgr1.dat']:
    from parsers.bits_parser import parse_bits_file
    events = list(parse_bits_file(file_path))
    # Index to case_X_network

# Windows Search
elif filename.lower() == 'windows.edb':
    from parsers.winsearch_parser import parse_windows_search_file
    events = list(parse_windows_search_file(file_path))
    # Index to case_X_filesystem

# Activities Cache
elif 'activitiescache' in filename.lower() and file_ext == '.db':
    from parsers.activities_parser import parse_activities_cache_file
    events = list(parse_activities_cache_file(file_path))
    # Index to case_X_execution

# Notifications
elif 'wpndatabase' in filename.lower() and file_ext == '.db':
    from parsers.notifications_parser import parse_notifications_file
    events = list(parse_notifications_file(file_path))
    # Index to case_X_events

# RDP Cache
elif filename.lower().startswith('cache') and file_ext == '.bin':
    from parsers.rdp_cache_parser import parse_rdp_cache_file
    events = list(parse_rdp_cache_file(file_path))
    # Index to case_X_filesystem

# WMI
elif filename.lower() in ['objects.data', 'index.btr']:
    from parsers.wmi_parser import parse_wmi_file
    events = list(parse_wmi_file(file_path))
    # Index to case_X_events

# PST/OST
elif file_ext in ['.pst', '.ost']:
    from parsers.pst_parser import parse_pst_file
    events = list(parse_pst_file(file_path))
    # Index to case_X_events

# Scheduled Tasks
elif 'tasks' in file_path.lower() and (file_ext == '.xml' or file_ext == ''):
    from parsers.schtasks_parser import parse_scheduled_task_file
    events = list(parse_scheduled_task_file(file_path))
    # Index to case_X_events

# Teams/Skype
elif 'skype' in file_path.lower() and filename.lower() == 'main.db':
    from parsers.teams_skype_parser import parse_teams_skype_file
    events = list(parse_teams_skype_file(file_path))
    # Index to case_X_events
```

### Using the Parser Factory

```python
from parsers import get_parser, detect_parser_type

# Auto-detect and parse
parser_type = detect_parser_type(filename, parent_dir)
parser_func = get_parser(parser_type)

if parser_func:
    events = list(parser_func(file_path))
```

---

## CyLR Collection Mapping

When processing CyLR artifacts, these parsers cover:

| CyLR Collection | Parser |
|-----------------|--------|
| $MFT | eztools_mft_parser |
| *.evtx | evtx_parser |
| Prefetch/*.pf | dissect_prefetch_parser |
| SRUDB.dat | srum_parser |
| WebCacheV01.dat | webcache_parser |
| Jump Lists | eztools_jumplist_parser |
| *.lnk | lnk_parser |
| thumbcache_*.db | thumbcache_parser |
| qmgr.db | bits_parser |
| Windows.edb | winsearch_parser |
| ActivitiesCache.db | activities_parser |
| wpndatabase.db | notifications_parser |
| Cache*.bin (RDP) | rdp_cache_parser |
| OBJECTS.DATA | wmi_parser |
| *.pst, *.ost | pst_parser |
| Tasks/*.xml | schtasks_parser |
| setupapi.dev.log | usb_history_parser |

---

## Dependencies Summary

```bash
# System packages
sudo apt install pst-utils libesedb-utils

# Python packages
pip install dissect.util pyesedb --break-system-packages
```

All parsers are pure Python except:
- `pst_parser`: Uses `readpst` command-line tool (falls back to basic parsing if unavailable)
- ESE parsers (SRUM, BITS, WebCache, Windows Search): Use `pyesedb` library

---

## Testing

To test individual parsers:

```python
from parsers.thumbcache_parser import parse_thumbcache_file

for event in parse_thumbcache_file('/path/to/thumbcache_256.db'):
    print(event)
```

Or using the factory:

```python
from parsers import get_parser

parser = get_parser('thumbcache')
for event in parser('/path/to/thumbcache_256.db'):
    print(event)
```
