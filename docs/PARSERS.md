# CaseScope Parser Documentation

CaseScope uses a modular parser framework to extract forensic artifacts from various file types. All parsers convert their output to a standardized `ParsedEvent` format for insertion into ClickHouse.

## Parser Framework Overview

### Architecture

```
File → ParserRegistry.detect_type() → Parser.can_parse() → Parser.parse() → ParsedEvent → ClickHouse
```

1. **ParserRegistry** - Central registry that auto-detects file types and routes to appropriate parsers
2. **BaseParser** - Abstract base class all parsers inherit from
3. **ParsedEvent** - Standardized event dataclass for ClickHouse insertion
4. **BatchProcessor** - Handles batched inserts to ClickHouse

### File Locations

| File | Description |
|------|-------------|
| `parsers/__init__.py` | Package exports |
| `parsers/base.py` | BaseParser class, ParsedEvent dataclass |
| `parsers/registry.py` | ParserRegistry, detection, batch processing |
| `parsers/evtx_parser.py` | Windows Event Log parser |
| `parsers/dissect_parsers.py` | Prefetch, Registry, LNK, JumpList, MFT, SRUM |
| `parsers/log_parsers.py` | IIS, Firewall, Huntress, JSON, CSV, SonicWall |
| `parsers/browser_parsers.py` | Firefox, Chrome, Edge SQLite and JSONLZ4 |
| `parsers/windows_parsers.py` | Scheduled Tasks, ActivitiesCache, WebCache |

---

## Parser Reference

### 1. EVTX Parser (Windows Event Logs)

**Class:** `EvtxECmdParser` (v2.2.0)  
**Artifact Type:** `evtx`  
**Files:** `*.evtx` (Magic: `ElfFile\x00`)

#### Description
Parses Windows Event Log files using Eric Zimmerman's EvtxECmd for complete event extraction with field normalization via Maps. Hayabusa provides optional SIGMA detection enrichment.

#### How It Works
1. **Parallel Execution** - EvtxECmd and Hayabusa run simultaneously (~2x speedup)
2. **EvtxECmd** extracts ALL events with Maps-based field normalization
3. **Hayabusa** detects SIGMA rule violations and enriches matching events
4. **Merge** - Results correlated by RecordID after both complete

#### Extracted Fields
- Event metadata: timestamp, event_id, channel, provider, record_id, level
- User: username, domain, SID, logon_type, logon_id
- Logon details: remote_host, workstation_name, auth_package, logon_process
- Process: process_name, process_path, process_id, parent_process, command_line
- Network: src_ip, dst_ip, src_port, dst_port
- Detection: rule_title, rule_level, rule_file, mitre_tactics, mitre_tags
- Maps payload: payload_data1-6 (EvtxECmd extracted summaries)

#### Timestamp Handling
EVTX timestamps are **always UTC** (FILETIME format). No timezone conversion needed.

#### Dependencies
- `/opt/casescope/bin/evtxecmd` - EZ Tools wrapper script
- `/opt/casescope/bin/hayabusa` - Hayabusa binary
- `/opt/casescope/rules/hayabusa-rules` - SIGMA rules

#### Fallback
`EvtxFallbackParser` uses pyevtx-rs if EvtxECmd unavailable (no Maps, no detection).

---

### 2. Prefetch Parser

**Class:** `PrefetchParser` (v2.0.0)  
**Artifact Type:** `prefetch`  
**Files:** `*.pf` (Magic: `SCCA` or `MAM\x04`)

#### Description
Parses Windows Prefetch files to extract program execution history including timestamps, run counts, and loaded files.

#### How It Works
Uses `dissect.target` to parse the Prefetch file structure:
1. Extracts executable name from header or filename
2. Retrieves all execution timestamps (latest + previous)
3. Collects loaded files from metrics
4. Creates one event per execution timestamp

#### Extracted Fields
- process_name: Executed program name
- timestamp: Execution timestamp
- Extra: run_count, run_index, total_runs, prefetch_version, loaded_files

#### Timestamp Handling
Prefetch timestamps are **UTC** (Windows FILETIME).

---

### 3. Registry Parser

**Class:** `RegistryParser` (v2.0.0)  
**Artifact Type:** `registry`  
**Files:** SAM, SECURITY, SOFTWARE, SYSTEM, NTUSER.DAT, USRCLASS.DAT, *.hve (Magic: `regf`)

#### Description
Parses Windows Registry hives extracting keys and values. Creates individual events for each registry value for granular searching.

#### How It Works
Uses `dissect.regf` to parse registry hive structure:
1. Identifies hive type from filename
2. Recursively processes keys up to max_depth
3. Each value becomes a separate event with key path, value name, type, and data

#### Extracted Fields
- reg_key: Full registry key path
- reg_value: Value name (or "(Default)")
- reg_data: Value data (decoded, truncated to 2000 chars)
- Extra: hive_type, value_type

#### High-Value Keys (when extract_all=False)
- Run/RunOnce keys (persistence)
- Services
- USB/USBSTOR (device history)
- NetworkList (network profiles)
- UserAssist, RecentDocs, ShellBags

#### Timestamp Handling
Registry timestamps are **UTC** (Windows FILETIME).

#### Excluded Files
- Transaction logs: `.log`, `.log1`, `.log2`, `.blf`, `.regtrans-ms`
- SA.DAT (Scheduled Tasks state file)

---

### 4. LNK Parser (Shortcuts)

**Class:** `LnkParser` (v2.1.0)  
**Artifact Type:** `lnk`  
**Files:** `*.lnk` (Magic: `\x4c\x00\x00\x00`)

#### Description
Parses Windows shortcut files extracting target paths, timestamps, arguments, and machine tracking data.

#### How It Works
Uses `dissect.shellitem.lnk` to parse LNK structure:
1. Extracts target path from linkinfo
2. Gets relative path, arguments, working directory from stringdata
3. Retrieves MACB timestamps from link_header
4. Extracts machine_id and droids from extradata (TRACKER_PROPS)

#### Extracted Fields
- target_path: Target file/program path
- command_line: Arguments
- process_name: Target filename
- file_size: Target file size
- Extra: machine_id, volume_droid, file_droid, creation/access/write times

#### Special Handling
- Shell folder shortcuts (Control Panel, etc.) marked as partial
- URI scheme shortcuts (ms-settings:) handled gracefully
- Missing targets use filename as identifier

---

### 5. JumpList Parser

**Class:** `JumpListParser` (v2.1.0)  
**Artifact Type:** `jumplist`  
**Files:** `*.automaticDestinations-ms`, `*.customDestinations-ms`

#### Description
Parses Windows Jump Lists containing recent files accessed via applications. Each entry is an embedded LNK file.

#### How It Works
Uses `dissect.ole` to parse the OLE compound file:
1. Extracts AppID from filename hash
2. Iterates OLE streams (skipping DestList metadata)
3. Each stream contains an embedded LNK parsed with `dissect.shellitem.lnk`
4. Handles corrupt/empty OLE files gracefully

#### Extracted Fields
- target_path: Target file path
- command_line: Arguments
- process_name: Target filename
- Extra: app_id, entry_id, machine_id, timestamps

#### Error Handling
- Files too small (<512 bytes) yield status event
- Invalid OLE signature yields corrupt status event
- Empty files tracked for audit purposes

---

### 6. MFT Parser (NTFS Master File Table)

**Class:** `MFTParser` (v2.0.0)  
**Artifact Type:** `mft`  
**Files:** `$MFT`, `$MFT_MIRR` (Magic: `FILE`)

#### Description
Parses NTFS Master File Table extracting file metadata and all MACB timestamps.

#### How It Works
Uses `dissect.ntfs` to iterate MFT records:
1. Extracts filename and record number
2. Gets MACB timestamps from STANDARD_INFORMATION
3. Determines file vs directory
4. Optional max_entries limit for large MFTs

#### Extracted Fields
- target_path: Filename
- file_size: File size in bytes
- Extra: record_number, is_directory, si_created/modified/accessed/changed

#### Timestamp Handling
MFT timestamps are **UTC** (Windows FILETIME).

---

### 7. SRUM Parser (System Resource Usage Monitor)

**Class:** `SRUMParser` (v1.1.0)  
**Artifact Type:** `srum`  
**Files:** `SRUDB.dat`, `SRU.dat`

#### Description
Parses Windows SRUM database containing application resource usage, network connectivity, energy usage, and push notifications.

#### How It Works
Uses `dissect.esedb` to parse the ESE database:
1. Loads SruDbIdMapTable to resolve AppId/UserId references
2. Processes each SRUM table (identified by GUID)
3. Converts OLE Automation Date timestamps
4. Resolves IDs to actual application paths/usernames

#### Known SRUM Tables
| GUID | Description |
|------|-------------|
| {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} | Application Resource Usage |
| {973F5D5C-1D90-4944-BE8E-24B94231A174} | Network Connectivity |
| {DD6636C4-8929-4683-974E-22C046A43763} | Network Data Usage |
| {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37} | Energy Usage |
| {DA73FB89-2BEA-4DDC-86B8-6E048C6DA477} | Push Notifications |

#### Extracted Fields
- process_name: Application name (resolved from IdMap)
- username: User name (resolved from IdMap)
- Extra: table, table_description, app_id, user_id

---

### 8. IIS Log Parser

**Class:** `IISLogParser` (v1.0.0)  
**Artifact Type:** `iis`  
**Files:** `u_ex*.log`, `w3svc*.log` (W3C Extended format)

#### Description
Parses IIS Web Server logs in W3C Extended Log Format.

#### How It Works
1. Looks for `#Software: Microsoft Internet Information Services` header
2. Parses `#Fields:` directive to determine column order
3. Maps fields to normalized names

#### Extracted Fields
- timestamp: date + time
- username: cs-username
- src_ip: c-ip (client IP)
- dst_ip: s-ip (server IP)
- dst_port: s-port
- target_path: cs-uri-stem + cs-uri-query
- Extra: method, status_code, user_agent

#### Timestamp Handling
IIS timestamps are **ambiguous** (local time). Uses case timezone for conversion.

---

### 9. Firewall Log Parser

**Class:** `FirewallLogParser` (v1.0.0)  
**Artifact Type:** `firewall`  
**Files:** Files containing `firewall`, `sonicwall`, `pfsense`, `syslog`, `fw` in name

#### Description
Parses syslog-format firewall logs with key=value pairs.

#### How It Works
1. Matches syslog timestamp pattern
2. Extracts key=value pairs from message
3. Maps to normalized network fields

#### Extracted Fields
- timestamp: Parsed from syslog format or time/datetime fields
- src_ip, dst_ip: From src/srcip/src_ip fields
- src_port, dst_port: From srcport/dstport fields
- Extra: action, protocol

#### Timestamp Handling
Firewall timestamps are **ambiguous**. Uses case timezone for conversion.

---

### 10. Huntress Parser (EDR)

**Class:** `HuntressParser` (v2.1.0)  
**Artifact Type:** `huntress`  
**Files:** `*huntress*.json`, `*.ndjson`, `*.jsonl` (with ECS structure)

#### Description
Parses Huntress EDR NDJSON exports with full ECS (Elastic Common Schema) field mapping.

#### How It Works
1. Detects Huntress via `huntress.io` in content or ECS structure
2. Extracts nested ECS fields (host, process, user, event, agent)
3. Maps to ParsedEvent with complete process chain

#### Extracted Fields
- Host: hostname, host_ip, host_domain, os_full
- Process: name, path, pid, command_line, hash (MD5/SHA1/SHA256)
- Parent/Grandparent: Full process chain
- User: name, domain, SID, elevation_type
- Code Signature: exists, valid, subject, issuer
- PE Info: original_name, imphash, compile_time
- Event: kind, category, type
- Organization: account_id, account_name, org_id, org_name

#### Timestamp Handling
Huntress uses **UTC** timestamps (`@timestamp` field).

---

### 11. Generic JSON Parser

**Class:** `GenericJSONParser` (v1.1.0)  
**Artifact Type:** `json_log`  
**Files:** `*.json`, `*.ndjson`, `*.jsonl`

#### Description
Fallback parser for JSON-formatted logs that don't match specific parsers. Extracts common user/system/process fields.

#### How It Works
1. Handles both JSON arrays and NDJSON
2. Tries multiple field name patterns for each extracted field
3. Supports ECS nested structure and flat field formats

#### Extracted Fields
- username, domain, sid: From various field patterns
- source_host: From host.hostname or flat hostname field
- Process fields: From process object or flat fields
- Network fields: From source/destination objects or flat fields

---

### 12. CSV Log Parser

**Class:** `CSVLogParser` (v1.0.0)  
**Artifact Type:** `csv_log`  
**Files:** `*.csv`

#### Description
Generic parser for CSV-formatted log files. Auto-detects CSV dialect.

#### Timestamp Handling
CSV timestamps are **ambiguous**. Uses case timezone for conversion.

---

### 13. SonicWall CSV Parser

**Class:** `SonicWallCSVParser` (v1.0.0)  
**Artifact Type:** `sonicwall`  
**Files:** `*.csv` with SonicWall headers

#### Description
Specialized parser for SonicWall firewall CSV exports (51-column format).

#### Detection
Looks for header containing `"Time"`, `"Src. IP"`, and `"FW Action"`.

#### Extracted Fields
- timestamp: Time field
- src_ip, dst_ip: Source/destination IPs
- src_port, dst_port: Source/destination ports
- username: User Name
- event_id: ID
- channel: Category
- rule_title: FW Action + Event
- Extra: Full 51-column mapping including zones, NAT, VPN, IDP

#### Timestamp Handling
SonicWall timestamps are **ambiguous**. Uses case timezone for conversion.

---

### 14. Browser SQLite Parser

**Class:** `BrowserSQLiteParser` (v1.0.1)  
**Artifact Type:** `browser` (subtypes: `browser_history`, `browser_cookies`, etc.)  
**Files:** `places.sqlite`, `cookies.sqlite`, `History`, `Cookies`, etc.

#### Description
Parses browser SQLite databases from Firefox, Chrome, and Edge.

#### Supported Databases

| Database | Browser | Artifact Type |
|----------|---------|---------------|
| places.sqlite | Firefox | browser_history, browser_download |
| cookies.sqlite | Firefox | browser_cookies |
| formhistory.sqlite | Firefox | browser_forms |
| downloads.sqlite | Firefox | browser_download |
| History | Chrome/Edge | browser_history, browser_download |
| Cookies | Chrome/Edge | browser_cookies |
| Login Data | Chrome/Edge | browser_logins |
| Web Data | Chrome/Edge | browser_autofill |

#### How It Works
1. Identifies database type by filename or table structure
2. Copies to temp directory (SQLite needs write access for WAL)
3. Routes to appropriate parsing method
4. Converts WebKit/Mozilla timestamps to datetime

#### Timestamp Conversion
- **Chrome/Edge**: WebKit timestamps (microseconds since 1601-01-01) - **UTC**
- **Firefox**: Mozilla PRTime (microseconds since Unix epoch) - **UTC**

#### Excluded Files
Windows cache files that are SQLite but not browser databases:
- `iconcache_*.db`, `thumbcache_*.db`
- `staterepository-*.srd`, `cachedata.db`

---

### 15. Firefox JSONLZ4 Parser

**Class:** `FirefoxJSONLZ4Parser` (v1.0.0)  
**Artifact Type:** `firefox_session` (and subtypes)  
**Files:** `*.jsonlz4`, `*.mozlz4`, `*.baklz4` (Magic: `mozLz40\x00`)

#### Description
Parses Firefox LZ4-compressed JSON files including session data, search engines, and extensions.

#### How It Works
1. Validates Mozilla LZ4 magic header
2. Decompresses using lz4.block
3. Routes based on filename:
   - `sessionstore*` → Session tabs/windows
   - `search*` → Search engine config
   - `addon*`/`extension*` → Installed extensions
   - `handler*` → Protocol handlers

#### Extracted Fields (Session)
- target_path: Tab URL
- Extra: window_index, tab_index, referrer, closed status

---

### 16. Scheduled Task Parser

**Class:** `ScheduledTaskParser` (v1.0.0)  
**Artifact Type:** `scheduled_task`  
**Files:** XML files in `/Tasks/` directory

#### Description
Parses Windows Task Scheduler XML files containing task definitions.

#### How It Works
1. Detects by path containing `/tasks/`
2. Handles UTF-16LE encoding (common for Task Scheduler)
3. Extracts registration info, triggers, actions, and principal

#### Extracted Fields
- process_name: Executed command filename
- command_line: Command + arguments
- username: Principal user ID
- Extra: uri, author, enabled, hidden, run_level, triggers, actions

#### Timestamp Handling
Scheduled task timestamps are **ambiguous**. Uses case timezone for conversion.

---

### 17. ActivitiesCache Parser (Windows Timeline)

**Class:** `ActivitiesCacheParser` (v1.0.0)  
**Artifact Type:** `activities_cache`  
**Files:** `ActivitiesCache.db`

#### Description
Parses Windows Timeline database containing application usage and file access history.

#### Tables Parsed
- **Activity**: Main activity records (app usage, file access)
- **ActivityOperation**: Clipboard and sync operations

#### Activity Types
| ID | Type |
|----|------|
| 5 | App in use/Focus |
| 6 | App in use |
| 10 | Clipboard |
| 16 | Copy/Paste |

#### Extracted Fields
- process_name: App display name or app_id
- target_path: Content URI
- Extra: activity_type, duration_seconds, is_local_only

---

### 18. WebCache Parser (IE/Edge)

**Class:** `WebCacheParser` (v1.0.0)  
**Artifact Type:** `webcache` (subtypes: `webcache_history`, `webcache_cookies`, etc.)  
**Files:** `WebCacheV01.dat`, `WebCacheV24.dat`

#### Description
Parses Windows WebCache ESE database containing IE/legacy Edge browsing data.

#### Container Types
| Container | Artifact Type |
|-----------|---------------|
| Content | webcache_cache |
| Cookies | webcache_cookies |
| History | webcache_history |
| DOMStore | webcache_dom_storage |
| iedownload | webcache_downloads |

#### How It Works
Uses `dissect.esedb` to parse the ESE database:
1. Gets container mapping from Containers table
2. Processes Container_N tables
3. Each entry yields an event with container context

#### Timestamp Handling
WebCache uses **Windows FILETIME** which is **UTC**.

---

## Timestamp Handling Summary

### UTC Sources (No conversion needed)
- EVTX (Windows FILETIME)
- Browser databases (WebKit/Mozilla)
- MFT, Registry (Windows FILETIME)
- Huntress/EDR (ISO 8601 UTC)
- WebCache (Windows FILETIME)

### Ambiguous Sources (Use case timezone)
- IIS logs (local time)
- Firewall/syslog logs (local time)
- SonicWall CSV (local time)
- Generic CSV (unknown)
- Scheduled Tasks (local time)

The `timestamp_source_tz` field in `ParsedEvent` indicates the assumed timezone. UTC conversion is handled by `utils/timezone.py`.

---

## Parser Detection Priority

Parsers are matched in priority order (lower = higher priority):

| Priority | Parsers |
|----------|---------|
| 5 | ScheduledTask |
| 10 | EVTX, Prefetch, Registry, LNK, JumpList, MFT, SRUM, ActivitiesCache, WebCache, Firefox JSONLZ4 |
| 15 | Browser SQLite, SonicWall CSV |
| 20 | IIS, Huntress |
| 30 | Firewall |
| 90 | Generic JSON, Generic CSV (fallbacks) |

---

## Adding a New Parser

1. Create parser class inheriting from `BaseParser`
2. Implement required methods:
   - `artifact_type` property
   - `can_parse(file_path)` method
   - `parse(file_path)` generator yielding `ParsedEvent`
3. Register in `registry.py` `_register_default_parsers()`

Example:
```python
class MyParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'my_artifact'
    
    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE
    
    def can_parse(self, file_path: str) -> bool:
        return file_path.endswith('.myext')
    
    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        # Parse logic here
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=timestamp,
            source_file=os.path.basename(file_path),
            ...
        )
```

---

## Dependencies

### Python Packages
- `dissect.target` - Prefetch parsing
- `dissect.regf` - Registry hive parsing
- `dissect.shellitem` - LNK parsing
- `dissect.ole` - JumpList OLE parsing
- `dissect.ntfs` - MFT parsing
- `dissect.esedb` - SRUM and WebCache ESE parsing
- `lz4` - Firefox JSONLZ4 decompression
- `evtx` (pyevtx-rs) - Fallback EVTX parsing

### External Tools
- **EvtxECmd** - `/opt/casescope/bin/evtxecmd`
- **Hayabusa** - `/opt/casescope/bin/hayabusa`
- **.NET Runtime** - Required for EvtxECmd
