# Artifact Hunting

Artifact Hunting is the case-level review surface opened from the left menu item **Hunt Artifacts**. It loads `/case/hunting` and presents parsed artifacts that were normalized into the ClickHouse `events` table. The page is a shared event grid with artifact-specific tabs, search, filtering, details, raw data review, analyst tagging, noise handling, exports, and optional AI-assisted review.

This page documents what each Hunt Artifacts tab contains and how the hunting controls work.

## How Hunting Is Built

CaseScope defines the Hunt Artifacts tabs in `parsers/catalog.py`. Each tab maps to one or more stored `artifact_type` values. The hunting page sends those values to `/api/hunting/events/<case_id>`, which queries ClickHouse and returns paginated event rows.

Every row can include normalized fields such as:

- Timestamp and UTC timestamp
- Artifact type
- Source file, source path, and source host
- Event ID, channel, provider, record ID, and level
- Username, domain, SID, and logon type
- Process name, path, PID, parent process, parent PID, and command line
- Target path, hashes, and file size
- Source and destination IPs and ports
- Registry key, value, and data
- Detection metadata such as rule title, rule level, rule file, MITRE tactics, and MITRE tags
- `search_blob`, `extra_fields`, and `raw_json` for parser-specific detail
- Effective IOC, noise, and analyst tag state

The visible row description is built from the most useful available fields. EVTX rows emphasize channel and provider, user/process rows show account and process context, file-oriented rows show target paths, and rows without normalized fields fall back to `search_blob`.

## Shared Grid Behavior

The Events, Browsers, File System, Registry, IIS, Tasks, Apps & Network, and Acquisition tabs all use the same event grid. The Other tab is different: it currently hosts Noise Detection actions rather than a direct artifact list.

The grid provides:

- Search across normalized fields and `search_blob`
- Time range filters: no limit, last 1 day, last 3 days, last 7 days, last 30 days, or custom case-timezone range
- Pagination at 50, 100, 200, or 500 rows per page
- Event detail modal with Info, Raw Data, and Process Analysis tabs
- Raw data tree review with addable custom columns
- Per-tab custom columns stored in browser local storage
- Analyst tagging and notes
- Bulk analyst tagging, untagging, and noise marking
- Export Tagged and Export View JSON downloads
- Unified Findings summary above the grid
- Optional AI Review and Chat Agent buttons when AI features are enabled
- Hunt Patterns, which runs rule-based attack pattern checks against the current case

## Search Syntax

Search terms are combined with AND by default. Use `|` for OR, parentheses for grouped OR searches, and `-` to exclude terms.

Examples:

- `4624 Security` finds rows matching both terms.
- `4624|4625` finds either event ID.
- `(4624 logontype:10)|4778|4779|1149` finds common RDP activity.
- `powershell -encodedcommand` finds rows containing PowerShell and excluding encodedcommand.
- `-"NT AUTHORITY"` excludes a phrase.

Fielded search maps common analyst terms to normalized columns. Supported examples include:

- `eventid:4624`, `event_id:4624`, or `id:4624`
- `channel:Security`
- `provider:Microsoft-Windows-Security-Auditing`
- `host:DC01`, `hostname:DC01`, or `computer:DC01`
- `artifact:evtx`, `parser:evtx`, or `type:evtx`
- `user:admin`, `domain:CONTOSO`, or `sid:S-1-5-...`
- `logontype:3`
- `process:powershell`, `cmd:encoded`, `parent:cmd`
- `pid:1234` or `ppid:5678`
- `path:AppData`, `file:invoice.exe`, or `filename:invoice.exe`
- `md5:<hash>`, `sha1:<hash>`, `sha256:<hash>`, or `hash:<hash>`
- `ip:10.0.0.5`, `src_ip:10.0.0.5`, `dst_ip:10.0.0.8`
- `srcport:443`, `dstport:3389`, or `port:3389`
- `natip:203.0.113.10`
- `regkey:Run`, `regvalue:Updater`, or `regdata:powershell`
- `rule:credential`, `severity:high`, or `rule_level:critical`

Unknown field names are searched as `field:value` tokens in `search_blob`, which preserves many parser-specific raw fields.

## Alert And Display Filters

The Events tab has event-family filters:

- EVTX Files maps to `evtx`.
- Firewall Logs maps to `firewall`, `sonicwall`, `sonicwall_syslog`, `palo_alto`, `fortigate`, `pfsense`, `cisco_asa`, and `suricata`.
- EDR Platforms maps to `huntress`, `defender_av`, `mde_xdr`, `crowdstrike`, `sentinelone`, and `sophos`.
- Other includes remaining artifact types on the Events tab.

Alert filters apply across shared grid tabs:

- SIGMA Violations means rows with rule title or rule level metadata. On non-Events tabs this is excluded by default.
- IOCs Found means rows with effective IOC state.
- Analyst Tagged means rows tagged by an analyst.
- Other Alerts means rows that have no SIGMA metadata, no IOC match, and are not analyst tagged.
- AI Tagged is currently a disabled placeholder.

SIGMA severity filtering is Events-tab only and narrows rule levels to Info, Low, Medium, or High/Critical.

Noise Events are hidden by default on the Events tab. Enabling the display filter includes rows matched by noise rules. The Other tab includes the Noise Detection action, which scans events for configured known-good rules and records effective noise state.

## Events Tab

The Events tab is the broadest hunting surface. It combines Windows events, firewall logs, EDR exports, generic structured logs, host metadata, diagnostic artifacts, and vendor exports.

Windows Event Logs:

- `evtx`
- Parsed from EVTX inputs.
- Stored as normalized event rows with event ID, channel, provider, record ID, level, user, host, process, network, registry, and raw JSON fields when available.
- Enriched with Hayabusa/SIGMA metadata when rule matches exist.
- Uses UTC timestamp behavior.
- Best for authentication review, administrative activity, service creation, PowerShell, process creation, account changes, policy changes, and Windows telemetry.

Firewall and network security logs:

- `firewall`, `sonicwall`, `sonicwall_syslog`, `palo_alto`, `fortigate`, `pfsense`, `cisco_asa`, `suricata`
- Normalize source/destination IPs, ports, action/event text, host/source metadata, and parser-specific fields.
- Most firewall exports use the case timezone; Suricata uses UTC behavior.
- Best for connection review, denied traffic, NAT context, perimeter activity, VPN/firewall events, IDS alerts, and host-to-host pivoting.

EDR and security platform exports:

- `huntress`, `defender_av`, `mde_xdr`, `crowdstrike`, `sentinelone`, `sophos`
- Stored in the event grid with command-line, process, host, user, file, hash, detection, and raw vendor fields when available.
- Use UTC timestamp behavior.
- Best for process execution, detections, malware alerts, endpoint containment context, file hashes, parent/child process leads, and vendor alert pivots.

Generic and timeline-style logs:

- `json_log`, `csv_log`, `velociraptor`, `plaso`
- Store structured rows from generic uploads and timeline exports.
- JSON, Velociraptor, and Plaso use UTC behavior; generic CSV uses case timezone behavior.
- Best for bringing external triage exports into the same search and tagging workflow.

Host and diagnostic event sources:

- `powershell_history`, `hosts`, `diagnostic_log`, `etl_trace`, `windows_error_report`, `wbem_repository`, `cloud_metadata`
- Cover PowerShell console history, hosts file content, Windows diagnostic logs, ETL traces, Windows Error Reporting, WBEM/WMI repository metadata, and cloud sync metadata.
- Timestamp behavior depends on parser family: PowerShell history and hosts use case timezone behavior; diagnostic, ETL, WER, WBEM, and cloud metadata use UTC behavior.
- Best for command history, suspicious name resolution, WMI persistence leads, crash/error context, and application or cloud-client metadata.

## Browsers Tab

The Browsers tab collects browser and web activity artifacts.

Browser SQLite artifacts:

- `browser`, `browser_history`, `browser_cookies`, `browser_forms`, `browser_logins`, `browser_autofill`, `browser_download`
- Cover browser history, cookies, form entries, saved login metadata, autofill data, and downloads.
- Use UTC timestamp behavior.
- Best for user web activity, downloaded payloads, phishing links, visited infrastructure, credential storage clues, and browser form/autofill pivots.

Firefox storage and profile artifacts:

- `sqlite_firefox_origin_storage`, `sqlite_firefox_cache_storage`, `sqlite_firefox_indexeddb`
- `firefox_session`
- `firefox_json`, `firefox_addon`, `firefox_search_engine`, `firefox_handler`
- Cover Firefox storage databases, session files, JSON profile artifacts, installed add-ons, search engines, and protocol/file handlers.
- Use UTC timestamp behavior.
- Best for persistence or policy clues in browser profiles, suspicious add-ons, session recovery, cached web application data, and non-history browser evidence.

WebCache artifacts:

- `webcache`, `webcache_history`, `webcache_cookies`, `webcache_cache`, `webcache_downloads`, `webcache_dom_storage`, `webcache_compatibility`
- Cover Windows WebCache ESE records including history, cookies, cache, downloads, DOM storage, and compatibility records.
- Use UTC timestamp behavior.
- Best for Internet Explorer, Edge Legacy, and Windows web activity not present in standard browser SQLite databases.

Browser state:

- `browser_state`
- Covers browser profile state files.
- Use UTC timestamp behavior.
- Best for profile configuration, state, and browser-environment context.

The Browsers tab also exposes a preconfigured **Downloaded Files** action. It opens a dedicated modal backed by `/api/hunting/browser/downloads/<case_id>` and lists user-initiated browser downloads with timestamp, host, user, filename, file path, source URL, and IOC indicators.

## File System Tab

The File System tab contains file, filesystem metadata, execution trace, collection, and triage artifacts.

Execution and shell artifacts:

- `prefetch`
- `lnk`
- `jumplist`
- These use UTC timestamp behavior.
- Best for program execution, file opening, removable media traces, shortcut targets, application usage, and user activity timelines.

NTFS and filesystem metadata:

- `mft`
- `usn`
- `ntfs_metadata`, `ntfs_logfile`
- These use UTC timestamp behavior.
- Best for file creation, modification, deletion, rename, path activity, and filesystem timeline reconstruction.

System setup and shell-adjacent artifacts:

- `setupapi`
- `windows_search_db`
- `recycle_bin`
- `transaction_sidecar`
- SetupAPI uses case timezone behavior. Windows Search, Recycle Bin, and transaction sidecar metadata use UTC behavior.
- Best for device installation, indexed file discovery, deleted item review, and transaction metadata.

Collection and file triage artifacts:

- `file_triage`
- `office_autosave`
- `crash_dump_triage`
- These use UTC timestamp behavior.
- Best for collected-file security review, Office recovery artifacts, suspicious recovered documents, and crash dump triage metadata.

## Registry Tab

The Registry tab maps to:

- `registry`

Registry rows are stored in the shared event model with normalized registry fields:

- `reg_key`
- `reg_value`
- `reg_data`
- source file and source path
- host and timestamp context
- parser-specific detail in `extra_fields` and `raw_json`

Registry artifacts use UTC timestamp behavior. This tab is best for Run keys, services, shell extensions, persistence mechanisms, user assist-style leads, policy changes, installed software, autostart locations, and host configuration pivots.

## IIS Tab

The IIS tab maps to:

- `iis`

IIS logs are standard event rows using case timezone behavior. They are useful for reviewing web server traffic, client IPs, requested resources, status codes, user agents, suspicious paths, webshell access, authentication activity, and exploitation attempts.

## Tasks Tab

The Tasks tab maps to:

- `scheduled_task`

Scheduled task artifacts use case timezone behavior. They are useful for persistence review, task author and principal review, action command lines, trigger timing, suspicious task names, and task paths.

## Apps & Network Tab

The Apps & Network tab contains Windows application and activity telemetry.

SRUM:

- `srum`
- Uses UTC timestamp behavior.
- Best for application usage, network usage, user/SID context, and host activity over time.

Windows Timeline:

- `activities_cache`
- `activity_operation`
- Uses UTC timestamp behavior.
- Best for user activity, application launches, documents, URLs, timeline operations, and cross-device activity records when present.

## Acquisition Tab

The Acquisition tab maps to:

- `kape_log`

KAPE acquisition logs use UTC timestamp behavior. They are useful for understanding what was collected, when collection ran, collection warnings/errors, module behavior, and acquisition provenance.

## Other Tab

The Other tab currently hosts hunting utilities rather than a direct event list. Its primary function is Noise Detection:

- Shows active noise rule count, last scan time, and events tagged as noise.
- Starts a background noise tagging task.
- Displays scan progress and results.
- Links to noise rule management in Settings.

Noise state is stored separately and projected into hunting queries so noise can be hidden or shown without rewriting the original event rows.

## Detail Review

Selecting an event opens an event detail modal with:

- Source section: timestamp, host, artifact type, source file, source path
- Event info: event ID, channel, provider, record ID, level
- User section when account fields exist
- Process section and full command line when process fields exist
- File section when target path, hashes, or size exist
- Network section when IP, port, or NAT fields exist
- Registry section when registry fields exist
- Detection section when rule metadata exists, including MITRE tactics and tags
- Analyst tagging section for tags and notes

The Raw Data tab fetches the full matching ClickHouse row and renders expandable raw data. Analysts can add any raw field as a custom column for the current tab.

The Process Analysis tab uses process-related fields from the event to pivot into parent and child process context where available.

## Exports

Export Tagged downloads all analyst-tagged events for the case.

Export View downloads all events that match the current search, tab, artifact type filter, alert filters, severity filters, noise setting, and time range. Exports include full row data rather than only the visible page.

## Timezone Behavior

The hunting API formats timestamps in the case timezone for display. Custom time range input is interpreted in the case timezone and converted to UTC for ClickHouse filtering.

Parser families still have source timestamp behavior:

- UTC behavior means the parser treats source timestamps as UTC-normalized.
- Case behavior means the parser treats source timestamps relative to the case timezone.

When reviewing mixed artifacts, prefer the displayed case-time value for analyst workflow and use raw data when validating original source timestamps.

## Relationship To Other Hunting Pages

Hunt Artifacts is the normalized event/artifact hunting surface.

Related pages use different storage models:

- Hunt Processes combines process analysis across event and memory-derived sources.
- Hunt Memory reviews Volatility-derived PostgreSQL memory tables.
- Hunt Network reviews PCAP/Zeek network log tables.

Use Hunt Artifacts when the evidence has been parsed into the standard `events` table. Use the specialized hunting pages when the evidence lives in dedicated process, memory, or network stores.
