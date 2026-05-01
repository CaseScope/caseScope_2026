# Memory Hunting

> **Note:** CaseScope memory hunting is built from Volatility3 output that has been ingested into PostgreSQL memory tables. The page reviews completed memory jobs for the active case.

## Overview

The **Hunt Memory** page is the analyst view for memory-derived artifacts. It is separate from Hunt Artifacts because memory data is stored in dedicated PostgreSQL tables instead of the normalized ClickHouse `events` table.

Use this page when the question involves:

- Processes and process trees from a memory image
- Network sockets recovered from memory
- Windows services and their execution paths
- Suspicious executable memory regions
- Credentials and secrets extracted by selected Volatility plugins
- System metadata from the memory image
- Repeated processes, IPs, or services across multiple memory dumps in the same case

The left menu entry is **Hunt Memory**. The page loads completed memory jobs for the current case, auto-selects the first available job in the selector, and then displays the artifact tabs for that job.

## Data Flow

Memory hunting starts with a memory job created from the Memory Files workflow.

1. A memory image is tracked in `memory_jobs` with hostname, operating system, memory type, selected plugins, status, timestamps, and output paths.
2. Celery runs selected Volatility3 plugins and writes JSON output under the job output folder.
3. The memory parser ingests supported JSON files into dedicated `memory_*` PostgreSQL tables.
4. Cross-memory counts are recalculated for repeated process names, foreign IP addresses, and service names across memory jobs in the same case.
5. Hunt Memory reads only jobs with status `completed`.

If a completed job has no ingested hunting data, the job still appears in the selector with an explanatory no-data state when available.

## Supported Hunt Memory Tabs

### Processes

Source plugins:

- `windows.pslist`
- `windows.pstree`
- `windows.cmdline`

Storage table: `memory_processes`

The Processes tab shows process activity recovered from memory. It supports a tree view and a list view.

The stored fields include:

- PID and PPID
- Process name and lower-case search name
- Path, command line, and audit path when provided by Volatility
- Session ID, thread count, handle count, and WoW64 flag
- Process create time and exit time
- Cross-memory count

`windows.pslist` creates the baseline process rows. `windows.pstree` updates or creates rows with parent/child context, path, command line, and audit path. `windows.cmdline` updates existing process rows with command-line arguments when available.

The tree is built from PID and PPID relationships within the selected memory job. Root nodes are processes whose parent PID is missing or not present in that job. Tree children start collapsed and can be expanded or collapsed from the toolbar.

Process rows can pivot to Hunt Artifacts by opening the main hunting page with the process name pre-filled as the search term. Selecting a process in the tree opens a detail modal with PID, PPID, session, threads, WoW64 state, create and exit times, path, and command line.

Important caveats:

- `windows.psscan` output is retained as raw plugin output but is not ingested into `memory_processes`; this avoids duplicate rows with `windows.pslist`.
- Corrupt rows with invalid PID values are skipped.
- Process names that are mostly non-printable are skipped.
- Memory process records do not currently store a username.
- Parent names are not stored directly; lineage is derived from PID and PPID.

### Network

Source plugins:

- `windows.netscan`
- `windows.netstat`

Storage table: `memory_network`

The Network tab shows sockets and connections recovered from memory. It supports text search and state filtering.

The stored fields include:

- Protocol such as TCPv4, TCPv6, UDPv4, or UDPv6
- Local address and port
- Foreign address and port
- Connection state
- PID and owner process name
- Offset and created time
- Cross-memory count

The tab searches local address, foreign address, and owner process name. It also builds a state dropdown from distinct states in the selected job.

When both `windows.netscan` and `windows.netstat` output exist, `windows.netstat` ingestion is skipped if `windows.netscan` already produced rows. During processing, CaseScope can automatically add `windows.netstat` if `windows.netscan` completes with zero rows and `windows.netstat` was not already selected.

Network rows can pivot to Hunt Artifacts by searching for the foreign address. Cross-memory badges are based on the same foreign address appearing in multiple memory jobs, excluding empty placeholder addresses such as `0.0.0.0` and `::`.

### Services

Source plugin: `windows.svcscan`

Storage table: `memory_services`

The Services tab shows Windows service records recovered from memory. It supports text search and state filtering.

The stored fields include:

- Service name and lower-case search name
- Display name
- Binary path
- Registry binary path
- Service DLL
- Service state
- Start type
- Service type
- PID, offset, and order
- Cross-memory count

The tab searches service name, display name, binary path, and registry binary path. The displayed binary path prefers the direct binary path and falls back to the registry binary path.

Service rows can pivot to Hunt Artifacts by searching for the service name. Cross-memory badges are based on the same lower-case service name appearing in more than one memory job for the case.

### Injections

Source plugin: `windows.malfind`

Storage table: `memory_malfind`

The Injections tab displays suspicious memory regions identified by Volatility `malfind`. It supports search by process name.

The stored fields include:

- PID and process name
- Memory protection, such as executable writable regions
- Start VPN and end VPN
- VAD tag
- Commit charge
- Private memory flag
- Hexdump
- Disassembly
- Notes
- Cross-memory count

The UI presents each finding as a card with process name, PID, protection, VPN range, and hexdump when available. If no rows exist, the tab shows a "No Suspicious Memory Regions" empty state.

Malfind rows can pivot to Hunt Artifacts by searching for the associated process name.

Important caveats:

- `malfind` is a lead-generation artifact, not a verdict. Treat hits as regions that deserve review with process lineage, loaded modules, command line, network activity, and case events.
- Rows with invalid PID values are skipped during ingestion.

### Credentials

Source plugins:

- `windows.hashdump`
- `windows.cachedump`
- `windows.lsadump`

Storage table: `memory_credentials`

The Credentials tab shows credential material recovered by selected sensitive Volatility plugins. It supports filtering by source plugin:

- `hashdump` for SAM hashes
- `cachedump` for cached domain credentials
- `lsadump` for LSA secrets

The stored fields include:

- Source plugin
- Username
- Domain
- RID for SAM hash rows
- LM hash and NT hash
- Cached credential hash
- LSA key and LSA secret hex
- Cross-memory count

The hunting API masks secrets for display. NT and LM hashes are shortened, cached hashes are shortened, and LSA secret values are represented as present rather than displayed in full. The database model still stores the parsed values so access to this artifact family should be treated as sensitive.

### System Info

Source plugin: `windows.info`

Storage table: `memory_info`

The System Info tab shows memory image metadata from Volatility.

The stored fields include:

- Hostname
- Kernel base
- DTB
- Symbol path
- 32-bit or 64-bit architecture
- PAE flag
- Major/minor version and NT major/minor version
- Machine type
- Processor count
- NT product type
- NT system root
- System time

When `windows.info` provides `SystemTime`, CaseScope stores it in `memory_info.system_time` and updates the parent memory job `memory_timestamp`. Hunt Memory uses this timestamp in the job selector and cross-memory result groups when available.

## Ingested But Not Top-Level Tabs

Some memory tables are populated and used by related search or future pivot workflows but are not currently displayed as standalone Hunt Memory tabs.

### Modules

Source plugins:

- `windows.ldrmodules`
- `windows.dlllist`

Storage table: `memory_modules`

The stored fields include PID, process name, base address, mapped path, and the `InInit`, `InLoad`, and `InMem` link-state flags. A module is considered unlinked when all three link-state flags are false.

`windows.ldrmodules` is preferred because it exposes link-state flags used for hidden or unlinked DLL review. If `windows.ldrmodules` produced rows, `windows.dlllist` ingestion is skipped. If `windows.dlllist` is ingested as a fallback, module rows are marked as present in init, load, and memory lists.

Modules are searchable through the shared memory artifact search helper by module/path search types, but the current Hunt Memory UI does not render a dedicated Modules tab.

### Process SIDs

Source plugin: `windows.getsids`

Storage table: `memory_sids`

The stored fields include PID, process name, SID, and SID name. This data provides user and security-context clues for processes, but the current Hunt Memory UI does not render a dedicated SIDs tab.

## Cross-Memory Search

The Cross-Memory Search modal searches all completed memory jobs in the current case.

The UI exposes these search types:

- Process: process name, command line, or path
- IP Address: local address, foreign address, or owner process name
- Service: service name, display name, or binary path
- Path: process path, command line, or module mapped path

The backing search helper also supports module, credential, and malfind search types for internal or tool-based use.

Search results are grouped by memory job and include hostname, memory timestamp, and matching rows. The route limits results to a bounded set, with a default of 50 from the Hunt Memory API.

## Cross-Reference Badges

Hunt Memory can show cross-memory badges for artifacts that appear in multiple memory jobs in the same case.

Badges are currently calculated for:

- Processes by lower-case process name
- Network rows by foreign address
- Services by lower-case service name

Selecting a badge opens a popover that lists the other memory jobs where the artifact appears. Choosing a result switches the selected memory job so the analyst can review the matching host and capture time.

## Unified Findings Pivot

The page includes a Unified Findings Pivot panel at the top. It loads findings for the current case from the findings API and shows a short list with confidence summaries. This is intended to help analysts decide which memory artifacts deserve closer review, but it does not change which rows appear in the memory tabs.

## Time Behavior

Memory artifact timestamps come from Volatility output and are stored in PostgreSQL. `windows.info` system time is used as the memory capture timestamp when available. Browser rendering on the Hunt Memory page uses the analyst browser locale for displayed date strings.

For event hunting and time-range filtering in Hunt Artifacts, use the displayed case-time behavior documented in the Artifact Hunting page.

## Analyst Workflow

A typical memory-hunting workflow is:

1. Select the relevant completed memory dump from the Memory Dump selector.
2. Review System Info to confirm the host, architecture, Windows version, and capture time.
3. Review Processes in tree view for unexpected parent/child relationships, then switch to list view for command-line review.
4. Review Network for external connections, listening sockets, unusual owners, and repeated foreign addresses across memory jobs.
5. Review Services for unusual auto-start services, odd binary paths, missing display names, and repeated service names across hosts.
6. Review Injections for executable writable memory regions and pivot back to the process, modules, network activity, and events.
7. Review Credentials only when the case requires sensitive credential handling.
8. Use Cross-Memory Search to compare process names, IP addresses, services, and paths across all completed memory jobs in the case.
9. Pivot suspicious process names, service names, and IP addresses back to Hunt Artifacts to correlate with logs and other parsed evidence.

## Limitations

- Hunt Memory only lists memory jobs with status `completed`.
- The visible tab counts include processes, network, services, malfind, credentials, and system info; modules and SIDs are ingested but not represented in the selector summary.
- The current UI does not provide top-level Modules or SIDs tabs.
- Memory usernames are not stored on process records; use SIDs, events, or other artifacts for user context.
- Process tree accuracy depends on PID and PPID values recovered from the image and can be affected by PID reuse, missing parents, terminated processes, or capture timing.
- `psscan` output is not ingested into process rows to avoid duplicate rows.
- `netstat` and `dlllist` may be skipped when richer plugin output already produced rows.
- Credential artifacts are sensitive. The UI masks displayed secrets, but selected plugins may still store sensitive parsed values in PostgreSQL.
