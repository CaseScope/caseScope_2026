# Process Hunting

Process Hunting is the case-level review surface opened from the left menu item **Hunt Processes**. It loads `/case/hunting/processes` and presents a unified process list built from normalized event records and completed memory analysis jobs.

Use this page when the investigation question starts with a process name, PID, parent process, command line, host, or process tree relationship. Use [Artifact Hunting](artifact-hunting.md) when the question needs the full event record, raw parser fields, tagging, noise handling, or artifact-specific event tabs.

## How Process Hunting Is Built

The page is rendered by `case_hunting_processes` and populated by three API calls:

- `/api/hunting/processes/hostnames/<case_id>` returns hosts that have process data.
- `/api/hunting/processes/list/<case_id>` returns the paginated unified process list.
- `/api/hunting/processes/tree/<case_id>` returns the selected process, parent chain, and child process tree.

The unified list has two source families:

- **Events/EDR** rows from the ClickHouse `events` table.
- **Memory Dumps** rows from the PostgreSQL `memory_processes` table for completed memory jobs.

The UI shows timestamp, hostname, username, PPID, parent process, PID, process name, command-line preview, badges, and source. Selecting a row opens the process tree modal.

## Filters And Search

Filters are applied server-side.

- **Hostname** limits results to one `source_host` for events or one memory job hostname for memory data.
- **Source** limits results to Events/EDR, Memory Dumps, or both.
- **Search** matches process names and command-line context. Event results search `process_name`, `command_line`, and `parent_process`. Memory results search `name`, `cmdline`, and `path`.
- **Pagination** defaults to 50 rows per page and is capped at 200 rows per request by the API.

When both source families are selected, the API asks ClickHouse for the requested page of event process groups and asks PostgreSQL for up to 500 memory processes, then sorts the combined list by displayed timestamp and returns the first page of combined results.

## Events And EDR Source

Events/EDR process hunting reads normalized rows from the ClickHouse `events` table. A row can participate when it has:

- `case_id` matching the active case
- non-empty `process_name`
- `process_id` greater than zero
- a process name ending in a known executable/script extension

The executable filter currently includes `.exe`, `.dll`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.com`, `.msi`, `.js`, and `.wsf` for the list API. The hostname API uses the same concept but currently enumerates through `.msi`.

Rows are grouped by `source_host`, `process_id`, and `process_name`. For each group, the API returns:

- Latest and first-seen timestamps from `timestamp_utc` or `timestamp`
- Latest parent PID and parent process
- Latest command line
- Latest username
- Latest process path
- Event count for the group
- Child and parent indicators

Event-backed process rows can come from any parser that populates the standard process fields in `ParsedEvent`. The most important sources are:

- **Windows Event Logs (`evtx`)**: EVTX parsing extracts process name/path from fields such as `NewProcessName`, `ProcessName`, `CallerProcessName`, or EvtxECmd payload summaries. It extracts `CommandLine` or `ProcessCommandLine`, process ID fields, parent process, and parent PID when the event supplies them. Hayabusa/Sigma detections remain attached to the original event rows in Hunt Artifacts.
- **Huntress (`huntress`)**: Huntress-style event data maps ECS-like `process` fields into process name, executable path, PID, command line, parent name, parent PID, user, hashes, code-signing details, process ancestry, and detection metadata. Hunt Processes uses the normalized process columns; the extended Huntress fields remain available in the original event raw/extra data.
- **Microsoft Defender and MDE XDR (`defender_av`, `mde_xdr`)**: MDE XDR parsing maps fields such as `FileName`, `InitiatingProcessFileName`, `ProcessCommandLine`, `InitiatingProcessCommandLine`, device name, account, action, severity, hashes, and network details into the event model. Defender AV and other delegated vendor parsers use the generic JSON or CSV paths where possible.
- **Other vendor and generic logs**: CrowdStrike, SentinelOne, Sophos, Velociraptor, Plaso, generic JSON, NDJSON, CSV, and selected firewall/security parsers can contribute if they normalize process fields. They appear only when the resulting `process_name` and `process_id` satisfy the Hunt Processes filters.
- **Forensic artifacts with process context**: Some parsed forensic artifacts, such as WER reports, crash dump triage, LNK, Jump List, Prefetch, SRUM, and related KAPE/dissect outputs, may populate process fields. They can appear in Hunt Processes only when the normalized record includes a valid process ID and executable-like process name.

Events/EDR caveats:

- The process list is a pivot view, not a full event log. It collapses many events into one row per host, PID, and process name.
- The displayed command line, username, parent, and path are the latest observed values by timestamp for that group.
- Parent/child links depend on `parent_pid` and, for event children, matching `parent_process` to the selected process name.
- A process without a valid PID is searchable in Hunt Artifacts but will not appear in Hunt Processes.

## Memory Dumps Source

Memory-backed process hunting reads completed memory jobs and their parsed Volatility output. The central table for Hunt Processes is `memory_processes`, represented by `MemoryProcess`.

Memory process rows store:

- Case, memory job, and hostname
- PID, PPID, process name, and lower-case process name
- Path, command line, and audit path when available
- Offset, session ID, thread count, handle count, WOW64 status
- Create time and exit time
- Cross-memory and cross-event count fields
- Parser provenance metadata

The memory parser ingests and enriches this table from these Volatility plugins:

- **`windows.pslist`** creates the base process rows. It stores PID, PPID, image name, offset, session, threads, handles, WOW64, create time, and exit time.
- **`windows.pstree`** updates existing process rows or creates missing rows with path, command line, audit path, and parent-child structure. It walks nested `__children` output recursively.
- **`windows.cmdline`** updates existing process rows with command-line arguments from Volatility when available.

The parser intentionally does not ingest `windows.psscan` into `memory_processes`; it is retained as raw output only to avoid duplicating `pslist` process rows.

Memory source caveats:

- Hunt Processes includes only memory jobs with status `completed`.
- Memory usernames are not shown in this page because `MemoryProcess` does not store a user field.
- Memory parent names are not stored directly; parent/child relationships are derived from PID and PPID on the same hostname.
- The timestamp shown for memory rows is the process create time when Volatility provides it.
- Corrupt or garbage process entries are skipped when PID values are invalid or the process name is mostly non-printable.

## Related Memory Artifacts

Several memory tables are not shown as top-level rows in Hunt Processes, but they are process-adjacent and support process investigation in **Hunt Memory**:

- **Network connections (`memory_network`)** from `windows.netscan` or `windows.netstat`: protocol, local and foreign address/port, state, PID, owner, offset, and created time. `windows.netstat` is skipped when `windows.netscan` already produced rows.
- **Services (`memory_services`)** from `windows.svcscan`: service name, display name, binary path, registry binary path, DLL, state, start type, service type, PID, offset, and order.
- **Malfind regions (`memory_malfind`)** from `windows.malfind`: PID, process name, protection, VPN range, tag, commit charge, private memory flag, hexdump, disassembly, and notes.
- **Modules (`memory_modules`)** from `windows.ldrmodules` or `windows.dlllist`: PID, process name, base address, mapped path, and link-state flags. `windows.dlllist` is skipped when `windows.ldrmodules` already produced module rows.
- **Process SIDs (`memory_sids`)** from `windows.getsids`: PID, process name, SID, and SID name.
- **Credentials (`memory_credentials`)** from `windows.hashdump`, `windows.cachedump`, and `windows.lsadump`: credential source, account fields, hashes or secrets, and masked display fields.
- **System info (`memory_info`)** from `windows.info`: memory image metadata, including system time. When present, this updates the memory job capture timestamp.

Use Hunt Processes for process list and tree pivots. Use Hunt Memory when the question involves sockets, services, suspicious memory regions, loaded modules, SIDs, credentials, or per-memory-job artifact review.

## Process Tree Modal

Selecting a process opens a modal that requests `/api/hunting/processes/tree/<case_id>` with hostname, PID, process name, parent-chain inclusion, and a maximum depth. The UI currently requests depth 5; the API caps depth at 10.

The modal shows:

- Current process name, PID, source, command line, path, username, and timestamp
- Parent link when a parent is found
- A not-found parent marker when a PPID exists but the parent cannot be resolved
- Child processes from both events and memory
- Expand and collapse controls for child trees

Tree construction tries events first for the selected process, then memory. Children are gathered from both source families and de-duplicated by PID and process name. Event children require matching host, parent PID, and parent process name. Memory children require matching host and PPID.

## Badges And Counts

The list can show several badges:

- Child-process badge when the process has children.
- Parent-process badge when the process has a parent.
- Memory cross-reference badge when the same memory process name appears in more than one memory job.
- Event count badge when more than one event row contributed to the event-backed process group.

Cross-memory counts are recalculated after successful memory parsing. Process counts are based on the same lower-case process name appearing in distinct memory jobs for the case.

## Timezone Behavior

Event process timestamps use the same case-timezone display behavior as event hunting. The API formats `timestamp_utc` or `timestamp` through the case timezone.

Memory process timestamps are stored in PostgreSQL from Volatility plugin output and formatted for display through the case timezone. If the memory image includes `windows.info` system time, that value is also stored on the memory job for memory review workflows.

## Analyst Workflow

A typical process-hunting workflow is:

1. Filter to a host when investigating a specific endpoint.
2. Search for the process name, parent name, or command-line fragment.
3. Compare source badges to see whether the process was observed in events, memory, or both.
4. Open the process tree to inspect parent and child relationships.
5. Pivot to Hunt Artifacts for the full underlying event records, detections, tags, raw fields, and exports.
6. Pivot to Hunt Memory for process-adjacent memory artifacts such as network connections, services, modules, malfind regions, SIDs, and credentials.

## Limitations

Process Hunting is intentionally a normalized pivot. It does not replace raw event review or per-plugin memory review.

- It only shows event rows with a valid process ID and executable-like process name.
- It groups event activity, so repeated process events are summarized by host, PID, and process name.
- It does not expose all parser-specific fields in the process list.
- It does not show memory services, modules, network connections, SIDs, credentials, or malfind rows directly.
- Process lineage is only as complete as the source artifact fields. Missing parent PID, parent process name, PID reuse, incomplete telemetry, and memory capture timing can all affect tree accuracy.
