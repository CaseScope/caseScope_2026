# CaseScope Routes Documentation

Complete list of all HTTP routes/endpoints in the application with descriptions.

---

## Authentication & Session Management

| Route | Method | Description |
|-------|--------|-------------|
| `/login` | GET, POST | User login page and authentication handler |
| `/logout` | GET | Log out current user and redirect to login |
| `/select_case/<int:case_id>` | GET | Select and lock a case for the current user session |
| `/clear_case` | GET | Clear currently selected case from session |
| `/case/<int:case_id>/unlock` | POST | Unlock a case and release the lock for other users |
| `/case/<int:case_id>/lock_status` | GET | Check if a case is locked and by whom |
| `/case/<int:case_id>/heartbeat` | POST | Send heartbeat to maintain case lock session |

---

## Dashboard & System Health

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Main dashboard (system status, cases, resources) |
| `/health/db` | GET | Database health check endpoint for monitoring |
| `/health/system` | GET | System health metrics (CPU, RAM, GPU, Redis, PostgreSQL, OpenSearch) |
| `/ai/status` | GET | Check AI/Ollama service availability and models |

---

## Case Management

| Route | Method | Description |
|-------|--------|-------------|
| `/cases` | GET | Case selection page listing all available cases |
| `/case/create` | GET, POST | Create new case form and handler |
| `/case/<int:case_id>` | GET | Case dashboard with files, stats, and AI analysis |
| `/case/<int:case_id>/status` | GET | Get case status and file processing statistics |
| `/cases/case-management` | GET | Admin page for managing all cases |
| `/cases/<int:case_id>/edit` | GET, POST | Edit case details |
| `/cases/<int:case_id>/delete` | POST | Delete a case (async with progress tracking) |
| `/cases/<int:case_id>/delete/status/<task_id>` | GET | Poll deletion task progress |

---

## File Management

### Case Files

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/files` | GET | Case files dashboard with statistics and file list |
| `/case/<int:case_id>/file/<int:file_id>/details` | GET | Detailed view of a single file with event stats |
| `/case/<int:case_id>/file/<int:file_id>/status` | GET | Get processing status of a specific file |
| `/case/<int:case_id>/file/<int:file_id>/toggle_hidden` | POST | Hide or unhide a single file |
| `/case/<int:case_id>/hidden_files` | GET | View list of hidden files in a case |
| `/case/<int:case_id>/failed_files` | GET | View list of failed files in a case |
| `/case/<int:case_id>/file-stats` | GET | Get file statistics for auto-refresh (JSON) |

### Global Files (Admin)

| Route | Method | Description |
|-------|--------|-------------|
| `/files/global` | GET | Global files dashboard showing all cases |
| `/files/global/queue/status` | GET | Get global queue status across all cases |
| `/files/global/hidden` | GET | View all hidden files across all cases |
| `/files/global/failed` | GET | View all failed files across all cases |

---

## File Upload & Processing

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/upload` | GET, POST | File upload page and chunked upload handler |
| `/case/<int:case_id>/upload_chunk` | POST | Handle individual upload chunks for large files |
| `/case/<int:case_id>/finalize_upload` | POST | Finalize chunked upload and start processing |

---

## File Operations (Bulk & Single)

### Reindexing

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/file/<int:file_id>/reindex` | POST | Reindex a single file (re-parse and index events) |
| `/case/<int:case_id>/bulk_reindex` | POST | Reindex all files in a case |
| `/case/<int:case_id>/bulk_reindex_selected` | POST | Reindex selected files from file list |
| `/files/global/bulk_reindex` | POST | Reindex files across all cases (admin) |
| `/files/global/bulk_reindex_selected` | POST | Reindex selected files globally (admin) |

### SIGMA Testing (Chainsaw)

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/file/<int:file_id>/rechainsaw` | POST | Re-run SIGMA rules on a single file |
| `/case/<int:case_id>/bulk_rechainsaw` | POST | Re-run SIGMA on all files in a case |
| `/case/<int:case_id>/bulk_rechainsaw_selected` | POST | Re-run SIGMA on selected files |
| `/files/global/bulk_rechainsaw` | POST | Re-run SIGMA globally (admin) |
| `/files/global/bulk_rechainsaw_selected` | POST | Re-run SIGMA on selected files globally (admin) |

### IOC Hunting

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/file/<int:file_id>/rehunt_iocs` | POST | Re-hunt IOCs in a single file |
| `/case/<int:case_id>/rehunt_iocs` | POST | Hunt IOCs across all events in a case |
| `/case/<int:case_id>/bulk_rehunt_iocs` | POST | Re-hunt IOCs in all files |
| `/case/<int:case_id>/bulk_rehunt_selected` | POST | Re-hunt IOCs in selected files |
| `/files/global/bulk_rehunt_iocs` | POST | Re-hunt IOCs globally (admin) |
| `/files/global/bulk_rehunt_selected` | POST | Re-hunt IOCs in selected files globally (admin) |

### File Hiding & Deletion

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/bulk_hide_selected` | POST | Bulk hide selected files |
| `/case/<int:case_id>/bulk_unhide` | POST | Bulk unhide files |
| `/case/<int:case_id>/bulk_delete_hidden` | POST | Permanently delete hidden files |
| `/case/<int:case_id>/bulk_delete_files` | POST | Delete all files in a case |
| `/files/global/bulk_hide_selected` | POST | Bulk hide files globally (admin) |
| `/files/global/bulk_delete_files` | POST | Delete files globally (admin) |

### Queue Management

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/queue/status` | GET | Get case-specific queue status for auto-refresh |
| `/case/<int:case_id>/queue/cleanup` | POST | Clean up completed tasks from queue |
| `/case/<int:case_id>/queue/health` | GET | Check Celery worker health for case |
| `/case/<int:case_id>/file/<int:file_id>/requeue` | POST | Requeue a single failed file |
| `/case/<int:case_id>/bulk_requeue_selected` | POST | Requeue selected failed files |
| `/case/<int:case_id>/queue/requeue-failed` | POST | Requeue all failed files in a case |
| `/files/global/requeue_failed` | POST | Requeue failed files globally (admin) |

### Bulk Import (Folder Scanning)

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/bulk_import/scan` | GET | Scan a folder for EVTX/NDJSON files |
| `/case/<int:case_id>/bulk_import/start` | POST | Start bulk import from scanned folder |
| `/case/<int:case_id>/bulk_import/status/<task_id>` | GET | Poll bulk import task progress |

---

## Event Search & Analysis

### Search Interface

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/search` | GET | Main event search page with filters and results |
| `/case/<int:case_id>/search/export` | GET | Export search results to CSV |
| `/case/<int:case_id>/search/event/<event_id>` | GET | View detailed event JSON modal |
| `/case/<int:case_id>/search/columns` | POST | Save custom column preferences for search |

### Quick Analysis Endpoints

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/search/logins-ok` | GET | Analyze successful logins (Event ID 4624) |
| `/case/<int:case_id>/search/logins-failed` | GET | Analyze failed logins (Event ID 4625) |
| `/case/<int:case_id>/search/rdp-connections` | GET | Analyze RDP connections (Event ID 1149) |
| `/case/<int:case_id>/search/console-logins` | GET | Analyze console logins (LogonType 2) |
| `/case/<int:case_id>/search/vpn-authentications` | GET | Analyze VPN authentications (Event 6272) |
| `/case/<int:case_id>/search/vpn-failed-attempts` | GET | Analyze failed VPN attempts |

### Event Status Management

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/event-status` | POST | Set event status (new/hunted/confirmed/noise) |
| `/case/<int:case_id>/event-status/bulk` | POST | Bulk set event status |
| `/case/<int:case_id>/event-status/counts` | GET | Get event status counts (for stats display) |
| `/case/<int:case_id>/event-status/<event_id>` | GET | Get status of a single event |

### Legacy Event Tagging (TimelineTag - Deprecated)

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/search/tag` | POST | ⚠️ LEGACY: Tag a single event for timeline (use event-status instead) |
| `/case/<int:case_id>/search/untag` | POST | ⚠️ LEGACY: Untag a single event (use event-status instead) |
| `/case/<int:case_id>/search/bulk-tag` | POST | ⚠️ LEGACY: Bulk tag selected events (use event-status/bulk instead) |
| `/case/<int:case_id>/search/bulk-untag` | POST | ⚠️ LEGACY: Bulk untag selected events (use event-status/bulk instead) |

### Event Hiding (Deprecated - Use event-status='noise')

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/search/hide` | POST | ⚠️ DEPRECATED: Hide a single event (use event-status='noise' instead) |
| `/case/<int:case_id>/search/unhide` | POST | ⚠️ DEPRECATED: Unhide a single event (use event-status='new' instead) |
| `/case/<int:case_id>/search/bulk-hide` | POST | ⚠️ DEPRECATED: Bulk hide selected events (use event-status/bulk instead) |
| `/case/<int:case_id>/search/bulk-unhide` | POST | ⚠️ DEPRECATED: Bulk unhide selected events (use event-status/bulk instead) |

### AI Triage Exclusions

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/search/exclude-from-tagging` | POST | Exclude an event from AI triage auto-marking (prevents setting hunted status) |
| `/case/<int:case_id>/search/bulk-exclude` | POST | Bulk exclude events from AI triage auto-marking |
| `/case/<int:case_id>/search/remove-exclusion` | POST | Remove AI triage exclusion from an event |
| `/case/<int:case_id>/search/exclusions` | GET | List all AI triage exclusions |

### Saved Searches

| Route | Method | Description |
|-------|--------|-------------|
| `/search/saved/list` | GET | List all saved searches for current user |
| `/search/saved/<int:search_id>` | GET | Get details of a saved search |
| `/search/saved/save` | POST | Save current search parameters |
| `/search/saved/<int:search_id>/delete` | POST | Delete a saved search |
| `/case/<int:case_id>/search/history/<int:search_id>/favorite` | POST | Mark a search as favorite |

### IOC Management from Search

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/search/add_ioc` | POST | Add an IOC from event details to case IOC list |
| `/case/<int:case_id>/search/bulk_add_iocs` | POST | Bulk add IOCs from quick analysis modals |

---

## IOC Management

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/ioc` | GET | IOC management page with full list and search |
| `/case/<int:case_id>/ioc/add` | POST | Add a new IOC manually |
| `/case/<int:case_id>/ioc/<int:ioc_id>` | GET | Get single IOC details (JSON) |
| `/case/<int:case_id>/ioc/<int:ioc_id>` | PUT | Update an existing IOC |
| `/case/<int:case_id>/ioc/<int:ioc_id>` | DELETE | Delete an IOC |
| `/case/<int:case_id>/ioc/bulk-delete` | POST | Bulk delete selected IOCs |
| `/case/<int:case_id>/ioc/import` | POST | Import IOCs from CSV/text file |
| `/case/<int:case_id>/ioc/export` | GET | Export IOCs to CSV |
| `/case/<int:case_id>/ioc/enrich` | POST | Enrich IOCs with OpenCTI threat intelligence |
| `/case/<int:case_id>/ioc/<int:ioc_id>/notes` | POST | Add or update notes for an IOC |

---

## Systems Management

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/systems` | GET | Systems management page (workstations, servers, firewalls) |
| `/case/<int:case_id>/systems/list` | GET | List systems with optional type filter (JSON) |
| `/case/<int:case_id>/systems/add` | POST | Add a new system manually |
| `/case/<int:case_id>/systems/<int:system_id>` | GET | Get system details (JSON) |
| `/case/<int:case_id>/systems/<int:system_id>` | PUT | Update an existing system |
| `/case/<int:case_id>/systems/<int:system_id>` | DELETE | Delete a system |
| `/case/<int:case_id>/systems/discover` | POST | Auto-discover systems from events |
| `/case/<int:case_id>/systems/bulk-delete` | POST | Bulk delete selected systems |
| `/case/<int:case_id>/systems/import` | POST | Import systems from CSV |
| `/case/<int:case_id>/systems/export` | GET | Export systems to CSV |

---

## Known Users Management

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/known-users` | GET | Known users management page |
| `/case/<int:case_id>/known-users/add` | POST | Add a known user/admin manually |
| `/case/<int:case_id>/known-users/<int:user_id>` | GET | Get known user details (JSON) |
| `/case/<int:case_id>/known-users/<int:user_id>` | PUT | Update an existing known user |
| `/case/<int:case_id>/known-users/<int:user_id>` | DELETE | Delete a known user |
| `/case/<int:case_id>/known-users/bulk-delete` | POST | Bulk delete selected known users |
| `/case/<int:case_id>/known-users/import` | POST | Import known users from CSV |
| `/case/<int:case_id>/known-users/export` | GET | Export known users to CSV |

---

## Evidence Files Management

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/evidence` | GET | Evidence files management page |
| `/case/<int:case_id>/evidence/upload` | POST | Upload evidence file attachment |
| `/case/<int:case_id>/evidence/<int:evidence_id>` | GET | Get evidence file details (JSON) |
| `/case/<int:case_id>/evidence/<int:evidence_id>` | PUT | Update evidence file metadata |
| `/case/<int:case_id>/evidence/<int:evidence_id>` | DELETE | Delete an evidence file |
| `/case/<int:case_id>/evidence/<int:evidence_id>/download` | GET | Download an evidence file |
| `/case/<int:case_id>/evidence/bulk-delete` | POST | Bulk delete selected evidence files |

---

## AI Triage & Hunting

### Triage Page (Hunting)

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/triage` | GET | Triage/Hunting page with prerequisites and AI analysis phases |
| `/case/<int:case_id>/triage/extract-iocs` | POST | Phase 1: Extract IOCs from EDR report using AI |
| `/case/<int:case_id>/triage/add-extracted-iocs` | POST | Add extracted IOCs to case IOC list |
| `/case/<int:case_id>/triage/find-iocs` | POST | Phase 2: Find events matching extracted IOCs (snowball hunting) |
| `/case/<int:case_id>/triage/add-found-iocs` | POST | Add discovered IOCs from snowball hunting |
| `/case/<int:case_id>/triage/tag-events` | POST | Phase 3: Auto-mark events as 'hunted' (3+ IOCs or attack patterns) |

### AI Triage Search (9-Phase Analysis)

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/ai-triage-search/pre-check` | GET | Check prerequisites before starting triage |
| `/case/<int:case_id>/ai-triage-search/run` | POST | Start full 9-phase AI triage search (Celery task) |
| `/case/<int:case_id>/ai-triage-search/<int:search_id>/status` | GET | Poll triage search progress |
| `/case/<int:case_id>/ai-triage-searches` | GET | List all AI triage searches for a case |
| `/ai-triage-search/<int:search_id>/view` | GET | View full AI triage search report |
| `/ai-triage-search/<int:search_id>/cancel` | POST | Cancel a running AI triage search |
| `/ai-triage-search/<int:search_id>/delete` | POST | Delete an AI triage search report |

### AI Case Reports

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/ai/generate` | POST | Generate AI case report using Ollama LLM |
| `/case/<int:case_id>/ai/reports` | GET | List all AI reports for a case |
| `/ai/report/<int:report_id>/view` | GET | View AI report with chat interface |
| `/ai/report/<int:report_id>` | GET | Get AI report data (JSON) |
| `/ai/report/<int:report_id>` | DELETE | Delete an AI report |
| `/ai/report/<int:report_id>/live-preview` | GET | Stream live AI report generation progress |
| `/ai/report/<int:report_id>/cancel` | POST | Cancel AI report generation |
| `/ai/report/<int:report_id>/download` | GET | Download AI report as Word document |
| `/ai/report/<int:report_id>/chat` | GET | Get chat history for AI report refinement |
| `/ai/report/<int:report_id>/chat` | POST | Send chat message to refine AI report |
| `/ai/report/<int:report_id>/review` | GET | Review AI report validation details |
| `/ai/report/<int:report_id>/apply` | POST | Apply AI report refinements |

### AI Case Timeline

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/timeline/generate` | POST | Generate AI case timeline from hunted/confirmed events |
| `/case/<int:case_id>/timeline/<int:timeline_id>` | GET | Get timeline data (JSON) |
| `/case/<int:case_id>/timeline/<int:timeline_id>/view` | GET | View interactive timeline |
| `/case/<int:case_id>/timeline/<int:timeline_id>/download` | GET | Download timeline as HTML |

---

## System Configuration

### SIGMA Rules Management

| Route | Method | Description |
|-------|--------|-------------|
| `/sigma` | GET | SIGMA rules management page |
| `/sigma/update` | POST | Update SIGMA rules from SigmaHQ repository |

### EVTX Event Descriptions

| Route | Method | Description |
|-------|--------|-------------|
| `/evtx_descriptions` | GET | EVTX event descriptions management page |
| `/evtx_descriptions/update` | POST | Update event descriptions from Ultimate Windows Security |
| `/evtx_descriptions/custom` | POST | Add custom event description |
| `/evtx_descriptions/custom/<int:event_desc_id>` | PUT | Update custom event description |
| `/evtx_descriptions/custom/<int:event_desc_id>` | DELETE | Delete custom event description |
| `/case/<int:case_id>/refresh_descriptions` | POST | Refresh descriptions for case events |
| `/refresh_descriptions_global` | POST | Refresh descriptions globally (all cases) |

### System Tools (Known Good/Noise Configuration)

| Route | Method | Description |
|-------|--------|-------------|
| `/settings/system-tools/` | GET | System tools settings page (RMM, EDR, Remote tools, IP exclusions) |
| `/settings/system-tools/rmm/add` | POST | Add RMM tool exclusion pattern with executable and path |
| `/settings/system-tools/remote/add` | POST | Add remote tool with known-good session IDs |
| `/settings/system-tools/edr/add` | POST | Add EDR tool with routine commands and response keywords |
| `/settings/system-tools/ip/save` | POST | Add known-good IP/CIDR range |
| `/settings/system-tools/setting/<int:setting_id>/toggle` | POST | Enable/disable an exclusion setting |
| `/settings/system-tools/setting/<int:setting_id>/delete` | POST | Delete an exclusion setting |
| `/settings/system-tools/setting/<int:setting_id>/edit` | POST | Edit existing exclusion setting (RMM, Remote, EDR) |
| `/settings/system-tools/api/exclusions` | GET | Get exclusions summary (JSON) |
| `/settings/system-tools/api/has-exclusions` | GET | Check if any exclusions are configured |
| `/settings/system-tools/case/<int:case_id>/hide-known-good` | POST | Start parallel "Hide Known Good" task (sets event_status='noise') |
| `/settings/system-tools/case/<int:case_id>/hide-known-good/status/<task_id>` | GET | Poll hide known-good task progress |
| `/settings/system-tools/case/<int:case_id>/hide-noise` | POST | Start "Hide Noise" task (sets event_status='noise') |
| `/settings/system-tools/case/<int:case_id>/hide-noise/status/<task_id>` | GET | Poll hide noise task progress |

---

## User Management

| Route | Method | Description |
|-------|--------|-------------|
| `/users/` | GET | User management page (list all users) |
| `/users/create` | GET, POST | Create new user form and handler |
| `/users/<int:user_id>/edit` | GET, POST | Edit user details and permissions |
| `/users/<int:user_id>/delete` | POST | Delete a user account |
| `/users/<int:user_id>/reset-password` | POST | Admin reset user password |
| `/users/profile` | GET, POST | Current user profile page and update handler |
| `/users/profile/change-password` | POST | User change their own password |

---

## Settings & Configuration

| Route | Method | Description |
|-------|--------|-------------|
| `/settings/` | GET | System settings page (Ollama, OpenCTI, IRIS integration) |
| `/settings/ollama/test` | POST | Test Ollama AI connection |
| `/settings/ollama/update` | POST | Update Ollama configuration |
| `/settings/ollama/models` | GET | List available Ollama models |
| `/settings/ollama/models/pull` | POST | Download a new Ollama model |
| `/settings/ollama/models/delete` | POST | Delete an Ollama model |
| `/settings/opencti/test` | POST | Test OpenCTI threat intelligence connection |
| `/settings/opencti/update` | POST | Update OpenCTI configuration |
| `/settings/iris/test` | POST | Test IRIS DFIR platform connection |
| `/settings/iris/update` | POST | Update IRIS configuration |

---

## IRIS Integration

| Route | Method | Description |
|-------|--------|-------------|
| `/case/<int:case_id>/sync-timeline-to-iris` | POST | Export case timeline to IRIS platform |

---

## Miscellaneous

| Route | Method | Description |
|-------|--------|-------------|
| `/search-instructions` | GET | Search syntax help page with examples |
| `/queue/cleanup` | POST | Global queue cleanup (legacy) |
| `/queue/health` | GET | Global queue health check (legacy) |

---

## Summary Statistics

- **Total Routes:** ~265
- **Main Application Routes:** ~140 (in `main.py`)
- **File Management Routes:** 48 (in `routes/files.py`)
- **System Tools Routes:** 14 (in `routes/system_tools.py`)
- **Triage/AI Routes:** 18 (in `routes/triage_report.py`)
- **IOC Management Routes:** 11 (in `routes/ioc.py`)
- **Systems Management Routes:** 11 (in `routes/systems.py`)
- **Known Users Routes:** 9 (in `routes/known_users.py`)
- **Evidence Files Routes:** 7 (in `routes/evidence.py`)
- **User Management Routes:** 8 (in `routes/users.py`)
- **Case Management Routes:** 5 (in `routes/cases.py`)

**Note:** Some legacy routes (event hiding, timeline tagging) are marked as deprecated in favor of the unified EventStatus system (`event_status='new'|'hunted'|'confirmed'|'noise'`).

---

## Route Conventions

### HTTP Methods
- **GET:** Retrieve data or display pages
- **POST:** Create new resources or trigger actions
- **PUT:** Update existing resources
- **DELETE:** Delete resources

### URL Parameters
- `<int:case_id>` - Case identifier
- `<int:file_id>` - File identifier
- `<int:ioc_id>` - IOC identifier
- `<int:system_id>` - System identifier
- `<int:user_id>` - User identifier
- `<task_id>` - Celery task identifier (UUID string)
- `<event_id>` - OpenSearch event document ID (string)

### Response Formats
- Most GET routes return HTML pages
- Routes ending in `/status/` typically return JSON with progress
- API routes (`/api/`) return JSON
- Export routes return CSV or downloadable files

---

*Last Updated: December 2025*
*Version: 1.46.0*

## Breaking Changes in v1.46.0

### EventStatus System Migration
- **New System:** All event visibility is now controlled by `event_status` field (new/hunted/confirmed/noise)
- **Deprecated:** `is_hidden` field in OpenSearch (replaced by `event_status='noise'`)
- **Deprecated:** Manual hide/unhide routes (use `/event-status` and `/event-status/bulk` instead)
- **Deprecated:** `TimelineTag` table and tagging routes (use `event_status='hunted'` or `'confirmed'` instead)

### "Hide Known Good" & "Hide Noise" Updates
- Both operations now set `event_status='noise'` in both OpenSearch and PostgreSQL `EventStatus` table
- No longer use `is_hidden` field
- UI filters by `event_status` instead of `is_hidden`

### AI Triage Phase 3 Updates
- Phase 3 now "marks events as hunted" instead of "tagging"
- Sets `event_status='hunted'` for events with:
  - 3+ IOC matches
  - Attack pattern matches (via `events_attack_patterns.py`)
- Excludes events with `event_status='noise'`

### System Tools Configuration
- RMM tools now include both `executable_pattern` and `rmm_path` fields
- Edit functionality added for RMM, Remote, and EDR tools
- All exclusion rules now trigger `event_status='noise'` marking
