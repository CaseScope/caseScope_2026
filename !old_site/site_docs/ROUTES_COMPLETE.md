# CaseScope 2026 - Complete Routes Guide
**All HTTP Endpoints - For AI Code Assistants**

**Total Routes**: ~140+  
**Files**: main.py (72 routes - NEEDS REFACTORING) + 13 blueprint files  
**Last Updated**: November 20, 2025

---

## 🚨 CRITICAL NOTE

**main.py contains 72 routes that should be in blueprints!**  
This is the #1 refactoring priority. See `CaseScope_Refactoring_Analysis.md` for details.

---

## 📁 Route Organization

### Current State
```
main.py (4,532 lines)
├── 72 routes (SHOULD BE ~10)
│   ├── Authentication (2) → routes/auth.py ✅
│   ├── Dashboard (2) → routes/dashboard.py ❌ NEW
│   ├── Search (13) → routes/search.py ❌ NEW
│   ├── AI Reports (13) → routes/ai.py ❌ NEW
│   ├── EVTX Descriptions (7) → routes/evtx.py ❌ NEW
│   ├── Timeline Tagging (8+) → routes/timeline.py ✅
│   └── Case Management (27+) → routes/cases.py ✅

routes/ (13 blueprints)
├── auth.py (3 routes) ✅ EXISTS
├── cases.py (8 routes) ✅ EXISTS
├── files.py (60+ routes) ✅ EXISTS
├── ioc.py (25 routes) ✅ EXISTS
├── systems.py (20+ routes) ✅ EXISTS
├── known_users.py (15 routes) ✅ EXISTS
├── evidence.py (18 routes) ✅ EXISTS
├── settings.py (25 routes) ✅ EXISTS
├── users.py (12 routes) ✅ EXISTS
├── admin.py (8 routes) ✅ EXISTS
├── timeline.py (10 routes) ✅ EXISTS
├── api.py (5 routes) ✅ EXISTS
└── api_stats.py (8 routes) ✅ EXISTS
```

---

## 🔐 Authentication Routes

### **File**: `routes/auth.py` ✅ + `main.py` (LOGIN/LOGOUT)

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/login` | GET, POST | `login()` | User login form and authentication |
| `/logout` | GET | `logout()` | User logout |
| `/select_case/<int:case_id>` | GET | `select_case()` | Set active case in session |
| `/clear_case` | GET | `clear_case()` | Clear active case from session |

#### Example Usage:
```python
# Login
POST /login
Body: {"username": "admin", "password": "password"}
Response: Redirect to dashboard or case

# Logout  
GET /logout
Response: Redirect to login

# Select case (set in session)
GET /select_case/22
Response: Redirect to case page
```

---

## 🏠 Dashboard Routes

### **File**: `main.py` (SHOULD BE routes/dashboard.py)

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/` | GET | `dashboard()` | Main dashboard with stats |
| `/cases` | GET | `case_selection()` | List all cases |

#### Dashboard Stats:
- Total cases
- Total files processed
- Total events indexed
- SIGMA violations
- IOC matches
- Active IOCs
- Recent activity

---

## 📁 Case Management Routes

### **File**: `routes/cases.py` ✅

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/create` | GET, POST | `create_case()` | Create new case |
| `/case/<int:case_id>` | GET | `view_case()` | View case details |
| `/case/<int:case_id>/edit` | GET, POST | `edit_case()` | Edit case metadata |
| `/case/<int:case_id>/delete` | POST | `delete_case()` | Delete case (async) |
| `/case/<int:case_id>/status` | GET | `case_file_status()` | Get file processing status (JSON) |
| `/case/<int:case_id>/bulk_reindex` | POST | `bulk_reindex_route()` | Re-index all files in case |
| `/case/<int:case_id>/stats` | GET | `get_case_stats()` | Get case statistics (JSON) |
| `/case/<int:case_id>/export` | GET | `export_case()` | Export case data |

#### Case Status Response:
```json
{
  "completed": 150,
  "queued": 5,
  "indexing": 2,
  "failed": 3,
  "hidden": 12,
  "sigma": 1,
  "ioc_hunting": 0
}
```

---

## 📄 File Management Routes

### **File**: `routes/files.py` (2,050 lines - largest blueprint)

#### Upload Routes
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/upload_files` | GET, POST | `upload_files()` | Upload files via HTTP |
| `/case/<int:case_id>/bulk_upload` | POST | `bulk_upload()` | Upload from local folder |
| `/case/<int:case_id>/file/<int:file_id>/download` | GET | `download_file()` | Download original file |

#### File Operations
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/files` | GET | `case_files()` | List all files |
| `/case/<int:case_id>/file/<int:file_id>/details` | GET | `file_details()` | View file details |
| `/case/<int:case_id>/file/<int:file_id>/delete` | POST | `delete_file()` | Delete file |
| `/case/<int:case_id>/file/<int:file_id>/hide` | POST | `hide_file()` | Hide file (0-event) |
| `/case/<int:case_id>/file/<int:file_id>/unhide` | POST | `unhide_file()` | Unhide file |

#### Reprocessing Routes
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/file/<int:file_id>/reindex` | POST | `reindex_single_file()` | ⚠️ BROKEN - Re-index file |
| `/case/<int:case_id>/file/<int:file_id>/rechainsaw` | POST | `rechainsaw_single_file()` | Re-run SIGMA |
| `/case/<int:case_id>/file/<int:file_id>/rehunt` | POST | `rehunt_single_file()` | Re-hunt IOCs |
| `/case/<int:case_id>/bulk_reindex_selected` | POST | `bulk_reindex_selected()` | ⚠️ BROKEN - Re-index selected |
| `/case/<int:case_id>/bulk_rechainsaw_selected` | POST | `bulk_rechainsaw_selected()` | Re-run SIGMA on selected |
| `/case/<int:case_id>/bulk_rehunt_selected` | POST | `bulk_rehunt_selected()` | Re-hunt IOCs on selected |

#### Hidden Files Routes
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/hidden_files` | GET | `hidden_files()` | View hidden files |
| `/case/<int:case_id>/hidden_files/search` | GET | `search_hidden_files()` | Search hidden files |
| `/case/<int:case_id>/hidden_files/bulk_unhide` | POST | `bulk_unhide()` | Unhide selected files |
| `/case/<int:case_id>/hidden_files/bulk_delete` | POST | `bulk_delete_hidden()` | Delete selected hidden |

#### Failed Files Routes
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/failed_files` | GET | `failed_files()` | View failed files |
| `/case/<int:case_id>/failed_files/requeue` | POST | `requeue_failed()` | Retry failed files |

#### Global File Routes
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/files/global` | GET | `global_files()` | View files across all cases |
| `/files/global/hidden` | GET | `global_hidden_files()` | View hidden files globally |
| `/files/global/failed` | GET | `global_failed_files()` | View failed files globally |
| `/files/global/bulk_reindex` | POST | `global_bulk_reindex()` | Re-index files globally |

#### Statistics Routes
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/file-stats` | GET | `get_file_stats()` | Get file statistics (JSON) |
| `/case/<int:case_id>/file/<int:file_id>/events/count` | GET | `get_event_count()` | Count events in file |

---

## 🔍 Search & Event Routes

### **File**: `main.py` (SHOULD BE routes/search.py)

#### Search Routes
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/search` | GET | `search_events()` | Search events in case |
| `/case/<int:case_id>/search/export` | GET | `export_search_results()` | Export search results to CSV |
| `/case/<int:case_id>/search/event/<event_id>` | GET | `get_event_detail_route()` | Get single event details (JSON) |

#### Timeline Tagging Routes (in main.py - SHOULD BE routes/timeline.py)
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/search/tag` | POST | `tag_timeline_event()` | Tag event for timeline |
| `/case/<int:case_id>/search/untag` | POST | `untag_timeline_event()` | Remove timeline tag |
| `/case/<int:case_id>/search/bulk-tag` | POST | `bulk_tag_events()` | Tag multiple events |
| `/case/<int:case_id>/search/bulk-untag` | POST | `bulk_untag_events()` | Untag multiple events |
| `/case/<int:case_id>/search/hide` | POST | `hide_event()` | Hide single event |
| `/case/<int:case_id>/search/unhide` | POST | `unhide_event()` | Unhide single event |
| `/case/<int:case_id>/search/bulk-hide` | POST | `bulk_hide_events()` | Hide multiple events |
| `/case/<int:case_id>/search/bulk-unhide` | POST | `bulk_unhide_events()` | Unhide multiple events |

#### Search Customization
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/search/columns` | POST | `update_search_columns()` | Update displayed columns |
| `/case/<int:case_id>/search/history/<int:search_id>/favorite` | POST | `toggle_search_favorite()` | Favorite a search |

#### Example Search Query:
```
GET /case/22/search?q=EventID:4624+AND+LogonType:10&page=1&per_page=50

Filters:
- q: Search query (OpenSearch syntax)
- file_id: Filter by file
- event_type: EVTX, JSON, CSV, IIS
- has_ioc: true/false
- has_sigma: true/false
- date_range: start,end (ISO 8601)
- event_id: Windows Event ID
- computer: Computer name
```

---

## 🎯 IOC Management Routes

### **File**: `routes/ioc.py` (918 lines)

#### IOC CRUD
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/ioc` | GET | `ioc_management()` | IOC management page |
| `/case/<int:case_id>/ioc/add` | POST | `add_ioc()` | Add new IOC |
| `/case/<int:case_id>/ioc/<int:ioc_id>/edit` | POST | `edit_ioc()` | Edit IOC |
| `/case/<int:case_id>/ioc/<int:ioc_id>/delete` | POST | `delete_ioc()` | Delete IOC |
| `/case/<int:case_id>/ioc/<int:ioc_id>/toggle` | POST | `toggle_ioc()` | Enable/disable IOC |

#### IOC Operations
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/ioc/rehunt` | POST | `rehunt_iocs()` | Re-hunt all IOCs |
| `/case/<int:case_id>/ioc/bulk_enable` | POST | `bulk_enable_iocs()` | Enable selected IOCs |
| `/case/<int:case_id>/ioc/bulk_disable` | POST | `bulk_disable_iocs()` | Disable selected IOCs |
| `/case/<int:case_id>/ioc/bulk_delete` | POST | `bulk_delete_iocs()` | Delete selected IOCs |

#### IOC Enrichment (OpenCTI)
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/ioc/<int:ioc_id>/enrich` | POST | `enrich_ioc()` | Enrich with OpenCTI |
| `/case/<int:case_id>/ioc/bulk_enrich` | POST | `bulk_enrich_iocs()` | Enrich selected IOCs |

#### IOC Types Supported (v1.23.1):
- IP addresses
- Usernames (auto-creates Known User if compromised, v1.21.0)
- User SIDs
- Hostnames
- FQDNs (domains)
- Commands (simple)
- Commands (complex/obfuscated)
- Filenames
- Malware names
- Hashes (MD5/SHA1/SHA256)
- Ports
- URLs
- Registry keys
- Email addresses
- **PID (Process ID)** - New in v1.23.1
- **Other** - Catch-all for custom artifacts (mutex names, service names, etc.) - New in v1.23.1

#### Example IOC Add:
```json
POST /case/22/ioc/add
{
  "ioc_type": "ip",
  "ioc_value": "192.168.1.100",
  "description": "Suspicious internal IP",
  "threat_level": "high",
  "tags": ["internal", "suspicious"]
}
```

---

## 🧬 SIGMA Detection Routes

### **File**: `routes/settings.py` (SIGMA section)

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/settings/sigma` | GET | `sigma_management()` | SIGMA rule management |
| `/settings/sigma/update` | POST | `update_sigma_rules()` | Update rules from GitHub |
| `/settings/sigma/<int:rule_id>/toggle` | POST | `toggle_sigma_rule()` | Enable/disable rule |
| `/settings/sigma/bulk_enable` | POST | `bulk_enable_sigma()` | Enable selected rules |
| `/settings/sigma/bulk_disable` | POST | `bulk_disable_sigma()` | Disable selected rules |

#### SIGMA Rule Sources:
- **SigmaHQ**: Official SIGMA rules repository
- **LOLRMM**: Living Off the Land Remote Monitoring & Management
- **Custom**: User-created rules

**Total Active Rules**: 3,074

---

## 🖥️ Systems Management Routes

### **File**: `routes/systems.py` (1,190+ lines with v1.23.0 bulk operations)

#### System Discovery
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/systems` | GET | `systems_management()` | Systems management page with pagination |
| `/case/<int:case_id>/systems/discover` | POST | `discover_systems()` | Auto-discover systems |
| `/case/<int:case_id>/systems/add` | POST | `add_system()` | Manually add system |
| `/case/<int:case_id>/systems/<int:system_id>/edit` | POST | `edit_system()` | Edit system |
| `/case/<int:case_id>/systems/<int:system_id>/delete` | POST | `delete_system()` | Delete system (Admin only) |
| `/case/<int:case_id>/systems/<int:system_id>/toggle_hidden` | POST | `toggle_hidden()` | Show/hide system |

#### Bulk Operations (v1.23.0)
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/systems/bulk_edit` | POST | `bulk_edit_systems()` | Bulk edit system type/hidden status |
| `/case/<int:case_id>/systems/bulk_delete` | POST | `bulk_delete_systems()` | Bulk delete systems (Admin only) |

**Bulk Edit Fields**: System Type, Hidden Status  
**Protected Fields**: System Name, IP Address (cannot be bulk-changed per design)  
**Selection Persistence**: JavaScript Set maintains selections across pagination

#### System Types:
- Workstation
- Server
- Firewall
- Switch
- Printer
- Actor System (malicious/attacker-controlled)

#### System Discovery Sources:
- Computer field in events
- IP addresses in events
- Hostname patterns
- Network logon events

---

## 👤 Known Users Routes

### **File**: `routes/known_users.py` (650+ lines with v1.22.0 bulk operations)

#### User CRUD
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/known_users` | GET | `known_users()` | Known users management with pagination |
| `/case/<int:case_id>/known_users/discover` | POST | `discover_users()` | Auto-discover users |
| `/case/<int:case_id>/known_users/add` | POST | `add_known_user()` | Manually add user (auto-creates IOC if compromised, v1.21.0) |
| `/case/<int:case_id>/known_users/<int:user_id>` | GET | `get_known_user()` | Get user details (JSON) |
| `/case/<int:case_id>/known_users/<int:user_id>/edit` | POST | `edit_known_user()` | Edit user (auto-creates IOC if marked compromised, v1.21.0) |
| `/case/<int:case_id>/known_users/<int:user_id>/delete` | POST | `delete_known_user()` | Delete user (Admin only) |

#### Bulk Operations (v1.22.0)
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/known_users/bulk_edit` | POST | `bulk_edit_known_users()` | Bulk edit user type/status/compromised/active |
| `/case/<int:case_id>/known_users/bulk_delete` | POST | `bulk_delete_known_users()` | Bulk delete users (Admin only) |

**Bulk Edit Fields**: User Type, Compromised Status, Active Status  
**Protected Fields**: Username, User SID (cannot be bulk-changed)  
**IOC Integration**: Bulk marking as compromised auto-creates username IOCs  
**Selection Persistence**: JavaScript Set maintains selections across pagination

#### User Types (v1.21.0):
- Domain
- Local
- Unknown (auto-assigned when created from IOC)
- Invalid

#### Import/Export
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/known_users/upload_csv` | POST | `upload_csv()` | Import users from CSV (auto-creates IOCs for compromised users) |
| `/case/<int:case_id>/known_users/export_csv` | GET | `export_csv()` | Export users to CSV |

**CSV Format**: Username, Type, Compromised, Active, UserSID

---

## 🤖 AI Report Routes

### **File**: `main.py` (SHOULD BE routes/ai.py)

#### Report Generation
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/ai/status` | GET | `ai_status()` | Check AI system status (JSON) |
| `/case/<int:case_id>/ai/generate` | POST | `generate_ai_report()` | Generate new report |
| `/case/<int:case_id>/ai/reports` | GET | `list_ai_reports()` | List all reports for case |
| `/ai/report/<int:report_id>/view` | GET | `view_ai_report()` | View report (HTML) |
| `/ai/report/<int:report_id>` | GET | `get_ai_report()` | Get report data (JSON) |
| `/ai/report/<int:report_id>` | DELETE | `delete_ai_report()` | Delete report |

#### Report Interaction
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/ai/report/<int:report_id>/live-preview` | GET | `get_ai_report_live_preview()` | Get streaming preview |
| `/ai/report/<int:report_id>/cancel` | POST | `cancel_ai_report()` | Cancel generation |
| `/ai/report/<int:report_id>/download` | GET | `download_ai_report()` | Download as PDF/MD |
| `/ai/report/<int:report_id>/chat` | POST | `ai_report_chat()` | Refine report with chat |
| `/ai/report/<int:report_id>/chat` | GET | `get_ai_report_chat_history()` | Get chat history |
| `/ai/report/<int:report_id>/review` | GET | `get_ai_report_review()` | Get review suggestions |
| `/ai/report/<int:report_id>/apply` | POST | `apply_ai_chat_refinement()` | Apply refinement |

#### AI Models Available:
- **phi3:mini** - Fast (default)
- **dfir-qwen:latest** - Forensics-optimized
- **Custom LoRA** - User-trained models

#### Example Report Generation:
```json
POST /case/22/ai/generate
{
  "model_name": "phi3:mini",
  "hardware_mode": "gpu"
}
Response: {"report_id": 50, "status": "generating"}

GET /ai/report/50/live-preview (WebSocket or polling)
Response: Streaming markdown content
```

---

## 📅 Timeline Routes

### **File**: `routes/timeline.py` ✅

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/timeline/generate` | POST | `generate_timeline()` | Generate AI timeline |
| `/case/<int:case_id>/timeline/<int:timeline_id>` | GET | `view_timeline()` | View timeline |
| `/case/<int:case_id>/timeline/<int:timeline_id>/delete` | POST | `delete_timeline()` | Delete timeline |
| `/case/<int:case_id>/timeline/<int:timeline_id>/download` | GET | `download_timeline()` | Download timeline |
| `/case/<int:case_id>/sync-timeline-to-iris` | POST | `sync_timeline_to_iris_case()` | Sync to DFIR-IRIS |

---

## 📋 EVTX Descriptions Routes

### **File**: `main.py` (SHOULD BE routes/evtx.py)

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/evtx_descriptions` | GET | `evtx_descriptions()` | Manage event descriptions |
| `/evtx_descriptions/update` | POST | `evtx_descriptions_update()` | Update from MITRE/MS |
| `/evtx_descriptions/custom` | POST | `create_custom_event()` | Create custom description |
| `/evtx_descriptions/custom/<int:id>` | PUT | `update_custom_event()` | Update custom description |
| `/evtx_descriptions/custom/<int:id>` | DELETE | `delete_custom_event()` | Delete custom description |
| `/case/<int:case_id>/refresh_descriptions` | POST | `refresh_descriptions_case_route()` | Refresh descriptions in case |
| `/refresh_descriptions_global` | POST | `refresh_descriptions_global_route()` | Refresh globally |

---

## 📊 Evidence Files Routes

### **File**: `routes/evidence.py` (602 lines)

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/case/<int:case_id>/evidence` | GET | `evidence_files()` | View evidence files |
| `/case/<int:case_id>/evidence/upload` | POST | `upload_evidence()` | Upload evidence file |
| `/case/<int:case_id>/evidence/<int:file_id>` | GET | `view_evidence()` | View evidence details |
| `/case/<int:case_id>/evidence/<int:file_id>/download` | GET | `download_evidence()` | Download evidence |
| `/case/<int:case_id>/evidence/<int:file_id>/delete` | POST | `delete_evidence()` | Delete evidence |

**Note**: Evidence files are NOT processed/indexed. They're stored for reference only.

---

## ⚙️ Settings Routes

### **File**: `routes/settings.py` (952 lines)

#### Application Settings
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/settings` | GET | `settings_page()` | Settings dashboard |
| `/settings/general` | POST | `update_general_settings()` | Update general settings |
| `/settings/integrations` | POST | `update_integrations()` | Configure integrations |
| `/settings/ai` | POST | `update_ai_settings()` | Configure AI settings |

#### User Settings
| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/settings/profile` | GET, POST | `user_profile()` | Edit user profile |
| `/settings/password` | POST | `change_password()` | Change password |
| `/settings/preferences` | POST | `update_preferences()` | Update UI preferences |

---

## 👥 User Management Routes

### **File**: `routes/users.py` (387 lines)

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/users` | GET | `list_users()` | List all users |
| `/users/create` | GET, POST | `create_user()` | Create new user |
| `/users/<int:user_id>/edit` | GET, POST | `edit_user()` | Edit user |
| `/users/<int:user_id>/delete` | POST | `delete_user()` | Delete user |
| `/users/<int:user_id>/toggle` | POST | `toggle_user()` | Enable/disable user |

**Roles**:
- **administrator**: Full access
- **analyst**: Case access
- **read-only**: View only

---

## 🔧 Admin Routes

### **File**: `routes/admin.py` (504 lines)

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/admin/audit` | GET | `audit_trail()` | View audit logs |
| `/admin/system_logs` | GET | `system_logs()` | View system logs |
| `/admin/system_logs/download/<service>` | GET | `download_log()` | Download service logs |
| `/admin/diagnostics` | GET | `diagnostics()` | System diagnostics dashboard |
| `/admin/diagnostics/restart_web` | POST | `restart_web_service()` | Restart web service |
| `/admin/diagnostics/restart_worker` | POST | `restart_worker_service()` | Restart worker service |
| `/admin/diagnostics/clear_queue` | POST | `clear_queue()` | Clear processing queue |

#### Diagnostics Features (NEW v1.18.3)
- **System Status**: Real-time monitoring of Database, OpenSearch, Celery, Disk Space
- **Service Controls**: Restart web/worker services without SSH access
- **Queue Management**: Clear stuck queues and reset files to initial state
- **Audit Logging**: All actions logged to database with user details
- **Admin-Only**: Requires administrator role

---

## 📡 API Routes

### **File**: `routes/api.py` (32 lines)

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/api/v1/case/<int:case_id>/stats` | GET | `get_case_stats_api()` | Case stats (JSON) |
| `/api/v1/case/<int:case_id>/events/count` | GET | `get_event_count_api()` | Event count (JSON) |
| `/api/v1/search` | POST | `api_search()` | Search API endpoint |

### **File**: `routes/api_stats.py` (98 lines)

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/api/stats/system` | GET | `system_stats()` | System health (JSON) |
| `/api/stats/cases` | GET | `cases_stats()` | All cases stats (JSON) |
| `/api/stats/processing` | GET | `processing_stats()` | Processing queue (JSON) |
| `/api/stats/opensearch` | GET | `opensearch_stats()` | OpenSearch health (JSON) |
| `/api/stats/celery` | GET | `celery_stats()` | Celery workers (JSON) |

---

## 🔄 Queue Management Routes

### **File**: `main.py` (SHOULD BE routes/queue.py)

| Route | Method | Function | Purpose |
|-------|--------|----------|---------|
| `/queue/cleanup` | POST | `queue_cleanup_all()` | Clear stuck tasks |
| `/queue/health` | GET | `queue_health_check()` | Check queue health (JSON) |

---

## 🐛 Known Issues with Routes

### **CRITICAL - Broken Routes**:
1. **Re-index operations** ⚠️
   - `/case/<id>/file/<id>/reindex`
   - `/case/<id>/bulk_reindex_selected`
   - `/case/<id>/bulk_reindex`
   - **Fix available**: See `Reindex_Bug_Analysis_and_Fix.md`

### **Needs Refactoring**:
1. **72 routes in main.py should be in blueprints**
2. **Search routes** (13) → create `routes/search.py`
3. **AI routes** (13) → create `routes/ai.py`
4. **EVTX description routes** (7) → create `routes/evtx.py`
5. **Timeline tagging** (8+) → move to `routes/timeline.py`

---

## 📝 Route Naming Conventions

### **URL Patterns**:
```
# Single resource
GET    /resource/<int:id>        # View
POST   /resource/create          # Create
POST   /resource/<int:id>/edit   # Edit
POST   /resource/<int:id>/delete # Delete

# Collection
GET    /resources                # List all
POST   /resources/bulk_action    # Bulk operation

# Case-scoped
/case/<int:case_id>/resource
/case/<int:case_id>/resource/<int:id>
```

### **Function Naming**:
```python
# CRUD operations
def view_resource(resource_id)
def list_resources()
def create_resource()
def edit_resource(resource_id)
def delete_resource(resource_id)

# Actions
def process_resource(resource_id)
def bulk_process_resources()
```

---

## 🔍 How to Find a Route

### **Method 1: Grep**
```bash
# Find route by path
grep -rn "@.*route.*'/case/<int:case_id>/search'" app/

# Find route by function name
grep -rn "def search_events" app/

# Find all routes in a file
grep -n "@.*route" app/main.py
```

### **Method 2: Flask Routes Command**
```bash
cd /opt/casescope/app
source ../venv/bin/activate
flask routes

# Output shows:
# Endpoint          Methods    Rule
# ----------------  ---------  ----------------------
# search_events     GET        /case/<int:case_id>/search
# upload_files      GET, POST  /case/<int:case_id>/upload_files
```

### **Method 3: Check This File**
All routes documented here with:
- URL pattern
- HTTP methods
- Function name
- File location
- Purpose

---

## 📚 Related Documentation

- **ARCHITECTURE_OVERVIEW.md** - System architecture
- **DATABASE_SCHEMA.md** - Database models
- **API_REFERENCE.md** - API endpoint details
- **QUICK_REFERENCE.md** - Common patterns

---

**✅ VERIFIED**: Extracted from actual codebase (Nov 20, 2025)  
**⚠️ KNOWN ISSUES**: Re-index routes broken, main.py needs refactoring  
**📊 TOTAL ROUTES**: ~140+ across all files
