# CaseScope 2026 - Site Layout & Organization

## File Naming Convention
**Pattern**: `Type_section_function.py`
- **Example**: `route_admin_users.py`, `task_ioc_hunt.py`, `model_case_file.py`
- **Purpose**: Immediately identify file type and purpose without opening it

## Directory Structure

### `/app` - Core Application
All Flask application code, models, configuration, and business logic.

**Key Files**:
- `main.py` - Flask app initialization, auto-loads blueprints from `/app/routes`
- `config.py` - **User-configurable settings** (web server port, SSL, database, session timeout)
- `models.py` - SQLAlchemy database models (User, Case, AuditLog)
- `audit_logger.py` - Reusable audit logging utility
- `init_db.py` - Database initialization script (creates tables, seeds default admin user)
- `wsgi.py` - Gunicorn WSGI entry point

### `/app/routes` - Flask Blueprints (Auto-loaded)
All route blueprints are automatically discovered and registered by `main.py` (24 total routes).

**Core Routes**:
- `auth.py` - Login/logout authentication routes
- `admin.py` - Administrator user management, audit log viewer  
- `case.py` - Case management (create, edit, delete, select, dashboard, file management, artifact stats API)
- `dashboard.py` - Main dashboard with system stats and metrics API
- `upload.py` - File upload system (chunk-based upload, drag & drop, bulk folder)
- `settings.py` - System settings (Celery workers, Sigma rules, EVTX descriptions, SSL certificates)

**Evidence Analysis Routes** (Search & Artifacts):
- `search.py` - Event search system (boolean operators, file type filtering, event tagging)
- `browser.py` - Browser history (Chrome, Edge, Firefox, WebCache) → `case_X_browser`
- `execution.py` - Execution artifacts (Prefetch, Activities, SRUM) → `case_X_execution`
- `filesystem.py` - Filesystem timeline (MFT, Thumbcache, WinSearch) → `case_X_filesystem`

**NEW Forensic Artifact Routes** (Jan 2026):
- `useractivity.py` - User activity (Jump Lists, LNK shortcuts) → `case_X_useractivity` ⭐
- `communications.py` - Communications (PST/OST, Teams/Skype, Notifications) → `case_X_comms` ⭐
- `network.py` - Network activity (BITS transfers) → `case_X_network` ⭐
- `persistence.py` - Persistence mechanisms (Scheduled Tasks, WMI) → `case_X_persistence` ⭐
- `devices.py` - Device history (USB connections, SetupAPI) → `case_X_devices` ⭐
- `cloud.py` - Cloud storage (OneDrive operations) → `case_X_cloud` ⭐
- `remote.py` - Remote sessions (RDP bitmap cache) → `case_X_remote` ⭐

**Threat Intelligence Routes**:
- `ioc.py` - IOC management (56 indicator types, 7 categories, AI extraction)
- `hunting.py` - Threat hunting dashboard (IOC hunts, SIGMA detection)
- `noise_filters.py` - Noise filter management (29 rules, 6 categories)
- `events_noise_check.py` - Event noise checking API (real-time filter matching)

**Asset Tracking Routes**:
- `known_systems.py` - Known systems tracking (auto-discovery, CSV import/export, bulk ops)
- `known_users.py` - Known users tracking (auto-discovery, CSV import/export, bulk ops, 50+ exclusions)

**AI/Advanced Routes**:
- `ai.py` - AI assistant (RAG-powered threat intel, natural language queries, Ollama integration)

**Adding New Routes**: Create a new file in `/app/routes` exporting a blueprint with `{module_name}_bp` naming pattern, auto-loaded on restart.

### `/static` - Static Assets
Frontend resources (CSS, JavaScript, images).

#### `/css` - Centralized Styling (Root Level)
- `main.css` - Global styles, CSS variables, color palette, typography
- `components.css` - Reusable UI components (buttons, modals, alerts, badges, process tree, etc.)
- `layout.css` - Page layout and structural styles

#### `/static/css` - Static Assets (Served via Flask)
- `main.css` - Deployed/production CSS (may differ from /css)

**Philosophy**: All styling centralized in CSS files. **No inline styles**. **No `<style>` blocks in templates**. Modals and all UI components use consistent, reusable classes from `/css/components.css`.

**CSS Architecture Compliance:**
- ✅ Zero inline styles in HTML (e.g., no `style="..."`)
- ✅ Zero `<style>` blocks in templates
- ✅ All styling in central `/static/css/main.css`
- ✅ Reusable classes with semantic names
- ✅ CSS variables for theme colors (`var(--color-primary)`, etc.)
- ✅ Utility classes for spacing (`.gap-2`, `.mb-0`, `.mt-1`, etc.)
- ✅ Component classes (`.progress`, `.progress-bar`, `.processing-card`, etc.)

**If you need to add styles:**
1. Never use inline `style="..."` attributes
2. Never add `<style>` blocks to templates
3. Always add to `/static/css/main.css`
4. Use existing CSS variables when possible
5. Follow existing naming conventions

#### `/static/js` - JavaScript
- `main.js` - Core utilities (formatNumber, formatFileSize, confirmAction, flash message handling)

### `/templates` - Jinja2 HTML Templates
All HTML templates using Jinja2 templating engine (33 templates across 18 directories).

**Base Templates**:
- `base.html` - Base template with sidebar navigation (11 artifact pages), header, theme toggle
- `index.html` - Dashboard/homepage with system stats
- `login.html` - Authentication page
- `error.html` - Generic error page

**Admin Section** (`/templates/admin/`):
- `users.html` - User management (create, edit, delete users, role assignment)
- `settings.html` - System settings (Celery workers, parallel processing, SSL management)
- `evtx_descriptions.html` - EVTX event descriptions (scraping, viewing, searching 3000+ events)
- `audit_log.html` - Audit trail viewer with detail modal (searchable, filterable)
- `noise_filters.html` - Noise filter management (categories, rules, testing)
- `sigma_rules.html` - SIGMA rule management (enable/disable, sync from repo)

**Case Management** (`/templates/case/`):
- `select.html` - Case selection with table (status, files, events)
- `dashboard.html` - Case details, network config, EDR reports, artifact stats
- `files.html` - File management with artifact tracking dashboard (11 indices)
- `upload.html` - Chunked file upload (5MB chunks, drag-drop, staging modal)

**Evidence Analysis - Existing** (`/templates/`):
- `search/events.html` - Event search (boolean operators, file filtering, tagging, noise filtering)
- `browser/history.html` - Browser activity (visits, downloads, cache) → `case_X_browser`
- `execution/artifacts.html` - Execution artifacts (Prefetch, Activities, SRUM) → `case_X_execution`
- `filesystem/timeline.html` - Filesystem events (MFT, Thumbcache, WinSearch) → `case_X_filesystem`

**Evidence Analysis - NEW** (Jan 2026) (`/templates/`):
- `useractivity/shortcuts.html` - User activity (Jump Lists, LNK) → `case_X_useractivity` ⭐
- `communications/messages.html` - Communications (Email, Teams/Skype, Notifications) → `case_X_comms` ⭐
- `network/activity.html` - Network activity (BITS transfers) → `case_X_network` ⭐
- `persistence/mechanisms.html` - Persistence (Scheduled Tasks, WMI) → `case_X_persistence` ⭐
- `devices/history.html` - Device history (USB connections) → `case_X_devices` ⭐
- `cloud/sync.html` - Cloud storage (OneDrive sync) → `case_X_cloud` ⭐
- `remote/sessions.html` - Remote sessions (RDP cache) → `case_X_remote` ⭐

**Threat Intelligence** (`/templates/`):
- `ioc/manage.html` - IOC management (56 types, bulk operations, AI extraction)
- `hunting/dashboard.html` - Threat hunting (IOC hunts, SIGMA detection)

**Asset Tracking** (`/templates/`):
- `systems/manage.html` - Known systems (auto-discovery, CSV import/export, bulk edit/delete)
- `users/manage.html` - Known users (auto-discovery, CSV import/export, 50+ exclusions, bulk ops)

**AI/Advanced** (`/templates/`):
- `ai/assistant.html` - AI-powered threat intelligence assistant (RAG, Ollama, chat interface)

### `/ai_prompts` - AI Model Prompts (User-Editable)
Template prompts for AI/LLM operations that end users can customize.

### `/bin` - External Executables
Binary tools and utilities (e.g., chainsaw, sigma tools).

### `/site_docs` - Documentation
Project documentation, architecture guides, database structure, implementation plans.

### `/migrations` - Database Migrations
SQL migration scripts for schema changes.

### `/app/parsers` - Forensic Artifact Parsers (25+ parsers)
All parsers follow interface: `parse_<type>_file(file_path) -> Generator[dict]`

**Parser Factory System** (`parsers/__init__.py`):
- `detect_parser_type(filename, parent_dir)` - Auto-detects parser from filename/path
- `get_parser(parser_type)` - Lazy-loads parser function
- `PARSER_MAP` - Registry of all 25+ parsers

**Existing Parsers**:
- `evtx_parser.py`, `eztools_evtx_parser.py` - Windows Event Logs (Python + EZ Tools)
- `ndjson_parser.py` - EDR/NDJSON logs
- `firewall_csv_parser.py` - Firewall CSV logs
- `browser_history_parser.py` - Chrome/Firefox/Edge history
- `webcache_parser.py` - IE/Edge WebCache (ESE database)
- `prefetch_parser_dissect.py` - Prefetch files (dissect.util for Win10/11 compression)
- `srum_parser.py` - SRUM database (ESE)
- `eztools_mft_parser.py` - Master File Table (MFTECmd)
- `eztools_jumplist_parser.py` - Jump Lists (JLECmd)
- `eztools_lnk_parser.py`, `lnk_parser.py` - LNK shortcuts (LECmd + Python fallback)
- `setupapi_parser.py` - SetupAPI device logs

**NEW Parsers** (Jan 2026):
- `thumbcache_parser.py` - Windows thumbnail cache
- `bits_parser.py` - BITS background transfer database (ESE)
- `winsearch_parser.py` - Windows Search index (ESE)
- `activities_parser.py` - Windows Timeline/ActivitiesCache
- `notifications_parser.py` - Windows Push Notifications
- `rdp_cache_parser.py` - RDP bitmap cache
- `wmi_parser.py` - WMI persistence detection
- `pst_parser.py` - Outlook PST/OST email archives (readpst)
- `schtasks_parser.py` - Scheduled Tasks XML
- `teams_skype_parser.py` - Teams/Skype communications
- `usb_history_parser.py` - USB device history (setupapi.dev.log + registry)
- `onedrive_parser.py` - OneDrive sync logs/databases

### `/app/tasks` - Celery Background Tasks
Asynchronous processing tasks registered with Celery.

**File Processing Tasks**:
- `task_ingest_files.py` - Main ingestion orchestrator (staging, hashing, queueing)
- `task_process_file_v2.py` - **ACTIVE** parallel file processor (parser factory, auto-routing)
- `task_file_upload.py` - Legacy file upload tasks (extract_and_process_zip, parse_and_index_file)

**Threat Intelligence Tasks**:
- `task_hunt_iocs.py` - IOC hunting across events
- `task_hunt_sigma.py` - SIGMA rule detection (Chainsaw integration)
- `task_tag_noise.py` - Software noise tagging (parallel processing, 29 rules)
- `task_sigma_management.py` - SIGMA rule sync from GitHub repo

**Discovery Tasks**:
- `task_discover_systems.py` - Auto-discover systems from event logs
- `task_discover_users.py` - Auto-discover users from event logs

**Utility Tasks**:
- `task_scrape_events.py` - EVTX event description scraping from Microsoft docs

### `/app/utils` - Utility Modules
Reusable helper functions and utilities.

**Current Utilities**:
- `file_ingestion.py` - File ingestion helpers (staging, hashing, duplicate detection, cleanup)
- `event_normalization.py` - Computer name normalization (15+ field paths)
- `user_prompts.py` - Centralized user prompt messages
- `parallel_config.py` - Parallel processing configuration (slice calculation)
- `parser_routing.py` - **NEW** Parser-to-index routing map (25+ parsers → 11 indices)

## Server Configuration

**Web Server**: Gunicorn with HTTPS support
- Port configurable in `app/config.py` (default: 443)
- Workers: 4 (configurable)
- SSL certificates: `/opt/casescope/ssl/cert.pem`, `key.pem`
- Start script: `start_server.sh` (dynamically reads config.py)

**Celery Workers**: Background task processing
- Workers: 8 concurrent (configurable in Settings page)
- Max tasks per worker: 1000 (worker recycling)
- Queues: celery, default, file_processing, ingestion
- Task parallelism: 50% of workers for internal slice parallelism (SIGMA, noise tagging)
- Start script: `start_celery.sh`

**Systemd Services**:
- `casescope-new.service` - Flask web application (Gunicorn, 4 workers, HTTPS)
- `casescope-workers.service` - Celery task workers (8 workers, 4 queues)

## Key Design Principles

1. **Modularity**: Each feature in its own file with clear naming (`type_section_function.py`)
2. **Auto-loading**: Routes and tasks automatically discovered and registered
3. **Centralized Configuration**: One config file (`app/config.py`) for all user settings
4. **Centralized Styling**: All CSS in `/static/css/main.css`, zero inline styles, zero `<style>` blocks
5. **Parser Factory**: Auto-detect parsers, lazy-load, automatic routing to correct indices
6. **User-Editable**: AI prompts, config, worker settings exposed for customization
7. **Audit Everything**: Comprehensive logging of all security-sensitive actions
8. **Zero Deletion**: Files compressed (GZIP), never permanently deleted
9. **Parallel Processing**: 8 workers + configurable internal task parallelism
10. **Multi-Index Strategy**: 11 specialized OpenSearch indices for artifact types
