# CaseScope 2026 - Technical Documentation

**Last Updated**: January 6, 2026  
**Version**: 2.0.0  
**Status**: Production Ready

## Quick Navigation

### 🎯 Essential Reading
1. **[SITE_LAYOUT.MD](SITE_LAYOUT.MD)** - Project structure, file organization, design principles
2. **[DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD)** - Complete schema reference
3. **[ZIP_ARCHITECTURE.md](ZIP_ARCHITECTURE.md)** - File processing system (v2.0)

### 🔍 Features & Systems
- **[SEARCH_SYSTEM.md](SEARCH_SYSTEM.md)** - Event search with boolean operators, filtering, tagging
- **[THREAT_HUNTING.md](THREAT_HUNTING.md)** - IOC hunting, SIGMA rules, noise filtering
- **[IOC-MANAGEMENT.md](IOC-MANAGEMENT.md)** - Threat intelligence database (56 types, AI extraction)
- **[NOISE_FILTERS.md](NOISE_FILTERS.md)** - Software noise reduction (29 rules, 6 categories)
- **[OPENSEARCH_FIELDS.md](OPENSEARCH_FIELDS.md)** - Field structure and normalization
- **[MERGE_COMBINE_FEATURE.md](MERGE_COMBINE_FEATURE.md)** - Auto-merge and manual combine for systems/users/IOCs

### 👥 Asset Tracking
- **[ASSET_TRACKING.md](ASSET_TRACKING.md)** - Known systems and users (auto-discovery, CSV import, bulk ops)

### 🔐 Security & Administration
- **[USERS.MD](USERS.MD)** - User authentication and account management
- **[PERMISSIONS.MD](PERMISSIONS.MD)** - Role-based access control (RBAC)
- **[AUDIT.MD](AUDIT.MD)** - Comprehensive audit logging

### 🤖 Advanced Features
- **[AI_SYSTEM.MD](AI_SYSTEM.MD)** - AI-powered analysis (Ollama, Qwen2.5)
- **[RAG_SYSTEM.MD](RAG_SYSTEM.MD)** - Retrieval Augmented Generation for threat intelligence
- **[CELERY_SYSTEM.md](CELERY_SYSTEM.md)** - Background task processing with parallel execution

### 🛠️ Operations
- **[CASE_CLEANUP_PROCEDURE.md](CASE_CLEANUP_PROCEDURE.md)** - Data cleanup and reset procedures
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and feature additions

---

## System Architecture

**Tech Stack**:
- **Backend**: Python 3.12, Flask, SQLAlchemy
- **Database**: PostgreSQL 14+ with pgvector
- **Search**: OpenSearch (multi-index strategy)
- **Tasks**: Celery with Redis broker
- **AI/ML**: Ollama (Qwen2.5, Mistral)

**Services** (`systemctl status`):
- `casescope-new.service` - Flask web application (Gunicorn, 4 workers, HTTPS)
- `casescope-workers.service` - Celery background workers (8 concurrent, configurable)

**File Processing** (V2.0):
- Parser factory system with auto-detection (25+ parsers)
- Parallel processing (8 workers, configurable)
- Multi-index routing (11 specialized indices)
- GZIP compression for all files
- Zero deletion policy (everything archived)
- Upload folder cleanup after staging
- MFT hostname extraction

---

## Key Features

### File Processing & Parsers (V2.0)
- ✅ Chunked web upload (5MB chunks, staging modal with progress)
- ✅ Parallel processing (8 workers, configurable parallelism)
- ✅ ZIP auto-extraction to staging folders
- ✅ Parser factory system (25+ parsers, auto-detection, lazy-loading)
- ✅ Multi-index routing (11 specialized indices)
- ✅ Real-time progress tracking with worker file display
- ✅ Automatic GZIP compression (all files)
- ✅ Upload folder cleanup after staging
- ✅ Hostname extraction (MFT, EVTX, NDJSON)
- ✅ SHA256 duplicate detection with storage verification

### Event Analysis
- ✅ Boolean search (AND, OR, NOT, parentheses)
- ✅ File type filtering (EVTX, NDJSON, CSV, IIS)
- ✅ Event tagging (manual star/unstar)
- ✅ IOC/SIGMA detection badges
- ✅ Noise filtering (show/hide by category)
- ✅ Deep pagination (100K+ events)
- ✅ Computer name normalization (15+ field path checking)

### Threat Hunting
- ✅ IOC database (56 types, 7 categories)
- ✅ AI-powered IOC extraction from EDR reports
- ✅ SIGMA rule hunting (3,652 rules via Chainsaw)
- ✅ Software noise tagging (29 rules, parallel processing)
- ✅ Related process correlation (entity_id tracking)

### Asset Tracking
- ✅ Auto-discover systems from logs
- ✅ Auto-discover users from logs  
- ✅ CSV import/export
- ✅ Bulk operations (edit, delete)
- ✅ 50+ excluded noise usernames/patterns
- ✅ Alphabetical sorting

### Security
- ✅ Three-tier RBAC (administrator, analyst, read-only)
- ✅ Comprehensive audit logging
- ✅ Session management (8-hour timeout)
- ✅ HTTPS with certificate management
- ✅ Password security (Werkzeug hashing)

---

## Quick Commands

### Service Management
```bash
sudo systemctl status casescope-new casescope-workers
sudo systemctl restart casescope-new casescope-workers
```

### Database Access
```bash
sudo -u casescope psql casescope
```

### View Logs
```bash
sudo tail -f /opt/casescope/logs/celery_worker.log
sudo tail -f /opt/casescope/logs/error.log
```

### Bulk Upload (SFTP)
```bash
# Copy files to SFTP folder (standardized upload path)
cp /path/to/files/*.zip /opt/casescope/uploads/sftp/{case_id}/

# Files await manual processing trigger via web UI
# Click "Scan for New Files" or "Start Processing" in the upload interface
```

---

## Default Credentials

**Username**: `admin`  
**Password**: `admin`

**⚠️ Change immediately after first login!**

---

## File Locations

| Data Type | Location |
|-----------|----------|
| Uploaded ZIPs (permanent) | `/opt/casescope/storage/case_{id}/` |
| Compressed files (.gz) | `/opt/casescope/storage/case_{id}/` |
| Temp extraction | `/opt/casescope/staging/{id}/` |
| Web uploads | `/opt/casescope/uploads/web/{case_id}/` |
| SFTP uploads | `/opt/casescope/uploads/sftp/{case_id}/` |
| Logs | `/opt/casescope/logs/` |
| Database | PostgreSQL `casescope` database |
| Search indexes | OpenSearch `case_{id}*` indices |

---

## Recent Updates

### v2.0.0 - January 6, 2026

**Major Release: Parser Factory & 7 New Artifact Categories**

**Parser System Overhaul**:
- ✅ V2 parser factory with automatic routing (25+ parsers)
- ✅ 12 new forensic artifact parsers added
- ✅ 7 new OpenSearch indices (11 total)
- ✅ Automatic parser detection from filename/path
- ✅ Single source of truth for index routing
- ✅ 80% code reduction (500+ lines → 100 lines)

**New Forensic Artifact Pages** (7 new evidence categories):
- ✅ User Activity (Jump Lists, LNK shortcuts)
- ✅ Communications (PST/OST email, Teams/Skype, Notifications)
- ✅ Network Activity (BITS transfers)
- ✅ Persistence Mechanisms (Scheduled Tasks, WMI subscriptions)
- ✅ Device History (USB connections, SetupAPI logs)
- ✅ Cloud Storage (OneDrive sync operations)
- ✅ Remote Sessions (RDP bitmap cache)

**NEW Parsers**:
- thumbcache_parser, bits_parser, winsearch_parser
- activities_parser, notifications_parser, rdp_cache_parser
- wmi_parser, pst_parser, schtasks_parser
- teams_skype_parser, usb_history_parser, onedrive_parser

**Parallel Processing Fixes**:
- ✅ Fixed missing task registration (7,323 files were stuck)
- ✅ Fixed UI monitoring (now shows active workers and files)
- ✅ Upload folder cleanup after staging (was leaving files behind)
- ✅ MFT hostname extraction from file paths

**Artifact Tracking Dashboard**:
- ✅ Comprehensive artifact statistics across all 11 indices
- ✅ Collapsible breakdown on Case Files page
- ✅ Per-index counts with artifact type distributions
- ✅ Replaces generic "Total Events" with accurate "Total Artifacts"

**Infrastructure**:
- ✅ Parser routing module (`utils/parser_routing.py`)
- ✅ 24 route handlers (7 new artifact pages)
- ✅ Complete sidebar navigation with icons
- ✅ All pages functional with API endpoints

### v1.5.9 - January 3, 2026

### CSV Event Display Fixes
- ✅ CSV events showing correct Event ID (from 'id' field)
- ✅ CSV events showing message content in Description column
- ✅ Firewall logs showing "Firewall" as System Name
- ✅ Enhanced event normalization for CSV logs
- ✅ 18,889 events updated via backfill script

### v1.5.7 - Dec 29, 2025

### Major Fixes
- ✅ Computer name normalization (no more "Unknown")
- ✅ ZIP container status auto-updates
- ✅ Active file tracking (see what's indexing in real-time)
- ✅ ZIP breakdown modal with file type descriptions
- ✅ Chunked upload improvements (500ms delay, better error logging)
- ✅ Known systems/users alphabetical sorting
- ✅ Search display logic fixed

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

---

*For detailed information on any topic, refer to the specific documentation file above.*
