# CaseScope 2026 - Technical Documentation

**Last Updated**: December 29, 2025

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

**File Processing**:
- ZIP-centric architecture (v2.0)
- Virtual file tracking
- Multi-index routing (5 specialized indexes)
- GZIP compression
- Zero deletion policy

---

## Key Features

### File Processing
- ✅ Chunked web upload (5MB chunks, 500ms delay)
- ✅ Bulk upload folder monitoring
- ✅ ZIP auto-extraction with virtual file tracking
- ✅ Multi-index routing (events, browser, execution, network, devices)
- ✅ Real-time progress tracking with active file display
- ✅ Automatic GZIP compression

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

### Bulk Upload
```bash
# Copy files to monitored folder
cp /path/to/files/*.zip /opt/casescope/bulk_upload/3/

# Files auto-process (no web upload needed)
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
| Bulk upload | `/opt/casescope/bulk_upload/{case_id}/` |
| Logs | `/opt/casescope/logs/` |
| Database | PostgreSQL `casescope` database |
| Search indexes | OpenSearch `case_{id}*` indices |

---

## Recent Updates (v1.5.7 - Dec 29, 2025)

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
