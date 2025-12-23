# CaseScope 2026 - Documentation Index

**Last Updated**: December 24, 2025

This directory contains comprehensive technical documentation for the CaseScope 2026 Digital Forensics & Incident Response platform.

---

## 🚀 START HERE

### For New Developers

1. **Read First**: [SITE_LAYOUT.MD](SITE_LAYOUT.MD) - Understand project structure and design principles
2. **Database Setup**: [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD) - Learn schema and relationships
3. **Authentication**: [USERS.MD](USERS.MD) - Implement user features
4. **Security**: [PERMISSIONS.MD](PERMISSIONS.MD) + [AUDIT.MD](AUDIT.MD) - Enforce access control
5. **Cases**: [CASE_PERMISSIONS.MD](CASE_PERMISSIONS.MD) + [CASE_TABLE_NEW_FIELDS.MD](CASE_TABLE_NEW_FIELDS.MD) - Case management
5. **File System**: [FILE_UPLOAD_PROCESSING.md](FILE_UPLOAD_PROCESSING.md) + [FILE_PARSING_SYSTEM.md](FILE_PARSING_SYSTEM.md) + [FILE_MANAGEMENT_UI.md](FILE_MANAGEMENT_UI.md) - Upload, parse, and display
6. **Search System**: [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md) - Query and analyze events
7. **Background Tasks**: [CELERY_SYSTEM.md](CELERY_SYSTEM.md) - Async processing
8. **Data Cleanup**: [CASE_CLEANUP_PROCEDURE.md](CASE_CLEANUP_PROCEDURE.md) - Reset case data

### For System Administrators

1. **Installation**: Follow README instructions
2. **User Management**: [USERS.MD](USERS.MD) - Create/manage accounts
3. **Permissions**: [PERMISSIONS.MD](PERMISSIONS.MD) - Understand role capabilities
4. **Settings**: [SETTINGS_WORKER_CONFIGURATION.md](SETTINGS_WORKER_CONFIGURATION.md) - Configure workers via UI
5. **Audit Log**: [AUDIT.MD](AUDIT.MD) - Monitor system activity
6. **Server Config**: [SITE_LAYOUT.MD](SITE_LAYOUT.MD) - Gunicorn, SSL, systemd

### For Security Auditors

1. **Audit System**: [AUDIT.MD](AUDIT.MD) - Complete audit trail
2. **Access Control**: [PERMISSIONS.MD](PERMISSIONS.MD) - RBAC implementation
3. **User Lifecycle**: [USERS.MD](USERS.MD) - Account management
4. **Case Operations**: [CASE_PERMISSIONS.MD](CASE_PERMISSIONS.MD) - Case-specific controls

---

## 📚 Documentation Files

### Core Architecture & Systems

#### [SITE_LAYOUT.MD](SITE_LAYOUT.MD)
**Purpose**: Project structure, file organization, and design principles

**Contents**:
- File naming conventions
- Directory structure
- Flask blueprints and auto-loading
- CSS architecture (centralized, no inline styles)
- Server configuration (Gunicorn, HTTPS, systemd)
- Key design principles

**Read First**: Essential for understanding project organization

---

#### [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD)
**Purpose**: Complete database schema and field definitions

**Contents**:
- User table (authentication, roles)
- Case table (investigations, network config, EDR reports)
- CaseFile table (uploaded files tracking)
- AuditLog table (security trail)
- Field types and relationships
- Example queries and usage patterns

**Critical For**: Backend development, database migrations

---

#### [CELERY_SYSTEM.md](CELERY_SYSTEM.md)
**Purpose**: Complete guide to background task processing

**Contents**:
- Celery configuration (Redis, workers, queues)
- Production-proven settings (battle-tested)
- Memory-safe task design
- Service management commands
- Troubleshooting guide
- Performance tuning

**Critical For**: Async operations, file processing

**Consolidated From**: CELERY_COMPLETE.md, CELERY_CONFIGURATION.md, CELERY_IMPLEMENTATION_SUMMARY.md, CELERY_PRODUCTION_SETTINGS.md

---

### File Upload & Processing

#### [FILE_UPLOAD_PROCESSING.md](FILE_UPLOAD_PROCESSING.md)
**Purpose**: Complete file upload and EVTX parsing system
**Purpose**: Complete file upload and processing system

**Contents**:
- Chunk-based upload (5MB chunks, 3 concurrent)
- EVTX parsing (Rust-based, 10-100x faster)
- NDJSON/JSON/JSONL parsing (EDR logs, Elastic Agent)
- OpenSearch bulk indexing
- Memory-safe streaming design (16GB+ systems)
- ZIP extraction (recursive)
- API reference
- Performance benchmarks

**Critical For**: File upload features, EVTX/NDJSON processing

**Consolidated From**: CHUNK_UPLOAD_SYSTEM.md, EVTX_PARSING_INDEXING.md, IMPLEMENTATION_COMPLETE.md, UPLOAD_REDIRECT_COMPLETE.md, UPLOAD_TEST_RESULTS.md, EVTX_DIAGNOSIS_SUMMARY.md, MEMORY_MANAGEMENT.md, MEMORY_SAFE_DESIGN.md

---

#### [FILE_PARSING_SYSTEM.md](FILE_PARSING_SYSTEM.md)
**Purpose**: Deep dive into file parsers and event normalization

**Contents**:
- EVTX parser internals (Rust library integration)
- NDJSON parser with ECS support
- Search blob creation algorithm
- Source system detection logic
- Normalization process
- Process tree extraction
- Memory-safe chunked processing
- Error handling strategies
- Performance benchmarks

**Critical For**: Understanding parsing pipeline, troubleshooting parser issues

---

#### [FILE_MANAGEMENT_UI.md](FILE_MANAGEMENT_UI.md)
**Purpose**: File list interface with real-time updates

**Contents**:
- File list table (8 columns with metadata)
- Real-time statistics (5-second updates)
- Processing progress indicator
- Search & filter system
- Hidden files feature (auto-classify empty files)
- Auto-refresh during processing
- System name extraction (100% success rate)

**Critical For**: UI features, file display

**Consolidated From**: FILE_LIST_COMPLETE.md, FILE_LIST_IMPLEMENTATION.md, ENHANCED_FILE_UI.md, HIDDEN_FILES_FEATURE.md, REALTIME_PROGRESS_TRACKING.md

---

### User Management & Security

#### [SITE_LAYOUT.MD](SITE_LAYOUT.MD)
**Purpose**: Project structure, file organization, and design principles

**Contents**:
- File naming conventions (`Type_section_function.py`)
- Directory structure (`/app`, `/static`, `/templates`, etc.)
- Flask blueprints and auto-loading system
- CSS architecture (centralized styling)
- Server configuration (Gunicorn, HTTPS, systemd)
- Key design principles

**Read First**: Essential for understanding project organization

---

#### [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD)
**Purpose**: Complete database schema and field definitions

**Contents**:
- User table (authentication, roles)
- Case table (investigations, network config, EDR reports)
- AuditLog table (security trail)
- Field types and relationships
- Example queries and usage patterns

**Critical For**: Backend development, database migrations

---

### User Management & Security

#### [USERS.MD](USERS.MD)
**Purpose**: User authentication and account management
- User model and database schema
- Authentication flow (login/logout)
- Session management (8-hour timeout)
- Password security (Werkzeug hashing)
- User roles (administrator, analyst, read-only)
- Case assignment for viewers
- User interface components
- Default admin account (`admin`/`admin`)
- Common queries and troubleshooting

**Use For**: Implementing user features, debugging auth issues

---

#### [PERMISSIONS.MD](PERMISSIONS.MD)
**Purpose**: Role-based access control (RBAC) system

**Contents**:
- Complete permission matrices by role
- Route decorators (`@admin_required`, `@admin_or_analyst_required`)
- Server-side enforcement patterns
- Client-side UI control (conditional rendering)
- Access control examples for all features
- Security best practices
- Privilege escalation prevention

**Critical For**: Security features, access control implementation

---

#### [AUDIT.MD](AUDIT.MD)
**Purpose**: Comprehensive audit logging system

**Contents**:
- What gets audited (login, user management, case operations)
- Audit log schema and fields
- `audit_logger.py` module usage
- Automatic context capture (user, IP, timestamp)
- Viewing audit logs (web interface with modal)
- Query examples for common scenarios
- Compliance readiness (SOC 2, HIPAA, PCI-DSS, GDPR)
- Data retention and security considerations

**Use For**: Compliance, security monitoring, forensic investigation

---

### Case Management

#### [CASE_PERMISSIONS.MD](CASE_PERMISSIONS.MD)
**Purpose**: Case-specific permission rules and enforcement

**Contents**:
- Permission matrix (create, edit, delete cases)
- Administrator: Full access including deletion
- Analyst: Create and edit (no delete)
- Viewer: Read-only access to assigned case only
- UI element visibility by role
- Route-level access control
- Audit logging for case operations
- Testing checklist by role

**Critical For**: Case management features, role restrictions

---

#### [CASE_TABLE_NEW_FIELDS.MD](CASE_TABLE_NEW_FIELDS.MD)
**Purpose**: Detailed documentation of case table fields

**Contents**:
- `opensearch_index` - Case-level indexing
- `router_ips` - Network infrastructure tracking
- `vpn_ips` - VPN ranges (supports IPs, CIDR, ranges)
- `edr_reports` - EDR report storage with delimiter
- Field formats and examples
- UI helper text recommendations
- Python parsing examples
- Migration history

**Use For**: Case form implementation, data validation

---

## 🚀 Quick Start Guide

### For Developers

1. **Start Here**: [SITE_LAYOUT.MD](SITE_LAYOUT.MD) - Understand project structure
2. **Database Setup**: [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD) - Learn schema
3. **Authentication**: [USERS.MD](USERS.MD) - Implement user features
4. **Security**: [PERMISSIONS.MD](PERMISSIONS.MD) + [AUDIT.MD](AUDIT.MD) - Enforce access control
5. **Case Management**: [CASE_PERMISSIONS.MD](CASE_PERMISSIONS.MD) + [CASE_TABLE_NEW_FIELDS.MD](CASE_TABLE_NEW_FIELDS.MD)
6. **File Upload**: [FILE_UPLOAD_PROCESSING.md](FILE_UPLOAD_PROCESSING.md) - Chunked upload system
7. **File Parsing**: [FILE_PARSING_SYSTEM.md](FILE_PARSING_SYSTEM.md) - EVTX/NDJSON parsers
8. **Search System**: [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md) - Event querying
9. **Background Tasks**: [CELERY_SYSTEM.md](CELERY_SYSTEM.md) - Async processing

### For System Administrators

1. **User Management**: [USERS.MD](USERS.MD) - Create/manage accounts
2. **Permissions**: [PERMISSIONS.MD](PERMISSIONS.MD) - Understand role capabilities
3. **Audit Log**: [AUDIT.MD](AUDIT.MD) - Monitor system activity
4. **Server Config**: [SITE_LAYOUT.MD](SITE_LAYOUT.MD) - Configure Gunicorn, SSL, systemd

### For Security Auditors

1. **Audit System**: [AUDIT.MD](AUDIT.MD) - Complete audit trail
2. **Access Control**: [PERMISSIONS.MD](PERMISSIONS.MD) - RBAC implementation
3. **User Lifecycle**: [USERS.MD](USERS.MD) - Account management
4. **Case Operations**: [CASE_PERMISSIONS.MD](CASE_PERMISSIONS.MD) - Case-specific controls

---

### Settings & Configuration

#### [SETTINGS_WORKER_CONFIGURATION.md](SETTINGS_WORKER_CONFIGURATION.md)
**Purpose**: Dynamic worker configuration via Settings page

**Contents**:
- Web UI for adjusting Celery workers (2, 4, 6, or 8)
- CPU limit validation (2/3 of cores)
- Automatic service restart
- Audit logging of changes
- Sudo permissions for casescope user

**Use For**: Administrator configuration, worker scaling

---

## 📋 Feature Status

| Feature | Status | Documentation |
|---------|--------|---------------|
| User Authentication | ✅ Complete | [USERS.MD](USERS.MD) |
| Role-Based Access Control | ✅ Complete | [PERMISSIONS.MD](PERMISSIONS.MD) |
| Audit Logging | ✅ Complete | [AUDIT.MD](AUDIT.MD) |
| Case Management | ✅ Complete | [CASE_PERMISSIONS.MD](CASE_PERMISSIONS.MD) |
| Case Dashboard | ✅ Complete | [CASE_TABLE_NEW_FIELDS.MD](CASE_TABLE_NEW_FIELDS.MD) |
| File Upload & Processing | ✅ Complete | [FILE_UPLOAD_PROCESSING.md](FILE_UPLOAD_PROCESSING.md) |
| EVTX Parsing | ✅ Complete | [FILE_PARSING_SYSTEM.md](FILE_PARSING_SYSTEM.md) |
| NDJSON/JSON Parsing | ✅ Complete | [FILE_PARSING_SYSTEM.md](FILE_PARSING_SYSTEM.md) |
| Event Search System | ✅ Complete | [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md) |
| File Type Filtering | ✅ Complete | [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md) |
| Case Cleanup | ✅ Complete | [CASE_CLEANUP_PROCEDURE.md](CASE_CLEANUP_PROCEDURE.md) |
| EDR Report Management | ✅ Complete | [CASE_TABLE_NEW_FIELDS.MD](CASE_TABLE_NEW_FIELDS.MD) |
| Network Config (Router/VPN IPs) | ✅ Complete | [CASE_TABLE_NEW_FIELDS.MD](CASE_TABLE_NEW_FIELDS.MD) |
| Celery Worker Configuration | ✅ Complete | [SETTINGS_WORKER_CONFIGURATION.md](SETTINGS_WORKER_CONFIGURATION.md) |
| EVTX Event Descriptions | ✅ Complete | [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD) |

---

## 🔐 Security Features

- **Authentication**: Session-based with 8-hour timeout
- **Password Security**: Werkzeug hashing (bcrypt-compatible)
- **RBAC**: Three-tier role system (administrator, analyst, read-only)
- **Audit Trail**: Immutable log of all security-sensitive actions
- **Access Control**: Multi-layer enforcement (route, template, JavaScript)
- **HTTPS**: SSL/TLS support with configurable certificates
- **Session Management**: Server-side sessions, secure cookies

---

## 📊 Current Routes

### Public Routes
- `/login` - User authentication
- `/health` - Health check endpoint

### Protected Routes (Authenticated)
- `/` - Dashboard (system stats, auto-refresh)
- `/case/select` - Case selection page
- `/case/dashboard` - Case details and management
- `/case/dashboard/<id>` - Specific case dashboard

### Admin Routes (Administrator Only)
- `/admin/settings` - System settings (Celery workers, EVTX descriptions)
- `/admin/settings/evtx-descriptions` - EVTX event descriptions management
- `/admin/users` - User management (create, edit, delete)
- `/admin/audit-log` - Audit trail viewer

### API Routes
- `POST /case/create` - Create new case
- `POST /case/<id>/edit` - Edit case details
- `POST /case/<id>/delete` - Delete case (admin only)
- `GET /case/<id>/edr-report` - Get EDR reports
- `POST /case/<id>/edr-report` - Update EDR reports
- `GET /api/dashboard/stats` - System statistics (auto-refresh)

---

## 🗄️ Database Tables

| Table | Purpose | Rows (typical) |
|-------|---------|----------------|
| `user` | User accounts | 1-100 |
| `case` | Investigation cases | 10-1000 |
| `audit_log` | Security audit trail | 100-10,000+ |

---

## 🔧 Configuration

**User-Configurable Settings** (`/app/config.py`):
- Web server port (default: 443)
- SSL certificates
- Database connection (PostgreSQL)
- OpenSearch connection
- Session timeout (default: 8 hours)

---

## 📝 Conventions

### File Naming
- Routes: `route_section_function.py` (e.g., `route_admin_users.py`)
- Models: `model_name.py` (e.g., `models.py`)
- Tasks: `task_operation.py` (e.g., `task_ioc_hunt.py`)

### Code Style
- Python: PEP 8 compliance
- SQL: PostgreSQL 14+ syntax
- JavaScript: ES6+ features
- CSS: BEM-like methodology with utility classes

### Commit Messages
- Format: `[Component] Description`
- Example: `[Auth] Add session timeout configuration`
- Include issue/ticket numbers when applicable

---

## 🆘 Troubleshooting

### Common Issues

**Cannot Login**:
- Check [USERS.MD](USERS.MD) - User troubleshooting section
- Verify password hash in database
- Check session configuration

**Access Denied Errors**:
- Review [PERMISSIONS.MD](PERMISSIONS.MD) - Permission matrices
- Verify user role in database
- Check audit log for failed access attempts

**Database Errors**:
- See [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD) - Migration section
- Verify PostgreSQL connection
- Check table permissions for `casescope` user

**Case Management Issues**:
- Refer to [CASE_PERMISSIONS.MD](CASE_PERMISSIONS.MD) - Role restrictions
- Check session for selected case
- Verify viewer case assignment

---

## 📞 Support

For questions or issues:
1. **Check Documentation**: Start with relevant .MD file above
2. **Review Audit Log**: `/admin/audit-log` for security issues
3. **Check Server Logs**: `/opt/casescope/logs/` for errors
4. **Database Queries**: Use examples in [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD)

---

## 📅 Changelog

### 2025-12-24
- ✅ EVTX event descriptions system (1,100+ events)
- ✅ Web scraping from multiple sources (ultimatewindowssecurity.com, microsoft.com)
- ✅ Embedded event database for reliability
- ✅ Event description search and pagination
- ✅ Automatic deduplication (keeps most descriptive version)

### 2025-12-23
- ✅ Event search system with boolean operators
- ✅ File type filtering (EVTX, NDJSON, IIS, CSV)
- ✅ Event ID display fix for EVTX files
- ✅ NDJSON/JSON/JSONL parsing
- ✅ Search blob for full-text search
- ✅ Process tree visualization
- ✅ Deep pagination optimization
- ✅ Source system detection fix
- ✅ File parsing documentation
- ✅ Search system documentation
- ✅ Case cleanup procedure documentation
- ✅ Celery worker configuration UI

### 2025-12-21
- ✅ Complete user authentication system
- ✅ Role-based access control (RBAC)
- ✅ Comprehensive audit logging
- ✅ Case management (CRUD operations)
- ✅ Case dashboard with network config
- ✅ EDR report management
- ✅ System dashboard with auto-refresh
- ✅ Documentation suite created

---

*This documentation is maintained alongside the codebase. If you find outdated information, please update it immediately.*
