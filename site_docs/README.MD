# CaseScope 2026 - Documentation Index

**Last Updated**: December 28, 2025

This directory contains comprehensive technical documentation for the CaseScope 2026 Digital Forensics & Incident Response platform.

---

## 🚀 START HERE

### For New Developers

1. **Read First**: [SITE_LAYOUT.MD](SITE_LAYOUT.MD) - Understand project structure and design principles
2. **ZIP Architecture**: [ZIP_ARCHITECTURE.md](ZIP_ARCHITECTURE.md) - NEW ZIP-centric file processing system
3. **Database Setup**: [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD) - Learn schema and relationships
4. **Authentication**: [USERS.MD](USERS.MD) - User management and authentication
5. **Security**: [PERMISSIONS.MD](PERMISSIONS.MD) + [AUDIT.MD](AUDIT.MD) - Access control and audit logging
6. **Search System**: [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md) + [EVENT_TAGGING_SYSTEM.md](EVENT_TAGGING_SYSTEM.md) - Query and tag events
7. **Threat Hunting**: [THREAT_HUNTING.md](THREAT_HUNTING.md) - IOC and Sigma rule hunting
8. **IOC Management**: [IOC-MANAGEMENT.md](IOC-MANAGEMENT.md) - Threat intelligence database
9. **Known Assets**: [KNOWN_SYSTEMS.md](KNOWN_SYSTEMS.md) + [KNOWN_USERS.md](KNOWN_USERS.md) - Track systems and user accounts
10. **AI System**: [AI_SYSTEM.MD](AI_SYSTEM.MD) + [RAG_SYSTEM.MD](RAG_SYSTEM.MD) - AI-powered analysis
11. **Background Tasks**: [CELERY_SYSTEM.md](CELERY_SYSTEM.md) - Async processing
12. **Data Cleanup**: [CASE_CLEANUP_PROCEDURE.md](CASE_CLEANUP_PROCEDURE.md) - Reset case data

### For System Administrators

1. **Installation**: Follow main project README
2. **User Management**: [USERS.MD](USERS.MD) - Create/manage accounts
3. **Permissions**: [PERMISSIONS.MD](PERMISSIONS.MD) - Role capabilities
4. **Settings**: Settings page for system configuration
5. **Audit Log**: [AUDIT.MD](AUDIT.MD) - Monitor system activity
6. **Server Config**: [SITE_LAYOUT.MD](SITE_LAYOUT.MD) - Gunicorn, SSL, systemd

### For Security Auditors

1. **Audit System**: [AUDIT.MD](AUDIT.MD) - Complete audit trail
2. **Access Control**: [PERMISSIONS.MD](PERMISSIONS.MD) - RBAC implementation
3. **User Lifecycle**: [USERS.MD](USERS.MD) - Account management
4. **Case Operations**: [PERMISSIONS.MD](PERMISSIONS.MD) - Case-specific controls

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
- IOC tables (indicators of compromise)
- Event tracking tables (ioc_hits, sigma_hits)
- Known assets tables (systems, users)
- Audit log table (security trail)
- Field types and relationships

**Critical For**: Backend development, database migrations

---

#### [CELERY_SYSTEM.md](CELERY_SYSTEM.md)
**Purpose**: Complete guide to background task processing

**Contents**:
- Celery configuration (Redis, workers, queues)
- Production-proven settings
- Memory-safe task design
- Service management commands
- Troubleshooting guide
- Dynamic worker configuration via Settings page

**Critical For**: Async operations, file processing

---

### File Upload & Processing

#### [ZIP_ARCHITECTURE.md](ZIP_ARCHITECTURE.md) ⭐ NEW
**Purpose**: ZIP-centric file processing architecture (v2.0)

**Contents**:
- Zero-deletion policy with GZIP compression
- ZIP as source of truth (virtual file tracking)
- Multi-index strategy (5 specialized indexes)
- Phase 1-3 parsers (EVTX, Browser History, Prefetch, SRUM, etc.)
- On-demand extraction for downloads
- Auto-tune performance system
- Complete API reference
- Migration guide from v1.x

**Critical For**: Understanding new file processing architecture

---

### Search & Analysis

#### [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md)
**Purpose**: Event search system with boolean operators

**Contents**:
- Boolean search operators (AND, OR, NOT)
- Parenthetical grouping
- File type filtering (EVTX, NDJSON, CSV, IIS)
- Deep pagination (100K+ events)
- Event detail modal with JSON tree
- Process tree visualization
- Performance optimization

**Critical For**: Event querying and analysis

---

#### [EVENT_TAGGING_SYSTEM.md](EVENT_TAGGING_SYSTEM.md)
**Purpose**: Manual event tagging system

**Contents**:
- Tag/untag events
- Four filter types (Other, Tagged, IOC, SIGMA)
- OpenSearch-based storage
- Performance considerations

**Use For**: Event triage and filtering

---

#### [OPENSEARCH_FIELDS.md](OPENSEARCH_FIELDS.md)
**Purpose**: OpenSearch field structure and mappings

**Contents**:
- Core field categories (EVTX, normalized, CSV)
- Field type mapping
- Index structure (case-level)
- Query examples
- Performance considerations

**Critical For**: Understanding indexed data

---

### Threat Hunting & Intelligence

#### [THREAT_HUNTING.md](THREAT_HUNTING.md)
**Purpose**: Automated IOC and SIGMA rule hunting system

**Contents**:
- IOC hunting implementation
- SIGMA rule hunting with Chainsaw (3,652 rules)
- Event matching algorithms
- Background processing
- Badge system with severity colors
- Rule management interface

**Critical For**: Automated threat detection

---

#### [IOC-MANAGEMENT.md](IOC-MANAGEMENT.md)
**Purpose**: Comprehensive IOC management system

**Contents**:
- IOC database model (56 types, 7 categories)
- Manual IOC creation, editing, deletion
- Automated IOC extraction from EDR reports (AI + regex fallback)
- Intelligent duplicate detection and merging
- Manual deduplication with tree view
- Search, filtering, pagination
- CSV export/import

**Critical For**: Threat intelligence database

---

#### [KNOWN_SYSTEMS.md](KNOWN_SYSTEMS.md)
**Purpose**: Track systems and devices in investigations

**Contents**:
- System tracking database
- Manual entry and auto-discovery from logs
- CSV import/export
- System type detection
- FQDN handling and deduplication

**Use For**: Asset tracking, system identification

---

#### [KNOWN_USERS.md](KNOWN_USERS.md)
**Purpose**: Track user accounts and identities

**Contents**:
- User tracking database
- Manual entry and auto-discovery from logs
- CSV import/export
- Cross-variant deduplication (user, DOMAIN\user, user@domain)
- System account filtering (50+ exclusions)

**Use For**: Account tracking, identity management

---

### User Management & Security

#### [USERS.MD](USERS.MD)
**Purpose**: User authentication and account management

**Contents**:
- User model and database schema
- Authentication flow (login/logout)
- Session management (8-hour timeout)
- Password security (Werkzeug hashing)
- User roles (administrator, analyst, read-only)
- User interface components
- Default admin account (`admin`/`admin`)

**Use For**: Implementing user features, debugging auth issues

---

#### [PERMISSIONS.MD](PERMISSIONS.MD)
**Purpose**: Role-based access control (RBAC) system

**Contents**:
- Complete permission matrices by role
- Route decorators (`@admin_required`, etc.)
- Server-side enforcement patterns
- Client-side UI control
- Access control examples for all features

**Critical For**: Security features, access control implementation

---

#### [AUDIT.MD](AUDIT.MD)
**Purpose**: Comprehensive audit logging system

**Contents**:
- What gets audited (login, user management, case operations)
- Audit log schema and fields
- `audit_logger.py` module usage
- Viewing audit logs (web interface)
- Query examples
- Compliance readiness (SOC 2, HIPAA, PCI-DSS, GDPR)

**Use For**: Compliance, security monitoring, forensic investigation

---

### AI & Advanced Features

#### [AI_SYSTEM.MD](AI_SYSTEM.MD)
**Purpose**: AI-powered analysis system

**Contents**:
- Architecture and components
- LLM integration (Ollama, Qwen2.5)
- Natural language queries
- Event analysis
- IOC extraction
- Setup and configuration

**Use For**: AI feature implementation

---

#### [RAG_SYSTEM.MD](RAG_SYSTEM.MD)
**Purpose**: Retrieval Augmented Generation for threat intelligence

**Contents**:
- RAG architecture
- Vector database (pgvector)
- Sigma rules and MITRE ATT&CK embeddings
- Semantic search
- Performance considerations

**Use For**: AI context enhancement

---

### Maintenance & Operations

#### [CASE_CLEANUP_PROCEDURE.md](CASE_CLEANUP_PROCEDURE.md)
**Purpose**: Reset case data procedures

**Contents**:
- Data storage locations
- Cleanup procedures for each storage type
- Statistics recalculation
- Full reset vs selective cleanup

**Use For**: Case maintenance, testing, data cleanup

---

#### [CHANGELOG.md](CHANGELOG.md)
**Purpose**: Version history and feature additions

**Contents**:
- Version-by-version changes
- New features
- Bug fixes
- Breaking changes

**Use For**: Tracking system evolution

---

## 📋 Feature Status

| Feature | Status | Documentation |
|---------|--------|---------------|
| User Authentication | ✅ Complete | [USERS.MD](USERS.MD) |
| Role-Based Access Control | ✅ Complete | [PERMISSIONS.MD](PERMISSIONS.MD) |
| Audit Logging | ✅ Complete | [AUDIT.MD](AUDIT.MD) |
| Case Management | ✅ Complete | [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD) |
| File Upload & Processing | ✅ Complete | [ZIP_ARCHITECTURE.md](ZIP_ARCHITECTURE.md) |
| EVTX Parsing | ✅ Complete | [ZIP_ARCHITECTURE.md](ZIP_ARCHITECTURE.md) |
| NDJSON/JSON Parsing | ✅ Complete | [ZIP_ARCHITECTURE.md](ZIP_ARCHITECTURE.md) |
| CSV Firewall Parsing | ✅ Complete | [ZIP_ARCHITECTURE.md](ZIP_ARCHITECTURE.md) |
| Browser History Parsing | ✅ Complete | [ZIP_ARCHITECTURE.md](ZIP_ARCHITECTURE.md) |
| Event Search System | ✅ Complete | [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md) |
| Event Tagging System | ✅ Complete | [EVENT_TAGGING_SYSTEM.md](EVENT_TAGGING_SYSTEM.md) |
| Event IOC/SIGMA Detection Alerts | ✅ Complete | [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md) |
| File Type Filtering | ✅ Complete | [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md) |
| IOC Management | ✅ Complete | [IOC-MANAGEMENT.md](IOC-MANAGEMENT.md) |
| IOC Hunting | ✅ Complete | [THREAT_HUNTING.md](THREAT_HUNTING.md) |
| IOC Extraction (AI + Regex) | ✅ Complete | [IOC-MANAGEMENT.md](IOC-MANAGEMENT.md) |
| IOC Deduplication | ✅ Complete | [IOC-MANAGEMENT.md](IOC-MANAGEMENT.md) |
| SIGMA Rule Hunting | ✅ Complete | [THREAT_HUNTING.md](THREAT_HUNTING.md) |
| SIGMA Rule Management | ✅ Complete | [THREAT_HUNTING.md](THREAT_HUNTING.md) |
| Known Systems Tracking | ✅ Complete | [KNOWN_SYSTEMS.md](KNOWN_SYSTEMS.md) |
| Known Users Tracking | ✅ Complete | [KNOWN_USERS.md](KNOWN_USERS.md) |
| AI System | ✅ Complete | [AI_SYSTEM.MD](AI_SYSTEM.MD) |
| RAG System | ✅ Complete | [RAG_SYSTEM.MD](RAG_SYSTEM.MD) |
| Case Cleanup | ✅ Complete | [CASE_CLEANUP_PROCEDURE.md](CASE_CLEANUP_PROCEDURE.md) |
| Celery Worker Configuration | ✅ Complete | [CELERY_SYSTEM.md](CELERY_SYSTEM.md) |
| SSL Certificate Upload | ✅ Complete | Settings page |

---

## 🔐 Security Features

- **Authentication**: Session-based with configurable timeout
- **Password Security**: Werkzeug hashing (bcrypt-compatible)
- **RBAC**: Three-tier role system (administrator, analyst, read-only)
- **Audit Trail**: Immutable log of all security-sensitive actions
- **Access Control**: Multi-layer enforcement (route, template, JavaScript)
- **HTTPS**: SSL/TLS support with certificate management
- **Session Management**: Server-side sessions, secure cookies

---

## 📊 Current Routes

### Public Routes
- `/login` - User authentication
- `/health` - Health check endpoint

### Protected Routes (Authenticated)
- `/` - Dashboard (system stats)
- `/case/select` - Case selection
- `/case/dashboard/<id>` - Case dashboard
- `/case/<id>/files` - File management
- `/case/<id>/upload` - File upload
- `/search/events` - Event search
- `/browser/history` - Browser history viewer
- `/ioc/manage` - IOC management
- `/hunting/dashboard` - Threat hunting
- `/systems/manage` - Known systems
- `/users/manage` - Known users
- `/ai/assistant` - AI assistant

### Admin Routes (Administrator Only)
- `/admin/users` - User management
- `/admin/audit-log` - Audit trail viewer
- `/settings` - System settings
- `/settings/evtx-descriptions` - EVTX event descriptions
- `/settings/sigma-rules` - SIGMA rule management

---

## 📝 Conventions

### File Naming
- Routes: `{section}.py` (e.g., `admin.py`, `case.py`)
- Models: `models.py`
- Tasks: `task_{operation}.py` (e.g., `task_file_upload.py`)

### Code Style
- Python: PEP 8 compliance
- SQL: PostgreSQL 14+ syntax
- JavaScript: ES6+ features
- CSS: BEM-like methodology with utility classes

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

**File Processing Issues**:
- Refer to [ZIP_ARCHITECTURE.md](ZIP_ARCHITECTURE.md) - Troubleshooting
- Check Celery workers: `systemctl status casescope-workers`
- Review logs: `/opt/casescope/logs/celery_worker.log`

---

## 📞 Support

For questions or issues:
1. **Check Documentation**: Start with relevant .MD file above
2. **Review Audit Log**: `/admin/audit-log` for security issues
3. **Check Server Logs**: `/opt/casescope/logs/` for errors
4. **Database Queries**: Use examples in [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD)

---

*This documentation is maintained alongside the codebase. All information verified against live code as of December 28, 2025.*
