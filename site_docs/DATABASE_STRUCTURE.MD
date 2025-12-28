# CaseScope 2026 - Database Structure

Last Updated: 2025-12-24

## Technology Stack
- **Database**: PostgreSQL 14+
- **ORM**: SQLAlchemy (Flask-SQLAlchemy)
- **Authentication**: Flask-Login with Werkzeug password hashing
- **Extensions**: pgvector (for AI embeddings)
- **Search**: OpenSearch (external)

## User Management

### User Table (`user`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `username` | String(80) | Unique login username, indexed |
| `email` | String(120) | Unique email address |
| `password_hash` | String(255) | Werkzeug hashed password |
| `full_name` | String(120) | User's display name |
| `role` | String(20) | Permission level (see below) |
| `is_active` | Boolean | Account enabled/disabled (default: True) |
| `case_assigned` | Integer | Foreign key to `case.id` (read-only users only) |
| `created_at` | DateTime | Account creation timestamp |
| `last_login` | DateTime | Last successful login timestamp |

**Relationships**:
- `assigned_case` - Relationship to `Case` model (for read-only users locked to specific case)
- `cases_created` - Backref to cases this user created
- `cases_assigned` - Backref to cases assigned to this user
- `audit_logs` - Backref to audit log entries

**Methods**:
- `set_password(password)` - Hash and set password
- `check_password(password)` - Verify password against hash

### User Roles & Permissions

#### `administrator`
- **Full Access**: All functions, all cases, all users
- **User Management**: Can create, edit, delete any user of any role
- **Case Management**: Full CRUD on all cases
- **Audit Log**: Full access to view all audit logs
- **Default User**: `admin` / `admin` (created by `init_db.py`)

#### `analyst`
- **User Management**: Can edit themselves or any `read-only` (viewer) user; **cannot** create users, **cannot** change user roles
- **Case Management**: Full access to assigned cases
- **Audit Log**: View logs for their cases only
- **Restrictions**: Cannot delete users, cannot see administrators in user list

#### `read-only` (viewer)
- **Access**: View-only access to assigned case (specified in `case_assigned` field)
- **Restrictions**: Cannot edit anything, cannot access user management, cannot see audit logs
- **Case Lock**: Locked to single case specified by administrator

## Case Management

### Case Table (`case`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `name` | String(200) | Case name/title, indexed |
| `description` | Text | Case details/notes |
| `company` | String(200) | Client/organization name |
| `status` | String(20) | Case workflow status |
| `created_by` | Integer | Foreign key to `user.id` |
| `assigned_to` | Integer | Foreign key to `user.id` |
| `opensearch_index` | String(100) | OpenSearch index name (case-level, e.g., `case_123`) |
| `router_ips` | Text | Comma-separated router IP addresses |
| `vpn_ips` | Text | Comma-separated VPN IPs/subnets/ranges |
| `edr_reports` | Text | EDR reports (separate multiple with `*** NEW REPORT ***`) |
| `created_at` | DateTime | Creation timestamp |
| `updated_at` | DateTime | Last update timestamp (auto-updates) |

**Status Values**:
- `New` - Newly created case
- `Assigned` - Assigned to analyst
- `In Progress` - Active investigation
- `Completed` - Investigation finished
- `Archived` - Closed and archived

**Relationships**:
- `creator` - Relationship to `User` who created the case
- `assignee` - Relationship to `User` assigned to the case
- `viewers` - Backref to read-only users locked to this case

### Network Configuration Fields

#### `opensearch_index`
**Purpose**: Store the OpenSearch index name for this case  
**Format**: String (e.g., `case_123`, `case_456`)  
**Notes**: 
- Indexes are **case-level**, not file-level
- All events for this case stored in single index
- Index name typically follows pattern: `case_{id}`

#### `router_ips`
**Purpose**: Store company router IP addresses involved in the case  
**Format**: Comma-separated list of IP addresses  
**Examples**:
- Single router: `192.168.1.1`
- Multiple routers: `192.168.1.1, 10.0.0.1, 172.16.0.1`

#### `vpn_ips`
**Purpose**: Store VPN IP addresses/ranges for the case  
**Format**: Comma-separated, supports multiple formats  
**Examples**:
- Single IP: `192.168.1.100`
- Subnet: `192.168.1.0/24`
- Range: `192.168.1.50-192.168.1.60`
- Multiple entries: `192.168.1.0/24, 10.0.0.50-10.0.0.60, 172.16.5.10`

**Use Case**: Define internal/VPN IP ranges for filtering during analysis

#### `edr_reports`
**Purpose**: Store EDR (Endpoint Detection and Response) reports  
**Format**: Text field, multiple reports separated by delimiter  
**Delimiter**: `*** NEW REPORT ***`  
**Example**:
```
EDR Report #1 - Suspicious PowerShell
Detected on: 2026-01-15
Endpoint: WORKSTATION-01
Details: Base64 encoded command execution...

*** NEW REPORT ***

EDR Report #2 - Lateral Movement
Detected on: 2026-01-16  
Endpoint: SERVER-DC01
Details: Unusual RDP session from compromised account...
```

**Helper Text**: "If entering multiple EDR reports, separate each with *** NEW REPORT ***"

## File Management

### CaseFile Table (`case_file`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `case_id` | Integer | Foreign key to `case.id`, indexed |
| `filename` | String(500) | Filename in storage |
| `original_filename` | String(500) | Original uploaded filename |
| `file_type` | String(50) | File type (evtx, json, csv, ndjson, zip, pf, etc.) |
| `file_size` | BigInteger | File size in bytes |
| `file_path` | String(1000) | Full storage path |
| `file_hash` | String(64), indexed | SHA256 hash for file deduplication (per case, ZIP-level) |
| **ZIP-Centric Fields** |||
| `is_container` | Boolean | True for ZIP files (default: False) |
| `is_virtual` | Boolean | True for files extracted from ZIP (default: False) |
| `parent_file_id` | Integer | Foreign key to parent ZIP container (NULL for standalone/containers) |
| `target_index` | String(100) | Target OpenSearch index (case_X, case_X_browser, case_X_execution, etc.) |
| **Processing Status** |||
| `extraction_status` | String(50) | ZIP extraction status (pending, in_progress, completed, failed) |
| `parsing_status` | String(50) | File parsing status (pending, in_progress, completed, failed) |
| `indexing_status` | String(50) | OpenSearch indexing status (pending, in_progress, completed, failed) |
| **Metadata** |||
| `source_system` | String(200) | Computer name extracted from events |
| `event_count` | Integer | Number of events parsed (default: 0) |
| `sigma_violations` | Integer | Number of Sigma rule matches (default: 0) |
| `ioc_count` | Integer | Number of IOC matches (default: 0) |
| **Error Handling** |||
| `error_message` | Text | Error details if processing failed |
| `error_details` | Text | Detailed error messages for container processing |
| `files_failed` | Integer | Count of failed files in ZIP container (default: 0) |
| `retry_count` | Integer | Number of retry attempts (default: 0) |
| **Tracking** |||
| `uploaded_by` | Integer | Foreign key to `user.id` |
| `uploaded_at` | DateTime | Upload timestamp, indexed |
| `indexed_at` | DateTime | When file was successfully indexed |
| `status` | String(50) | Overall processing status (default: 'pending') |
| `is_hidden` | Boolean | Hide from file list (default: False) |

**Status Values**:
- `pending` - Awaiting processing
- `processing` - Currently being parsed/indexed
- `parsing` - Currently parsing artifact
- `extracting` - Extracting ZIP contents
- `indexed` - Successfully indexed to OpenSearch
- `failed` - Processing failed (see error_message)
- `error` - Error occurred (see error_details)

**Foreign Keys**:
- `parent_file_id` → `case_file.id` (CASCADE on delete)

**Indexes**:
- `idx_case_file_parent` on `parent_file_id`
- `idx_case_file_virtual` on `is_virtual` WHERE `is_virtual = true`

**Relationships**:
- `case` - Relationship to `Case` this file belongs to
- `uploader` - Relationship to `User` who uploaded the file
- `parent` - Relationship to parent ZIP container (if virtual)
- `children` - Backref to virtual files extracted from this ZIP (if container)

**ZIP-Centric Architecture**:
- **Container files** (`is_container=True`): ZIP files stored in `storage/case_X/`, tracked but not indexed
- **Virtual files** (`is_virtual=True`): Files extracted from ZIP, temporarily in staging, deleted after indexing
- **Standalone files**: Regular uploaded files, compressed with GZIP after indexing
- **Multi-index routing**: `target_index` determines OpenSearch index (case_X, case_X_browser, etc.)

**Purpose**: Track all uploaded files with metadata, processing status, and extracted statistics for display in file management UI.

---

## EVTX Event Descriptions

### EventDescription Table (`event_description`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `event_id` | String(20) | Event ID (e.g., "4624"), indexed |
| `log_source` | String(100) | Log source (e.g., "Security", "System", "Microsoft-Windows-Sysmon/Operational"), indexed |
| `description` | Text | Event description |
| `category` | String(100) | Category (e.g., "Account Logon", "Object Access") |
| `subcategory` | String(100) | Subcategory if available |
| `source_website` | String(200) | Website scraped from (e.g., "ultimatewindowssecurity.com", "microsoft.com") |
| `source_url` | String(500) | Direct URL to event documentation |
| `scraped_at` | DateTime | When description was scraped, indexed |
| `updated_at` | DateTime | Last update timestamp |
| `description_length` | Integer | Length of description (for deduplication) |

**Indexes**:
- Unique constraint on (`event_id`, `log_source`) - one entry per event/source combo
- Composite index on (`event_id`, `log_source`) for fast lookups

**Purpose**: 
- Store comprehensive Windows Event Log descriptions
- Support for multiple sources: Sysmon, Security, System, Application
- Deduplication: keeps most descriptive version for each event_id + log_source
- Scraped from ultimatewindowssecurity.com, microsoft.com, and embedded data

**Example Usage**:
```python
# Lookup event description
event_desc = EventDescription.query.filter_by(
    event_id='4624',
    log_source='Security'
).first()

# Get all Security log events
security_events = EventDescription.query.filter_by(
    log_source='Security'
).all()

# Search by category
logon_events = EventDescription.query.filter_by(
    category='Logon/Logoff'
).all()
```

---

## AI & Threat Intelligence

### Pattern Embeddings Table (`pattern_embeddings`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `pattern_id` | String(200) | Unique identifier (e.g., Sigma rule ID, MITRE technique ID), indexed |
| `source` | String(50) | Source type ('sigma', 'mitre'), indexed |
| `content` | Text | Full pattern/rule content |
| `embedding` | VECTOR(384) | Sentence embedding for RAG search |
| `metadata` | JSONB | Additional fields (technique name, tags, severity), indexed (GIN) |
| `created_at` | Timestamp | Creation timestamp |
| `updated_at` | Timestamp | Last update timestamp |

**Indexes**:
- HNSW index on `embedding` column for fast vector similarity search
- GIN index on `metadata` for flexible JSONB queries
- B-tree indexes on `source` and `pattern_id`

**Purpose**: 
- Store Sigma rules and MITRE ATT&CK technique embeddings for RAG-powered AI assistant
- Enable semantic search across detection patterns
- Power AI features (natural language queries, auto-hunting, threat context)

**Note**: Owned by `postgres` user, managed via `app/ai/vector_store.py`

---

## IOC Management

### IOCs Table (`iocs`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `type` | Enum | IOC type (56 types: ipv4, domain, md5, sha256, cve_id, etc.) |
| `value` | Text | The actual IOC value (truncated to 2500 chars for indexing) |
| `full_value` | Text | Complete, untruncated value (for long command lines, etc.) |
| `category` | Enum | Category (network, file, host, identity, vulnerability, cloud, mobile) |
| `confidence` | SmallInt | Confidence score (0-100) |
| `threat_level` | Enum | Threat level (info, low, medium, high, critical) |
| `is_whitelisted` | Boolean | Whitelisted flag (default: False) |
| `is_active` | Boolean | Active/archived flag (default: True) |
| `first_seen` | Timestamp | First sighting timestamp |
| `last_seen` | Timestamp | Most recent sighting timestamp |
| `times_seen` | Integer | Number of sightings (default: 1) |
| `expires_at` | Timestamp | Optional expiration for time-limited indicators |
| `source` | Enum | Source (manual, ai_extraction, event_extraction, file_analysis, threat_feed, osint, import) |
| `source_reference` | Text | Source reference (URL, feed name, case event ID) |
| `description` | Text | IOC description |
| `analyst_notes` | Text | Analyst comments/context |
| `case_id` | Integer | Foreign key to `case.id` (nullable, cascades on delete) |
| `parent_ioc_id` | Integer | Foreign key to `iocs.id` for hierarchies (e.g., URL → Domain → IP) |
| `metadata` | JSONB | Type-specific fields (geolocation, WHOIS, etc.) |
| `enrichment` | JSONB | External threat intel (VirusTotal, AbuseIPDB, etc.) |
| `created_by` | Integer | Foreign key to `user.id` |
| `updated_by` | Integer | Foreign key to `user.id` |
| `created_at` | Timestamp | Creation timestamp |
| `updated_at` | Timestamp | Last update timestamp (auto-updates via trigger) |

**Note on IOC Value Storage**:
- `value` field is indexed (btree) and limited to 2500 characters to avoid PostgreSQL index size limits
- `full_value` field stores complete, untruncated values (no index) for very long indicators like PowerShell command lines
- When `value` is truncated, `full_value` contains the original complete value
- Analyst notes automatically updated to reflect truncation with original length

**IOC Types (56 Total)**:
- **Network** (14): ipv4, ipv6, domain, fqdn, url, uri_path, email_address, email_subject, user_agent, ja3_hash, ja3s_hash, jarm_hash, ssl_cert_hash, ssl_cert_serial
- **File** (11): md5, sha1, sha256, sha512, ssdeep, imphash, tlsh, filename, filepath, filesize, filetype
- **Host** (10): registry_key, registry_value, mutex, named_pipe, service_name, scheduled_task, process_name, command_line, parent_child_process, wmi_subscription
- **Identity** (6): username, sid, email_sender, bitcoin_address, ethereum_address, monero_address
- **Vulnerability** (6): cve_id, exploit_kit, malware_family, mitre_attack_id, yara_rule, sigma_rule_id
- **Cloud** (5): aws_account_id, s3_bucket, azure_tenant_id, oauth_app_id, api_key
- **Mobile** (4): app_package_name, apk_hash, ios_bundle_id, imei

**Indexes**:
- Core: type, value, type+value, category, threat_level, confidence
- Filters: is_active, is_whitelisted
- Temporal: first_seen, last_seen, expires_at
- Relationships: case_id, parent_ioc_id, source
- JSONB: metadata, enrichment (GIN indexes)
- Unique constraint on (type, value, case_id)

**Relationships**:
- `case` - Belongs to case
- `created_by_user` - User who created IOC
- `updated_by_user` - User who last updated IOC
- `parent_ioc` - Parent IOC (self-referential)
- `child_iocs` - Child IOCs

### IOC Tags Table (`ioc_tags`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `ioc_id` | Integer | Foreign key to `iocs.id` (cascades on delete) |
| `tag` | String(100) | Tag name (e.g., 'apt29', 'ransomware', 'false_positive') |
| `created_at` | Timestamp | Creation timestamp |

**Indexes**:
- ioc_id, tag (for lookups)
- Unique constraint on (ioc_id, tag)

### IOC Relationships Table (`ioc_relationships`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `source_ioc_id` | Integer | Foreign key to `iocs.id` (cascades on delete) |
| `target_ioc_id` | Integer | Foreign key to `iocs.id` (cascades on delete) |
| `relationship_type` | String(50) | Relationship type (resolves_to, downloads, communicates_with, drops, executes, etc.) |
| `confidence` | SmallInt | Confidence score (0-100) |
| `notes` | Text | Relationship notes |
| `created_at` | Timestamp | Creation timestamp |

**Indexes**:
- source_ioc_id, target_ioc_id, relationship_type
- Unique constraint on (source_ioc_id, target_ioc_id, relationship_type)

### IOC Enrichment Table (`ioc_enrichment`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `ioc_id` | Integer | Foreign key to `iocs.id` (cascades on delete) |
| `enrichment_source` | String(100) | External source (virustotal, abuseipdb, shodan, etc.) |
| `enrichment_data` | JSONB | Enrichment response data |
| `success` | Boolean | Enrichment success flag (default: True) |
| `error_message` | Text | Error details if enrichment failed |
| `enriched_at` | Timestamp | Enrichment timestamp |

**Purpose**: 
- Comprehensive IOC tracking system for threat intelligence
- Support for 56 IOC types across 7 categories
- Flexible tagging and relationship mapping
- External threat intel enrichment tracking
- Case-level IOC association with hierarchical relationships

**Helper Functions**:
- `increment_ioc_sighting(type, value, case_id)` - Auto-increment times_seen and update last_seen
- `get_ioc_stats()` - Returns IOC statistics (total, active, critical, breakdowns by category/threat_level)

### Event IOC Hits Table (`event_ioc_hits`)
|| Column | Type | Details |
||--------|------|---------|
|| `id` | Integer | Primary key |
|| `case_id` | Integer | Foreign key to `case.id` (cascades on delete), indexed |
|| `opensearch_doc_id` | String(255) | OpenSearch document ID, indexed |
|| `source_index` | String(100) | Source OpenSearch index (e.g., `case_3`, `case_3_browser`) |
|| `event_record_id` | BigInteger | Event record ID (nullable, EVTX only) |
|| `event_id` | String(255) | Event ID or event_type, indexed |
|| `event_timestamp` | DateTime | Event timestamp |
|| `computer` | String(255) | Computer/hostname (nullable, EVTX only) |
|| `ioc_id` | Integer | Foreign key to `iocs.id` (cascades on delete), indexed |
|| `ioc_value` | String(1000) | IOC value (denormalized) |
|| `ioc_type` | String(50) | IOC type (denormalized), indexed |
|| `ioc_category` | String(50) | IOC category (denormalized) |
|| `threat_level` | String(20) | Threat level (denormalized), indexed |
|| `matched_in_field` | String(255) | Field where IOC was found |
|| `match_context` | Text | Context of the match |
|| `confidence` | String(20) | Confidence level (default: 'high') |
|| `detected_at` | DateTime | Detection timestamp (default: now), indexed |
|| `detected_by` | Integer | Foreign key to `user.id` |

**Indexes**:
- case_id, opensearch_doc_id, ioc_id, event_id
- threat_level, ioc_type, detected_at
- Unique constraint on (case_id, opensearch_doc_id, ioc_id)

**Relationships**:
- `case` - Belongs to case
- `ioc` - References IOC
- `detector` - User who initiated hunt

**Purpose**:
- Links OpenSearch events to IOC database entries across multiple indices
- **Multi-index support**: Tracks IOC hits in both main (`case_X`) and browser (`case_X_browser`) indices
- Powers IOC badge display in search results
- Tracks which events contain which IOCs
- Supports IOC hunt statistics and reporting
- Enables filtering events by IOC presence

---

### Event Sigma Hits Table (`event_sigma_hits`)
|| Column | Type | Details |
||--------|------|---------|
|| `id` | Integer | Primary key |
|| `case_id` | Integer | Foreign key to `case.id`, indexed |
|| `opensearch_doc_id` | String(255) | OpenSearch document ID, indexed |
|| `file_id` | Integer | Foreign key to `case_file.id`, indexed |
|| `sigma_rule_id` | String(255) | Sigma rule ID (e.g., UUID), indexed |
|| `rule_title` | Text | Human-readable rule title |
|| `rule_level` | String(50) | Severity (critical, high, medium, low, informational), indexed |
|| `mitre_tags` | Text | Comma-separated MITRE ATT&CK tags |
|| `matched_at` | DateTime | Detection timestamp (default: now), indexed |
|| `detected_by` | Integer | Foreign key to `user.id` |

**Indexes**:
- case_id, opensearch_doc_id, file_id, sigma_rule_id
- rule_level, matched_at, detected_by
- Unique constraint on (opensearch_doc_id, sigma_rule_id)

**Relationships**:
- `case` - Belongs to case
- `case_file` - References EVTX file that was scanned
- `detector` - User who initiated hunt

**Purpose**:
- Links OpenSearch events to Sigma rule detections
- Powers Sigma badge display in search results with severity-based colors
- Tracks which events match which Sigma rules
- Supports Sigma hunt statistics and reporting
- Enables filtering events by Sigma rule matches

---

## Known Systems Management

### KnownSystems Table (`known_systems`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `hostname` | String(255) | System hostname, indexed |
| `domain_name` | String(255) | Domain name, indexed |
| `ip_address` | String(45) | IP address (IPv4/IPv6), indexed |
| `system_type` | String(50) | System type (workstation, server, router, switch, printer, wap, other, threat_actor), indexed |
| `compromised` | String(20) | Compromised status (yes, no, unknown), default: 'unknown', indexed |
| `source` | String(50) | Source (manual, logs, EDR, csv_import, ioc_extraction), default: 'manual', indexed |
| `description` | Text | System description |
| `analyst_notes` | Text | Analyst notes and observations |
| `case_id` | Integer | Foreign key to `case.id` (cascades on delete), indexed |
| `created_by` | Integer | Foreign key to `user.id` |
| `updated_by` | Integer | Foreign key to `user.id` |
| `created_at` | Timestamp | Creation timestamp, indexed |
| `updated_at` | Timestamp | Last update timestamp |

**Indexes**:
- hostname, domain_name, ip_address (for search)
- system_type, compromised, source (for filtering)
- case_id (for case-level queries)
- created_at (for sorting)

**Relationships**:
- `case` - Belongs to case
- `creator` - User who created the entry
- `updater` - User who last updated the entry

**Purpose**: 
- Track systems and devices involved in investigations
- Identify compromised systems vs. legitimate infrastructure
- Support manual entry, automated extraction from logs, EDR reports, IOC extraction, and CSV import
- Track workstations, servers, network equipment, and threat actor infrastructure

**Features**:
- **Discovery from Logs**: Scan OpenSearch logs to automatically identify systems
- **CSV Import**: Bulk import systems from CSV (format: name,domain,ip,compromised)
- **IOC Extraction**: Automatically add hostnames found during EDR IOC extraction
- **Deduplication**: Hostname-based deduplication across all sources

**Validation**:
- At least one identifier required (hostname, domain_name, or ip_address)
- system_type is required

---

## Known Users Management

### KnownUsers Table (`known_users`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `username` | String(255) | Username, indexed |
| `domain_name` | String(255) | Domain name (or '-' for local/unknown), indexed |
| `sid` | String(255) | Security Identifier (or '-' if unknown), indexed |
| `user_type` | String(50) | User type (domain, local, unknown), default: 'unknown', indexed |
| `compromised` | String(20) | Compromised status (yes, no), default: 'no', indexed |
| `source` | String(50) | Source (manual, logs, ioc_extraction, csv_import), default: 'manual', indexed |
| `description` | Text | User description |
| `analyst_notes` | Text | Analyst notes and observations |
| `case_id` | Integer | Foreign key to `case.id` (cascades on delete), indexed |
| `created_by` | Integer | Foreign key to `user.id` |
| `updated_by` | Integer | Foreign key to `user.id` |
| `created_at` | Timestamp | Creation timestamp, indexed |
| `updated_at` | Timestamp | Last update timestamp |

**Indexes**:
- username, domain_name, sid (for search)
- user_type, compromised, source (for filtering)
- case_id (for case-level queries)
- created_at (for sorting)

**Relationships**:
- `case` - Belongs to case
- `creator` - User who created the entry
- `updater` - User who last updated the entry

**Purpose**: 
- Track user accounts/identities involved in investigations
- Identify compromised accounts vs. legitimate users
- Support manual entry, automated extraction from logs, IOC extraction, and CSV import
- Distinguish between domain users, local users, and unknown user types

**Features**:
- **Discovery from Logs**: Scan EVTX and NDJSON logs to automatically identify users
  - EVTX fields: TargetUserName, SubjectUserName, User, AccountName
  - NDJSON fields: user.name, user.id, source.user.name, destination.user.name
  - Extracts domains and SIDs when available
- **CSV Import**: Bulk import users from CSV (format: name,domain,sid,compromised)
- **IOC Extraction**: Automatically add usernames found during EDR IOC extraction
- **Deduplication**: Username + domain based deduplication across all sources
- **Cross-variant Matching**: Recognizes `user`, `DOMAIN\user`, and `user@domain` as related
- **System Account Filtering**: Excludes 50+ common system accounts, groups, and service accounts

**User Type Classification**:
- `domain`: User with domain context (DOMAIN\user or user@domain.com)
- `local`: Local system account (hostname\user or workgroup account)
- `unknown`: User without clear domain association

**Validation**:
- Username is required
- Domain and SID are optional (use '-' for unknown)

---

## Audit Logging

### AuditLog Table (`audit_log`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `timestamp` | DateTime | When action occurred, indexed |
| `user_id` | Integer | Foreign key to `user.id` (nullable) |
| `username` | String(80) | Denormalized username (preserved if user deleted) |
| `action` | String(100) | Action performed, indexed |
| `resource_type` | String(50) | Type of resource (user, case, file, ioc), indexed |
| `resource_id` | Integer | ID of affected resource |
| `resource_name` | String(500) | Human-readable resource name |
| `ip_address` | String(45) | Client IP (IPv4 or IPv6) |
| `user_agent` | Text | Browser/client user agent string |
| `details` | Text | JSON string with additional context |
| `status` | String(20) | Action result (success, failed, error) |

**Relationships**:
- `user` - Relationship to `User` who performed the action

**Purpose**: 
- Security compliance and forensic investigation
- Track all security-sensitive actions (login, user creation/deletion/modification, case changes)
- Immutable audit trail for compliance requirements

### Audit Logger Usage

```python
from audit_logger import log_action

# Login/logout
log_action('login', status='success')
log_action('logout')

# User management with detailed changes
log_action('create_user', 
    resource_type='user', 
    resource_id=new_user.id,
    resource_name=new_user.username,
    details={
        'role': new_user.role,
        'email': new_user.email,
        'case_assigned': case_id  # If read-only user
    }
)

log_action('modify_user',
    resource_type='user',
    resource_id=user.id,
    resource_name=user.username,
    details={
        'changes': {
            'role': {'old': 'analyst', 'new': 'administrator'},
            'email': {'old': 'old@example.com', 'new': 'new@example.com'}
        },
        'current_role': user.role
    }
)

log_action('delete_user',
    resource_type='user',
    resource_id=user.id,
    resource_name=user.username,
    details={
        'reason': 'Employee terminated',
        'deleted_by': current_user.username,
        'role': user.role,
        'case_assigned': user.case_assigned
    }
)

# Case operations
log_action('create_case',
    resource_type='case',
    resource_id=case.id,
    resource_name=case.name
)
```

## Database Initialization

**Script**: `app/init_db.py`

**Creates**:
1. All tables (user, case, case_file, audit_log, event_description)
2. Default administrator account:
   - Username: `admin`
   - Password: `admin`
   - Role: `administrator`

**Usage**:
```bash
cd /opt/casescope
source venv/bin/activate
python3 app/init_db.py
```

## Complete Table List

| Table Name | Owner | Purpose |
|------------|-------|---------|
| `user` | casescope | User accounts and authentication |
| `case` | casescope | Investigation cases |
| `case_file` | casescope | Uploaded files and processing status |
| `audit_log` | casescope | Security audit trail |
| `event_description` | casescope | Windows Event Log descriptions |
| `iocs` | casescope | Indicators of Compromise |
| `ioc_tags` | casescope | IOC tagging system |
| `ioc_relationships` | casescope | IOC relationship mappings |
| `ioc_enrichment` | casescope | External threat intel enrichment log |
| `event_ioc_hits` | casescope | Event-to-IOC linkage tracking |
| `event_sigma_hits` | casescope | Event-to-Sigma rule linkage tracking |
| `known_systems` | casescope | Known systems and devices tracking |
| `known_users` | casescope | Known users and identities tracking |
| `pattern_embeddings` | postgres | AI embeddings for Sigma rules & MITRE ATT&CK |

## Schema Changes & Migrations

Store SQL migration scripts in `/migrations` directory with descriptive names and GRANT statements for the `casescope` PostgreSQL user.

**Existing Migrations**:
- `add_pgvector_patterns.sql` - Creates pattern_embeddings table with pgvector extension for AI/RAG
- `add_ioc_management.sql` - Creates IOC management tables (iocs, ioc_tags, ioc_relationships, ioc_enrichment)
- `add_known_systems.sql` - Creates known_systems table for tracking devices and infrastructure
- `add_known_users.sql` - Creates known_users table for tracking user accounts and identities
- `add_event_ioc_hits.sql` - Creates event_ioc_hits table for linking events to IOCs
- `add_event_sigma_hits.sql` - Creates event_sigma_hits table for linking events to Sigma rule detections

## PostgreSQL Extensions

| Extension | Version | Purpose |
|-----------|---------|---------|
| `vector` | Latest | pgvector for AI embeddings (384-dimensional sentence transformers) |

**Enable Extensions**:
```sql
CREATE EXTENSION IF NOT EXISTS vector;
```
