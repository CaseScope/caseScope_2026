# Known Systems Management

**Route**: `/systems`  
**Blueprint**: `known_systems_bp` (auto-loaded)  
**Database Table**: `known_systems`

## Overview

Track systems and devices involved in investigations, including workstations, servers, network equipment, and threat actor infrastructure.

## Database Fields

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | VARCHAR(255) | System hostname (optional) |
| `domain_name` | VARCHAR(255) | Domain name (optional) |
| `ip_address` | VARCHAR(45) | IP address - IPv4/IPv6 (optional) |
| `system_type` | VARCHAR(50) | Type: workstation, server, router, switch, printer, wap, other, threat_actor |
| `compromised` | VARCHAR(20) | Status: yes, no, unknown (default: unknown) |
| `source` | VARCHAR(50) | Source: manual, logs (default: manual) |
| `description` | TEXT | Description (optional) |
| `analyst_notes` | TEXT | Analyst notes (optional) |
| `case_id` | INTEGER | Foreign key to case (required) |
| `created_by` | INTEGER | Foreign key to user |
| `updated_by` | INTEGER | Foreign key to user |
| `created_at` | TIMESTAMP | Creation timestamp |
| `updated_at` | TIMESTAMP | Last update timestamp |

**Note**: At least one identifier (hostname, domain_name, or ip_address) is required.

## API Endpoints

### List Systems
```
GET /systems/api/list?page=1&per_page=50&search=query&system_type=workstation&compromised=yes&source=logs
```

### Get Single System
```
GET /systems/api/get/<system_id>
```

### Statistics
```
GET /systems/api/stats
```
Returns breakdown by:
- Total count
- By system type
- By compromised status
- By source

### Create System
```
POST /systems/api/create
{
    "hostname": "DESKTOP-ABC123",
    "ip_address": "192.168.1.100",
    "domain_name": "corp.example.com",
    "system_type": "workstation",
    "compromised": "yes",
    "source": "manual",
    "description": "User workstation",
    "analyst_notes": "Found suspicious PowerShell activity"
}
```

### Update System
```
PUT /systems/api/update/<system_id>
{
    "compromised": "yes",
    "analyst_notes": "Confirmed compromised via EDR"
}
```

### Delete System
```
DELETE /systems/api/delete/<system_id>
```
**Permissions**: Analyst or Administrator only

### Bulk Update
```
POST /systems/api/bulk_update
{
    "system_ids": [1, 2, 3],
    "updates": {
        "compromised": "no",
        "source": "logs"
    }
}
```

### Bulk Delete
```
POST /systems/api/bulk_delete
{
    "system_ids": [1, 2, 3]
}
```
**Permissions**: Analyst or Administrator only

### Export CSV
```
GET /systems/api/export_csv?search=query&system_type=workstation
```

## Features

- **Statistics Tile**: Shows total systems, compromised count, workstations, and servers
- **Search**: Search across hostname, domain name, IP address, description, and notes
- **Filters**: Filter by system type, compromised status, and source
- **Pagination**: Configurable page size (25, 50, 100)
- **Auto-Discovery**: Scan OpenSearch events to automatically discover systems
- **Bulk Operations**: 
  - Select multiple systems with checkboxes
  - Bulk edit selected systems
  - Bulk delete selected systems (analyst+ only)
- **Modals**:
  - Add System: Create new system entry
  - Edit System: Update existing system (single or bulk)
  - View Details: Read-only view of system information
  - Discovery Progress: Real-time progress tracking for auto-discovery
- **CSV Export**: Export filtered results to CSV file
- **Audit Logging**: All create/update/delete operations logged

## Auto-Discovery from Logs

The "Find in Logs" feature automatically discovers systems by scanning OpenSearch events using **aggregation queries** for maximum performance.

### How It Works

1. User clicks "Find in Logs" button
2. System uses OpenSearch **terms aggregations** to extract unique hostnames/IPs (fast!)
3. Scans multiple event fields for system identifiers
4. Extracts domains from both NDJSON (`host.domain`) and EVTX (`event_data_fields.SubjectDomainName`)
5. Resolves IP addresses using aggregated `host.ip` data
6. Identifies system type based on hostname patterns
7. Performs deduplication and creates/updates database entries
8. Displays progress in real-time modal

### Fields Scanned

**Primary Fields (Keyword type - aggregated directly)**:
- `normalized_computer` - Primary hostname field (NDJSON files)
- `computer` - EVTX computer field (may contain FQDN like "ATN64025.DWTEMPS.local")

**Secondary Hostname Fields (Text with .keyword subfield)**:
- `host.name` - ECS hostname field
- `Computer`, `ComputerName`, `Hostname`, `System`, `WorkstationName`
- `SourceHostname`, `DestinationHostname`, `ClientName`
- `DeviceName`, `MachineName`, `SystemName`, `ServerName`

**Domain Fields**:
- `host.domain` - NDJSON domain field
- `event_data_fields.SubjectDomainName` - EVTX domain (Windows Security logs)
- `event_data_fields.TargetDomainName` - EVTX target domain

**IP Address Fields**:
- `host.ip` - Primary IP field (NDJSON files)
- Aggregated alongside `normalized_computer` for hostname-to-IP mapping

### System Type Detection

The discovery task attempts to identify system types based on hostname patterns:

- **Server**: server, srv-, dc-, dc0, dc1, sql-, web-, app-, file-, exchange, exch-, backup
- **Router**: router, rtr-, fw-, firewall, gateway, gw-, fortigate, palo alto, checkpoint
- **Switch**: switch, sw-, core-, dist-, access-, cisco, arista, nexus
- **Printer**: printer, print-, mfp-, copier, ricoh, xerox, konica
- **WAP**: wap, ap-, wifi, wireless, accesspoint
- **Threat Actor**: attacker, threat, actor, malicious, external, suspicious, rogue
- **Workstation**: Default if no specific pattern matches

### FQDN Handling

- Automatically strips FQDNs: "ATN64025.DWTEMPS.local" → Hostname: "ATN64025", Domain: "DWTEMPS.local"
- Normalizes to uppercase for consistency
- Prevents duplicate entries for same system with/without domain suffix

### Deduplication

- Systems are matched by hostname (case-insensitive)
- If a match is found, existing system is updated with additional information:
  - IP address (if not already set)
  - Domain name (if not already set)
- No analyst notes are added for duplicate discoveries (clean approach)

### Performance

- Uses OpenSearch **aggregations** instead of scrolling (MUCH faster!)
- Terms aggregation on keyword fields with bucket size of 1000
- Typical performance: Processes 200,000+ events in 1-2 seconds
- Celery task runs in background (non-blocking)
- Real-time progress updates via task state

### OpenSearch Field Types

Important for aggregations:
- **Keyword fields** (aggregated directly): `normalized_computer`, `computer`
- **Text fields** (need `.keyword` suffix): `host.name`, `ComputerName`, etc.
- **Nested fields**: Use dot notation: `host.ip`, `host.domain`, `event_data_fields.SubjectDomainName`

## Permissions

| Role | View | Create | Edit | Delete |
|------|------|--------|------|--------|
| **Administrator** | ✓ | ✓ | ✓ | ✓ |
| **Analyst** | ✓ | ✓ | ✓ | ✓ |
| **Read-only** | ✓ (assigned case only) | ✗ | ✗ | ✗ |

## Audit Events

- `system_created` - System manually created
- `system_updated` - System modified
- `system_deleted` - System deleted
- `systems_bulk_updated` - Bulk edit operation
- `systems_bulk_deleted` - Bulk delete operation
- `systems_exported` - CSV export

## System Types

- **workstation** - End user workstation/laptop
- **server** - Server system
- **router** - Network router
- **switch** - Network switch
- **printer** - Printer/MFP
- **wap** - Wireless access point
- **other** - Other device type
- **threat_actor** - Threat actor infrastructure

## Migration

Migration file: `/opt/casescope/migrations/add_known_systems.sql`

Applied: 2025-12-24

## Files

- **Route**: `/opt/casescope/app/routes/known_systems.py`
- **Model**: `/opt/casescope/app/models.py` (`KnownSystem` class)
- **Template**: `/opt/casescope/templates/systems/manage.html`
- **Navigation**: Updated in `/opt/casescope/templates/base.html`

## UI Design

Follows the same pattern as IOC Management:
- Central CSS used throughout (no inline styles)
- Consistent modal design
- Responsive table layout
- Badge-based status indicators
- Bulk action toolbar

