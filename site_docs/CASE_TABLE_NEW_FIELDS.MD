# Case Table - New Fields Summary

## Migration Applied: 2025-12-21

The `case` table has been enhanced with the following new fields:

### 1. **opensearch_index** (VARCHAR 100)
**Purpose**: Store the OpenSearch index name for case-level indexing

**Details**:
- OpenSearch indexes are **case-level**, not file-level
- All events for a case are stored in a single index
- Typical format: `case_{id}` (e.g., `case_123`, `case_456`)
- Used for querying all events related to this case

**Example Values**:
```
case_27
case_123
incident_2026_001
```

---

### 2. **router_ips** (TEXT)
**Purpose**: Store company router IP addresses involved in the investigation

**Format**: Comma-separated list of IP addresses

**Helper Text**: "Enter router IP addresses, comma-separated if multiple"

**Example Values**:
```
192.168.1.1
192.168.1.1, 10.0.0.1
192.168.1.1, 10.0.0.1, 172.16.0.1
```

**Use Cases**:
- Network traffic analysis
- Identifying external vs internal communication
- Router log correlation

---

### 3. **vpn_ips** (TEXT)
**Purpose**: Store VPN IP addresses, subnets, and ranges for the case

**Format**: Comma-separated, supports multiple formats:
- **Single IP**: `192.168.1.100`
- **Subnet (CIDR)**: `192.168.1.0/24`
- **Range**: `192.168.1.50-192.168.1.60`

**Helper Text**: "Enter VPN IPs/ranges (e.g., 192.168.1.0/24, 10.0.0.50-10.0.0.60), comma-separated if multiple"

**Example Values**:
```
192.168.1.0/24
10.0.0.50-10.0.0.60
192.168.1.0/24, 10.0.0.50-10.0.0.60, 172.16.5.10
```

**Use Cases**:
- Define internal/VPN IP ranges
- Filter events by network location
- Identify remote vs local access
- Correlate VPN logs with events

---

### 4. **edr_reports** (TEXT)
**Purpose**: Store EDR (Endpoint Detection and Response) reports

**Format**: Text field with special delimiter for multiple reports

**Delimiter**: `*** NEW REPORT ***`

**Helper Text**: "Paste EDR reports here. If entering multiple reports, separate each with *** NEW REPORT ***"

**Example Value**:
```
EDR Report #1 - Suspicious PowerShell Execution
Detected: 2026-01-15 14:32:15
Endpoint: WORKSTATION-01
User: john.doe
Process: powershell.exe
Command Line: powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIA...
Severity: High
Details: Base64 encoded command execution detected. Decoded command 
attempts to download and execute remote script from suspicious domain.

*** NEW REPORT ***

EDR Report #2 - Lateral Movement Detected
Detected: 2026-01-16 09:15:42
Endpoint: SERVER-DC01
User: admin_compromised
Process: mstsc.exe
Source IP: 192.168.1.100
Destination: 10.0.0.50
Severity: Critical
Details: Unusual RDP session initiated from compromised workstation 
to domain controller outside normal business hours.

*** NEW REPORT ***

EDR Report #3 - Data Exfiltration Attempt
Detected: 2026-01-16 11:23:09
Endpoint: FILESERVER-02
User: john.doe
Process: robocopy.exe
Destination: \\external-site.com\share
File Count: 1,247
Data Volume: 4.7 GB
Severity: Critical
Details: Large-scale file copy operation to external SMB share.
```

**Use Cases**:
- Centralize EDR alerts for the case
- Track threat actor activity timeline
- Correlate EDR detections with log events
- Reference specific alerts in reports

---

## Database Schema

```sql
CREATE TABLE "case" (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    company VARCHAR(200),
    status VARCHAR(20),
    created_by INTEGER REFERENCES "user"(id),
    assigned_to INTEGER REFERENCES "user"(id),
    opensearch_index VARCHAR(100),       -- NEW
    router_ips TEXT,                     -- NEW
    vpn_ips TEXT,                        -- NEW
    edr_reports TEXT,                    -- NEW
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

---

## UI Considerations

When building the case create/edit form:

### Router IPs Field
```html
<div class="form-group">
    <label class="form-label">Router IP Addresses</label>
    <input type="text" class="form-input" name="router_ips" 
           placeholder="192.168.1.1, 10.0.0.1">
    <small class="text-muted">Comma-separated if multiple</small>
</div>
```

### VPN IPs Field
```html
<div class="form-group">
    <label class="form-label">VPN IP Ranges</label>
    <input type="text" class="form-input" name="vpn_ips" 
           placeholder="192.168.1.0/24, 10.0.0.50-10.0.0.60">
    <small class="text-muted">
        Supports: Single IPs, Subnets (CIDR), Ranges. Comma-separated if multiple.
    </small>
</div>
```

### EDR Reports Field
```html
<div class="form-group">
    <label class="form-label">EDR Reports</label>
    <textarea class="form-textarea" name="edr_reports" rows="10"
              placeholder="Paste EDR reports here..."></textarea>
    <small class="text-muted">
        If entering multiple reports, separate each with <code>*** NEW REPORT ***</code>
    </small>
</div>
```

---

## Python Model Access

```python
from models import Case

# Get case
case = Case.query.get(27)

# Access new fields
print(f"OpenSearch Index: {case.opensearch_index}")
print(f"Router IPs: {case.router_ips}")
print(f"VPN IPs: {case.vpn_ips}")
print(f"EDR Reports: {case.edr_reports}")

# Parse comma-separated values
if case.router_ips:
    routers = [ip.strip() for ip in case.router_ips.split(',')]
    print(f"Router list: {routers}")

if case.vpn_ips:
    vpn_ranges = [ip.strip() for ip in case.vpn_ips.split(',')]
    print(f"VPN ranges: {vpn_ranges}")

# Parse multiple EDR reports
if case.edr_reports:
    reports = case.edr_reports.split('*** NEW REPORT ***')
    reports = [r.strip() for r in reports if r.strip()]
    print(f"Found {len(reports)} EDR reports")
    for i, report in enumerate(reports, 1):
        print(f"\n--- Report {i} ---")
        print(report[:200])  # First 200 chars
```

---

## Migration File

Location: `/opt/casescope/migrations/add_case_network_and_edr_fields.sql`

Status: ✅ **Applied Successfully** (2025-12-21)

All new columns added to `case` table with proper permissions granted to `casescope` user.
