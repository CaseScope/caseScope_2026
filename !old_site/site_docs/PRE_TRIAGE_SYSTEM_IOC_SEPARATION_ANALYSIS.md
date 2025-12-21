# Pre-Triage Checks: System vs IOC Separation Analysis

**Status**: ANALYSIS / DRY RUN PLANNING  
**Date**: 2025-11-29  
**Purpose**: Define pre-triage requirements and separate Systems from IOCs

---

## 📋 Problem Statement

### Current Behavior
The AI Triage Search (Phase 6) creates IOCs for ALL discovered hostnames:

```python
for hostname in iocs.get('hostnames', []):
    normalized = normalize_hostname(hostname)
    if normalized and not is_noise_hostname(normalized):
        add_ioc_if_new('hostname', normalized)   # Creates IOC
        add_system_if_new(normalized)             # Creates System
```

### The Fundamental Issue

**A hostname or IP address is NOT an IOC by itself.**

| Term | Definition | Example |
|------|------------|---------|
| **System** | An asset in the environment | DC01, WORKSTATION-42, 192.168.1.10 |
| **IOC** | Indicator of **Compromise** - evidence of malicious activity | Attacker IP, C2 domain, malware hash |

**Current Problem**: If the triage finds that `DC01` was accessed during the attack window, it creates:
- IOC: hostname = DC01 ❌ (DC01 is a legitimate asset, not an indicator)
- System: DC01 ✓ (correct - it's an asset)

A domain controller being accessed is **normal**. It only becomes IOC-worthy if:
1. It was used as a staging point for lateral movement
2. It was compromised and credentials were dumped
3. The attacker used it to propagate

---

## 💡 Proposed Solution

### Core Concept

**Separate "Systems" (assets) from "IOCs" (indicators of compromise)**

1. **Pre-Triage Requirement**: User must run "Scan Systems" before triage
2. **IOC Creation Logic**: Only create IOCs for:
   - Systems marked as `actor_system` (attacker-controlled)
   - Systems NOT in Systems Management (unknown/external)
   - IPs NOT associated with known systems

### Pre-Triage Check Flow

```
User clicks "Run AI Triage"
         │
         ▼
┌─────────────────────────────┐
│ CHECK 1: Systems Scanned?   │
│ (Systems.count > 0 for case)│
└─────────────────────────────┘
         │
    NO ──┴── YES
    │         │
    ▼         ▼
┌──────────┐  ┌─────────────────────────┐
│ BLOCK    │  │ CHECK 2: Anchor exists? │
│ Show msg │  │ (Tagged event OR IOC)   │
│ "Scan    │  └─────────────────────────┘
│ systems  │           │
│ first"   │      NO ──┴── YES
└──────────┘      │         │
                  ▼         ▼
            ┌──────────┐  ┌──────────┐
            │ BLOCK    │  │ PROCEED  │
            │ Show msg │  │ Run      │
            │ "Need    │  │ Triage   │
            │ anchor"  │  └──────────┘
            └──────────┘
```

---

## 🔍 Detailed Analysis

### What Changes in IOC Creation (Phase 6)

#### Current Logic
```python
# Creates IOC for EVERY hostname found
add_ioc_if_new('hostname', hostname)
add_system_if_new(hostname)
```

#### Proposed Logic
```python
# Get known systems for this case
known_systems = {s.system_name.upper() for s in System.query.filter_by(case_id=case_id).all()}
known_ips = {s.ip_address for s in System.query.filter_by(case_id=case_id).all() if s.ip_address}
actor_systems = {s.system_name.upper() for s in System.query.filter_by(case_id=case_id, system_type='actor_system').all()}

for hostname in discovered_hostnames:
    normalized = normalize_hostname(hostname).upper()
    
    if normalized in actor_systems:
        # Actor system = definitely an IOC
        add_ioc_if_new('hostname', normalized)
        # System already exists (it's marked actor_system)
        
    elif normalized not in known_systems:
        # UNKNOWN system = potential external/attacker asset
        add_ioc_if_new('hostname', normalized)
        add_system_if_new(normalized)  # Add as unknown for review
        
    else:
        # KNOWN internal system = NOT an IOC
        # Just update System if needed (e.g., mark as accessed during incident)
        pass

for ip in discovered_ips:
    if ip not in known_ips:
        # Unknown IP = potential IOC
        add_ioc_if_new('ip', ip)
    else:
        # Known internal IP = NOT an IOC
        pass
```

### IOC Types That ARE Always IOCs

These should ALWAYS be created as IOCs regardless of known systems:

| IOC Type | Always IOC? | Reason |
|----------|-------------|--------|
| `ip` (external) | ✓ | External IPs contacting internal systems |
| `ip` (internal) | ❌ | Only if not associated with known system |
| `hostname` (internal) | ❌ | Only if actor_system or unknown |
| `hostname` (external) | ✓ | External hostnames are suspicious |
| `username` | ✓ | Compromised credentials are IOCs |
| `user_sid` | ✓ | User identifiers |
| `command` | ✓ | Suspicious commands are IOCs |
| `hash` | ✓ | File hashes are IOCs |
| `url` | ✓ | URLs are IOCs |
| `filename` | ✓ | Suspicious filenames are IOCs |
| `malware_name` | ✓ | Malware names are IOCs |

### What Constitutes "Unknown" System?

A system is **unknown** if:
1. Not in Systems Management table for this case
2. Not resolvable as internal (no matching IP in known ranges)

A system is **known** if:
1. Exists in Systems Management for this case
2. Has a recognized naming pattern (SRV-*, DC*, WKS-*)
3. IP is in internal ranges (10.x, 172.16-31.x, 192.168.x)

### RFC1918 IPs Without Matching Systems - Decision Required

The dry run found 27 internal-range IPs in Case 25 that don't match known systems:
- `10.230.22.54`, `10.230.22.82`
- `172.16.10.25`, `172.16.10.26`
- `192.168.0.10`, etc.

**Options**:

| Option | Behavior | Pros | Cons |
|--------|----------|------|------|
| A: Treat as IOC | Create IOC for unmatched internal IPs | Catches internal lateral movement | Many false positives from DHCP/temp IPs |
| B: Ignore | Don't create IOC for RFC1918 | Cleaner IOC list | May miss internal attacker IPs |
| C: Flag for review | Create with "unverified" flag | Best of both | Adds complexity |

**Recommendation**: Option B (Ignore RFC1918 without system match)
- Internal IPs are discovered through hostnames anyway
- If an internal IP matters, the associated hostname will be found
- External IPs (true C2, etc.) will still be captured

---

## 🧪 Dry Run Test Plan

### Test Case 1: Pre-Triage Block (No Systems Scanned)

**Real Example: Case 22**
- Systems: 0 ← NO SYSTEMS SCANNED
- IOCs: 1
- This case would have run triage without any system context!

**Setup**:
1. Create new case or use case with no systems
2. Add one IOC or tag one event (to pass anchor check)

**Expected Behavior**:
- User clicks "Run AI Triage"
- Modal shows: "⚠️ System scan required before triage"
- Button: "Scan Systems Now" → redirects to Systems Management

**Validation Query**:
```python
# Check if systems exist for case
system_count = System.query.filter_by(case_id=case_id).count()
if system_count == 0:
    return "block", "Please scan systems before running triage"
```

### Test Case 2: IOC Creation with Known Systems

**Setup** (Case 25):
1. Ensure systems are scanned (should have ~100+ systems)
2. Run manual query to identify which hostnames would become IOCs

**Validation Query**:
```python
from main import app, db
from models import System, IOC
with app.app_context():
    case_id = 25
    
    # Get current systems
    known_systems = {s.system_name.upper() for s in System.query.filter_by(case_id=case_id).all()}
    actor_systems = {s.system_name.upper() for s in System.query.filter_by(case_id=case_id, system_type='actor_system').all()}
    
    # Get current hostname IOCs
    current_hostname_iocs = {
        i.ioc_value.upper() 
        for i in IOC.query.filter_by(case_id=case_id, ioc_type='hostname').all()
    }
    
    print(f"Known systems: {len(known_systems)}")
    print(f"Actor systems: {len(actor_systems)}")
    print(f"Current hostname IOCs: {len(current_hostname_iocs)}")
    
    # How many hostname IOCs are actually known internal systems?
    internal_iocs = current_hostname_iocs & known_systems
    unknown_iocs = current_hostname_iocs - known_systems
    
    print(f"\n⚠️ IOCs that are internal systems (shouldn't be IOCs): {len(internal_iocs)}")
    for ioc in sorted(internal_iocs)[:10]:
        print(f"   - {ioc}")
    
    print(f"\n✓ IOCs that are unknown (correctly IOCs): {len(unknown_iocs)}")
    for ioc in sorted(unknown_iocs)[:10]:
        print(f"   - {ioc}")
```

### Test Case 3: Actor System Creates IOC

**Setup**:
1. In Systems Management, mark one system as "Actor System"
2. Run triage
3. Verify that system was created as an IOC

**Expected**: Actor systems should ALWAYS become IOCs

### Test Case 4: External IP Creates IOC

**Setup**:
1. Identify an external IP in the events (not 10.x, 172.x, 192.168.x)
2. Verify it gets created as IOC
3. Internal IPs with matching systems should NOT become IOCs

---

## 📊 Impact Analysis

### Dry Run Results (2025-11-30)

| Case | Systems | Hostname IOCs | False Positive | True Positive | FP Rate |
|------|---------|---------------|----------------|---------------|---------|
| 14 | 48 | 0 | 0 | 0 | N/A |
| 16 | 40 (1 actor) | 1 | 1 | 1 | **50.0%** |
| 22 | 0 | 0 | 0 | 0 | N/A |
| 25 | 29 | 29 | 29 | 2 | **93.5%** |

### Case 25 Deep Dive (Worst Case)

```
📊 SYSTEMS: 29 total, 0 actor systems
📌 IOCs: 75 total (29 hostname, 29 IP)

🔍 HOSTNAME IOC ANALYSIS:
   ❌ Internal systems (SHOULD NOT be IOCs): 29  ← ALL hostname IOCs are false positives!
   ✓ Unknown (correctly IOCs): 0
   
   Examples of FALSE POSITIVE IOCs:
      - ALLY-COMPAQ (internal workstation)
      - ATN55915 (internal workstation)
      - ATN59736 (internal workstation)

🌐 IP IOC ANALYSIS:
   ❌ Known system IPs: 0
   ⚠️ Internal range but unknown: 27 (RFC1918 IPs - need investigation)
   ✓ External IPs: 2 (TRUE IOCs: 23.4.4.223, 96.78.213.49)
```

**Key Finding**: 93.5% of IOCs in Case 25 are FALSE POSITIVES (internal systems)

### Before Implementation

| Item | Count (Typical) | Status |
|------|-----------------|--------|
| Hostname IOCs | 50-200 | Many are internal systems |
| IP IOCs | 20-100 | Mix of internal and external |
| False Positive IOCs | ~60-80% | Internal systems treated as IOCs |

### After Implementation

| Item | Count (Expected) | Status |
|------|------------------|--------|
| Hostname IOCs | 5-20 | Only unknown/external/actor |
| IP IOCs | 10-30 | Only external/unknown |
| True Positive IOCs | ~90%+ | Actual indicators of compromise |

### Benefits

1. **Cleaner IOC List**: Only actual indicators, not internal assets
2. **Better Threat Intelligence**: IOCs can be exported/shared without internal data
3. **Faster Analysis**: Analysts don't have to filter through noise
4. **Accurate Reporting**: IOC counts reflect actual threats

### Risks

1. **May miss attacker using internal system names**: Mitigated by actor_system flag
2. **Requires user action before triage**: User must scan systems first
3. **Learning curve**: Users need to understand the distinction

---

## 🔧 Implementation Phases

### Phase 1: Pre-Triage Check (Low Risk)
Add validation before triage runs:
- Check if systems exist for case
- Show modal with guidance if not
- Link to "Scan Systems" functionality

**Files to modify**:
- `templates/search_events.html` - Modal/check in frontend
- `routes/triage_report.py` - Backend validation

### Phase 2: IOC Creation Logic (Medium Risk)
Modify Phase 6 to check known systems:
- Load known systems and IPs
- Only create IOCs for unknown/actor
- Log decisions for audit

**Files to modify**:
- `tasks.py` - Phase 6 logic

### Phase 3: System Classification (Low Risk)
Add "Accessed During Incident" flag to systems:
- Mark systems seen in attack window
- Different from IOC - just for timeline context

**Files to modify**:
- `models.py` - Add field
- `routes/systems.py` - Update logic

---

## 🧪 Dry Run Script

Save this as a test script to analyze current data:

```python
#!/usr/bin/env python3
"""
Dry run analysis: System vs IOC separation
Run from /opt/casescope/app directory
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db
from models import System, IOC

def analyze_case(case_id):
    with app.app_context():
        print(f"\n{'='*60}")
        print(f"CASE {case_id} - SYSTEM vs IOC ANALYSIS")
        print(f"{'='*60}")
        
        # Get systems
        systems = System.query.filter_by(case_id=case_id).all()
        known_systems = {s.system_name.upper() for s in systems}
        known_ips = {s.ip_address for s in systems if s.ip_address}
        actor_systems = {s.system_name.upper() for s in systems if s.system_type == 'actor_system'}
        
        print(f"\n📊 SYSTEMS:")
        print(f"   Total systems: {len(systems)}")
        print(f"   Actor systems: {len(actor_systems)}")
        print(f"   Systems with IPs: {len(known_ips)}")
        
        # Get IOCs
        iocs = IOC.query.filter_by(case_id=case_id).all()
        hostname_iocs = [i for i in iocs if i.ioc_type == 'hostname']
        ip_iocs = [i for i in iocs if i.ioc_type == 'ip']
        
        print(f"\n📌 IOCs:")
        print(f"   Total IOCs: {len(iocs)}")
        print(f"   Hostname IOCs: {len(hostname_iocs)}")
        print(f"   IP IOCs: {len(ip_iocs)}")
        
        # Analyze hostname IOCs
        hostname_ioc_values = {i.ioc_value.upper() for i in hostname_iocs}
        
        internal_hostname_iocs = hostname_ioc_values & known_systems
        unknown_hostname_iocs = hostname_ioc_values - known_systems
        actor_hostname_iocs = hostname_ioc_values & actor_systems
        
        print(f"\n🔍 HOSTNAME IOC ANALYSIS:")
        print(f"   ❌ Internal systems (SHOULD NOT be IOCs): {len(internal_hostname_iocs)}")
        print(f"   ✓ Unknown (correctly IOCs): {len(unknown_hostname_iocs)}")
        print(f"   ⚠️ Actor systems (correctly IOCs): {len(actor_hostname_iocs)}")
        
        if internal_hostname_iocs:
            print(f"\n   Internal systems incorrectly marked as IOCs (sample):")
            for h in sorted(internal_hostname_iocs)[:5]:
                print(f"      - {h}")
        
        if unknown_hostname_iocs:
            print(f"\n   Unknown hostnames (correctly IOCs, sample):")
            for h in sorted(unknown_hostname_iocs)[:5]:
                print(f"      - {h}")
        
        # Analyze IP IOCs
        ip_ioc_values = {i.ioc_value for i in ip_iocs}
        
        internal_ip_iocs = ip_ioc_values & known_ips
        unknown_ip_iocs = ip_ioc_values - known_ips
        
        # Check for external IPs (not RFC1918)
        external_ips = set()
        internal_range_ips = set()
        for ip in unknown_ip_iocs:
            if ip.startswith('10.') or ip.startswith('192.168.') or \
               any(ip.startswith(f'172.{i}.') for i in range(16, 32)):
                internal_range_ips.add(ip)
            else:
                external_ips.add(ip)
        
        print(f"\n🌐 IP IOC ANALYSIS:")
        print(f"   ❌ Known system IPs (SHOULD NOT be IOCs): {len(internal_ip_iocs)}")
        print(f"   ⚠️ Internal range but unknown: {len(internal_range_ips)}")
        print(f"   ✓ External IPs (correctly IOCs): {len(external_ips)}")
        
        if external_ips:
            print(f"\n   External IPs (sample):")
            for ip in sorted(external_ips)[:5]:
                print(f"      - {ip}")
        
        # Summary
        total_false_positive = len(internal_hostname_iocs) + len(internal_ip_iocs)
        total_true_positive = len(unknown_hostname_iocs) + len(external_ips) + len(actor_hostname_iocs)
        
        print(f"\n{'='*60}")
        print(f"SUMMARY:")
        print(f"   False Positive IOCs: {total_false_positive}")
        print(f"   True Positive IOCs: {total_true_positive}")
        if total_false_positive + total_true_positive > 0:
            fp_rate = total_false_positive / (total_false_positive + total_true_positive) * 100
            print(f"   False Positive Rate: {fp_rate:.1f}%")
        print(f"{'='*60}\n")
        
        return {
            'systems': len(systems),
            'iocs': len(iocs),
            'false_positive': total_false_positive,
            'true_positive': total_true_positive
        }


if __name__ == '__main__':
    cases = [14, 16, 22, 25]
    
    for case_id in cases:
        try:
            analyze_case(case_id)
        except Exception as e:
            print(f"Error analyzing case {case_id}: {e}")
```

---

## 🧪 Test Case: Case 13 (JAMESMFG)

### Baseline (2025-11-30)

| Metric | Value |
|--------|-------|
| Name | 2025-09-05 - JAMEMFG |
| Company | JAMESMFG |
| Events | 9,793,572 |
| Indexed Files | 5,284 |
| **Systems** | 18 total |
| - Firewall | 1 |
| - Server | 4 |
| - Workstation | 13 |
| - Actor System | 0 |
| **IOCs** | 0 (clean slate) |
| **Pre-triage check** | ✓ PASS |

### Test Plan

1. **Run AI Triage** on Case 13
2. **After Triage - Measure**:
   - How many hostname IOCs were created?
   - How many match existing systems? (false positives)
   - How many are unknown? (potential true IOCs)
   - How many external IPs found?

3. **Expected Results (Current Behavior)**:
   - All discovered hostnames become IOCs (including internal systems)
   - High false positive rate expected

4. **Expected Results (After Fix)**:
   - Only unknown/external hostnames become IOCs
   - Internal systems (18 known) should NOT become IOCs
   - Only external IPs should become IOCs

### Post-Test Analysis Script

```bash
cd /opt/casescope/app && /opt/casescope/venv/bin/python3 << 'EOF'
# Run this AFTER triage to measure results
from main import app, db
from models import System, IOC

with app.app_context():
    case_id = 13
    
    systems = {s.system_name.upper() for s in System.query.filter_by(case_id=case_id).all()}
    iocs = IOC.query.filter_by(case_id=case_id).all()
    hostname_iocs = {i.ioc_value.upper() for i in iocs if i.ioc_type == 'hostname'}
    
    false_pos = hostname_iocs & systems
    true_pos = hostname_iocs - systems
    
    print(f"Hostname IOCs created: {len(hostname_iocs)}")
    print(f"False positives (internal systems): {len(false_pos)}")
    print(f"True positives (unknown): {len(true_pos)}")
    print(f"FP Rate: {len(false_pos)/(len(hostname_iocs) or 1)*100:.1f}%")
EOF
```

---

## 🔐 VPN IP Ranges (v1.43.0) - IMPLEMENTED

### Feature Added
Added `vpn_ip_ranges` field to Case model to identify VPN connections during triage.

### Database Field
```sql
ALTER TABLE "case" ADD COLUMN vpn_ip_ranges TEXT;
```

### Format
- Range format: `192.168.100.1-192.168.100.50`
- CIDR format: `10.10.0.0/24`
- Multiple ranges: Comma or semicolon separated
- Example: `192.168.100.1-192.168.100.50, 10.10.0.0/24; 172.16.50.0/24`

### UI Locations
- **Create Case**: New "🔐 VPN IP Ranges" field in Network Information section
- **Edit Case**: New "🔐 VPN IP Ranges" field after Company field

### Helper Functions Added (tasks.py)
```python
def parse_vpn_ip_ranges(vpn_ranges_str):
    """Parse VPN IP ranges string into list of networks/tuples"""
    # Returns: list of IPv4Network or (start_ip, end_ip) tuples

def is_vpn_ip(ip_str, vpn_ranges):
    """Check if IP is within any VPN range"""
    # Returns: True if IP in VPN range
```

### Usage in Triage
During triage, VPN IPs can be:
1. Flagged as `[VPN]` in analysis
2. Excluded from unknown IP IOC creation (they're expected)
3. Used to identify remote access patterns

---

## 📝 Next Steps

1. **Run dry run script** on Cases 14, 16, 22, 25 to measure current false positive rate
2. **Review results** to validate the concept
3. **Implement Phase 1** (pre-triage check) if results support concept
4. **Test Phase 1** in staging before production
5. **Implement Phase 2** (IOC creation logic) after Phase 1 is stable

---

## 📎 Related Files

- `/opt/casescope/app/tasks.py` - AI Triage Search (Phase 6)
- `/opt/casescope/app/routes/systems.py` - Systems Management
- `/opt/casescope/app/routes/triage_report.py` - Triage entry point
- `/opt/casescope/app/templates/search_events.html` - Triage modal
- `/opt/casescope/app/models.py` - System and IOC models

---

## 🔖 Key Takeaways

1. **Systems ≠ IOCs**: A hostname/IP is an asset, not evidence of compromise
2. **Actor Systems = IOCs**: Systems marked as attacker-controlled ARE indicators
3. **Unknown = Suspicious**: Hostnames/IPs not in Systems Management warrant investigation
4. **Pre-scan Required**: Users should map their environment before hunting

