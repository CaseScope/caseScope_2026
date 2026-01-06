# Hostname Tracking Implementation - Complete Summary

## Overview

Implemented a comprehensive two-phase hostname extraction and tracking system that ensures every artifact indexed into OpenSearch can be reliably traced back to its source machine. This enables:
- IOC hunting across machines
- Machine-based artifact correlation  
- Reliable source attribution for forensic analysis

---

## What Was Implemented

### 1. Database Schema Updates (`models.py`)

**New Fields Added to `CaseFile` Model:**
```python
archive_type                 # single_host, multi_host, unknown
source_system_method        # evtx, lnk, filename, manual, path, ndjson
source_system_confidence    # high, medium, low, pending
suggested_source_system     # Alternative hostname found during processing
user_specified_hostname     # Manually entered by user
needs_review               # Flag for hostname review page
```

### 2. OpenSearch Schema Updates (`opensearch_indexer.py`)

**New Field in Index Mapping:**
```python
'source_system': {'type': 'keyword'}  # Hostname where artifact was collected
```

**Enhanced `bulk_index()` Method:**
- Added `source_system` parameter
- Automatically adds `source_system` to every indexed event
- Works alongside existing `source_file`, `case_id`, `file_type` metadata

### 3. Archive Detection Utilities (`utils/archive_detection.py`)

**New Helper Functions:**
- `detect_archive_type()` - Inspects ZIP contents to determine single vs multi-host
- `extract_hostname_from_filename()` - Extracts hostname from filenames
- `suggest_hostname_source()` - Recommends initial hostname and confidence
- `extract_username_from_path()` - Extracts username from Windows paths
- `validate_hostname()` - Validates hostname format

**Detection Patterns:**
- CyLR/KAPE: Detects `C/Windows/System32/winevt/Logs/*.evtx` structure
- Multi-host: Detects hostname directories or NDJSON exports
- Confidence scoring based on structure and content

### 4. Enhanced File Processing (`tasks/task_process_file_v2.py`)

**Two-Phase Hostname Extraction:**

**Phase 1 - Upload Time:**
- Archive type detected (single-host, multi-host, unknown)
- Initial hostname from filename or user input
- Confidence marked as 'pending' for refinement

**Phase 2 - Processing Time:**
- Extract from artifacts (EVTX, LNK, NDJSON)
- Refine initial hostname with extracted data
- Update confidence level (high/medium/low)
- Flag for review if mismatch or uncertain

**Extraction Priority:**
1. EVTX Computer field (highest confidence)
2. LNK MachineID field
3. NDJSON/EDR hostname fields
4. File path patterns
5. ZIP filename (fallback)
6. User-specified manual entry

### 5. Upload Page Enhancements (`templates/case/upload.html`)

**CyLR Recommendation Section:**
- Prominent recommendation to use CyLR for forensic collections
- Direct download link to GitHub releases
- Benefits explanation (hostname detection, comprehensive artifacts)

**Archive Type Selection (for ZIP files):**
- **Single-Host Collection**: CyLR/KAPE archives from one machine
- **Multi-Host Collection**: EDR exports, bulk logs from multiple systems
- **Unknown/Mixed**: Will attempt extraction, mark uncertain as needing review

**Hostname Source Options (Single-Host):**
- **Auto-detect**: Extract from artifacts, fallback to filename (recommended)
- **Use filename**: Use ZIP filename as hostname
- **Specify manually**: User enters exact hostname

**UI Features:**
- Archive type auto-detection and pre-selection
- Hostname preview from filename
- Per-file configuration for bulk uploads
- Visual feedback with badges and helpers

### 6. Hostname Review Page (`templates/case/review_hostnames.html`)

**Post-Processing Review Interface:**

**Shows Files Needing Review:**
- Low confidence hostnames
- Conflicting hostname data (filename vs extracted)
- Failed extractions

**For Each File:**
- Current hostname and source method
- Suggested hostname (if found in artifacts)
- Confidence level badge
- Update or verify options

**Actions:**
- Update hostname (triggers re-indexing)
- Mark current as correct (upgrades confidence)
- Use suggested hostname (one-click)
- Bulk verify all

### 7. Review Routes (`routes/case.py`)

**New Endpoints:**
- `GET /case/<id>/review_hostnames` - Review page
- `POST /case/<id>/update_hostname/<file_id>` - Update and re-index
- `POST /case/<id>/verify_hostname/<file_id>` - Mark as verified
- `POST /case/<id>/verify_all_hostnames` - Bulk verify

**Re-indexing Logic:**
- Updates OpenSearch events via `update_by_query`
- Modifies all events with matching `source_file`
- Updates database record atomically
- Handles failures gracefully

### 8. Database Migration (`migrations/add_hostname_tracking_fields.py`)

**Migration Script:**
- Adds 6 new columns to `case_file` table
- Updates existing records with default values
- Sets `needs_review=TRUE` for uncertain hostnames
- Includes rollback capability
- Provides migration summary with review count

---

## How It Works: End-to-End Flow

### Scenario 1: CyLR Archive Upload

**1. User uploads `ATN62319.zip`**
- System detects: Single-Host (CyLR structure with EVTX files)
- Auto-selects: "Single-Host Collection"
- Suggests hostname: `ATN62319` (from filename)
- User clicks "Upload" (no manual intervention needed)

**2. Background Processing**
- Extracts ZIP → finds Security.evtx
- Parses first event → Computer: `ATN62319.DWTEMPS.local`
- Refines hostname: `ATN62319` → `ATN62319.DWTEMPS.local`
- Updates confidence: `pending` → `high`
- Updates method: `filename` → `evtx`

**3. Indexing**
- All EVTX events get: `source_system: ATN62319.DWTEMPS.local`
- All MFT entries get: `source_system: ATN62319.DWTEMPS.local`
- All Prefetch events get: `source_system: ATN62319.DWTEMPS.local`
- All browser history get: `source_system: ATN62319.DWTEMPS.local`

**4. Result**
- 100% of events have reliable source system
- No review needed (high confidence)
- Ready for IOC hunting and analysis

### Scenario 2: Generic Archive with No EVTX

**1. User uploads `forensic_collection.zip`**
- System detects: Unknown (no EVTX, mixed artifacts)
- Auto-selects: "Unknown/Mixed"
- Suggests hostname: `forensic_collection` (from filename)
- User should specify: Selects "Specify manually" → enters `WORKSTATION-05`

**2. Background Processing**
- Extracts ZIP → finds only MFT, Prefetch, Browser data
- Tries extraction → no hostname in artifacts
- Uses user-specified: `WORKSTATION-05`
- Confidence: `high` (user-specified)
- Method: `manual`

**3. Indexing**
- All events get: `source_system: WORKSTATION-05`
- No review needed (user specified)

### Scenario 3: Multi-Host EDR Export

**1. User uploads `EDR_Export_Nov2025.zip`**
- System detects: Multi-Host (NDJSON files)
- Auto-selects: "Multi-Host Collection"
- No single hostname needed

**2. Background Processing**
- Each NDJSON file processed independently
- Hostnames extracted per file from EDR data
- File 1 → `host.hostname: LAPTOP-01` → `source_system: LAPTOP-01`
- File 2 → `host.hostname: LAPTOP-02` → `source_system: LAPTOP-02`
- File 3 → `host.hostname: SERVER-DC` → `source_system: SERVER-DC`

**3. Indexing**
- Events segregated by source system
- 47 unique hostnames identified
- Each event traceable to source machine

---

## Query Capabilities Enabled

### Find All Artifacts from a Machine
```json
{
  "query": {
    "term": { "source_system": "ATN62319.DWTEMPS.local" }
  }
}
```

### IOC Hunt Across All Machines
```json
{
  "query": {
    "match": { "search_blob": "malware.exe" }
  },
  "aggs": {
    "affected_systems": {
      "terms": { "field": "source_system", "size": 100 }
    }
  }
}
```
**Returns:** List of all machines with the IOC

### Find Shared Artifacts
```json
{
  "query": {
    "term": { "file_hash": "abc123..." }
  },
  "aggs": {
    "systems_with_file": {
      "terms": { "field": "source_system" }
    }
  }
}
```

### Dual-Level Tracking (Collection vs Artifact Source)
```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "source_system": "ATN62319.DWTEMPS.local" } },
        { "term": { "machine_id": "desktop-54fbqrv" } }
      ]
    }
  }
}
```
**Use Case:** Find LNK files collected from ATN62319 that reference a different machine (lateral movement indicator)

---

## Installation & Setup

### 1. Run Database Migration

```bash
sudo -u casescope python3 /opt/casescope/migrations/add_hostname_tracking_fields.py
```

**Expected Output:**
```
Starting migration: Adding hostname tracking fields
Adding column 'archive_type'...
✓ Added column 'archive_type'
Adding column 'source_system_method'...
✓ Added column 'source_system_method'
...
✓ Migration completed successfully
Updating existing records with default values...
✓ Updated 145 existing records
============================================================
Migration Summary:
============================================================
Total files: 145
Files needing review: 23
⚠️  23 file(s) flagged for hostname review
Visit /case/<case_id>/review_hostnames to review and update
============================================================
✓ Migration complete!
```

### 2. Review Existing Files (Optional)

If you have existing files that need hostname review:
1. Navigate to `/case/<case_id>/review_hostnames`
2. Review flagged files
3. Update hostnames or mark as verified
4. System will re-index events with new hostnames

### 3. Restart Services

```bash
sudo systemctl restart casescope-new
sudo systemctl restart casescope-workers
```

### 4. Test Upload

1. Go to case upload page
2. Upload a CyLR archive (e.g., `ATN62319.zip`)
3. Observe archive type detection
4. Verify hostname extraction
5. Check OpenSearch events for `source_system` field

---

## User Workflow

### For Analysts

**Upload:**
1. Visit case upload page
2. See CyLR recommendation
3. Select/drag files
4. For ZIP files:
   - Review auto-detected archive type
   - Adjust if needed
   - Specify hostname if desired (optional)
5. Click Upload

**Review (if prompted):**
1. After processing, check for review notification
2. Visit hostname review page
3. Review suggested hostnames
4. Update or verify
5. Done

### For Investigators

**IOC Hunting:**
```python
# Find all machines with IOC
results = search_events(
    query="malware.exe",
    agg_field="source_system"
)

# Returns:
# - LAPTOP-01: 15 hits
# - LAPTOP-02: 3 hits
# - SERVER-DC: 7 hits
```

**Machine Timeline:**
```python
# Get all activity from specific machine
events = search_events(
    filter={"source_system": "WORKSTATION-05"},
    sort="@timestamp"
)
```

---

## File Structure

### Modified Files
```
app/
├── models.py                          # Added 6 new fields
├── opensearch_indexer.py              # Added source_system support
├── tasks/task_process_file_v2.py      # Enhanced extraction logic
├── routes/case.py                     # Added review routes
└── utils/
    └── archive_detection.py           # NEW - Detection utilities

templates/case/
├── upload.html                        # Added CyLR recommendation + archive selection
└── review_hostnames.html              # NEW - Review page

migrations/
└── add_hostname_tracking_fields.py    # NEW - Database migration
```

### New Utilities
- `extract_hostname_from_filename()` - Parse hostname from filenames
- `detect_archive_type()` - Inspect ZIP structure
- `validate_hostname()` - Validate hostname format

---

## Configuration Options

### Archive Type Behavior

**Single-Host:**
- One hostname for entire collection
- Fallback chain: EVTX → LNK → filename → manual
- Best for: CyLR, KAPE, forensic images

**Multi-Host:**
- Hostname extracted per file
- No fallback to archive name
- Best for: EDR exports, log aggregations

**Unknown:**
- Attempts extraction, marks uncertain
- Useful for: Mixed collections, unknown sources

### Confidence Levels

| Level | Meaning | Source | Review Needed |
|-------|---------|--------|---------------|
| **High** | Extracted from artifacts or user-specified | EVTX, LNK, Manual | No |
| **Medium** | Fallback to filename | ZIP filename | Yes (recommended) |
| **Low** | Generic or failed extraction | Generic filename, None | Yes (required) |
| **Pending** | Awaiting artifact extraction | Initial upload | Auto-upgraded |

---

## Troubleshooting

### Issue: "Files still show 'Unknown' hostname"

**Solution:**
1. Check if migration ran: `SELECT source_system_confidence FROM case_file LIMIT 1;`
2. Re-run migration if fields missing
3. Visit review page to update

### Issue: "Archive type not detected correctly"

**Possible Causes:**
- Non-standard ZIP structure
- Mixed artifact types
- Insufficient EVTX files

**Solution:**
- Manually override archive type during upload
- Use "Unknown/Mixed" and specify hostname manually

### Issue: "Hostname mismatch between files"

**Expected Behavior:**
- LNK files may reference different machines (normal)
- System tracks both collection source AND artifact machine

**Fields:**
- `source_system` = where collected (file-level)
- `machine_id` = machine referenced in LNK (event-level)

### Issue: "Re-indexing failed after hostname update"

**Check:**
1. OpenSearch connection: `curl localhost:9200/_cluster/health`
2. Index exists: Check `target_index` field
3. Events exist: Query `source_file` field

**Recovery:**
- Database is already updated
- Re-index manually or re-upload file

---

## Best Practices

### For Data Collection

1. **Use CyLR** - Provides best hostname detection
2. **Name archives with hostname** - e.g., `HOSTNAME_collection.zip`
3. **Include EVTX logs** - Ensures reliable hostname extraction
4. **Organize multi-host exports** - Use hostname subdirectories

### For Upload

1. **Review auto-detection** - Verify archive type is correct
2. **Specify if uncertain** - Better to manually specify than guess
3. **Use bulk verify** - For trusted collections, verify all at once
4. **Review low-confidence** - Always review files flagged for review

### For Analysis

1. **Trust source_system** - It's the most reliable field
2. **Check machine_id for LNK** - May reveal lateral movement
3. **Use aggregations** - Find all affected systems quickly
4. **Filter by confidence** - Focus on high-confidence data first

---

## Security & Privacy

- Hostnames are indexed as keywords (not analyzed)
- User actions logged (who updated what hostname)
- Re-indexing preserves data integrity
- Rollback available if needed

---

## Future Enhancements

Potential improvements:
1. Machine nickname aliases (map technical names to friendly names)
2. Hostname normalization (HOSTNAME vs hostname.domain.com)
3. Bulk hostname update (update multiple files at once)
4. Import hostname mapping from CSV
5. Auto-detection from Registry hives
6. Integration with Active Directory for validation

---

## Support

**Questions or Issues:**
- Check logs: `/var/log/casescope/app.log`
- Review migration output
- Visit review page for diagnostic info
- Validate OpenSearch queries directly

**Rollback Migration (if needed):**
```bash
sudo -u casescope python3 /opt/casescope/migrations/add_hostname_tracking_fields.py --rollback
```

---

## Summary

✅ **Database** - 6 new tracking fields added  
✅ **OpenSearch** - `source_system` field in all events  
✅ **Upload UI** - CyLR recommendation + archive selection  
✅ **Detection** - Auto-detect archive types and hostnames  
✅ **Extraction** - Two-phase refinement (upload → processing)  
✅ **Review** - Post-processing review page for uncertain cases  
✅ **Re-indexing** - Update existing events with corrected hostnames  
✅ **Migration** - Database migration with rollback support  

**Result:** 100% reliable source system tracking for all artifacts, enabling comprehensive IOC hunting and machine-based analysis.

