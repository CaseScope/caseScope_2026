# File Indexing Pipeline - Technical Reference

Complete documentation for the file indexing and reindex operations, covering initial uploads and full reindex procedures.

---

## Overview

The File Indexing Pipeline is the core data ingestion system that processes evidence files (EVTX, CSV, JSON, IIS logs) and populates both OpenSearch (event storage) and PostgreSQL (metadata/statistics). The pipeline ensures events are properly classified as `new` or `noise` before downstream processing (SIGMA detection, IOC hunting).

### Key Concepts

| Term | Description |
|------|-------------|
| **Initial Index** | Processing a newly uploaded file for the first time |
| **Re-Index** | Clearing ALL data and reprocessing an already-indexed file (fresh start) |
| **event_status** | Field in OpenSearch: 'new', 'noise', 'hunted', or 'confirmed' |
| **Known Good** | Detection system that marks RMM/EDR/Remote tool events as 'noise' |
| **Known Noise** | Detection system that marks system noise (routine processes) as 'noise' |
| **EventStatus Table** | PostgreSQL table tracking event statuses for dashboard statistics |
| **Fresh Start** | Complete data wipe + rebuild (the core goal of reindex operations) |

---

## Pipeline Stages

### Stage 1: File Conversion & Parsing
- EVTX files: Converted to JSONL using `evtx_dump`
- CSV files: Parsed row-by-row into event dictionaries
- IIS logs: Parsed using W3C Extended Log Format parser
- JSON/NDJSON: Parsed line-by-line as events

### Stage 2: Event Processing & Indexing
**File:** `app/file_processing.py` → `index_file()` (line 669)

For each event:
1. **Normalization**: Standardize timestamp, computer name, event_id
2. **search_blob Generation**: Flatten event into searchable text field
3. **Known Good Detection**: Check RMM/Remote/EDR patterns → sets `event_status='noise'`
4. **Known Noise Detection**: Check system noise patterns → sets `event_status='noise'`
5. **Default Status**: If no noise match, sets `event_status='new'`
6. **Track Noise IDs**: Collect event IDs marked as 'noise' for database sync
7. **Bulk Index**: Index to OpenSearch in batches of 1000

**Post-Indexing:**
- Sync `noise_event_ids` list to PostgreSQL `EventStatus` table
- Update `CaseFile` record with event counts and indexing status

### Stage 3: SIGMA Detection (EVTX only)
**File:** `app/file_processing.py` → `chainsaw_file()` (line 1422)

- Run Chainsaw CLI against raw EVTX file
- Parse CSV detections
- Create `SigmaViolation` database records
- Update OpenSearch events with `has_sigma` flags

### Stage 4: IOC Hunting
**File:** `app/file_processing.py` → `hunt_iocs()` (line 1625)

- Query OpenSearch for events **excluding `event_status='noise'`**
- Search for IOC patterns (IP, domain, hash, filename)
- Create `IOCMatch` database records
- Update OpenSearch events with `has_ioc` flags

**CRITICAL:** IOC hunting skips noise events by design, ensuring Known Good/Noise detection happens FIRST.

---

## Initial Index vs Re-Index

### Initial Index (New File Upload)

**Trigger:** User uploads a new file via web UI or Splunk integration

**Process:**
```
1. Upload → Duplicate Check (by hash + filename)
2. Index File (Stage 2):
   - Parse events
   - Apply Known Good detection (sets event_status='noise')
   - Apply Known Noise detection (sets event_status='noise')
   - Track noise_event_ids during indexing
   - Bulk index to OpenSearch
   - Sync noise_event_ids to database
3. SIGMA (Stage 3) - EVTX only
4. IOC Hunt (Stage 4) - Excludes event_status='noise'
```

**Result:** Events in OpenSearch + metadata in PostgreSQL, properly classified as 'new' or 'noise'

### Re-Index (Clean Slate Rebuild)

**Trigger:** User clicks "Re-Index" button (bulk/select/single file)

**Process:**
```
1. CLEAR PHASE (bulk_operations.py):
   ✓ Delete OpenSearch events (or entire index if >95% files)
   ✓ Delete SIGMA violations (database)
   ✓ Delete IOC matches (database)
   ✓ Delete timeline tags (database)
   ✓ Delete EventStatus records (database) ← v1.46.0
   ✓ Reset file metadata (database)

2. REBUILD PHASE:
   - Same as Initial Index (steps 2-4 above)
   - Treated as brand new file
   - All detection rules re-applied
```

**Result:** TRUE fresh start - old statuses cleared, new ones created

---

## Re-Index Clearing Logic

### Function: `clear_event_statuses()`
**File:** `app/bulk_operations.py` (line 327)

Clears `EventStatus` records before reindex to ensure fresh start.

```python
def clear_event_statuses(db, scope: str, case_id: int = None, file_ids: list = None):
    """
    Clear EventStatus records for true fresh start.
    
    Scopes:
    - 'case': Clear all EventStatus for entire case
    - 'file': Clear EventStatus for specific file IDs (queries OpenSearch for event IDs)
    - 'global': Clear all EventStatus across all cases
    """
```

### Case-Level Reindex
**Route:** `/case/<case_id>/bulk_reindex`
**File:** `app/main.py` (line 4776)

Clears:
- Entire OpenSearch index (if >95% files, otherwise per-file delete_by_query)
- All SIGMA violations for case
- All IOC matches for case
- All timeline tags for case
- All EventStatus records for case ← **v1.46.0 NEW**

### File-Level Reindex
**Route:** `/case/<case_id>/bulk_reindex_selected`
**File:** `app/routes/files.py` (line 878)

Clears:
- OpenSearch events for selected files (delete_by_query by file_id)
- SIGMA violations for selected files
- IOC matches for selected files
- EventStatus records for selected files ← **v1.46.0 NEW**
  - Queries OpenSearch to get event IDs for each file
  - Deletes matching EventStatus records from database

### Global Reindex
**Routes:**
- `/files/global/bulk_reindex` (all files)
- `/files/global/bulk_reindex_selected` (selected files)

**File:** `app/routes/files.py` (lines 1804, 2082)

Same as above but across multiple cases.

---

## Database Sync Optimization (v1.46.0)

### Old Approach (v1.45.0 and earlier)
**Problem:** After bulk indexing, system queried OpenSearch to find noise events

```python
# Query OpenSearch (SLOW for large files)
noise_query = {"query": {"term": {"event_status": "noise"}}}
response = opensearch_client.search(index, body=noise_query)
noise_ids = [hit['_id'] for hit in response['hits']['hits']]
bulk_set_status(case_id, noise_ids, STATUS_NOISE)
```

**Issues:**
- Extra OpenSearch query after indexing
- Performance overhead for large files
- Potential scroll/pagination issues

### New Approach (v1.46.0)
**Solution:** Track noise event IDs DURING indexing, sync once at end

```python
# Initialize tracker
noise_event_ids = []

# During event processing loop
for event in events:
    event = apply_auto_hide(event, exclusions)        # Known Good
    event = apply_auto_hide_noise(event)              # Known Noise
    
    # Track noise events
    if event.get('event_status') == 'noise':
        doc_id = generate_event_document_id(case_id, event)
        noise_event_ids.append(doc_id)
    
    bulk_index(event)

# After indexing complete
if noise_event_ids:
    bulk_set_status(case_id, noise_event_ids, STATUS_NOISE)
```

**Benefits:**
- No extra OpenSearch query
- Faster indexing (especially for large files)
- Simpler code
- Guaranteed consistency

---

## Status Field Behavior

### OpenSearch Document Fields

| Field | Values | Purpose |
|-------|--------|---------|
| `event_status` | 'new', 'noise', 'hunted', 'confirmed' | Primary status for filtering |
| `status_reason` | 'auto_known_good', 'noise_auto_index', etc. | Tracking why status was set |

### PostgreSQL EventStatus Table

| Column | Type | Purpose |
|--------|------|---------|
| `case_id` | int | Case reference |
| `event_id` | string | OpenSearch document ID |
| `status` | string | 'new', 'noise', 'hunted', 'confirmed' |
| `changed_by` | int | User ID (NULL for auto-set) |
| `changed_at` | datetime | When status changed |
| `notes` | string | Reason (e.g., "Auto-set during indexing") |

### When Database Sync Happens

| Operation | OpenSearch | Database |
|-----------|------------|----------|
| **Initial Index** | `event_status` set during indexing | Synced after bulk indexing |
| **Re-Index** | Old records deleted, new `event_status` set | Old records deleted, new synced |
| **Hide Known Good** (manual) | `event_status='noise'` updated | `status='noise'` created/updated |
| **Hide Noise** (manual) | `event_status='noise'` updated | `status='noise'` created/updated |

---

## Code Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     INITIAL INDEX                            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ↓
                    ┌───────────────┐
                    │ Upload File   │
                    └───────────────┘
                            │
                            ↓
                ┌───────────────────────┐
                │ duplicate_check()     │
                │ (hash + filename)     │
                └───────────────────────┘
                            │
                            ↓
                ┌───────────────────────────────────────┐
                │ index_file()                          │
                │ ┌─────────────────────────────────┐   │
                │ │ Parse events                    │   │
                │ │ ↓                               │   │
                │ │ normalize_event()               │   │
                │ │ ↓                               │   │
                │ │ apply_auto_hide()               │   │
                │ │   (Known Good → event_status)   │   │
                │ │ ↓                               │   │
                │ │ apply_auto_hide_noise()         │   │
                │ │   (Known Noise → event_status)  │   │
                │ │ ↓                               │   │
                │ │ Track noise_event_ids           │   │
                │ │ ↓                               │   │
                │ │ Bulk index to OpenSearch        │   │
                │ │ ↓                               │   │
                │ │ Sync noise_event_ids to DB      │   │
                │ └─────────────────────────────────┘   │
                └───────────────────────────────────────┘
                            │
                            ↓
                ┌───────────────────────┐
                │ chainsaw_file()       │
                │ (EVTX only)           │
                └───────────────────────┘
                            │
                            ↓
                ┌───────────────────────────┐
                │ hunt_iocs()               │
                │ (excludes noise events)   │
                └───────────────────────────┘


┌─────────────────────────────────────────────────────────────┐
│                        RE-INDEX                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ↓
        ┌───────────────────────────────────────┐
        │ CLEAR PHASE (bulk_operations.py)     │
        │ ┌─────────────────────────────────┐   │
        │ │ clear_opensearch_events()       │   │
        │ │   (delete index or per-file)    │   │
        │ │ ↓                               │   │
        │ │ clear_sigma_violations()        │   │
        │ │   (database)                    │   │
        │ │ ↓                               │   │
        │ │ clear_ioc_matches()             │   │
        │ │   (database)                    │   │
        │ │ ↓                               │   │
        │ │ clear_timeline_tags()           │   │
        │ │   (database, case-level only)   │   │
        │ │ ↓                               │   │
        │ │ clear_event_statuses() ← NEW    │   │
        │ │   (database)                    │   │
        │ │ ↓                               │   │
        │ │ reset_file_metadata()           │   │
        │ │   (database)                    │   │
        │ └─────────────────────────────────┘   │
        └───────────────────────────────────────┘
                            │
                            ↓
        ┌───────────────────────────────────────┐
        │ REBUILD PHASE                         │
        │ (Same as Initial Index above)         │
        │ - index_file()                        │
        │ - chainsaw_file()                     │
        │ - hunt_iocs()                         │
        └───────────────────────────────────────┘
```

---

## Files and Functions

### 1. `app/file_processing.py` (Core Pipeline)

| Function | Lines | Purpose |
|----------|-------|---------|
| `index_file()` | 669-1415 | **Main indexing function** - processes file, indexes to OpenSearch, syncs to DB |
| `apply_auto_hide()` | 36-88 | Known Good detection → sets `event_status='noise'` |
| `apply_auto_hide_noise()` | 95-134 | Known Noise detection → sets `event_status='noise'` |
| `chainsaw_file()` | 1422-1623 | SIGMA detection (EVTX only) |
| `hunt_iocs()` | 1625-1850 | IOC hunting (excludes noise events) |

### 2. `app/bulk_operations.py` (Clear Operations)

| Function | Lines | Purpose |
|----------|-------|---------|
| `clear_event_statuses()` | 327-398 | **NEW v1.46.0** - Clear EventStatus records for fresh start |
| `clear_opensearch_events()` | 78-175 | Delete events from OpenSearch (index delete or per-file) |
| `clear_sigma_violations()` | 400-465 | Delete SIGMA violations from database |
| `clear_ioc_matches()` | 468-502 | Delete IOC matches from database |
| `clear_timeline_tags()` | 505-525 | Delete timeline tags from database |

### 3. `app/main.py` (Case-Level Routes)

| Route | Lines | Purpose |
|-------|-------|---------|
| `/case/<id>/bulk_reindex` | 4776-4907 | Re-index all files in case |

### 4. `app/routes/files.py` (File-Level Routes)

| Route | Lines | Purpose |
|-------|-------|---------|
| `/case/<id>/bulk_reindex_selected` | 878-1030 | Re-index selected files in case |
| `/files/global/bulk_reindex` | 1804-1918 | Re-index all files globally |
| `/files/global/bulk_reindex_selected` | 2082-2213 | Re-index selected files globally |

### 5. `app/tasks.py` (Background Processing)

| Function | Lines | Purpose |
|----------|-------|---------|
| `process_file()` | 60-500 | **Celery task** - orchestrates all 4 pipeline stages |

---

## Integration Points

### 1. events_known_good.py
- Called during indexing via `apply_auto_hide()`
- Checks RMM/Remote/EDR patterns
- Sets `event_status='noise'` and `status_reason='auto_known_good'`

### 2. events_known_noise.py
- Called during indexing via `apply_auto_hide_noise()`
- Checks system noise patterns (processes, commands)
- Sets `event_status='noise'` and `status_reason='noise_auto_index'`

### 3. event_status.py
- `bulk_set_status()` - Creates/updates EventStatus records in database
- Called after indexing completes to sync noise events

### 4. event_normalization.py
- `normalize_event()` - Standardizes timestamp, computer name, event_id
- Creates `search_blob` field for pattern matching

---

## Performance Considerations

### Indexing Speed
- **Bulk operations:** 1000 events per batch to OpenSearch
- **Parallel workers:** 8 Celery workers process multiple files simultaneously
- **Deduplication:** Optional deterministic document IDs prevent duplicate events

### Database Sync Optimization (v1.46.0)
- **Old:** Query OpenSearch after indexing (~500ms for 10K events)
- **New:** Track IDs during indexing (~0ms overhead)
- **Savings:** ~30-50% faster for large files

### Index Deletion Threshold
- If reindexing ≥95% of files in a case → delete entire index
- Benefits: Fresh field mappings, no conflicts, faster than per-file delete
- If <95% → per-file `delete_by_query` (preserves other files' data)

---

## Error Handling

### Indexing Failures
- **0 events indexed:** Check OpenSearch field limit (50K default)
- **Mapping conflicts:** Delete index and re-create (happens during bulk reindex)
- **Timeout errors:** Increase Celery task timeout or reduce batch size

### Database Sync Failures
- **EventStatus sync fails:** Logged as warning, doesn't fail indexing
- **Impact:** Dashboard counts may be inaccurate until manual Hide Known Good/Noise run
- **Recovery:** Run "Hide Known Good" + "Hide Noise" buttons to resync

---

## Version History

### v1.46.0 (Current)
- ✅ Added `clear_event_statuses()` to reindex clear phase
- ✅ Optimized database sync (track IDs during indexing, no post-query)
- ✅ Default `event_status='new'` for all events
- ✅ TRUE fresh start on reindex (old statuses cleared)

### v1.45.0
- Added Known Good/Noise detection during indexing
- Database sync via OpenSearch query (slower)

### v1.27.16
- Fixed bulk reindex index deletion threshold bug
- Changed to `len(files)` instead of checking `opensearch_key`

### v1.27.15
- Added full index deletion for true fresh start (>95% threshold)
- Fixed field limit issues from old indices

---

## Testing Reindex

### Verify Fresh Start
```sql
-- Before reindex
SELECT status, COUNT(*) FROM event_status WHERE case_id = 15 GROUP BY status;
-- Example: 100 noise, 50 hunted

-- Trigger reindex (bulk/select/single)

-- After reindex
SELECT status, COUNT(*) FROM event_status WHERE case_id = 15 GROUP BY status;
-- Example: 120 noise, 0 hunted (fresh counts, hunted cleared)
```

### Check OpenSearch
```bash
# Query for event statuses
curl -X GET "localhost:9200/case_15/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "status_counts": {
      "terms": { "field": "event_status" }
    }
  }
}
'
```

### Monitor Logs
```bash
journalctl -u casescope -f | grep -E "CLEAR|INDEX FILE|Syncing event statuses"
```

---

## Troubleshooting

### Issue: Reindex doesn't clear old statuses
**Symptom:** After reindex, still see old 'hunted' events in database  
**Cause:** `clear_event_statuses()` not called or failed  
**Fix:** Check logs for "Cleared X EventStatus records" - if missing, update route code

### Issue: Dashboard counts don't match OpenSearch
**Symptom:** OpenSearch has 1000 noise events, database has 500  
**Cause:** Database sync failed during indexing  
**Fix:** Run "Hide Known Good" + "Hide Noise" buttons to force resync

### Issue: IOC hunt finds noise events
**Symptom:** IOC matches created for RMM tool events  
**Cause:** Known Good detection not running before IOC hunt  
**Fix:** Check `apply_auto_hide()` is called in `index_file()` before bulk indexing

---

## See Also

- **Known Good Detection:** `site_documentation/EVENTS_KNOWN_GOOD.md`
- **Known Noise Detection:** `site_documentation/EVENTS_KNOWN_NOISE.md`
- **Event Status System:** `site_documentation/EVENT_STATUS.md`
- **SIGMA Detection:** `site_documentation/SIGMA_DETECTION.md`
- **IOC Hunting:** `site_documentation/IOC_HUNTING.md`

