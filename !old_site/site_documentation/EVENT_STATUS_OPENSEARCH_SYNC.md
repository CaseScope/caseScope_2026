# Event Status OpenSearch Synchronization (v1.47.0)

## Problem

**Symptom:** Case Files dashboard showed 2,364 "hunted" events, but search page filters showed 0 events when filtering by "Hunted" status.

**Root Cause:**
- Event status changes (hunted, noise, confirmed) were only written to PostgreSQL `EventStatus` table
- OpenSearch documents were never updated with the `event_status` field
- Search page filters rely on OpenSearch fields for performance (can't do DB lookups on 19M events)
- This caused a disconnect between:
  - **Database counts** (used by Case Files dashboard) ✓ Correct
  - **OpenSearch filters** (used by search page) ✗ Broken

## Solution

Implemented **automatic synchronization** of event statuses from PostgreSQL to OpenSearch whenever statuses are changed.

### Changes Made

#### 1. Added OpenSearch Sync Functions (`app/event_status.py`)

```python
def sync_status_to_opensearch(case_id: int, event_id: str, status: str) -> bool:
    """Sync a single event's status to OpenSearch."""
    # Updates the event_status field in OpenSearch document
    
def bulk_sync_status_to_opensearch(case_id: int, event_ids: List[str], status: str) -> Dict:
    """Sync multiple events' statuses to OpenSearch using bulk API."""
    # Batches updates in groups of 5,000 for performance
```

#### 2. Updated Status Functions to Auto-Sync

**`set_status()`** - Single event status change:
- Added `sync_opensearch=True` parameter (default enabled)
- Automatically syncs to OpenSearch after database commit

**`bulk_set_status()`** - Bulk event status changes:
- Added `sync_opensearch=True` parameter (default enabled)
- Syncs all events to OpenSearch after database commit
- Returns sync results: `{'updated': X, 'created': Y, 'synced': Z, 'sync_failed': N}`

### Operations That Now Auto-Sync

All status-changing operations automatically sync to OpenSearch:

1. **Phase 3 AI Triage** - Marking events as "hunted"
2. **Hide Known Good** - Marking events as "noise"
3. **Hide Known Noise** - Marking events as "noise"
4. **Manual Status Changes** - Analyst marking events as "confirmed"
5. **Event Status API** - Any programmatic status changes

### Performance

- **Single event sync:** ~10-20ms per event
- **Bulk sync (941K events):** ~3 minutes (5,000 events/batch)
- **OpenSearch bulk API:** Uses `refresh=false` for performance (eventual consistency)

## Migration

### One-Time Sync for Existing Data

For cases with existing event statuses that weren't synced, run:

```bash
cd /opt/casescope
source venv/bin/activate
sudo -E venv/bin/python3 -c "
import sys
sys.path.insert(0, 'app')
from main import app, db
from models import EventStatus
from event_status import bulk_sync_status_to_opensearch

with app.app_context():
    case_id = 16  # Change to your case ID
    records = EventStatus.query.filter_by(case_id=case_id).all()
    statuses_by_type = {}
    for r in records:
        if r.status not in statuses_by_type:
            statuses_by_type[r.status] = []
        statuses_by_type[r.status].append(r.event_id)
    
    for status, event_ids in statuses_by_type.items():
        print(f'Syncing {len(event_ids):,} events with status {status}...')
        result = bulk_sync_status_to_opensearch(case_id, event_ids, status)
        print(f'Result: {result}')
"
```

## Verification

### Check OpenSearch Event Status Counts

```bash
# Count hunted events
curl -s "localhost:9200/case_16/_count" -H 'Content-Type: application/json' \
  -d'{"query":{"term":{"event_status.keyword":"hunted"}}}'

# Count noise events
curl -s "localhost:9200/case_16/_count" -H 'Content-Type: application/json' \
  -d'{"query":{"term":{"event_status.keyword":"noise"}}}'

# Get status breakdown
curl -s "localhost:9200/case_16/_search" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "status_breakdown": {
      "terms": {
        "field": "event_status.keyword",
        "missing": "null/missing",
        "size": 10
      }
    }
  }
}' | python3 -m json.tool
```

### Expected Results (Case 16 Example)

```json
{
  "aggregations": {
    "status_breakdown": {
      "buckets": [
        {"key": "null/missing", "doc_count": 16775204},  // New events
        {"key": "noise", "doc_count": 939342},           // Known-good/noise
        {"key": "hunted", "doc_count": 2364}             // Phase 3 tagged
      ]
    }
  }
}
```

## Technical Details

### Data Architecture

```
┌─────────────────────────────────────────────────┐
│ PostgreSQL EventStatus Table                    │
│ - Source of truth for event status              │
│ - Tracks who/when/why status changed            │
│ - Supports audit trail and notes                │
└─────────────────────────────────────────────────┘
                     ↓ Automatic Sync
┌─────────────────────────────────────────────────┐
│ OpenSearch event_status Field                   │
│ - Fast filtering in search (no DB lookups)      │
│ - Enables status checkboxes in search UI        │
│ - Allows aggregations for counts                │
└─────────────────────────────────────────────────┘
```

### Error Handling

- If OpenSearch sync fails, the database change still succeeds
- PostgreSQL is the source of truth
- Failed syncs are logged but don't block operations
- Re-running sync operations is safe (idempotent updates)

## Benefits

1. **Search filters now work** - Status checkboxes filter correctly
2. **Performance** - No database lookups during search (19M events)
3. **Consistency** - Database and OpenSearch stay in sync automatically
4. **Audit trail** - Database maintains full history, OpenSearch has current state
5. **Scalability** - Bulk operations handle 900K+ events efficiently

## Future Considerations

- Consider adding a background sync job to catch any missed updates
- Monitor OpenSearch sync failures in logs
- Consider adding a "Resync Status" button in admin panel for manual correction


