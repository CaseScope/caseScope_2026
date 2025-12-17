# Re-SIGMA Celery Deadlock Issue

## Summary
Re-SIGMA coordinator (`coordinator_resigma.py`) **has NEVER worked via Celery `.delay()`** despite having identical import patterns to `coordinator_reindex.py` which works perfectly.

## Evidence

### 1. coordinator_resigma Was Never Wired Until Today
- **Created:** 2 days ago (commit 7469b0c)
- **Originally:** UI called `tasks.bulk_rechainsaw` (old task)
- **Today:** We wired it to `coordinator_resigma.resigma_files_task` (commit a45f6c4)
- **Result:** NEVER successfully ran via Celery

### 2. Identical Import Patterns
Both coordinators use the EXACT same imports:
```python
import time
from main import app, db
from models import CaseFile
```

### 3. What Works vs. What Doesn't

#### ✅ WORKS:
- `coordinator_reindex.reindex_files_task.delay()` - runs successfully
- `resigma_files()` called directly (not via Celery) - runs successfully  
- Manual Python script simulating Celery import order - runs successfully

#### ❌ DOESN'T WORK:
- `coordinator_resigma.resigma_files_task.delay()` - task wrapper starts, calls function, hangs on import

### 4. Symptoms
```
[RESIGMA_COORDINATOR_TASK] Starting for case 15...
[RESIGMA_COORDINATOR_TASK] About to call resigma_files()...
<HANGS FOREVER - NO ERROR, NO LOG>
```

The task wrapper logs show it's calling `resigma_files()` but the function never logs anything. The import `from main import app, db` appears to deadlock ONLY when called via Celery.

## Attempted Fixes (All Failed)

1. ❌ **Module-level imports** - Broke Flask startup (circular import)
2. ❌ **sys.modules check** - `main` not in sys.modules in Celery worker
3. ❌ **Verbose logging** - Confirmed hang is on `from main import app, db`
4. ❌ **Remove all logging** - Still hangs
5. ❌ **Match reindex wrapper exactly** - Still hangs
6. ❌ **Add progress_tracker import** - Still hangs
7. ❌ **Clean restarts** - Still hangs

## The Mystery

**Why does coordinator_reindex work but coordinator_resigma doesn't when they have identical imports?**

Possible causes:
1. Import order in `celery_app.py` (resigma loaded after reindex)
2. Circular dependency triggered differently for each module
3. Celery worker process forking issue
4. Hidden state from today's multiple restarts

## Next Steps

1. Copy ENTIRE `coordinator_reindex.py` to `coordinator_resigma.py` 
2. Only change the logic (not structure/imports)
3. Test if the copied version works
4. If yes: Find the subtle difference
5. If no: There's a systemic Celery configuration issue

## Files to Compare
- `/opt/casescope/app/coordinator_reindex.py` (WORKING)
- `/opt/casescope/app/coordinator_resigma.py` (BROKEN)
- `/opt/casescope/app/celery_app.py` (imports both)

