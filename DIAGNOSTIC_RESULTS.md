# Re-SIGMA Diagnostic Results

## Test Results Summary

### ✅ PASS: Module Structure
- `coordinator_resigma.py` imports successfully
- Task is registered in Celery (`coordinator_resigma.resigma_files_task`)
- Task callable and properly configured
- **Same configuration as reindex task**

### ✅ PASS: Task Registration  
- Both `resigma_files_task` and `reindex_files_task` registered
- Same Celery app instance
- Same task class type
- Task signatures serialize identically

### ❌ FAIL: Task Execution via .delay()

**Reindex (.delay()):**
```
PENDING → SUCCESS (3 seconds)
✓ Worker picks up task
✓ Completes successfully
```

**Resigma (.delay()):**
```
PENDING → PENDING → PENDING (forever)
✗ Task never picked up by worker
✗ Stays in PENDING state indefinitely
```

### Key Findings

1. **Queue Behavior:**
   - Task appears to be sent to Redis (queue length changes)
   - But task metadata never created
   - Worker never logs receiving the task

2. **Direct Function Call:**
   - `resigma_files(15, None)` works perfectly when called directly
   - Only fails when dispatched via Celery `.delay()`

3. **Identical Configuration:**
   - Both tasks use same decorator: `@celery_app.task(bind=True, name=...)`
   - Both have same imports
   - Both serialize to same message format
   - Both registered in same Celery app

## Hypothesis

The task is being **dispatched** but something about how `coordinator_resigma` is loaded/imported prevents the worker from **receiving/executing** it.

Possible causes:
1. Import order in `celery_app.py` (resigma loaded after reindex)
2. Module caching issue in worker processes
3. Circular import creates inconsistent state
4. Worker has stale version of module

## Next Steps

1. Check import order in celery_app.py
2. Verify worker has latest code
3. Try swapping import order
4. Check for any hidden differences in module structure

