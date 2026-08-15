# Ingest Fence Contract

Status: LOCKED for Phase 0B. This does not implement the fence.

## Model

The future model is fail-closed shared/exclusive admission control.

Normal writer:

```text
acquire shared admission lease
↓
INSERT
↓
release
```

Administrative destructive operation:

```text
prevent new shared admissions
↓
wait active shared writers = 0
↓
acquire exclusive fence
↓
recount
↓
destructive operation
↓
recount
↓
release
```

## Current Baseline

- `utils.clickhouse.destructive_event_rewrite_guard()` uses Redis when available.
- It yields unlocked when Redis is unavailable unless `require_lock=True`.
- `delete_case_events` currently uses the default fail-open behavior.
- `delete_file_events`, `run_events_update`, and normal inserts do not use a shared writer lease.

## Fail-Closed Rule

Redis unavailable + correctness depends on fence = FAIL CLOSED.

No default bypass is permitted for:

- direct inserts after the shared lease is required;
- case/file destructive deletes;
- dedup rewrites;
- schema/shadow table swaps;
- Buffer removal transition operations;
- broad `ALTER UPDATE` overlay/state rewrites;
- partition purge validation.

## Lease Semantics

- Shared lease is scoped to writer process/task, operation, case ID when available, source ref when available, and token.
- Exclusive fence is global to the `events` physical table unless a future version proves partition-scoped correctness.
- Lease TTL must be renewed by heartbeat before expiry.
- Heartbeat failure means the holder must stop before any further correctness-sensitive operation.
- Writer crash is recovered by TTL expiry plus audit/reconciler checks.
- Admin crash releases by TTL expiry, but any in-progress destructive operation requires post-crash recount/reconcile before retry.
- Stale lease cleanup requires token comparison; a process may only release its own lease.
- Nested calls reuse the caller's held lease/fence only when the nested scope is equal or narrower and carries the same token.
- Timeout waiting for drain fails closed and does not run the destructive operation.
- Cancellation releases held lease/fence if the process still owns it.
- Process termination relies on TTL expiry and later reconciliation.
- Multiple administrators contend for one exclusive fence; only one can hold it.

## Destructive Operations Requiring Fence

From Phase 0A write inventory:

- `utils.clickhouse.delete_case_events`
- `utils.clickhouse.delete_file_events`
- `utils.clickhouse.run_events_update` when correctness-sensitive or broad
- `utils.event_deduplication` duplicate `ALTER DELETE`
- `tasks.celery_tasks.case_indexing_complete_task` Buffer flush/OPTIMIZE transition work
- `migrations/add_evidence_record_identity.py` shadow table/swap paths
- `utils.case_deletion` coordinated case deletion
- administrative reset utilities such as `bin/clear_cases.py` and `bin/archive_then_reset.py`

## Tests

- Redis unavailable refuses correctness-sensitive operation.
- Shared writer lease renews and releases by token.
- Writer crash leaves stale lease that expires and is reconciled.
- Exclusive acquisition prevents new shared writers.
- Exclusive waits for active shared writers to drain.
- Timeout/cancellation does not execute destructive work.
- Nested shared operation does not double-count active writers.
- Two admins cannot hold exclusive fence simultaneously.

## Explicit Open Items

- OPEN — ADDITIONAL MEASUREMENT REQUIRED: drain timing and contention behavior during Phase 1.4a implementation.
- NOT APPLICABLE: Phase 0B does not change `utils.clickhouse` behavior.
