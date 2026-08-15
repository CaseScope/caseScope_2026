# Phase 1 Step 2 Report

Status: STEP2_ACCEPTED. FENCE_PASS. Full Phase 1 is not complete.

## 1. Starting State

- Remote main: `8c4c1dd3b1651df42dc08c39f06250d296864c57`
- Local HEAD: `8c4c1dd3b1651df42dc08c39f06250d296864c57`
- Version: `4.18.5`
- Remote main has not moved since the locked baseline.
- Phase 0A, Phase 0B, and Phase 1 Step 1 are ACCEPTED.
- Pre-existing/unowned worktree files were preserved. No commit. No push.
- Production ClickHouse `casescope.events_buffer` was not dropped in this pass.

## 2. Accepted Step 1 State

Approved corpus `/opt/casescope-benchmark/phase0a_evtx/`: 8 EVTX, 77,103,104 bytes, 110,742 parsed events. SHA256s re-verified on every disposable ingest; all 8 matched.

| | wall | events/sec | MB/sec | RSS |
|---|---:|---:|---:|---:|
| Phase 0 | 332.884 s | 332.674 | 0.221 | 237.36 MB |
| Step 1 | 148.408 s | 746.198 | 0.495 | 226.29 MB |

Step 1 semantic: exact event/ERK parity; contracted CMMC_CUI alias parity exact (1,152). ERK set SHA256 `6ad87fe76520d18bde4cfb421bbd4fce0b410c00d60abaf642769aa303515b7c`.

Critical Buffer fact from Step 1 remains: `OPTIMIZE TABLE events FINAL` does not drain `events_buffer`. Drain is `OPTIMIZE TABLE events_buffer`.

## 3. Writer Inventory

From the accepted Phase 0A write inventory, every current production path that can INSERT or whose correctness assumes quiet writers:

| Path | Classification | Coverage |
|---|---|---|
| `parsers/registry.py::BatchProcessor.flush` | SHARED_WRITER | Shared ingest lease around `client.insert`. Default destination is now `events`. |
| `scripts/phase0a_ingest_benchmark.py` / parity harnesses | SHARED_WRITER | Same `process_file` → `BatchProcessor` path. Isolated fence prefix. |
| `scripts/phase0g_deployed_runtime.py` / `phase0g_scale_benchmark.py` direct `client.insert("events")` | ADMIN_RAW_EXCEPTION | Measurement harnesses, not production web/worker ingest. Not used by `casescope-web` / `casescope-workers`. |
| Operator `clickhouse-client` SQL | ADMIN_RAW_EXCEPTION | Outside application admission. Runbook/operator responsibility. |
| `network_logs` / `CLICKHOUSE_USE_BUFFER` | NOT_APPLICABLE | Different table. Unchanged. |

No silent omissions on the events INSERT path. Production ingest cannot INSERT without shared admission.

## 4. Destructive Operation Inventory

| Path | Classification | Coverage |
|---|---|---|
| `utils/clickhouse.py::delete_file_events` | EXCLUSIVE_OPERATION | Entire probe+delete under `exclusive_ingest_fence('file_event_delete')`. |
| `utils/clickhouse.py::delete_case_events` | EXCLUSIVE_OPERATION | `destructive_event_rewrite_guard` → exclusive. `require_lock` ignored as a fail-open switch. |
| `utils/clickhouse.py::run_events_update` | EXCLUSIVE_OPERATION | Exclusive; nested reuse if caller already holds exclusive. |
| `utils/event_deduplication.py` | EXCLUSIVE_OPERATION | Guard default `rewrite_guard_behavior='error'`. Completion and manual dedup use `'error'`. |
| `tasks/celery_tasks.py::case_indexing_complete_task` | EXCLUSIVE_OPERATION | Exclusive around optional Buffer OPTIMIZE (if table exists) then nested exclusive dedup. |
| `utils/case_deletion.py::delete_case_permanently` | EXCLUSIVE_OPERATION | Exclusive around buffer flush-if-present, `delete_case_events`, overlay purge. |
| `bin/clear_cases.py` | EXCLUSIVE_OPERATION | Exclusive around Buffer flush-if-present and case event deletes. |
| `bin/archive_then_reset.py` auxiliary deletes | EXCLUSIVE_OPERATION | `destructive_event_rewrite_guard`; events themselves go through `delete_client_permanently`. Missing `events_buffer` counts as zero. |
| `migrations/remove_events_buffer.py` | EXCLUSIVE_OPERATION | Exclusive, drain, verify, DROP. Refuses production without `--apply-production`. Not wired to startup. |
| `migrations/add_evidence_record_identity.py` shadow/swap | EXCLUSIVE_OPERATION | Already used `destructive_event_rewrite_guard(require_lock=True)`; now fail-closed regardless. Buffer helpers remain MIGRATION_COMPATIBILITY. |
| Overlay IOC/MITRE/noise PostgreSQL or overlay-table writes that do not mutate `events` | NOT_APPLICABLE | No events-writer quiet assumption. Events summary `ALTER UPDATE` still goes through `run_events_update`. |
| `utils/event_mitre_state.py` `ALTER TABLE events_buffer ADD COLUMN` | MIGRATION_COMPATIBILITY | Skips if table missing (`existing` empty). |
| Qdrant / graph authority | NOT_APPLICABLE | Not changed. Graph support lifecycle tests still pass. |

Correctness-sensitive fail-open callers: **0**.

## 5. Fence Design Implementation

New module `utils/ingest_fence.py` implements INGEST_FENCE_CONTRACT exactly:

- Shared: acquire → INSERT → token-compared release. Refused when exclusive pending or held.
- Exclusive: set pending (blocks new shared) → drain active writers to 0 → acquire exclusive → operate → `assert_active` → release.
- Unique owner/token, TTL, heartbeat/renewal, crash via expiry, stale owner cannot release a new owner's lease.
- Nested reuse: exclusive covers nested exclusive/shared; shared cannot acquire exclusive (`IngestFenceConflict`).
- Timeout waiting for drain raises `IngestExclusiveTimeout` and does **not** run the destructive op.
- Redis/backend unavailable: shared must not INSERT (`IngestFenceUnavailable`); exclusive refuses to run.
- Exclusive is global to `events`.
- Backends: Redis Lua (production), `MemoryFenceBackend` (tests), `FailingFenceBackend` (outage tests). Disposable harnesses set `INGEST_FENCE_KEY_PREFIX=casescope:ingest_fence:disposable:<db>`.

`destructive_event_rewrite_guard` now wraps `exclusive_ingest_fence`. `require_lock` is retained only for call-site compatibility and is ignored as a fail-open switch.

Celery `parse_file_task` retries fence errors (`max_retries=10`) without marking the file failed.

## 6. Redis Failure Behavior

- Shared writer: no INSERT; fail/retry per task policy.
- Exclusive/destructive: refuse to run.
- Production Redis was **not** stopped. Tests use an in-process backend or isolated key prefix.
- No silent fallback to uncoordinated writes.

## 7. Drain / Crash / Lease Tests

`tests/test_ingest_fence.py` covers the required 18 cases plus extras (23 tests):

1. Shared writer acquires and inserts
2. Multiple shared writers coexist
3. Exclusive prevents new writers
4. Exclusive waits for existing writers to drain
5. Exclusive starts only after writer count is zero
6. Writer after exclusive begins is denied
7. Redis unavailable → shared fail (no INSERT)
8. Redis unavailable → destructive refused
9. Writer crash expires/cleans
10. Admin crash recovers
11. Stale owner cannot release new owner's lease
12. Heartbeat preserves a long operation
13. Lost exclusive ownership prevents continuation
14. Two administrators serialize
15. Timeout does not run destructive fallback
16. Cancellation releases owned state
17. Nested exclusive helper does not deadlock
18. No correctness-sensitive current caller uses fail-open

## 8. FENCE Verdict

**FENCE_PASS**

All normal event writers covered. All correctness-sensitive destructive operations classified. Redis outage is fail-closed. Drain/crash/stale lease proven. Fail-open correctness path count is 0.

Buffer removal was authorized only after this gate.

## 9. Buffer References Before

Step 1 accepted production runtime required `events_buffer`:

- `BatchProcessor` default destination `events_buffer`
- `migrate_clickhouse()` created Buffer on fresh install
- Completion `OPTIMIZE TABLE events_buffer` before dedup
- Alias scan preferred Buffer so just-inserted rows were visible
- File/case DELETE also mutated Buffer
- Buffer served as an accidental physical writer fence
- Identity migration recreate/fence helpers
- Admin reset scripts flushed Buffer before delete

## 10. Direct Insert Change

`BatchProcessor(..., use_buffer=False)` by default. Inserts go to `events` under shared admission.

- Insert mode unchanged (synchronous clickhouse-connect insert; no async inserts).
- Semantic payloads unchanged.
- Production batch size unchanged at 10,000.
- No ingest manifests/generations.
- Alias scan table is always `events`.
- Fresh `migrate_clickhouse()` does not create `events_buffer`; if it already exists it is left until the controlled migration.

## 11. Buffer Cutover Migration

`migrations/remove_events_buffer.py`:

acquire exclusive → writers=0 → `OPTIMIZE TABLE events_buffer` → pending=0 and buffer-visible==events → DROP → verify absent.

- Not invoked from application startup.
- Refuses database `casescope` unless `--apply-production`.
- **Not executed against production.**

Disposable ClickHouse `phase1_step2_cutover_20260814` (26.7.3.19):

- 50 Buffer-only rows, events=0
- Drain landed 50 rows in `events`, pending=0
- DROP succeeded
- Second run: `already_removed=true`
- Production client refused without the flag

## 12. Buffer References After

Production runtime required Buffer dependencies: **0**.

Remaining references:

| Location | Class |
|---|---|
| `docs/database_flow_phase0/*`, locked plan, Step 1 reports | HISTORICAL_DOC |
| `migrations/add_events_table.py` Buffer helpers; `add_evidence_record_identity.py`; `add_timezone_columns.py` try/except ALTER | MIGRATION_COMPATIBILITY |
| `migrations/remove_events_buffer.py` | MIGRATION_COMPATIBILITY (the cutover) |
| `utils/clickhouse.py` DELETE/probe on `events_buffer` if table exists | MIGRATION_COMPATIBILITY |
| `tasks/celery_tasks.py` OPTIMIZE if table exists else `not_required` | MIGRATION_COMPATIBILITY |
| `utils/case_deletion.py` / `bin/clear_cases.py` OPTIMIZE try/except | MIGRATION_COMPATIBILITY |
| `utils/privacy_aliases.py` `_ALIAS_SCAN_TABLES` still names Buffer but resolver returns `events` | MIGRATION_COMPATIBILITY |
| `utils/event_mitre_state.py` ADD COLUMN skipped if missing | MIGRATION_COMPATIBILITY |
| `bin/archive_then_reset.py` counts missing Buffer as 0 | MIGRATION_COMPATIBILITY |
| `tests/test_phase1_step2.py`, fence `use_buffer=True` outage case, delete-contract fakes | TEST_FIXTURE |
| `scripts/phase0a_ingest_benchmark.py` / parity drain-if-exists | TEST_FIXTURE |
| `scripts/phase0g_deployed_runtime.py` `_ensure_events_buffer_schema` | TEST_FIXTURE (measurement harness; do not run against production after cutover) |
| `bin/database_flow_baseline.py` optional census | TEST_FIXTURE |

No DEFECT remaining in production ingest/completion.

Identity migration can still recreate Buffer if that operator migration is re-run. That is a remaining compatibility risk, not a runtime ingest dependency.

## 13. Semantic Parity

Two independent Step 2 disposable ingests (`phase0a_ingest_20260814200500` and `phase0a_ingest_20260814203000`) dumped 110,742 rows each.

| Check | Result |
|---|---|
| Parsed row count | 110,742 = 110,742 |
| ERK set vs accepted Step 1 | exact, SHA256 `6ad87fe76520d18bde4cfb421bbd4fce0b410c00d60abaf642769aa303515b7c` |
| Deterministic field differences between Step 2 dumps | 0 |
| `raw_json` / `search_blob` / `extra_fields` | exact after canonical JSON parse |
| Contracted CMMC_CUI protected identities | 1,152 = Step 1 |
| Legacy dedup | 0 duplicates (same as Step 1) |
| Retry semantics | fence errors retry; parser-failure cleanup still `delete_file_events(wait=True)` |

Step 1 dump directories had been cleaned, so BASELINE vs Step 2 field compare used the accepted Step 1 ERK hash plus two independent Step 2 dumps. Direct insertion did not alter forensic semantics.

## 14. Tests

Focused suites only. No production-bound full unittest discovery. Production Redis was not stopped.

130 tests OK, including:

- `tests.test_ingest_fence` (23)
- `tests.test_phase1_step2` (13)
- `tests.test_phase1_step1`
- `tests.test_parser_retry_cleanup`
- `tests.test_clickhouse_delete_dedup_contracts`
- `tests.test_clickhouse_destructive_lock`
- `tests.test_ingest_metrics`
- `tests.test_privacy_fail_closed`
- `tests.test_graph_support_lifecycle`
- `test_parser_hardening` delete_file_events methods

Investigation Graph support lifecycle acceptance is preserved. Graph does not take the events ingest fence; file-delete helpers used by graph cleanup still fail closed.

## 15. Step 2 Benchmark

Same corpus. Official production-default run: disposable PG/CH `phase0a_ingest_20260814204500`, batch size 10,000, no Buffer.

| Metric | Step 2 official |
|---|---:|
| wall | 152.325 s |
| events/sec | 727.01 |
| MB/sec | 0.483 |
| peak RSS | 233.21 MB |
| CH insert wall | 5.439 s (16 calls to `events`) |
| after insert | 1 Compact + 4 Wide |
| after `OPTIMIZE TABLE events FINAL` (harness census only) | 1 Wide, 110,742 rows |
| completion Buffer OPTIMIZE | 0 ms (`events_buffer` absent) |
| shared admission | 9.088 ms |
| exclusive acquire (pre-parse DELETE + dedup) | 15.212 ms |

Investigation runs: 233.482 s (one 77.2 s Security insert that did not reproduce) and 196.734 s (colder EvtxECmd/Hayabusa). Fence overhead is not the cause. Direct `events` insert is visible (~5.4 s vs Step 1 Buffer 2.5 s).

## 16. Step 1 → Step 2 Delta

- wall: +3.917 s (+2.64%)
- throughput: 0.974×
- RSS: +6.92 MB
- CH insert: +2.948 s (expected Buffer → MergeTree wait)
- fence: +24.3 ms

Not a meaningful regression. Tiny fence overhead is expected. Direct-insert wait accounts for the insert delta. Production batch size was not changed.

## 17. Phase 0 → Step 2 Delta

- wall reduction: 180.559 s (54.24%)
- throughput: 2.185×
- RSS: −4.15 MB

Step 1's >=2× vs Phase 0 remains intact on the official Step 2 run.

## 18. Batch-Size Study

Disposable only. Production default remains 10,000. ERK SHA256 identical on every size.

| batch | wall s | events/sec | RSS MB | insert calls | insert ms | after-insert parts |
|---:|---:|---:|---:|---:|---:|---|
| 10,000 official | 152.325 | 727.01 | 233.21 | 16 | 5439 | 1 Compact + 4 Wide |
| 25,000 | 153.941 | 719.38 | 303.34 | 10 | 5232 | 3 Wide |
| 50,000 | 152.838 | 724.57 | 351.29 | 8 | 5134 | 2 Compact + 6 Wide |
| 100,000 | 153.634 | 720.82 | 396.48 | 7 | 4904 | 2 Compact + 5 Wide |

Future generation-aware batching contract recommendation: keep 10k until generations exist; 25k is the first candidate (fewer insert calls, similar wall, smaller RSS jump than 50k/100k). Do not apply now.

## 19. Remaining Risks

- Production `casescope.events_buffer` still exists until an operator runs `migrations/remove_events_buffer.py --apply-production`. This pass did not do that.
- Rollback of application code to Buffer-era ingest still works while Buffer exists. After DROP, rollback must recreate Buffer before Buffer-era writers can run.
- `migrations/add_evidence_record_identity.py` can recreate Buffer if that operator migration is re-run.
- `scripts/phase0g_deployed_runtime.py` still calls `_ensure_events_buffer_schema`; measurement only.
- Completion still OPTIMIZEs Buffer if the table exists; after production DROP this is `not_required`.
- First 10k run showed a non-reproducible 77 s ClickHouse insert stall. Treat as CH load, not fence.

## 20. Step 2 Verdict

**STEP2_ACCEPTED**

- FENCE_PASS
- semantic parity PASS
- production runtime Buffer dependency = 0
- disposable drain/removal PASS
- no unresolved Step 2-caused regression

This is not a full Phase 1 exit.

## 21. Remaining Phase 1 Work

Not implemented here:

- 1.5 IOC query-path changes
- 1.6 behavioral profiler rewrite
- 1.7 Hayabusa/EvtxECmd directory mode
- 1.8 typed-column promotion
- 1B progressive orchestration
- Phase 2+ async inserts, generations/manifests/LEK/event surfaces
- Qdrant changes
- graph authority changes
- production Buffer DROP
- production batch-size change

Durable artifacts: `phase1_step2_results.json`, `phase1_step2_after_benchmark.json`, `phase1_step2_parity_compare.json`, `phase1_step2_batch_size_study.json`.
