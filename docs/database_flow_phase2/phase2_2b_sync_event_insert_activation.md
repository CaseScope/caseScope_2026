# Phase 2.2B Synchronous Event-Insert Activation Result

Implementation/activation record for the accepted Phase 2.2A decision.
Does not rewrite the 2.2A measurement artifact. Does not start Phase 2.3.

**Tranche verdict: PHASE2_2B_PASS**

Phase 2.2 state: `PHASE2_2_CLOSED_PENDING_INDEPENDENT_REVIEW`

## 1. Starting State

- Repository: `/opt/casescope`
- Python: `/opt/casescope/venv/bin/python`
- HEAD / origin/main: `23999b3c10eaa2b0aa2942559d71f95aaa54b3c5`
- HEAD == origin/main, working tree clean at start
- Starting version: 4.26.0
- Deployed ClickHouse: 26.7.3.19

## 2. Accepted 2.2A Decision

- `PHASE2_2_MODE_SYNC`
- `ASYNC_NO_WAIT_FORBIDDEN`
- `KEEP_PRODUCTION_BATCH_SIZE_10000`

Independent review accepted Phase 2.2A (`PHASE2_2A_PASS`, `PHASE2_2_DECISION_READY`).
The 15% "material advantage" heuristic in the 2.2A measurement script was not
adopted as a CaseScope architecture or acceptance threshold.

## 3. Runtime Change

Canonical helper in `utils/clickhouse.py`:

- `EVENT_INSERT_MODE = "sync"`
- `event_insert_settings()` returns a **fresh** mapping:

```python
{
    "async_insert": 0,
    "materialize_skip_indexes_on_insert": 1,
}
```

`wait_for_async_insert` is not set on the SYNC path. There is no environment
variable that can silently restore async. Changing insertion mode again requires
another explicit architecture review.

Generic `get_client()` / `get_fresh_client()` still pin only `max_threads` and
`max_execution_time`.

## 4. Managed Event Insert

`utils.manifest_protocol.insert_managed_batch()` now passes
`settings=event_insert_settings()` on the physical `events` INSERT only.
Shared ingest admission, batch identity, row order, protocol columns, timing
metrics, and error propagation are unchanged. Verification and DURABLE ordering
are unchanged.

## 5. BatchProcessor Event Insert

`parsers.registry.BatchProcessor.flush()` applies the same settings only when
`self.table == "events"`. Non-events destinations (including hypothetical
legacy `events_buffer`) do not receive the event settings.
`BatchProcessor.DEFAULT_BATCH_SIZE` remains 10000.

## 6. Recovery / Retry Coverage

Existing Celery paths inherit the setting through `insert_managed_batch()`:

- `recover_staged_ingest_batch_task`
- stale STAGED reconciliation (`reconcile_staged_batch` -> `_schedule_staged_batch_recovery`)
- managed initial and replacement parsing (`_process_managed_initial_case_file`)
- managed EVTX directory/group parsing (`_process_managed_evtx_directory_group`)

`tasks/celery_tasks.py` was not changed. No duplicated async configuration was added.

## 7. Generic Client Isolation

Source inspection of `get_client()` and `get_fresh_client()` confirms they do
not pin `async_insert`, `wait_for_async_insert`, or
`materialize_skip_indexes_on_insert`.

## 8. Control Projection Isolation

Same fake/test client: managed events INSERT receives `async_insert=0`;
`project_generation_control_state()` INSERTs into
`visible_evidence_generations` / `durable_ingest_batches` have no event-specific
settings override. Verification SELECTs are unchanged.

Live same-client proof: control INSERT into `control_probe` entered
`system.asynchronous_insert_log`; the events INSERT did not.

## 9. Batch / Identity Contract

Unchanged: `ingest_batch_id`, `ingest_row_ordinal`, `ingest_row_hash`,
`batch_content_hash`, ERK set, row_count, column order. Insertion mode is not
part of ERK, batch ID, row hash, batch hash, or generation identity.
Frozen generation fields were not mutated. No new generation was allocated.
`KEEP_PRODUCTION_BATCH_SIZE_10000`.

## 10. Failure Semantics

Disposable protocol tests:

- A. INSERT raise: exception propagates, batch remains STAGED
- B. Fence unavailable: INSERT never called, batch remains STAGED
- C. INSERT succeeds but verify fails: no DURABLE
- D. Retry same deterministic batch: `duplicate_identical` preserved

ClickHouse async deduplication was not enabled.

## 11. Disposable Server-Observed SYNC Proof

Used `get_fresh_client()`-style client against disposable database
`cs_p22b_proof_ad66df3749b6` (dropped after capture). Production
`insert_managed_batch()` path. ClickHouse 26.7.3.19.

- Event query ID: `36cbdca7-1f5a-4043-b749-3354605a9677`
- `system.query_log` Settings: `async_insert = 0`
- `system.asynchronous_insert_log`: **absent** for that query ID
- 8 rows, 8 ERKs, hashes matched the managed manifest
- Text-index files present on the new part, including `skp_idx_idx_search_blob_text.idx`
- `hasAllTokens(search_blob, 'uniqueP22BToken')` returned 1 immediately
- EXPLAIN used `__text_index_idx_search_blob_text_hasAllTokens_*` / Skip `idx_search_blob_text`

SYNC was not inferred from latency.

## 12. Same-Client Control Insert Proof

Control query ID: `6f07213e-c8d4-4e44-920c-7a85e1791203` (no event settings).
That INSERT **did** enter `system.asynchronous_insert_log` (`table=control_probe`,
status Ok), matching production server defaults `async_insert=1` /
`wait_for_async_insert=1`. Event override did not mutate the client/session default.

## 13. Immediate Text-Index Searchability

Fresh part `9022_1_1_0` from the SYNC events INSERT:

- `skp_idx_idx_search_blob_text.idx` and companion files present
- `hasAllTokens` exact expected row
- EXPLAIN text-index direct path
- No `MATERIALIZE INDEX` / `OPTIMIZE FINAL`

## 14. Ngram Regression

Same disposable part:

- `skp_idx_idx_search_ngram.idx` present
- `search_blob LIKE '%NTLM%'` returned 1
- EXPLAIN Skip `idx_search_ngram` (`ngrambf_v1 GRANULARITY 4`)

`PHASE2_1_EXC_001` ngram retained. `idx_search_token` remains absent.

## 15. Production Pre-Activation State

Read-only, database `casescope`:

- ClickHouse 26.7.3.19
- 745,463,991 events / 135 active parts / 25 partitions
- `idx_search_blob_text` PRESENT (MATERIALIZED 25/25 partitions, 135/135 parts)
- `idx_search_ngram` PRESENT
- `idx_search_token` ABSENT
- `materialize_skip_indexes_on_insert` server default 1
- `async_insert` server default 1
- `wait_for_async_insert` server default 1
- mutations in progress: 0
- no unexpected events mutation running
- Server/user settings were not changed

## 16. Safe Worker Activation

Producer-first / no-message-deletion discipline.

Before restart: active=0, reserved=0, scheduled=0, queued=0 (celery+ioc),
unacked=0, shared writers=0, no exclusive fence. Natural safe idle.

**NO BROKER MESSAGE DELETION**

Restarted only `casescope-workers` then `casescope-web`. Beat not restarted.

## 17. Service State

| unit | before PID | before start (UTC) | after PID | after start (UTC) |
|---|---|---|---|---|
| casescope-workers | 1048283 | 2026-08-22 14:51:32 | 1173262 | 2026-08-22 17:22:51 |
| casescope-web | 1048172 | 2026-08-22 14:51:27 | 1173723 | 2026-08-22 17:23:24 |
| casescope-beat | 1048416 | 2026-08-22 14:51:38 | 1048416 | 2026-08-22 14:51:38 (unchanged) |

After: workers/web active, celery still empty, fence idle, queued/unacked 0.

## 18. Production Event-Insert Observation

`LIVE_PRODUCTION_EVENT_INSERT_NOT_OBSERVED`

No natural production `events` INSERT after worker activation. Not a blocker:
disposable proof used the production helper, workers restarted on the new code,
and per-call setting tests passed. Production `events` row count remained
745,463,991.

## 19. Hunt / Publication Smoke

Authenticated admin session. Case 14 `sonicwall`:

- `GET /login` 200; login succeeded; UI reports **v4.26.1**
- Hunt page 200
- Grid `GET /api/hunting/events/14?search=sonicwall` 200, total 13, 13 rows
- Detail 200 for a grid `selector_key`
- Small export-view 200 `text/csv`
- Phase 1B publication authority unchanged; analyst tags not modified

## 20. Production Server Settings After

Unchanged:

- `async_insert = 1` (changed=0)
- `wait_for_async_insert = 1` (changed=0)
- `materialize_skip_indexes_on_insert = 1` (changed=0)

Architecture: server/user defaults may remain async, but CaseScope physical
events INSERT explicitly overrides `async_insert=0` and
`materialize_skip_indexes_on_insert=1` per call.

## 21. Regression Tests

238 passed, 0 failed, 0 skipped (required suite including
`tests/test_phase2_2b_sync_event_insert.py`, with
`PHASE1B_PG_TEST_DATABASE_URL` / `PHASE1B_CH_TEST_DATABASE=phase2_2a_test`).
py_compile on changed Python, pyflakes on new/changed logic, `git diff --check` passed.

Historical 2.1D2B live-version pin was updated so later 4.26.x patches can keep
the 4.26.0 changelog entry without claiming current version is forever 4.26.0.

## 22. Files Changed

Runtime: `utils/clickhouse.py`, `utils/manifest_protocol.py`, `parsers/registry.py`,
`version.json`.

Tests: `tests/test_phase2_2b_sync_event_insert.py` plus fake-client `settings=`
compatibility and the 2.1D2B version-contract adjustment.

Docs: this file and `phase2_2b_sync_event_insert_activation.json`.

`tasks/celery_tasks.py` unchanged.

## 23. Version

4.26.1 (patch).

## 24. Production Mutation Audit

- NO EVIDENCE MUTATION (row count unchanged)
- NO INDEX MUTATION
- NO SERVER SETTINGS MUTATION

## 25. No-Later-Phase Audit

No Phase 2.3 lightweight UPDATE, 2.4 dedup, async event mode,
`wait_for_async_insert=0`, server ALTER SETTINGS, batch-size change, generation
contract change, parser ordering change, text/ngram/command_line index change,
pattern_rules rewrite, evidence/search_blob rewrite, LEK, `events_current`,
`event_observations_current`, Phase 3+, pagination redesign, or broker-message
deletion.

## 26. Git State

Recorded after operator commit/push of this activation.

## 27. Phase 2.2 Exit Checklist

1. Phase 2.2A accepted SYNC decision — PASS
2. physical events INSERT explicitly async_insert=0 — PASS
3. materialize_skip_indexes_on_insert=1 pinned on events INSERT — PASS
4. generic clients not globally changed — PASS
5. control projection semantics unchanged — PASS
6. managed ingest covered — PASS
7. legacy BatchProcessor events covered — PASS
8. recovery/retry covered — PASS
9. deterministic batch/ERK identity unchanged — PASS
10. STAGED -> INSERT -> VERIFY -> DURABLE ordering unchanged — PASS
11. fresh rows immediately text-index searchable — PASS
12. PHASE2_1_EXC_001 ngram maintained — PASS
13. server defaults not mutated — PASS
14. frozen 10k batch contract unchanged — PASS
15. async-no-wait remains forbidden — PASS
16. no Phase 2.3+ work — PASS

## 28. Phase 2.2 State

`PHASE2_2_CLOSED_PENDING_INDEPENDENT_REVIEW`

## 29. Remaining Work

Independent 2.2B review. Only after independent acceptance: Phase 2.3 —
lightweight UPDATE bridge. Not begun here.

## 30. Verdict

PHASE2_2B_PASS
