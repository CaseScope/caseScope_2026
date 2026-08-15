# Phase 0A Events Write / Mutation Inventory

Source of truth: `casescope_database_flow_plan_v4_locked.md`.

Scope: production paths that write to or mutate ClickHouse `events` or `events_buffer`.

## Summary

- Full-scan distinct production write/mutation paths: 47
- Grouped inventory records below: 11
- Main write classes: INSERT, ALTER UPDATE, ALTER DELETE, OPTIMIZE, schema mutation, migration/shadow-table operation, overlay/state writes
- Biggest rewrite paths:
  - `utils/clickhouse.py::delete_case_events`: whole-case `ALTER DELETE`
  - `utils/event_deduplication.py`: legacy destructive duplicate deletion
  - `migrations/add_evidence_record_identity.py`: shadow-table migration/swap
  - `utils/clickhouse.py::run_events_update`: caller-defined legacy state mutations
- Key guard gaps:
  - `delete_file_events` has no Redis destructive rewrite guard.
  - `run_events_update` overlay/state paths have no Redis destructive rewrite guard.
  - `destructive_event_rewrite_guard` fails open by default unless `require_lock=True`.
  - Pre-parse DELETE is unconditional; the Phase 1.9 existence-probe path is not implemented.

Full-scan category counts:

| Category | Count |
|---|---:|
| INSERT paths | 2 |
| File DELETE call sites | 4 |
| Case DELETE call sites | 6 |
| Dedup DELETE call sites | 4 |
| Overlay UPDATE call sites | 15+ |
| Buffer OPTIMIZE / fence / recreate paths | 7 |
| Schema / shadow paths | 12+ |

## Write Records

| File / function | Type | Scope | Guard / Redis | Future phase |
|---|---|---|---|---|
| `parsers/registry.py::BatchProcessor.flush` | INSERT | parser batch into `events_buffer` by default | no destructive guard | Phase 1.4 Buffer removal; Phase 1B deterministic batches |
| `tasks/celery_tasks.py::case_indexing_complete_task` | OPTIMIZE | whole `events_buffer` flush | no guard | Phase 1.4 removes Buffer and OPTIMIZE |
| `utils/clickhouse.py::delete_file_events` | ALTER DELETE | one `case_file_id` | no guard; waits when requested | Phase 4.4 generation model removes pre-parse DELETE |
| `utils/clickhouse.py::delete_case_events` | ALTER DELETE | one case | destructive guard, `require_lock=False`; fail-open if Redis unavailable | Phase 4.6 partition purge validation |
| `utils/clickhouse.py::run_events_update` | ALTER UPDATE | caller predicate | no destructive guard; `mutations_sync=1` by default | Phase 5 freezes legacy event state columns |
| `utils/event_deduplication.py` | ALTER DELETE | duplicate rows by legacy artifact recipes | destructive guard behavior configurable; completion uses skip | Phase 4.5 deletes mutation pass |
| Overlay state helpers | schema/state writes | analyst/IOC/MITRE/noise facts and summaries | mixed; not a uniform fence | Phase 3 IOC; Phase 5 overlays |
| `migrations/add_events_table.py` | schema mutation | `events` and `events_buffer` creation | none | Phase 1.4 removes Buffer |
| `migrations/add_evidence_record_identity.py` | schema/shadow migration | full/case-scoped ERK migration | destructive fence and buffer drain paths | Phase 3.0 ERK API migration |
| `utils/case_deletion.py` | OPTIMIZE + ALTER DELETE | whole-case deletion service | inherits `delete_case_events` fail-open guard | Phase 4.6/8 coordinated deletion |
| `bin/clear_cases.py`, `bin/archive_then_reset.py` | maintenance deletion | administrative reset | varies by helper path | Phase 4.6/8 coordinated deletion |

Full machine-readable details are in `docs/database_flow_phase0/events_write_inventory.json`.
