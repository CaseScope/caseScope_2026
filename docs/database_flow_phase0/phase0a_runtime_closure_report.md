# Phase 0A Runtime Closure Report

## 1. Starting State

- Remote main SHA: `8c4c1dd3b1651df42dc08c39f06250d296864c57`
- Local HEAD SHA at verification: `8c4c1dd3b1651df42dc08c39f06250d296864c57`
- Version: `4.18.5`
- Local HEAD differs from main: no

## 2. Source-of-Truth Verification

- Locked plan path: `casescope_database_flow_plan_v4_locked.md`
- Confirmed read in full again for this final closure pass.
- Locked plan was not edited.
- No v5, Phase 0B, Phase 1, LEK, generations, manifest, reader migration, Buffer removal, or ingest optimization was implemented.

## 3. Runtime Environment

- Runtime Python: `/opt/casescope/venv/bin/python`, Python `3.12.3`
- Runtime env: `/etc/casescope/casescope.env`
- Required imports verified: `clickhouse_connect`, `flask`, `sqlalchemy`, `flask_sqlalchemy`, `redis`, `celery`, `psutil`
- Connectivity verified read-only: PostgreSQL `SELECT 1`, ClickHouse `SELECT 1`, Redis `PING`

## 4. Current Ingestion Flow

Current production flow remains: queue case files -> `parse_file_task` -> pre-parse cleanup with `delete_file_events(wait=True)` -> parser registry/parser -> EVTX subprocess tools when applicable -> `BatchProcessor` -> `events_buffer` inserts -> PostgreSQL `CaseFile` status updates -> completion task -> Buffer `OPTIMIZE` -> dedup / KnownSystem / KnownUser / MITRE / embeddings / graph scheduling.

## 5. Reader Inventory

- 167 production direct-events reader locations.
- 52 production files.
- 227+ embedded `events` query strings.
- Inventories preserved in `events_reader_inventory.md` and `events_reader_inventory.json`.

## 6. Write/Mutation Inventory

- 47 production write/mutation paths.
- Includes inserts, `ALTER UPDATE`, `ALTER DELETE`, `OPTIMIZE`, schema/shadow-table operations, state/IOC/MITRE/noise writes, retry cleanup, and deletion paths.
- Inventories preserved in `events_write_inventory.md` and `events_write_inventory.json`.

## 7. Instrumentation

Phase 0A instrumentation remains observational and bounded in `utils/ingest_metrics.py`, `parsers/registry.py`, `parsers/evtx_parser.py`, `tasks/celery_tasks.py`, and `utils/clickhouse.py`.

Final closure fixed one instrumentation regression: EVTX metric counters are now lazily initialized for tests and code paths that construct `EvtxECmdParser` without `__init__`. This preserves parsed event semantics and restored affected parser hardening tests.

## 8. ClickHouse Baseline

- ClickHouse version: `26.7.3.19`
- Database: `casescope`
- `events` rows from active parts: `745463991`
- Active-part bytes: `107590061428`
- Active parts: `201`
- Partitions: `25`
- Median rows/part: `371928`
- P95 rows/part: `16275388`
- Compact vs Wide: `Wide=201`
- `events_buffer`: exists, engine `Buffer`
- Full output: `clickhouse_storage_baseline.json` and `clickhouse_baseline.md`

## 9. ClickHouse Version Implication

OBSERVED: deployed ClickHouse `26.7.3.19` already exceeds the locked plan's `>=26.2` Phase 2 Gate A minimum version prerequisite.

Status: VERSION PREREQUISITE SATISFIED.

This does not mean Phase 2 is ready. Later work still requires text-index DDL/capability checks, tokenizer/preprocessor verification, deployed syntax validation, lightweight UPDATE capability checks, events table block-number/block-offset settings, feature/table settings, benchmark behavior, and explicit insert mode decisions.

## 10. EXPLAIN Baseline

Executed read-only `EXPLAIN indexes = 1` for representative query shapes against case `3`.

Measured highlights:

- `hasToken(search_blob, ...)`: search skip indexes considered and material pruning observed.
- `lower(search_blob) LIKE`: search skip-index pruning not observed.
- `positionCaseInsensitive(search_blob, ...)`: search skip-index pruning not observed.
- `event_id` and combined hunt: `idx_event_id` bloom pruning observed.
- `username`, `source_host`, `process_name`, and `command_line`: no dedicated skip-index pruning observed beyond case/order pruning.

Full output: `clickhouse_query_explain_baseline.json` and `clickhouse_query_baseline.md`.

## 11. Duplicate Baseline

Read-only duplicate diagnostics were executed across cases `3`, `23`, `1`, and `37`.

- Rows analyzed: `20894468`
- Duplicate rows under current legacy semantics: `9392460`
- Same CaseFile duplicates: `2552676`
- Cross CaseFile duplicates: `6839784`
- Same ERK duplicates: `2480028`
- Different ERK duplicates: `6912432`
- `source_generation`: NOT CURRENTLY MEASURABLE

## 12. Duplicate-Sample Interpretation

Observed duplicate percentage across the four analyzed cases: `44.952%`.

Scope label: OBSERVED ACROSS THE FOUR ANALYZED CASES. This is not a global CaseScope duplicate rate because not every retained case was analyzed.

This is an empirical input to the later LEK contract. LEK is not defined here.

## 13. Full Test Failure Triage

Comparison states:

- State A clean main: `{'tests': 2085, 'duration_seconds': 74.809, 'failures': 6, 'errors': 7, 'skipped': 7}`
- State B clean main plus Phase 0A only after fix: `{'tests': 2090, 'duration_seconds': 73.075, 'failures': 6, 'errors': 7, 'skipped': 7}`
- State C current worktree after fix: `{'tests': 2092, 'duration_seconds': 67.908, 'failures': 6, 'errors': 6, 'skipped': 7}`

Classifications after fix:

- PRE_EXISTING_MAIN_FAILURE: `12`
- ENVIRONMENT_DEPENDENT: `1`
- PHASE0A_REGRESSION unresolved: `0`

Triage outputs: `full_suite_failure_triage.md` and `full_suite_failure_triage.json`.

Isolation and safety limit: some tests read absolute `/opt/casescope/...` source paths, and full discovery with `/etc/casescope/casescope.env` is not read-only because selected tests write to production PostgreSQL or mutate production ClickHouse. This was recorded in the triage docs.

## 14. Safe Benchmark Environment

`CORPUS_PRESENT_VERIFIED_NON_RETAINED`.

Approved corpus path: `/opt/casescope-benchmark/phase0a_evtx/`.

Manifest: `/opt/casescope-benchmark/phase0a_evtx/MANIFEST.txt`.

Manifest states the files are benign lab/test Windows event logs, not retained CaseScope evidence, and authorized for disposable/repeated benchmark processing.

Corpus inventory:

- Files: `8` EVTX.
- Total bytes: `77103104`.
- Exact PostgreSQL `case_files.file_path` retained-source matches: `0`.
- Exact ClickHouse `events.source_path` / `events.source_file` matches: `0`.
- Filename-only overlaps such as `Security.evtx` exist in retained evidence metadata but were recorded as generic channel-name overlap, not retained-source correspondence.
- Source EVTX files were not modified.

Detailed file hashes and sizes: `approved_benchmark_corpus_check.md` and `approved_benchmark_corpus_check.json`.

## 15. Hot-Path Profile

Executed against a disposable benchmark process, not production workers.

- `py-spy`: `0.4.2`, installed only in `/tmp/casescope-phase0a-tools`.
- Profile artifact: `phase0a_ingest_profile.svg`.
- Top-sample extraction: `phase0a_ingest_profile_top_samples.json`.
- Samples reported by `py-spy`: `25893`.
- `py-spy` post-child wrapper note: after writing the flamegraph it returned `No child process (os error 10)`. The child benchmark completed and wrote `baseline_performance_run.json`.

Measured wall-time highlights from structured metrics:

- EvtxECmd subprocess wall time: `47.408s`.
- Hayabusa subprocess wall time: `49.259s`.
- EVTX JSONL consume wall time: `256.142s`.
- Outer JSON decode: `2.197s`.
- Nested Payload JSON decode: `1.209s`.
- Normalization: `38.961s`.
- `search_blob` construction: `0.931s`.
- Alias extraction: `170.863s`.
- PostgreSQL alias writes: `8.136s`.
- ClickHouse insert wait: `2.954s`.

Top Python CPU samples were timestamp parsing, `ParsedEvent.to_clickhouse_row`, `build_evidence_record_identity`, privacy alias extraction, `BatchProcessor.add_event`, extra-field serialization, and `dateutil` parsing. Subprocess time was correlated from structured wall-time metrics and not inferred from Python CPU samples.

## 16. Controlled BEFORE Benchmark

Executed with disposable PostgreSQL, ClickHouse, and storage:

- PostgreSQL database: `phase0a_ingest_20260814110501`, dropped after capture.
- ClickHouse database: `phase0a_ingest_20260814110501`, dropped after capture.
- Storage root: `/tmp/phase0a_ingest_20260814110501_storage`, removed after capture.

Benchmark results:

- Wall time: `332.884s`.
- Files: `8`.
- Source bytes: `77103104`.
- Events parsed before dedup: `110742`.
- Events physically present after current dedup: `49115`.
- Events/sec before dedup: `332.674`.
- Source MB/sec: `0.221`.
- Time to first physical row: `184.478s`.
- Time to first current-searchable event: `184.478s`.
- Peak RSS: `237.36 MB`.
- Errors: `0`.
- Retries: `0`.

Completion stages:

- Buffer/current final optimize reproduced as `OPTIMIZE TABLE events FINAL`: `2.196s`.
- Dedup reproduced in disposable ClickHouse: success, `0` duplicates found, `0` deleted, `98.187ms`.
- KnownSystem discovery reproduced: success, `7` systems created, `971.908ms`.
- KnownUser discovery reproduced: success, `2` users created, `1` updated, `47.136ms`.
- MITRE match insertion/scheduling: NOT REPRODUCED because the disposable harness used `process_file` and did not run production `parse_file_task` post-parse MITRE queueing.
- Embeddings: NOT REPRODUCED because the disposable harness did not enqueue embedding workers.
- Graph materialization: NOT REPRODUCED because the disposable harness did not enqueue graph workers.

ClickHouse disposable state:

- Before: active parts `0`, active rows `0`, mutation count `0`.
- After: active parts `1`, active rows `49115`, mutation count `8`.

No optimization behavior was changed: no `orjson`, Buffer removal, batch-size change, alias optimization, Hayabusa mode change, dedup redesign, schema/settings change, or retained-evidence reprocessing.

## 17. Focused Test Results

Command:

```bash
sudo -u casescope bash -lc 'cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && /opt/casescope/venv/bin/python -m unittest tests.test_ingest_metrics tests.test_clickhouse_delete_dedup_contracts tests.test_parser_retry_cleanup'
```

Result after final closure fixes: `44` tests OK in `0.677s`.

Additional final-closure fix: `BatchProcessor` alias metric counting now supports the current `AliasCandidate` map shape. This fixes the benchmark-discovered Phase 0A regression without changing alias extraction, alias writes, parser semantics, batch size, or ClickHouse behavior.

## 18. Full Test Results

Latest full-suite triage from the prior runtime closure pass remains:

- Ran: `2092`
- Failures: `6`
- Errors: `6`
- Skipped: `7`
- Duration: `67.908s`

All remaining current failures/errors were classified as clean-main or environment-dependent; no unresolved Phase0A-caused failure/error remained. Focused Phase 0A tests were rerun after the final closure benchmark/profile fixes and passed.

## 19. Measurement-Derived Phase 1 Inputs

- `events` contains `745463991` active rows and `107590061428` active-part bytes.
- `events_buffer` is present and remains part of current ingestion.
- All observed active production parts are Wide.
- `hasToken(search_blob, ...)` pruned with current skip indexes in the representative EXPLAIN baseline; `lower(search_blob) LIKE` did not.
- Duplicate sample across four retained cases showed `44.952%` duplicate rows under current legacy semantics.
- Real EVTX benchmark showed alias extraction, timestamp parsing, row serialization, and ERK identity generation are dominant Python hot paths.
- EvtxECmd and Hayabusa are material subprocess wall-time costs but were not the majority of observed end-to-end wall time on the approved corpus.
- Current first-searchable latency under the disposable current architecture was `184.478s` for this corpus.

## 20. Phase 0A Verdict

READY FOR PHASE 0B.

Readiness basis:

- Real EVTX hot-path profile completed with saved flamegraph/profile summary.
- Controlled BEFORE benchmark completed in disposable PostgreSQL/ClickHouse/storage only.
- Measurements are documented and reproducible in the Phase 0A docs and JSON artifacts.
- Focused Phase 0A tests pass: `44` tests OK.
- No unresolved Phase0A regression remains.
- Instrumentation remains structured, bounded, and does not log raw evidence values.
- Production databases and retained evidence were not used for benchmark rows and were not reprocessed, deleted, rebuilt, or deduplicated.
