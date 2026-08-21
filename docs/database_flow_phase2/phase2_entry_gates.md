# Phase 2 Entry Gate Qualification

Independent Gate A (text index) and Gate B (lightweight UPDATE) qualification
against the locked v4 database-flow plan. Phase 1B remains closed. Phase 2.1
reader cutover, 2.2 insert-mode decision, 2.3 UPDATE bridge, and 2.4/Phase 3–8
were not implemented.

Measurement artifact: `docs/database_flow_phase2/phase2_entry_gate_measurements.json`.

Production `casescope.events` was inspected read-only. All DDL, inserts, updates,
and `MATERIALIZE INDEX` ran in disposable database `casescope_phase2_gate_scratch`.

## Starting state

- origin/main and HEAD: `b83f60550b0a4cdbfa3417b373acc2041dd6115a`
- Commit: Phase 1B close EXIT first-DURABLE-to-Hunt measurement
- Baseline version: 4.22.2
- This tranche version: 4.23.0
- Python: `/opt/casescope/venv/bin/python`
- Deployed ClickHouse: `26.7.3.19`

## Locked scope

Qualified only the two independent Phase 2 entry gates:

- Gate A: CH >= 26.2, text-index DDL/tests/index migration
- Gate B: lightweight UPDATE feature + `enable_block_number_column` /
  `enable_block_offset_column` migration + benchmark

Not done: 2.1 Hunt reader cutover, bloom-index drop, 2.2 setting change,
2.3 product UPDATE cutover, 2.4 dedup engine, Phase 3–8.

## Current production events schema

- Engine: MergeTree
- PARTITION BY `case_id`
- ORDER BY `(case_id, timestamp_utc, artifact_type, source_host, source_file, event_id)`
- Settings: `index_granularity = 8192, min_bytes_for_wide_part = 0, min_rows_for_wide_part = 0`
- Active parts: 135 / 25 partitions / 745,463,991 rows / 108,493,322,926 bytes
- No `enable_block_number_column` / `enable_block_offset_column`
- No `_block_number` / `_block_offset` persisted settings
- Phase 1B protocol columns (`source_ref_*`, `ingest_batch_id`, …) are not present
  on production `events`. That is recorded only; Phase 1B is not reopened here.

## Current search index inventory

| Name | Type | Expression | Granularity | Compressed bytes |
|---|---|---|---:|---:|
| idx_search_ngram | ngrambf_v1(3, 512, 2, 0) | search_blob | 4 | 4,049,580 |
| idx_search_token | tokenbf_v1(32768, 3, 0) | search_blob | 4 | 964,699,630 |
| idx_event_id | bloom_filter(0.01) | event_id | 4 | 9,913,034 |
| idx_selector_key | bloom_filter(0.01) | selector_key | 4 | 453,214,994 |
| idx_evidence_record_key | bloom_filter(0.01) | evidence_record_key | 4 | 886,609,005 |

No `command_line` skip/text index.

Hunt term search today is substring, not token:

- `routes/hunting_query_helpers.py` `build_hunting_search_clause` emits
  `search_blob ilike {param}` with `%term%` for free-text terms, quoted phrases,
  OR groups, and exclusions.
- Numeric bare terms use `event_id =`.
- Field filters such as `cmd:` / `command_line:` use column `ilike`.
- Event-detail `match_search_blob` uses `position(e.search_blob, …)` (case-sensitive substring).

Other high-volume `search_blob` consumers (not migrated): IOC tagger
(`hasTokenCaseInsensitive` / LIKE), candidate extractor, RAG token search,
Phase 0 baseline `hasToken` / `positionCaseInsensitive`.

Production `EXPLAIN indexes = 1` on case 32 (largest partition, 35,535 granules)
for Hunt-style `search_blob ILIKE '%powershell%'` used partition/primary-key
pruning only. Skip indexes `idx_search_ngram` and `idx_search_token` were not
listed as used. `hasTokenCaseInsensitive(search_blob, 'powershell')` and
`command_line ILIKE` were the same: no Skip section.

Readers were not changed.

## Current insert-mode inventory

Server defaults on this deploy (session `changed = 0`):

- `async_insert = 1`
- `wait_for_async_insert = 1`
- `materialize_skip_indexes_on_insert = 1`

`utils.clickhouse.get_client` / `get_fresh_client` set only `max_threads` and
`max_execution_time`. Parser `BatchProcessor` inserts to `events` (not Buffer)
with `DEFAULT_BATCH_SIZE = 10000` under shared ingest admission.
`insert_managed_batch` uses the same client `insert()` path.
`PHASE1B_MANIFEST_BATCH_SIZE` defaults to 10000 when unset. Phase 1 exit
benchmark used 10k batches. Production batch-size changes still require a new
generation.

CaseScope does not explicitly configure insert mode or wait. Current inserts
inherit the 26.7 server default of async insert with wait.

# GATE A

## Version

PASS. Deployed `26.7.3.19` >= 26.2.

`enable_full_text_index = 1` (default). `allow_experimental_full_text_index = 1`
(default; still present, not required as a manual enable).
`query_plan_direct_read_from_text_index = 1`.

## Text index DDL proof

`tokenizer = 'default'` is rejected (`Unknown tokenizer: 'default'`).

Accepted on this server:

```sql
INDEX idx_search_blob_text search_blob TYPE text(
    tokenizer = 'splitByNonAlpha',
    preprocessor = lower(search_blob)
) GRANULARITY 1
```

The server stores GRANULARITY as `100000000` for text indexes regardless of 1/4/8.
`search_blob` remains a stored `String`; the preprocessor is index-only.
`ALTER ADD INDEX IF NOT EXISTS` on a populated table is metadata (~6 ms, zero
mutations, `data_compressed_bytes = 0` until MATERIALIZE or insert-time build).

## Tokenizer / preprocessor

- Tokenizer: `splitByNonAlpha` (matches `hasAllTokens(..., 'splitByNonAlpha')`)
- Preprocessor: `lower(search_blob)`
- Stored `search_blob` unchanged

With the index present, ClickHouse rewrites
`hasAllTokens(search_blob, 'powershell')` to
`hasAllTokens(lower(search_blob), ['powershell'], 'splitByNonAlpha')` and, after
the index is materialized, to direct read
`__text_index_idx_search_blob_text_hasAllTokens_*`.

Without the index, `hasAllTokens` is case-sensitive (`PowerShell` matches,
`powershell` does not). The locked lower() preprocessor is therefore required
for Hunt-like case-insensitive term semantics.

## Term search semantic parity

Disposable 80,000-row events-shaped table.

Token path (scan `hasAllTokens(lower(search_blob), …)` vs indexed
`hasAllTokens(search_blob, …)`): **equal result sets for every fixture term**.
`token_path_false_negatives` is empty. No Gate A semantic false negative on the
token path.

Current Hunt ILIKE `%term%` vs indexed `hasAllTokens`:

- Equal for whole-token terms in this fixture set: `powershell`, `PowerShell`,
  `jsmith`, `evil.example.com`, `10.20.30.40`, SHA-256, `4688`, `zxqvunique`,
  `HKLM`, paths, unicode `用户` / `münchen`.
- Not equal for true substring `power`: ILIKE 5715 / hasAllTokens 0
  (`a_only_count = 5715`, `b_only_count = 0`). Classified as required LIKE
  retention, not a token-path miss.

`hasAnyTokens` equals `hasAllTokens` for single-token queries; multi-separator
terms such as `evil.example.com` and `C:\Windows\System32\cmd.exe` can differ
because `hasAnyTokens` is disjunctive.

## Substring preservation

ILIKE `%owerSh%` result sets were equal on the bloom-only table and the
text-index table (5715/5715). LIKE remains the required path for genuine
substrings. Product readers still use ILIKE.

## EXPLAIN / index use

After MATERIALIZE, rare and common `hasAllTokens` queries show Skip index
`idx_search_blob_text` and Filter column `__text_index_idx_search_blob_text_hasAllTokens_*`
(direct text-index read).

Unmaterialized index (`materialize_skip_indexes_on_insert=0`) still lists Skip
but Filter remains `hasAllTokens(lower(search_blob), …)` over `search_blob`
(scan). Counts stay correct: empty index granules are not treated as
false-negative misses.

Production Hunt ILIKE does not show text-index or bloom Skip use.

## Text search benchmark

80k-row disposable table, 9 samples with 1 warmup, p50/p95:

| Query | Result | p50 ms | p95 ms | read_rows p50 | read_bytes p50 |
|---|---:|---:|---:|---:|---:|
| ILIKE `%zxqvunique%` (current) | 2000 | 7.48 | 7.67 | 80000 | 4,965,896 |
| hasAllTokens text index rare | 2000 | 4.78 | 4.87 | 80000 | 80,000 |
| ILIKE `%powershell%` | 5715 | 10.34 | 10.54 | 80000 | 4,965,896 |
| hasAllTokens text index powershell | 5715 | 4.69 | 6.70 | 80000 | 80,000 |

Same row count; text-index path reads far fewer bytes via direct index read.

## materialize_skip_indexes_on_insert=0

| Step | Index bytes | EXPLAIN filter |
|---|---:|---|
| Insert with default 1 | 8630 | `__text_index_…hasAllTokens…` |
| Insert with 0 | 0 | `hasAllTokens(lower(search_blob), …)` scan |
| Count with 0 | 2000 correct | scan |
| Explicit MATERIALIZE INDEX | 8630 | `__text_index_…` |
| New rows after index with setting 0 | visible (200) | empty-index parts scanned, not dropped |

Reconnect after insert still sees the new rows.

## Existing-row materialization

`ALTER ADD INDEX` does not build postings for existing parts. Operator
`MATERIALIZE INDEX idx_search_blob_text SETTINGS mutations_sync = 1` does.
Default `materialize_skip_indexes_on_merge = 1` would also build the index on
later merges unless excluded.

Upgrade migration therefore:

1. ADD INDEX (metadata)
2. `exclude_materialize_skip_indexes_on_merge = 'idx_search_blob_text'`
3. Does **not** MATERIALIZE
4. Refuses production MATERIALIZE
5. Is not invoked from application startup

New INSERTs still follow `materialize_skip_indexes_on_insert` (server default 1).

## Gate A migration

Files:

- `migrations/add_events_search_blob_text_index.py` (upgrade, operator-run)
- `EVENTS_SCHEMA` now declares the text index for fresh CREATE and keeps both
  bloom indexes

Fresh CREATE includes the index. Upgrade is idempotent, fail-closed on an
incompatible existing `idx_search_blob_text`, refuses `casescope` without
`--apply-production`, never rewrites `search_blob`, never drops blooms, never
materializes on production.

Not applied to retained production `events` in this tranche.

## command_line evaluation

**DEFER**

Disposable: 32,000 / 80,000 rows had command_line; ILIKE and token counts matched
(16,000). Text index on command_line was used (`__text_index_idx_command_line_text_hasAllTokens_*`)
and p50 dropped from 7.01 ms (ILIKE) to 4.42 ms. Production first 20,000 rows of
largest case_id 32 had 0 nonempty command_line. Hunt `cmd:` is still column ILIKE.
The plan requires evaluation, not creation. No production command_line index was
added.

## GATE A VERDICT

PHASE2_GATE_A_PASS

# GATE B

## Version / feature support

PASS by actual SQL, not version inference.

- `enable_lightweight_update = 1` (default)
- `allow_experimental_lightweight_update = 1` (default; still present, already on)
- `alter_update_mode = heavy` (classic ALTER UPDATE remains heavy)
- `apply_patch_parts = 1`
- SQL `UPDATE t SET … WHERE …` is accepted when block columns are enabled
- SQL `UPDATE` without block columns fails closed:
  `Lightweight updates are supported only for tables with materialized _block_number column`

No extra experimental session flag had to be turned on for this 26.7.3.19.

## Current block settings

Production events: **absent** (both default 0). Not in `engine_full`.

## Block-setting migration

`migrations/add_events_block_number_offset.py`:

```sql
ALTER TABLE events MODIFY SETTING
    enable_block_number_column = 1,
    enable_block_offset_column = 1
```

Proven on a populated disposable table (2,000 existing rows):

- ALTER succeeds
- part count/bytes unchanged (1 part, 17,082 bytes)
- forensic `selector_key` / `search_blob` unchanged
- `_block_number` / `_block_offset` readable on old rows (offset 0–1999)
- subsequent INSERT works (`_block_number` 2 on the new row)
- idempotent second run is a no-op
- refuses production without `--apply-production`
- not invoked from application startup

Fresh `EVENTS_SCHEMA` now sets both settings.

Not applied to retained production `events` in this tranche.

## Lightweight UPDATE correctness

Disposable table with block settings enabled:

- Intended `sel-1` flipped to true; `sel-0` and `sel-2` stayed false
- Repeated UPDATE stayed true
- Batched three additional keys: 4 tagged / 1997 untagged of 2001 rows
- Concurrent SELECTs during UPDATE: no errors
- INSERT after settings change visible
- Classic `ALTER TABLE … UPDATE` still functions on the same table
- Future 2.3 must keep `utils.evidence_audit` hooks; faster UPDATE is not an
  audit bypass

## Classic mutation benchmark

`ALTER TABLE … UPDATE … SETTINGS mutations_sync = 1, alter_update_mode = 'heavy'`
on 25,000 rows:

| n | submit_ms | visible_select_ms | rows_affected |
|---:|---:|---:|---:|
| 1 | 19.1 | 3.1 | 1 |
| 10 | 38.3 | 26.7 | 10 |
| 100 | 22.0 | 3.3 | 100 |
| 1,000 | 59.5 | — | 1,000 |
| 10,000 | 362.0 | — | 10,000 |

## Lightweight UPDATE benchmark

SQL `UPDATE`:

| n | submit_ms | visible_select_ms | rows_affected |
|---:|---:|---:|---:|
| 1 | 6.9 | — | 1 |
| 10 | 7.5 | — | 10 |
| 100 | 8.9 | — | 100 |
| 1,000 | 20.6 | — | 1,000 |
| 10,000 | 142.3 | — | 10,000 |

Materially faster for small state patches. 10k already costs 142 ms plus patch
parts; this is not a large-rewrite path.

## Patch-part read impact

At n=10,000, `countIf(analyst_tagged)` p50:

- before: 3.39 ms / 25,000 rows / 3 bytes
- with patch parts: 3.72 ms / 25,000 rows / 204,001 bytes
- after `OPTIMIZE FINAL`: 2.75 ms / 25,000 rows / 40,001 bytes

Patch parts add modest latency and extra bytes; merge restores. Acceptable for
small state updates only.

## Large rewrite / fence boundary

Unchanged. `run_events_update` still issues `ALTER TABLE events UPDATE` inside
`exclusive_ingest_fence`. Shared writer admission, exclusive drain, Redis
fail-closed, and destructive refusal when lock authority is unavailable were not
weakened. Large classic rewrites stay behind that fence. 2.3 may use SQL UPDATE
only for small state paths and must still fence/audit.

## Audit hook inventory

All current product mutations go through `utils.clickhouse.run_events_update`
except analyst/noise per-event audit which records via `record_event_changes`
immediately after the mutation.

| Current path | Audit hook | Eligibility | Reason |
|---|---|---|---|
| `event_analyst_state` selector-bounded tag/notes | `record_event_changes` after mutation (not `audit=` on `run_events_update`) | SMALL_BRIDGE_CANDIDATE | Bounded named events; 2.3 must keep per-event before/after |
| `event_noise_state` manual selector-bounded | `record_event_changes` after mutation | SMALL_BRIDGE_CANDIDATE | Same as analyst |
| `event_noise_state` scan / case-wide | `audit=EvidenceChange` on `run_events_update` | KEEP_CLASSIC_FENCED | Predicate can be case-wide |
| `event_ioc_state` start_ioc_refresh clear | `audit=EvidenceChange` | KEEP_CLASSIC_FENCED | Case-wide `length(ioc_types) > 0` |
| `event_ioc_state` insert_ioc_scan_matches | `audit=EvidenceChange` | KEEP_CLASSIC_FENCED | IOC WHERE can be huge |
| `event_mitre_state` map/reset/rebuild | `audit=EvidenceChange` | KEEP_CLASSIC_FENCED | Overlay rewrite, often large |
| `event_overlay_repair` case state reset | `audit=` plus `destructive_event_rewrite_guard` | KEEP_CLASSIC_FENCED | Case-wide clear |
| `hayabusa_mitre_reenrichment` | `audit=EvidenceChange`, batches of 5000 record_ids | DEFER | At the 10k ceiling; 2.3 must pick a small-batch threshold |

Do not implement 2.3 in this tranche.

## GATE B VERDICT

PHASE2_GATE_B_PASS

# Next decision inputs

## 2.2 insert-mode current state

Inventory only. No production insert-setting change.

- Server default `async_insert=1`, `wait_for_async_insert=1`
- Application clients do not set either
- Parser/managed ingest uses clickhouse-connect `insert()` in 10k batches
- Client-side batching exists; insert mode is inherited, not explicit
- Phase 1 / 1B managed batch contract remains 10k for existing generations

## 2.2 benchmark plan

Compare on a disposable events-shaped table, same row payload, fence on,
`wait_for_async_insert=0` forbidden for forensic correctness:

SYNC (`async_insert=0`): 10k, 25k, 50k, 100k

ASYNC (`async_insert=1`, `wait_for_async_insert=1`): equivalent batch sizes and
server async_insert_* knobs only as needed to keep wait-for-flush correctness

Do not change production batch size on an existing managed generation.

## 2.4 boundary

No ReplacingMergeTree, LEK, `events_current`, `event_observations_current`, or
new dedup engine. Phase 2.4 remains generation-aware accounting + deterministic
batch retry exclusion. Logical dedup stays Phase 4.

## Regression tests

`/opt/casescope/venv/bin/python -m pytest` on:

- `tests/test_phase2_entry_gates.py` (fake + live disposable CH)
- `tests/test_query_hardening_regressions.py`
- `tests/test_ingest_fence.py`
- `tests/test_event_analyst_state.py` / `tests/test_event_noise_state.py` /
  `tests/test_overlay_audit_repairs.py`
- `tests/test_clickhouse_delete_dedup_contracts.py`
- `tests/test_phase1_step1.py` / `tests/test_phase1_step2.py`
- `tests/test_phase1b_tranche_a_contracts.py`
- `tests/test_evidence_identity_migration.py`
- `tests/test_ioc_hunting_regressions.py`
- `tests/test_hunt_routes_contract.py`
- `tests/test_phase1b_tranche_f2_product_search_publication_gate.py` (skipped without live 1B env)

Also `py_compile`, `pyflakes`, `git diff --check`.

## No-later-phase audit

No ERK API migration, IOC overlay authority transfer, LEK,
`event_observations_current`, `events_current`, Hunt reader cutover, Phase 5–8.
Phase 1B publication helpers/tests were not modified.

## Remaining work authorized by this result

- Phase 2.1 reader cutover is eligible (Gate A PASS); not started
- Phase 2.3 small-update bridge is eligible (Gate B PASS); not started
- Phase 2.2 still needs an explicit benchmark/decision tranche
- Phase 2.4 remains separate
- Production operator apply of the two migrations is a later controlled step
  (`--apply-production`, no MATERIALIZE of the text index across 745M rows)

## Overall verdict

PHASE2_ENTRY_GATES_PASS

# Independent-review closure (4.23.1)

This section does not replace the qualification measurements above. It records
the three remaining closure items after independent review of that result.

Measurement artifact: `docs/database_flow_phase2/phase2_entry_gate_closure.json`.

HEAD / origin/main at start: `c73d414961d7417e78a2a3abdaad01655cb8e53c`
(Phase 2 qualify entry Gates A and B without reader or UPDATE cutover).
Baseline version: 4.23.0. Closure version: 4.23.1.
Deployed ClickHouse remains `26.7.3.19`.

No Phase 2.1 reader cutover, production text-index materialization, bloom
removal, 2.2 insert-mode change, 2.3 lightweight UPDATE caller, 2.4 dedup,
Phase 3, Phase 4, LEK, `events_current`, or `event_observations_current`.

## Gate A expression-validation defect

`migrations/add_events_search_blob_text_index.py` already read
`name`, `type`, `type_full`, `expr`, and `granularity` from
`system.data_skipping_indices`, but compatibility only checked `type_full`.

An existing index named `idx_search_blob_text` on `command_line`,
`lower(search_blob)`, `concat(...)`, or another expression would have been
treated as already applied.

## Gate A migration fix

Compatibility now requires both:

- type matches `tokenizer = splitByNonAlpha` and
  `preprocessor = lower(search_blob)` (quoting/whitespace only)
- expression is the locked `search_blob` column

Live ClickHouse 26.7.3.19 reports `system.data_skipping_indices.expr` for the
locked ADD INDEX as exactly `search_blob`. That proven form is the expected
expression. Superficial identifier quoting (backticks / wrapping double quotes
on a bare identifier) is normalized; `lower(search_blob)`, `command_line`,
`concat(...)`, and other expressions fail closed as `IncompatibleSearchBlobTextIndex`.
The migration does not DROP or REPLACE an incompatible index.

Production `add_events_search_blob_text_index.py --apply-production` was **not**
run. MATERIALIZE INDEX was not run.

## Gate A tests

A. correct type + `search_blob` expression → compatible / already-applied
B. correct type + `command_line` expression → `IncompatibleSearchBlobTextIndex`
C. correct type + `lower(search_blob)` expression → `IncompatibleSearchBlobTextIndex`
D. wrong type + correct expression → `IncompatibleSearchBlobTextIndex`
E. new ADD result validates both type and expression (`expr == search_blob`)

Live disposable ClickHouse also proves after-ADD `expr == search_blob` and that
the same index name on `command_line` fails closed without DROP.

## Final Gate A verdict

PHASE2_GATE_A_PASS

Production index application remains a Phase 2.1 operator step.

## Production Phase 1B schema before

Read-only inspection of production database `casescope` (no DDL):

- `events` column count: 75
- Protocol columns **absent**: `source_ref_type`, `source_ref_id`,
  `source_generation`, `ingest_batch_id`, `ingest_row_ordinal`,
  `ingest_row_hash`, `ingest_attempt_id`
- Engine settings: `index_granularity = 8192, min_bytes_for_wide_part = 0,
  min_rows_for_wide_part = 0`
- `enable_block_number_column` / `enable_block_offset_column` **absent** (default 0)
- Active parts: 135 / 25 partitions / 745,463,991 rows / 108,493,322,926 bytes
- Recent `system.mutations` on `events` are historical completed MITRE overlay
  UPDATEs; none were in progress at inspection

## Phase 1B schema convergence

**Not applied.** Independent review required the seven protocol columns, but
production ClickHouse also lacks the required control projections.

STOP condition from the locked closure plan:

PHASE1B_DEPLOYMENT_SCHEMA_NOT_READY

No production `ALTER TABLE events ADD COLUMN` was executed. No backfill, no
ALTER UPDATE, no OPTIMIZE, no historical-row rewrite.

The earlier Gate qualification statement that protocol columns were absent was
**confirmed**, not stale.

## Phase 1B control tables / PostgreSQL authority

ClickHouse production `casescope` tables matching
`visible_evidence_generations` / `durable_ingest_batches`: **absent**.

Those tables exist only in disposable `phase1b_exit_ingest_*` databases, not in
production `casescope`. Production `casescope` tables remain:
`events`, `events_buffer`, `events_evidence_identity_previous`,
`event_mitre_matches`, `network_logs`, `network_logs_buffer`,
`case_unified_findings`.

PostgreSQL control-plane tables **present** (all row counts 0):

- `evidence_source_generations`
- `ingest_attempts`
- `ingest_batches`
- `case_capability_source_state`
- `case_capability_batch_completions`
- `case_completion_reconciliation_audit`
- also present: `evidence_generation_audit`, `ingest_batch_reconciliation_audit`

`case_files.ingest_protocol_origin` is **absent**. This is deployment drift, not
a reason to classify retained cases as LEGACY.

Existing accepted repair migrations were **not** improvised or applied:

- `migrations/add_phase1b_tranche_b_manifest_protocol.py`
- `migrations/add_case_file_ingest_protocol_origin.py`
- `migrations/add_phase1b_event_protocol_columns.py`

## Production Hunt smoke

Not performed. Services were not stopped or restarted because production schema
convergence did not complete.

## Production Gate B settings before

Absent from `SHOW CREATE TABLE events` / `engine_full`. Both default 0.

## Gate B migration application

**Not applied.** `migrations/add_events_block_number_offset.py --apply-production`
requires Phase 1B production schema to be verified/converged first.

No SQL UPDATE against production. No lightweight UPDATE on retained evidence.

## Gate B no-rewrite proof

Not applicable: the settings ALTER was not executed. Pre-change active
parts/rows/bytes remain 135 / 745,463,991 / 108,493,322,926.

## Production Gate B settings after

Unchanged: both settings still absent / 0.

## Final Gate B verdict

PHASE2_GATE_B_NOT_READY

Locked Gate B requires the settings **enabled on production events via
migration**, not merely that the migration file exists. Disposable benchmark
from 4.23.0 remains valid and was not re-run as a production UPDATE.

## Closure remaining work

Do not start Phase 2.1.

Required before Gate B can pass and before Phase 2.1:

1. Apply existing Phase 1B ClickHouse control-table migration so
   `visible_evidence_generations` and `durable_ingest_batches` exist in
   production `casescope` with the locked schemas
2. Apply existing `case_files.ingest_protocol_origin` migration
3. Apply existing additive `events` protocol-column migration (no backfill)
4. Apply Gate B `enable_block_number_column` / `enable_block_offset_column`
   with services stopped and no-rewrite proof
5. Independent Phase 2 entry-gate re-review
