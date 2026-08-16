# Phase 1B Tranche D1 Generation Lifecycle Certification

## Scope

Tranche D1 implements CASE_FILE managed generation lifecycle authority only. It does not implement the D2 stale-STAGED reconciler, capability watermarks, derivation migration, AI freeze/verify, reader cutover, `events_current`, LEK migration, graph/Qdrant lifecycle migration, MEMORY_JOB/PCAP generations, historical backfill, or ClickHouse `OPTIMIZE FINAL`.

## Schema And Migration

- `evidence_source_generations` now has `final_batch_ordinal`, `activated_at`, `superseded_at`, and `superseded_by_generation`.
- `final_batch_ordinal` is nullable and nonnegative when present.
- `evidence_generation_audit` records PostgreSQL-authoritative generation transitions with case/source identity, prior/new active generation numbers, actor, reason, transition, and timestamp.
- The additive D1 migration is `migrations/add_phase1b_tranche_d1_generation_lifecycle.py`.
- Existing control-plane table creation also includes the audit table.

## Generation Allocation

- Initial managed CASE_FILE ingest allocates generation `1` in `BUILDING_INITIAL`.
- Explicit managed reprocess of an `ACTIVE` managed CASE_FILE allocates a new monotonically increasing `BUILDING_REPLACEMENT` generation.
- The active generation is not mutated into a replacement.
- Failed generation numbers are not reused.
- PostgreSQL partial indexes preserve at most one `ACTIVE` generation and at most one open building generation per source.

## Durable EOF / Completeness Declaration

D1 does not infer completeness from a lack of STAGED batches. `declare_generation_ingest_complete()` writes the durable EOF declaration only after parser enumeration completes successfully.

The declaration records:

- `completed_at`
- `expected_rows`
- `final_batch_ordinal` for non-empty generations
- `NULL final_batch_ordinal` for legitimate zero-event generations

A worker that dies after durable batches `0..N` but before reserving the next batch cannot activate the generation, because `completed_at`, `expected_rows`, and `final_batch_ordinal` remain absent.

Zero-event semantics are explicit: `expected_rows = 0`, `completed_at IS NOT NULL`, `final_batch_ordinal IS NULL`, and no ingest batch rows. No fake event and no fake batch are created.

## Activation Completeness

Activation checks lock the generation batches and require:

- durable EOF declaration
- expected row count
- known final ordinal for non-empty generations
- exact contiguous batch ordinals `0..final_batch_ordinal`
- every required batch in `DURABLE`
- no missing or extra expected ordinal
- summed durable `row_count` equals declared `expected_rows`
- no currently declared activation-blocking derivation requirements

D1 leaves `_declared_activation_requirements()` empty because no implemented Phase 1B path currently declares derivation capability readiness as activation-blocking. It does not fabricate future derivation/watermark state.

## Initial Activation

After completeness succeeds, `activate_initial_generation()` transitions:

`BUILDING_INITIAL -> ACTIVE`

It sets `activated_at`, increments `state_version`, and writes a generation audit row in the same PostgreSQL transaction.

## Managed Reprocess Routing

Managed active sources remain managed even when the global adoption flag is off. For an existing managed `ACTIVE` CASE_FILE, routing returns managed replacement mode and does not fall back to legacy cleanup.

The single-file rebuild/reprocess task detects an existing managed `ACTIVE` generation and queues `parse_file_task` directly. It bypasses `_delete_standard_case_file_scope`, so UI-triggered managed reprocess uses replacement allocation rather than broad CaseFile deletion.

Legacy sources with `legacy_or_unknown` remain legacy. Deferred parsers remain legacy. D1 does not adopt historical files.

## Replacement Lifecycle

Replacement build state:

`N ACTIVE + N+1 BUILDING_REPLACEMENT`

Replacement generation rows and raw ClickHouse rows can physically coexist with the active generation. The replacement remains hidden from the generation-aware visible resolver until activation.

Terminal replacement failure transitions only the replacement:

`N+1 BUILDING_REPLACEMENT -> FAILED`

The prior `N ACTIVE` generation remains unchanged and visible. A later reprocess allocates `N+2`.

## Atomic Activation

`activate_replacement_generation()` locks all source generations and performs one PostgreSQL transaction:

- prior `ACTIVE` generation becomes `SUPERSEDED`
- prior `state_version` increments
- prior `superseded_at` and `superseded_by_generation` are set
- replacement `BUILDING_REPLACEMENT` becomes `ACTIVE`
- replacement `state_version` increments
- replacement `activated_at` is set
- audit row is inserted

Rollback injection after the first state update proves the transaction restores:

`N ACTIVE + N+1 BUILDING_REPLACEMENT`

No no-active or two-active state is committed.

## ClickHouse Projection

PostgreSQL remains authority. D1 projects generation authority to `visible_evidence_generations` and durable batch state to `durable_ingest_batches`.

- `BUILDING_INITIAL` remains publishable under the existing progressive-initial control model.
- `BUILDING_REPLACEMENT` is not publishable.
- `ACTIVE` is publishable.
- `SUPERSEDED` and `FAILED` are not publishable.

Projection ordering uses `state_version` in the ClickHouse replacing table. The D1 real PG/CH test inserts a stale lower-version active projection after replacement activation and verifies the resolver still returns the replacement generation.

## Real Database Proofs

Executed with:

`PHASE1B_PG_TEST_DATABASE_URL=postgresql://casescope:casescope@localhost/phase1b_d1_test`

`PHASE1B_CH_TEST_DATABASE=phase1b_d1_test`

Result:

`tests/test_phase1b_tranche_d1_generation_lifecycle.py`: 16 passed, 6 subtests passed

The real PG/CH proof covers initial activation, replacement allocation, replacement hiddenness, physical coexistence, deterministic batch ID changes by generation, atomic replacement activation, audit rows, stale projection resistance, rollback injection, and PostgreSQL open-building constraint behavior.

## Regression Evidence

Focused D1/protocol/routing:

`tests/test_phase1b_tranche_d1_generation_lifecycle.py tests/test_phase1b_tranche_b_protocol.py tests/test_phase1b_tranche_b_routing.py`: 28 passed, 2 skipped when real DB env was not set.

Certified managed parser regressions:

`tests/test_phase1b_tranche_c1_managed_integration.py tests/test_phase1b_tranche_c2_evtx_safety.py tests/test_phase1b_tranche_c3a_structured_parsers.py tests/test_phase1b_tranche_c3b_mft_usn.py tests/test_phase1b_tranche_c3c_registry_jumplist.py tests/test_phase1b_tranche_c3d1_sqlite.py tests/test_phase1b_tranche_c3d2b_search_eventtranscript.py`: 30 passed, 10 skipped.

## Legacy Protection

Managed lifecycle tests include tripwires that raise if CaseFile-wide legacy cleanup or rebuild delete scope is called during managed replacement. The managed active source with global flag off uses managed replacement mode and succeeds without broad cleanup.

## D1 CLOSURE — MANAGED REBUILD ROUTING

### Root Cause

The previous D1 result was `PHASE1B_TRANCHE_D1_NOT_READY` because `rebuild_single_case_file_task` could enter `_delete_standard_case_file_scope` before managed replacement routing. For an `ACTIVE` managed CaseFile this was unacceptable: generation N must remain authoritative and physically present while generation N+1 builds.

### Rebuild Path Before

The single-file rebuild path resolved the retained original, built a delete scope, and then called `_delete_standard_case_file_scope(..., lifecycle_mode='revalidation')`. That helper can call `delete_file_events` and delete CaseFile metadata for legacy rebuilds, so a managed source could have been routed through CaseFile-wide legacy cleanup before replacement generation allocation.

### Rebuild Path After

`rebuild_single_case_file_task` now checks for `ingest_protocol_origin == 'manifest_initial'` and an open managed `EvidenceSourceGeneration` before any legacy delete scope. `ACTIVE` queues `parse_file_task` and returns `mode='managed_replacement'`; `BUILDING_INITIAL` queues `parse_file_task` and returns `mode='managed_initial_retry'`. Both return `records_deleted=0` and `events_deleted=0`.

The revalidation guard in `_delete_standard_case_file_scope` also raises if a managed `BUILDING_INITIAL`, `ACTIVE`, or `BUILDING_REPLACEMENT` source reaches that legacy cleanup helper. Its generation-model imports are lazy and only used on revalidation paths, preserving legacy test stubs while keeping the managed tripwire.

### Repo-Wide Reprocess Matrix

| Entry point | Legacy source behavior | Managed BUILDING_INITIAL behavior | Managed ACTIVE behavior | Deferred parser behavior | Broad cleanup possible? |
|---|---|---|---|---|---|
| `routes/ingest._queue_registered_files` -> `queue_case_files_for_parsing` -> `parse_file_task` | Queues parse; `parse_file_task` selects legacy and runs `_cleanup_case_file_events` before parser insert. | Queues parse; `select_case_file_ingest_mode` pins existing BUILDING_INITIAL and reuses the managed generation contract. | Queues parse; managed replacement mode allocates BUILDING_REPLACEMENT. | Selects legacy for new/deferred parser sources. | Legacy only. Managed no. |
| `tasks.process_case_files_task` -> `queue_case_files_for_parsing` -> `parse_file_task` | Same as normal queue path. | Same managed BUILDING_INITIAL retry path. | Same managed replacement path. | Same legacy path. | Legacy only. Managed no. |
| `routes/case_files.recover_stuck_files` -> `parse_file_task` | Requeues staging files; legacy cleanup remains legacy. | Requeued managed BUILDING_INITIAL remains managed. | Requeued managed ACTIVE routes to replacement if parser contract matches. | Deferred parser remains legacy. | Legacy only. Managed no. |
| `routes/parsing.process_single_file` -> `rebuild_single_case_file_task` | Uses retained-original rebuild, `_delete_standard_case_file_scope`, and `_ingest_standard_rebuild_entries`. | Detects managed BUILDING_INITIAL before delete scope, queues `parse_file_task`, returns `managed_initial_retry`. | Detects managed ACTIVE before delete scope, queues `parse_file_task`, returns `managed_replacement`. | Deferred parser remains legacy through parse selection. | Legacy only. Managed BUILDING_INITIAL/ACTIVE no. |
| `tasks.reindex_case_task` full case rebuild | Clean-slate case rebuild deletes case events and CaseFile rows, then re-ingests retained originals as new legacy/adoptable rows. | Not a per-CaseFile managed reprocess path; it is a whole-case destructive rebuild. | Not D1 replacement lifecycle; explicit full-case reset remains legacy/destructive. | Legacy/deferred remains legacy. | Yes by design for full-case rebuild, not D1 managed replacement. |
| `parse_file_task` direct Celery retry/redelivery | Legacy retries run `_cleanup_case_file_events` before reinserting. | Existing managed BUILDING_INITIAL is selected with global flag off and uses deterministic same-generation retry. | Existing managed ACTIVE uses replacement mode. | Deferred parser remains legacy. | Legacy only. Managed no. |
| `delete_case_events_task`, file delete routes, permanent case deletion | Destructive deletion paths, not reprocess/rebuild. | Deletion/invalidation scope is outside D1 reprocess. | Deletion/invalidation scope is outside D1 reprocess. | Not applicable. | Yes by deletion design, not a rebuild/reprocess path. |

### Broad Cleanup Tripwire Proof

The closure tests patch these cleanup paths to raise immediately during managed BUILDING_INITIAL and ACTIVE rebuild:

- `_delete_standard_case_file_scope`
- `_cleanup_case_file_events`
- `utils.clickhouse.delete_file_events`
- `utils.clickhouse.delete_case_events`

Both managed rebuild paths still succeed. Therefore no managed BUILDING_INITIAL or ACTIVE reprocess/rebuild path proven in D1 can call CaseFile-wide legacy cleanup.

### Full Lifecycle Rerun

`tests/test_phase1b_tranche_d1_generation_lifecycle.py` now covers durable EOF declaration, known-durable-without-EOF activation refusal, zero-event completion, initial activation, managed BUILDING_INITIAL rebuild retry routing, replacement allocation, monotonic generation numbering, failed generation number non-reuse, replacement hiddenness, deterministic replacement batches, atomic swap, rollback injection, failed replacement preserving N ACTIVE, N+2 after failed N+1, concurrent reprocess, concurrent activation, audit rows, stale/lower `state_version` projection rejection, physical N/N+1 coexistence, and no broad delete.

### Real PG/CH Rebuild Proof

The closure test uses a certified managed IIS parser fixture against disposable PostgreSQL and ClickHouse. It proves:

- N is ACTIVE and has 11 raw ClickHouse rows.
- `rebuild_single_case_file_task` detects managed ACTIVE before cleanup.
- No broad cleanup tripwire fires.
- `parse_file_task` runs the managed replacement lifecycle with the global flag off.
- N+1 is allocated as BUILDING_REPLACEMENT, ingested as STAGED -> ClickHouse -> DURABLE, and atomically activated.
- N rows remain physically present after swap.
- N+1 is the generation-aware projected authority after activation.

### Concurrency Exact Results

Concurrent reprocess with two independent PostgreSQL sessions:

- one caller committed N+1 as BUILDING_REPLACEMENT;
- the other caller received `ReplacementInProgressError`;
- final states were exactly `{1: ACTIVE, 2: BUILDING_REPLACEMENT}`;
- no N+2 builder was allocated.

Concurrent activation with two independent PostgreSQL sessions:

- both callers returned generation 2 ACTIVE;
- exactly one authority swap committed;
- final states were exactly `{1: SUPERSEDED, 2: ACTIVE}`;
- exactly one ACTIVE generation remained;
- exactly one `BUILDING_REPLACEMENT_TO_ACTIVE` audit row existed.

### Known Failures And Environment Notes

- `tests/test_clickhouse_delete_dedup_contracts.py` initially exposed D1 import placement issues in legacy stubs after the managed cleanup guard was added. This was a D1-caused regression and was fixed by lazy managed-only imports/string origin comparison. The file now passes: 35 passed.
- Follow-up audit found a managed BUILDING_INITIAL single-file rebuild gap. This was a D1 closure blocker and was fixed by routing BUILDING_INITIAL rebuilds to `parse_file_task` as `managed_initial_retry`, plus broad cleanup tripwire coverage.
- Combined broad tranche runs can fail C2 with `IngestAdmissionDenied: exclusive_held` if earlier tests in the same process leak real Redis ingest-fence keys. Isolated C2 with cleared `casescope:ingest_fence:v1*` keys passes. The final broad gate was therefore run sequentially by tranche group to avoid cross-test Redis contamination.
- The previously noted diagnostic parser `metadata_only` versus `parse_error` mismatch was not exercised by the D1 closure gates run here and was not changed by D1.

### Closure Regression Results

- C3E parser coverage: 84 registered, 12 certified managed, 72 deferred legacy only, 0 unclassified.
- Focused D1 real PG/CH: 16 passed, 6 subtests passed.
- Broad Phase1B A/B/C/D1 tranche suite, run sequentially by tranche group: 117 passed, 35 subtests passed.
- Retry/task failure/ingest fence: 31 passed.
- ClickHouse delete/dedup contracts: 35 passed.
- Graph regression group: 170 passed, 2 skipped.
- Privacy/completion group: 83 passed, 44 subtests passed.
- `py_compile` over tracked Python files: passed.
- `pyflakes` on changed files: passed.
- `git diff --check`: passed.

## No-Cutover Audit

- Capability watermarks: no
- Derivation migration: no
- AI freeze/verify: no
- Reader migration: no
- `events_current`: no
- LEK cutover: no
- D2 stale-STAGED reconciler: no

## Verdict

The implemented D1 lifecycle is ready for review subject to the full regression run remaining green in the local environment.
