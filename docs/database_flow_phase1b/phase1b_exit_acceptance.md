# Phase 1B EXIT Blocker Closure Evidence

Status: **final measurement closure complete**. This is not a new tranche and does not start Phase 2.

Independent Phase 1B EXIT ACCEPTANCE re-review remains the only remaining Phase 1B work.

Baseline for this measurement closure: `origin/main` `16bede5ac622820492b09813146ea9b3a351ec8a` (4.22.1 EXIT readiness blockers). Closure version: **4.22.2**.

## Three correctness closures

### 1. Reconciliation is not inspect-certified

`utils/case_readiness.py` `inspect_reconciliation_from_snapshot()` never returns `RECONCILED`.

Current / Reconciled requires a current F1 `CaseCompletionReconciliationAudit` whose generation fingerprint and batch counts still match PostgreSQL authority.

Inspect-only may still report proven `failed`, `blocked`, `incomplete_ingest`, `in_progress`, or `work_queued`. Gap-free inspect-only state is `pending_reconciliation` (`Needs reconciliation`). A stale prior reconciled audit remains stale until F1 runs again.

Repair for managed/mixed continues to use the existing F1 path.

Proof: `tests/test_phase1b_tranche_f2_readiness_ui.py::test_active_privacy_complete_without_f1_audit_is_not_reconciled`.

### 2. EOF is not Published

Ordinary non-zero managed evidence:

- ACTIVE → Published
- BUILDING_INITIAL before EOF with DURABLE rows → Searchable, still ingesting
- BUILDING_INITIAL after EOF before ACTIVE → Searchable, finalizing ingest

EOF, `completed_at`, or a STAGED/missing-ordinal/row-count gap cannot label the generation Published. Hunt publication semantics are unchanged. Search stays enabled for DURABLE BUILDING_INITIAL batches.

Proof: `test_eof_with_staged_or_missing_ordinal_is_not_published`, `test_zero_event_before_activation_is_not_published`.

### 3. Multi-source privacy is source-scoped

Source watermarks remain authoritative. A case-level contiguous ordinal is shown only for one relevant non-zero current source. Multiple current sources use qualitative wording and `contiguous_batch_ordinal = null`. Partial coverage across current sources must not claim another source's batch ordinal as case-wide proof. All current sources COMPLETE may show Covered. Zero-event COMPLETE sources do not get a fake ordinal. Replacement privacy remains secondary.

If managed authority is withdrawn and no current source remains, Privacy and Evidence say withdrawn, not Not started. `authorizes_ai_egress` stays false.

Proof: `test_multi_source_privacy_does_not_claim_case_wide_ordinal`, `test_invalidation_withdraws_stale_readiness`.

## Real PostgreSQL / ClickHouse lifecycle proof

`tests/test_phase1b_exit_blocker_closure.py::test_required_exit_lifecycle_proof` on `phase1b_f2_test`:

1. BUILDING_INITIAL starts
2. STAGED rows are Hunt-invisible
3. first DURABLE batch is searchable before EOF
4. privacy watermark advances contiguously
5. second DURABLE batch becomes searchable
6. EOF occurs
7. pre-activation UI is `finalizing`, not Published
8. activation → ACTIVE / Published
9. current F1 audit → Current
10. replacement N+1 Hunt-hidden
11. current N remains authoritative
12. replacement privacy does not downgrade current N
13. atomic activation N → SUPERSEDED / N+1 → ACTIVE
14. old reconciliation audit becomes stale
15. new F1 reconciliation makes current audit Current
16. invalidation withdraws evidence/privacy readiness
17. Redis loss changes only Live Activity
18. PG readiness failure never becomes ready/legacy
19. Hunt remains non-blocking throughout published states

Last measured lifecycle timings (IIS fixture, not the EVTX corpus):

- time-to-first-searchable (lifecycle start → Hunt visible): 376.0 ms
- first DURABLE to Hunt (`mark_batch_durable` → Hunt visible): 179.51 ms
- privacy batch completions: 17.897 / 8.688 / 10.894 ms
- completion reconciliation: 36.475 ms
- lifecycle wall: 1620.015 ms

## Phase 1B exit baseline measurement

Harness: `scripts/phase1b_exit_measure.py`.

Artifact: `docs/database_flow_phase1b/phase1b_exit_baseline.json`.

Isolation: disposable PostgreSQL/ClickHouse `phase1b_exit_ingest_20260821152852`. Production databases were not used.

Corpus: existing Phase 0A authorized EVTX set at `/opt/casescope-benchmark/phase0a_evtx` (8 files, 77,103,104 bytes, 110,742 events, includes `Security.evtx`). Deviation from locked preferred corpus: not >=20 EVTX, no memory image, no PCAP. That is the existing Phase 0/1 baseline corpus.

IOC full-run: not included. Phase 1.5 raw_json recall gate failed; no passing full-run baseline was shipped.

The 4.22.1 artifact stored ingest-start → first-searchable **19.515 s** under both `time_to_first_searchable_managed_seconds` and `first_durable_to_hunt`. That 19.515 s figure is **not** first DURABLE → Hunt. 4.22.2 times those origins separately at protocol boundaries.

Timed batch: `ingest-batch:v1:19328c306ba20690a7af7e264f5d3acf1a8e65afc5311234d99ea94a306c0c43`, `Application.evtx`, `case_id=1`, `source_ref_id=1`, `source_generation=1`, `batch_ordinal=0`, Hunt-visible row count 10000.

| Metric | Phase 0 | Phase 1 exit | Phase 1B exit |
|---|---:|---:|---:|
| Wall seconds | 332.884 | 136.869 | 237.647 |
| Events | 110,742 | 110,742 | 110,742 |
| Events / sec | 332.674 | 809.109 | 465.994 |
| Ingest / GB (s) | — | — | 3309.484 |
| Ingest / million events (s) | — | — | 2145.952 |
| First searchable (ingest start → Hunt visible, s) | 184.478 | 18.371 | 18.708 |
| First DURABLE → Hunt (s) | — | — | 0.176 |
| Peak RSS (MB) | 237.36 | 222.45 | 259.7 |

Phase 1B ingest is slower than Phase 1 because this measurement includes managed STAGED/DURABLE protocol, control-projection, first-searchable Hunt probes during ingest, then privacy-alias derivation and F1 reconciliation. No optimization pass was performed.

- First DURABLE offset: 18.531 s after ingest start
- Control projection complete offset: 18.669 s (`durable_to_projection_ms` 137.405)
- Hunt visible offset: 18.708 s (`durable_to_hunt_ms` 176.233)
- Privacy-alias time-to-ready: 9.104 s (16 DURABLE batches)
- Completion reconciliation: 0.1 s, assessment `work_queued` (transitional MITRE/embedding/discovery work remains queued; that is F1, not a false Reconciled UI state)
- Hunt count p50/p95/p99: 40.733 / 51.991 / 66.927 ms (20 samples)
- Hunt page p50/p95/p99: 60.554 / 76.35 / 84.121 ms
- Hunt count read_rows / read_bytes: 110,766 / 14,287,603
- `EXPLAIN indexes=1` stored in the JSON artifact. Events PK/partition still case-scoped; control projections are FINAL joins on the existing tables.

## Hunt publication bridge scale

Artifact: `docs/database_flow_phase1b/phase1b_exit_hunt_bridge_scale.json`.

Population: 401 `visible_evidence_generations`, 4801 `durable_ingest_batches` (40 extra cases × 10 sources × 12 batches plus the lifecycle case).

| | Unscoped (production) count | Case-scoped count |
|---|---:|---:|
| p50 ms | 18.652 | 19.963 |
| p95 ms | 22.676 | 25.750 |
| p99 ms | 25.895 | 27.515 |
| read_rows | 4808 | 4808 |
| read_bytes | 241719 | 241719 |

`read_row_ratio_unscoped_over_scoped = 1.0`. `material_unscoped_overhead = false`.

Case-scoping the FINAL control subqueries did not reduce rows or bytes read at this population. `durable_ingest_batches` primary-key condition remains `true` either way because the table is ordered by `ingest_batch_id`, not `case_id`. Production Hunt therefore remains unscoped. No `events_current` and no Phase 2 index work.

## Regression

| Suite | Result |
|---|---|
| Focused first-DURABLE-to-Hunt origin split | PASS (`Phase1BExitFirstDurableHuntMeasurementTestCase`) |
| F2 readiness UI + Redis-loss + PG-failure + completion repair | PASS |
| F2 Hunt publication gate | PASS |
| EXIT blocker lifecycle + Hunt scale + no-later-phase | PASS |

## No-later-phase audit

- Phase 2 ClickHouse modernization: **NO**
- Phase 3 ERK API migration: **NO**
- Phase 4: **NO**
- `event_observations_current`: **NO**
- `events_current`: **NO**
- LEK: **NO**
- Broad reader migration: **NO**
- Qdrant / MEMORY_JOB / PCAP generation adoption: **NO**
- New capability migrations: **NO**
- Production Hunt publication semantics unchanged: **YES**

Hunt still reads `events` plus the existing control-projection bridge.

## Remaining work

Independent Phase 1B EXIT ACCEPTANCE re-review only.

Do not start Phase 2.
