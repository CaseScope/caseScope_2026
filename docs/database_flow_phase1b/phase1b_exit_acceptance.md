# Phase 1B EXIT Blocker Closure Evidence

Status: **blocker closure complete**. This is not a new tranche and does not start Phase 2.

Independent Phase 1B EXIT ACCEPTANCE re-review remains the only remaining Phase 1B work.

Baseline for this closure: `origin/main` `9aaafaf3ce13ccb9eee7676a9ec636637b16b765` (4.22.0 F2 UI). Closure version: **4.22.1**.

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

- time-to-first-searchable: 286.19 ms
- first DURABLE to Hunt: 286.19 ms
- privacy batch completions: 21.723 / 9.591 / 10.435 ms
- completion reconciliation: 22.651 ms
- lifecycle wall: 1441.682 ms

## Phase 1B exit baseline measurement

Harness: `scripts/phase1b_exit_measure.py`.

Artifact: `docs/database_flow_phase1b/phase1b_exit_baseline.json`.

Isolation: disposable PostgreSQL/ClickHouse `phase1b_exit_ingest_20260821142146`. Production databases were not used.

Corpus: existing Phase 0A authorized EVTX set at `/opt/casescope-benchmark/phase0a_evtx` (8 files, 77,103,104 bytes, 110,742 events, includes `Security.evtx`). Deviation from locked preferred corpus: not >=20 EVTX, no memory image, no PCAP. That is the existing Phase 0/1 baseline corpus.

IOC full-run: not included. Phase 1.5 raw_json recall gate failed; no passing full-run baseline was shipped.

| Metric | Phase 0 | Phase 1 exit | Phase 1B exit |
|---|---:|---:|---:|
| Wall seconds | 332.884 | 136.869 | 245.202 |
| Events | 110,742 | 110,742 | 110,742 |
| Events / sec | 332.674 | 809.109 | 451.636 |
| Ingest / GB (s) | — | — | 3414.696 |
| Ingest / million events (s) | — | — | 2214.173 |
| First searchable (s) | 184.478 | 18.371 | 19.515 |
| Peak RSS (MB) | 237.36 | 222.45 | 288.71 |

Phase 1B ingest is slower than Phase 1 because this measurement includes managed STAGED/DURABLE protocol, control-projection, first-searchable Hunt probes during ingest, then privacy-alias derivation and F1 reconciliation. No optimization pass was performed.

- Privacy-alias time-to-ready: 9.091 s (16 DURABLE batches)
- Completion reconciliation: 0.099 s, assessment `work_queued` (transitional MITRE/embedding/discovery work remains queued; that is F1, not a false Reconciled UI state)
- Hunt count p50/p95/p99: 39.931 / 49.104 / 67.469 ms (20 samples)
- Hunt page p50/p95/p99: 59.452 / 73.233 / 73.713 ms
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
| F2 readiness UI + Redis-loss + PG-failure + completion repair | PASS |
| F2 Hunt publication gate | PASS (8 tests, product request 85.894 ms, extra Hunt SELECT round-trips 0) |
| F1 completion reconciliation + fail-closed | PASS (35 tests; `PYTEST_CURRENT_TEST` set so the pytest-disabled scheduler contract holds under unittest) |
| D1 lifecycle | PASS |
| D2 reconciler | PASS |
| E1 watermarks | PASS |
| E2 privacy freeze/send | PASS |
| C3E parser inventory | PASS: 84 registered, 12 CERTIFIED_MANAGED, 72 DEFERRED_LEGACY_ONLY, 0 unclassified |
| Route security | 1 pre-existing failure on origin/main, out of this closure's locked scope: `test_tag_artifacts_start_routes_to_ioc_queue_and_tracks_task_access` still expects `apply_async(args=(11,), queue='ioc')` while `routes/iocs.py` on the F2 baseline already passes `(case.id, username, remote_ip)`. This closure did not change IOC routes. |

## No-later-phase audit

- Phase 2 ClickHouse modernization: **NO**
- Phase 3 ERK API migration: **NO**
- `event_observations_current`: **NO**
- `events_current`: **NO**
- LEK: **NO**
- Broad reader migration: **NO**
- Qdrant / MEMORY_JOB / PCAP generation adoption: **NO**
- New capability migrations: **NO**

Hunt still reads `events` plus the existing control-projection bridge.

## Remaining work

Independent Phase 1B EXIT ACCEPTANCE re-review only.

Do not start Phase 2.
