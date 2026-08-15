# Phase 1 Step 3 Report

Status: STEP3_ACCEPTED. IOC raw_json optimization NOT SHIPPED because the recall gate failed. Profiler set-based rewrite SHIPPED. Full Phase 1 is not complete.

## 1. Starting State

- Remote main and local HEAD: locked baseline `8c4c1dd` (version `4.18.5`). Remote main has not moved.
- Phase 0A, Phase 0B, Phase 1 Step 1, and Phase 1 Step 2 are ACCEPTED.
- Authorized scope this pass: Phase 1.5 (IOC recall gate) and Phase 1.6 (profiler set-based rewrite) only.
- Pre-existing/unowned worktree files were preserved. No commit. No push. No PR.
- Accepted contracts were not revised. No `CONTRACT_IMPLEMENTATION_BLOCKER`.

## 2. Accepted Step 2 State

Approved corpus `/opt/casescope-benchmark/phase0a_evtx/`: 8 EVTX, 77,103,104 bytes, 110,742 parsed events.

| | wall | events/sec | MB/sec | RSS |
|---|---:|---:|---:|---:|
| Phase 0 | 332.884 s | 332.674 | 0.221 | 237.36 MB |
| Step 1 | 148.408 s | 746.198 | 0.495 | 226.29 MB |
| Step 2 official | 152.325 s | 727.01 | 0.483 | 233.21 MB |
| Phase 0 to Step 2 | 2.185x | | | |

Step 2 semantic: exact ERK parity; 0 deterministic event differences; contracted CMMC_CUI aliases = 1,152; production runtime Buffer dependencies = 0; FENCE_PASS. ERK set digest matches Step 1 (`phase1_step2_results.json`).

Step 2 also recorded a loaded-host investigation run at 196.734 s (EvtxECmd/Hayabusa colder), which is the relevant comparison for this pass's ingest rerun.

## 3. IOC Current Architecture

Entry: Celery `tasks.tag_iocs_for_case` then `utils/ioc_artifact_tagger.py::tag_all_iocs_globally`.

Pipeline:

1. Eligible IOCs: `case_id` match, `active IS TRUE`, `false_positive IS FALSE`.
2. `reset_ioc_types_for_case` / `start_ioc_refresh` allocates a UUID scan/run id (not `derivation_version`).
3. `begin_ioc_match_scan` marks existing `IOCEvidenceMatch` rows `PENDING_REVALIDATION`.
4. Per IOC: `detect_match_type` or stored match type, then `search_artifacts_for_ioc`, `mark_events_with_ioc_type`, `record_ioc_evidence_matches`.
5. `finalize_ioc_match_scan` invalidates rows still pending.

Match types:

- token: `hasTokenCaseInsensitive(col, needle)`; falls back to substring if the needle contains token separators.
- substring: `lower(col) LIKE`; path-like values use percent-joined segments.
- regex: `match(lower(col), pattern)` with unsafe-pattern fallback to substring.

Needles are lowercased when building LIKE/regex. Stored `search_blob`, `raw_json`, and `username` are not canonical lowercase.

Fields searched on the common path:

- Default: `raw_json` OR `search_blob`.
- Username: `username` OR `raw_json` OR `search_blob`, plus display-name forward/reverse variants.
- `extra_fields` is not searched.
- Typed columns are not on the common path.

Aliases: File Name aliases are OR-ed. Other aliases AND with the primary clause (two-tier SQL). No post-query Python filtering of the ERK set.

Provenance (`utils/ioc_match_provenance.py`): streams ERKs with the same `build_ioc_match_clause`. `IOCEvidenceMatch.matched_field` defaults to `search_blob` and is not the actual hit field. ERK provenance was not changed. Lifecycle: begin scan, PENDING_REVALIDATION, upsert ACTIVE, finalize INVALIDATED. IOC storage was not redesigned.

## 4. IOC Legacy Set A

Dry-run comparator: `utils/phase1_step3_ioc_recall.py` and `scripts/phase1_step3_run.py`. Does not mutate IOC rows, `IOCEvidenceMatch`, or `events.ioc_types`.

A is the exact `(case_id, ERK, ioc_uuid)` set from the current production clause. Each match records case, ERK, IOC UUID/type, matched-field classification, and which candidate path is compared.

| Corpus | Events | IOCs | A matches | Notes |
|---|---:|---:|---:|---|
| Deterministic fixtures (disposable CH) | 14 | 13 | 15 | typed-only, blob-only, raw_json-only, nested JSON, mixed-case, IPv4/IPv6, hash, URL, path, token ltsvc, substring d.bat |
| Retained case 33 (read-only) | ~131k EVTX | 6 | 0 | Vacuous A=B |
| Retained case 10 (read-only) | ~2.4M mixed | 6 | 61 | EVTX, registry, MFT, browser, Huntress/EDR |

Full 745M+ production event scan was treated as operationally unsafe. Stratified coverage plus fixtures for shapes retained IOCs do not hit. IOC-searchable artifact types are whatever lands in `events`.

## 5. IOC Candidate Set B

Paths measured independently against the same snapshot as A (not combined):

1. `no_lower_sensitive` — drop `lower()`; case-sensitive LIKE/match.
2. `ilike` — `col ILIKE`; keep `hasTokenCaseInsensitive`.
3. `no_raw_json` — `search_blob` only (Username also keeps `username`).
4. `structured_plus_search_blob` — typed columns for the IOC type plus `search_blob`, no `raw_json`.

## 6. A-B Recall Analysis

Fixtures (A=15):

| Path | B | A-B | B-A | Gate |
|---|---:|---:|---:|---|
| `no_lower_sensitive` | 13 | 2 | 0 | IOC_FAIL |
| `ilike` | 15 | 0 | 0 | IOC_PASS |
| `no_raw_json` | 13 | 2 | 0 | IOC_FAIL |
| `structured_plus_search_blob` | 13 | 2 | 0 | IOC_FAIL |

Case 10 (A=61):

| Path | B | A-B | Gate |
|---|---:|---:|---|
| `ilike` | 61 | 0 | IOC_PASS |
| `no_raw_json` | 58 | 3 | IOC_FAIL |
| `structured_plus_search_blob` | 58 | 3 | IOC_FAIL |

Case 33: A=B=0 for all paths (vacuous PASS; not used as the recall gate).

A-B must be empty before `raw_json` may leave the common path. It is not empty.

## 7. Raw-JSON-Only Match Classification

Fixture A-B for `no_raw_json` / `structured_plus_search_blob` (2), both `RAW_JSON_ONLY_TRUE_MATCH`:

- Domain `nested-json.example` in nested `raw_json` (`EventData.Network.Dest`); absent from `search_blob`.
- Domain `rawjson-only.example` in unmapped `raw_json`; absent from `search_blob`.

These are valid legacy matches. Not `LEGACY_FALSE_POSITIVE`. Dumping entire `raw_json` into `search_blob` is forbidden. Nested/unmapped JSON is why `raw_json` exists on the common path.

Case 10 A-B (3), all `RAW_JSON_ONLY_TRUE_MATCH` (also a Huntress blob/typed omission candidate):

- IOC UUID `d866a4e7-6496-47e3-94e6-ae20116b7b74`, type SHA256 Hash
- Three Huntress ERKs; exact keys and hit-field booleans are in `phase1_step3_ioc_case10.json`
- Hash present in `raw_json`; absent from `search_blob`; absent from `file_hash_sha256`

Not repaired in this step. Even a Huntress blob/typed promotion would not cover the fixture nested/unmapped class, so `raw_json` still cannot leave the common path. Typed-column promotion is Phase 1.8.

Sensitive-path fixture misses (mixed-case domain + path case) classified `OTHER` / `NORMALIZATION_DIFFERENCE`: stored fields are not canonical lowercase.

## 8. lower() / EXPLAIN Findings

ClickHouse 26.7.3.19. Stored IOC common-path columns are not canonicalized. `CANONICAL_STORED_COLUMNS` for this path is empty.

Fixture table (14 rows): EXPLAIN is not meaningful for pruning (1 granule).

Production read-only `EXPLAIN indexes=1` on case 4 (needle `powershell`; 8 parts / 20,363 case granules after partition prune):

| Predicate | Granules | Skip indexes |
|---|---:|---|
| `lower(raw_json/search_blob) LIKE` | 20,363 | none |
| `ILIKE` | 20,363 | none |
| `hasTokenCaseInsensitive` | 20,363 | none |
| `lower(search_blob) LIKE` | 20,363 | none |
| case-sensitive `search_blob LIKE` | 13,858 | ngram and token bloom |

ILIKE matches recall on the comparison corpus but has no granule win versus `lower()`. Case-sensitive LIKE prunes but fails recall. Decision: do not ship ILIKE and do not globally remove `lower()`. Phase 2 text index with a `lower` preprocessor remains the planned path.

## 9. IOC Changes Shipped

Production default path is unchanged: `lower(raw_json)` plus `lower(search_blob)` (Username also `username`).

Shipped additive comparator hooks only: `columns` and `case_mode` on `build_ioc_match_clause`. Callers that omit the new arguments keep legacy SQL. No overlay migration. No ERK provenance change. No `IOCEvidenceMatch` semantic change.

## 10. IOC Recall Verdict

- Production recall: not regressed (clause unchanged).
- `raw_json` removal: IOC_FAIL (A-B not empty on fixtures and case 10).
- `lower()` removal: IOC_FAIL.
- ILIKE: recall-OK, no index win; not shipped.

IOC raw_json optimization NOT SHIPPED because recall gate failed. Recall beats speed.

## 11. Profiler Current Architecture

`utils/behavioral_profiler.py`. Counting basis remains current Phase 1 row `count()` over `events` (not LEK). Time bounds: `utils/event_time_window.py` plus `MIN_VALID_EVENT_TIME`. Timezone: `timestamp_utc` converted with case TZ.

Users (KnownUser):

- Predicate: `lower(username) = … OR sid = …`
- Input: all KnownUsers for the case.
- GROUP BY hour/day/date/event_id/source_host/remote_host/auth_package/logon_type.
- Skip profile if total events < `ANALYSIS_MIN_EVENTS_FOR_PROFILE` (default 10).
- Aggregates: activity hours/days, peak hours, off-hours percent, logons, auth types, typical hosts, daily stats, anomaly thresholds.

Systems (KnownSystem):

- Predicate: `upper(source_host) OR upper(workstation_name) OR upper(remote_host)` equals hostname.
- Stored `SystemBehaviorProfile` is one combined OR profile. Roles are distinct match predicates; they must not be UNION ALL-summed into `total_events`. Role-tagged counts are diagnostics in the same pass, not the profile total.

Legacy query shape: one ClickHouse statement per principal (N+1). Per-principal `_calculate_user_profile` / `_calculate_system_profile` remain for contract tests.

## 12. Legacy Profiler Output

Comparator: `utils/phase1_step3_profiler.py::capture_profiles(mode='legacy')`. Read-only; no PG profile writes. Canonical records ignore row order.

USERS: identity ref, username, SID, event count, first/last seen, aggregates (activity hours/days, peak core, typical hosts core, auth, logon rates).

SYSTEMS: hostname, combined OR event count / first / last, aggregates; role-tagged `source_host` / `workstation_name` / `remote_host` counts recorded separately and not summed into `total_events`.

## 13. Set-Based Design

First ARRAY JOIN design reduced statements (101 to 3) but was slower. Replaced with:

- 1 user query: `lower(username) IN … OR sid IN …`, GROUP BY username,sid,hour,… then Python maps each grouped row onto every KnownUser that matches username or SID, counting the row once per user.
- 1 system query: the three role columns IN known hostnames, GROUP BY those role columns plus aggregates; Python OR-maps without double-counting the combined profile; role stats accumulated in the same pass.

`profile_users` / `profile_systems` now call the set-based fetch then `_materialize_*_profile`. Statement count is 2, independent of principal count.

## 14. Profiler Semantic Parity

| Case | Principals | Parity | Notes |
|---|---|---|---|
| 33 small | 6 users / 8 systems | green | system digest differs only on existing top-N ties; stable-core compare equal |
| 8 medium | 26 / 5 | green | digests equal |
| 4 high-N sample | 80 / 20 of 353 / 47 | green | digests equal |

Zero unexplained semantic differences. Username-OR-SID preserved. Hostname roles preserved and not collapsed into one undifferentiated relation for `total_events`.

## 15. Query Count Delta

| Case | Legacy statements | Set-based | Bound |
|---|---:|---:|---|
| 33 | 15 | 2 | 2 |
| 8 | 32 | 2 | 2 |
| 4 sample | 101 | 2 | 2 |

Full case 4 (353 users / 47 systems) would be about 400 legacy statements to 2. Query count is bounded and independent of principal count.

## 16. Profiler Performance Delta

| Case | Legacy wall / CH wall / rows | Set-based wall / CH wall / rows | RSS |
|---|---|---|---:|
| 33 | 363 ms / 308 ms / 34,555 | 183 ms / 108 ms / 33,897 | 107 MB |
| 8 | 2.89 s / 1.48 s / 613,467 | 3.13 s / 1.59 s / 613,587 | 324 MB |
| 4 sample | 48.7 s / 38.3 s / 3,646,243 | 26.3 s / 12.4 s / 3,681,934 | 1,534 MB |

Case 8 is slightly slower at low principal count. High-N case 4 is about 1.85x faster with 101 to 2 statements. Rows transferred stay at grouped aggregates, not raw events. RSS for the case 4 capture includes both modes in one process.

## 17. Focused Tests

Focused suites only. No production-bound full unittest discovery. No production DB writes for testing.

165 tests OK this verification pass:

- `tests.test_phase1_step3` (16)
- `tests.test_ingest_fence` (23)
- `tests.test_phase1_step1` (18)
- `tests.test_phase1_step2` (13)
- `tests.test_parser_retry_cleanup` (3)
- `tests.test_clickhouse_delete_dedup_contracts` (35)
- `tests.test_clickhouse_destructive_lock` (3)
- `tests.test_ingest_metrics` (6)
- `tests.test_privacy_fail_closed` (10)
- `tests.test_graph_support_lifecycle` (19)
- `tests.test_ioc_artifact_tagger` (6)
- `tests.test_behavioral_profiler_contract` (11)
- `ParserHardeningTestCase` delete_file_events methods (2)

Step 1/2 fence, alias, retry-cleanup, and IOC/graph lifecycle contracts remain green.

## 18. EVTX Regression Benchmark

Same 8-file corpus. Disposable PG/CH `phase0a_ingest_20260814212141`, batch 10,000, no Buffer. Cleaned up after the run.

| Metric | Step 2 official | Step 3 |
|---|---:|---:|
| wall | 152.325 s | 194.706 s |
| events/sec | 727.01 | 568.765 |
| peak RSS | 233.21 MB | 228.87 MB |
| parsed events | 110,742 | 110,742 |
| ERK digest | Step 2 accepted | identical |
| CH inserts | 16 / 5.439 s | 16 / 6.712 s |
| EvtxECmd | 45.214 s | 60.201 s |
| Hayabusa | 45.798 s | 66.219 s |
| JSONL consume | 74.616 s | 88.896 s |

Step 3 did not change ingest parsers, fence, or insert destination. The wall delta is EvtxECmd +14.99 s, Hayabusa +20.42 s, JSONL +14.28 s — the same loaded-host band as Step 2's 196.734 s investigation run. ERK/alias/Buffer facts are unchanged. Not treated as a Step 3 code regression.

## 19. Existing Correctness Defects

Documented, not silently fixed:

1. EXISTING_PROFILER_CORRECTNESS_DEFECT: `_get_top_n` / `peak_hours` ties follow dict insertion order (stable sort by count only). Comparator uses a stable core (counts strictly above the 10th-place cutoff) plus a stable peak from `activity_hours`. Production `_get_top_n` left unchanged.
2. `IOCEvidenceMatch.matched_field` is always `search_blob` even when the hit is `raw_json` or a typed column. Existing provenance contract; overlay migration is Phase 3, out of scope.
3. Huntress SHA256 values can exist only in `raw_json` (search_blob/typed-column omission). Classified as valid raw_json-only matches; repair deferred to 1.5 blob work / 1.8 typed columns.

No new profiler semantic bugs were introduced under the parity gate.

## 20. Step 3 Verdict

**STEP3_ACCEPTED**

- IOC valid-match recall has zero regression (production clause unchanged).
- `raw_json` was not removed; A-B=0 was not satisfied for that candidate.
- Profiler semantic parity is green.
- Profiler query count is bounded at 2 statements.
- Accepted Step 1/2 semantics remain green.
- No unresolved Step 3 code regression. Ingest wall variance is explained and outside the Step 3 change set.

A valid Step 3 result may ship the profiler while retaining `raw_json` on the IOC common path. That is what shipped.

## 21. Remaining Phase 1 Work

- 1.5 remaining: keep `raw_json` on the common path until A-B=0. Optional later: Huntress/search_blob hash repair without dumping all of `raw_json`; do not remove `lower()` until stored values are canonical or Phase 2 text index provides a `lower` preprocessor.
- 1.6: done for current ERK counting basis. LEK-basis profiles are Phase 6.
- 1.7: Hayabusa/EvtxECmd directory mode — not started.
- 1.8: typed-column promotion — not started (Huntress SHA256 is a candidate).
- 1.9: pre-parse DELETE existence-probe already in prior steps; full fix is Phase 4 generations.
- 1B / Phase 2+: not started. No LEK, generations, manifests, event surfaces, Qdrant, or overlay work in this step.
