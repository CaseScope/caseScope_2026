# Review 3a — Deterministic Core Correctness

Date: 2026-04-20

## Scope
Review deterministic-core scoring math, timezone handling, SQL construction, window semantics, and anchor selection against the live repo; carry forward Review 1 scoring findings only if they still survive verification; pay specific attention to `GAP-V2-SEQUENCE-COVERAGE`; and land any unambiguous in-scope fixes discovered during the review.

## Review Outcome
- Scoring math: Scoring 2.0 check-level `exclude` vs. `evaluable` handling is live for normal checks and burst checks, and the Review 1 spread-reconciliation fix still survives in code/tests. The Review 1 sequence-coverage gap still survives unchanged.
- Timezone handling: the deterministic core is not yet aligned to the documented UTC-normalization contract. The task-side candidate extractor time filter was corrected in this Review, but the engine still evaluates windows and checks against raw `timestamp` rather than the UTC-normalized query column described in `docs/TIMEZONE.md`.
- SQL construction: the engine check/coverage path is parameterized, but `utils/candidate_extractor.py` still assembles extraction queries and `LIKE` clauses with string interpolation rather than the stricter parameterized style used by the engine.
- Window semantics: package windows are computed as `[min(anchor_ts) - half_window, max(anchor_ts) + half_window]`, but sequence evaluation is still relative to the representative anchor for the package rather than an explicit per-step or per-anchor walk.
- Anchor selection: the live census is used only for whole-pattern eligibility filtering. The repo does not yet implement the planned rarest-event pivot inside candidate extraction or deterministic evaluation.

## Verified Behavior
- `utils/deterministic_evidence_engine.py` still enforces Review 1's Scoring 2.0 package split between `deterministic_score` and `eligible_to_emit`, including required-check gating and anchor-class validation.
- Review 1's spread fix still survives: Scoring 2.0 spread bonuses reconcile `deterministic_score`, `evaluable_weight`, `raw_total_weight`, `max_possible_score`, and emit-block state together; `tests/test_scoring_2_engine_fixtures.py` still covers that path.
- The deterministic engine's coverage checks and query-check templates still use ClickHouse named parameters for runtime values; the main SQL-discipline gap is concentrated in candidate extraction rather than in `_evaluate_query_check()` / `_check_coverage()`.
- Review 3a landed one code fix in `69aa2673`: task-scoped candidate extraction now filters on `COALESCE(timestamp_utc, timestamp)` and normalizes aware datetimes to naive UTC before building the ClickHouse time clause.

## Findings
### 1. `CORRECTNESS` / `HIGH`
- Location: `utils/deterministic_evidence_engine.py:1258`, `utils/deterministic_evidence_engine.py:1550`
- Summary: `GAP-V2-SEQUENCE-COVERAGE` still survives in live code. Sequence contribution is always treated as evaluable once a sequence config exists, with no explicit Scoring 2.0 exclude-vs-evaluable behavior for missing telemetry.
- Proposed fix: extend sequence scoring to mirror the explicit missing-telemetry policy already used for `INCONCLUSIVE` checks and burst checks, then add fixture coverage before any sequence-dependent pattern migrates to Scoring 2.0. Rough effort: M.

### 2. `CORRECTNESS` / `HIGH`
- Location: `utils/deterministic_evidence_engine.py:245`, `utils/pattern_check_definitions.py`, `utils/candidate_extractor.py:201`, `docs/TIMEZONE.md`
- Summary: the deterministic core still evaluates coverage, query checks, burst queries, and sequence queries against raw `timestamp` even though the timezone contract and route-side filters treat `timestamp_utc` / `COALESCE(timestamp_utc, timestamp)` as the authoritative query surface.
- Proposed fix: standardize deterministic-core queries on the UTC-normalized query column with a pre-migration fallback policy, then re-verify window alignment end to end on ambiguous-source artifacts. Review 3a landed the narrow task-extraction time-filter fix in `69aa2673`, but the engine-wide query column still needs follow-through. Rough effort: M.

### 3. `CORRECTNESS` / `MEDIUM`
- Location: `utils/deterministic_evidence_engine.py:625`
- Summary: all `*_off_hours` checks evaluate `anchor_ts.hour` directly, so "off-hours" is currently judged in storage/UTC hour rather than in the case timezone the product otherwise treats as authoritative for interactive time ranges.
- Proposed fix: pass case timezone into deterministic evaluation and convert the anchor instant before applying the off-hours threshold, or explicitly narrow the product claim if UTC-hour scoring is intentional. Rough effort: M.

### 4. `RISK` / `MEDIUM`
- Location: `utils/candidate_extractor.py:201`, `utils/candidate_extractor.py:222`, `utils/candidate_extractor.py:343`, `utils/candidate_extractor.py:398`
- Summary: candidate extraction still builds ClickHouse SQL with string interpolation for event IDs, time bounds, and pattern-defined `LIKE` fragments instead of using the parameterized style already used elsewhere in the deterministic engine.
- Proposed fix: move extractor query assembly onto named parameters and central escaping/quoting helpers for pattern-defined fragments. Review 3a's `69aa2673` narrows the timezone column drift for time filters but does not yet harden the rest of the extractor SQL surface. Rough effort: M.

### 5. `GAP` / `LOW`
- Location: `pipeline/pattern_analysis.py:712`, `utils/deterministic_evidence_engine.py:46`, `utils/candidate_extractor.py:58`
- Summary: the event-ID census only skips impossible patterns. The planned rarest-event anchor pivot is not implemented in the live deterministic core, and `DeterministicEvidenceEngine.census` is otherwise unused.
- Proposed fix: use the census to choose the rarest available anchor/pivot event per pattern (or narrow the architecture claim if the live design is intentionally anchor-list-driven). Rough effort: M/L.

## Code Changes Landed During Review 3a
- `utils/candidate_extractor.py`
  - normalized task-scoped extractor time filters onto `COALESCE(timestamp_utc, timestamp)` and converted aware bounds to naive UTC before ClickHouse comparison (`69aa2673`)
- `tests/test_candidate_extractor_time_filter.py`
  - added focused regression coverage for naive and aware extractor time bounds (`69aa2673`)

## Verification Run
- `python3 -m unittest tests.test_candidate_extractor_time_filter tests.test_scoring_2_engine_fixtures`
- Result: `OK` (8 tests)

## Review 3b Hand-off
- Pick up deterministic-core partial-data behavior, burst semantics beyond the already-verified 2.0 weight split, sequence handling beyond the surviving Scoring 2.0 gap, spread detection, and `utils/stateful_detectors/*` / `utils/gap_detector_bridge.py` integration.
- Carry forward the still-open `GAP-V2-SEQUENCE-COVERAGE` work as a live engine correctness issue, not just a documentation note.
- Treat the UTC-query-column mismatch as still open even after `69aa2673`; Review 3a only fixed the task-side extraction filter, not the engine's own coverage/check/burst/sequence query column choice.
