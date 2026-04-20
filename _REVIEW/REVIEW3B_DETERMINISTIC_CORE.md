# Review 3b — Deterministic Core Correctness

Date: 2026-04-20

## Scope
Review deterministic-core partial-data behavior, burst detection, sequence handling, spread detection, and `utils/stateful_detectors/*` / `utils/gap_detector_bridge.py` integration against the live repo; carry forward Review 3a findings only where they still survive verification; and land any unambiguous in-scope fixes discovered during the review.

## Review Outcome
- Burst detection had a live correctness defect: package-local burst scoring was pulling case-wide buckets from the active window instead of scoping to the package correlation key. Review 3b fixed that in `3f9f3d43`.
- Spread detection had a live partial-data/windowing defect: when coverage windows were absent, spread queries could fall back to an unbounded case-wide scan even though anchor timestamps were available. Review 3b fixed that in `3f9f3d43`.
- `GAP-V2-SEQUENCE-COVERAGE` still survives. Sequence scoring remains always evaluable once a sequence config exists, without explicit exclude-vs-evaluable handling for missing telemetry.
- Sequence validation still does not perform a true ordered chain walk per matched step/candidate. Each step is queried independently relative to the representative anchor and only scoped by `source_host`, which can mix unrelated same-host events into one chain.
- The stateful detector stage still has correctness gaps outside the narrow bridge mappings already shipped: password-spraying and brute-force candidates are aggregated case-wide instead of within their configured time windows, and behavioral-anomaly findings are still not mapped into deterministic-engine checks or producer inputs.

## Verified Behavior
- `utils/gap_detector_bridge.py` still behaves as a pure mapping layer: mapped `PASSWORD_SPRAYING`, `BRUTE_FORCE`, and `DISTRIBUTED_BRUTE_FORCE` findings resolve to canonical `CheckResult` objects and canonical producer metadata.
- Review 3a's `GAP-V2-SEQUENCE-COVERAGE` still survives unchanged in `utils/deterministic_evidence_engine.py`; sequence weight is still added to `raw_total_weight` and `evaluable_weight` regardless of missing-telemetry state.
- Review 3b landed two low-risk deterministic-core fixes in `3f9f3d43`:
  - burst queries are now scoped to the current pattern correlation fields when those fields are available on the active package
  - spread queries now fall back to anchor-derived time bounds when coverage windows are unavailable

## Findings
### 1. `CORRECTNESS` / `HIGH`
- Location: `utils/deterministic_evidence_engine.py:1258`, `utils/deterministic_evidence_engine.py:1550`
- Summary: `GAP-V2-SEQUENCE-COVERAGE` still survives in live code. Sequence contribution is always treated as evaluable once a sequence config exists, with no explicit Scoring 2.0 exclude-vs-evaluable behavior for missing telemetry.
- Proposed fix: extend sequence scoring to mirror the explicit missing-telemetry policy already used for `INCONCLUSIVE` checks and burst checks, then add fixture coverage before any additional sequence-dependent patterns migrate to Scoring 2.0. Rough effort: M.

### 2. `CORRECTNESS` / `HIGH`
- Location: `utils/deterministic_evidence_engine.py:1258`
- Summary: sequence validation still checks each step independently relative to the representative anchor and only filters by `source_host`, so multi-candidate chains can be built from unrelated same-host events and step ordering is not actually enforced between matched steps.
- Proposed fix: rework sequence validation into a true stepwise walk that narrows each subsequent query off the previously matched event (not just the anchor), scopes on the active correlation key fields, and distinguishes "outside window" from "absent" in the returned step metadata. Rough effort: M/L.

### 3. `CORRECTNESS` / `HIGH`
- Location: `utils/stateful_detectors/password_spraying.py:88`, `utils/stateful_detectors/brute_force.py:77`
- Summary: the password-spraying and brute-force detectors define `time_window_hours` thresholds but never apply them in their candidate queries, so findings are aggregated over the whole case rather than within the configured attack window.
- Proposed fix: push detector candidate grouping onto explicit time buckets or sliding windows keyed to the configured threshold, then re-tune confidence/event-count semantics against those bounded windows. Rough effort: M.

### 4. `DRIFT` / `MEDIUM`
- Location: `utils/pattern_check_definitions.py:2916`, `utils/deterministic_evidence_engine.py:1614`, `utils/stateful_detectors/behavioral_anomaly.py:30`
- Summary: the anomaly-detection pipeline runs behavioral-anomaly detection, but only password-spraying/brute-force finding types are registered for deterministic-engine consumption, so behavioral-anomaly findings never become deterministic checks or producer inputs.
- Proposed fix: either add canonical check bindings for the intended behavioral-anomaly finding types or explicitly narrow the product claim so those detectors remain standalone outputs rather than part of the deterministic-core evidence package. Rough effort: M.

### 5. `CORRECTNESS` / `MEDIUM`
- Location: `utils/deterministic_evidence_engine.py:1626`
- Summary: `_scope_gap_results()` drops user-scoped gap findings whenever the finding carries sampled `source_ips` but the active anchor lacks `src_ip`, so partial telemetry can suppress otherwise relevant gap evidence instead of surfacing it as unresolved/inconclusive.
- Proposed fix: treat "user matched but IP unavailable on the anchor" as partial-data state rather than silently excluding the finding, and add regression coverage for user-only anchors. Rough effort: S/M.

### 6. `CORRECTNESS` / `MEDIUM`
- Location: `utils/deterministic_evidence_engine.py:208`
- Summary: `_compute_window()` still falls back to `datetime.utcnow()` when an anchor timestamp cannot be parsed, making malformed/partial-timestamp evaluations non-deterministic across runs.
- Proposed fix: replace the wall-clock fallback with a deterministic no-timestamp path (for example, explicit unknown-window handling that yields coverage/query inconclusive results) and add a regression test for malformed anchor timestamps. Rough effort: S/M.

### 7. `CORRECTNESS` / `MEDIUM`
- Location: `utils/deterministic_evidence_engine.py:245`, `utils/deterministic_evidence_engine.py:1198`, `utils/deterministic_evidence_engine.py:1258`, `utils/deterministic_evidence_engine.py:1805`
- Summary: Review 3a's deterministic-core UTC query-column drift still survives in the 3b surfaces: coverage, burst, sequence, and spread queries continue to use raw `timestamp` rather than the documented UTC-normalized query surface.
- Proposed fix: carry the Review 3a UTC-normalized query-column follow-through into all deterministic-engine query helpers before Review 10 closes the cross-cutting timezone thread. Rough effort: M.

## Code Changes Landed During Review 3b
- `utils/deterministic_evidence_engine.py`
  - scoped burst queries to the active pattern correlation fields and preserved spread time bounds by falling back to anchor timestamps when coverage windows are absent (`3f9f3d43`)
- `tests/test_scoring_2_engine_fixtures.py`
  - added focused regressions covering burst query scoping and spread anchor-time fallback (`3f9f3d43`)

## Verification Run
- `python3 -m unittest tests.test_scoring_2_engine_fixtures tests.test_phase4a_gap_bridge_normalization tests.test_phase4a_producer_inputs_normalization tests.test_phase4a_stateful_detector_entrypoint`
- Result: `OK` (27 tests)

## Review 4a Hand-off
- Review 4a should treat the deterministic-core parser-consumer boundary as still carrying two live constraints from Review 3: the UTC-normalized query-column migration is still incomplete across engine queries, and sequence evidence still lacks explicit missing-telemetry scoring semantics.
- Parser review should pay special attention to whether EVTX / Windows / registry surfaces reliably emit the `source_host`, `src_ip`, `timestamp_utc`, and coverage-bearing channel fields that Review 3b found are load-bearing for bounded burst/spread/sequence evaluation.
