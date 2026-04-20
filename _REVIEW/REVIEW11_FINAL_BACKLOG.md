# Review 11 — Final Backlog

Date: 2026-04-20

## Scope
Consolidate the unresolved findings from Reviews 1-10 into one ranked backlog, separate release blockers from medium-term cleanup, identify which issues are really follow-on review candidates, and sync the master plan / `docs/refactor/file_audit.md` to the live repo.

## Review Outcome
- The highest-risk remaining work is still concentrated in four bundles: deterministic temporal correctness, route authorization/write-policy drift, async task-state contracts, and premium chat/runtime boundary hardening.
- Review 11 did not uncover a new hidden subsystem that needs its own mandatory Review. The open work is implementation and verification backlog, not missing review coverage.
- Two important unresolved findings were still missing from the master cross-cutting log and are now explicitly carried forward here: inconsistent viewer-write enforcement on mutating case routes, and permissive L1 tool-call argument validation in the chat runtime.
- `docs/refactor/file_audit.md` was updated in this Review to stop implying closure on surfaces that are still only partially complete.

## Consolidated Ranked Backlog
Resolved findings from Reviews 1-10 are intentionally omitted below. This backlog is the ranked list of work that still survives in the live repo after Review 10.

### Fix Before Ship
1. `RISK-VIEWER-WRITE-POLICY-DRIFT` — `RISK` / `HIGH`
   Review 7a found, and Review 11 re-verified in live code, that several mutating or task-triggering case routes still rely on `@login_required` plus case lookup without a shared write-role guard. Current examples include `routes/analysis.py`, `routes/iocs.py`, `routes/known_users.py`, `routes/known_systems.py`, and `routes/case_files.py`. If "viewer" is meant to be read-only, this is an authorization bug, not just cleanup. Proposed fix: add one shared case-write guard and apply it consistently to all case mutation / task-start routes. Suggested test-first coverage: yes.

2. `DRIFT-DET-UTC-QUERY-COLUMN` — `CORRECTNESS` / `HIGH`
   Reviews 3a, 3b, and 10 all confirmed that deterministic-engine coverage, query, burst, sequence, and spread paths still query raw `timestamp` even though the product's documented query contract is `timestamp_utc` or `COALESCE(timestamp_utc, timestamp)`. This can change forensic results on mixed-timezone data. Proposed fix: move every deterministic query helper onto the UTC-normalized query column and replay fixture coverage end to end. Suggested test-first coverage: yes.

3. `BUG-DET-SEQUENCE-CHAIN-ORDER` — `CORRECTNESS` / `HIGH`
   Review 3b found that sequence validation still matches each step independently relative to the anchor and only filters on `source_host`, so unrelated same-host events can satisfy a multi-step chain. This is a direct deterministic false-positive risk. Proposed fix: rework sequence evaluation into a true stepwise walk keyed off the previously matched event and the active correlation fields. Suggested test-first coverage: yes.

4. `DRIFT-STATEFUL-DETECTOR-WINDOWS` — `CORRECTNESS` / `HIGH`
   Review 3b and Review 10 confirmed that `utils/stateful_detectors/password_spraying.py` and `utils/stateful_detectors/brute_force.py` define `time_window_hours` thresholds but never apply them in candidate queries. Findings currently aggregate across the full case instead of the configured attack window. Proposed fix: bucket or slide candidate grouping by the configured time window and re-baseline confidence/event-count semantics. Suggested test-first coverage: yes.

5. `GAP-V2-SEQUENCE-COVERAGE` — `GAP` / `HIGH`
   Reviews 1, 3a, and 3b all found that sequence contribution is still always treated as evaluable once a sequence config exists; Scoring 2.0 does not yet express "not evaluable because telemetry is missing" for sequences. This makes package scoring and excluded-weight reporting wrong for sequence-dependent patterns under partial telemetry. Proposed fix: add explicit sequence evaluability states before any further 2.0 migration. Suggested test-first coverage: yes.

6. `GAP-TASK-FAILURE-STATE-CONTRACT` — `CORRECTNESS` / `HIGH`
   Reviews 8 and 10 found that several long-running tasks persist failure details locally and then return `{"success": false, ...}` instead of raising, so Celery records operational failures as `SUCCESS`. Retry, dead-letter, and monitoring semantics are therefore not authoritative. Proposed fix: keep durable status writes, but raise or retry after persisting failure state so broker-level task state is truthful. Suggested test-first coverage: yes.

7. `GAP-DET-NONDETERMINISTIC-WINDOW-FALLBACK` — `CORRECTNESS` / `MEDIUM`
   Reviews 3b and 10 found that `_compute_window()` still falls back to `datetime.utcnow()` when an anchor timestamp cannot be parsed, making malformed/partial-timestamp evaluations non-deterministic across runs. Proposed fix: replace wall-clock fallback with an explicit deterministic "unknown window" path that yields inconclusive results. Suggested test-first coverage: yes.

8. `RISK-L1-TOOL-SCHEMA-VALIDATION` — `RISK` / `HIGH`
   Review 6 found that model-supplied tool arguments are JSON-decoded and passed into Python tool callsites without strict request-shape validation, and some tools accept `**kwargs`. If tool-enabled premium chat is release scope, this is a ship blocker for that surface. Proposed fix: validate tool arguments against `TOOL_DEFINITIONS` before permission checks, reject unknown keys and obvious type mismatches as structured tool errors, and make provenance on rejected tool calls explicit. Suggested test-first coverage: yes.

### Fix This Quarter
9. `GAP-ASYNC-CANCELLATION-CONTRACT` — `GAP` / `MEDIUM`
   Reviews 8 and 10 found no shared cooperative cancellation contract in long-running case, archive, memory, and PCAP flows. Cancellation still depends on revoke/terminate behavior rather than stage-aware stop points. Proposed fix: define one cancellation token/checkpoint contract and thread it into the heavy loops. Suggested test-first coverage: yes.

10. `DRIFT-CASE-ANALYZER-FINALIZE` — `DRIFT` / `MEDIUM`
    Reviews 2b, 8, and 10 all re-verified that `utils/case_analyzer.py` is thinner, but still owns terminal persistence, summary shaping, degraded-status synthesis, progress bookkeeping, and unified-findings mirroring. Proposed fix: extract terminal persistence/finalization into one narrower boundary instead of leaving the analyzer half-orchestrator, half-finalizer. Suggested test-first coverage: yes.

11. `GAP-EVTX-FALLBACK-PARSER-CONTRACT` — `CORRECTNESS` / `HIGH`
    Reviews 4a and 10 found that `EvtxFallbackParser` still stores native fallback JSON instead of the normalized `EventData` contract and can also violate the IPv4 column contract. Deterministic extraction can therefore silently degrade when fallback ingestion is active. Proposed fix: normalize fallback output onto the primary EVTX contract or explicitly exclude fallback-ingested EVTX from deterministic correlation until parity exists. Suggested test-first coverage: yes.

12. `DRIFT-JSON-403-ERROR-SHAPE` — `DRIFT` / `MEDIUM`
    Reviews 7a, 7b, and 10 confirmed that otherwise-JSON APIs can still emit HTML 403 responses because shared case access enforcement uses `abort(403)`, and async status payloads still vary by blueprint. Proposed fix: move access-denial onto a JSON-aware API handler and standardize task-status envelopes. Suggested test-first coverage: yes.

13. `DRIFT-LEGACY-UNIFIED-FINDINGS-ROUTE` — `DRIFT` / `MEDIUM`
    Review 7b confirmed that `routes/findings.py` is canonical, but active UI callers still use `/api/rag/unified-findings/<case_id>`. The legacy route now delegates to the canonical serializer, so this is no longer a payload-correctness issue, but it is still route-surface drift. Proposed fix: migrate live callers to `/api/findings/list/<case_uuid>` and retire the compatibility wrapper afterward. Suggested test-first coverage: no.

14. `RISK-IOC-AUDIT-AUTHORITY` — `RISK` / `HIGH`
    Review 5 found that IOC audit mode is additive in implementation shape but authoritative over the returned candidate set: validated AI deltas mutate the deterministic output in place. Proposed fix: preserve the pre-audit deterministic candidate set alongside the post-audit view, or persist audit overlays separately so downstream consumers can distinguish detector output from AI correction. Suggested test-first coverage: yes.

15. `DRIFT-PROVENANCE-L1-FALLBACK` — `DRIFT` / `MEDIUM`
    Reviews 2b and 6 confirmed that dispatch still falls back to policy provenance when emitted provenance is missing or invalid instead of enforcing producer-emitted tags end to end. Proposed fix: fail closed for successful data-bearing tool payloads without valid emitted provenance, or explicitly narrow the contract everywhere that fallback remains intentional. Suggested test-first coverage: yes.

16. `RISK-DET-SQL-PARAMETERIZATION` — `RISK` / `MEDIUM`
    Review 3a found that `utils/candidate_extractor.py` still interpolates event IDs, time bounds, and pattern-defined `LIKE` fragments into ClickHouse SQL rather than using the parameterized style already present elsewhere in the engine. Proposed fix: move extractor SQL assembly onto named parameters and one shared escaping boundary for pattern-defined fragments. Suggested test-first coverage: yes.

### Known Limitation
17. `DRIFT-MEMORY-PARSER-PROVENANCE-CONTRACT` — `DRIFT` / `MEDIUM`
    Review 4b found that the memory family still bypasses `BaseParser` / `ParsedEvent`, writes into dedicated `memory_*` tables, and gets provenance annotations later in runtime surfaces instead of at parser emit time. This is a documented exception now, but not a fully unified parser contract.

18. `GAP-BEHAVIORAL-DETECTOR-INTEGRATION` — `DRIFT` / `MEDIUM`
    Review 3b verified that behavioral-anomaly detection still runs, but only brute-force/password-spraying findings are registered for deterministic-engine consumption. Until the product wants those outputs inside the deterministic evidence package, this remains a contract gap rather than a release blocker.

19. `GAP-SCORE-DISPLAY-CONTRACT` — `GAP` / `MEDIUM`
    Reviews 1 and 7b found that the raw Scoring 2.0 fields exist, but the promised compact analyst/LLM score display contract is still not implemented as one shared presentation payload. This is a usability/documentation gap, not a detector-correctness defect.

20. `GAP-IOC-EVENT-TAG-IDENTITY` — `CORRECTNESS` / `HIGH`
    Review 5 found that event-level IOC tagging still stores shortened badge labels rather than canonical IOC identity. Review 7 later verified that the currently reviewed route surfaces only use these tags for non-empty IOC presence, not exact type identity, so this is a latent limitation until a downstream consumer needs canonical event-row IOC identity.

21. `GAP-RAREST-ANCHOR-PIVOT` — `GAP` / `LOW`
    Review 3a found that the event census only skips impossible patterns; the planned rarest-event anchor pivot is still not implemented. This is worthwhile deterministic-core follow-up, but it is optimization/design completeness rather than the current source of a known wrong result.

22. `CORRECTNESS-OFF-HOURS-CASE-TZ` — `CORRECTNESS` / `MEDIUM`
    Review 3a found that `*_off_hours` checks still evaluate `anchor_ts.hour` directly, so off-hours logic currently uses storage/UTC hour instead of the case timezone the product presents as authoritative. This should be fixed, but it is narrower than the broader UTC query-column drift above.

### Nice To Have
23. `TEST-SOURCE-TEXT-GUARDRAILS` — `TEST` / `MEDIUM`
    Review 10 found several regression suites that still assert source text, helper names, or decorator stacking instead of behavior. This does not currently produce wrong runtime output, but it makes safe cleanup needlessly expensive and should be cleaned up before larger refactors.

24. `DRIFT-IOC-EXTRACTOR-THIN-FACADE` — `DRIFT` / `MEDIUM`
    Review 5 found that `utils/ioc_extractor.py` still owns regex, alias generation, import prep, and persistence logic instead of acting as a thinner orchestration facade. This is important maintainability work, but not the current source of wrong output.

25. `DRIFT-IOC-DEFANG-SOURCE-OF-TRUTH` — `DUPLICATION` / `MEDIUM`
    Review 5 found that `utils/ioc_text.py`, `utils/ioc_extractor.py`, and `utils/ioc_audit.py` still maintain overlapping defang/refang normalization tables. This is drift-prone, but not yet tied to one confirmed user-visible defect after the completed review set.

26. `BUG-HAYABUSA-RECORDID-ENRICHMENT-COLLAPSE` — `CORRECTNESS` / `MEDIUM`
    Review 4a found that Hayabusa enrichment still keys on `RecordID` and later matches overwrite earlier ones, so multiple detections on one record collapse to the last rule seen. This is a real enrichment loss, but it is lower urgency than the release-blocking deterministic and auth contracts above.

27. `CORRECTNESS-GAP-RESULT-IP-SCOPING` — `CORRECTNESS` / `MEDIUM`
    Review 3b found that `_scope_gap_results()` can drop user-scoped gap findings when the finding carries sampled `source_ips` but the anchor has no `src_ip`. This is a narrower partial-telemetry issue and should be fixed once the larger deterministic-window bundle above is addressed.

## Regression Tests To Add Before Fixing
- Add characterization fixtures for `DRIFT-DET-UTC-QUERY-COLUMN`, `GAP-V2-SEQUENCE-COVERAGE`, `BUG-DET-SEQUENCE-CHAIN-ORDER`, `DRIFT-STATEFUL-DETECTOR-WINDOWS`, and `GAP-DET-NONDETERMINISTIC-WINDOW-FALLBACK` before touching the deterministic engine again. Those changes are correctness-sensitive and will be hard to audit after the fact without pre-fix examples.
- Add authorization regression tests for `RISK-VIEWER-WRITE-POLICY-DRIFT` before introducing a shared write guard so the repo proves which routes should be viewer-readable versus viewer-writable.
- Add broker-state tests for `GAP-TASK-FAILURE-STATE-CONTRACT` before changing Celery failure behavior; the contract needs to pin both durable status persistence and terminal task state.
- Add contract tests for `RISK-L1-TOOL-SCHEMA-VALIDATION` and `DRIFT-PROVENANCE-L1-FALLBACK` before tightening the chat runtime so the tool-call boundary fails in explicitly reviewed ways instead of silently changing behavior.
- Add parser parity tests for `GAP-EVTX-FALLBACK-PARSER-CONTRACT` before normalizing fallback EVTX rows so primary and fallback contracts can be compared directly.

## Findings That Would Justify A New Review
- No new mandatory Review is required. The current plan covered the codebase; the remaining work is implementation backlog.
- If the team wants review-style checkpoints after fixes land, the only two follow-on Reviews that appear justified are:
  - a deterministic replay Review covering items `2-7` and `16, 21, 22, 27`
  - an async/runtime contract Review covering items `6, 8-15`

## `file_audit.md` Sync Landed In Review 11
- refreshed line counts for the live files touched by the final backlog roll-up
- added the previously omitted deterministic-core entries for `utils/deterministic_evidence_engine.py` and `utils/candidate_extractor.py`
- updated `utils/case_analyzer.py`, `routes/findings.py`, `routes/rag.py`, and `utils/unified_findings.py` notes to the post-Review-10 live state
- documented the still-open stateful-detector contract gaps so the audit no longer implies those detectors are fully aligned with their configured windows or deterministic-engine bindings
- added concrete mismatch bullets for the remaining route authorization drift, chat runtime contract drift, and async contract drift
