# Review 11 — Final Backlog

Date: 2026-04-20

## Scope
Consolidate the unresolved findings from Reviews 1-10 into one ranked backlog, separate release blockers from medium-term cleanup, identify which issues are really follow-on review candidates, and sync the master plan / `docs/refactor/file_audit.md` to the live repo.

## Review Outcome
- The highest-risk remaining work is now concentrated in three bundles: deterministic temporal correctness, async task-state contracts, and premium chat/runtime boundary hardening.
- Review 11 did not uncover a new hidden subsystem that needs its own mandatory Review. The open work is implementation and verification backlog, not missing review coverage.
- Two important findings were still missing from the master cross-cutting log and were explicitly carried forward here: inconsistent viewer-write enforcement on mutating case routes, and permissive L1 tool-call argument validation in the chat runtime. The viewer-write item has now been resolved post-Review 11; the L1 tool-call validation item remains open.
- `docs/refactor/file_audit.md` was updated in this Review to stop implying closure on surfaces that are still only partially complete.
- Post-Review 11 implementation on 2026-04-20 resolved `RISK-VIEWER-WRITE-POLICY-DRIFT` by adding one shared viewer-write guard across the affected case mutation and task-start routes; the ranked backlog below keeps the entry for auditability but it is no longer open work.
- Post-Review 11 implementation on 2026-04-20 also resolved `DRIFT-DET-UTC-QUERY-COLUMN` by moving deterministic-engine coverage, query-template execution, burst, sequence, and spread SQL onto the UTC-normalized event-time column and preferring `timestamp_utc` when anchor-derived helper windows are built.
- Operational follow-up on 2026-04-21 resolved the upload-side hash/stage drift outside the original Review 11 backlog: case-upload preflight hashes are now keyed per queued upload entry instead of bare filename, preflight hash failures are surfaced explicitly instead of silently falling back, and the upload progress UI now distinguishes archive preparation from final parser queueing.
- Operational follow-up on 2026-04-21 also resolved the IOC responsiveness/visibility drift outside the original Review 11 backlog: analyst-facing IOC extraction and tagging now route to the dedicated `ioc` queue, the async routes consistently track and gate those task IDs, and the IOC UI now shows queued-vs-running state instead of looking idle while the task is still waiting behind ingest.
- Operational follow-up on 2026-04-21 advanced the ClickHouse mutation-remediation plan from the initial analyst overlay to the full mutable-tagging bundle that fits the overlay pattern cleanly: analyst event state, mutable noise state, and IOC event tags now write to dedicated overlay tables and the main hunt/chat/RAG/deterministic read surfaces consume effective overlay-backed state instead of mutating `events`. The main remaining ClickHouse production-safety gap is destructive delete/dedup behavior, not mutable event tagging.
- A later operational follow-up on 2026-04-21 tightened the remaining delete/dedup contract further without replacing ClickHouse: automatic post-ingest dedup now skips very large per-artifact duplicate rewrites instead of always issuing them, those skips are surfaced in task/route results, `buffer_flushed` no longer reports true when the buffer flush was merely skipped, the case rebuild task now states that the destructive reset already completed before re-ingest was queued, manual dedup now runs asynchronously with explicit queued/processing/completed status plus an explicit force flag to bypass the manual safety ceiling, permanent case/client deletion plus case-wide and single-PCAP destructive resets now wait for the corresponding ClickHouse delete mutations before claiming completion, PCAP log reindex now waits for the old `network_logs` delete to finish before reinserting rows, case-wide `network_logs` deletion now prefers `(case_id, log_type)` partition drops before falling back to a full mutation rewrite, destructive PCAP `network_logs` routes now reject overlap with explicit active-rewrite context, explicit case-wide `events` rewrites now acquire one shared destructive-rewrite guard so delete/rebuild/dedup work does not overlap under load, single-file and single-PCAP delete routes now fail closed if the ClickHouse delete fails instead of dropping metadata anyway, rebuild helpers now abort before metadata deletion on the same failure mode, parser-side partial-row cleanup now waits for the file-scoped delete mutation before surfacing parse failure, and the `bin/clear_cases.py` maintenance script now waits for those destructive deletes instead of merely scheduling them.

## Consolidated Ranked Backlog
Resolved findings from Reviews 1-10 are intentionally omitted below. This backlog is the ranked list of work that still survives in the live repo after Review 10.

### Fix Before Ship
1. `RISK-VIEWER-WRITE-POLICY-DRIFT` — `RISK` / `HIGH` / `RESOLVED 2026-04-20`
   Review 7a found, and Review 11 re-verified in live code, that several mutating or task-triggering case routes relied on `@login_required` plus case lookup without a shared write-role guard. Post-Review 11 implementation closed this by adding one shared case-write guard and applying it consistently across the affected mutation and task-start routes in `routes/analysis.py`, `routes/iocs.py`, `routes/known_users.py`, `routes/known_systems.py`, and `routes/case_files.py`, with focused route-security regression coverage for the viewer-versus-writer contract.

2. `DRIFT-DET-UTC-QUERY-COLUMN` — `CORRECTNESS` / `HIGH` / `RESOLVED 2026-04-20`
   Reviews 3a, 3b, and 10 found that deterministic-engine coverage, query, burst, sequence, and spread paths still queried raw `timestamp` even though the product's documented query contract is `timestamp_utc` or `COALESCE(timestamp_utc, timestamp)`. Post-Review 11 implementation closed this by moving the engine's direct SQL onto `COALESCE(timestamp_utc, timestamp)`, normalizing runtime-executed check templates onto the same query column, preferring `timestamp_utc` when anchor helpers derive query windows, and adding focused regression fixtures for coverage, query-check, burst, sequence, spread, and anchor-parameter behavior.

3. `BUG-DET-SEQUENCE-CHAIN-ORDER` — `CORRECTNESS` / `HIGH` / `RESOLVED 2026-04-20`
   Review 3b found that sequence validation matched each step independently relative to the anchor and only filtered on `source_host`, so unrelated same-host events could satisfy a multi-step chain. Post-Review 11 implementation closed this by making sequence validation walk `before_anchor` steps backward from the anchor and `after_anchor` steps forward from the anchor, updating each branch from the previously matched event, scoping queries to the active correlation fields already on the package, and adding a focused deterministic regression fixture for the same-host out-of-order false-positive case.

4. `DRIFT-STATEFUL-DETECTOR-WINDOWS` — `CORRECTNESS` / `HIGH` / `RESOLVED 2026-04-20`
   Review 3b and Review 10 confirmed that `utils/stateful_detectors/password_spraying.py` and `utils/stateful_detectors/brute_force.py` defined `time_window_hours` thresholds but never applied them in candidate queries. Post-Review 11 implementation closed this by grouping both detectors inside their configured attack windows on `COALESCE(timestamp_utc, timestamp)`, scoping password-spraying successful-account evidence to the detected window, and adding focused regression coverage that locks the detector SQL boundary to the configured time bucket.

5. `GAP-V2-SEQUENCE-COVERAGE` — `GAP` / `HIGH` / `RESOLVED 2026-04-20`
   Reviews 1, 3a, and 3b found that Scoring 2.0 treated sequence contribution as evaluable whenever a sequence config existed, even when missing telemetry made the chain non-evaluable. Post-Review 11 implementation first added explicit sequence evaluability metadata, and a subsequent deterministic follow-up closed the remaining gap by declaring sequence-specific required-source contracts for the live sequence definitions, filtering sequence telemetry-gap metadata down to sources that actually matter to the configured chain, and excluding sequence weight only when that required telemetry is missing. Focused regression coverage now locks both the filtered metadata contract and the sequence-specific excluded-weight behavior.

6. `GAP-TASK-FAILURE-STATE-CONTRACT` — `CORRECTNESS` / `HIGH` / `RESOLVED 2026-04-20`
   Reviews 8 and 10 found that several long-running tasks persist failure details locally and then return `{"success": false, ...}` instead of raising, so Celery records operational failures as `SUCCESS`. Post-Review 11 follow-up first fixed the job-backed archive, memory, and PCAP task surfaces, and a subsequent async-task pass closed the remaining `tasks/celery_tasks.py` / `tasks/rag_tasks.py` slice by making the long-running/result-cached IOC tagging/extraction and case-analysis/RAG entrypoints raise after writing their failed progress or durable state, with focused regression coverage that locks the broker-visible failure contract for those remaining async surfaces.

7. `GAP-DET-NONDETERMINISTIC-WINDOW-FALLBACK` — `CORRECTNESS` / `MEDIUM` / `RESOLVED 2026-04-20`
   Reviews 3b and 10 found that `_compute_window()` still fell back to `datetime.utcnow()` when an anchor timestamp could not be parsed, making malformed/partial-timestamp evaluations non-deterministic across runs. Post-Review 11 implementation closed this by replacing the wall-clock substitution with an explicit unknown-window path, returning deterministic inconclusive query and sequence results when the anchor window cannot be computed, excluding that sequence weight from Scoring 2.0, and adding focused engine regressions for unknown-window behavior.

8. `RISK-L1-TOOL-SCHEMA-VALIDATION` — `RISK` / `HIGH` / `RESOLVED 2026-04-20`
   Review 6 found that model-supplied tool arguments were JSON-decoded and passed into Python tool callsites without strict request-shape validation, and some tools accept `**kwargs`. Post-Review 11 implementation closed this by validating decoded tool arguments against the declared `TOOL_DEFINITIONS` schema before permission checks or execution, rejecting unknown keys and obvious type mismatches as structured tool-call failures, and adding focused chat-runtime regressions for both live model tool calls and approval-resume paths.

### Fix This Quarter
9. `GAP-ASYNC-CANCELLATION-CONTRACT` — `GAP` / `MEDIUM` / `RESOLVED 2026-04-20`
   Reviews 8 and 10 found no shared cooperative cancellation contract in long-running case, archive, memory, and PCAP flows. Post-Review 11 follow-up first added stop checkpoints to the archive and memory loops, and a subsequent async-task pass closed the remaining PCAP and case-analysis slice by introducing one shared async-cancellation token helper, adding cooperative checkpoints to the PCAP Zeek/indexing and case-analysis phase boundaries, and exposing matching route-level cancellation requests without hard worker termination. Focused regressions now lock the remaining archive/memory/PCAP/case-analysis cancellation stop points.

10. `DRIFT-CASE-ANALYZER-FINALIZE` — `DRIFT` / `MEDIUM` / `RESOLVED 2026-04-20`
    Reviews 2b, 8, and 10 re-verified that `utils/case_analyzer.py` had become thinner but still owned terminal persistence, summary shaping, and unified-findings mirroring inline. Post-Review 11 implementation closed this by extracting the finalization tail into a dedicated `pipeline.case_finalize` boundary that persists terminal run state, materializes the summary payload, and mirrors unified findings, with focused regression coverage for the extracted helper.

11. `GAP-EVTX-FALLBACK-PARSER-CONTRACT` — `CORRECTNESS` / `HIGH` / `RESOLVED 2026-04-20`
    Reviews 4a and 10 found that `EvtxFallbackParser` still stored native fallback JSON instead of the normalized `EventData` contract and could also violate the IPv4 column contract. Post-Review 11 implementation closed this by normalizing fallback EVTX `raw_json` onto flattened `EventData`, routing `IpAddress` through the shared IPv4-safe storage helper, preserving non-IPv4 values in parser metadata, and adding focused parser-hardening regressions that compare fallback output shape and IP handling against the primary EVTX contract.

12. `DRIFT-JSON-403-ERROR-SHAPE` — `DRIFT` / `MEDIUM` / `RESOLVED 2026-04-20`
    Reviews 7a, 7b, and 10 confirmed that otherwise-JSON APIs can still emit HTML 403 responses because shared case access enforcement uses `abort(403)`, and async status payloads still vary by blueprint. Post-Review 11 follow-up first normalized the shared API-side forbidden shape, and a subsequent route pass closed the remaining async status slice by routing the live task status/result endpoints in `routes/iocs.py`, `routes/rag.py`, `routes/parsing.py`, and `routes/hunting.py` through one shared async-status envelope helper. Focused route regressions now lock that cross-blueprint status contract.

13. `DRIFT-LEGACY-UNIFIED-FINDINGS-ROUTE` — `DRIFT` / `MEDIUM` / `RESOLVED 2026-04-20`
    Review 7b confirmed that `routes/findings.py` is canonical, but active UI callers still used `/api/rag/unified-findings/<case_id>`. Post-Review 11 implementation closed this by migrating the shipped template callers onto `/api/findings/list/<case_uuid>`, removing the compatibility wrapper from `routes/rag.py`, and adding focused regressions for the canonical route plus the template caller surface.

14. `RISK-IOC-AUDIT-AUTHORITY` — `RISK` / `HIGH` / `RESOLVED 2026-04-20`
    Review 5 found that IOC audit mode was additive in implementation shape but authoritative over the returned candidate set because validated AI deltas mutated the deterministic output in place. Post-Review 11 implementation closed this by preserving the pre-audit deterministic extraction and accepted audit overlay metadata alongside the audited IOC view and by forwarding that distinction through the cached async extraction results, with focused regressions for both the audit-mode pipeline and the processed handoff.

15. `DRIFT-PROVENANCE-L1-FALLBACK` — `DRIFT` / `MEDIUM` / `RESOLVED 2026-04-20`
    Reviews 2b and 6 confirmed that dispatch still fell back to policy provenance when emitted provenance was missing or invalid instead of enforcing producer-emitted tags end to end. Post-Review 11 implementation closed this by making the chat dispatcher reject successful data-bearing tool payloads that omit or emit invalid producer provenance and by adding focused Phase 6 fail-closed regressions for both missing and invalid provenance.

16. `RISK-DET-SQL-PARAMETERIZATION` — `RISK` / `MEDIUM` / `RESOLVED 2026-04-20`
    Review 3a found that `utils/candidate_extractor.py` still interpolated event IDs, time bounds, and pattern-defined `LIKE` fragments into ClickHouse SQL rather than using the parameterized style already present elsewhere in the engine. Post-Review 11 implementation closed this by moving the extractor’s case/event/time/limit filters and per-pattern `LIKE` fragments onto named ClickHouse parameters with one shared literal-escaping boundary, and by adding focused extractor regressions that verify the raw dynamic values stay out of the query text while the parameter payload preserves the intended matching semantics.

### Known Limitation
17. `DRIFT-MEMORY-PARSER-PROVENANCE-CONTRACT` — `DRIFT` / `MEDIUM` / `PARTIAL 2026-04-20`
    Review 4b found that the memory family still bypasses `BaseParser` / `ParsedEvent`, writes into dedicated `memory_*` tables, and gets provenance annotations later in runtime surfaces instead of at parser emit time. Post-Review 11 implementation narrowed that drift by making `parsers/memory_parser.py` emit shared parser provenance on ingest/plugin result envelopes and by making direct `memory_*` serializers emit shared field/parser provenance metadata, but the memory family still does not persist parser provenance on the stored rows or unify onto the shared parsed-event contract.

18. `GAP-BEHAVIORAL-DETECTOR-INTEGRATION` — `DRIFT` / `MEDIUM`
    Review 3b verified that behavioral-anomaly detection still runs, but only brute-force/password-spraying findings are registered for deterministic-engine consumption. Until the product wants those outputs inside the deterministic evidence package, this remains a contract gap rather than a release blocker.

19. `GAP-SCORE-DISPLAY-CONTRACT` — `GAP` / `MEDIUM` / `RESOLVED 2026-04-20`
    Reviews 1 and 7b found that the raw Scoring 2.0 fields existed, but the promised compact analyst/LLM score display contract was not implemented as one shared presentation payload. Post-Review 11 implementation closed this by adding a shared `score_display` payload on deterministic findings and analysis formatter outputs, then updating the analysis-results UI to consume that contract for compact score, emit-eligibility, coverage, and AI-adjustment display instead of recomputing those semantics locally.

20. `GAP-IOC-EVENT-TAG-IDENTITY` — `CORRECTNESS` / `HIGH` / `RESOLVED 2026-04-21`
    Review 5 found that event-level IOC tagging still stored shortened badge labels rather than canonical IOC identity. Operational follow-up on 2026-04-21 closed this by moving IOC event tags onto the `event_ioc_state` overlay table, storing canonical IOC types there with append-only scan inserts instead of mutating `events.ioc_types`, and updating the main hunt/chat/RAG/count read surfaces to consume the effective overlay-backed IOC tag set.

21. `GAP-RAREST-ANCHOR-PIVOT` — `GAP` / `LOW`
    Review 3a found that the event census only skips impossible patterns; the planned rarest-event anchor pivot is still not implemented. This is worthwhile deterministic-core follow-up, but it is optimization/design completeness rather than the current source of a known wrong result.

22. `CORRECTNESS-OFF-HOURS-CASE-TZ` — `CORRECTNESS` / `MEDIUM`
    Review 3a found that `*_off_hours` checks still evaluate `anchor_ts.hour` directly, so off-hours logic currently uses storage/UTC hour instead of the case timezone the product presents as authoritative. This should be fixed, but it is narrower than the broader UTC query-column drift above.

### Nice To Have
Operational follow-up still open after the overlay remediation:
- `PERF-CLICKHOUSE-DELETE-MUTATION-CONTRACT` — `PERF` / `HIGH`
  The remaining high-risk ClickHouse workflows are destructive deletes and dedup deletes. Follow-up work made the contract materially safer by waiting for case rebuild, single-file delete, permanent case/client deletion, single-PCAP delete, and case-wide PCAP rebuild mutations where subsequent logic depends on completion, by making PCAP log reindex wait for the old `network_logs` delete before reinserting rows, by moving case-wide `network_logs` deletion onto a lower-rewrite partition-drop path before any mutation fallback, by rejecting overlapping destructive PCAP `network_logs` routes with explicit active-rewrite context, by serializing explicit case-wide `events` rewrites behind one shared destructive-rewrite guard so delete/rebuild/dedup work does not overlap, by making the case-wide delete task wait for mutation completion instead of stopping at submission, by failing closed when single-file / single-PCAP delete and rebuild-reset ClickHouse deletes fail instead of deleting metadata anyway, by moving manual dedup onto an explicit async task/status surface instead of running it on the request thread, and by making automatic post-ingest dedup skip very large per-artifact rewrites instead of unconditionally issuing them. The unresolved risk is now concentrated mostly in the remaining explicit `events` and artifact-scoped `network_logs` `ALTER TABLE ... DELETE` rewrites under production load even one at a time, especially case-wide event deletes and operator-requested manual dedup on very large artifact families.

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
- Add authorization regression tests for `RISK-VIEWER-WRITE-POLICY-DRIFT` before introducing a shared write guard so the repo proves which routes should be viewer-readable versus viewer-writable.
- `GAP-TASK-FAILURE-STATE-CONTRACT` now has focused contract coverage for both the job-backed archive/memory/PCAP task surfaces and the remaining async IOC/case-analysis/RAG entrypoints, so broker-visible failure state is locked across the reviewed async task boundaries.
- `GAP-ASYNC-CANCELLATION-CONTRACT` now has focused cancellation-checkpoint coverage for the archive, memory, PCAP, and case-analysis stop points that were reworked to share the cooperative async-cancellation contract.
- `DRIFT-JSON-403-ERROR-SHAPE` now has focused coverage for both the shared API 403 response path and the shared async status-envelope contract across the remaining IOC/RAG/parsing/hunting task-status routes.
- `RISK-L1-TOOL-SCHEMA-VALIDATION` and `DRIFT-PROVENANCE-L1-FALLBACK` now both have focused Phase 6 contract coverage on the live L1 boundary: unknown-key/type-mismatch tool argument rejection on one side and fail-closed producer provenance enforcement on the other.
- `GAP-EVTX-FALLBACK-PARSER-CONTRACT` now has parser parity coverage for flattened `EventData` and IPv4-safe `src_ip` handling on the fallback EVTX path.

## Findings That Would Justify A New Review
- No new mandatory Review is required. The current plan covered the codebase; the remaining work is implementation backlog.
- If the team wants review-style checkpoints after fixes land, the only two follow-on Reviews that appear justified are:
  - a deterministic replay Review covering items `16, 21, 22, 27`
  - an async/runtime contract Review covering items `6, 8-15`

## `file_audit.md` Sync Landed In Review 11
- refreshed line counts for the live files touched by the final backlog roll-up
- added the previously omitted deterministic-core entries for `utils/deterministic_evidence_engine.py` and `utils/candidate_extractor.py`
- updated `utils/case_analyzer.py`, `routes/findings.py`, `routes/rag.py`, and `utils/unified_findings.py` notes to the post-Review-10 live state
- documented the then-open stateful-detector contract gaps during Review 11, and post-Review 11 implementation has now closed the configured-window drift while leaving behavioral-anomaly integration as the remaining detector-side contract gap
- added concrete mismatch bullets for the remaining route authorization drift, chat runtime contract drift, and async contract drift
