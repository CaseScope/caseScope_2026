# Review 10 — Cross-Cutting Concerns and Dead Code Sweep

Date: 2026-04-20

## Scope
Consolidate the cross-cutting carry-forward from Reviews 1-9, verify dead-code and compatibility-shim candidates in the live repo, audit duplicated/legacy read surfaces, and spot tests that still assert refactor-era implementation details instead of behavior.

## Review Outcome
- Review 10 confirmed that the biggest remaining cross-cutting risks are still temporal/query determinism, async task-state contracts, and route/orchestration drift rather than broad dead-code accumulation.
- The dead-code sweep found one clear live cleanup target: `utils/unified_findings.py` still carried unreachable in-process legacy readers even though the only active path is the ClickHouse mirror.
- Review 10 landed four narrow in-scope fixes: retiring those dead unified-findings readers, bounding the OpenCTI connector catalog cache, memoizing prompt-scope threat-intel lookups while skipping redundant CVE exact lookups, and adding runtime metrics to streamed chat calls.
- The test audit confirmed a recurring refactor-era pattern of source-text/assert-string tests. Review 10 only tightened one nearby store test to assert named columns rather than tuple offsets; the broader rewrite remains backlog work.

## Findings
### 1. `CORRECTNESS` / `HIGH`
- Location: `utils/deterministic_evidence_engine.py:212`, `utils/deterministic_evidence_engine.py:270`, `utils/deterministic_evidence_engine.py:1247`, `utils/deterministic_evidence_engine.py:1301`, `utils/deterministic_evidence_engine.py:1882`, `utils/stateful_detectors/password_spraying.py:88`, `utils/stateful_detectors/brute_force.py:98`
- Summary: the temporal evaluation contract still drifts across detection surfaces: deterministic-engine SQL predicates continue to filter on raw `timestamp`, `_compute_window()` still falls back to `datetime.utcnow()` when an anchor timestamp cannot be parsed, and the brute-force/password-spraying detectors still configure `time_window_hours` without applying that bound in candidate queries.
- Proposed fix: keep this as a Review 10 carry-forward bundle for backlog prioritization. The concrete fix is to standardize detection queries on the UTC-normalized query column, make malformed anchor timestamps fail closed or use a deterministic case-bound fallback, and apply explicit time-window predicates/bucketing in the stateful detector SQL. Rough effort: L.

### 2. `GAP` / `MEDIUM`
- Location: `utils/deterministic_evidence_engine.py:51`, `utils/pattern_check_definitions.py:2915`, `models/behavioral_profiles.py:629`, `parsers/evtx_parser.py:806`
- Summary: three planned-but-unshipped detector contracts still remain open together: the deterministic engine stores `census` but never uses it for rarest-anchor pivoting, behavioral anomaly finding types still do not map into `GAP_FINDING_CHECK_BINDINGS`, and `EvtxFallbackParser` still persists weaker `raw_json` / `src_ip` data than the primary EVTX path.
- Proposed fix: keep these as separate backlog items rather than widening Review 10 further. Rarest-anchor pivot needs a design-backed engine change; behavioral anomaly integration needs explicit check mappings or a deliberate exclusion decision; EVTX fallback needs targeted contract parity work around `EventData` flattening and IP normalization. Rough effort: M/L depending on item.

### 3. `DRIFT` / `MEDIUM`
- Location: `utils/case_analyzer.py:1001`, `routes/rag.py:815`, `routes/findings.py:30`, `static/templates/case_hunting.html:260`, `static/templates/case_hunting_network.html:108`, `models/case.py:170`
- Summary: the route/orchestration cleanup is still only partially finished. `CaseAnalyzer._finalize_analysis()` still owns final summary shaping, mirror persistence, and unified-findings sync; the legacy `/api/rag/unified-findings/<case_id>` compatibility route still serves active template callers even though `routes/findings.py` is canonical; and shared case-access enforcement still uses `abort(403)`, so JSON APIs can still surface HTML 403s.
- Proposed fix: preserve the current compatibility route until caller migration is complete, then retire it; introduce a JSON-aware shared access helper or 403 error handler for API surfaces; and keep any `case_analyzer` thinning as a deliberate follow-up refactor rather than opportunistic Review 10 surgery. Rough effort: M.

### 4. `RISK` / `HIGH`
- Location: `tasks/celery_tasks.py:550`, `tasks/archive_tasks.py:328`, `tasks/memory_tasks.py:206`, `tasks/pcap_tasks.py:428`, `routes/rag.py:1195`, `routes/memory.py:616`
- Summary: the async contract drift from Review 8 still holds. Multiple task paths return `{"success": false, ...}` payloads instead of raising, so broker-level task state can still read as `SUCCESS`, and cancellation remains route-level revoke/terminate behavior rather than a shared cooperative stop contract inside long-running stages.
- Proposed fix: treat this as one backlog theme. Move task-failure handling onto an explicit Celery failure contract and thread cooperative cancellation checkpoints through long-running orchestrators instead of depending on process termination. Rough effort: L.

### 5. `TEST` / `MEDIUM`
- Location: `tests/test_phase3_route_decomposition.py`, `tests/test_case_analysis_pipeline.py`, `tests/test_phase7_pattern_task_execution_stage.py`, `tests/test_route_security_regressions.py`
- Summary: several refactor-era regression suites still assert source text, helper names, decorator stacking, or exact import strings instead of user-visible route/task behavior. This keeps implementation cleanup artificially expensive and makes harmless refactors fail tests for non-behavioral reasons.
- Proposed fix: rewrite the strongest offenders toward `test_client` route behavior, mocked task-entrypoint behavior, and stable payload assertions. Review 10 only landed one local improvement nearby by changing the unified-findings store test to assert named inserted columns rather than tuple offsets. Rough effort: M.

### 6. `DEAD` / `LOW`
- Location: `utils/unified_findings.py:1`
- Summary: `utils/unified_findings.py` still carried the full in-process System 1/2/3 legacy reader stack even though `get_unified_findings()` had already become store-backed only and no live callers used those helpers anymore.
- Proposed fix: landed in this Review by removing the unreachable legacy reader helpers and their no-longer-needed imports while preserving the current response shape (`read_path`, `legacy_fallback_used`, `store_backed`) for compatibility. Rough effort: S. Commit: local Review 10 checkpoint.

### 7. `RISK` / `MEDIUM`
- Location: `utils/opencti.py:69`, `utils/opencti.py:272`
- Summary: Review 9's connector-cache freshness drift was real: active connector metadata was cached for the lifetime of the process with no freshness bound.
- Proposed fix: landed in this Review by adding a bounded connector-catalog TTL so admin/IOC-hint surfaces refresh automatically without restart. Rough effort: S. Commit: local Review 10 checkpoint.

### 8. `PERF` / `MEDIUM`
- Location: `utils/threat_intel_context.py:97`
- Summary: Review 9's prompt-building lookup fanout also still held: duplicate IOC values triggered duplicate `lookup_threat_intel()` calls, and CVE values took the generic exact-IOC lookup path before the dedicated vulnerability-context fetch.
- Proposed fix: landed in this Review by memoizing prompt-scope IOC lookups and skipping the redundant exact-IOC lookup for CVEs, leaving vulnerability context to the dedicated OpenCTI call. Rough effort: S. Commit: local Review 10 checkpoint.

### 9. `RISK` / `LOW`
- Location: `utils/ai/router.py:333`
- Summary: Review 6's streamed-chat observability gap still held: `invoke_text()` / `invoke_json()` recorded runtime metrics, but `stream_chat()` did not.
- Proposed fix: landed in this Review by recording runtime metrics for streamed chat calls and attaching the runtime payload to terminal/error chunks so downstream chat/report surfaces can observe duration and cache/token metadata consistently. Rough effort: S. Commit: local Review 10 checkpoint.

## Code Changes Landed During Review 10
- `utils/unified_findings.py`
  - removed the unreachable in-process legacy readers and kept the live unified-findings surface explicitly store-backed only
- `utils/opencti.py`
  - added a bounded TTL to the active connector catalog cache so connector metadata refreshes without process restart
- `utils/threat_intel_context.py`
  - memoized prompt-scope IOC lookups and skipped redundant generic CVE exact lookups before vulnerability-context fetches
- `utils/ai/router.py`
  - added streamed-chat runtime metric recording and attached runtime metadata to terminal/error chunks
- `tests/test_phase2_unified_findings_store.py`
  - updated the unified-findings store regression to assert named inserted columns instead of tuple positions and removed assumptions about deleted legacy reader helpers
- `tests/test_phase6_ai_router_contract.py`
  - added regression coverage for streamed-chat runtime metric recording
- `tests/test_opencti_exact_enrichment.py`
  - added regression coverage for connector cache TTL expiry
- `tests/test_threat_intel_context.py`
  - added regression coverage for prompt-scope IOC lookup memoization and CVE lookup skipping

## Verification Run
- `python3 -m unittest tests.test_phase2_unified_findings_store tests.test_phase6_ai_router_contract tests.test_opencti_exact_enrichment tests.test_threat_intel_context`
- Result: `OK` (23 tests)

## Review 10 Hand-off
- Review 10 is complete.
- Cross-cutting carry-forward remains concentrated in five unresolved themes: temporal/query determinism, planned-but-unshipped detector contracts, route/orchestration drift, async failure/cancellation semantics, and implementation-coupled refactor tests.
- Review 10 directly resolved four narrower cross-cutting items: `GAP-CHAT-STREAM-METRICS`, `DRIFT-OPENCTI-CONNECTOR-CACHE-FRESHNESS`, `GAP-THREAT-INTEL-CONTEXT-CACHING`, and the newly identified dead unified-findings legacy readers.
- The next Review should treat the remaining Review 10 findings as backlog input rather than assuming more cleanup is still hidden in dead code; the highest-risk unresolved work is still correctness/contract work, not further deletion.
