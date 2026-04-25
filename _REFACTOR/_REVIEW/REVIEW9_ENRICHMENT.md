# Review 9 — Enrichment and External Integrations

Date: 2026-04-20

## Scope
Review the live enrichment and external-integration surface in `utils/pattern_overlay.py`, `utils/ti/enrichment.py`, `utils/opencti.py`, `utils/opencti_context.py`, `utils/misp.py`, `utils/mitre_attack_sync.py`, `utils/peer_clustering.py`, `utils/behavioral_profiler.py`, and `utils/threat_intel_context.py` for additive-only TI behavior, query construction, error handling, caching/freshness, and case-scope correctness.

## Review Outcome
- `utils/pattern_overlay.py` growth does **not** represent a regression back to pre-emission TI mutation. The live overlay path remains metadata-only: `utils/ti/enrichment.py` attaches `intel_overlay` / `ti_enrichment` fields and preserves the stored detector confidence as authoritative.
- `EvidencePackage.final_score()` still ignores `overlay_score_adjustment`; the overlay remains advisory/display metadata rather than a persisted score input.
- Review 9 directly re-verified the carried-forward `GAP-TI-AI-PROMPT-PATH`: the task-side AI pattern flow was still injecting OpenCTI ATT&CK prompt context into `analyze_with_evidence()` before persistence. That violated the additive-only TI invariant and was fixed in this Review.
- Review 9 landed four narrow in-scope fixes: the task-side TI prompt path, a malformed MITRE credential-dump query, peer-group member loss on undersized clusters, and MISP exact-match normalization drift.

## Findings
### 1. `GAP` / `HIGH`
- Location: `pipeline/pattern_analysis.py:217`, `tasks/rag_tasks.py:2970`, `utils/ai_correlation_analyzer.py:310`
- Summary: before this Review's patch, task-side AI pattern analysis passed OpenCTI ATT&CK prompt context into `analyze_with_evidence()` before `finalize_deterministic_package(...)`, so threat-intel text could influence persisted AI score adjustments even though the TI contract is additive-only.
- Proposed fix: landed in this Review by removing `threat_intel_context` from the task-side scoring path while keeping the post-detection TI overlay surface intact. Rough effort: S. Commit: local Review 9 checkpoint.

### 2. `BUG` / `CRITICAL`
- Location: `utils/mitre_attack_sync.py:557`
- Summary: `_generate_credential_dump_query()` built its default `event_list` as a Python tuple because of operator precedence, producing malformed `event_id IN (...)` SQL whenever a credential-dumping technique reached the fallback event-id path.
- Proposed fix: landed in this Review by forcing the fallback event IDs into one joined string before interpolation. Rough effort: S. Commit: local Review 9 checkpoint.

### 3. `CORRECTNESS` / `HIGH`
- Location: `utils/peer_clustering.py:298`
- Summary: `_create_peer_groups()` dropped members of undersized non-outlier clusters entirely. The comment said small clusters would be merged with the nearest cluster, but the live code just `continue`d, leaving some profiled entities with no peer-group membership.
- Proposed fix: landed in this Review by reassigning undersized clusters to the nearest eligible cluster, with an outlier fallback when no eligible cluster exists. Rough effort: S. Commit: local Review 9 checkpoint.

### 4. `CORRECTNESS` / `HIGH`
- Location: `utils/misp.py:113`, `utils/misp.py:216`
- Summary: exact MISP attribute matching normalized request-side IOC values using CaseScope type names but normalized attribute-side values using raw MISP attribute types (`sha256`, `regkey`, etc.). Case-variant hashes and similar values could therefore false-negative even when MISP returned the correct attribute.
- Proposed fix: landed in this Review by teaching `_normalize_lookup_value()` to normalize both CaseScope IOC type names and MISP attribute type identifiers. Rough effort: S. Commit: local Review 9 checkpoint.

### 5. `RISK` / `MEDIUM`
- Location: `utils/opencti.py:262`
- Summary: `get_connectors()` memoizes the active-only connector catalog for the lifetime of the process with no TTL or explicit invalidation path. Admin/status views and IOC enrichment hints can therefore drift from live OpenCTI connector state until the worker process restarts.
- Proposed fix: add a bounded TTL or explicit invalidation on settings/health refresh so connector metadata freshness does not depend on process lifetime. Rough effort: M.

### 6. `PERF` / `MEDIUM`
- Location: `utils/threat_intel_context.py:94`
- Summary: `get_threat_intel_context()` performs up to 10 synchronous `lookup_threat_intel()` calls per prompt build and also sends CVE values through exact IOC lookup before separate vulnerability-context queries. Narrative/report prompt construction can therefore fan out repeated provider traffic unnecessarily.
- Proposed fix: cache prompt-scope IOC lookups and skip the exact IOC lookup for CVE values in favor of `get_vulnerability_context()`. Rough effort: M.

## Code Changes Landed During Review 9
- `pipeline/pattern_analysis.py`
  - stopped threading `threat_intel_context` into task-side `run_full_analysis_for_package(...)`, preserving additive-only TI behavior for persisted AI pattern findings
- `tasks/rag_tasks.py`
  - removed the task-side `analyze_with_evidence(..., threat_intel_context=...)` call path so OpenCTI ATT&CK context no longer influences persisted AI score adjustments
- `utils/mitre_attack_sync.py`
  - fixed the fallback credential-dump event-id list so generated SQL uses a valid `IN ('4656', '4663', '10')` clause
- `utils/peer_clustering.py`
  - reassigned undersized non-outlier clusters instead of silently dropping their members from all peer groups
- `utils/misp.py`
  - aligned exact-match normalization across CaseScope IOC types and raw MISP attribute types
- `tests/test_phase7_pattern_task_execution_stage.py`
  - updated the task execution contract to assert TI context is not fed into the persisted full-analysis scoring path
- `tests/test_phase7_pattern_task_iteration_stage.py`
  - updated helper signatures to match the non-authoritative task-side AI path
- `tests/test_misp_enrichment.py`
  - added regression coverage for exact-match normalization against raw MISP hash types
- `tests/test_mitre_attack_sync.py`
  - added regression coverage for the credential-dump fallback query builder
- `tests/test_peer_clustering.py`
  - added regression coverage proving undersized clusters are reassigned instead of dropped

## Verification Run
- `venv/bin/python -m unittest tests.test_phase7_pattern_task_execution_stage tests.test_phase7_pattern_task_iteration_stage tests.test_misp_enrichment tests.test_mitre_attack_sync tests.test_peer_clustering`
- Result: `OK` (9 tests)

## Review 9 Hand-off
- Review 9 is complete.
- `DRIFT-OVERLAY-LINES` and `GAP-TI-AI-PROMPT-PATH` were both directly re-verified and resolved here: the live TI overlay surface remains metadata-only, and the last pre-persistence task-side TI prompt injection path has been removed.
- Remaining Review 9 follow-up is narrower than the landed fixes and did not justify widening this session:
  - OpenCTI connector metadata cache freshness still depends on process lifetime
  - narrative/report threat-intel prompt building still performs uncached per-IOC provider lookups and redundant CVE exact-lookups
