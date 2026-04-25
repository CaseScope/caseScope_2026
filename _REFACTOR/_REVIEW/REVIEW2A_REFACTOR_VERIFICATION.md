# Review 2a — Refactor Exit-Criteria Verification

Date: 2026-04-20

## Scope
Verify Refactor Phases 0 through 4b against the live repo, cross-check `docs/refactor/file_audit.md` against actual files and behavior, confirm the route split / pattern inventory / TI separation checkpoints called out in the master plan, and land any unambiguous in-scope fixes discovered during verification.

## Review Outcome
- Phase 0: Verified with doc drift corrected.
- Phase 1: Verified.
- Phase 1.5: Verified.
- Phase 2: Verified with documentation nuance corrected.
- Phase 3: Verified.
- Phase 4a: Verified with documentation/test drift corrected.
- Phase 4b: Not fully verified; one live TI-at-detection-time path remains in the task-side AI pattern-analysis flow.

## Per-Phase Verification Table
| Refactor Phase | Criterion | Evidence | Status |
|---|---|---|---|
| 0 | High-risk route or feature-gating ambiguity is resolved. | `utils/feature_availability.py` centrally gates AI/OpenCTI/MISP/TI, exposes `get_feature_snapshot()`, and the shared-gate tests in `tests/test_phase0_feature_gating.py` passed. | Verified |
| 0 | Hot-path TI influence on deterministic detection is identified and documented. | Deterministic overlay application now runs through `pipeline/case_enrichment.py` after pattern analysis, while the remaining pre-persistence TI prompt path is now documented in `docs/refactor/file_audit.md`. | Verified |
| 0 | Transcript-derived artifacts are committed in `docs/refactor/`. | `docs/refactor/file_audit.md`, `finding_contract.md`, `dispatch_state_machine.md`, `agent_loop.md`, `pattern_check_inventory.md`, and `silent_default_audit.md` all exist and were re-audited. | Verified |
| 0 | Plan-referenced file paths are checked against the live repo. | Spot-checks confirmed `routes/api.py` is gone, `routes/findings.py` exists, `utils/gap_detectors/` is gone, and the named Phase 0-4b files are present with current line-count drift reconciled in `docs/refactor/file_audit.md`. | Verified |
| 1 | New contracts exist in code. | `utils/finding_contract.py` exposes canonical builders; `utils/feature_availability.py` exposes the shared capability snapshot; `pipeline/` exists and is live. Contract-surface tests passed. | Verified |
| 1 | New pipeline entry points exist even if legacy callers still adapt. | `pipeline/pattern_analysis.py`, `pipeline/detect.py`, `pipeline/detect_anomalies.py`, `pipeline/case_enrichment.py`, `pipeline/case_timeline.py`, and `pipeline/case_narrative.py` are live and referenced by case/task orchestration. | Verified |
| 1 | `detector_metadata` is part of the locked finding contract. | `docs/refactor/finding_contract.md` and `utils/finding_contract.py` both preserve `detector_metadata` as the additive overflow field. `tests/test_phase1_contract_surfaces.py` passed. | Verified |
| 1.5 | Old overlay call site is deleted in the migration. | `utils/case_analyzer.py` no longer imports `PatternOverlayEnhancer` or applies overlays inline; TI enrichment is delegated to `pipeline.case_enrichment.run_opencti_enrichment()`. | Verified |
| 1.5 | Detection is overlay-free on licensed and unlicensed paths. | `utils/ti/enrichment.py` applies metadata-only overlay context to findings after pattern analysis, preserving authoritative confidence in `ti_enrichment['authoritative_confidence']`. `tests/test_phase15_ti_overlay_separation.py` passed after aligning the stale orchestration assertion to the live stage boundary. | Verified |
| 2 | Existing producers can emit into the unified finding path. | `utils/case_analyzer.py` mirrors finalized findings through `utils.unified_findings_store.sync_case_findings()`, and `utils/unified_findings_store.py` canonicalizes mixed raw findings before ClickHouse insert. | Verified |
| 2 | Downstream consumers can read the unified path without external behavior change. | `utils/unified_findings.py` reads via `load_case_findings()` only, `routes/findings.py` is the canonical API surface, and `tests/test_phase2_unified_findings_store.py` passed. | Verified |
| 2 | High-fidelity evidence can be retained without reviving legacy readers. | `utils/unified_findings_store.py` stores both canonical and legacy JSON alongside normalized fields; readback still uses the mirrored store only. The lingering `summary['read_path']` / `summary['legacy_fallback_used']` fields are compatibility metadata, not a fallback branch. | Verified |
| 3 | `routes/api.py` is reduced to a thin compatibility or registration layer. | Stronger than planned: `routes/api.py` is absent, and `app.py` directly imports/registers extracted blueprints including `findings_bp`. | Verified |
| 3 | Behavior and public routes remain stable after decomposition. | `tests/test_phase3_route_decomposition.py` passed, covering extracted route surfaces, helper extraction, findings blueprint registration, and absence of `api_bp`. | Verified |
| 3 | Shared helper sprawl is kept bounded. | Shared route helpers live in `routes/route_helpers.py` / `routes/hunting_query_helpers.py`, with route tests asserting those shared imports instead of a monolithic `api.py`. | Verified |
| 4a | The check, not the pattern, is the normalized atomic unit. | `scripts/refactor/inventory_checks.py` still regenerates the authoritative CSV from live code. Live counts are 42 patterns / 247 checks, and `docs/refactor/pattern_check_inventory.csv` matches those counts. | Verified |
| 4a | Deterministic producers emit through the unified finding path consistently enough for shared downstream handling. | `utils/hayabusa_correlator.py` emits canonical findings directly; gap findings feed the shared pipeline via `utils/gap_detector_bridge.py` and are normalized again by `utils/unified_findings_store.py` before mirrored storage. | Verified |
| 4a | Dual-path rule loading exists. | `utils/rules/loader.py` loads declarative packs plus Python verifier registrations, burst configs, sequence configs, and spread configs behind one catalog. Rule-loader tests passed. | Verified |
| 4a | `gap_detectors/` naming lie is removed. | The live package is `utils/stateful_detectors/`; `utils/gap_detectors/` is absent. Phase 4a tests were updated to assert the extracted `pipeline.detect_anomalies` call sites rather than stale direct manager imports. | Verified |
| 4b | TI influence is either scheduled rule sync or post-detection enrichment. | `pipeline/case_enrichment.py` and `utils/ti/enrichment.py` keep deterministic overlays post-detection, but `pipeline/pattern_analysis.py` still builds OpenCTI ATT&CK context and passes it through `tasks/rag_tasks.py` into `AICorrelationAnalyzer.analyze_with_evidence(..., threat_intel_context=...)` before that producer persists results. | Drift |
| 4b | No remaining detection-time TI mutation paths. | The deterministic hot path is clean, but the task-side AI producer still takes TI context pre-persistence. That keeps TI influence inside a live producer path rather than purely in post-detection enrichment or scheduled sync. | Not verified |

## Findings
### 1. `DRIFT` / `MEDIUM`
- Location: `pipeline/pattern_analysis.py`, `tasks/rag_tasks.py`, `utils/ai_correlation_analyzer.py`
- Summary: Phase 4b's TI-separation exit criterion is not fully met because task-side AI pattern analysis still injects OpenCTI ATT&CK context into `analyze_with_evidence()` before the AI producer persists its results.
- Proposed fix: either remove pre-persistence TI context from the AI producer flow and keep TI strictly post-detection, or explicitly narrow/restate the Phase 4b claim so the plan matches the shipped architecture. Rough effort: M.

### 2. `DRIFT` / `MEDIUM`
- Location: `docs/refactor/file_audit.md`
- Summary: The file audit had stale line counts and understated two live nuances: the unified findings summary still exposes compatibility metadata, and TI still feeds the task-side AI prompt path.
- Proposed fix: landed in this Review in `2a7c8b4f` by refreshing the audited counts/notes and documenting the remaining AI-side TI prompt path. Rough effort: S.

### 3. `DRIFT` / `MEDIUM`
- Location: `docs/refactor/pattern_check_inventory.md`
- Summary: The inventory doc still described the historical duplicate-key state and a 246-row CSV even though the live registry is now de-duplicated and the generated inventory is 247 checks across 42 patterns.
- Proposed fix: landed in this Review in `2a7c8b4f` by reconciling the narrative to the live registry and current generator output. Rough effort: S.

### 4. `TEST` / `LOW`
- Location: `tests/test_phase15_ti_overlay_separation.py`, `tests/test_phase4a_stateful_detector_entrypoint.py`, `tests/test_phase4a_pattern_sync_reporting_contract.py`
- Summary: Three phase-verification tests were asserting pre-extraction implementation details instead of the current staged boundaries, causing false-negative Review 2a verification noise.
- Proposed fix: landed in this Review in `2a7c8b4f` by updating the assertions to the live stage boundaries (`pipeline.case_enrichment`, `pipeline.detect_anomalies`, and `utils.pattern_sync_execution`). Rough effort: S.

## `file_audit.md` Updates
Landed in `2a7c8b4f`:
- refreshed live line counts for the Phase 0-4b files reviewed in this session
- corrected the `utils/unified_findings.py` note to reflect store-only reads plus remaining summary metadata
- updated Phase 4a notes to the live 42-pattern / 247-check state
- updated `utils/case_analyzer.py` / `utils/feature_availability.py` descriptions to the current staged orchestration
- documented the remaining TI-in-AI-prompt path so the audit no longer implies stricter separation than the code actually provides

## Code Changes Landed During Review 2a
- `docs/refactor/file_audit.md`
  - refreshed Phase 0-4b audit counts/notes and documented the remaining AI-side TI prompt path (`2a7c8b4f`)
- `docs/refactor/pattern_check_inventory.md`
  - reconciled duplicate-key and row-count narrative to the live 42-pattern / 247-check registry (`2a7c8b4f`)
- `tests/test_phase15_ti_overlay_separation.py`
  - updated the Phase 1.5 verification assertion to the live `pipeline.case_enrichment` boundary (`2a7c8b4f`)
- `tests/test_phase4a_stateful_detector_entrypoint.py`
  - updated the Phase 4a assertion to the live `pipeline.detect_anomalies` call sites (`2a7c8b4f`)
- `tests/test_phase4a_pattern_sync_reporting_contract.py`
  - updated the Phase 4a assertion to the extracted `utils.pattern_sync_execution` helper boundary (`2a7c8b4f`)

## Verification Run
- `python3 -m unittest tests.test_phase0_feature_gating tests.test_phase1_contract_surfaces tests.test_phase2_unified_findings_store tests.test_phase3_route_decomposition tests.test_phase15_ti_overlay_separation tests.test_phase4a_pattern_event_mapping_contract tests.test_phase4a_rule_loader_contract tests.test_phase4a_stateful_detector_entrypoint tests.test_phase4a_gap_detector_manager_contract tests.test_phase4a_gap_bridge_normalization tests.test_phase4a_producer_inputs_normalization tests.test_phase4a_inventory_generator tests.test_phase4a_pattern_sync_execution_contract tests.test_phase4a_attack_pattern_loader_contract tests.test_phase4a_pattern_sync_reporting_contract tests.test_phase4a_sigma_converter_contract tests.test_phase4a_pattern_suppression_contract`
- Result: `OK` (130 tests)
