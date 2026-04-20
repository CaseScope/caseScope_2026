# Review 2b — Refactor Exit-Criteria Verification

Date: 2026-04-20

## Scope
Verify Refactor Phases 5 through 9, plus Refactor Phase 6.5, against the live repo; cross-check `docs/refactor/file_audit.md` against actual files and behavior for the reviewed phases; confirm the IOC boundary, AI-router, parser-provenance, case-analysis decomposition, overlay-authority, and Phase 9 retirement checkpoints called out in the master plan; and land any unambiguous in-scope fixes discovered during verification.

## Review Outcome
- Phase 5: Verified for deterministic execution, additive/schema-validated AI augmentation, and canonical production-facing facade usage; residual tooling-side direct imports remain.
- Phase 6: Verified for the named caller set using `utils/ai/router.py`; one IOC sub-stage consistency drift remains because semantic/audit execution still calls `provider.generate_json()` directly after router resolution.
- Phase 6.5: Partially verified. Parser and producer provenance emission is live, but dispatch still falls back to policy defaults when emitted provenance is missing or invalid.
- Phase 7: Partially verified. Stage decomposition is real and tasks invoke shared stages, but `utils/case_analyzer.py` still owns terminal persistence/summary orchestration rather than being orchestration-only in the strictest sense.
- Phase 8: Verified. Overlay context remains metadata-only and does not change authoritative deterministic ranking or emitted confidence.
- Phase 9: Verified for store-only findings reads, dedicated `routes/findings.py` wiring, retained canonical IOC facade, and explicit TI rule-sync deferral.

## Per-Phase Verification Table
| Refactor Phase | Criterion | Evidence | Status |
|---|---|---|---|
| 5 | IOC extraction can run deterministically without AI. | `utils/ioc_extractor.py` runs deterministic extraction first via `run_deterministic_ioc_extraction()` / `_deterministic_stage.run_deterministic_stage(...)`, and `extract_iocs_with_ai()` returns deterministic-only results when AI is unavailable. `tasks/celery_tasks.py` also uses `run_deterministic_ioc_extraction()` directly for background flows. | Verified |
| 5 | Optional AI IOC handling is additive and schema-validated. | `run_ioc_pipeline_with_provider()` merges semantic/audit results back onto deterministic output via `utils/ioc_merge.py`, validates AI task results through `ioc_contract_adapter` hooks, and materializes low-trust `_ioc_records` separately from deterministic records. | Verified |
| 5 | `utils/ioc_extractor.py` is the canonical public IOC facade for live product entry points. | The module declares an explicit `__all__` surface, `routes/iocs.py` imports public helpers from the facade, `tasks/celery_tasks.py` uses public facade helpers, and `utils/opencti.py` uses `extract_derived_indicator_candidates()` rather than reaching into regex internals. | Verified |
| 5 | Callers no longer reach past the IOC facade. | Production route/task/enrichment callers no longer do, but tooling/evaluation modules such as `utils/ioc_training_dataset.py` and `utils/ioc_model_eval.py` still import extracted IOC modules directly. | Drift |
| 6 | `chat_agent.py`, `ai_report_generator.py`, `ai_timeline_generator.py`, `ai_checkpoints.py`, `ioc_extractor.py`, and `rag_llm.py` go through `utils/ai/router.py`. | Each named file now imports router helpers such as `stream_chat`, `invoke_text`, `invoke_json`, `get_provider_descriptor`, or `resolve_provider`; no reviewed feature module still acquires providers via `get_llm_provider(...)` directly. | Verified |
| 6 | Feature-specific IOC AI execution is fully normalized onto the shared router runtime, not just provider resolution. | `utils/ioc_extractor.py` resolves the provider through `utils/ai/router.py`, but `utils/semantic_ioc_extractor.py` and `utils/ioc_audit.py` still call `provider.generate_json(...)` directly instead of the shared `invoke_json(...)` wrapper. | Drift |
| 6.5 | Parsers emit provenance tags. | `parsers/base.py` computes `field_provenance`, `emitted_provenance`, and `provenance_source` in `ParsedEvent._build_parser_provenance()` and serializes them into `extra_fields` before ClickHouse insert. | Verified |
| 6.5 | Producer/chat-tool surfaces thread parser/producer provenance through the shared handoff. | `utils/provenance.py`, `utils/forensic_chat_sources.py`, and `utils/chat_tools.py` merge record provenance and attach shared `_provenance` payload metadata for downstream consumption. | Verified |
| 6.5 | Dispatch validates emitted provenance tags rather than fallback defaults. | `utils/chat/dispatch.py` prefers emitted `_provenance` when present and valid, but falls back to the policy provenance when metadata is missing or invalid; `utils/chat/policy.py` still defines per-tool fallback provenance. | Drift |
| 7 | Explicit case-analysis stages exist and can be invoked independently outside `CaseAnalyzer`. | `pipeline/case_enrichment.py`, `pipeline/case_timeline.py`, `pipeline/case_narrative.py`, `pipeline/case_actions.py`, `pipeline/detect.py`, `pipeline/detect_anomalies.py`, and `pipeline/baselines.py` are live, and `tasks/rag_tasks.py` invokes shared stage helpers directly. | Verified |
| 7 | `utils/case_analyzer.py` is orchestration-only rather than owning multi-domain logic. | The analyzer now delegates pattern analysis, anomaly detection, TI enrichment, timeline/narrative generation, and suggested actions to pipeline stages, but it still owns terminal persistence, progress bookkeeping, summary shaping, and unified-findings sync in `_finalize_analysis()`. | Drift |
| 8 | `pattern_overlay.py` and the live TI overlay path strictly annotate rather than mutate authoritative confidence. | `utils/ti/enrichment.py` writes `overlay_score_adjustment`, `intel_overlay`, and `ti_enrichment['display_confidence_preview']` while preserving `ti_enrichment['authoritative_confidence']`; `pipeline/pattern_analysis.py` still ranks/materializes packages by `deterministic_score` only; `EvidencePackage.final_score()` only adds bounded AI adjustment. | Verified |
| 8 | Premium overlays do not silently steer deterministic package selection. | `pipeline/pattern_analysis.authoritative_package_score()` returns `package.deterministic_score`, and the live enrichment path runs after findings exist rather than mutating package selection in the hot path. | Verified |
| 9 | The legacy unified-findings fallback path is removed. | `utils/unified_findings.py` reads only from `load_case_findings(case_id)` and unconditionally reports `legacy_fallback_used = False`; the remaining field is compatibility/telemetry metadata, not an executable fallback branch. | Verified |
| 9 | `routes/findings.py` exists and is wired into the app. | `routes/findings.py` defines `findings_bp`, and `app.py` imports and registers that blueprint. | Verified |
| 9 | The IOC facade retirement decision is resolved in live code. | The live boundary is to keep `utils/ioc_extractor.py` as the canonical orchestration facade; callers now use its public helpers rather than deleting the module outright. | Verified |
| 9 | TI rule sync is explicitly deferred rather than silently missing. | `utils/ti/rule_sync.py` is absent, and `docs/refactor/file_audit.md` now accurately records the deferral instead of implying the file should exist. | Verified |

## Findings
### 1. `DRIFT` / `MEDIUM`
- Location: `utils/semantic_ioc_extractor.py`, `utils/ioc_audit.py`, `utils/ai/router.py`
- Summary: Phase 6's named callers do resolve providers through `utils/ai/router.py`, but the IOC semantic and audit sub-stages still call `provider.generate_json(...)` directly, so they bypass the shared `invoke_json(...)` runtime metadata/metrics path.
- Proposed fix: route those sub-stage calls through `invoke_json(...)` or a shared wrapper that preserves their current task metadata while keeping provider selection in the router. Rough effort: M.

### 2. `DRIFT` / `MEDIUM`
- Location: `parsers/base.py`, `utils/chat/dispatch.py`, `utils/chat/policy.py`
- Summary: Phase 6.5's provenance emission is live, but dispatch L1 still falls back to policy provenance when emitted provenance is missing or invalid instead of enforcing producer-emitted tags as the remaining-refactor plan claimed.
- Proposed fix: either tighten L1 to reject/flag missing provenance explicitly, or narrow the refactor claim so it matches the shipped "prefer emitted, else fallback" behavior. Rough effort: M.

### 3. `DRIFT` / `MEDIUM`
- Location: `utils/case_analyzer.py`
- Summary: Phase 7's stage extraction is materially complete, but `CaseAnalyzer` still owns terminal persistence, progress/result summarization, and unified-findings sync, so the "orchestration-only" claim is only partially true.
- Proposed fix: continue extracting the finalization/sync path into a dedicated pipeline stage or restate the phase as "thin orchestrator plus terminal persistence shell." A low-risk duplicate suggested-action helper cleanup was landed during this Review. Rough effort: M; landed cleanup pending local checkpoint commit.

### 4. `DRIFT` / `LOW`
- Location: `utils/ioc_training_dataset.py`, `utils/ioc_model_eval.py`
- Summary: A small tooling/evaluation surface still imports extracted IOC modules directly instead of staying entirely behind `utils/ioc_extractor.py`.
- Proposed fix: either document these as explicitly out-of-band tooling surfaces or migrate them onto facade helpers for a stricter Phase 5 boundary. Rough effort: S/M.

### 5. `DRIFT` / `LOW`
- Location: `_REFACTOR/remaining_refactor_work_3b16c544.plan.md`
- Summary: The remaining-refactor plan still describes several Phase 5-9 checkpoints as open in ways the live repo has already surpassed, including parser provenance emission, the dedicated findings route, and the store-only unified findings read path.
- Proposed fix: refresh the remaining-refactor plan narrative or treat `docs/refactor/file_audit.md` plus this Review artifact as the current baseline. Rough effort: S.

## `file_audit.md` Updates
Landed in this Review working tree:
- refreshed `utils/case_analyzer.py` line count and note to reflect the current `pipeline.case_actions` boundary
- refreshed `tasks/rag_tasks.py` line count
- re-verified that the existing `utils/unified_findings.py`, `routes/findings.py`, `utils/ioc_extractor.py`, `utils/pattern_overlay.py`, and `utils/ti/enrichment.py` notes still match live behavior

## Code Changes Landed During Review 2b
- `utils/case_analyzer.py`
  - removed stale duplicate suggested-action helper methods so the live path remains centralized in `pipeline.case_actions` (local checkpoint commit still pending)
- `utils/rag_llm.py`
  - corrected the module docstring to describe the live shared-router boundary instead of the old direct-provider wording (local checkpoint commit still pending)
- `docs/refactor/file_audit.md`
  - refreshed Phase 5-9 audit counts/notes touched by this review (local checkpoint commit still pending)

## Verification Run
- `python3 -m unittest tests.test_phase5_ioc_text_contract tests.test_phase5_ioc_merge_contract tests.test_phase5_ioc_normalizer_contract tests.test_phase5_ioc_contract_adapter_contract tests.test_phase6_ai_router_contract tests.test_phase6_ai_correlation_runtime_contract tests.test_phase6_ai_review_runtime_contract tests.test_phase6_ai_report_runtime_contract tests.test_phase6_ai_timeline_runtime_contract tests.test_phase6_ai_event_summary_runtime_contract tests.test_phase6_chat_runtime_contract tests.test_phase6_chat_agent_runtime_flow_contract tests.test_phase6_chat_agent_dispatch_contract tests.test_phase6_chat_route_approval_contract tests.test_phase65_parser_provenance_contract tests.test_phase7_case_stage_contracts tests.test_phase7_baselines_stage tests.test_phase7_detect_stage tests.test_phase7_detect_anomalies_stage tests.test_phase7_pattern_package_selection_stage tests.test_phase7_pattern_materialization_stage tests.test_phase7_pattern_threat_intel_stage tests.test_pattern_overlay tests.test_opencti_exact_enrichment tests.test_phase2_unified_findings_store`
- Result: `OK` (focused Review 2b suite passed)

## Next Review Hand-off
- Review 3 should pick up the unresolved Scoring 2.0 / deterministic-core correctness threads, especially the already-logged `GAP-V2-SEQUENCE-COVERAGE`.
- Review 6 should revisit the IOC sub-stage router consistency gap and the dispatch provenance fallback behavior as runtime-boundary concerns.
- Review 8 should treat `utils/case_analyzer.py` as "mostly decomposed but not yet orchestration-only" and verify the remaining finalization/store-sync responsibilities for correctness.
- Review 9 should continue from the carried-forward `GAP-TI-AI-PROMPT-PATH` caveat: TI no longer mutates deterministic detection, but task-side AI pattern-analysis prompts still take OpenCTI context before producer persistence.
