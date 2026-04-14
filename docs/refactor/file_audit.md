# File Audit

## Status
Phase 0 deliverable. This file exists to stop the plan from drifting onto ghost files or stale assumptions.

## Audit Time Snapshot
Line counts and existence checks were captured during this revision pass.

## Plan-Referenced Existing Files

| Path | Exists | Line count | Notes |
| --- | --- | ---: | --- |
| `routes/api.py` | no | removed | Phase 9 retired the final route-level compatibility shim after migrating the remaining repo tests to `routes.route_helpers` and `routes.hunting_query_helpers`. |
| `utils/unified_findings.py` | yes | 327 | Current unified finding read path area. |
| `utils/ioc_extractor.py` | yes | present | External IOC entry point retained during Phase 5 decomposition; explicit Phase 9 decision required to either keep it as the real orchestrator or migrate callers and delete the facade. |
| `utils/pattern_check_definitions.py` | yes | 2937 | Live duplicate-key issue at `security_tool_tampering`. |
| `utils/pattern_event_mappings.py` | yes | 1618 | Live companion file for pattern semantics and mappings. |
| `utils/hayabusa_correlator.py` | yes | 745 | Needs unified finding emission in later phases. |
| `utils/pattern_overlay.py` | yes | 384 | Phase 8 overlay-authority contract surface; overlay context now remains explicit metadata on packages instead of mutating deterministic package scores before downstream selection/materialization. |
| `utils/provenance.py` | yes | present | Phase 6.5 shared parser-to-runtime provenance helper surface for per-field artifact tagging, rollup calculation, and producer payload handoff into the shared chat runtime. |
| `utils/forensic_chat_sources.py` | yes | present | Shared forensic chat producer surface; `search_artifacts`, browser-download retrieval, memory search, unified process retrieval, unified process-tree retrieval, and network-log retrieval now emit shared payload provenance metadata derived from normalized artifact records instead of relying on dispatch-side defaults. |
| `utils/chat_tools.py` | yes | present | Direct chat-tool producer surface; `query_events`, `count_events`, `get_findings`, `lookup_ioc`, and `lookup_threat_intel` now emit shared payload provenance metadata or forward shared producer metadata instead of falling back to dispatcher defaults, and Phase 8 now routes optional IOC TI enrichment through the shared premium-availability gate instead of an ad hoc tool-local check. |
| `utils/chat_agent.py` | yes | present | Shared chat runtime surface; Phase 8 now grounds the assistant with an explicit premium-context guardrail so TI and RAG context remain supporting evidence rather than detector-of-record authority. |
| `utils/case_analyzer.py` | yes | 1380 | Current orchestration bottleneck and overlay call site; gap detection and more of both the AI and rule-based pattern-analysis orchestration now route through shared `pipeline/` stage helpers, including the shared case-side orchestration head, shared pre-branch pattern preparation step, shared case-side runtime setup, shared case-side AI execution handoff, shared per-pattern case iteration stage, shared per-pattern case loop shell, and shared case-side completion tail. |
| `utils/ai_checkpoints.py` | yes | present | Phase 8 narrative checkpoint surface; triage and synthesis prompts now explicitly keep TI and RAG context as supporting context only and preserve deterministic findings as the authority of record. |
| `tasks/rag_tasks.py` | yes | 3026 | AI correlation task now reuses shared pattern-analysis helpers for setup, per-pattern progress payload construction, per-pattern iteration orchestration, cleanup handling, final tail orchestration, final overlap annotation, and response packaging, while still retaining task-specific provider initialization and outer error/stat aggregation; semantic pattern-discovery metadata is now explicitly marked as prioritization-only rather than authoritative detection. |
| `routes/rag.py` | yes | present | RAG route surface; Ask-AI prompt/response handling now labels TI and semantic context as grounded assistance only, not detector-of-record proof, and returns explicit authority metadata for the analyst-facing answer path. |
| `pipeline/__init__.py` | yes | 86 | Shared pipeline package export surface now populated beyond the original pattern-analysis wrappers. |
| `pipeline/pattern_analysis.py` | yes | 1117 | Pattern-analysis stage surface now includes shared extractor/evidence setup wrappers, case-side orchestration head handling, case-side runtime setup orchestration, case-side pre-branch pattern preparation, case-side AI execution orchestration, case-side per-pattern iteration orchestration, case-side per-pattern loop orchestration, case-side completion tail orchestration, task-side progress payload construction, task-side completion payload construction, task-side iteration orchestration, task-side cleanup handling, task-side completion tail orchestration, task-side completion log emission, task-side AI execution orchestration, final overlap annotation, task response packaging, concise per-pattern threat-intel prompt assembly, census, eligibility filtering, stable ordering, evidence-package selection, suppression, materialization, package processing, evaluation, persistence, and rule-based result-persistence helpers; Phase 8 now makes the authoritative package score boundary explicit so overlay metadata cannot silently steer package selection or deterministic-score persistence. |
| `pipeline/baselines.py` | yes | 62 | Phase 7 baseline-building stage surface for behavioral profiling and peer clustering. |
| `pipeline/detect.py` | yes | 34 | Phase 7 detection-stage surface for Hayabusa correlation and attack-chain building. |
| `pipeline/detect_anomalies.py` | yes | 21 | Phase 7 anomaly-detection stage surface for shared gap-detection orchestration. |
| `utils/feature_availability.py` | yes | 541 | Current feature source-of-truth candidate; Phase 8 now uses it as the shared premium TI gate for chat-tool licensing, IOC enrichment, and OpenCTI context-provider availability checks. |
| `utils/opencti_context.py` | yes | present | OpenCTI context-provider surface now defers premium availability decisions to `utils/feature_availability.py` instead of re-implementing its own activation/config/settings gate stack. |
| `utils/ioc_contract_adapter.py` | yes | present | Phase 5 IOC contract coercion, review gating, and task-field filtering surface. |
| `utils/ioc_merge.py` | yes | present | Phase 5 shared IOC merge surface. |
| `utils/ioc_normalizer.py` | yes | present | Phase 5 shared IOC normalization and AI-guardrail surface. |
| `utils/ioc_text.py` | yes | present | Phase 5 deterministic IOC text normalization helpers kept outside the optional AI normalization layer. |
| `utils/ioc_audit.py` | yes | 688 | Verified present. |
| `utils/ioc_model_eval.py` | yes | 557 | Verified present. |
| `utils/stateful_detectors/__init__.py` | yes | 218 | Phase 4a stateful-detector entrypoint and orchestration package. |
| `utils/stateful_detectors/behavioral_anomaly.py` | yes | 434 | Kept in stateful detectors for Phase 4a; deferred move tracked below. |
| `utils/stateful_detectors/brute_force.py` | yes | 403 | Stateful detector implementation. |
| `utils/stateful_detectors/password_spraying.py` | yes | 449 | Stateful detector implementation. |
| `utils/rules/loader.py` | yes | present | Phase 4a loader MVP for declarative packs and Python verifiers. |
| `utils/ti/enrichment.py` | yes | present | Phase 8 additive TI enrichment surface; finding overlays now emit explicit metadata-only authority markers and preview fields without rewriting authoritative finding confidence. |
| `_REFACTOR/session-a.md` | yes | 715 | Agent loop source transcript. |
| `_REFACTOR/session-b.md` | yes | 343 | Dispatch state source transcript. |
| `_REFACTOR/session-c.md` | yes | 289 | Provenance and parser-tier source transcript. |
| `_REFACTOR/session-d.md` | yes | 344 | Route split source transcript. |
| `_REFACTOR/session-e.md` | yes | 296 | Verification and extraction source transcript. |
| `_REFACTOR/session-f.md` | yes | 402 | Detection-core source transcript. |
| `_REFACTOR/master-goals-and-workstreams.plan.md` | yes | 559 | Master plan under revision. |

## Existing Directories With Naming Or Scope Caveats

| Path | Exists | Notes |
| --- | --- | --- |
| `claude-code/` | yes | Present in repo root and available for direct reading. |
| `claw-code/` | yes | Present in repo root and available for direct reading. |

## Historical Paths

| Path | Exists | Notes |
| --- | --- | --- |
| `utils/gap_detectors/` | no | Renamed to `utils/stateful_detectors/` during Phase 4a deterministic-core normalization. |

## Deferred Moves

- `utils/stateful_detectors/behavioral_anomaly.py` stays in `utils/stateful_detectors/` for Phase 4a and is deferred for possible relocation to `utils/behavioral/` in Phase 7.

## Planned But Not Yet Present

| Path | Exists | Notes |
| --- | --- | --- |
| `pipeline/` | yes | Active shared pipeline surface; expanded from Phase 1 pattern-analysis wrappers into Phase 7 stage modules. |
| `routes/findings.py` | no | Planned canonical findings route surface. |
| `utils/ai/router.py` | yes | present | Phase 6 shared AI invocation router and runtime metrics surface. |
| `utils/chat/` | yes | present | Phase 6 shared chat runtime and dispatch package. |
| `utils/ti/rule_sync.py` | no | Planned scheduled TI rule-pack builder. |
| `utils/rules/stateful/` | no | Planned normalized stateful-detector interface. |

## Current Concrete Mismatch Findings
- `utils/ioc_audit.py` and `utils/ioc_model_eval.py` do exist, so Phase 5 should not treat them as hypothetical.
- `routes/api.py` has now been deleted, so Phase 9 route cleanup should focus on the extracted live blueprints and their shared helper modules rather than preserving the old compatibility wrapper.
- `utils/ioc_extractor.py` remains a mixed regex, AI normalization, merge, and import-pipeline surface at the start of Phase 5, so decomposition work should preserve the deterministic path while peeling AI layers outward.
- `utils/ioc_extractor.py` is now intentionally a compatibility-facing IOC entry point, so Phase 9 should retire the facade state explicitly rather than letting it linger as a convenience wrapper.
- `utils/progress.py` no longer carries the unused `set_completion_phase()` legacy shim, so the remaining Phase 9 progress cleanup should focus on live compatibility data shapes rather than dead helper removal.
- `routes/findings.py` and `utils/ti/rule_sync.py` remain planned targets, but `pipeline/`, `utils/ai/router.py`, and `utils/chat/` are now live surfaces and should be audited as current files rather than hypothetical paths.

## Use Rule
Any future plan revision that references a file path should update this audit or be updated by it. This file is the baseline check against ghost-file planning.
