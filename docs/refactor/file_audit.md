# File Audit

## Status
Phase 0 deliverable. This file exists to stop the plan from drifting onto ghost files or stale assumptions.

## Audit Time Snapshot
Line counts and existence checks were captured during this revision pass.

## Plan-Referenced Existing Files

| Path | Exists | Line count | Notes |
| --- | --- | ---: | --- |
| `routes/api.py` | no | removed | Phase 9 retired the final route-level compatibility shim after migrating the remaining repo tests to `routes.route_helpers` and `routes.hunting_query_helpers`. |
| `utils/unified_findings.py` | yes | 460 | Unified finding read path area; reads only from the mirrored ClickHouse store, but the response summary still carries compatibility/telemetry fields such as `read_path` and `legacy_fallback_used`. |
| `utils/ioc_extractor.py` | yes | present | Phase 9 canonical IOC orchestration boundary; the module now declares an explicit public export contract for the live route/task/enrichment entry points, and OpenCTI derived-indicator enrichment uses its public helper surface instead of reaching into regex internals. |
| `utils/pattern_check_definitions.py` | yes | 3073 | Duplicate `security_tool_tampering` entry removed; deterministic pattern registry now has a single authoritative definition for that pattern and currently materializes 42 patterns / 247 checks. |
| `utils/pattern_event_mappings.py` | yes | 1728 | Live companion file for pattern semantics and mappings; carries `anchor_class`, `required_pass_count`, and `allow_anchor_only_emit` materialization for Scoring 2.0-aware patterns. |
| `utils/hayabusa_correlator.py` | yes | 772 | Already emits unified findings through `build_hayabusa_correlation_finding`; remaining work is contract verification and downstream parity cleanup, not first-time migration. |
| `utils/pattern_overlay.py` | yes | 518 | Stored-overlay helper surface; packages/finding payloads keep TI as metadata-only context with bounded preview adjustments rather than mutating authoritative detector confidence. |
| `utils/provenance.py` | yes | present | Phase 6.5 shared parser-to-runtime provenance helper surface for per-field artifact tagging, rollup calculation, and producer payload handoff into the shared chat runtime. |
| `utils/forensic_chat_sources.py` | yes | present | Shared forensic chat producer surface; `search_artifacts`, browser-download retrieval, memory search, unified process retrieval, unified process-tree retrieval, and network-log retrieval now emit shared payload provenance metadata derived from normalized artifact records instead of relying on dispatch-side defaults. |
| `utils/chat_tools.py` | yes | present | Direct chat-tool producer surface; `query_events`, `count_events`, `get_findings`, `lookup_ioc`, and `lookup_threat_intel` now emit shared payload provenance metadata or forward shared producer metadata instead of falling back to dispatcher defaults, and Phase 8 now routes optional IOC TI enrichment through the shared premium-availability gate instead of an ad hoc tool-local check. |
| `utils/chat_agent.py` | yes | present | Shared chat runtime surface; Phase 8 now grounds the assistant with an explicit premium-context guardrail so TI and RAG context remain supporting evidence rather than detector-of-record authority. |
| `utils/case_analyzer.py` | yes | 1108 | Current orchestration bottleneck; gap detection now routes through `pipeline.detect_anomalies`, pattern analysis through shared `pipeline.pattern_analysis` helpers, TI enrichment through `pipeline.case_enrichment`, and suggested-action generation through `pipeline.case_actions` rather than retaining duplicate local rule helpers. |
| `utils/ai_checkpoints.py` | yes | present | Phase 8 narrative checkpoint surface; triage and synthesis prompts now explicitly keep TI and RAG context as supporting context only and preserve deterministic findings as the authority of record. |
| `tasks/rag_tasks.py` | yes | 3028 | AI correlation task now reuses shared pattern-analysis helpers for setup, per-pattern progress payload construction, per-pattern iteration orchestration, cleanup handling, final tail orchestration, final overlap annotation, and response packaging, while still retaining task-specific provider initialization and outer error/stat aggregation; semantic pattern-discovery metadata is now explicitly marked as prioritization-only rather than authoritative detection. |
| `routes/rag.py` | yes | present | RAG route surface; Ask-AI prompt/response handling now labels TI and semantic context as grounded assistance only, not detector-of-record proof, and returns explicit authority metadata for the analyst-facing answer path. |
| `pipeline/__init__.py` | yes | 86 | Shared pipeline package export surface now populated beyond the original pattern-analysis wrappers. |
| `pipeline/case_timeline.py` | yes | 67 | Shared case-analysis stage surface for IOC timeline and incident storyline orchestration. |
| `pipeline/case_narrative.py` | yes | 75 | Shared case-analysis narrative stage surface for triage and synthesis checkpoints. |
| `pipeline/case_enrichment.py` | yes | 81 | Shared case-analysis TI enrichment stage surface for additive OpenCTI context attachment. |
| `pipeline/case_actions.py` | yes | 181 | Shared case-analysis suggested-action stage surface for hunt and response recommendations. |
| `pipeline/pattern_analysis.py` | yes | 1117 | Pattern-analysis stage surface now includes shared extractor/evidence setup wrappers, case-side orchestration head handling, case-side runtime setup orchestration, case-side pre-branch pattern preparation, case-side AI execution orchestration, case-side per-pattern iteration orchestration, case-side per-pattern loop orchestration, case-side completion tail orchestration, task-side progress payload construction, task-side completion payload construction, task-side iteration orchestration, task-side cleanup handling, task-side completion tail orchestration, task-side completion log emission, task-side AI execution orchestration, final overlap annotation, task response packaging, concise per-pattern threat-intel prompt assembly, census, eligibility filtering, stable ordering, evidence-package selection, suppression, materialization, package processing, evaluation, persistence, and rule-based result-persistence helpers; Phase 8 now makes the authoritative package score boundary explicit so overlay metadata cannot silently steer package selection or deterministic-score persistence. |
| `pipeline/baselines.py` | yes | 62 | Phase 7 baseline-building stage surface for behavioral profiling and peer clustering. |
| `pipeline/detect.py` | yes | 34 | Phase 7 detection-stage surface for Hayabusa correlation and attack-chain building. |
| `pipeline/detect_anomalies.py` | yes | 21 | Phase 7 anomaly-detection stage surface for shared gap-detection orchestration. |
| `utils/feature_availability.py` | yes | 601 | Current feature source-of-truth candidate; shared premium TI gating covers chat-tool licensing, IOC enrichment, OpenCTI context-provider availability, and immutable runtime feature snapshots. |
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

## Planned Surface Status

| Path | Exists | Notes |
| --- | --- | --- |
| `pipeline/` | yes | Active shared pipeline surface; expanded from Phase 1 pattern-analysis wrappers into Phase 7 stage modules. |
| `routes/findings.py` | yes | 33 | Canonical unified-findings route surface now exists as a dedicated findings blueprint. |
| `utils/ai/router.py` | yes | present | Phase 6 shared AI invocation router and runtime metrics surface. |
| `utils/chat/` | yes | present | Phase 6 shared chat runtime and dispatch package. |
| `utils/ti/rule_sync.py` | no | Explicitly deferred: the live TI architecture now separates deterministic detection from additive enrichment without a scheduled rule-pack builder on the hot path. |
| `utils/rules/stateful/` | no | Explicitly deferred: `utils/stateful_detectors/` remains the live stateful-detector boundary until a concrete normalization need appears. |

## Current Concrete Mismatch Findings
- `utils/ioc_audit.py` and `utils/ioc_model_eval.py` do exist, so Phase 5 should not treat them as hypothetical.
- `routes/api.py` has now been deleted, so Phase 9 route cleanup should focus on the extracted live blueprints and their shared helper modules rather than preserving the old compatibility wrapper.
- `utils/unified_findings.py` now reads only from the mirrored ClickHouse findings store, so any remaining parity gaps must be fixed in the producer sync path rather than by reviving legacy readers. The API summary still emits `read_path` / `legacy_fallback_used` metadata for compatibility and observability.
- `utils/ioc_extractor.py` remains the canonical IOC orchestration facade. The public helper surface now includes `run_deterministic_ioc_extraction()` so background tasks can stop instantiating `RegexIOCExtractor` directly while internal decomposition continues behind the facade.
- `utils/opencti.py` no longer reaches into `RegexIOCExtractor` or `_defang_text` directly, so future IOC caller cleanup should continue moving dependencies onto explicit public helpers exported by `utils/ioc_extractor.py`.
- `utils/progress.py` no longer carries the unused `set_completion_phase()` legacy shim, so the remaining Phase 9 progress cleanup should focus on live compatibility data shapes rather than dead helper removal.
- `utils/case_analyzer.py` now delegates IOC timeline, incident storyline, AI narrative, TI enrichment, and suggested-action work through dedicated `pipeline/case_*` stage modules instead of keeping those responsibilities solely embedded in the analyzer class.
- `utils/ti/rule_sync.py` remains explicitly deferred, while `routes/findings.py`, `pipeline/`, `utils/ai/router.py`, and `utils/chat/` are now live surfaces and should be audited as current files rather than hypothetical paths.
- `tasks/rag_tasks.py` and `pipeline/pattern_analysis.py` still inject OpenCTI ATT&CK context into AI pattern-analysis prompts before that producer persists results. This is no longer a deterministic hot-path mutation, but it means TI influence is not yet purely limited to scheduled sync plus post-detection enrichment.

## Use Rule
Any future plan revision that references a file path should update this audit or be updated by it. This file is the baseline check against ghost-file planning.
