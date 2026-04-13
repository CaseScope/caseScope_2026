# CaseScope Master Goals And Workstreams Plan

## Purpose
This plan consolidates the architectural goals and refactor direction captured across `session-a.md` through `session-f.md` into one implementation-oriented reference.

This file is a planning artifact. It captures intended direction and sequencing, but implementation decisions should still be validated against the live code before execution.

## Architectural Goals
- Establish one deterministic core pipeline as the system of record for detections, findings, timelines, and evidence references.
- Ensure the product remains fully useful without a license, with deterministic ingestion, normalization, rule execution, correlation, baselines, anomaly detection, IOC regex extraction, timeline construction, and reporting.
- Treat AI, RAG, OpenCTI, and MISP as enrichment and acceleration layers, never as the authoritative detection source.
- Collapse competing outputs into one unified finding contract with one confidence model, one MITRE mapping shape, one evidence-pointer shape, and one downstream read path.
- Keep high-volume analytical data in ClickHouse and transactional and business state in Postgres.
- Make the layered flow explicit in code and execution: ingest, normalize, detect, correlate, enrich, triage, narrate, report.
- Keep all higher layers additive. If enrichment or AI is disabled, the deterministic layer must still produce a complete, defensible case output.

## Refactor Goals
- Break oversized modules into bounded, responsibility-specific files.
- Replace feature-sprawl with layer-oriented organization so the directory tree shows how the system works.
- Split `routes/api.py` into route modules grouped by responsibility such as admin, cases, ingest, enrichment, search, AI, and later findings.
- Split IOC handling so deterministic extraction, normalization, merging, schema and contract handling, and optional AI auditing are separate concerns.
- Replace duplicated LLM-calling code with one reusable AI router path and thin feature-specific callers.
- Move shared helper logic out of route files into utility modules with stable interfaces.
- Reduce parallel systems that produce overlapping findings and instead make producers write into one model and one storage strategy.
- Separate runtime orchestration from domain logic so Celery tasks, routes, and chat tools call the same pipeline functions instead of reimplementing behavior.

## Licensing Goals
- Make licensing structural, consistent, and visible, not scattered through hand-rolled checks.
- Keep the unlicensed product honestly useful rather than artificially crippled.
- Gate only the premium layers:
  - OpenCTI and MISP enrichment and sync
  - AI IOC extraction from prose
  - AI chat assistant with tools
  - AI triage and clustering
  - AI narrative generation for reports and timelines
  - RAG-backed assistant features
- Keep deterministic baselines, anomaly detection, nearby-artifact search, and core case analysis available without licensing where they can run without AI or TI.
- Use one source of truth for feature availability so routes, pipelines, tools, and UI all agree on what is enabled.
- Make gated failures explicit and machine-readable so the assistant learns the boundary instead of retrying blindly.

## AI And Runtime Goals
- Build one reusable agent and chat runtime instead of bespoke LLM logic per feature.
- Freeze session-level capability state at conversation start so prompt structure remains stable and cacheable.
- Keep stable instructions and tool schemas in the cached prefix, and move dynamic case context into per-turn attachments or messages.
- Use bounded toolsets per task or subagent so each flow only sees the tools it should be allowed to use.
- Keep tools read-only by default.
- Require explicit analyst confirmation for any state-changing action.
- Enforce hard boundaries in dispatch:
  - evidentiary lock
  - case-scope isolation
  - license availability
  - artifact and prompt-injection resistance
- Ground AI outputs in structured findings, tagged artifacts, timelines, and retrieval context rather than raw uncontrolled event streams.
- Use the large model only where language reasoning is the right tool:
  - chat
  - IOC extraction from prose
  - timeline narration
  - report generation
- Prefer smaller task-specific models or deterministic and statistical methods for classification-style work where possible:
  - triage scoring
  - anomaly ranking
  - nearby-artifact relevance
- Preserve auditability by storing AI judgments as annotations, deltas, or overlays rather than overwriting original detector outputs.

## Detection Core Goals
- Clarify the detection model into distinct parts:
  - deterministic rules and pattern checks
  - stateful detectors
  - Hayabusa and Sigma-derived signals
  - IOC regex extraction
  - TI-generated rule packs
  - post-detection TI enrichment
- Keep OpenCTI and MISP out of the hot detection path except where they are compiled ahead of time into rule packs.
- Treat TI in two separate ways:
  - scheduled rule-sync or build step for deterministic matching
  - post-detection enrichment of existing findings
- Normalize how pattern checks, Sigma-like matches, Hayabusa outputs, and stateful detectors become unified findings.
- Preserve MITRE mapping, provenance, and evidence references across all producers.
- Separate presence detections from absence and coverage-based signals, with conservative confidence handling for absence-derived findings.
- Keep deterministic IOC extraction first, with optional AI review or augmentation only after schema validation and guardrails.
- Make nearby-artifact search primarily a deterministic query-and-extract capability, with AI as an optional intelligence layer.
- Formalize one rule-loading story so built-in rules, synced TI rules, Sigma-compatible rules, and stateful detectors can coexist cleanly.

## Practical Workstreams

### Workstream 1: Core Contracts
- Define the unified finding model.
- Define evidence and provenance shape.
- Define feature-availability source of truth.
- Define pipeline stage interfaces.

### Workstream 2: Data And Storage
- Converge on a ClickHouse finding path.
- Standardize dedup keys.
- Store enrichment overlays without mutating detector-of-record output.
- Clarify the Postgres and ClickHouse boundary.

### Workstream 3: Route Decomposition
- Split route surfaces by responsibility.
- Remove helper sprawl from route files.
- Preserve external route behavior while reducing internal coupling.

### Workstream 4: Detection Core Cleanup
- Clean up pattern checks.
- Normalize Hayabusa outputs into unified findings.
- Separate stateful detectors from pattern verifiers.
- Move TI rule sync to scheduled and deterministic pack generation.

### Workstream 5: AI Runtime
- Implement shared router behavior.
- Implement prompt and cache discipline.
- Implement attachment strategy.
- Implement tool dispatch and confirmation taxonomy.
- Implement subagent scoping.

### Workstream 6: Feature Layering
- Rebuild IOC extraction, nearby search, case analysis, reports, timelines, chat, and RAG as thin compositions over the shared pipeline and runtime.

## Execution Order
1. Lock the architectural invariants before changing code.
2. Build the master source-of-truth definitions.
3. Fix any live correctness or security inconsistencies discovered during verification.
4. Establish the target pipeline surface without moving everything at once.
5. Move findings toward the unified model and storage path.
6. Refactor the largest structural bottlenecks.
7. Separate detection from enrichment completely.
8. Standardize the chat and agent runtime.
9. Rework the case-analysis flow into explicit pipeline stages.
10. Add or refine the premium layers on top of the stable core.
11. Retire legacy paths only after parity and operational confidence are proven.

## Success State
- A case can be fully processed with no license and no AI.
- All findings flow through one contract and one read path.
- AI never becomes the evidentiary source of record.
- TI improves prioritization and coverage without contaminating determinism.
- Large files are replaced by smaller modules with clear ownership.
- The assistant and runtime are fast, cache-efficient, bounded, and safe.
- Licensing cleanly adds intelligence and speed, not baseline product viability.

## Phased Implementation Roadmap

Hard prerequisite:
- No new planning sessions should extend this roadmap until the transcript-derived contract artifacts are materialized into `docs/refactor/` and treated as the repo-backed source of truth.

### Phase 0: Verification And Guardrails
**Objective**
- Verify the current system boundaries and fix any live correctness or licensing inconsistencies before structural refactors begin.

**Primary repo areas**
- `routes/api.py`
- `utils/feature_availability.py`
- `models/system_settings.py`
- `utils/opencti.py`
- `utils/misp.py`
- `utils/pattern_overlay.py`
- `utils/licensing/`
- `docs/refactor/file_audit.md`

**Key outputs**
- Verified feature-gating behavior for AI, OpenCTI, MISP, RAG, and related routes.
- Verified current detection-versus-enrichment boundaries.
- A short list of live bugs or policy inconsistencies to fix immediately.
- `docs/refactor/file_audit.md` listing plan-referenced existing files, planned-but-missing files, and naming mismatches.
- Grep audit for silent defaults on case-scoped fields such as `arguments.get(...case...)` and similar inheritance patterns.
- Sanity check of plan-referenced live files such as `utils/ioc_audit.py` and `utils/ioc_model_eval.py`.

**Dependencies**
- None. This phase should happen first.

**Exit criteria**
- High-risk route or feature-gating ambiguity is resolved.
- Any hot-path TI influence on deterministic detection is identified and documented.
- Transcript-derived artifacts are committed into `docs/refactor/`.
- File references in the plan have been checked against the live repo.

### Phase 1: Core Contracts And Pipeline Surface
**Objective**
- Define the stable contracts the rest of the refactor will build on.

**Primary repo areas**
- `utils/unified_findings.py`
- `utils/deterministic_evidence_engine.py`
- `utils/ioc_contract.py`
- `utils/ioc_schema.py`
- `utils/feature_availability.py`
- `docs/refactor/finding_contract.md`
- `docs/refactor/dispatch_state_machine.md`
- `docs/refactor/agent_loop.md`
- `docs/refactor/pattern_check_inventory.md`
- New pipeline package such as `pipeline/`

**Phase 1 inputs already produced**
- `docs/refactor/finding_contract.md`
- `docs/refactor/dispatch_state_machine.md`
- `docs/refactor/agent_loop.md`
- `docs/refactor/pattern_check_inventory.md`
- `scripts/refactor/inventory_checks.py`

**Key outputs**
- Unified finding contract locked into code.
- Additive `detector_metadata` field or column for producer-specific metadata.
- Evidence and provenance shape locked into code.
- Provenance enum and ToolTier table locked as runtime contracts.
- Stable pipeline stage interfaces:
  - ingest
  - normalize
  - detect
  - correlate
  - enrich
  - triage
  - narrate
  - report
- Single feature-availability source of truth.
- Transcript-derived contract specs translated from docs into repo-backed code surfaces, not re-litigated.

**Dependencies**
- Phase 0 verification complete.

**Exit criteria**
- New contracts exist in code, even if legacy callers still wrap or adapt to them.
- New pipeline entry points exist, even if they initially delegate to legacy logic.
- `detector_metadata` is part of the locked finding contract before downstream migration work starts.

### Phase 1.5: TI Separation Quick Win
**Objective**
- Remove the known TI overlay violation from the detection loop without waiting for all deterministic-core normalization work.

**Primary repo areas**
- `utils/case_analyzer.py`
- `utils/pattern_overlay.py`
- planned target areas such as `utils/ti/enrichment.py`
- planned target areas such as `utils/ti/rule_sync.py`

**Key outputs**
- `PatternOverlayEnhancer` no longer mutates findings inside the detection loop.
- Overlay behavior is moved to post-detection enrichment.
- Scheduled or persistence-oriented overlay writes are removed from the hot detection path.

**Dependencies**
- Phase 1 complete so the finding contract, including `detector_metadata`, is already locked.

**Exit criteria**
- The old overlay call site is deleted in the same commit as the migration.
- Detection is overlay-free on both licensed and unlicensed paths.

### Phase 2: Findings Storage Convergence
**Objective**
- Move toward one finding path and one read path, centered on ClickHouse for analytical findings.

**Primary repo areas**
- `utils/clickhouse.py`
- `utils/unified_findings.py`
- finding-related models and queries
- migration files under `migrations/`
- case analysis read paths that currently merge multiple systems

**Key outputs**
- Unified finding table or storage contract in ClickHouse.
- Stable dedup key and provenance rules.
- Dual-write or bridge strategy from legacy producers into the unified model.
- One canonical read path for findings.

**Dependencies**
- Phase 1 contracts complete.

**Exit criteria**
- Existing producers can emit into the unified finding path.
- Downstream consumers can read the unified path without changing external behavior.

### Phase 3: Route Decomposition
**Objective**
- Reduce `routes/api.py` into bounded route modules without changing behavior.

**Primary repo areas**
- `routes/api.py`
- existing route modules under `routes/`
- new route modules such as:
  - `routes/admin.py`
  - `routes/cases.py`
  - `routes/ingest.py`
  - `routes/enrichment.py`
  - `routes/search.py`
  - `routes/ai.py`
  - `routes/findings.py`
- shared helper destinations in `utils/`

**Key outputs**
- Route split by responsibility.
- Shared decorators or helpers extracted from route files.
- Cleaner blueprint boundaries and less helper sprawl.

**Dependencies**
- Phase 0 complete for any licensing and policy checks.
- Phase 1 feature-availability rules available for consistent gating.

**Exit criteria**
- `routes/api.py` is reduced to a thin compatibility or registration layer.
- Behavior and public routes remain stable.
- Route block counts are re-verified at extraction time.
- Any divergence from the original inventory triggers a re-count of remaining blocks before proceeding.

### Phase 4a: Deterministic Core Normalization
**Objective**
- Normalize the deterministic detection core and separate distinct detector classes cleanly, using the check rather than the pattern as the atomic unit.

**Primary repo areas**
- `utils/pattern_check_definitions.py`
- `utils/pattern_event_mappings.py`
- `utils/hayabusa_correlator.py`
- `utils/deterministic_evidence_engine.py`
- `utils/gap_detectors/` (rename target: stateful-detector or behavioral-detector concept)
- `utils/sigma_converter.py`
- planned rule-loader areas such as `utils/rules/loader.py`
- planned stateful-rule areas such as `utils/rules/stateful/`

**Key outputs**
- Clear distinction between:
  - check-level verifiers
  - stateful detectors
  - Hayabusa or Sigma findings
  - TI-generated rule packs
  - TI enrichment overlays as a separate later concern
- Dual-path rule loader:
  - declarative YAML or Sigma-style loading
  - Python verifier registration for aggregation-heavy checks
- Unified finding emission across deterministic producers.
- `gap_detectors/` naming lie removed from the plan and from the target architecture.
- Phase 4a is sized against the generated `246`-row inventory in `docs/refactor/pattern_check_inventory.csv`, not the earlier transcript-level `~180` estimate.

**Dependencies**
- Phase 1 contracts complete.
- Phase 2 finding contract available.

**Exit criteria**
- Detection producers emit unified findings consistently.
- The check, not the pattern, is the normalized atomic unit for deterministic-core work.

### Phase 4b: TI Separation
**Objective**
- Finish separating TI behavior from deterministic detection, building on the quick win from Phase 1.5.

**Primary repo areas**
- `utils/opencti.py`
- `utils/misp.py`
- `utils/pattern_overlay.py`
- `utils/case_analyzer.py`
- planned TI enrichment and sync modules

**Key outputs**
- TI influence is either:
  - scheduled rule sync
  - post-detection enrichment
- No remaining detection-time TI mutation paths.

**Dependencies**
- Phase 1.5 complete.
- Phase 2 complete.

**Exit criteria**
- TI no longer mutates detector-of-record output inside the hot detection path.

### Phase 5: IOC Stack Decomposition
**Objective**
- Split IOC processing into deterministic, normalization, merge, contract, and optional AI review layers.

**Primary repo areas**
- `utils/ioc_extractor.py`
- `utils/ioc_merge.py`
- `utils/ioc_contract.py`
- `utils/ioc_schema.py`
- `utils/ioc_audit.py`
- `utils/ioc_model_eval.py`

**Key outputs**
- Deterministic IOC extraction isolated from optional AI augmentation.
- Shared normalization and defang or refang handling in one place.
- Stable merge path for regex plus AI-reviewed outputs.
- Cleaner evaluation harness and audit pipeline boundaries.

**Dependencies**
- Phase 1 contracts.
- Phase 4a deterministic-core cleanup where IOC-derived findings intersect with unified findings.

**Exit criteria**
- IOC extraction can run deterministically without AI.
- Optional AI path is additive and schema-validated.

### Phase 6: AI Runtime Unification
**Objective**
- Replace duplicated AI calling logic with one reusable router and one safe runtime model.

**Primary repo areas**
- `utils/ai_providers.py`
- `utils/ai_adapters.py`
- `utils/ai_correlation_analyzer.py`
- `utils/ai_event_summary.py`
- `utils/ai_report_generator.py`
- `utils/ai_review.py`
- `utils/ai_timeline_generator.py`
- `utils/chat_tools.py`
- new shared runtime areas such as:
  - `utils/ai/router.py`
  - `utils/chat/`

**Key outputs**
- Shared AI router.
- Frozen conversation context.
- Stable prompt assembly and cache discipline.
- Dynamic per-turn attachment strategy.
- Provenance enum.
- Four-tier ToolDispatcher model.
- L0/L1/L2/L3 dispatch state machine.
- Parser-tier provenance tagging policy.
- Tool dispatch, confirmation taxonomy, and subagent scoping.
- Chat-runtime boundary completed across the shared loop, dispatcher, policy module, feature gate, pending approval lifecycle, and session eviction surfaces in `utils/chat/`, `utils/chat_agent.py`, and `routes/chat.py`.

**Dependencies**
- Phase 1 feature-availability source of truth.
- Phase 3 route decomposition for cleaner AI call sites.

**Exit criteria**
- Feature-specific AI modules become thin callers over one runtime.
- Tool use is bounded, auditable, and safe by default.
- Phase 6 completes at the chat-runtime boundary. Parser-tier provenance propagation is intentionally split into Phase 6.5 rather than being folded into this runtime phase.

### Phase 7: Case Analysis Pipeline Decomposition
**Objective**
- Turn case analysis from a god-function into a sequence of explicit, testable pipeline stages.

**Primary repo areas**
- `utils/case_analyzer.py`
- behavioral profiling and discovery utilities
- timeline and report generation callers
- nearby-artifact search and IOC expansion flows
- pipeline modules created in Phase 1

**Key outputs**
- Explicit callable stages such as:
  - detect
  - extract_iocs
  - enrich_ti
  - build_baselines
  - detect_anomalies
  - nearby_search
  - triage
  - build_timeline
  - generate_report
- One orchestration path for full case analysis.

**Dependencies**
- Phases 1, 2, 4a, 4b, 5, and 6.

**Exit criteria**
- Full case analysis is orchestration, not embedded multi-domain logic.
- Each stage can be invoked independently by routes, tasks, or chat tools.

### Phase 6.5: Parser-Tier Provenance Propagation
**Objective**
- Turn the provenance model from a dispatch-side contract into an end-to-end security property by making parser and producer surfaces emit real provenance tags that downstream runtime validation can enforce.

**Primary repo areas**
- `parsers/`
- `utils/stateful_detectors/`
- producer and artifact-normalization surfaces that read parser output and pass values into downstream runtime or case-analysis flows
- shared provenance helpers created for parser-to-runtime handoff

**Key outputs**
- Per-field provenance tagging implementations for every parser tier captured in `docs/refactor/dispatch_state_machine.md`.
- Shared producer-side tagging surface instead of ad hoc provenance defaults.
- Dispatch L1 provenance validation operating on real emitted tags rather than fallback defaults.
- Grep-auditable producer path showing artifact-derived values flow through the shared tagging surface before dispatch consumption.

**Dependencies**
- Phase 7 should land first so parser provenance is attached to stabilized stage interfaces rather than the pre-decomposition case-analysis flow.

**Exit criteria**
- Every parser tier from `docs/refactor/dispatch_state_machine.md` has a tagging implementation.
- Dispatch L1 validates against emitted provenance tags where artifact-derived values enter the runtime.
- Audit confirms no producer bypasses the shared provenance-tagging surface.

### Phase 8: Premium Layer Tightening
**Objective**
- Reintroduce or harden licensed intelligence layers on top of the stabilized core.

**Primary repo areas**
- TI enrichment code
- AI triage and clustering
- report and timeline narration
- chat assistant tools
- RAG-related modules and routes

**Key outputs**
- Premium capabilities run cleanly as additive overlays.
- RAG is limited to explainability, Q&A, and grounded assistance rather than detection-of-record.
- Classification-style AI tasks are narrowed or moved to smaller models where appropriate.

**Dependencies**
- Phases 4 through 7, plus Phase 6.5.

**Exit criteria**
- Premium features add speed, explainability, and analyst leverage without altering deterministic authority.

### Phase 9: Legacy Retirement And Hardening
**Objective**
- Remove obsolete paths only after parity, telemetry, and operational confidence are proven.

**Primary repo areas**
- Legacy route or AI call paths
- compatibility helpers
- old finding merge paths
- deprecated detector overlays and adapters
- `utils/ioc_extractor.py` facade retirement decision

**Key outputs**
- Old code paths removed or archived.
- Feature flags simplified.
- Documentation and operator expectations updated.
- `utils/ioc_extractor.py` is either promoted to the real IOC orchestration module or its external callers are migrated to extracted IOC modules so the facade can be deleted.

**Dependencies**
- All previous phases functionally complete.

**Exit criteria**
- Legacy paths are no longer required for rollback confidence.
- Operational monitoring shows the new paths are stable.

## Recommended Dependency Order
- Phase 0 before all others.
- Phase 1 before Phases 1.5, 2, 4a, 5, and 6.
- Phase 1.5 before Phase 4b.
- Phase 2 before Phase 7.
- Phase 3 can begin after Phase 1, but should not outrun verified licensing and route-policy cleanup from Phase 0.
- Phase 4a should complete before Phase 8 premium detection-related tightening.
- Phase 4b should complete before TI behavior is considered fully separated.
- Phase 5 should complete before AI-assisted IOC workflows are finalized in Phase 8.
- Phase 6 should complete before Phase 7 is considered done.
- Phase 6.5 should complete after Phase 7 and before Phase 8 opens.
- Phase 9 happens last.

## Suggested Early Execution Sequence
1. Phase 0
2. Phase 1
3. Phase 1.5
4. Phase 2
5. Phase 3
6. Phase 4a
7. Phase 4b
8. Phase 5
9. Phase 6
10. Phase 7
11. Phase 6.5
12. Phase 8
13. Phase 9

## Notes On Parallelism
- Phase 3 route decomposition can overlap with Phase 2 storage convergence as long as route behavior does not change.
- Phase 5 IOC decomposition can overlap with Phase 6 AI runtime unification if the IOC path consumes the shared router only through a stable interface.
- Phase 8 should avoid starting until the underlying deterministic and runtime surfaces are stable enough not to cause churn.
