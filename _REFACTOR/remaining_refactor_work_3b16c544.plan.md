---
name: Remaining Refactor Work
overview: "Audit the shipped refactor phases against the live repo and focus the next execution plan on the still-open exit criteria: AI router consolidation, parser provenance rollout, deeper case-analysis stage extraction, IOC legacy-boundary cleanup, and final retirement/hardening work."
todos:
  - id: audit-debt
    content: Reconcile file-audit drift and deterministic-core hygiene issues, including the duplicate key in pattern check definitions.
    status: completed
  - id: ai-router
    content: Finish AI runtime unification so feature modules stop calling providers directly and route through the shared router/runtime path.
    status: completed
  - id: parser-provenance
    content: Push provenance tagging into parser and producer surfaces so dispatch validates emitted tags instead of defaults.
    status: completed
  - id: ioc-boundary
    content: Finish IOC decomposition and decide whether ioc_extractor remains the canonical facade or is retired after caller migration.
    status: completed
  - id: case-pipeline
    content: Extract the remaining CaseAnalyzer responsibilities into pipeline stages and leave CaseAnalyzer as orchestration only.
    status: completed
  - id: findings-retirement
    content: Retire unified-findings fallback and other legacy compatibility paths once parity and observability are confirmed.
    status: completed
  - id: phase9-closeout
    content: Complete explicit Phase 9 hardening, including the findings-route decision and refreshed completion audits.
    status: completed
isProject: false
---

# Remaining Refactor Plan

## Audit Summary
The live repo shows substantial completion across the earlier roadmap, but several phases are only partially complete when measured against their stated exit criteria.

Mostly complete:
- Phase 0 guardrails and audit artifacts are present in [docs/refactor/file_audit.md](docs/refactor/file_audit.md) and [docs/refactor/silent_default_audit.md](docs/refactor/silent_default_audit.md).
- Phase 1 contracts and Phase 2 storage convergence are live, but not yet at the strictest interpretation of their end state.
- Phase 3 route decomposition is materially done; `routes/api.py` is gone.
- Phase 1.5 and most of Phase 8 are in place as additive post-detection enrichment and premium-layer constraints.

Still open or only partially complete:
- Unified findings still expose a rollback branch in [utils/unified_findings.py](utils/unified_findings.py) via `legacy_fallback_used` / `read_path` summary metadata.
- Deterministic-core cleanup still has open hygiene debt called out in [docs/refactor/file_audit.md](docs/refactor/file_audit.md), especially the duplicate key in [utils/pattern_check_definitions.py](utils/pattern_check_definitions.py), plus planned-but-missing surfaces like [utils/rules/stateful/](utils/rules/stateful/) and [utils/ti/rule_sync.py](utils/ti/rule_sync.py).
- IOC decomposition is incomplete because [utils/ioc_extractor.py](utils/ioc_extractor.py) remains a broad public facade used by routes, tasks, and enrichment code.
- AI runtime unification is incomplete because several modules still call `get_llm_provider(...)` directly instead of going through [utils/ai/router.py](utils/ai/router.py), including [utils/chat_agent.py](utils/chat_agent.py), [utils/ai_report_generator.py](utils/ai_report_generator.py), [utils/ai_timeline_generator.py](utils/ai_timeline_generator.py), [utils/ai_checkpoints.py](utils/ai_checkpoints.py), [utils/ioc_extractor.py](utils/ioc_extractor.py), and [utils/rag_llm.py](utils/rag_llm.py).
- Parser-tier provenance propagation is not complete because [parsers/](parsers/) does not yet emit provenance tags, while [docs/refactor/dispatch_state_machine.md](docs/refactor/dispatch_state_machine.md) still documents dispatch-side fallback behavior.
- Case-analysis decomposition is incomplete because [utils/case_analyzer.py](utils/case_analyzer.py) still owns IOC timeline, TI enrichment, AI triage, synthesis, and storyline/report orchestration rather than delegating those concerns to first-class pipeline stages.
- Legacy retirement and hardening are not complete: there is no Phase 9-style evidence of full legacy-path removal, [utils/ioc_extractor.py](utils/ioc_extractor.py) is still a compatibility-heavy boundary, and [routes/findings.py](routes/findings.py) has not been created.

## Concrete Remaining Work

### 1. Lock the remaining Phase 0 and 4a audit debt
- Reconcile stale statements in [docs/refactor/file_audit.md](docs/refactor/file_audit.md) against live code so the audit remains trustworthy.
- Remove the duplicate-key defect in [utils/pattern_check_definitions.py](utils/pattern_check_definitions.py).
- Decide whether [utils/hayabusa_correlator.py](utils/hayabusa_correlator.py) is already on the unified contract or still needs migration, then align docs and tests accordingly.

### 2. Finish the findings authority transition before deleting the fallback
- Measure who still depends on the legacy readers behind [utils/unified_findings.py](utils/unified_findings.py).
- Build a removal checklist for the `legacy_fallback_used` path and the read-path summary metadata.
- Only then delete the rollback branch and make the ClickHouse-backed path the only authoritative read path.

### 3. Complete deterministic/TI structural leftovers
- Either materialize [utils/rules/stateful/](utils/rules/stateful/) and [utils/ti/rule_sync.py](utils/ti/rule_sync.py), or explicitly close them out of the roadmap if they are no longer required.
- Add a grep-auditable verification pass proving there are no remaining detection-time TI mutation paths outside post-detection enrichment.

### 4. Finish IOC stack decomposition and set the long-term boundary
- Break [utils/ioc_extractor.py](utils/ioc_extractor.py) into a thin orchestration facade over the already-extracted modules: [utils/ioc_text.py](utils/ioc_text.py), [utils/ioc_normalizer.py](utils/ioc_normalizer.py), [utils/ioc_merge.py](utils/ioc_merge.py), [utils/ioc_contract.py](utils/ioc_contract.py), and [utils/ioc_contract_adapter.py](utils/ioc_contract_adapter.py).
- Migrate callers in [routes/iocs.py](routes/iocs.py), [tasks/celery_tasks.py](tasks/celery_tasks.py), and [utils/opencti.py](utils/opencti.py) onto explicit public helpers.
- Decide Phase 9’s unresolved question: keep [utils/ioc_extractor.py](utils/ioc_extractor.py) as the canonical orchestration boundary or delete it after caller migration.

### 5. Finish AI runtime unification
- Route all non-streaming and streaming chat/model entry points through [utils/ai/router.py](utils/ai/router.py) or a shared adapter layer directly above it.
- Remove direct provider acquisition from feature modules unless they are the router implementation itself.
- Prioritize [utils/chat_agent.py](utils/chat_agent.py), [utils/ai_checkpoints.py](utils/ai_checkpoints.py), [utils/ai_report_generator.py](utils/ai_report_generator.py), [utils/ai_timeline_generator.py](utils/ai_timeline_generator.py), [utils/ioc_extractor.py](utils/ioc_extractor.py), and [utils/rag_llm.py](utils/rag_llm.py).
- Preserve the existing approval, cache, and provenance semantics already present in [utils/chat/](utils/chat/).

### 6. Complete Phase 6.5 parser provenance end to end
- Extend provenance emission into [parsers/catalog.py](parsers/catalog.py), [parsers/registry.py](parsers/registry.py), [parsers/dissect_parsers.py](parsers/dissect_parsers.py), and the remaining parser families under [parsers/](parsers/).
- Ensure parser outputs carry field-level tags through producer surfaces into [utils/provenance.py](utils/provenance.py), [utils/forensic_chat_sources.py](utils/forensic_chat_sources.py), [utils/chat_tools.py](utils/chat_tools.py), and [utils/chat/dispatch.py](utils/chat/dispatch.py).
- Replace dispatch-side fallback assumptions with validation against emitted provenance wherever artifact-derived data enters the runtime.

### 7. Finish case-analysis pipeline decomposition
- Extract first-class stage modules for the still-embedded responsibilities in [utils/case_analyzer.py](utils/case_analyzer.py): IOC extraction/timeline, TI enrichment, nearby search if applicable, triage, narration/synthesis, storyline/report assembly, and final orchestration.
- Leave [utils/case_analyzer.py](utils/case_analyzer.py) as a thin coordinator over [pipeline/](pipeline/) rather than the owner of multi-domain business logic.
- Add targeted tests mirroring the existing Phase 7 stage contract pattern for each new stage.

### 8. Execute Phase 9 retirement and hardening explicitly
- Remove or shrink remaining compatibility paths after parity is proven, especially the unified-findings fallback and any residual direct provider or IOC facade bypasses.
- Create the missing canonical findings route surface if it is still part of the intended architecture: [routes/findings.py](routes/findings.py).
- Re-run route, IOC, AI-runtime, and findings-path audits so Phase 9 has explicit completion evidence instead of implied completion.

## Recommended Order
1. Audit/doc cleanup and deterministic-core hygiene.
2. AI router unification and parser provenance rollout, since both affect runtime safety boundaries.
3. IOC boundary cleanup and case-analysis stage extraction.
4. Unified findings fallback retirement.
5. Final legacy retirement, findings route decision, and hardening verification.

## Validation Focus
- Expand the existing `tests/test_phase6_*`, `tests/test_phase7_*`, and Phase 5 contract suites instead of creating broad low-signal tests.
- Add missing coverage specifically for parser-emitted provenance, router-only AI entry points, and fallback-free unified-findings reads.
- Treat [docs/refactor/file_audit.md](docs/refactor/file_audit.md) as a living source of truth and keep it aligned with code changes during each slice.