# File Audit

## Status
Phase 0 deliverable. This file exists to stop the plan from drifting onto ghost files or stale assumptions.

## Audit Time Snapshot
Line counts and existence checks were captured during this revision pass.

## Plan-Referenced Existing Files

| Path | Exists | Line count | Notes |
| --- | --- | ---: | --- |
| `routes/api.py` | yes | 10739 | Large route surface still present. |
| `utils/unified_findings.py` | yes | 327 | Current unified finding read path area. |
| `utils/pattern_check_definitions.py` | yes | 2937 | Live duplicate-key issue at `security_tool_tampering`. |
| `utils/pattern_event_mappings.py` | yes | 1618 | Live companion file for pattern semantics and mappings. |
| `utils/hayabusa_correlator.py` | yes | 745 | Needs unified finding emission in later phases. |
| `utils/pattern_overlay.py` | yes | 384 | Narrow TI leak source identified by Session F. |
| `utils/case_analyzer.py` | yes | 1738 | Current orchestration bottleneck and overlay call site. |
| `utils/feature_availability.py` | yes | 541 | Current feature source-of-truth candidate. |
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
| `utils/ti/enrichment.py` | yes | present | Phase 4b post-detection TI enrichment surface. |
| `_REFACTOR/session-a.md` | yes | 715 | Agent loop source transcript. |
| `_REFACTOR/session-b.md` | yes | 343 | Dispatch state source transcript. |
| `_REFACTOR/session-c.md` | yes | 289 | Provenance and parser-tier source transcript. |
| `_REFACTOR/session-d.md` | yes | 344 | Route split source transcript. |
| `_REFACTOR/session-e.md` | yes | 296 | Verification and extraction source transcript. |
| `_REFACTOR/session-f.md` | yes | 402 | Detection-core source transcript. |
| `_REFACTOR/master-goals-and-workstreams.plan.md` | yes | 446 at open time | Master plan under revision. |

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
| `pipeline/` | no | Planned shared pipeline surface. |
| `routes/findings.py` | no | Planned canonical findings route surface. |
| `utils/ai/router.py` | no | Planned shared AI router. |
| `utils/chat/` | no | Planned shared chat runtime package. |
| `utils/ti/rule_sync.py` | no | Planned scheduled TI rule-pack builder. |
| `utils/rules/stateful/` | no | Planned normalized stateful-detector interface. |

## Current Concrete Mismatch Findings
- `utils/ioc_audit.py` and `utils/ioc_model_eval.py` do exist, so Phase 5 should not treat them as hypothetical.
- `utils/ioc_extractor.py` remains a mixed regex, AI normalization, merge, and import-pipeline surface at the start of Phase 5, so decomposition work should preserve the deterministic path while peeling AI layers outward.
- `routes/findings.py`, `pipeline/`, `utils/ai/router.py`, `utils/chat/`, and `utils/ti/rule_sync.py` are planned targets, not current files.

## Use Rule
Any future plan revision that references a file path should update this audit or be updated by it. This file is the baseline check against ghost-file planning.
