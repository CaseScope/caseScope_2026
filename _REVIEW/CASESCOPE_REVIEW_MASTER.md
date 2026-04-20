# CaseScope Code Review — Master Plan

> **Purpose.** Drive a multi-chat, phased independent review of the CaseScope codebase. Each phase is scoped tightly enough to complete in a single chat, produces a self-contained findings artifact, and leaves this master document updated for the next phase to pick up from.

> **Source of truth.** Code in the repo. This plan and its phase findings are the review's output. When the plan and the code disagree, the code wins and this plan gets updated.

---

## 1. Project Context

CaseScope is a DFIR platform (~130K lines of Python, Flask + ClickHouse + Postgres + Celery) for ingesting forensic artifacts (CyLR output, EVTX, memory images, PCAP, browser history, registry, etc.), running deterministic detection patterns over them, and producing case-level forensic output (timelines, reports, findings, IOC extraction). AI, OpenCTI/MISP, and RAG are premium overlays on top of a deterministic core that must remain fully functional without them.

The system has undergone a structured multi-phase refactor (Phases 0 through 9, plus Phase 6.5 and a dedicated Scoring 2.0 rollout). Most of that work is either shipped or explicitly deferred. This review is not a refactor — it is an independent correctness and completeness check against the post-refactor state, plus prioritized follow-up for unshipped design work.

**What "correct" means here is forensic-grade output.** A wrong SQL filter is worse than a slow one. A score that silently inflates is worse than a score that is missing. A finding that loses provenance is worse than a finding that was never generated. Every phase weights findings accordingly.

---

## 2. Review Principles

**In scope:**
- Concrete defects in live code (bugs, incorrect math, unsafe queries, broken invariants).
- Forensic correctness of detection, scoring, and evidence-production paths.
- Drift between the refactor's declared state (`docs/refactor/file_audit.md`, the `_REFACTOR/*.plan.md` files) and the live code.
- Dead code, stale compatibility shims, duplicated logic that should converge.
- Unshipped design work that affects correctness (e.g., Scoring 2.0).
- Cross-cutting concerns: timezone handling, SQL construction, error paths, logging discipline.

**Out of scope:**
- Architectural second-guessing of decisions the refactor already made.
- "Best practices" findings without a concrete incorrect behavior behind them.
- Style and formatting.
- Test-suite reorganization (unless a test is asserting wrong behavior).
- Performance tuning that isn't a user-visible scaling concern at the documented 30M+ event level.

**Claude will not make code changes as part of this review.** Findings identify problems and propose patches; the human decides what lands. If a finding's fix is a one-line diff, the phase will include that diff as a suggestion, not a committed change.

---

## 3. Finding Taxonomy

Each finding carries all five fields. No exceptions.

| Field | Values |
|---|---|
| **Category** | `BUG` / `CORRECTNESS` / `DEAD` / `DUPLICATION` / `RISK` / `PERF` / `CLARITY` / `GAP` / `TEST` / `DOC` / `DRIFT` |
| **Severity** | `CRITICAL` (data loss, security, forensic output wrong) / `HIGH` (degraded output, defensibility concerns) / `MEDIUM` (confusing but correct, or fragile) / `LOW` (cleanup, clarity) |
| **Location** | `file.py:line` or `module/` for cross-file |
| **Summary** | One-line problem statement |
| **Proposed fix** | Concrete change and rough effort (S/M/L) |

`DRIFT` is reserved for "the refactor plan says X, the code says Y." It's separate from `DEAD` because the resolution is usually "update the doc," not "delete code."

---

## 4. Architecture Map (as-observed)

Captured during Phase 0 exploration. Sizes are current line counts.

**Entry points:** `run.py`, `wsgi.py`, `app.py`, `config.py`.

**Data layer:**
- Postgres for transactional/business state, accessed through `models/*.py` (SQLAlchemy). Notable sizes: `models/pattern_rules.py` 3672, `models/rag.py` 1715, `models/ioc.py` 1117, `models/behavioral_profiles.py` ~28K chars.
- ClickHouse for high-volume analytical data, accessed through `utils/clickhouse.py` and direct query construction in engines/tasks.
- Migrations in `migrations/`.

**Detection core:**
- `utils/deterministic_evidence_engine.py` (1610) — anchor-walk evaluator, scoring, coverage, burst, sequence.
- `utils/pattern_check_definitions.py` (3046) — declarative check registry (42 patterns, ~246 checks per inventory).
- `utils/pattern_event_mappings.py` (1650) — per-pattern anchor/supporting/context event mappings.
- `utils/candidate_extractor.py` (~1050) — first-pass anchor extraction.
- `utils/stateful_detectors/` — behavioral_anomaly, brute_force, password_spraying (the renamed "gap detectors").
- `utils/rules/loader.py` — dual-path rule loader.
- `utils/hayabusa_correlator.py` (745) — Hayabusa → unified finding bridge.
- `utils/sigma_converter.py` — Sigma ingestion.
- `utils/attack_pattern_loader.py`, `utils/attack_chain_builder.py`.
- `utils/pattern_overlay.py` (384) — post-detection TI overlay (moved out of the hot path per Phase 1.5).
- `utils/pattern_suppression.py`, `utils/gap_detector_bridge.py`.

**Pipeline orchestration:**
- `pipeline/pattern_analysis.py` (1121) — per-pattern stage orchestration.
- `pipeline/detect.py`, `detect_anomalies.py`, `baselines.py`, `case_actions.py`, `case_enrichment.py`, `case_narrative.py`, `case_timeline.py`.
- `utils/case_analyzer.py` (1203) — case-level orchestrator, now thinner.

**IOC pipeline:**
- `utils/ioc_extractor.py` (2826) — canonical orchestration facade (per Phase 9 decision).
- `utils/ioc_text.py`, `ioc_normalizer.py`, `ioc_merge.py`, `ioc_contract.py`, `ioc_contract_adapter.py`, `ioc_schema.py`, `ioc_audit.py`, `ioc_model_eval.py`, `ioc_artifact_tagger.py`, `ioc_timeline_builder.py`, `ioc_training_dataset.py`, `ioc_vendor_corpus.py`, `semantic_ioc_extractor.py`, `deterministic_ioc_extractor.py`.

**AI runtime:**
- `utils/ai/router.py` — shared router (Phase 6).
- `utils/chat/dispatch.py`, `policy.py`, `runtime.py` — shared chat runtime with L0/L1/L2/L3 dispatch state machine.
- `utils/ai_providers.py` (1808), `ai_adapters.py`, `ai_correlation_analyzer.py` (1616), `ai_event_summary.py`, `ai_report_generator.py` (1320), `ai_review.py`, `ai_timeline_generator.py`, `ai_checkpoints.py`.
- `utils/chat_agent.py`, `chat_tools.py` (1259), `forensic_chat_sources.py`.

**Parsers:**
- `parsers/` with `base.py`, `catalog.py`, `registry.py`, `evtx_parser.py`, `dissect_parsers.py` (1966), `log_parsers.py` (1797), `browser_parsers.py` (2054), `memory_parser.py`, `windows_parsers.py`, `vendor_parsers.py`.

**Enrichment / external:**
- `utils/opencti.py` (2239), `opencti_context.py`, `misp.py`, `mitre_attack_sync.py`, `threat_intel_context.py`, `peer_clustering.py`, `behavioral_profiler.py`.
- `utils/ti/enrichment.py` — additive post-detection TI overlay.

**Routes:**
- `routes/` split by responsibility: `admin.py`, `ai.py`, `analysis.py`, `archive.py`, `auth.py`, `case_files.py`, `chat.py`, `dashboard.py`, `enrichment.py`, `evidence.py`, `findings.py`, `hunting.py`, `ingest.py`, `iocs.py`, `known_systems.py`, `known_users.py`, `main.py`, `memory.py`, `network_hunting.py`, `noise.py`, `ops.py`, `parsing.py`, `pcap.py`, `rag.py`, `reports.py`, `activation.py`.
- `routes/api.py` is gone (retired in Phase 9 per `file_audit.md`).

**Tasks:** `tasks/celery_tasks.py` (2237), `tasks/rag_tasks.py` (3027), `tasks/pcap_tasks.py` (1216).

**Licensing:** `utils/licensing/` with `fingerprint.py`, `license_manager.py`, `nist_time.py`, `server_client.py`, `validator.py`.

**Scoring 2.0 surface (planned):** `utils/deterministic_evidence_engine.py`, `utils/pattern_check_definitions.py`, `utils/finding_contract.py`, `pipeline/pattern_analysis.py`, `utils/pattern_suppression.py`, `utils/candidate_extractor.py`, `utils/ai_correlation_analyzer.py`, `utils/hunting_logger.py` (telemetry).

**Refactor docs:** `docs/refactor/file_audit.md`, `finding_contract.md`, `dispatch_state_machine.md`, `agent_loop.md`, `pattern_check_inventory.md` + `.csv`, `silent_default_audit.md`.

**Tests:** 88 files in `tests/`, 63 of which are phase contract tests (`test_phase*.py`) asserting refactor invariants.

---

## 5. Phase Plan

Phases are sequenced so earlier phases' findings feed later ones. Each phase has a clearly scoped file list, an entry condition, a deliverable, and an expected chat size.

### Phase 0 — Orientation and Master Plan
**Status:** Complete (this document).
**Deliverable:** This file.
**Entry:** None.
**Exit:** User approves the plan.

---

### Phase 1 — Scoring 2.0 Design Review and Implementation Planning
**Why first:** This is the highest-value unshipped work. The rollout plan is already excellent, but before implementation starts it deserves an independent review: are the semantics right, is the dual-path safe, do the acceptance criteria actually prove what they claim to prove?

**Scope:**
- Review `_REFACTOR/scoring_2_0_rollout.plan.md` against the live scoring code.
- Walk through the six design invariants and validate each against a concrete pattern.
- Trace what implementation changes are required in `_compute_score`, `_run_checks`, `_validate_sequences`, burst contribution, and finding emission.
- Identify risks the plan doesn't address (if any).
- Produce a concrete implementation checklist — file, function, what changes, what tests cover it.
- Flag any patterns in `PATTERN_CHECKS` whose weights will behave surprisingly under 2.0 semantics.

**Files:**
- `_REFACTOR/scoring_2_0_rollout.plan.md`
- `utils/deterministic_evidence_engine.py`
- `utils/pattern_check_definitions.py` (structure, not full content)
- `utils/pattern_event_mappings.py` (structure)
- `utils/finding_contract.py`
- `pipeline/pattern_analysis.py` (scoring consumption points)
- `utils/ai_correlation_analyzer.py` (how AI consumes scores)
- `utils/pattern_suppression.py`
- Selected tests: `test_deterministic_pattern_regressions.py`, `test_pattern_overlay.py`, phase 7 pattern stage tests.

**Deliverable:** `PHASE1_SCORING_2_0_REVIEW.md` with:
- Validated vs. questioned design invariants.
- Per-file implementation checklist.
- Risks the plan doesn't currently cover.
- Recommended acceptance-criteria additions.
- Pattern migration priority (cross-referenced with the 10 patterns the rollout plan already named).

**Expected chat size:** 1 chat.

---

### Phase 2 — Refactor Exit-Criteria Verification
**Why:** The refactor plan declares every todo complete, but completion was declared by the same sessions doing the work. An independent verification pass against the exit criteria turns "declared complete" into "verified complete."

**Scope — for each phase in the refactor:**
- Read the stated exit criteria from `master-goals-and-workstreams.plan.md` and `remaining_refactor_work_3b16c544.plan.md`.
- Grep/inspect the live code for evidence that the criteria are met.
- Confirm or flag with `DRIFT` category.
- Cross-check `docs/refactor/file_audit.md` against actual line counts, file existence, and described behavior.

**Specific checks:**
- Phase 3 route decomposition: is `routes/api.py` actually gone (file_audit says yes, verify), do all routes register cleanly, is there still shared helper sprawl?
- Phase 4a check inventory: does `docs/refactor/pattern_check_inventory.csv` match the live `PATTERN_CHECKS` dict? (42 patterns, ~246 rows.)
- Phase 4b TI separation: grep-audit for any detection-time TI mutation paths.
- Phase 5 IOC boundary: are `ioc_extractor.py` internal dependencies actually isolated, or do callers still reach past the facade?
- Phase 6 AI runtime: do `chat_agent.py`, `ai_report_generator.py`, `ai_timeline_generator.py`, `ai_checkpoints.py`, `ioc_extractor.py`, `rag_llm.py` go through `utils/ai/router.py`?
- Phase 6.5 parser provenance: do parsers actually emit provenance tags? Does dispatch validate them?
- Phase 7 case-analysis decomposition: is `case_analyzer.py` really orchestration-only, or does it still own domain logic?
- Phase 8 overlay authority: does `pattern_overlay.py` mutate pre-emission confidence, or strictly annotate?
- Phase 9: `legacy_fallback_used` path removal, `routes/findings.py` presence, TI rule sync deferral.

**Files:** Spot-checked from each phase's `Primary repo areas`. Focus on the files named in `file_audit.md`.

**Deliverable:** `PHASE2_REFACTOR_VERIFICATION.md` with:
- Per-phase verification table (criterion → evidence → verified/drift/not-verified).
- Proposed updates to `docs/refactor/file_audit.md`.
- `DRIFT` findings for each inconsistency.

**Expected chat size:** 1–2 chats. If it splits, Phase 2a covers Phases 0–4b, Phase 2b covers 5–9 and Scoring 2.0.

---

### Phase 3 — Deterministic Core Correctness Review
**Why:** The forensic heart of the system. Even after scoring 2.0, the core has to be right on timezones, SQL, windowing, edge cases, and partial data.

**Scope:**
- Scoring math end-to-end (already partially covered in the prior chat; fold those findings in and extend).
- Timezone handling across ingest → ClickHouse storage → window computation → display.
- SQL construction: parameterization discipline, `LIKE` escaping, user-data-derived fragments.
- Window semantics: per-edge vs. per-step-from-anchor, wraparound, open/closed intervals.
- Partial-data behavior: how does the engine behave when a log source is missing mid-window vs. for the whole window?
- Anchor-selection: is the rarest-event optimization available where the census is present?
- Burst detection: cadence, single-source vs. distributed, peak-vs-count weighting.
- Sequence chains: multi-candidate handling, missing-because-outside-window vs. missing-because-absent.
- Spread detection (cross-host correlation).

**Files:**
- `utils/deterministic_evidence_engine.py`
- `utils/candidate_extractor.py`
- `utils/finding_contract.py`
- `pipeline/pattern_analysis.py`
- `utils/stateful_detectors/*`
- `utils/pattern_check_definitions.py` (check definitions that look suspect — spot check)
- `utils/gap_detector_bridge.py`
- `utils/timezone.py`

**Deliverable:** `PHASE3_DETERMINISTIC_CORE_REVIEW.md` with concrete findings in the standard taxonomy. Roll in prior-chat scoring observations. Produce a severity-ranked defect list.

**Expected chat size:** 1–2 chats.

---

### Phase 4 — Parsers
**Why:** Parsers are the source of truth for every downstream artifact. Any normalization bug here becomes a detection bug everywhere.

**Scope:**
- `parsers/base.py` contract: field names, types, timezone, missing-value handling.
- `parsers/catalog.py` and `parsers/registry.py`: coverage against declared artifact types.
- Per-family review: EVTX, dissect, log, browser, memory, registry, Windows, vendor.
- Provenance emission (Phase 6.5 exit criterion).
- Coverage gaps vs. `pattern_event_mappings.py`: does every event ID a pattern asks for have a parser that produces it with the right fields?
- Timezone consistency (hand off to Phase 3's timezone thread).

**Files:**
- `parsers/*.py`
- `docs/PARSERS.md`
- `utils/provenance.py`

**Deliverable:** `PHASE4_PARSER_REVIEW.md`. Pay special attention to `DRIFT` between parser output shape and what consumers expect.

**Expected chat size:** 1–2 chats (browser + dissect alone are 4K lines).

---

### Phase 5 — IOC Pipeline
**Why:** Large surface area (~15 modules), known historical duplication, Phase 5 of the refactor left `ioc_extractor.py` as a 2826-line facade. Worth a focused correctness pass.

**Scope:**
- Is `ioc_extractor.py` actually thin, or is it still doing real work that belongs in the component modules?
- Dedup/merge semantics: do two paths produce the same canonical IOC?
- Schema validation ordering (deterministic first, AI review after, per refactor invariant).
- Defang/refang handling: single source of truth?
- AI audit path: is the optional AI layer additive or authoritative?
- `ioc_artifact_tagger.py` correctness (cross-artifact tagging is load-bearing for forensic output).

**Files:** All `utils/ioc_*.py`, `models/ioc.py`.

**Deliverable:** `PHASE5_IOC_REVIEW.md`.

**Expected chat size:** 1 chat.

---

### Phase 6 — AI Runtime and Chat
**Why:** Phase 6 of the refactor unified the runtime, but `remaining_refactor_work` flagged that several callers still bypass the router. Verify, then review the runtime itself for correctness.

**Scope:**
- Do all callers go through `utils/ai/router.py`? (Grep audit.)
- Chat dispatch state machine: L0/L1/L2/L3 boundary enforcement.
- Tool dispatch: read-only default, explicit approval for state-changing tools, case-scope isolation, prompt-injection resistance.
- Provenance threading through chat outputs.
- Premium-gating consistency (feature_availability).
- Subagent scoping: does each flow only see its allowed tools?

**Files:**
- `utils/ai/router.py`
- `utils/chat/dispatch.py`, `policy.py`, `runtime.py`
- `utils/chat_agent.py`, `chat_tools.py`, `forensic_chat_sources.py`
- `utils/ai_checkpoints.py`
- `utils/ai_report_generator.py`, `ai_timeline_generator.py` (verify router usage)
- `docs/refactor/agent_loop.md`, `dispatch_state_machine.md`
- Tests: `test_phase6_*`.

**Deliverable:** `PHASE6_AI_RUNTIME_REVIEW.md`.

**Expected chat size:** 1 chat.

---

### Phase 7 — Routes and Request Surface
**Why:** Routes are where input validation, auth, error handling, and response-shape consistency live. Post-decomposition they're split across 26 files.

**Scope:**
- Auth and license-gating consistency per route.
- Input validation, especially for case_id and query params (see `docs/refactor/silent_default_audit.md`).
- Error-response shape consistency.
- SQL/ClickHouse query construction inside routes (should be minimal — should route to helpers).
- Response serialization consistency (unified finding contract compliance).
- `routes/findings.py` — is it actually wired in and serving the unified read path?

**Files:** `routes/*.py` (all), `routes/route_helpers.py`, `routes/hunting_query_helpers.py`.

**Deliverable:** `PHASE7_ROUTES_REVIEW.md`. Likely organized by category (auth/validation/shape/helpers) rather than per-file.

**Expected chat size:** 1–2 chats.

---

### Phase 8 — Tasks, Pipelines, and Orchestration
**Why:** The async/background surface. `celery_tasks.py` is 2237, `rag_tasks.py` is 3027 — they're where most of the heavy lifting actually runs.

**Scope:**
- Task idempotency, retry semantics, dead-letter handling.
- Pipeline stage interfaces: do they match the contracts declared in `pipeline/__init__.py`?
- Long-running task progress and cancellation.
- Storage writes: dedup keys, transactional boundaries, partial-failure behavior.
- `case_analyzer.py` as orchestration-only (feeds from Phase 2 verification).

**Files:** `tasks/*.py`, `pipeline/*.py`, `utils/case_analyzer.py`.

**Deliverable:** `PHASE8_TASKS_AND_PIPELINE_REVIEW.md`.

**Expected chat size:** 1 chat.

---

### Phase 9 — Enrichment and External Integrations
**Why:** OpenCTI and MISP are big surface areas with network I/O, rate limits, and TI correctness implications. TI separation is a core refactor invariant worth a focused verification.

**Scope:**
- `pattern_overlay.py` and `ti/enrichment.py`: strictly additive, no pre-emission mutation (verifies Phase 1.5 / Phase 8 invariants).
- `opencti.py` (2239): query construction, rate limits, error handling, caching, case-scope isolation.
- `misp.py`: same.
- `mitre_attack_sync.py`: freshness and sync semantics.
- `peer_clustering.py`, `behavioral_profiler.py`, `threat_intel_context.py`.

**Files:** listed above, plus `utils/ti/enrichment.py`.

**Deliverable:** `PHASE9_ENRICHMENT_REVIEW.md`.

**Expected chat size:** 1 chat.

---

### Phase 10 — Cross-Cutting Concerns and Dead Code Sweep
**Why:** By this point all subsystems have been reviewed. A dedicated pass can catch things that no single subsystem owner would: timezone drift, SQL pattern inconsistency across the codebase, import graph dead-ends, compatibility shims that outlived their need.

**Scope:**
- Consolidate the `cross_cutting` log from all prior phases into themed findings.
- Dead-code sweep: unused imports, unreachable branches, migrations superseded by others, scraper code with no callers.
- Import-graph audit: modules imported but never meaningfully used.
- Duplicated logic: same normalization or lookup in multiple places.
- Compatibility shims that Phase 9 was meant to retire.
- Test audit: tests asserting deprecated shapes, tests testing implementation not behavior.

**Files:** Cross-cutting — no single owner.

**Deliverable:** `PHASE10_CROSS_CUTTING_AND_DEAD_CODE.md`.

**Expected chat size:** 1 chat.

---

### Phase 11 — Documentation Sync and Backlog Roll-up
**Why:** After all review phases, reconcile everything into one prioritized backlog the human can act on.

**Scope:**
- Consolidate all phase findings into a single ranked backlog.
- Propose concrete updates to `docs/refactor/file_audit.md`.
- Identify findings that are really new phases (if any).
- Produce a "fix-before-ship" list vs. "fix-this-quarter" vs. "known-limitation" vs. "nice-to-have."
- Suggest which findings warrant regression tests before fixing.

**Deliverable:** `PHASE11_FINAL_BACKLOG.md` plus proposed patches to existing refactor docs.

**Expected chat size:** 1 chat.

---

## 6. Per-Chat Operating Protocol

Every phase chat starts with:

1. Claude reads this master MD.
2. Claude reads the prior phase's deliverable(s).
3. Claude reads the phase-specific files (from the plan above).
4. Claude produces the phase deliverable as an MD file in `/home/claude/` (and offers it as a download).
5. Claude appends a concise entry to the `Cross-Cutting Log` (Section 7 below) for anything that isn't owned by the current phase.
6. Claude updates the `Decisions Log` (Section 8) if any decision gets made that affects future phases.
7. Claude proposes updates to this master MD itself if the phase revealed scope inaccuracies.

Rules:
- No phase reaches out of its scoped file list without calling it out explicitly.
- Findings are actionable. "This could be better" is not a finding. "This produces wrong output when X, because Y, fix by Z" is a finding.
- If a phase runs long, stop at a clean break, write the partial deliverable, and flag the remaining scope for a continuation chat.
- If Claude is tempted to rewrite code, stop. Record the finding with a proposed patch and move on.

---

## 7. Cross-Cutting Log

_Maintained across phases. Each entry: short tag, description, where discovered, where it'll be resolved._

| Tag | Description | Found in | Owner phase |
|---|---|---|---|
| _(Phase 1 will begin populating.)_ | | | |

---

## 8. Decisions Log

_Records decisions made during review that affect subsequent phases._

| Date | Decision | Rationale | Affects |
|---|---|---|---|
| 2026-04-20 | Reframe from generic code review to (a) Scoring 2.0 planning, (b) refactor verification, (c) correctness review. | The refactor is ~95% complete. A generic review would duplicate prior work. | All phases |
| 2026-04-20 | Claude does not make code changes; findings + proposed patches only. | User retains control of what lands. | All phases |

---

## 9. Glossary

- **Anchor** — A required event that acts as the pivot for pattern evaluation. Other events in the pattern are found by walking forward/backward from the anchor.
- **Check** — The atomic unit of pattern evaluation. One pattern has many checks. Each check has a type (`anchor_match`, `threshold`, `graduated`, `field_match`, `burst`, `sequence`, `absence_with_coverage`) and a weight.
- **Burst** — A temporal clustering detection: N+ events of a certain type within a window from the same principal.
- **Sequence** — An ordered chain of events, validated by walking forward/backward from the anchor with per-step time offsets.
- **Coverage** — Whether the required log sources were even present in the window. Separates "didn't happen" from "wasn't observable."
- **Spread** — Cross-host/cross-key correlation: the same pattern firing on multiple principals within a window.
- **Gap finding** — Legacy term. Mostly a presence detector despite the name. Produced by `utils/stateful_detectors/` (renamed from `gap_detectors/`).
- **Producer input** — Contributory metadata from a specific detector (burst engine, sequence engine, gap detector) attached to a finding, used by downstream scoring and UI.
- **Evidence package** — The per-correlation-key output of the deterministic engine: checks + coverage + bursts + sequences + score.
- **Scoring 2.0** — The planned scoring overhaul separating `deterministic_score` from `eligible_to_emit`, fixing INCONCLUSIVE double-counting, and adding explicit coverage policy per check.
- **Unified finding** — The single canonical shape all detection producers write into (`utils/finding_contract.py`).
- **Detector metadata** — The opaque-to-most-consumers overflow field for producer-specific data on a unified finding.
- **Provenance** — Per-field tagging of where a value came from (parser → producer → runtime), validated at dispatch.
- **Anchor-walk** — The matching strategy: pivot on the rarest required event, walk backward/forward for the rest of the chain within per-step windows.
- **Phase** (in refactor docs) — A work unit in the refactor plan. Not the same as a review phase.
- **Phase** (in this plan) — A review work unit, each scoped for one or two chats.

---

## 10. Index of Phase Deliverables

_Populated as phases complete._

| Phase | File | Status |
|---|---|---|
| 0 | `CASESCOPE_REVIEW_MASTER.md` (this file) | Complete |
| 1 | `PHASE1_SCORING_2_0_REVIEW.md` | Not started |
| 2 | `PHASE2_REFACTOR_VERIFICATION.md` | Not started |
| 3 | `PHASE3_DETERMINISTIC_CORE_REVIEW.md` | Not started |
| 4 | `PHASE4_PARSER_REVIEW.md` | Not started |
| 5 | `PHASE5_IOC_REVIEW.md` | Not started |
| 6 | `PHASE6_AI_RUNTIME_REVIEW.md` | Not started |
| 7 | `PHASE7_ROUTES_REVIEW.md` | Not started |
| 8 | `PHASE8_TASKS_AND_PIPELINE_REVIEW.md` | Not started |
| 9 | `PHASE9_ENRICHMENT_REVIEW.md` | Not started |
| 10 | `PHASE10_CROSS_CUTTING_AND_DEAD_CODE.md` | Not started |
| 11 | `PHASE11_FINAL_BACKLOG.md` | Not started |

---

## 11. How To Start A Phase Chat

Copy this into a new chat along with an upload of the latest code:

> Phase N of the CaseScope review. Master plan is `CASESCOPE_REVIEW_MASTER.md` in the archive. Prior deliverables are `PHASE<N-1>_*.md` and earlier. Execute Phase N per the master plan. Produce the deliverable MD and update the Cross-Cutting Log and Decisions Log sections of the master as instructed. Do not exceed Phase N's scoped file list without flagging it.

That's the entire kickoff.
