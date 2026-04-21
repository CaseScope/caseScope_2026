# CaseScope Code Review — Master Plan

> **Purpose.** Drive a multi-session, phased independent review of the CaseScope codebase. Each Review is scoped tightly enough to complete in a single Cursor chat, produces a self-contained findings artifact in `_REVIEW/`, and leaves this master document updated for the next Review to pick up from.

> **Source of truth.** Code in the repo. This plan and its Review deliverables are the review's output. When the plan and the code disagree, the code wins and this plan gets updated.

---

## 1. Project Context

CaseScope is a DFIR platform (~130K lines of Python, Flask + ClickHouse + Postgres + Celery) for ingesting forensic artifacts (CyLR output, EVTX, memory images, PCAP, browser history, registry, etc.), running deterministic detection patterns over them, and producing case-level forensic output (timelines, reports, findings, IOC extraction). AI, OpenCTI/MISP, and RAG are premium overlays on top of a deterministic core that must remain fully functional without them.

The system has undergone a structured multi-phase refactor (Refactor Phases 0 through 9, plus Refactor Phase 6.5 and a dedicated Scoring 2.0 rollout). Most of that work is either shipped or explicitly deferred. This review is not a refactor — it is an independent correctness and completeness check against the post-refactor state, plus prioritized follow-up for unshipped design work.

**What "correct" means here is forensic-grade output.** A wrong SQL filter is worse than a slow one. A score that silently inflates is worse than a score that is missing. A finding that loses provenance is worse than a finding that was never generated. Every Review weights findings accordingly.

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

**Code changes during a Review are allowed when authorized by the user.** The default is findings-and-proposed-patches; when the user says "do Review N" that constitutes authorization to make any code changes the Review's scope justifies. Changes outside the Review's scope still require explicit per-change authorization. The Reviewer must record every change made in the Review's deliverable.

---

## 3. Finding Taxonomy

Each finding carries all five fields. No exceptions.

| Field | Values |
|---|---|
| **Category** | `BUG` / `CORRECTNESS` / `DEAD` / `DUPLICATION` / `RISK` / `PERF` / `CLARITY` / `GAP` / `TEST` / `DOC` / `DRIFT` |
| **Severity** | `CRITICAL` (data loss, security, forensic output wrong) / `HIGH` (degraded output, defensibility concerns) / `MEDIUM` (confusing but correct, or fragile) / `LOW` (cleanup, clarity) |
| **Location** | `file.py:line` or `module/` for cross-file |
| **Summary** | One-line problem statement |
| **Proposed fix** | Concrete change and rough effort (S/M/L); if landed in this Review, note commit SHA |

`DRIFT` is reserved for "the refactor plan / docs say X, the code says Y." It's separate from `DEAD` because the resolution is usually "update the doc," not "delete code."

---

## 4. Architecture Map (as-observed)

Captured during Review 0 exploration, refreshed at the start of Review 1. Sizes are current line counts (verified 2026-04-20).

**Entry points:** `run.py`, `wsgi.py`, `app.py`, `config.py`.

**Data layer:**
- Postgres for transactional/business state, accessed through `models/*.py` (SQLAlchemy). Notable sizes: `models/pattern_rules.py` 3672, `models/rag.py` 1715, `models/ioc.py` 1117, `models/behavioral_profiles.py` ~28K chars.
- ClickHouse for high-volume analytical data, accessed through `utils/clickhouse.py` and direct query construction in engines/tasks.
- Migrations in `migrations/`.

**Detection core:**
- `utils/deterministic_evidence_engine.py` (1965) — anchor-walk evaluator, scoring, coverage, burst, sequence. Has grown ~22% since the original master plan was drafted; growth attributable to in-flight Scoring 2.0 work (see Cross-Cutting Log).
- `utils/pattern_check_definitions.py` (3073) — declarative check registry (42 patterns, 247 checks; `docs/refactor/pattern_check_inventory.csv` was regenerated from live code on 2026-04-20 and now matches).
- `utils/pattern_event_mappings.py` (1728) — per-pattern anchor/supporting/context event mappings.
- `utils/candidate_extractor.py` (1032) — first-pass anchor extraction.
- `utils/stateful_detectors/` — behavioral_anomaly, brute_force, password_spraying (the renamed "gap detectors").
- `utils/rules/loader.py` — dual-path rule loader.
- `utils/hayabusa_correlator.py` (772) — Hayabusa → unified finding bridge.
- `utils/sigma_converter.py` — Sigma ingestion.
- `utils/attack_pattern_loader.py`, `utils/attack_chain_builder.py`.
- `utils/pattern_overlay.py` (518) — post-detection TI overlay (moved out of the hot path per Refactor Phase 1.5). Has grown ~35% since the original master plan; verify intent during Review 9.
- `utils/pattern_suppression.py`, `utils/gap_detector_bridge.py`.

**Pipeline orchestration:**
- `pipeline/pattern_analysis.py` (1178) — per-pattern stage orchestration.
- `pipeline/detect.py`, `detect_anomalies.py`, `baselines.py`, `case_actions.py`, `case_enrichment.py`, `case_narrative.py`, `case_timeline.py`.
- `utils/case_analyzer.py` (1203) — case-level orchestrator, now thinner.

**IOC pipeline:**
- `utils/ioc_extractor.py` (2826) — canonical orchestration facade (per Refactor Phase 9 decision).
- `utils/ioc_text.py`, `ioc_normalizer.py`, `ioc_merge.py`, `ioc_contract.py`, `ioc_contract_adapter.py`, `ioc_schema.py`, `ioc_audit.py`, `ioc_model_eval.py`, `ioc_artifact_tagger.py`, `ioc_timeline_builder.py`, `ioc_training_dataset.py`, `ioc_vendor_corpus.py`, `semantic_ioc_extractor.py`, `deterministic_ioc_extractor.py`.

**AI runtime:**
- `utils/ai/router.py` — shared router (Refactor Phase 6).
- `utils/chat/dispatch.py`, `policy.py`, `runtime.py` — shared chat runtime with L0/L1/L2/L3 dispatch state machine.
- `utils/ai_providers.py` (1808), `ai_adapters.py`, `ai_correlation_analyzer.py` (1616), `ai_event_summary.py`, `ai_report_generator.py` (1320), `ai_review.py`, `ai_timeline_generator.py`, `ai_checkpoints.py`.
- `utils/chat_agent.py`, `chat_tools.py` (1259), `forensic_chat_sources.py`.

**Parsers:**
- `parsers/` with `base.py`, `catalog.py`, `registry.py`, `evtx_parser.py`, `dissect_parsers.py` (1966), `log_parsers.py` (1797), `browser_parsers.py` (2054), `memory_parser.py`, `windows_parsers.py`, `vendor_parsers.py`.

**Enrichment / external:**
- `utils/opencti.py` (2239), `opencti_context.py`, `misp.py`, `mitre_attack_sync.py`, `threat_intel_context.py`, `peer_clustering.py`, `behavioral_profiler.py`.
- `utils/ti/enrichment.py` — additive post-detection TI overlay.

**Routes:**
- `routes/` split by responsibility (29 Python files total including package `__init__.py`; 28 route modules listed here): `admin.py`, `ai.py`, `analysis.py`, `archive.py`, `auth.py`, `case_files.py`, `chat.py`, `dashboard.py`, `enrichment.py`, `evidence.py`, `findings.py`, `hunting.py`, `ingest.py`, `iocs.py`, `known_systems.py`, `known_users.py`, `main.py`, `memory.py`, `network_hunting.py`, `noise.py`, `ops.py`, `parsing.py`, `pcap.py`, `rag.py`, `reports.py`, `activation.py`, plus helpers (`route_helpers.py`, `hunting_query_helpers.py`).
- `routes/api.py` is gone (retired in Refactor Phase 9 per `file_audit.md`) — verified.

**Tasks:** `tasks/celery_tasks.py` (2237), `tasks/rag_tasks.py` (3028), `tasks/pcap_tasks.py` (1216).

**Licensing:** `utils/licensing/` with `fingerprint.py`, `license_manager.py`, `nist_time.py`, `server_client.py`, `validator.py`.

**Scoring 2.0 surface (planned + in-flight):** `utils/deterministic_evidence_engine.py`, `utils/pattern_check_definitions.py`, `utils/finding_contract.py`, `pipeline/pattern_analysis.py`, `utils/pattern_suppression.py`, `utils/candidate_extractor.py`, `utils/ai_correlation_analyzer.py`, `utils/hunting_logger.py` (telemetry).

**Refactor docs:** `docs/refactor/file_audit.md`, `finding_contract.md`, `dispatch_state_machine.md`, `agent_loop.md`, `pattern_check_inventory.md` + `.csv`, `silent_default_audit.md`.

**Tests:** 93 files in `tests/`, 63 of which are refactor-phase contract tests (`test_phase*.py`) asserting refactor invariants.

---

## 5. Review Plan

Reviews are sequenced so earlier ones' findings feed later ones. Each Review has a clearly scoped file list, an entry condition, a deliverable, and an expected session size. Each Review is one Cursor chat; the operating protocol in Section 6 applies.

**Naming conventions** (to disambiguate three concentric "Phase" namespaces):
- **Review N** — a unit of work in this master plan (Reviews 0–11).
- **Review Na / Nb** — a pre-split continuation of a larger Review, used when one logical Review is intentionally divided into multiple low-context chats.
- **Refactor Phase N** — a unit of work in the prior refactor effort (`_REFACTOR/master-goals-and-workstreams.plan.md`).
- **Rollout Step N** — a unit of work inside the Scoring 2.0 rollout plan (`_REFACTOR/scoring_2_0_rollout.plan.md`, internal Phase 0–5).

Deliverable filenames follow the exact Review label, e.g. `_REVIEW/REVIEW1_<topic>.md` or `_REVIEW/REVIEW2A_<topic>.md`.

### Review 0 — Orientation and Master Plan
**Status:** Complete (this document, as updated).
**Deliverable:** This file.
**Entry:** None.
**Exit:** User approved the plan; checkpoint committed; Cursor adaptation applied.

---

### Review 1 — Scoring 2.0 Design Review and Implementation Audit
**Why first:** This is the highest-value unshipped work. The rollout plan is excellent on paper, but the engine has already grown 355 lines since the master plan was drafted and 7 `fix(scoring): ...` commits are already in shared history on `main` — meaning Scoring 2.0 is no longer "before implementation." Review 1 must reconcile what the rollout plan claims is pending against what has actually shipped, then validate the design and remaining implementation against the live code.

**Pre-flight (do this first inside Review 1):**
A short foundation sanity check that confirms Review 1 is operating on the same ground truth the rollout plan assumes:
- `_compute_score`, `_run_checks`, `_validate_sequences` exist in `utils/deterministic_evidence_engine.py` with the shapes the rollout plan describes; record actual signatures.
- `utils/finding_contract.py` either already has the package-level fields the rollout plan adds (`deterministic_score`, `eligible_to_emit`, `evaluable_weight`, `excluded_weight`, `coverage_gap_present`, `scoring_version`) or doesn't — record which.
- Reconcile the rollout plan's todo statuses (all `pending`) against the 7 already-landed `fix(scoring): ...` commits and the +355 lines in the engine; produce an updated todo status table.
- `routes/findings.py` is wired into the unified read path (one grep / route registration check).
- `utils/ai/router.py` callers per Refactor Phase 6 — quick grep to seed Review 6.
- Confirm `pattern_check_inventory.csv` still matches the live `PATTERN_CHECKS` dict. Current baseline is 42 patterns and 247 CSV data rows/checks after regeneration from live code on 2026-04-20.

If Pre-flight reveals that Review 1's premises are materially wrong, stop, write what was found, and ask before continuing.

**Scope (post-Pre-flight):**
- Review `_REFACTOR/scoring_2_0_rollout.plan.md` against the live scoring code.
- Walk through the eight design invariants and validate each against a concrete pattern.
- Trace what implementation changes remain in `_compute_score`, `_run_checks`, `_validate_sequences`, burst contribution, and finding emission.
- Audit telemetry availability against the rollout plan's Rollout Step 0/1 telemetry contract; flag any acceptance criterion (rollout plan lines 168–174) that depends on telemetry that doesn't yet exist or that the in-flight commits have already added.
- Identify risks the plan doesn't address (if any).
- Produce a concrete implementation checklist — file, function, what changes, what tests cover it.
- Flag any patterns in `PATTERN_CHECKS` whose weights will behave surprisingly under 2.0 semantics.

**Files:**
- `_REFACTOR/scoring_2_0_rollout.plan.md`
- `_REFACTOR/scoring_2_0_case_*` artifacts (prior measurement output)
- `_REFACTOR/session-{a..f}.md` (read as background; do not assume conclusions still hold)
- `utils/deterministic_evidence_engine.py`
- `utils/pattern_check_definitions.py` (structure, not full content)
- `utils/pattern_event_mappings.py` (structure)
- `utils/finding_contract.py`
- `pipeline/pattern_analysis.py` (scoring consumption points)
- `utils/ai_correlation_analyzer.py` (how AI consumes scores)
- `utils/pattern_suppression.py`
- `utils/hunting_logger.py` (telemetry surface)
- Selected tests: `test_deterministic_pattern_regressions.py`, `test_pattern_overlay.py`, refactor-phase 7 pattern stage tests, `test_scoring_2_*`.

**Deliverable:** `REVIEW1_SCORING_2_0.md` with:
- Pre-flight results (foundations verified or flagged).
- Reconciled rollout plan todo status (declared vs. actual).
- Validated vs. questioned design invariants.
- Per-file implementation checklist for what remains.
- Risks the plan doesn't currently cover.
- Recommended acceptance-criteria additions.
- Pattern migration priority (cross-referenced with the 10 patterns the rollout plan already named).
- Any code changes landed during this Review (file, commit SHA, justification).

**Expected session size:** 1 Cursor chat.

---

### Review 2 — Refactor Exit-Criteria Verification
**Why:** The refactor plan declares every todo complete, but completion was declared by the same sessions doing the work. An independent verification pass against the exit criteria turns "declared complete" into "verified complete."

**Scope — for each Refactor Phase:**
- Read the stated exit criteria from `master-goals-and-workstreams.plan.md` and `remaining_refactor_work_3b16c544.plan.md`.
- Grep/inspect the live code for evidence that the criteria are met.
- Confirm or flag with `DRIFT` category.
- Cross-check `docs/refactor/file_audit.md` against actual line counts, file existence, and described behavior.

**Specific checks:**
- Refactor Phase 3 route decomposition: `routes/api.py` actually gone (verified in Review 0; re-spot-check for shared helper sprawl).
- Refactor Phase 4a check inventory: does `docs/refactor/pattern_check_inventory.csv` match the live `PATTERN_CHECKS` dict?
- Refactor Phase 4b TI separation: grep-audit for any detection-time TI mutation paths.
- Refactor Phase 5 IOC boundary: are `ioc_extractor.py` internal dependencies actually isolated, or do callers still reach past the facade?
- Refactor Phase 6 AI runtime: do `chat_agent.py`, `ai_report_generator.py`, `ai_timeline_generator.py`, `ai_checkpoints.py`, `ioc_extractor.py`, `rag_llm.py` go through `utils/ai/router.py`?
- Refactor Phase 6.5 parser provenance: do parsers actually emit provenance tags? Does dispatch validate them?
- Refactor Phase 7 case-analysis decomposition: is `case_analyzer.py` really orchestration-only, or does it still own domain logic?
- Refactor Phase 8 overlay authority: does `pattern_overlay.py` mutate pre-emission confidence, or strictly annotate? (Note: file has grown 35%; investigate.)
- Refactor Phase 9: `legacy_fallback_used` path removal, `routes/findings.py` presence, TI rule sync deferral.

**Files:** Spot-checked from each Refactor Phase's `Primary repo areas`. Focus on the files named in `file_audit.md`.

**Deliverables:** `REVIEW2A_REFACTOR_VERIFICATION.md` and `REVIEW2B_REFACTOR_VERIFICATION.md`, each with:
- Per-Refactor-Phase verification table (criterion → evidence → verified/drift/not-verified).
- Proposed updates to `docs/refactor/file_audit.md`.
- `DRIFT` findings for each inconsistency.

**Execution split:** Review 2a covers Refactor Phases 0–4b. Review 2b covers Refactor Phases 5–9 plus any Scoring 2.0 carryover that affects refactor exit-criteria claims.

**Expected session size:** 1 Cursor chat per subreview.

---

### Review 3 — Deterministic Core Correctness Review
**Why:** The forensic heart of the system. Even after Scoring 2.0, the core has to be right on timezones, SQL, windowing, edge cases, and partial data.

**Scope:**
- Scoring math end-to-end (extends Review 1).
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

**Deliverables:** `REVIEW3A_DETERMINISTIC_CORE.md` and `REVIEW3B_DETERMINISTIC_CORE.md`, each using the standard taxonomy.
- Review 3a: scoring math, timezone handling, SQL construction, window semantics, anchor selection.
- Review 3b: partial-data behavior, burst detection, sequence handling, spread detection, and `utils/stateful_detectors/*` / `utils/gap_detector_bridge.py` integration.
- Roll any prior-session scoring observations from `_REFACTOR/session-*.md` into the relevant subreview only if they survived Review 1 verification.

**Expected session size:** 1 Cursor chat per subreview.

---

### Review 4 — Parsers
**Why:** Parsers are the source of truth for every downstream artifact. Any normalization bug here becomes a detection bug everywhere.

**Scope:**
- `parsers/base.py` contract: field names, types, timezone, missing-value handling.
- `parsers/catalog.py` and `parsers/registry.py`: coverage against declared artifact types.
- Per-family review: EVTX, dissect, log, browser, memory, registry, Windows, vendor.
- Provenance emission (Refactor Phase 6.5 exit criterion).
- Coverage gaps vs. `pattern_event_mappings.py`: does every event ID a pattern asks for have a parser that produces it with the right fields?
- Timezone consistency (hand off to Review 3's timezone thread).

**Files:**
- `parsers/*.py`
- `docs/PARSERS.md`
- `utils/provenance.py`

**Deliverables:** `REVIEW4A_PARSERS.md` and `REVIEW4B_PARSERS.md`. Pay special attention to `DRIFT` between parser output shape and what consumers expect.

**Execution split:** Review 4a covers EVTX / dissect / Windows / registry. Review 4b covers browser / log / memory / vendor.

**Expected session size:** 1 Cursor chat per subreview.

---

### Review 5 — IOC Pipeline
**Why:** Large surface area (~15 modules), known historical duplication, Refactor Phase 5 left `ioc_extractor.py` as a 2826-line facade. Worth a focused correctness pass.

**Scope:**
- Is `ioc_extractor.py` actually thin, or is it still doing real work that belongs in the component modules?
- Dedup/merge semantics: do two paths produce the same canonical IOC?
- Schema validation ordering (deterministic first, AI review after, per refactor invariant).
- Defang/refang handling: single source of truth?
- AI audit path: is the optional AI layer additive or authoritative?
- `ioc_artifact_tagger.py` correctness (cross-artifact tagging is load-bearing for forensic output).

**Files:** All `utils/ioc_*.py`, `models/ioc.py`.

**Deliverable:** `REVIEW5_IOC.md`.

**Expected session size:** 1 Cursor chat.

---

### Review 6 — AI Runtime and Chat
**Why:** Refactor Phase 6 unified the runtime, but `remaining_refactor_work` flagged that several callers still bypass the router. Verify, then review the runtime itself for correctness.

**Scope:**
- Do all callers go through `utils/ai/router.py`? (Grep audit, seeded by Review 1 Pre-flight.)
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

**Deliverable:** `REVIEW6_AI_RUNTIME.md`.

**Expected session size:** 1 Cursor chat.

---

### Review 7 — Routes and Request Surface
**Why:** Routes are where input validation, auth, error handling, and response-shape consistency live. Post-decomposition they're split across 28 route modules plus the package `__init__.py`.

**Scope:**
- Auth and license-gating consistency per route.
- Input validation, especially for case_id and query params (see `docs/refactor/silent_default_audit.md`).
- Error-response shape consistency.
- SQL/ClickHouse query construction inside routes (should be minimal — should route to helpers).
- Response serialization consistency (unified finding contract compliance).
- `routes/findings.py` — is it actually wired in and serving the unified read path?

**Files:** `routes/*.py` (all), `routes/route_helpers.py`, `routes/hunting_query_helpers.py`.

**Deliverables:** `REVIEW7A_ROUTES.md` and `REVIEW7B_ROUTES.md`, organized by category rather than per-file.

**Execution split:** Review 7a covers auth/license gating, input validation, and error-response shape. Review 7b covers query construction, helper boundaries, response serialization, and `routes/findings.py` unified-read wiring.

**Expected session size:** 1 Cursor chat per subreview.

---

### Review 8 — Tasks, Pipelines, and Orchestration
**Why:** The async/background surface. `celery_tasks.py` is 2237, `rag_tasks.py` is 3028 — they're where most of the heavy lifting actually runs.

**Scope:**
- Task idempotency, retry semantics, dead-letter handling.
- Pipeline stage interfaces: do they match the contracts declared in `pipeline/__init__.py`?
- Long-running task progress and cancellation.
- Storage writes: dedup keys, transactional boundaries, partial-failure behavior.
- `case_analyzer.py` as orchestration-only (feeds from Review 2 verification).

**Files:** `tasks/*.py`, `pipeline/*.py`, `utils/case_analyzer.py`.

**Deliverable:** `REVIEW8_TASKS_AND_PIPELINE.md`.

**Expected session size:** 1 Cursor chat.

---

### Review 9 — Enrichment and External Integrations
**Why:** OpenCTI and MISP are big surface areas with network I/O, rate limits, and TI correctness implications. TI separation is a core refactor invariant worth a focused verification.

**Scope:**
- `pattern_overlay.py` and `ti/enrichment.py`: strictly additive, no pre-emission mutation (verifies Refactor Phase 1.5 / Refactor Phase 8 invariants). Note: `pattern_overlay.py` has grown 35% since the original master plan; understand why before judging.
- `opencti.py` (2239): query construction, rate limits, error handling, caching, case-scope isolation.
- `misp.py`: same.
- `mitre_attack_sync.py`: freshness and sync semantics.
- `peer_clustering.py`, `behavioral_profiler.py`, `threat_intel_context.py`.

**Files:** listed above, plus `utils/ti/enrichment.py`.

**Deliverable:** `REVIEW9_ENRICHMENT.md`.

**Expected session size:** 1 Cursor chat.

---

### Review 10 — Cross-Cutting Concerns and Dead Code Sweep
**Why:** By this point all subsystems have been reviewed. A dedicated pass can catch things that no single subsystem owner would: timezone drift, SQL pattern inconsistency across the codebase, import graph dead-ends, compatibility shims that outlived their need.

**Scope:**
- Consolidate the Cross-Cutting Log (Section 7) from all prior Reviews into themed findings.
- Dead-code sweep: unused imports, unreachable branches, migrations superseded by others, scraper code with no callers.
- Import-graph audit: modules imported but never meaningfully used.
- Duplicated logic: same normalization or lookup in multiple places.
- Compatibility shims that Refactor Phase 9 was meant to retire.
- Test audit: tests asserting deprecated shapes, tests testing implementation not behavior.

**Files:** Cross-cutting — no single owner.

**Deliverable:** `REVIEW10_CROSS_CUTTING_AND_DEAD_CODE.md`.

**Expected session size:** 1 Cursor chat.

---

### Review 11 — Documentation Sync and Backlog Roll-up
**Why:** After all Reviews, reconcile everything into one prioritized backlog the human can act on.

**Scope:**
- Consolidate all Review findings into a single ranked backlog.
- Propose concrete updates to `docs/refactor/file_audit.md`.
- Identify findings that are really new Reviews (if any).
- Produce a "fix-before-ship" list vs. "fix-this-quarter" vs. "known-limitation" vs. "nice-to-have."
- Suggest which findings warrant regression tests before fixing.

**Deliverable:** `REVIEW11_FINAL_BACKLOG.md` plus proposed patches to existing refactor docs.

**Expected session size:** 1 Cursor chat.

---

## 6. Per-Session Operating Protocol

Every Review session starts with:

1. Read this master MD.
2. Read the prior Review's deliverable(s).
3. Read the Review-specific files (from the plan above).
4. Produce the Review deliverable as `_REVIEW/REVIEW<N>_<topic>.md`.
5. Append a concise entry to the Cross-Cutting Log (Section 7) for anything that isn't owned by the current Review.
6. Update the Decisions Log (Section 8) if any decision gets made that affects future Reviews.
7. Propose updates to this master MD itself if the Review revealed scope inaccuracies; apply them in the same session if low-risk.
8. Update Section 10 (Index of Review Deliverables) status for this Review.
9. Commit the Review deliverable, master MD updates, and any in-scope code changes locally. Push to `origin/main` only when explicitly requested by the user.
10. Produce a hand-off summary in chat for the user that names: what was done, what code changed (with commit SHAs), what's outstanding for the next Review, and any open questions the user should resolve before starting the next Review.

Rules:
- No Review reaches out of its scoped file list without calling it out explicitly.
- Findings are actionable. "This could be better" is not a finding. "This produces wrong output when X, because Y, fix by Z" is a finding.
- If a Review runs long, stop at a clean break, write the partial deliverable, update Section 10 status to `In Progress`, hand off, and flag the remaining scope for a continuation session.
- Code changes during a Review:
  - Allowed when the change is squarely within the Review's scoped files and the fix is unambiguous.
  - Each change is recorded in the Review's deliverable (file, summary, commit SHA).
  - Out-of-scope changes require explicit user authorization (one chat round-trip).
  - Forensic-output-affecting changes (scoring math, finding shape, IOC dedup, parser normalization) are recorded as findings with proposed patches even if landed, so the human can audit before the next release.

---

## 7. Cross-Cutting Log

_Maintained across Reviews. Each entry: short tag, description, where discovered, where it'll be resolved._

| Tag | Description | Found in | Owner Review |
|---|---|---|---|
| `DRIFT-ENGINE-LINES` | `utils/deterministic_evidence_engine.py` is 1965 lines vs. 1610 reported in original master plan (+22%). Growth coincides with 7 already-landed `fix(scoring): ...` commits. | Review 0 validation | Review 1 |
| `DRIFT-OVERLAY-LINES` | Resolved in Review 9: `utils/pattern_overlay.py` growth reflects metadata-only overlay-context helpers and the post-detection `utils/ti/enrichment.py` attachment surface; live overlay behavior remains additive and does not feed `EvidencePackage.final_score()`. | Review 0 validation | Review 9 |
| `DRIFT-ROLLOUT-TODOS` | Resolved in Review 1: `_REFACTOR/scoring_2_0_rollout.plan.md` todo states now reflect live code (`schema`, `telemetry`, `measurement` completed; `engine`, `migrations` in progress; `cleanup` pending). | Review 0 validation | Review 1 |
| `DRIFT-TEST-COUNT` | Plan said 88 tests / 63 phase tests; actual is 93 / 63. Minor; new tests likely added during in-flight scoring work. | Review 0 validation | Review 2 |
| `DRIFT-ROUTE-COUNT` | Plan said ~26 routes; actual surface is 28 route modules plus package `__init__.py` (29 Python files total). Minor. | Review 0 validation | Review 7 |
| `GAP-V2-SEQUENCE-COVERAGE` | Resolved in post-Review 11 implementation follow-up: the live sequence definitions now declare sequence-specific required-source contracts, sequence evaluability now filters telemetry gaps to sources that actually matter to the configured chain, and Scoring 2.0 excludes sequence weight only when that required telemetry is missing instead of treating every configured sequence as generically evaluable. | Review 1 | Review 3 |
| `GAP-SCORE-DISPLAY-CONTRACT` | Resolved in post-Review 11 implementation follow-up: deterministic finding payloads and analysis formatter outputs now emit one shared `score_display` contract that carries compact score, emit eligibility, evaluable/excluded weight, coverage, and AI-adjustment presentation metadata, and the analysis results UI now consumes that shared payload instead of recomputing a separate display from raw Scoring 2.0 fields. | Review 1, Review 7b | Review 10 |
| `GAP-TI-AI-PROMPT-PATH` | Resolved in Review 9: task-side AI pattern analysis no longer injects OpenCTI ATT&CK context into `analyze_with_evidence()` before persistence; TI remains additive post-detection only. | Review 2a | Review 9 |
| `DRIFT-IOC-ROUTER-INSTRUMENTATION` | Resolved in Review 6: the IOC semantic/audit sub-stages now use `invoke_json(function='ioc_extraction', provider=provider, ...)` instead of direct `provider.generate_json(...)` calls, so the shared runtime path is preserved end to end. | Review 2b | Review 6 |
| `DRIFT-PROVENANCE-L1-FALLBACK` | Resolved in post-Review 11 implementation follow-up: `utils/chat/dispatch.py` now fails closed for successful data-bearing tool payloads that omit or emit invalid producer provenance, so the L1 tool runtime no longer silently falls back to policy provenance on those completed results. | Review 2b, Review 6 | Review 6 |
| `RISK-L1-TOOL-SCHEMA-VALIDATION` | Resolved in post-Review 11 implementation follow-up: chat runtime tool calls now validate decoded arguments against the declared `TOOL_DEFINITIONS` schemas before permission checks or execution, rejecting unknown keys and type-mismatched payloads as structured tool-call failures on both live model and approval-resume paths. | Review 6, Review 11 | Review 11 |
| `DRIFT-CASE-ANALYZER-FINALIZE` | Resolved in post-Review 11 implementation follow-up: terminal summary shaping, run finalization, and unified-findings mirroring now live in a dedicated `pipeline.case_finalize` boundary, leaving `utils/case_analyzer.py` as the orchestrator that decides final status and delegates the terminal persistence tail instead of owning that finalization block inline. | Review 2b, Review 8 | Review 10 |
| `DRIFT-DET-UTC-QUERY-COLUMN` | Resolved in post-Review 11 implementation follow-up: deterministic-engine coverage, runtime-executed check templates, burst, sequence, and spread SQL now execute against `COALESCE(timestamp_utc, timestamp)`, and anchor-derived helper windows prefer `timestamp_utc` when it is present. | Review 3a | Review 10 |
| `RISK-DET-SQL-PARAMETERIZATION` | Resolved in post-Review 11 implementation follow-up: `utils/candidate_extractor.py` now pushes case IDs, event IDs, time bounds, limits, and pattern-supplied `LIKE` fragments through named ClickHouse parameters with one shared literal-escaping boundary, so candidate extraction no longer interpolates those values directly into SQL. | Review 3a | Review 10 |
| `GAP-RAREST-ANCHOR-PIVOT` | Resolved in 2026-04-21 operational follow-up: the deterministic engine now uses event census counts to sort anchors by rarity before package pivoting, and focused regression coverage locks the rarest-anchor ordering contract. | Review 3a | Operational follow-up |
| `DRIFT-STATEFUL-DETECTOR-WINDOWS` | Resolved in post-Review 11 implementation follow-up: password-spraying and brute-force candidate queries now group inside their configured attack windows on `COALESCE(timestamp_utc, timestamp)`, and password-spraying successful-account evidence is scoped to the detected window instead of the full case. | Review 3b | Review 10 |
| `GAP-BEHAVIORAL-DETECTOR-INTEGRATION` | Review 3b verified that the anomaly stage still runs behavioral-anomaly detection, but only password-spraying/brute-force finding types are registered for deterministic-engine consumption. Behavioral-anomaly findings therefore never become deterministic checks or producer inputs. | Review 3b | Review 10 |
| `GAP-DET-NONDETERMINISTIC-WINDOW-FALLBACK` | Resolved in post-Review 11 implementation follow-up: `_compute_window()` now returns an explicit unknown-window state instead of substituting wall-clock time, and window-dependent query/sequence paths now yield deterministic inconclusive results when an anchor timestamp cannot be parsed. | Review 3b | Review 10 |
| `GAP-EVTX-FALLBACK-PARSER-CONTRACT` | Resolved in post-Review 11 implementation follow-up: `EvtxFallbackParser` now normalizes fallback `raw_json` onto flattened `EventData`, routes `IpAddress` through the shared IPv4-safe storage helper, and preserves non-IPv4 values in parser metadata so fallback-ingested EVTX matches the primary EVTX contract closely enough for deterministic consumers. | Review 4a | Review 10 |
| `DRIFT-MEMORY-PARSER-PROVENANCE-CONTRACT` | Partially progressed in post-Review 11 implementation follow-up: `parsers/memory_parser.py` now emits shared parser provenance metadata on ingest/plugin result envelopes and `models/memory_data.py` direct serializers now attach shared field/parser provenance to emitted memory records, but the memory family still bypasses `BaseParser` / `ParsedEvent` and does not persist parser provenance on the stored `memory_*` rows. | Review 4b | Review 8 |
| `DRIFT-IOC-SHORT-TAG-IDENTITY` | Resolved in Reviews 7a/7b as a route-surface concern: the reviewed hunt/chat/read surfaces only test `length(ioc_types) > 0` and do not currently treat `events.ioc_types` as canonical IOC identity. Revisit only if a later consumer starts depending on exact IOC-type identity from the event row. | Review 5, Review 7a, Review 7b | Review 7 |
| `GAP-CHAT-STREAM-METRICS` | Resolved in Review 10: `utils/ai/router.py` now records runtime/cache metrics for `stream_chat(...)` and attaches terminal/error runtime metadata so the primary chat runtime is no longer excluded from shared AI telemetry. | Review 6 | Review 10 |
| `DRIFT-HUNTING-TYPE-FILTER-SQL` | Resolved in Review 7b: the hunting live-grid and export-view routes now share one helper boundary for search/type/time filter construction, parameterize artifact types, and reject invalid alert/time filters with structured 400s instead of silently widening the read. | Review 7a, Review 7b | Review 7b |
| `DRIFT-LEGACY-UNIFIED-FINDINGS-ROUTE` | Resolved in post-Review 11 implementation follow-up: the live template callers now use the canonical `/api/findings/list/<case_uuid>` surface, and the legacy `/api/rag/unified-findings/<case_id>` compatibility wrapper has been retired from `routes/rag.py`. | Review 7b | Review 10 |
| `DRIFT-JSON-403-ERROR-SHAPE` | Resolved in post-Review 11 implementation follow-up: JSON API-side 403s now fail through one shared forbidden handler, and the remaining async task status/result endpoints in `routes/iocs.py`, `routes/rag.py`, `routes/parsing.py`, and `routes/hunting.py` now share one canonical async-status envelope helper instead of drifting by blueprint. | Review 7a | Review 10 |
| `RISK-VIEWER-WRITE-POLICY-DRIFT` | Resolved in post-Review 11 implementation follow-up: the remaining mutating or task-triggering case routes in `routes/analysis.py`, `routes/iocs.py`, `routes/known_users.py`, `routes/known_systems.py`, and `routes/case_files.py` now share one viewer-write guard so read-only users cannot start case analyses or mutate case-side state through those surfaces. | Review 7a, Review 11 | Review 11 |
| `BUG-DET-SEQUENCE-CHAIN-ORDER` | Resolved in post-Review 11 implementation follow-up: deterministic sequence validation now walks `before_anchor` steps backward from the anchor and `after_anchor` steps forward from the anchor, updating each branch from the previously matched event and scoping step queries to the active correlation fields instead of matching every step independently against the anchor with only `source_host` filtering. | Review 3b, Review 11 | Review 11 |
| `GAP-TASK-FAILURE-STATE-CONTRACT` | Resolved in post-Review 11 implementation follow-up: the remaining long-running/result-cached async entrypoints in `tasks/celery_tasks.py` and `tasks/rag_tasks.py` now preserve their existing failed progress/durable state writes where applicable and then raise instead of returning `{"success": false, ...}`, so broker-visible Celery state is authoritative across the reviewed async task surfaces. | Review 8 | Review 10 |
| `GAP-ASYNC-CANCELLATION-CONTRACT` | Resolved in post-Review 11 implementation follow-up: archive/memory now share cooperative cancellation with the remaining PCAP and case-analysis flows through explicit stop-point checks plus one shared async-cancellation token helper, and the corresponding route surfaces now request cancellation without hard worker termination so long-running tasks stop at clean stage boundaries instead of depending on revoke/kill semantics. | Review 8 | Review 10 |
| `DRIFT-UPLOAD-PREFLIGHT-HASH-CONTRACT` | Resolved in 2026-04-21 operational follow-up: case-upload preflight hashes are now keyed by stable queued-upload identity instead of bare filename, preflight hash failures are surfaced explicitly instead of silently falling back, and the upload progress UI now distinguishes archive preparation from final parser queueing so the visible stage better matches the backend work. | 2026-04-21 ingest audit | Operational follow-up |
| `DRIFT-IOC-INTERACTIVE-QUEUE-CONTRACT` | Resolved in 2026-04-21 operational follow-up: analyst-facing IOC extraction/tagging tasks now route to a dedicated `ioc` queue, the async route surface now tracks/access-controls those task IDs consistently, and the IOC UI now distinguishes queued-vs-running work instead of implying that nothing is happening while the task is still waiting behind ingest. | 2026-04-21 IOC responsiveness audit | Operational follow-up |
| `PERF-CLICKHOUSE-EVENT-MUTATION-PRESSURE` | Operational follow-up on 2026-04-21 completed the mutable event-tag remediation slices that fit the overlay pattern cleanly: analyst state, noise state, and IOC event tags now write to dedicated overlay tables and the main hunt/chat/RAG/deterministic read paths project effective state at read time instead of mutating `events`. Later 2026-04-21 follow-up then made the post-ingest dedup path skip very large destructive rewrites and report those skips truthfully, moved manual dedup off the request thread onto explicit async start/status contracts, surfaced the manual force-threshold gate at the route boundary with per-artifact details before queueing oversized dedup runs, made permanent case/client deletion plus case-wide PCAP rebuild wait for ClickHouse delete mutations before claiming completion, tightened the remaining PCAP destructive network-log paths so single-PCAP delete and PCAP log reindex also wait for `network_logs` delete mutations before reporting completion or reinserting rows, moved case-wide `network_logs` deletion onto a lower-rewrite partition-drop path before any mutation fallback, surfaced explicit 409 admission control for overlapping destructive PCAP network-log rewrites, serialized the remaining explicit case-wide `events` rewrites so delete/rebuild/dedup work no longer overlaps under load, made the remaining single-file / single-PCAP delete and rebuild-reset flows fail closed when the ClickHouse delete fails instead of dropping metadata anyway, made the remaining destructive case-delete and rebuild Celery task surfaces raise broker-visible failures instead of returning `{"success": false, ...}` inside successful task results, made case-wide PCAP rebuild preflight retained originals before deleting indexed state and abort before reingest when the final case-level `network_logs` cleanup fails, and finally made parser-side partial-row cleanup wait for the file-scoped delete mutation before surfacing parse failure. The remaining open ClickHouse risk is now mostly the underlying operational cost of the remaining explicit destructive `events` and artifact-scoped `network_logs` `ALTER TABLE ... DELETE` rewrites, not misleading completion semantics. | 2026-04-21 ClickHouse audit | Operational follow-up |
| `DRIFT-OPENCTI-CONNECTOR-CACHE-FRESHNESS` | Resolved in Review 10: `utils/opencti.py` now bounds the active connector catalog cache with a TTL, so admin/status and IOC-hint surfaces refresh without worker restart. | Review 9 | Review 10 |
| `GAP-THREAT-INTEL-CONTEXT-CACHING` | Resolved in Review 10: `utils/threat_intel_context.py` now memoizes prompt-scope IOC lookups and skips redundant generic exact-lookups for CVEs before the dedicated vulnerability-context fetch. | Review 9 | Review 10 |
| `DEAD-UNIFIED-FINDINGS-LEGACY-READERS` | Resolved in Review 10: `utils/unified_findings.py` had already become store-backed only, but still carried unreachable in-module System 1/2/3 readers and their imports. Review 10 removed that dead compatibility code while preserving the current response shape. | Review 10 | Review 10 |
| `TEST-SOURCE-TEXT-GUARDRAILS` | Review 10 found that multiple refactor-era regression suites still assert source text, helper names, or decorator stacking (`tests/test_phase3_route_decomposition.py`, `tests/test_case_analysis_pipeline.py`, `tests/test_phase7_pattern_task_execution_stage.py`, `tests/test_route_security_regressions.py`) instead of behavior, making harmless cleanup fail tests. | Review 10 | Review 11 |

---

## 8. Decisions Log

_Records decisions made during review that affect subsequent Reviews._

| Date | Decision | Rationale | Affects |
|---|---|---|---|
| 2026-04-20 | Reframe from generic code review to (a) Scoring 2.0 planning, (b) refactor verification, (c) correctness review. | The refactor is ~95% complete. A generic review would duplicate prior work. | All Reviews |
| 2026-04-20 | Original draft: Reviewer does not make code changes; findings + proposed patches only. | User retains control of what lands. | Superseded 2026-04-20 (see below) |
| 2026-04-20 | Adapt master plan for Cursor (replaces claude.ai assumptions). Deliverables land in `_REVIEW/`, master MD edited in-place between Reviews, "expected chat size" is guidance only. | Work is being done in Cursor against the live repo. | Sections 6, 11; all Reviews |
| 2026-04-20 | Rename master units "Phase N" → "Review N"; reserve "Refactor Phase N" for the prior workstream and "Rollout Step N" for Scoring 2.0 internal stages. | Three concentric Phase namespaces caused ambiguity in scope text and deliverable filenames. | All Reviews; deliverable filenames now follow the Review label (`REVIEW1_*.md`, `REVIEW2A_*.md`, etc.) |
| 2026-04-20 | Reviewer is authorized to make code changes during a Review when (a) the user has said "do Review N" and (b) the change is in-scope. Out-of-scope changes still require explicit per-change authorization. Every change must be recorded in the Review deliverable with a commit SHA. | User explicitly authorized this model and prefers end-to-end execution per Review. | All Reviews |
| 2026-04-20 | Insert a "Pre-flight" subsection inside Review 1 (rather than a separate Review 0.5) to verify the foundations Scoring 2.0 builds on before reviewing the rollout plan. | Avoids the Review 1 / Review 2 ordering inversion without bloating the plan. | Review 1 |
| 2026-04-20 | Each Review is its own Cursor chat to keep per-session context low. Hand-off is required at the end of each Review. | User preference for low-context sessions. | All Reviews; Section 6 step 10 |
| 2026-04-20 | Pre-split oversized Reviews into explicit suffixed subreviews (`2a/2b`, `3a/3b`, `4a/4b`, `7a/7b`) instead of deciding ad hoc mid-session. | Keeps each chat mapped to one concrete section and reduces scope drift. | Review plan, deliverable index, session kickoff instructions |
| 2026-04-20 | Default to local commits for Review checkpoints; push only when explicitly requested by the user. | Matches the current working agreement and avoids unwanted remote-side effects between review sessions. | Section 6 step 9; Section 11 kickoff and hand-off expectations |
| 2026-04-20 | Review 1 reconciled Scoring 2.0 rollout state to the live repo: `schema`, `telemetry`, and `measurement` are completed; `engine` and `migrations` are in progress; `cleanup` remains pending. | The rollout YAML had drifted far enough from the code that the review plan's own pre-flight assumptions were wrong until corrected. | Review 1, Review 2b |
| 2026-04-20 | Review 1 landed a Scoring 2.0 spread-reconciliation fix so spread bonuses update 2.0 package weights and score-threshold emit state consistently. | `pass_the_ticket` is already a migrated 2.0 pattern and also uses spread scoring, so stale metadata would have made package state internally inconsistent. | Review 1, Review 3 |
| 2026-04-20 | Treat the remaining OpenCTI context injection into task-side AI pattern-analysis prompts as Review 2a Phase 4b drift owned by Review 9, not as proof that deterministic overlay mutation regressed. | The deterministic hot path is overlay-free, but TI still enters one pre-persistence AI producer path and should be revisited during the dedicated enrichment/TI review. | Review 2a, Review 9 |
| 2026-04-20 | Review 4a verified that the EVTX / dissect / Windows / registry parser families still populate `timestamp_utc` through the base parser contract; the remaining UTC-normalized query-column drift stays owned by downstream consumer/query code, not these parser surfaces. | Review 3's timezone issue remained important to verify at the parser boundary before continuing the parser review, and the live repo shows the drift is downstream of ingestion for these families. | Review 4b, Review 10 |
| 2026-04-20 | Review 4b verified that the browser / log / vendor event parsers still populate `timestamp_utc` through the base parser contract, while the memory parser remains a separate non-`ParsedEvent` ingest path whose provenance contract is still open. | Keeps Review 3's UTC thread scoped to downstream query consumers for event parsers while explicitly flagging the memory-family exception for later pipeline review. | Review 5, Review 8, Review 10 |
| 2026-04-20 | Review 5 verified that the semantic IOC path remains deterministic-first and additive, but `pipeline_mode='audit'` currently applies validated AI deltas directly onto the deterministic extraction and should be treated as authoritative over the returned IOC candidate set until a preserved overlay/original-output contract exists. Post-Review 11 follow-up closed that gap by preserving the deterministic extraction and accepted audit overlay metadata alongside the audited IOC view returned to consumers. | Future reviews should now treat IOC audit mode as deterministic-first with an explicit additive overlay contract rather than assuming the detector-of-record output is overwritten without trace. | Review 6, Review 7, Review 11 |
| 2026-04-20 | Keep `/api/rag/unified-findings/<case_id>` as a compatibility wrapper over the canonical findings serializer until live callers migrate to `/api/findings/list/<case_uuid>`. | Review 7b verified that the canonical findings route is registered, but the live hunting UI still targets the legacy RAG endpoint. Sharing the serializer removes read-shape drift without taking an out-of-scope template migration in the same Review. | Review 7b, Review 10 |
| 2026-04-20 | Treat `case_analysis_runs.summary.phase_outcomes` as the authoritative degraded/partial contract for long-running case analysis. Any stage that can fail while the overall run continues must record an explicit failed phase outcome instead of relying on warning logs alone. | Review 8 found that per-pattern failures and IOC timeline failures could complete with a superficially clean final status until the phase-outcome bookkeeping was tightened. | Review 8, Review 10, Review 11 |
| 2026-04-20 | Treat all Review 9 threat-intel context injected into persisted pattern findings as non-authoritative. OpenCTI/MISP context may still inform post-detection overlays and narrative/report prompts, but it must not enter `analyze_with_evidence()` on the task-side persistence path. | Review 9 re-verified that the last remaining task-side OpenCTI ATT&CK prompt injection path still affected persisted AI-adjusted finding confidence, which violates the additive-only TI contract. | Review 9, Review 10, Review 11 |
| 2026-04-20 | Treat `utils/unified_findings.py` as a store-backed-only reader and remove unreachable in-module System 1/2/3 readers rather than preserving dead compatibility code. | Review 10 verified that the live route surface already depends on the ClickHouse mirror; the leftover reader helpers only kept dead imports and brittle tests alive. | Review 10, Review 11 |
| 2026-04-20 | Treat streamed chat calls as part of the shared AI runtime telemetry contract. | Review 10 added runtime metrics to `stream_chat(...)`, closing the last major observability gap in the Phase 6 shared router. | Review 10, Review 11 |
| 2026-04-20 | Treat `_REVIEW/REVIEW11_FINAL_BACKLOG.md` as the authoritative ranked backlog for unresolved review findings; Section 7 remains the historical discovery log, and `docs/refactor/file_audit.md` should only claim live closure where the Review 11 backlog says the work is closed. | Review 11 consolidated several still-open findings that were previously scattered across individual deliverables or omitted from the cross-cutting log. | Post-review implementation planning, `docs/refactor/file_audit.md`, Section 7 |
| 2026-04-20 | Treat the deterministic UTC query-column drift as resolved once the engine executes both its direct SQL and runtime-normalized check templates against `COALESCE(timestamp_utc, timestamp)` and prefers `timestamp_utc` when anchor helpers derive query windows. | Post-Review 11 implementation closed the documented timezone/query contract drift without needing to rewrite every static query template literal individually, while still making the executed deterministic SQL match the product contract. | Review 10, Review 11, `docs/refactor/file_audit.md` |
| 2026-04-21 | Treat case-upload preflight hashes as keyed per queued upload entry rather than bare filename, and treat archive preparation plus parser queueing as distinct user-visible upload stages. | The upload UI can legitimately queue same-name files and the backend can reuse preflight hashes only when the lookup key survives that ambiguity. Surfacing preflight hash failures and clarifying stage labels reduces false "extract is stuck" reports when the backend is still hashing or finalizing. | Operational follow-up, upload/ingest surfaces |
| 2026-04-21 | Treat analyst-facing IOC extraction and tagging as interactive work that should route to the dedicated `ioc` queue and expose queued-vs-running task state explicitly. | The default queue lets large parsing backlogs bury IOC work, and the old route/UI contract made queued IOC tasks look idle rather than backlogged. | Operational follow-up, IOC routes/tasks/UI |
| 2026-04-21 | Treat analyst event tagging as mutable overlay state stored beside `events`, not as in-place row mutation. | Analyst tags are sparse, user-driven state with stable event selectors and are the least risky first slice for reducing ClickHouse mutation pressure before tackling the heavier noise and IOC workflows. | Operational follow-up, hunting/AI analyst-tagged surfaces |
| 2026-04-21 | Treat mutable noise state and IOC event tags as overlay-backed read-time projections, and treat delete/rebuild/dedup task completion as truthful only when the corresponding ClickHouse delete mutation has either completed or been explicitly reported as still pending. | This operational follow-up finished the remaining append-heavy mutable tagging slices without replacing ClickHouse, while tightening the most misleading delete/rebuild semantics so future work can focus on the still-open destructive-delete rewrite risk rather than row-update backlog pressure. | Operational follow-up, hunting/IOC/tasks/ClickHouse safety |
| 2026-04-21 | Treat automatic post-ingest deduplication as best-effort cleanup with an explicit safety ceiling, not as an unconditional destructive rewrite. | Large duplicate-pruning mutations can be more operationally dangerous than leaving duplicates in place temporarily; the automatic path should skip over-threshold artifact groups and report that truthfully, while explicit/manual dedup remains the operator-controlled escape hatch until a safer redesign exists. | Operational follow-up, case ingest completion, ClickHouse safety |
| 2026-04-21 | Treat explicit duplicate removal and permanent case/client deletion as long-running destructive workflows that must either run asynchronously with status tracking or wait for the relevant ClickHouse mutations before reporting success. | Manual dedup no longer belongs on the request thread, and synchronous permanent deletion cannot truthfully claim the case is gone while the ClickHouse delete is still mutating in the background. | Operational follow-up, case files routes, admin delete flows, PCAP rebuilds |
| 2026-04-21 | Treat single-PCAP delete and PCAP log reindex as destructive `network_logs` workflows that must wait for the underlying delete mutation before deleting metadata or reinserting rows. | The remaining PCAP route/task paths could still claim success or start reindexing while the old network-log rows were mid-mutation, which preserved misleading completion semantics and risked overlap under load. | Operational follow-up, PCAP routes/tasks, ClickHouse safety |
| 2026-04-21 | Treat explicit case-wide `events` rewrites as globally serialized work: delete, rebuild reset, and dedup should not overlap, and the async case-delete surface should complete only after the mutation is done. | Once completion semantics were truthful, the remaining production risk was concurrent destructive rewrites themselves under load. Admission control plus truthful async completion reduces overlap without replacing ClickHouse. | Operational follow-up, parsing routes, case file routes, Celery tasks, ClickHouse safety |
| 2026-04-21 | Treat destructive single-file and single-PCAP reset/delete flows as fail-closed when the ClickHouse delete cannot be completed. | Logging and continuing after a ClickHouse delete failure can strand analytical rows while the app deletes metadata and disk state, so the remaining artifact-scoped destructive paths now abort before metadata deletion on that failure mode. | Operational follow-up, case file routes, PCAP routes, rebuild helpers, ClickHouse safety |
| 2026-04-21 | Treat parser-side partial-row cleanup as truthful only once the file-scoped ClickHouse delete mutation has completed. | Failed ingests should not surface an error state while partial event rows are still pending deletion, so parser cleanup now waits for the file-scoped mutation before returning the parse failure result. | Operational follow-up, parser registry, ClickHouse safety |
| 2026-04-21 | Treat case-wide `network_logs` deletion as partition-oriented maintenance and treat destructive PCAP `network_logs` rewrites as explicitly admitted work. | The table is already partitioned by `(case_id, log_type)`, so case-wide wipes should prefer cheap partition drops before any fallback mutation, and remaining artifact-scoped rewrites should fail fast with operator-visible conflict context instead of stacking destructive work. | Operational follow-up, `models/network_log.py`, `routes/pcap.py`, ClickHouse safety |
| 2026-04-21 | Treat the manual dedup safety ceiling as an admission-control decision, not just an async task outcome. | If the route already knows the targeted artifact families exceed the manual destructive-rewrite threshold, the operator should get that force-required decision immediately with concrete artifact counts rather than waiting for a queued task to report the same gate later. | Operational follow-up, `routes/case_files.py`, `utils/event_deduplication.py`, ClickHouse safety |
| 2026-04-21 | Treat destructive case-delete and rebuild task failures as broker-authoritative task failures, not successful task completions carrying `success: false` payloads. | These workflows are already async and operator-visible; if a ClickHouse delete or retained-original precondition fails, the task state itself must fail so status surfaces do not report a dangerous destructive workflow as completed. | Operational follow-up, `tasks/celery_tasks.py`, `tasks/pcap_tasks.py`, ClickHouse safety |
| 2026-04-21 | Treat case-wide PCAP rebuild as a preflighted destructive workflow: verify retained originals first, then require the final case-level `network_logs` cleanup to succeed before reingest. | Deleting derived PCAP state before proving rebuild input exists can turn a rebuild request into accidental data destruction, and best-effort orphan cleanup can otherwise allow stale rows to survive into the rebuilt case. | Operational follow-up, `tasks/pcap_tasks.py`, ClickHouse safety |
| 2026-04-21 | Treat the Review 11 backlog as stale until rechecked against live code before starting a new non-ClickHouse slice. | The remaining backlog still listed three already-landed fixes (`CORRECTNESS-OFF-HOURS-CASE-TZ`, `BUG-HAYABUSA-RECORDID-ENRICHMENT-COLLAPSE`, `CORRECTNESS-GAP-RESULT-IP-SCOPING`); syncing the review docs avoids wasting future sessions on already-covered paths. | Operational follow-up, `_REVIEW/REVIEW11_FINAL_BACKLOG.md` |
| 2026-04-21 | Treat `tasks/rag_tasks.py` helper-delegation contracts as runtime behavior, not source-text. | The Phase 7 task-delegation regressions are more durable when they execute `ai_pattern_correlation(...)` against stubbed shared helpers than when they grep for import lines or helper names in the source file. | Operational follow-up, `tests/test_phase7_pattern_*_stage.py`, `tasks/rag_tasks.py` |
| 2026-04-21 | Treat rarest-anchor pivoting and IOC defang/path normalization as resolved shared contracts, not open backlog design notes. | The deterministic core already uses census rarity to choose the best package anchor, and the IOC stack already routes defang/path cleanup through `utils/ioc_text.py`; the remaining work was to lock those contracts with behavioral tests and sync the backlog. | Operational follow-up, `utils/deterministic_evidence_engine.py`, `utils/ioc_text.py`, IOC/deterministic tests |
| 2026-04-21 | Treat IOC merge/text regression contracts as wrapper behavior and exported boundary, not source-file text. | The Phase 5 IOC tests are stronger when they patch `_ioc_merge` / `_ioc_text` and assert wrapper outputs plus `__all__` than when they grep `utils/ioc_extractor.py` for exact return statements or symbol lists. | Operational follow-up, `tests/test_phase5_ioc_*_contract.py`, `utils/ioc_extractor.py` |
| 2026-04-21 | Treat IOC alias generation as its own helper boundary even while the broader extractor facade remains open. | File-path and command-line alias derivation is cohesive logic that can move behind a shared helper without changing the public `generate_ioc_with_aliases(...)` API, giving the facade item a safe first extraction step before touching import/persistence workflows. | Operational follow-up, `utils/ioc_aliasing.py`, `utils/ioc_extractor.py` |

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
- **Review** (in this plan) — A unit of work in this master plan; one per Cursor chat session.
- **Refactor Phase** — A unit of work in the prior refactor effort (`_REFACTOR/master-goals-and-workstreams.plan.md`).
- **Rollout Step** — A unit of work inside the Scoring 2.0 rollout (`_REFACTOR/scoring_2_0_rollout.plan.md` internal Phase 0–5).

---

## 10. Index of Review Deliverables

_Populated as Reviews complete._

| Review | File | Status |
|---|---|---|
| 0 | `CASESCOPE_REVIEW_MASTER.md` (this file) | Complete |
| 1 | `REVIEW1_SCORING_2_0.md` | Complete |
| 2a | `REVIEW2A_REFACTOR_VERIFICATION.md` | Complete |
| 2b | `REVIEW2B_REFACTOR_VERIFICATION.md` | Complete |
| 3a | `REVIEW3A_DETERMINISTIC_CORE.md` | Complete |
| 3b | `REVIEW3B_DETERMINISTIC_CORE.md` | Complete |
| 4a | `REVIEW4A_PARSERS.md` | Complete |
| 4b | `REVIEW4B_PARSERS.md` | Complete |
| 5 | `REVIEW5_IOC.md` | Complete |
| 6 | `REVIEW6_AI_RUNTIME.md` | Complete |
| 7a | `REVIEW7A_ROUTES.md` | Complete |
| 7b | `REVIEW7B_ROUTES.md` | Complete |
| 8 | `REVIEW8_TASKS_AND_PIPELINE.md` | Complete |
| 9 | `REVIEW9_ENRICHMENT.md` | Complete |
| 10 | `REVIEW10_CROSS_CUTTING_AND_DEAD_CODE.md` | Complete |
| 11 | `REVIEW11_FINAL_BACKLOG.md` | Complete |

---

## 11. How To Start A Review Session

In Cursor, with the workspace at `/opt/casescope` on `main`:

1. Open a new Cursor chat.
2. Say: `do Review N` or `do Review Na/Nb` (e.g., `do Review 1`, `do Review 2a`).
3. The Reviewer will:
   - Read this master MD and the prior Review's deliverable(s).
   - Execute that exact Review/subreview per the scope above.
   - Produce the deliverable named for that exact Review/subreview in Section 10.
   - Update Sections 7, 8, 10 of this master MD.
   - Commit locally, and push only if explicitly requested.
   - Hand off in chat with what was done, what changed (with commit SHAs), and what's outstanding.

That's the entire kickoff. The Reviewer will only stop mid-Review for genuine ambiguity that would change the deliverable's correctness; otherwise it runs end-to-end.
