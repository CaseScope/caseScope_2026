---
name: Scoring 2.0 Rollout
overview: "Implement Scoring 2.0 for deterministic evidence evaluation by adding explicit eligibility semantics, zero-contribution missing-telemetry handling, coverage-gap reporting, compatibility-safe rollout paths, and the telemetry needed to prove the new model reduces analyst-facing false positives."
todos:
  - id: scoring-schema
    content: Add Scoring 2.0 schema defaults and payload metadata without changing live scoring behavior.
    status: pending
  - id: scoring-telemetry
    content: Add structured scoring and AI-adjustment telemetry so the Phase 0 ranking artifact can be produced from logs alone.
    status: pending
  - id: scoring-engine
    content: Implement dual-path deterministic scoring with explicit coverage policy, emit eligibility, and rollback control.
    status: pending
  - id: scoring-measurement
    content: Run the Phase 0 baseline, publish the ranking artifact, and hold the migration gate until the artifact is approved.
    status: pending
  - id: scoring-migrations
    content: Migrate the first approved patterns to Scoring 2.0 semantics and validate improvement against the baseline.
    status: pending
  - id: scoring-cleanup
    content: Retire the legacy scoring path in 2.1 after all targeted patterns are migrated and compatibility is no longer needed.
    status: pending
isProject: false
---

# Scoring 2.0 Rollout Plan

## Objective
Ship a compatibility-safe scoring overhaul for the deterministic evidence pipeline so missing telemetry no longer inflates scores, ambient anchors do not emit findings without corroboration, and scoring behavior is explicit, measurable, and auditable.

## Scope
In scope:
- Add Scoring 2.0 fields to deterministic check, result, evidence-package, and pattern-config contracts.
- Add structured telemetry for deterministic scores, excluded weight, emit eligibility, AI adjustments, and suppression outcomes.
- Implement dual-path scoring in the deterministic evidence engine with a runtime rollback switch.
- Separate `deterministic_score` from `eligible_to_emit` and thread both through materialization.
- Add compact score presentation and coverage-gap metadata to the LLM-facing and analyst-facing payload contracts.
- Add compatibility, fixture, emit-eligibility, telemetry, and materialization tests.
- Migrate approved patterns after the Phase 0 ranking artifact is produced and reviewed.

Out of scope for the initial rollout:
- No bulk candidate-extraction behavior changes beyond adding anchor metadata for explainability.
- No large prompt rewrite, model swap, or new LLM call path.
- No historical re-scoring or retroactive mutation of prior findings.
- No broad suppression-rule expansion before structural fixes are measured.
- No pattern-by-pattern retuning before the measurement gate approves the first migration set.

## Design Invariants
- Missing telemetry is not evidence.
- Score calculation and emit eligibility are separate decisions.
- Suppression is only for overlap between valid patterns, never for gating or missing data.
- If `lateral` is in a pattern name, a lateral signal must be required for emit eligibility.
- Anchor detail text must describe the specific trigger evidence that fired, not only the canonical pattern label.
- Telemetry is a contract: the Phase 0 ranking artifact must be producible from logs alone.

## Scoring 2.0 Contract
Check-level additions:
- `disqualifier: bool = False`
- `required_pass: bool = False`
- `coverage_policy: "inherit" | "zero" | "exclude" | "fail" = "inherit"`
- `role: "anchor" | "evidence" | "corroboration" | "gate" | "context" = "evidence"`

Package-level additions:
- `eligible_to_emit: bool`
- `emit_block_reasons: list[str]`
- `scoring_version: str`
- `scoring_changes: list[str]`
- `evaluable_weight: float`
- `excluded_weight: float`
- `raw_total_weight: float`
- `coverage_gap_present: bool`

Pattern-config additions:
- `required_check_ids: list[str]`
- `required_pass_count: int`
- `emit_threshold_mode: "score_only" | "score_and_required" | "required_only"`
- `allow_anchor_only_emit: bool`
- `scoring_version: str`

Migration rule:
- Patterns without `scoring_version: "2.0"` remain on the legacy path until explicitly reviewed.
- Patterns tagged `scoring_version: "2.0"` are treated as reviewed even if they do not use every new field.

## Coverage Policy Defaults
- `anchor_match`: contribute when the anchor exists; no missing-telemetry fallback.
- `field_match`: default `zero`.
- `threshold`: default `zero`.
- `graduated`: default `zero`.
- `absence_with_coverage`: default `zero`.
- `burst`: default `exclude` when not evaluable, `FAIL` when evaluable but not present.
- `sequence`: default `exclude` when not evaluable, `FAIL` when evaluable but not present.

Analyst and LLM score display:
- `Score: 67/80 evaluable (20 excluded: Sysmon missing)`

## Target Files
Primary implementation surfaces:
- `utils/pattern_check_definitions.py`
- `utils/pattern_event_mappings.py`
- `utils/deterministic_evidence_engine.py`
- `utils/finding_contract.py`
- `pipeline/pattern_analysis.py`
- `utils/candidate_extractor.py`
- `utils/ai_correlation_analyzer.py`
- `utils/pattern_suppression.py`

Telemetry surface:
- `utils/hunting_logger.py` or a new `utils/scoring_telemetry.py`

Tests:
- `tests/test_scoring_2_engine_fixtures.py`
- `tests/test_scoring_2_emit_eligibility.py`
- `tests/test_scoring_2_compat.py`
- `tests/test_scoring_2_telemetry.py`
- `tests/test_scoring_2_materialization_contract.py`

## Sequence
### Phase 1: Schema and telemetry
- Add schema defaults with no behavior change.
- Add scoring telemetry and deterministic rationale tagging for benign explanations such as machine account, DC replication, admin workflow, expected system behavior, and missing telemetry.
- Add a runtime flag that can force legacy scoring regardless of pattern tagging.
- Add telemetry-contract tests.

Definition of done:
- The ranking artifact can be generated from logs alone without ad-hoc SQL.

### Phase 2: Dual-path engine and contracts
- Add legacy and Scoring 2.0 scoring helpers in the deterministic evidence engine.
- Implement explicit coverage handling, evaluable versus excluded weight, required-pass semantics, and disqualifier semantics.
- Thread `eligible_to_emit`, `emit_block_reasons`, scoring metadata, and coverage-gap fields through finding contract and pattern materialization.
- Require actual anchor detail summaries for 2.0 anchor checks and fail loudly in development when they are missing.

### Phase 3: Baseline and gate review
- Capture baseline telemetry for at least one measurement window before any pattern migration.
- Publish a written ranking artifact listing volume, strong downrank rate, suppression rate, and analyst outcome correlation where available.
- Use that artifact to decide the first migration wave.

Patterns expected to need early migration review:
- `pass_the_ticket`
- `backup_operator_abuse`
- `rdp_lateral`
- `wmi_lateral`
- `dcom_lateral_movement`
- `scheduled_task_persistence`
- `service_persistence`
- `local_group_discovery`
- `domain_group_discovery`
- `network_scanning`

### Phase 4: First migration wave
- Migrate only the first approved patterns to `scoring_version: "2.0"`.
- Add engine fixtures for high-specificity, ambient-anchor-with-corroboration, and missing-telemetry cases.
- Compare post-change telemetry to baseline before expanding the migration set.

### Phase 5: Completion and retirement
- Continue pattern migration until the targeted set is complete.
- Mark the legacy path deprecated in `2.0`.
- Remove the legacy path in `2.1` and fail CI if a supported pattern still lacks `scoring_version: "2.0"`.

## Acceptance Criteria
- No `INCONCLUSIVE` check contributes positive score in Scoring 2.0 unless explicitly overridden by policy.
- Scoring payloads expose `deterministic_score`, `eligible_to_emit`, `emit_block_reasons`, `evaluable_weight`, `excluded_weight`, and `coverage_gap_present`.
- The top-10 strong downrank rate, defined as `ai_adjustment <= -15`, drops by at least 50 percent after the first migration wave compared to baseline.
- Benign-rationale tags for machine-account, DC-replication, and admin-workflow explanations drop by at least 40 percent on the migrated top patterns compared to baseline.
- The rollback flag successfully forces legacy scoring without a code deploy.
- Legacy scoring remains fully functional and tested until Bucket A migration is complete.

## Rollback
- Provide a runtime feature flag or configuration switch that forces legacy scoring for all patterns.
- Verify rollback behavior in staging before enabling the first `2.0` pattern.
- If migrated patterns produce materially worse telemetry or finding volume than baseline, use the runtime switch first and investigate before additional migrations.

## Deliverables
- Repo-backed Scoring 2.0 spec, implementation map, and engineer handoff packet.
- This rollout plan as the execution artifact.
- Phase 0 ranking artifact generated from structured logs.
- Scoring 2.0 telemetry contract and fixture suite.
- Versioned scoring metadata on materialized results for downstream UI consumption.
