# Review 1 — Scoring 2.0 Design Review and Implementation Audit

Date: 2026-04-20

## Scope
Review `_REFACTOR/scoring_2_0_rollout.plan.md` against live Scoring 2.0 code, reconcile plan state vs. implementation state, validate the rollout invariants against the current engine/contracts/tests, and land any unambiguous in-scope fixes.

## Pre-flight Results
### Foundations verified
- `utils/deterministic_evidence_engine.py`
  - `_run_checks(self, check_defs, params, coverage, gap_results)`
  - `_validate_sequences(self, pattern_id, params)`
  - `_compute_score(self, checks, bursts, sequences)`
- `utils/finding_contract.py` already threads Scoring 2.0 materialization fields through finalization and artifact building.
- `routes/findings.py` is wired into the app registration path.
- `utils/ai/router.py` callers already include `utils/ai_correlation_analyzer.py`, `utils/ai_review.py`, `utils/ai_report_generator.py`, `utils/ai_timeline_generator.py`, `utils/ai_event_summary.py`, `utils/ai_checkpoints.py`, `utils/chat_agent.py`, `utils/ioc_extractor.py`, `utils/rag_llm.py`, and `routes/rag.py`.
- `docs/refactor/pattern_check_inventory.csv` now matches the live registry at 42 patterns / 247 checks after regeneration from source.

### Package / contract state
- `utils/pattern_check_definitions.py`
  - `EvidencePackage` already carries `deterministic_score`, `eligible_to_emit`, `emit_block_reasons`, `anchor_class`, `scoring_version`, `scoring_changes`, `evaluable_weight`, `excluded_weight`, `raw_total_weight`, and `coverage_gap_present`.
- `utils/pattern_event_mappings.py`
  - materializes `anchor_class`, `required_check_ids`, `required_pass_count`, `emit_threshold_mode`, `allow_anchor_only_emit`, and `scoring_version`.
- `utils/finding_contract.py`
  - preserves `deterministic_score`
  - respects `eligible_to_emit` / `emit_block_reasons` for `scoring_version == "2.0"`
- `pipeline/pattern_analysis.py`
  - threads `eligible_to_emit`, `emit_block_reasons`, `anchor_class`, `scoring_version`, `evaluable_weight`, `excluded_weight`, `raw_total_weight`, and `coverage_gap_present`
  - emits structured scoring telemetry

## Reconciled Rollout Todo Status
The rollout YAML was stale. Actual state after Review 1:

| Todo | Plan status before review | Actual status | Evidence |
|---|---|---|---|
| `scoring-schema` | `pending` | `completed` | `EvidencePackage` fields exist; pattern materialization defaults/validation exist; contract-surface tests exist. |
| `scoring-telemetry` | `pending` | `completed` | `utils/scoring_telemetry.py`, telemetry emission in `pipeline/pattern_analysis.py`, baseline artifact loader/generator, telemetry tests. |
| `scoring-engine` | `pending` | `in_progress` | dual-path engine exists, rollback flag exists, 2.0 emit eligibility exists, but full parity is incomplete; only two patterns are migrated and sequence/spread edge semantics still required review. |
| `scoring-measurement` | `pending` | `completed` | baseline artifacts exist for cases 107 and 135; generator script builds artifacts from structured logs. |
| `scoring-migrations` | `pending` | `in_progress` | only `pass_the_ticket` and `token_manipulation` are on `scoring_version: "2.0"`. |
| `scoring-cleanup` | `pending` | `pending` | legacy path remains active and rollback-safe, as intended. |

## Design Invariants
| Invariant | Status | Notes |
|---|---|---|
| Missing telemetry is not evidence. | Partial | Check-level 2.0 handling exists for `INCONCLUSIVE` results and `exclude`/`zero` policies; sequence handling is still not coverage-aware. |
| Score calculation and emit eligibility are separate decisions. | Validated | `deterministic_score` and `eligible_to_emit` are distinct in engine, package, finalization, telemetry, and materialization. |
| Suppression is only for overlap between valid patterns, never for gating or missing data. | Validated | suppression is post-package bookkeeping in `pipeline/pattern_analysis.py` / `utils/pattern_suppression.py`; it is not used to explain missing telemetry. |
| `anchor_class` defaults drive anchor-only emit semantics. | Validated | materialization derives `allow_anchor_only_emit` from `anchor_class`; tests cover definitive/gateway/seed defaults. |
| Scoring 2.0 patterns must declare `anchor_class`. | Validated | enforced in pattern-materialization helpers and `_validate_anchor_class_for_scoring_v2()`. |
| Lateral patterns require lateral signal for emit. | Validated | `_compute_score_v2()` adds `missing_lateral_signal` when needed. |
| Anchor detail must describe actual trigger evidence. | Validated | `_validate_anchor_detail_for_scoring_v2()` rejects generic `"anchor matched"` detail; tests exist. |
| Telemetry is a contract and must support baseline artifacts from logs alone. | Mostly validated | telemetry emission and artifact generation are in place; analyst verdict enrichment still comes from DB, but the ranking artifact itself is derivable from logs. |

## Findings
### 1. `CORRECTNESS` / `HIGH`
- Location: `utils/deterministic_evidence_engine.py`
- Summary: Spread bonuses were applied after Scoring 2.0 package construction without reconciling `evaluable_weight`, `raw_total_weight`, `max_possible_score`, or score-based emit-block state.
- Why it matters: `pass_the_ticket` is already a migrated 2.0 pattern and also has spread scoring. A spread bonus could increase `deterministic_score` while leaving the package’s 2.0 metadata stale, making telemetry and materialized package state internally inconsistent.
- Proposed fix: Landed in this Review in `cab9948a`. Spread reconciliation now updates 2.0 weight metadata and clears only the stale `score_below_emit_threshold` block when the bonus moves the package across the threshold. Rough effort: S.

### 2. `GAP` / `HIGH`
- Location: `utils/deterministic_evidence_engine.py`
- Summary: Sequence handling is still effectively legacy-shaped. Sequence contribution is always counted as evaluable once a sequence config exists, and there is no explicit 2.0 exclude-vs-fail path for “not evaluable because telemetry is missing.”
- Why it matters: The rollout plan explicitly calls out sequence coverage semantics. Current code would misstate evaluable vs. excluded weight for any migrated pattern that depends on sequence logic under partial telemetry.
- Proposed fix: add explicit 2.0-aware sequence evaluation states and tests before migrating any sequence-dependent pattern. Rough effort: M.

### 3. `DRIFT` / `MEDIUM`
- Location: `_REFACTOR/scoring_2_0_rollout.plan.md`
- Summary: The todo block still marked every rollout step as `pending` even though schema, telemetry, measurement, and part of the engine/migration surface are already landed.
- Why it matters: Review 1 pre-flight assumptions were wrong until this was reconciled. Leaving the YAML stale would mislead future sessions.
- Proposed fix: Landed in this Review in `cab9948a` by updating the todo statuses to `completed` / `in_progress` / `pending` to match live code. Rough effort: S.

### 4. `DRIFT` / `MEDIUM`
- Location: `tests/`
- Summary: The rollout plan names `test_scoring_2_compat.py` and `test_scoring_2_materialization_contract.py`, but those exact files do not exist. Equivalent coverage currently lives in `test_phase1_contract_surfaces.py` and `test_phase7_pattern_materialization_stage.py`.
- Why it matters: The plan’s test map no longer matches the repo, which makes future verification noisier than it needs to be.
- Proposed fix: Landed in this Review in `cab9948a` by updating the rollout plan’s test list to the live filenames. Rough effort: S.

### 5. `GAP` / `MEDIUM`
- Location: `utils/ai_correlation_analyzer.py` and analyst-facing/LLM-facing payload surfaces
- Summary: Scoring 2.0 fields are threaded structurally, but the rollout plan’s compact score-display contract (`Score: 67/80 evaluable (20 excluded: ...)`) is not visibly implemented as a shared presentation surface.
- Why it matters: The raw fields exist, but the operator-facing explanation layer the rollout plan promised is not obviously present yet.
- Proposed fix: introduce one shared score-presentation formatter and test it where findings are rendered for analyst/LLM consumption. Rough effort: S/M.

## Implementation Checklist Remaining
### `utils/deterministic_evidence_engine.py`
- complete 2.0-aware sequence coverage semantics
- keep spread/burst/sequence metadata consistent with `evaluable_weight` / `excluded_weight` / emit reasoning
- keep migrated-pattern logic explicit and fail-loud on invalid 2.0 configs

### `utils/pattern_event_mappings.py`
- expand `scoring_version: "2.0"` beyond `pass_the_ticket` and `token_manipulation` only after fixture-backed review per pattern

### `utils/finding_contract.py`
- no structural blocker found
- keep finalization behavior aligned with package-level Scoring 2.0 semantics as more patterns migrate

### `pipeline/pattern_analysis.py`
- current telemetry emission is good enough for baseline artifacts
- verify migrated patterns still emit the intended `eligible_to_emit` / suppression / AI-adjustment story once more 2.0 patterns are added

### `utils/ai_correlation_analyzer.py`
- no router bypass found
- add compact score presentation only if the AI/analyst prompt surface genuinely consumes it

### `utils/pattern_suppression.py`
- keep suppression post-validity and post-coverage
- re-check behavior after first migration wave expands beyond the current two patterns

### Tests
- keep `test_scoring_2_engine_fixtures.py`
- keep `test_scoring_2_emit_eligibility.py`
- keep `test_scoring_2_telemetry.py`
- existing contract/materialization coverage lives in `test_phase1_contract_surfaces.py` and `test_phase7_pattern_materialization_stage.py`
- add sequence-coverage regression tests before any sequence-dependent pattern is migrated to 2.0

## Risks The Plan Does Not Cover Well Enough
- Spread scoring can change 2.0 threshold outcomes and therefore needs explicit metadata reconciliation tests. This was missing until the landed fix in this Review.
- Sequence semantics are still underspecified in code relative to the rollout plan’s `exclude` vs. `FAIL` language.
- The plan assumes payload fields are enough, but operator-facing score explanation needs one shared presentation contract, not just raw numbers.

## Acceptance-Criteria Additions Recommended
- Add a criterion that any post-score bonus path (`spread`, future bonus engines) must keep `deterministic_score`, `max_possible_score`, `evaluable_weight`, `raw_total_weight`, and `eligible_to_emit` internally consistent.
- Add a criterion that any migrated pattern using sequence logic proves the `exclude when not evaluable` behavior under missing telemetry.
- Add a criterion that at least one analyst-facing or LLM-facing surface renders a compact score explanation from the structured Scoring 2.0 fields.

## Pattern Migration Priority
### Highest priority
- `pass_the_ticket`
  - already migrated; keep as the lead validation pattern
- `backup_operator_abuse`
  - high false-positive pressure in baseline artifacts; good candidate for explicit emit gating
- `rdp_lateral`
  - heavy strong-downrank presence; migration should separate “interesting” from “emit-worthy”
- `scheduled_task_persistence`
  - baseline shows heavy coverage-gap pressure
- `wmi_lateral`
  - same reason as `scheduled_task_persistence`

### Next wave
- `service_persistence`
- `network_scanning`
- `local_group_discovery`
- `domain_group_discovery`
- `dcom_lateral_movement`

## Code Changes Landed During Review 1
- `utils/deterministic_evidence_engine.py`
  - fixed Scoring 2.0 spread-bonus reconciliation so spread updates 2.0 package weight metadata and clears stale score-threshold blocks when appropriate (`cab9948a`)
- `tests/test_scoring_2_engine_fixtures.py`
  - added regression coverage for spread reconciliation on a migrated 2.0-style package (`cab9948a`)
- `_REFACTOR/scoring_2_0_rollout.plan.md`
  - reconciled stale todo statuses to the live code state (`cab9948a`)
  - updated the Scoring 2.0 test list to the live filenames now carrying the contract/materialization coverage (`cab9948a`)

Verification run in this Review:
- `python3 -m unittest tests.test_scoring_2_engine_fixtures tests.test_scoring_2_emit_eligibility tests.test_scoring_2_telemetry tests.test_anchor_class_invariants`

