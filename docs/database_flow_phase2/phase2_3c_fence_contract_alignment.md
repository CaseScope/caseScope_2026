# Phase 2.3C Fence Contract Alignment Result

Document-only alignment of `INGEST_FENCE_CONTRACT` with accepted Phase 2.3
shared lightweight UPDATE writers. Does not change runtime behavior. Does not
start Phase 2.4.

**Tranche verdict: PHASE2_3C_PASS**

Phase 2.3 state: `PHASE2_3_CLOSED_PENDING_INDEPENDENT_REVIEW`

## 1. Starting State

- Repository: `/opt/casescope`
- Python: `/opt/casescope/venv/bin/python`
- HEAD / origin/main: `2e4817cfc6040fbe047ffe544664836ece7d80d4`
- HEAD == origin/main, working tree clean at start
- Version: 4.26.2 (unchanged)

## 2. Discovered Contract Gap

Phase 2.3 added bounded lightweight UPDATE as a legitimate shared-admission
events writer via `run_events_lightweight_update()` /
`shared_ingest_admission("events_lightweight_update", case_id=...)`.

The locked `INGEST_FENCE_CONTRACT` still described normal shared writers only
in terms of INSERT. Runtime was already accepted; the contract description was
incomplete.

## 3. Historical Contract Preservation

Phase 0B historical sections were not rewritten as current history.

Retained unchanged:

- Status: LOCKED for Phase 0B
- Model (INSERT-only "Normal writer" diagram)
- Current Baseline (including the historical statement that normal inserts do
  not use a shared writer lease)
- Fail-Closed Rule
- Lease Semantics
- Destructive Operations Requiring Fence
- Tests
- Explicit Open Items

`CONTRACT_STATUS.md` / `CONTRACT_STATUS.json` were not edited.
`casescope_database_flow_plan_v4_locked.md` was not edited.

## 4. Phase 2.3 Contract Addendum

Added dated section `## Implemented Extensions / Phase 2.3` (2026-08-22).

Current shared-admission events writer classes:

1. physical INSERT into `events` (`shared_ingest_admission`, operation
   `events_insert`)
2. bounded Phase 2.3 lightweight SQL UPDATE of `events`
   (`run_events_lightweight_update` / `shared_ingest_admission`, operation
   `events_lightweight_update`)

## 5. Lightweight Boundary

`LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS = 1000`

This is a CaseScope Phase 2.3 measurement-derived bridge boundary.
It is NOT a universal ClickHouse limit.
It is NOT permission for arbitrary predicate UPDATEs.
Changing it requires measurement/review.

The helper is structurally limited to explicit `case_id` + selector_key set +
optional `artifact_type`. It does not accept caller-supplied predicates.

## 6. Shared / Exclusive Semantics

- Lightweight UPDATE acquires shared admission.
- Physical INSERT continues to acquire shared admission.
- Broad/classic events rewrites continue to acquire
  `exclusive_ingest_fence("events_alter_update")` via `run_events_update`.
- Exclusive blocks new shared INSERT writers and new shared lightweight UPDATE
  writers, drains active shared INSERT/UPDATE writers, proceeds only after
  drain, and remains fail closed.
- Predicate-driven/case-wide updates remain classic/exclusive.

Lease ownership, epochs, TTL, renewal, nested-scope semantics, Redis
authority, exclusive acquisition, shared acquisition, and timeout behavior
were not altered.

## 7. Fail-Closed Semantics

Bounded lightweight UPDATE FAILS CLOSED when shared-admission authority is
unavailable. Exclusive classic rewrites remain fail closed. Historical
Fail-Closed Rule text is retained.

## 8. Runtime / Contract Verification

Verified live code before writing the addendum:

- `run_events_lightweight_update` exists
- `LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS == 1000`
- helper uses `shared_ingest_admission("events_lightweight_update", case_id=case_id)`
- `run_events_update` uses `exclusive_ingest_fence("events_alter_update")`
- physical event INSERT paths (`BatchProcessor`, `insert_managed_batch`) still
  use shared admission (`events_insert`)

No runtime file was edited.

## 9. Tests

`/opt/casescope/venv/bin/python -m pytest` on:

- `tests/test_phase2_3_lightweight_update_bridge.py`
- `tests/test_ingest_fence.py`
- `tests/test_phase2_3c_fence_contract_alignment.py`

Result: 72 passed, 0 failed, 0 skipped.

Also: `py_compile` and `pyflakes` on the new test; `git diff --check` passed.

## 10. Files Changed

- `docs/database_flow_contracts/INGEST_FENCE_CONTRACT.md`
- `tests/test_phase2_3c_fence_contract_alignment.py`
- `docs/database_flow_phase2/phase2_3c_fence_contract_alignment.md`
- `docs/database_flow_phase2/phase2_3c_fence_contract_alignment.json`

No runtime production file changed.

## 11. Version

4.26.2 (unchanged). Contract/document alignment for already-deployed accepted
behavior. No runtime release change. No service restart.

## 12. Production Mutation Audit

NONE.

- NO production mutation
- NO ClickHouse UPDATE
- NO ALTER UPDATE
- NO INSERT
- NO index operation
- NO server setting operation
- NO service restart
- NO Redis manipulation

## 13. No-Later-Phase Audit

No Phase 2.4 implementation, retry-collapse, generation-accounting, Hunt
reader, dedup, ERK API migration, LEK, `events_current`,
`event_observations_current`, overlay authority migration, or master-plan
amendment. Those names appear in the addendum only as explicit exclusions.

## 14. Git State

Tranche spec asked to leave changes uncommitted and not pushed. Operator
instruction was to commit all and push to main after PASS.

## 15. Phase 2.3 State

`PHASE2_3_CLOSED_PENDING_INDEPENDENT_REVIEW`

## 16. Remaining Work

Independent contract-alignment review.

Only after acceptance: Phase 2.4 — interim generation-aware accounting and
deterministic-batch retry exclusion.

Do not start Phase 2.4 here.

## 17. Verdict

PHASE2_3C_PASS
