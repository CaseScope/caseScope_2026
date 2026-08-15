# Phase 0B Contract Ratification Report

Correction pass after external architecture review. The locked v4 plan is unchanged. No Phase 1 implementation. No production code, schema, migrations, or retained evidence writes.

## 1. Starting State

- main SHA: `8c4c1dd3b1651df42dc08c39f06250d296864c57`
- version: `4.18.5`
- Prior Phase 0B verdict: READY FOR PHASE 1 (withdrawn by external review).
- External review verdict entering this pass: NOT READY FOR PHASE 1.
- git status: worktree contains Phase 0A/0B artifacts; no commit performed.

## 2. Phase 0A Acceptance

Unchanged. Phase 0A remains ACCEPTED. Reader identity authority remains the Phase 0A production `file::function` `FROM events` / `JOIN events` scan reconstructed as `P0A-R001` .. `P0A-R167`.

## 3. Contract Status Matrix

- LOCKED count: 10
- OPEN count: 0 contract-level blockers
- BLOCKED count: 0

The six external-review blockers are closed by contract correction. Non-blocking measurement items remain for later native-ID LEK recipes, principal collision rates, Qdrant recall parity, and batch-size benchmarking.

## 4. LEK Contract

- Artifact recipes: EVTX remains the only locked cross-source recipe.
- IIS, firewall, SonicWall, and Huntress are `NO_SAFE_CROSS_SOURCE_RECIPE_YET` with ERK-backed non-collapsing LEKs.
- Huntress `event_id` is ECS `event.code`/`action`/category grouping, not a unique source-event UUID.
- Rule: uncertainty => no cross-source collapse. `medium` quality is not permission to collapse.
- Representative-selection and conflict semantics are unchanged.

## 5. Principal Identity Contract

User keys prefer observed SID evidence, then authority-scoped domain/UPN username, then machine-local host-scoped account, then weak unscoped bare username. System keys prefer authoritative machine identifiers, then hostname/FQDN, then weak IP-only. `KnownSystem.id` is removed from `principal_key`. Curation references principal keys; it does not mint them.

## 6. Evidence Generation Contract

Generation state is per-generation. `ACTIVE -> BUILDING_REPLACEMENT` is prohibited. Generation N remains `ACTIVE` while N+1 is allocated `BUILDING_REPLACEMENT`. Atomic PostgreSQL transaction sets N+1 `BUILDING_REPLACEMENT -> ACTIVE` and N `ACTIVE -> SUPERSEDED`. `replacement_in_progress` is a derived source-level operation. `source_generation != ingest_attempt_id`.

## 7. Ingest Batch Contract

`ingest_batch_id` is deterministic over case, source ref, generation, and ordinal. Every future CH batch row persists `ingest_batch_id`, zero-based `ingest_row_ordinal`, and `ingest_row_hash` over an explicit canonical allowlist plus a five-field `parser_provenance` object. `batch_content_hash` is SHA-256 over framed ordered row hashes. Reconciler proves count, ordinal set, uniqueness, per-row hashes, and aggregate hash. Duplicate ordinal identical hash is retry-equivalent only after collapse proof; missing/extra/different-hash ordinals fail closed.

## 8. Capability Watermark Contract

Unchanged from prior Phase 0B lock: contiguous per-source watermarks; `case_capability_state` is UI/aggregate only; AI gating is freeze-then-verify.

## 9. Derivation Contract

Unchanged from prior Phase 0B lock: distinct `derivation_version` / `derivation_run_id` / `state_version`; classified idempotency boundaries.

## 10. Counting Basis Contract

Location-level accounting: 167 `phase0a_reader_id` records. Basis split: ERK 28, LEK 102, CANONICAL_EDGE 0 among `events` readers, OTHER 37, UNRESOLVED 0. Graph topology remains a locked basis for non-`events` graph views.

## 11. ERK API Contract

Unchanged from prior Phase 0B lock.

## 12. Qdrant Identity Contract

Locked option A: revisioned points. Point ID includes `publication_epoch`. Replacement writes use unpublished epochs and must not overwrite published point IDs. Payload support is `support_generation_keys[]`, `representative_generation_key`, and `active_support_count`. Default retrieval requires published epoch and `active_support_count >= 1`.

## 13. Ingest Fence Contract

Unchanged from prior Phase 0B lock.

## 14. Event Surface Migration Matrix

One record per Phase 0A reader ID in `event_surface_consumers.json`: `events_current` 102, `event_observations_current` 28, administrative/raw `events` 37, unresolved 0. Set equality of IDs is the accounting proof.

## 15. Contract Test Matrix

`CONTRACT_TEST_MATRIX.md` and `contract_test_matrix.json` define 44 future scenarios (CT-001..CT-044). New tests cover generation non-mutation, atomic activation, reconstructible batch hashes and ordinal outcomes, LEK non-collapse for unsafe families, Qdrant multi-support/replacement isolation, principal_key without KnownSystem.id, and reader ID set equality. None are executable production tests and none require DB writes.

## 16. Phase 0B Decision Log

- Decision count: 22
- Correction-pass decisions: PHASE0B-DEC-017 through PHASE0B-DEC-022
- Material open decisions: none that block Phase 1. Non-blocking measurement items remain for native-ID LEK expansion, retained principal collisions, Qdrant recall parity, and batch-size benchmarking.

## 17. Existing Correctness Defects Discovered

NONE in production code (no production changes). Contract defects identified by external review are corrected in this pass.

## 18. Validation

See the correction-pass validation section in the operator report. JSON parse, reader ID set equality, duplicate-ID check, contract-status counts, decision-log references, and contract-test JSON representation are required gates.

## 19. Phase 1 Dependencies

Unchanged: Phase 1 depends on the ingest fence contract before Buffer removal, and on ingest batch/generation/watermark contracts before Phase 1B. No Phase 1 optimization was implemented.

## 20. Phase 0B Verdict

READY FOR PHASE 1.

Readiness basis: all six external-review blockers are closed in contract documents; locked v4 is unmodified; no production code/schema/migrations; unsafe LEK families are non-collapsing; reader IDs are location-addressable with set equality; generation replacement is a new generation; batch hashes are reconstructible from CH row identity; Qdrant publication uses revisioned points; principal_key no longer uses KnownSystem surrogate IDs.
