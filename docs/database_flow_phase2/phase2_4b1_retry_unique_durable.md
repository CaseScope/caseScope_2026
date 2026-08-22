# Phase 2.4B1 Retry-Unique Durable Batch Result

Dated 2026-08-22. Does not close Phase 2. Does not start Phase 3 or Phase 4.

## 1. Starting State

HEAD and origin/main were `0937e42cb242b20053dd7f200a066e5ba6b3d6e2` (4.26.2). ClickHouse 26.7.3.19. Working tree clean at the Phase 2.4B1 start.

## 2. Locked 2.4 Boundary

Preserved exactly: "Dedup: no engine decision (RMT Option A remains removed). Interim = generation-aware accounting + deterministic-batch retry exclusion. Real design = Phase 4."

No LEK, no semantic/ERK collapse, no events_current, no RMT, no Phase 3/4.

## 3. 2.4A Findings Reverified

All eight accepted 2.4A facts still matched current main before the B1 writer change. Production still had zero managed generations/batches. Production PostgreSQL was missing accepted D1/D2 columns. D2 historically treated `duplicate_identical` like `exact`.

## 4. Production Phase 1B Schema Audit

Known drift was D1/D2 PostgreSQL deployment lag only. ClickHouse protocol columns and empty `visible_evidence_generations` / `durable_ingest_batches` were already present. No extra accepted Phase 1B schema drift.

Missing before migration: D1 generation lifecycle columns; D2 attempt lease/heartbeat columns; D2 batch reconcile columns including `last_reconcile_outcome`, `last_reconcile_error`, `updated_at`; D2 indexes and non-negative checks.

## 5. Production Backup / Safe Drain

Celery active/reserved/scheduled were idle at schema time. Leftover CaseFile 538677 was `ingesting`/`not_done` from 2026-08-03 with 0 events; not killed. PostgreSQL backup `/opt/casescope/backups/casescope-postgres-phase2-4b1-20260822-193511.dump` exists and is 2062852638 bytes.

## 6. D1 Schema Convergence

Applied existing `migrations/add_phase1b_tranche_d1_generation_lifecycle.py` with `/opt/casescope/venv/bin/python` and `/etc/casescope/casescope.env`.

## 7. D2 Schema Convergence

Applied existing `migrations/add_phase1b_tranche_d2_staged_reconciler.py` the same way.

## 8. Full Post-Migration Schema Verification

PRODUCTION_PHASE1B_SCHEMA_ALIGNED

ORM SELECTs on current `EvidenceSourceGeneration`, `IngestAttempt`, and `IngestBatch` no longer fail for missing D1/D2 columns.

## 9. Upgrade-Path Root Cause

`wiki/update-software.md` named Phase 1B Tranche A–C1 migrations for 4.19.0 and left later D1/D2 to an unstated `git diff migrations` review. A 4.3+-to-current host could therefore run 4.26.2 application code against PostgreSQL that still lacked accepted D1/D2 columns.

## 10. Update Guide Correction

Current 4.3+-to-current path now requires services stopped, PostgreSQL backup, D1, D2, schema verification, then application restart. Historical 4.19.0 notes were not rewritten. A unit test fails if those D1/D2 commands disappear from the 4.3+ path.

## 11. Deterministic Batch Ownership Before

`reserve_staged_batch()` could rebind an existing STAGED deterministic batch to a new `ingest_attempt_id` by overwrite.

## 12. Deterministic Batch Ownership After

One-writer STAGED ownership uses PostgreSQL attempt lease/staleness. New STAGED is owned by the current attempt. Same attempt may continue. A different live attempt fail-closes with zero ClickHouse INSERT. Stale/terminal transfer goes through `transfer_staged_batch_ownership()`. DURABLE matching manifests replay without rebinding or inserting.

## 13. Pre-Insert Verification State Machine

Shared `commit_managed_batch_exactly_once()`: DURABLE → already_durable; preflight exact → no insert, DURABLE; duplicate_identical → STAGED normalize; absent → insert once and require exact; partial/conflicts → fail closed.

## 14. Fresh Batch Path

INSERT once, verify exact, then DURABLE. Post-insert duplicate_identical is one normalization cycle, not publication.

## 15. Lost-Acknowledgement Path

LOST_ACK_SECOND_INSERT_PREVENTED

Preflight exact performs zero second INSERT. Same `ingest_batch_id`. PG DURABLE. landed_rows == N. Physical rows == N. Hunt published count == N.

## 16. Already-DURABLE Replay

Idempotent. No ownership rewrite. No second INSERT. No second durable row. No extra row-local derivation queue. landed_rows unchanged.

## 17. Concurrent Live Attempt

Attempt B cannot take a STAGED batch owned by live attempt A. Zero ClickHouse insert. Fail closed.

## 18. D2 Stale Transfer

Stale A + exact physical rows: D2 marks DURABLE with zero second insert. landed_rows == N. Physical rows == N.

## 19. duplicate_identical Runtime Policy

DUPLICATE_IDENTICAL_STAGED_NORMALIZATION_ENFORCED

Classifier still recognizes `duplicate_identical`. Current action is STAGED normalize/recover, not DURABLE with multiple physical copies.

## 20. Normalization Implementation

Whole-batch STAGED purge/reinsert through the accepted exclusive-fence purge helper. Targeted extra-copy deletion was not required. Fence unavailable: no purge, remain STAGED, fail closed. One controlled cycle; D2 keeps `DEFAULT_MAX_AUTO_RECOVERY_ATTEMPTS=3`.

## 21. Fail-Closed Conflict Matrix

partial, extra_ordinal, duplicate_different, hash_mismatch, aggregate_mismatch, and manifest mismatch do not become DURABLE.

## 22. DURABLE Physical Invariant

DURABLE_RETRY_UNIQUENESS_ENFORCED

For current managed DURABLE batches, one expected ordinal equals one physical row for the frozen ingest_row_hash.

## 23. Existing Production DURABLE Retry Copies

0. Census after schema alignment: 0 generations, 0 batches, 0 attempts; 0 control-projection rows.

## 24. Current Consumer Consequence Matrix

See JSON. Hunt publication paths are SAFE_BY_DURABLE_RETRY_UNIQUENESS. Paths that still query unpublished `events` rows without the DURABLE control projection remain CAN_READ_STAGED_OR_UNPUBLISHED_MANAGED_ROWS for in-flight first copies. Those publication expansions belong to Phase 2.4B2. No CURRENT_CONSUMER_PUBLICATION_BYPASS_REMAINS stop: Hunt, the product publication path, is unique once DURABLE, and B1 prevents publishing retry copies.

## 25. Contract Addendum

`docs/database_flow_contracts/INGEST_BATCH_CONTRACT.md` dated Phase 2.4 implemented extensions. Locked master plan not edited.

## 26. Performance / Contention

Disposable only. Fresh 2-row managed commit including first INSERT: 800.28 ms on cold disposable tables (1 INSERT). 15 live uniqueness proofs plus unit/sqlite tests: 5.306 s. No 745M-row production scan. No production retry copies created.

## 27. Regression Tests

Required suites passed under `/opt/casescope/venv/bin/python -m pytest` with disposable `PHASE1B_*` databases. `test_clickhouse_delete_dedup_contracts.py` must run in a separate process because it replaces `sys.modules['utils.event_deduplication']` at import. Combined: 294 + 35 passed, 0 skipped. pyflakes clean. `git diff --check` clean.

## 28. Files Changed

Runtime: `utils/manifest_protocol.py`, `utils/staged_batch_reconciler.py`, `tasks/celery_tasks.py`. Docs/tests/version/wiki/evidence as listed in git.

## 29. Version

Candidate source: 4.26.3

## 30. Production Runtime Version

Deployed baseline remains 4.26.2 at `0937e42...` until independent review restarts services onto 4.26.3.

PHASE2_4B1_RUNTIME_ACTIVATION_PENDING_INDEPENDENT_REVIEW

## 31. Production Mutation Audit

PostgreSQL accepted D1/D2 additive schema only. No production ClickHouse INSERT/UPDATE/DELETE/OPTIMIZE/index or evidence mutation.

## 32. Service State

`casescope-web`, `casescope-workers`, and `casescope-beat` active on the baseline runtime. PostgreSQL/Redis/ClickHouse required and available. At report time workers had production case 3 graph materialize and MITRE mapping; not ingest; not killed.

## 33. No-Later-Phase Audit

No Phase 3/4, LEK, events_current, RMT, ERK cutover, IOC/MITRE/Qdrant/graph identity migration, or Phase 2 exit declaration.

## 34. Git State

Operator instruction was commit all and push to main. Spec said leave uncommitted; operator instruction wins.

## 35. Remaining Work

Phase 2.4B2 after independent B1 acceptance: remaining CURRENT consumer publication gaps, activate accepted 2.4 runtime if still pending, locked Phase 2 exit baselines. Do not start Phase 3.

## 36. Phase State

PHASE2_4B_CORE_READY_PENDING_INDEPENDENT_REVIEW

## 37. Verdict

PHASE2_4B1_PASS
