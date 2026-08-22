# Phase 2.4A Deterministic Retry-Copy Gap Audit Result

Read-only production measurement plus disposable lost-acknowledgement proofs.
Does not implement retry exclusion. Does not start Phase 3 or Phase 4.

## 1. Starting State

{
  "ok": true,
  "repository": "/opt/casescope",
  "python": "/opt/casescope/venv/bin/python",
  "head": "3ba6483287ae7a1771f3fd8cf9f67fbf7113e633",
  "origin_main": "3ba6483287ae7a1771f3fd8cf9f67fbf7113e633",
  "head_equals_origin_main": true,
  "working_tree_clean_at_start": false,
  "status_short": "?? docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.json\n?? docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.md\n?? scripts/phase2_4a_retry_copy_gap_audit.py\n?? tests/test_phase2_4a_retry_copy_gap_audit.py",
  "unexpected_paths": [],
  "expected_head": "3ba6483287ae7a1771f3fd8cf9f67fbf7113e633",
  "expected_version": "4.26.2",
  "version": "4.26.2"
}

ClickHouse: 26.7.3.19

## 2. Locked Phase 2.4 Contract

"Dedup: no engine decision (RMT Option A remains removed). Interim = generation-aware accounting + deterministic-batch retry exclusion. Real design = Phase 4."

Preserved:

- Measurement discipline: baselines re-run at each phase exit; deltas in-repo; measurement beats plan.
- Forensic integrity: immutable events; ERK pure provenance; duplicates reconciled not destroyed; deterministic canonical representatives; publication != presence; fail-closed fencing.

Phase 2.4 is not logical/semantic dedup and is not Phase 4 early.

## 3. Existing Phase 1B Coverage

Deterministic `ingest_batch_id` over frozen generation/batch identity already exists.
`ingest_attempt_id` is execution identity only. Frozen `ingest_row_hash` allowlist already excludes
selector_key, indexed_at, ingest_attempt_id, analyst/noise/ioc overlays, and extra_fields.
`verify_ingest_batch` / D2 `classify_batch` already accept `duplicate_identical` as success.
D2 currently marks those batches DURABLE without physically removing extra copies.
Generation `landed_rows` already sums PostgreSQL DURABLE `IngestBatch.row_count`.
Hunt publication already filters STAGED vs DURABLE and generation visibility, but does not collapse retry copies.
Legacy semantic dedup remains blocked for managed evidence by default.

## 4. Deterministic Retry Definition

A Phase 2.4 retry copy is ONLY:

- same `ingest_batch_id`
- same `ingest_row_ordinal`
- same `ingest_row_hash`
- that hash matches the frozen PostgreSQL expected hash for that ordinal
- the frozen aggregate batch contract remains valid

This is DETERMINISTIC_RETRY_EQUIVALENT. Same ERK, selector_key, case_file_id, record_id,
timestamp, source_file, search_blob, or apparent semantic content is not enough.
Different deterministic batch identity is not a Phase 2.4 retry copy.

## 5. Current Retry State Machine

Normal: PG STAGED reserve → CH INSERT → verify exact → PG DURABLE → project `durable_ingest_batches`
→ `update_generation_ingest_accounting` from PG row_count → optional row-local derivation queue → F1 completion.

Lost acknowledgement / crash after CH accept: PG remains STAGED; CH already has rows; retry uses a new
`ingest_attempt_id` and the same deterministic `ingest_batch_id`; second physical copy can land;
verify returns `duplicate_identical` success; D2/mark_durable currently DURABLE without purge.

Partial/missing ordinals purge by `ingest_batch_id` behind exclusive fence, then retry. That is not the identical-hash path.

Authoritative state: PostgreSQL for generation/batch/watermarks/readiness; ClickHouse for physical evidence;
control projections are derived from PG.

## 6. Generation Accounting Audit

Decision: **GENERATION_ACCOUNTING_ALREADY_RETRY_SAFE**

`update_generation_ingest_accounting()` sets `landed_rows` from `SUM(IngestBatch.row_count)` where DURABLE.
Activation completeness compares that PG row_count sum to `expected_rows`. Capability watermarks and F1
batch counts key by `ingest_batch_id`. Physical ClickHouse multiplicity does not change those numbers.

{
  "A_ingest_batch_id_deterministic_excludes_attempt": true,
  "B_ingest_attempt_id_not_in_batch_identity": true,
  "C_row_hash_frozen_allowlist": {
    "allowed": [
      "case_id",
      "artifact_type",
      "source_ref_type",
      "source_ref_id",
      "source_generation",
      "ingest_batch_id",
      "ingest_row_ordinal",
      "source_file",
      "source_path",
      "source_host",
      "case_file_id",
      "timestamp",
      "timestamp_utc",
      "timestamp_source_tz",
      "event_id",
      "channel",
      "provider",
      "record_id",
      "level",
      "username",
      "domain",
      "sid",
      "logon_type",
      "logon_id",
      "remote_host",
      "workstation_name",
      "auth_package",
      "logon_process",
      "elevated_token",
      "process_name",
      "process_path",
      "process_id",
      "parent_process",
      "parent_pid",
      "command_line",
      "thread_id",
      "executable_info",
      "payload_data1",
      "payload_data2",
      "payload_data3",
      "payload_data4",
      "payload_data5",
      "payload_data6",
      "target_path",
      "file_hash_md5",
      "file_hash_sha1",
      "file_hash_sha256",
      "file_size",
      "src_ip",
      "dst_ip",
      "src_port",
      "dst_port",
      "reg_key",
      "reg_value",
      "reg_data",
      "rule_title",
      "rule_level",
      "rule_file",
      "mitre_tactics",
      "mitre_tags",
      "mitre_attack_ids",
      "mitre_attack_tactics",
      "mitre_attack_sources",
      "mitre_mapping_max_confidence",
      "raw_json",
      "search_blob",
      "evidence_record_key",
      "evidence_identity_version",
      "evidence_identity_quality"
    ],
    "excluded": [
      "analyst_notes",
      "analyst_tagged",
      "analyst_tags",
      "celery_task_id",
      "extra_fields",
      "indexed_at",
      "ingest_attempt_id",
      "ingest_row_hash",
      "ioc_types",
      "job_id",
      "noise_matched",
      "noise_rules",
      "run_id",
      "selector_key",
      "task_id"
    ],
    "excludes_selector_indexed_attempt_overlays": true
  },
  "D_verify_duplicate_identical_success": true,
  "E_classify_batch_accepts_duplicate_identical": true,
  "F_reconcile_marks_durable_without_purge": true,
  "G_landed_rows_from_pg_durable_row_count": true,
  "H_hunt_publication_no_retry_collapse": true,
  "I_managed_dedup_blocked_default": true,
  "all_starting_facts_match_prompt": true
}

## 7. Retry-Sensitive Consumer Inventory

- Hunt Events count/list: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Hunt detail/raw: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Hunt exports using publication bridge: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Case/file product event counts: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Analyst selector state accounting: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Manual-noise selector state accounting: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Noise scan accounting: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- IOC accounting: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- MITRE accounting: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Privacy-alias batch derivation: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- AI freeze-then-verify: `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Ingest verify / duplicate_identical: `ALREADY_RETRY_SAFE`
- Generation landed_rows / expected_rows: `ALREADY_RETRY_SAFE`
- Activation completeness row sums: `ALREADY_RETRY_SAFE`
- Capability watermarks: `ALREADY_RETRY_SAFE`
- Case readiness Evidence dimension: `ALREADY_RETRY_SAFE`
- Completion reconciliation PG batch counts: `ALREADY_RETRY_SAFE`
- Graph extraction (F1 transitional): `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Event embeddings (F1 transitional): `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Known-principal discovery (F1 transitional): `NEEDS_PHASE2_4_RETRY_EXCLUSION`
- Legacy-only completion dedup: `LEGACY_ONLY_OUT_OF_SCOPE`
- Phase 4 logical/events_current dedup: `PHASE4_LOGICAL_DEDUP_OUT_OF_SCOPE`
- Managed destructive case-wide dedup: `INTEGRITY_FAIL_CLOSED`

Analyst/manual-noise: physical `matched_count` / EvidenceChange `affected_count` inflate;
per-event EventChange remains one row per unique selector_key. State mutation still needs to
update every physical copy; accounting must not treat each copy as an independent observation.

## 8. Production Managed Authority Census

{
  "managed_cases": 0,
  "managed_case_ids": [],
  "generations": 0,
  "generations_by_visibility": {},
  "batches": 0,
  "batches_by_state": {},
  "schema_lag": {
    "evidence_source_generations_missing": [
      "activated_at",
      "final_batch_ordinal",
      "superseded_at",
      "superseded_by_generation"
    ],
    "ingest_batches_missing": [
      "last_reconcile_at",
      "reconcile_attempt_count",
      "reconcile_lease_expires_at",
      "reconcile_owner"
    ],
    "ingest_attempts_columns": [
      "celery_task_id",
      "error",
      "finished_at",
      "generation_id",
      "id",
      "ingest_attempt_id",
      "started_at",
      "status",
      "worker_name"
    ],
    "evidence_source_generations_columns": [
      "batching_contract_version",
      "case_id",
      "completed_at",
      "configured_batch_size",
      "created_at",
      "expected_rows",
      "failed_at",
      "failure_reason",
      "id",
      "landed_rows",
      "normalization_version",
      "ordering_contract",
      "parser_version",
      "producer_version",
      "source_generation",
      "source_ref_id",
      "source_ref_type",
      "started_at",
      "state_version",
      "visibility_state"
    ],
    "ingest_batches_columns": [
      "batch_content_hash",
      "batch_ordinal",
      "created_at",
      "durable_at",
      "expected_ingest_row_hashes",
      "first_source_locator",
      "generation_id",
      "id",
      "ingest_attempt_id",
      "ingest_batch_id",
      "last_source_locator",
      "row_count",
      "state",
      "state_version"
    ]
  },
  "control_projections": {
    "tables_present": [
      "durable_ingest_batches",
      "events",
      "visible_evidence_generations"
    ],
    "counts": {
      "visible_evidence_generations": 0,
      "durable_ingest_batches": 0
    },
    "query_stats": [
      {
        "query_id": "6edc9487-a086-4c40-a682-8809987fec0c",
        "read_rows": 0,
        "read_bytes": 0,
        "duration_ms": 6.947,
        "sql_preview": "SELECT name FROM system.tables WHERE database = currentDatabase() AND name IN ('visible_evidence_generations', 'durable_ingest_batches', 'events') ORDER BY name"
      },
      {
        "query_id": "887930b4-7f53-4e86-abf9-42ca13ff08e7",
        "read_rows": 0,
        "read_bytes": 0,
        "duration_ms": 4.261,
        "sql_preview": "SELECT count() FROM visible_evidence_generations"
      },
      {
        "query_id": "65ad8162-332c-4d7c-b38b-9de2bb0e0fd3",
        "read_rows": 0,
        "read_bytes": 0,
        "duration_ms": 4.44,
        "sql_preview": "SELECT count() FROM durable_ingest_batches"
      }
    ],
    "skipped_unbounded_events_scan": true
  }
}

Production PostgreSQL currently has zero managed generations and zero ingest batches.
Control projections `visible_evidence_generations` and `durable_ingest_batches` are also empty.
Events were not scanned unbounded. Census was limited to PG-managed case IDs.
Code on main has Phase 1B columns (`final_batch_ordinal`, D2 reconcile lease fields) that production PG
tables have not yet received. That is schema lag versus current models, not a retry-copy integrity conflict.
2.4B pre-DURABLE normalization must apply those existing Phase 1B columns before using D2 lease fields in production.
Query/accounting exclusion does not require those columns.

## 9. Production ClickHouse Retry-Copy Census

Decision: **PRODUCTION_DETERMINISTIC_RETRY_COPIES_ABSENT**

{
  "managed_cases_inspected": 0,
  "managed_generations_inspected": 0,
  "managed_batches_inspected": 0,
  "batches_containing_physical_retry_copies": 0,
  "ordinals_containing_physical_retry_copies": 0,
  "total_extra_physical_rows": 0,
  "cases_affected": [],
  "generations_affected": 0,
  "maximum_copies_of_one_ordinal": 0,
  "staged_duplicate_batches": 0,
  "durable_duplicate_batches": 0,
  "duplicates_by_generation_visibility": {},
  "malformed_protocol_identity_rows": 0,
  "query_stats": []
}

## 10. Production Integrity Conflict Census

Decision: **PRODUCTION_RETRY_INTEGRITY_CONFLICT_ABSENT**

{
  "different_hash_conflicts": 0,
  "wrong_hash_conflicts": 0,
  "integrity_conflicts": []
}

No auto-delete or auto-repair was performed.

## 11. Non-Hashed Current-State Parity

Decision: **CURRENT_RETRY_COPY_STATE_NOT_OBSERVED**

{
  "token": "CURRENT_RETRY_COPY_STATE_NOT_OBSERVED",
  "groups_inspected": 0,
  "parity_groups": 0,
  "divergence_groups": 0,
  "notes": "No production deterministic retry-copy groups to compare."
}

`ingest_attempt_id` and `indexed_at` are expected to differ and were not treated as corruption.

## 12. Malformed Protocol Identity

Malformed/partial protocol identity rows on managed-case partitions: 0.
Hunt publication already treats partial identity as non-legacy and fails closed for publication.
Malformed rows were not reinterpreted as legacy.

## 13. Lost-Acknowledgement Disposable Proof

{
  "ack_error_present": true,
  "stored_before_raise": true,
  "verify_after_loss": {
    "success": true,
    "outcome": "exact",
    "physical_rows": 8
  },
  "verify_after_retry": {
    "success": true,
    "outcome": "duplicate_identical",
    "physical_rows": 16,
    "duplicate_physical_rows": 8,
    "retry_equivalent_duplicate": true
  },
  "same_batch_id": true,
  "different_attempt_id": true,
  "pg_state": "DURABLE"
}

## 14. Current DURABLE Duplicate Behavior

{
  "pg_expected_rows_declared": 8,
  "pg_batch_row_count": 8,
  "pg_landed_rows": 8,
  "clickhouse_physical_rows": 16,
  "hunt_building_initial_count": 16,
  "hunt_building_initial_excluded": 8,
  "hunt_active_count": 16,
  "hunt_active_excluded": 8,
  "hunt_during_building_replacement": 16,
  "one_ordinal_appears_once_in_current_hunt": false,
  "one_ordinal_appears_once_per_physical_copy": true
}

Current published Hunt consumer sees one deterministic ordinal once per physical copy.
PostgreSQL landed_rows remains the expected collapsed count.

## 15. Hunt Count / List / Pagination Effect

{
  "page_size": 5,
  "page1_rows": 5,
  "page2_rows": 5,
  "duplicate_selector_consumes_page_slot": true,
  "same_selector_can_appear_twice": true,
  "query_stats": {
    "page1": {
      "query_id": "03c278a1-9153-477e-9930-24ad91794118",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 24.334,
      "sql_preview": "SELECT e.selector_key, e.ingest_batch_id, e.ingest_row_ordinal, e.ingest_attempt_id, e.evidence_record_key FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM vi"
    },
    "page2": {
      "query_id": "e02b41cb-7d7f-43d3-9a2d-9fb0ecf4f6f4",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 23.222,
      "sql_preview": "SELECT e.selector_key, e.ingest_batch_id, e.ingest_row_ordinal, e.ingest_attempt_id, e.evidence_record_key FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM vi"
    },
    "count": {
      "query_id": "19ff5a44-0dde-4fed-a90a-fc426d036ac5",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 39.233,
      "sql_preview": "SELECT count() AS n FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM visible_evidence_generations FINAL WHERE case_id = {case_id:UInt32} ) AS veg ON veg.case_"
    }
  }
}

If expected observations = N and extra physical copies = R, current Hunt total reports N+R.
A retry copy consumes a page slot. The same selector can appear twice. 2.4A did not change Hunt.

## 16. Hunt Detail / Raw Effect

{
  "physical_copies_for_selector": 2,
  "limit_1_returns_one_row": true,
  "divergent_notes_present": true,
  "limit_1_after_divergence_notes": "copy-a",
  "order_dependent_when_diverged": true
}

Detail/raw `LIMIT 1` returns one arbitrary physical copy. If non-hashed mutable fields diverge,
the chosen copy is insertion/merge-order dependent. This is not Phase 4 canonical-representative design.

## 17. Phase 2.3 Mutation Accounting Effect

{
  "physical_copies_for_selector": 2,
  "analyst_matched_count": 2,
  "physical_rows_tagged": 2,
  "event_change_audit_rows": 1,
  "evidence_change_affected_counts": [
    0
  ],
  "manual_noise_matched_count": 2,
  "accounting_inflates_matched_count": true,
  "event_change_is_per_selector": true
}

2.4B needs an accounting-only adjustment for matched_count / affected_count.
Physical copies may still be updated together so overlay state stays synchronized.

## 18. Other Mutation Accounting Effect

Noise scan, IOC refresh, and MITRE mapping currently `SELECT count()` over physical `events` rows
and are still invoked on managed evidence (manual IOC/noise; F1 transitional MITRE/graph/embeddings/known-principal).
Classification: `NEEDS_PHASE2_4_RETRY_EXCLUSION` for their current affected-row accounting.
Those state models are not migrated here.

## 19. Privacy-Alias Derivation Effect

{
  "error": null,
  "derive_result_keys": [
    "batch_ordinal",
    "capability",
    "contiguous_batch_ordinal",
    "derivation_version",
    "ingest_batch_id",
    "populate",
    "source_generation",
    "state_version",
    "status"
  ],
  "alias_authority_rows": 0,
  "populate_event_count": 16,
  "physical_batch_rows": 16,
  "count_inflates_when_copies_exist": true,
  "needs_exclusion_for_counts": true
}

Classification: `NEEDS_PHASE2_4_RETRY_EXCLUSION` for CH `event_count` / `seen_count`.
Vault upsert identity and watermark completion keyed by `ingest_batch_id` are already retry-safe.

## 20. AI Freeze / Verify Effect

{
  "error": null,
  "selected_physical_rows": 16,
  "frozen_observations": 16,
  "selected_erks": 16,
  "unique_erks": 8,
  "managed_batch_ids": [
    "ingest-batch:v1:19328c306ba20690a7af7e264f5d3acf1a8e65afc5311234d99ea94a306c0c43"
  ],
  "payload_lines": 16,
  "duplicate_erks": true
}

Classification: `NEEDS_PHASE2_4_RETRY_EXCLUSION` for selected rows, ERK list, and aliased payload lines.
`managed_batch_ids` already unique; coverage by batch id is already retry-safe.

## 21. Completion / Readiness Effect

{
  "activation_complete": true,
  "landed_rows": 8,
  "readiness_clickhouse_calls": null,
  "completion_ch_queries": 0,
  "completion_batch_counts": {
    "staged": 0,
    "durable": 2,
    "generations": 2
  },
  "already_retry_safe": true
}

Classification: `ALREADY_RETRY_SAFE`. Do not add ClickHouse counting to readiness.

## 22. Legacy Dedup Safety Boundary

{
  "production_allow_managed_evidence_true": [],
  "blocked_default": true
}

No production caller passes `allow_managed_evidence=True`.
`deduplicate_case_events_task` and the legacy completion tail omit the flag (default False).
The case-files route only queues that task. Managed evidence remains blocked by default.

## 23. Negative Controls

{
  "same_erk_different_batch_is_retry": false,
  "same_erk_batch_diversity": [
    {
      "evidence_record_key": "erk-p24a-1-00000001",
      "batches": 3,
      "physical": 5
    }
  ],
  "legacy_protocol_null_physical": 2,
  "legacy_not_collapsed_by_retry_identity": true,
  "different_hash_same_ordinal": "integrity_conflict",
  "hunt_legacy_included_in_current_count": true,
  "candidate_exclusion_keeps_legacy_physical": true
}

- same ERK != retry
- same selector != retry
- different batch != retry
- different generation != retry
- semantic/legacy duplicate != retry
- different hash same ordinal = integrity conflict

## 24. Candidate Strategy Comparison

### PRE-DURABLE normalization

Before `duplicate_identical` STAGED becomes DURABLE, leave exactly one physical copy per ordinal,
reverify exact, then DURABLE. Requires exclusive ingest fence for DELETE of extras only
(current `purge_ingest_batch_rows` deletes the whole batch by `ingest_batch_id`, which is too broad).
STAGED copies are unpublished, so overlay divergence is unlikely but not proven for already-DURABLE history.
Crash window after extra insert and before purge still exists.

### QUERY exclusion

Leave physical copies intact. Collapse current managed readers/accounting by
`ingest_batch_id + ingest_row_ordinal` after frozen-hash validity.
Must not use `LIMIT 1 BY ingest_batch_id, ingest_row_ordinal` on mixed Hunt because legacy NULL identity
would collapse unrelated rows. Legacy remains physical; managed uses uniqExact / chosen-copy subquery.
No new writer fence. Hunt pagination and detail become deterministic only after an explicit copy-choice rule.
Already-DURABLE mutable divergence remains: exclusion picks one current copy.

### HYBRID

Prevent future duplicate-identical batches from becoming DURABLE with extra physical copies,
and apply narrow read/accounting exclusion for already-DURABLE historical copies and for
Hunt/AI/privacy/mutation accounting until/unless extras are gone.
This respects that already-DURABLE copies may have mutable non-hashed state.

### OTHER

None required. RMT and semantic/ERK dedup remain forbidden.

## 25. Recommended 2.4B Strategy

**PHASE2_4_STRATEGY_HYBRID**

## 26. Interim Consumer Decision

**INTERIM_RETRY_EXCLUSION_REQUIRED**

## 27. Exact 2.4B Runtime Scope

Protocol: change the `exact`/`duplicate_identical` STAGED→DURABLE success path so extra physical
retry copies of the same `(ingest_batch_id, ingest_row_ordinal, expected ingest_row_hash)` are
not left published. Preferred pre-DURABLE action: fence-protected deletion of extra copies only
(not whole-batch purge, not ERK/selector/artifact delete), then reverify `exact`, then DURABLE.
Do not physically delete already-DURABLE production copies in 2.4B without a separate current-state
parity proof; use query/accounting exclusion for those.

Interim readers/accounting to change:
- Hunt publication count, list, pagination, detail/raw, and publication-bridged exports
- analyst `matched_count` / EvidenceChange `affected_count` (keep updating all physical copies)
- manual-noise `matched_count` / `affected_count` (same)
- privacy-aliases scoped `event_count` / `seen_count`
- AI freeze `select_current_generation_event_rows` observation set / ERK tuple / payload lines

Already safe, do not change:
- PostgreSQL `landed_rows`, activation completeness, capability watermarks, F1 batch counts, readiness Evidence
- `verify_ingest_batch` / D2 collapsed proof identity rules
- managed-dedup fail-closed guard

Deferred / later phase:
- IOC/MITRE/noise-scan/graph/embedding/known-principal state-model migration
- LEK, events_current, event_observations_current, ERK API, Qdrant, RMT
- canonical logical representative and field-conflict surfacing
- whole-case semantic dedup removal

Future retry copies: prevent DURABLE extras (pre-DURABLE normalization).
Existing DURABLE extras: exclusion only unless independently proven safe to prune.

## 28. Contract Addendum Requirement

YES. Recommend a dated 2.4B implementation addendum to INGEST_BATCH_CONTRACT recording which
collapsed-proof option current runtime uses, that DURABLE extra copies must be excluded from
interim published counts until Phase 4, and that pre-DURABLE extra-copy removal is identity-scoped
to deterministic retry copies only. Do not rewrite the locked identity rule in 2.4A. Do not write the addendum yet.

## 29. Performance Evidence

{
  "ordinary_no_duplicate": {
    "n": 400,
    "extra_full_copies": 0,
    "physical": 400,
    "current_hunt_count": 400,
    "candidate_hunt_count": 400,
    "current_count_stats": {
      "query_id": "85653d7f-80ec-4ae5-ab74-2f04eaed064d",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 47.522,
      "sql_preview": "SELECT count() AS n FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM visible_evidence_generations FINAL WHERE case_id = {case_id:UInt32} ) AS veg ON veg.case_"
    },
    "candidate_count_stats": {
      "query_id": "01c78146-517d-4464-ada2-a6e268f23268",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 26.069,
      "sql_preview": "SELECT countIf(e.source_ref_type IS NULL AND e.source_ref_id IS NULL AND e.source_generation IS NULL AND e.ingest_batch_id IS NULL AND e.ingest_row_ordinal IS NULL AND e.ingest_row_hash IS NULL AND e.ingest_attempt_id IS NULL) AS legacy_n, "
    },
    "current_data_stats": {
      "query_id": "0a466155-d28d-47a7-8440-6e4dd6bb5fd5",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 20.925,
      "sql_preview": "SELECT e.selector_key, e.ingest_batch_id, e.ingest_row_ordinal, e.ingest_attempt_id, e.evidence_record_key FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM vi"
    },
    "candidate_data_stats": {
      "query_id": "80155305-9e7a-4ac9-b9f0-f1ded206b536",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 27.514,
      "sql_preview": "SELECT e.selector_key FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM visible_evidence_generations FINAL WHERE case_id = {case_id:UInt32} ) AS veg ON veg.cas"
    },
    "verify_outcome": "exact"
  },
  "sparse_retry_duplicates": {
    "n": 400,
    "extra_full_copies": 1,
    "physical": 800,
    "current_hunt_count": 800,
    "candidate_hunt_count": 400,
    "current_count_stats": {
      "query_id": "4e6748a2-e529-4e10-ada9-20e7dbd85368",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 28.041,
      "sql_preview": "SELECT count() AS n FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM visible_evidence_generations FINAL WHERE case_id = {case_id:UInt32} ) AS veg ON veg.case_"
    },
    "candidate_count_stats": {
      "query_id": "5f51c825-b2f0-4b4a-98b7-c508f82a0f02",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 22.251,
      "sql_preview": "SELECT countIf(e.source_ref_type IS NULL AND e.source_ref_id IS NULL AND e.source_generation IS NULL AND e.ingest_batch_id IS NULL AND e.ingest_row_ordinal IS NULL AND e.ingest_row_hash IS NULL AND e.ingest_attempt_id IS NULL) AS legacy_n, "
    },
    "current_data_stats": {
      "query_id": "886f0ce1-09a9-472d-a5eb-205ed02eb153",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 22.556,
      "sql_preview": "SELECT e.selector_key, e.ingest_batch_id, e.ingest_row_ordinal, e.ingest_attempt_id, e.evidence_record_key FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM vi"
    },
    "candidate_data_stats": {
      "query_id": "964081d2-424b-4f57-be63-b8adbb7a70f4",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 29.45,
      "sql_preview": "SELECT e.selector_key FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM visible_evidence_generations FINAL WHERE case_id = {case_id:UInt32} ) AS veg ON veg.cas"
    },
    "verify_outcome": "duplicate_identical"
  },
  "heavier_retry_duplicate": {
    "n": 2000,
    "extra_full_copies": 1,
    "physical": 4000,
    "current_hunt_count": 4000,
    "candidate_hunt_count": 2000,
    "current_count_stats": {
      "query_id": "6e352af8-6cee-4ef8-bdcf-9e1c170926f0",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 26.008,
      "sql_preview": "SELECT count() AS n FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM visible_evidence_generations FINAL WHERE case_id = {case_id:UInt32} ) AS veg ON veg.case_"
    },
    "candidate_count_stats": {
      "query_id": "6d8978cb-ebe2-4da3-b117-53869f518964",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 23.254,
      "sql_preview": "SELECT countIf(e.source_ref_type IS NULL AND e.source_ref_id IS NULL AND e.source_generation IS NULL AND e.ingest_batch_id IS NULL AND e.ingest_row_ordinal IS NULL AND e.ingest_row_hash IS NULL AND e.ingest_attempt_id IS NULL) AS legacy_n, "
    },
    "current_data_stats": {
      "query_id": "6262ced9-9b1f-486c-aa03-1b600368768a",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 23.522,
      "sql_preview": "SELECT e.selector_key, e.ingest_batch_id, e.ingest_row_ordinal, e.ingest_attempt_id, e.evidence_record_key FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM vi"
    },
    "candidate_data_stats": {
      "query_id": "ba016687-145b-45ae-a910-d3efd5118c0a",
      "read_rows": 0,
      "read_bytes": 0,
      "duration_ms": 31.924,
      "sql_preview": "SELECT e.selector_key FROM events AS e LEFT JOIN ( SELECT case_id, source_ref_type, source_ref_id, source_generation, visibility_state, publishable FROM visible_evidence_generations FINAL WHERE case_id = {case_id:UInt32} ) AS veg ON veg.cas"
    },
    "verify_outcome": "duplicate_identical"
  }
}

No OPTIMIZE FINAL. No token/substring search change. Disposable fixtures only.

## 30. Regression Tests

{
  "all_passed": true,
  "skipped_detected": false,
  "modules": [
    {
      "module": "tests.test_phase2_4a_retry_copy_gap_audit",
      "ok": true,
      "returncode": 0,
      "duration_s": 6.675,
      "tail": ".......................                                                  [100%]\n=============================== warnings summary ===============================\ntests/test_phase2_4a_retry_copy_gap_audit.py: 10 warnings\n  /opt/casescope/venv/lib/python3.12/site-packages/sqlalchemy/sql/schema.py:3624: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    return util.wrap_callable(lambda ctx: fn(), fn)  # type: ignore\n\n-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n23 passed, 10 warnings in 4.34s"
    },
    {
      "module": "tests.test_phase1b_tranche_b_protocol",
      "ok": true,
      "returncode": 0,
      "duration_s": 5.66,
      "tail": ".............                                                            [100%]\n=============================== warnings summary ===============================\ntests/test_phase1b_tranche_b_protocol.py: 59 warnings\n  /opt/casescope/venv/lib/python3.12/site-packages/sqlalchemy/sql/schema.py:3624: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    return util.wrap_callable(lambda ctx: fn(), fn)  # type: ignore\n\n-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n13 passed, 59 warnings in 3.50s"
    },
    {
      "module": "tests.test_phase1b_tranche_d2_staged_reconciler",
      "ok": true,
      "returncode": 0,
      "duration_s": 10.332,
      "tail": "ed_and_uses_stale_eligibility\ntests/test_phase1b_tranche_d2_staged_reconciler.py::Phase1BD2RealPGCHTestCase::test_discovery_is_bounded_and_uses_stale_eligibility\ntests/test_phase1b_tranche_d2_staged_reconciler.py::Phase1BD2RealPGCHTestCase::test_discovery_is_bounded_and_uses_stale_eligibility\ntests/test_phase1b_tranche_d2_staged_reconciler.py::Phase1BD2RealPGCHTestCase::test_discovery_is_bounded_and_uses_stale_eligibility\ntests/test_phase1b_tranche_d2_staged_reconciler.py::Phase1BD2RealPGCHTestCase::test_discovery_is_bounded_and_uses_stale_eligibility\n  /opt/casescope/tests/test_phase1b_tranche_d2_staged_reconciler.py:593: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)\n\ntests/test_phase1b_tranche_d2_staged_reconciler.py::Phase1BD2RealPGCHTestCase::test_live_writer_is_not_reconciled_until_attempt_lease_expires\n  /opt/casescope/tests/test_phase1b_tranche_d2_staged_reconciler.py:342: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    attempt.lease_expires_at = datetime.utcnow() + timedelta(hours=1)\n\ntests/test_phase1b_tranche_d2_staged_reconciler.py::Phase1BD2RealPGCHTestCase::test_live_writer_is_not_reconciled_until_attempt_lease_expires\n  /opt/casescope/tests/test_phase1b_tranche_d2_staged_reconciler.py:354: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)\n\ntests/test_phase1b_tranche_d2_staged_reconciler.py::Phase1BD2RealPGCHTestCase::test_purge_crash_recovery_requires_next_pass_to_reinspect_and_prove_zero\n  /opt/casescope/tests/test_phase1b_tranche_d2_staged_reconciler.py:485: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    batch.reconcile_lease_expires_at = datetime.utcnow() - timedelta(seconds=1)\n\n-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n14 passed, 172 warnings in 8.41s"
    },
    {
      "module": "tests.test_phase1b_tranche_d1_generation_lifecycle",
      "ok": true,
      "returncode": 0,
      "duration_s": 56.617,
      "tail": " = CaseFile.query.get(case_file_id)\n\ntests/test_phase1b_tranche_d1_generation_lifecycle.py::Phase1BD1LifecycleUnitTestCase::test_single_file_rebuild_routes_managed_active_to_replacement_without_delete_scope\ntests/test_phase1b_tranche_d1_generation_lifecycle.py::Phase1BD1LifecycleUnitTestCase::test_single_file_rebuild_routes_managed_building_initial_without_delete_scope\ntests/test_phase1b_tranche_d1_generation_lifecycle.py::Phase1BD1RealPGCHTestCase::test_real_rebuild_task_managed_active_uses_replacement_lifecycle_with_cleanup_tripwires\n  /opt/casescope/models/audit_log.py:285: LegacyAPIWarning: The Query.get() method is considered legacy as of the 1.x series of SQLAlchemy and becomes a legacy construct in 2.0. The method is now available as Session.get() (deprecated since: 2.0) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)\n    client = Client.query.get(case.client_id)\n\ntests/test_phase1b_tranche_d1_generation_lifecycle.py::Phase1BD1LifecycleUnitTestCase::test_single_file_rebuild_routes_managed_active_to_replacement_without_delete_scope\ntests/test_phase1b_tranche_d1_generation_lifecycle.py::Phase1BD1LifecycleUnitTestCase::test_single_file_rebuild_routes_managed_building_initial_without_delete_scope\ntests/test_phase1b_tranche_d1_generation_lifecycle.py::Phase1BD1RealPGCHTestCase::test_real_rebuild_task_managed_active_uses_replacement_lifecycle_with_cleanup_tripwires\n  /opt/casescope/models/audit_log.py:235: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    self.timestamp = datetime.utcnow()\n\ntests/test_phase1b_tranche_d1_generation_lifecycle.py::Phase1BD1RealPGCHTestCase::test_real_rebuild_task_managed_active_uses_replacement_lifecycle_with_cleanup_tripwires\ntests/test_phase1b_tranche_d1_generation_lifecycle.py::Phase1BD1RealPGCHTestCase::test_real_rebuild_task_managed_active_uses_replacement_lifecycle_with_cleanup_tripwires\n  /opt/casescope/tasks/celery_tasks.py:1665: LegacyAPIWarning: The Query.get() method is considered legacy as of the 1.x series of SQLAlchemy and becomes a legacy construct in 2.0. The method is now available as Session.get() (deprecated since: 2.0) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)\n    case = Case.query.get(case_id)\n\n-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n16 passed, 180 warnings, 6 subtests passed in 54.16s"
    },
    {
      "module": "tests.test_phase1b_tranche_e1_capability_watermarks",
      "ok": true,
      "returncode": 0,
      "duration_s": 10.174,
      "tail": "removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    batch.durable_at = datetime.utcnow()\n\ntests/test_phase1b_tranche_e1_capability_watermarks.py::Phase1BE1RealPGCHTestCase::test_d2_does_not_mark_capability_complete_then_late_hole_advances\ntests/test_phase1b_tranche_e1_capability_watermarks.py::Phase1BE1RealPGCHTestCase::test_d2_does_not_mark_capability_complete_then_late_hole_advances\ntests/test_phase1b_tranche_e1_capability_watermarks.py::Phase1BE1RealPGCHTestCase::test_d2_does_not_mark_capability_complete_then_late_hole_advances\ntests/test_phase1b_tranche_e1_capability_watermarks.py::Phase1BE1RealPGCHTestCase::test_iis_row_local_privacy_watermark_and_erk_coverage\ntests/test_phase1b_tranche_e1_capability_watermarks.py::Phase1BE1RealPGCHTestCase::test_iis_row_local_privacy_watermark_and_erk_coverage\ntests/test_phase1b_tranche_e1_capability_watermarks.py::Phase1BE1RealPGCHTestCase::test_iis_row_local_privacy_watermark_and_erk_coverage\ntests/test_phase1b_tranche_e1_capability_watermarks.py::Phase1BE1RealPGCHTestCase::test_iis_row_local_privacy_watermark_and_erk_coverage\n  /opt/casescope/models/case.py:190: LegacyAPIWarning: The Query.get() method is considered legacy as of the 1.x series of SQLAlchemy and becomes a legacy construct in 2.0. The method is now available as Session.get() (deprecated since: 2.0) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)\n    return Case._enforce_access(Case.query.get(case_id))\n\ntests/test_phase1b_tranche_e1_capability_watermarks.py: 11 warnings\n  /opt/casescope/utils/privacy_aliases.py:1516: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    existing.updated_at = datetime.utcnow()\n\ntests/test_phase1b_tranche_e1_capability_watermarks.py::Phase1BE1RealPGCHTestCase::test_d2_does_not_mark_capability_complete_then_late_hole_advances\n  /opt/casescope/tests/test_phase1b_tranche_e1_capability_watermarks.py:914: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    finish_attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)\n\n-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n19 passed, 486 warnings in 8.18s"
    },
    {
      "module": "tests.test_phase1b_tranche_f1_completion_reconciliation",
      "ok": true,
      "returncode": 0,
      "duration_s": 10.471,
      "tail": "scope/tests/test_phase1b_tranche_f1_completion_reconciliation.py:1028: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    attempt.finished_at = datetime.utcnow()\n\ntests/test_phase1b_tranche_f1_completion_reconciliation.py::Phase1BF1RealPGCHTestCase::test_iis_three_batch_reconciliation_pilot\n  /opt/casescope/tests/test_phase1b_tranche_f1_completion_reconciliation.py:1029: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)\n\ntests/test_phase1b_tranche_f1_completion_reconciliation.py::Phase1BF1RealPGCHTestCase::test_iis_three_batch_reconciliation_pilot\ntests/test_phase1b_tranche_f1_completion_reconciliation.py::Phase1BF1RealPGCHTestCase::test_iis_three_batch_reconciliation_pilot\ntests/test_phase1b_tranche_f1_completion_reconciliation.py::Phase1BF1RealPGCHTestCase::test_iis_three_batch_reconciliation_pilot\ntests/test_phase1b_tranche_f1_completion_reconciliation.py::Phase1BF1RealPGCHTestCase::test_managed_completion_task_skips_legacy_destructive_paths\ntests/test_phase1b_tranche_f1_completion_reconciliation.py::Phase1BF1RealPGCHTestCase::test_old_generation_evidence_survives_reconciliation\n  /opt/casescope/models/case.py:190: LegacyAPIWarning: The Query.get() method is considered legacy as of the 1.x series of SQLAlchemy and becomes a legacy construct in 2.0. The method is now available as Session.get() (deprecated since: 2.0) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)\n    return Case._enforce_access(Case.query.get(case_id))\n\ntests/test_phase1b_tranche_f1_completion_reconciliation.py::Phase1BF1RealPGCHTestCase::test_iis_three_batch_reconciliation_pilot\ntests/test_phase1b_tranche_f1_completion_reconciliation.py::Phase1BF1RealPGCHTestCase::test_iis_three_batch_reconciliation_pilot\n  /opt/casescope/utils/privacy_aliases.py:1516: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    existing.updated_at = datetime.utcnow()\n\n-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n36 passed, 429 warnings in 8.46s"
    },
    {
      "module": "tests.test_phase1b_tranche_f2_product_search_publication_gate",
      "ok": true,
      "returncode": 0,
      "duration_s": 19.853,
      "tail": "...........                                                              [100%]\n=============================== warnings summary ===============================\ntests/test_phase1b_tranche_f2_product_search_publication_gate.py: 99 warnings\n  /opt/casescope/venv/lib/python3.12/site-packages/sqlalchemy/sql/schema.py:3624: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    return util.wrap_callable(lambda ctx: fn(), fn)  # type: ignore\n\ntests/test_phase1b_tranche_f2_product_search_publication_gate.py: 92 warnings\n  /opt/casescope/models/case.py:190: LegacyAPIWarning: The Query.get() method is considered legacy as of the 1.x series of SQLAlchemy and becomes a legacy construct in 2.0. The method is now available as Session.get() (deprecated since: 2.0) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)\n    return Case._enforce_access(Case.query.get(case_id))\n\ntests/test_phase1b_tranche_f2_product_search_publication_gate.py: 25 warnings\n  /opt/casescope/routes/hunting.py:50: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    timestamp = datetime.utcnow().strftime(\"%Y%m%d_%H%M%S\")\n\ntests/test_phase1b_tranche_f2_product_search_publication_gate.py::Phase1BF2ProductSearchPublicationGateTestCase::test_export_tagged_obeys_phase1b_publication\ntests/test_phase1b_tranche_f2_product_search_publication_gate.py::Phase1BF2ProductSearchPublicationGateTestCase::test_export_tagged_obeys_phase1b_publication\ntests/test_phase1b_tranche_f2_product_search_publication_gate.py::Phase1BF2ProductSearchPublicationGateTestCase::test_export_tagged_obeys_phase1b_publication\ntests/test_phase1b_tranche_f2_product_search_publication_gate.py::Phase1BF2ProductSearchPublicationGateTestCase::test_export_tagged_obeys_phase1b_publication\n  /opt/casescope/models/audit_log.py:235: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    self.timestamp = datetime.utcnow()\n\n-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n11 passed, 220 warnings in 17.92s"
    },
    {
      "module": "tests.test_phase1b_tranche_e2_ai_privacy_freeze_verify",
      "ok": true,
      "returncode": 0,
      "duration_s": 20.916,
      "tail": "e_verify.py:223: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    verified_at=datetime.utcnow(),\n\ntests/test_phase1b_tranche_e2_ai_privacy_freeze_verify.py: 1109 warnings\n  /opt/casescope/venv/lib/python3.12/site-packages/sqlalchemy/sql/schema.py:3624: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    return util.wrap_callable(lambda ctx: fn(), fn)  # type: ignore\n\ntests/test_phase1b_tranche_e2_ai_privacy_freeze_verify.py: 35 warnings\n  /opt/casescope/models/case.py:190: LegacyAPIWarning: The Query.get() method is considered legacy as of the 1.x series of SQLAlchemy and becomes a legacy construct in 2.0. The method is now available as Session.get() (deprecated since: 2.0) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)\n    return Case._enforce_access(Case.query.get(case_id))\n\ntests/test_phase1b_tranche_e2_ai_privacy_freeze_verify.py: 82 warnings\n  /opt/casescope/utils/privacy_aliases.py:1516: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    existing.updated_at = datetime.utcnow()\n\ntests/test_phase1b_tranche_e2_ai_privacy_freeze_verify.py: 20 warnings\n  /opt/casescope/utils/privacy_aliases.py:625: LegacyAPIWarning: The Query.get() method is considered legacy as of the 1.x series of SQLAlchemy and becomes a legacy construct in 2.0. The method is now available as Session.get() (deprecated since: 2.0) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)\n    case = Case.query.get(case_id)\n\ntests/test_phase1b_tranche_e2_ai_privacy_freeze_verify.py::Phase1BE2RealPGCHTestCase::test_d2_repair_then_new_freeze_succeeds\n  /opt/casescope/tests/test_phase1b_tranche_e2_ai_privacy_freeze_verify.py:1041: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    finish_attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)\n\n-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n53 passed, 1259 warnings in 19.07s"
    },
    {
      "module": "tests.test_privacy_alias_vault_bounds",
      "ok": true,
      "returncode": 0,
      "duration_s": 2.0,
      "tail": "............                                                       [100%]\n12 passed, 6 subtests passed in 1.04s"
    },
    {
      "module": "tests.test_privacy_fail_closed",
      "ok": true,
      "returncode": 0,
      "duration_s": 2.32,
      "tail": "..........                                                         [100%]\n10 passed, 6 subtests passed in 1.15s"
    },
    {
      "module": "tests.test_phase2_2b_sync_event_insert",
      "ok": true,
      "returncode": 0,
      "duration_s": 7.798,
      "tail": "..................                                                       [100%]\n=============================== warnings summary ===============================\ntests/test_phase2_2b_sync_event_insert.py: 36 warnings\n  /opt/casescope/venv/lib/python3.12/site-packages/sqlalchemy/sql/schema.py:3624: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    return util.wrap_callable(lambda ctx: fn(), fn)  # type: ignore\n\n-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n18 passed, 36 warnings in 5.90s"
    },
    {
      "module": "tests.test_phase2_3_lightweight_update_bridge",
      "ok": true,
      "returncode": 0,
      "duration_s": 4.31,
      "tail": "..................................                                       [100%]\n34 passed in 3.18s"
    },
    {
      "module": "tests.test_phase2_3c_fence_contract_alignment",
      "ok": true,
      "returncode": 0,
      "duration_s": 2.659,
      "tail": "...............                                                          [100%]\n15 passed in 1.54s"
    },
    {
      "module": "tests.test_event_analyst_state",
      "ok": true,
      "returncode": 0,
      "duration_s": 0.805,
      "tail": ".....                                                                    [100%]\n5 passed in 0.23s"
    },
    {
      "module": "tests.test_event_noise_state",
      "ok": true,
      "returncode": 0,
      "duration_s": 0.978,
      "tail": "...                                                                      [100%]\n3 passed in 0.38s"
    },
    {
      "module": "tests.test_clickhouse_delete_dedup_contracts",
      "ok": true,
      "returncode": 0,
      "duration_s": 4.18,
      "tail": "...................................                                      [100%]\n=============================== warnings summary ===============================\ntests/test_clickhouse_delete_dedup_contracts.py::CompletionTaskContractTestCase::test_case_indexing_complete_reports_skipped_buffer_flush_and_passes_auto_dedup_threshold\n  /opt/casescope/utils/case_work.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).\n    timestamp=datetime.utcnow(),\n\n-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n35 passed, 1 warning in 2.37s"
    }
  ],
  "lint": {
    "py_compile_ok": true,
    "py_compile_stderr": "",
    "pyflakes_ok": true,
    "pyflakes_stdout": "",
    "git_diff_check_ok": true,
    "git_diff_check_stdout": ""
  },
  "phase1b_pg_test_database": "phase2_4a_reg",
  "phase1b_ch_test_database": "phase2_4a_reg"
}

## 31. Files Changed

- scripts/phase2_4a_retry_copy_gap_audit.py
- tests/test_phase2_4a_retry_copy_gap_audit.py
- docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.md
- docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.json

## 32. Version

4.26.2

## 33. Production Mutation Audit

NONE

{
  "production_insert": false,
  "production_update": false,
  "production_alter": false,
  "production_delete": false,
  "production_optimize": false,
  "production_materialize": false,
  "production_pg_manifest_mutation": false,
  "production_redis_mutation": false,
  "production_analyst_noise_mutation": false,
  "production_test_ingest": false,
  "service_restart": false,
  "result": "NONE"
}

## 34. No-Later-Phase Audit

{
  "lek": false,
  "events_current": false,
  "event_observations_current": false,
  "erk_api_migration": false,
  "qdrant_identity_migration": false,
  "ioc_overlay_pilot": false,
  "semantic_dedup": false,
  "cross_source_collapse": false,
  "same_erk_collapse": false,
  "rmt": false,
  "new_clickhouse_engine": false,
  "whole_case_dedup_redesign": false,
  "legacy_dedup_removal": false,
  "phase4_reader_cutover": false,
  "phase4_canonical_representative": false,
  "phase6_derivation_migration": false,
  "phase2_exit_declared": false,
  "master_plan_edited": false,
  "version_bumped": false
}

## 35. Git State

{
  "commit_requested_by_user": true,
  "spec_said_leave_uncommitted": true,
  "note": "User first-line instruction was to commit and push when done."
}

## 36. Phase 2.4 State

PHASE2_4B_SCOPE_READY

2.4A does not close Phase 2.4.

## 37. Remaining Work

Independent Phase 2.4A review.

Then only: Phase 2.4B — implement the independently accepted minimal interim
generation-accounting / deterministic retry-copy exclusion.

Phase 2.4B must also perform the locked Phase 2 EXIT baseline rerun because
2.4 is the final Phase 2 work.

Do NOT start Phase 3.

## 38. Verdict

PHASE2_4A_PASS

