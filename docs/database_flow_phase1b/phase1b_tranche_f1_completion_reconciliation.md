# Phase 1B Tranche F1 — Completion Becomes Durable Reconciliation

Status: implemented on live main, plus F1 closure fail-closed composition hardening. Does not implement Tranche F2 or G.

## Current completion architecture before F1

The live path was:

1. `CaseFile` finishes
2. Redis `increment_progress`
3. Last file sets Redis `status=complete`
4. `mark_completion_triggered` (SETNX)
5. `case_indexing_complete_task`
6. Exclusive ingest fence, optional `events_buffer` OPTIMIZE, case-wide ClickHouse dedup, known systems/users, cleanup, ingest summary, MITRE/embed/graph queues, Redis progress clear

Managed manifest parsing set `trigger_completion=False`, but that only skipped `processed_at`. Redis last-file completion still fired the whole-case tail, including for managed files.

## Legacy vs managed routing

`resolve_case_completion_route` classifies from PostgreSQL:

- `legacy_only` — no `evidence_source_generations`; existing exclusive-fence tail is preserved
- `managed_only` — only managed generations; durable reconciliation, no destructive tail
- `mixed` — legacy files plus managed generations; durable reconciliation, no case-wide destructive tail

Routing happens before fence, Buffer OPTIMIZE, or `deduplicate_case_events`.

## Mixed-case handling

A mixed case never uses Redis last-file counters as permission to rewrite managed generation evidence. Legacy compatibility work that remains is non-destructive (summary/audit). Known-user/system, MITRE, and embedding jobs may be queued once per generation fingerprint as transitional whole-case work only when no generation is BUILDING. They are not Phase 1B capability COMPLETE.

## Reconciliation authority

PostgreSQL is authority:

- `evidence_source_generations`
- `ingest_batches` / `ingest_attempts`
- `case_capability_source_state` / `case_capability_batch_completions`
- `graph_projection_state` where present

Redis may debounce `reconcile_case_completion_task`. Redis loss cannot mark a case complete or suppress reconciliation. There is no `case.ready` / `case.ai_ready` / `case.processing_complete` boolean.

Engine: `utils/completion_reconciler.py`

- `reconcile_case_ingest`
- `reconcile_case_derivations`
- `reconcile_case_completion`

Assessments: `reconciled`, `work_queued`, `in_progress`, `incomplete_ingest`, `blocked`, `deferred`, `failed`. A successful execution may still report deferred or incomplete work.

## Derivation inventory / classification

See `COMPLETION_DERIVATION_INVENTORY`. Only `privacy_aliases` / `privacy-aliases:v1` / `ROW_LOCAL` is E1-migrated and F1-inspectable as capability COMPLETE. IOC, MITRE, graph capability watermarks, known principals, behavioral profiles, pattern detection, and embeddings remain deferred/unverifiable for Phase 1B capability authority.

## Per-class reconciliation behavior

- `ROW_LOCAL` (privacy): DURABLE + missing completion → queue/run existing incremental derivation. STAGED → D2 handoff, never privacy. Terminal generations are not requeued.
- `ADDITIVE_AGGREGATE` / `WINDOWED_STATEFUL` / `WHOLE_CASE`: not faked as batch watermarks. Graph uses `GraphProjectionState` only. Others stay deferred unless a transitional whole-case marker says they were never queued for the current generation fingerprint.

## D2 handoff

F1 does not classify, purge, or rewrite STAGED batches. Stale BUILDING STAGED batches are handed to `reconcile_staged_batch`. ACTIVE + STAGED is an invariant violation: `blocked`, no silent repair. D2 remains the stale-batch authority.

## E1 watermark reconciliation

Eligible DURABLE batches are compared to `case_capability_batch_completions` for `privacy-aliases:v1`. Re-runs are idempotent. BUILDING_REPLACEMENT may derive but never becomes default authority. SUPERSEDED / FAILED / INVALIDATED coverage does not satisfy current gates.

## Legacy compatibility behavior

Legacy-only cases keep Redis progress, last-file completion, exclusive fence, optional Buffer OPTIMIZE, and case-wide dedup. Feature flags remain default off. Already-managed sources still reconcile if the global manifest flag is later turned off.

## Destructive-tail protection

`deduplicate_case_events` raises `ManagedEvidenceDedupForbidden` when managed generations exist. Managed/mixed completion never calls case-wide dedup, CaseFile-wide event rewrite, or Buffer-required logic. Managed-only tests patch those paths to raise.

## Redis non-authority proof

Reconciliation reads only control-plane PostgreSQL. Tests delete/break Redis and still detect DURABLE batches, missing privacy, STAGED/D2 gaps, and generation state.

## Idempotency / concurrency

Repeat runs against current state queue no duplicate privacy, D2, graph, or expensive whole-case jobs. Concurrent workers rely on existing unique completion rows, D2 claims, and graph projection state. No PostgreSQL lock is held across ClickHouse or Celery work.

## Audit design

Each run writes `case_completion_reconciliation_audit` plus best-effort `AuditLog` (`reconciled`) and `CaseWork` (`completion_reconciliation`). The audit is a snapshot, not a permanent ready latch. `_build_case_ingest_summary` adds a `phase1b` read-model fragment from PG.

## Race behavior

- New source/batch after snapshot: no case-complete latch; later readiness/reconciliation sees it
- Replacement activation during a run: final re-read sets `authority_changed` / `blocked`; next run uses the new ACTIVE generation
- Zero-event: EOF with `expected_rows=0`, `final_batch_ordinal=NULL`, no invented batch 0

## Real PostgreSQL / ClickHouse proof

Disposable PG/CH tests cover managed multi-batch IIS (`privacy-aliases:v1`), D2 promotion then privacy, BUILDING_INITIAL / ACTIVE / REPLACEMENT, Redis loss, concurrency, mixed-case dedup refusal, evidence survival, and legacy-only routing.

## Performance

Reconciliation walks generation/batch/watermark rows only. ClickHouse is used only when an executor actually runs a derivation or D2 inspect. Tests assert bounded row loads and sub-15s IIS pilot duration.

## Deferred / unverifiable derivations

`ioc_matches`, `mitre_matches`, `graph_extraction` (capability watermark), `known_principal_discovery`, `behavioral_profile_contribution`, `pattern_detection`, and `event_embeddings` are reported deferred. F1 does not write Phase 1B COMPLETE for them.

## No-F2 / no-G audit

Not implemented: readiness strip, search-during-ingest coverage note, analyst UI readiness, `events_current`, LEK reader cutover, graph Phase 6 lifecycle, Qdrant lifecycle, MEMORY_JOB/PCAP_FILE managed protocol.

## F1 CLOSURE — FAIL-CLOSED COMPLETION COMPOSITION

Independent review found a real fail-open after the original `PHASE1B_TRANCHE_F1_PASS` report. The F1 design is unchanged: PostgreSQL remains completion authority, Redis may debounce, and proven `legacy_only` still keeps the existing exclusive-fence tail. This closure only stops uncertainty from becoming permission.

### Original fail-open

Three connected paths treated authority-read failure as "no managed evidence":

1. **Classification helper.** `classify_case_ingest_composition()` caught any `EvidenceSourceGeneration` query exception and returned `legacy_only`. A PostgreSQL outage, schema mismatch, or missing control-plane table therefore looked like a proven legacy case.
2. **Completion task routing.** `case_indexing_complete_task` caught `resolve_case_completion_route()` failure and assigned `legacy_only`, which entered the exclusive ingest fence, optional `events_buffer` OPTIMIZE, case-wide destructive dedup, and the legacy known-systems/users/MITRE/embed/graph tail.
3. **Dedup guard.** `case_has_managed_source_generations()` returned `False` on `ProgrammingError`, `OperationalError`, and generic exceptions. `deduplicate_case_events(..., allow_managed_evidence=False)` treated that `False` as permission to rewrite.

`UNKNOWN != ABSENT`. Failure to read composition authority does not prove a legacy-only case.

### Corrected proven-legacy semantics

`resolve_case_completion_route()` returns only a proven composition:

- `legacy_only`
- `managed_only`
- `mixed`

Authority-read failures raise `CompletionCompositionUnknown`. That exception is not a durable case state and is not a global readiness value.

`legacy_only` is positively established only when:

- the `EvidenceSourceGeneration` query succeeds
- zero managed generations are found
- the `CaseFile` classification query also succeeds enough to establish legacy composition

A missing `case_uuid` cannot prove composition. Query failure is never converted into an empty collection.

### CaseFile classification failure

The second half of classification used `files = []` when the `CaseFile` query failed. That could misclassify managed+legacy as `managed_only`, or invent `legacy_only` from incomplete information. A `CaseFile` query failure now fails closed whenever that data is required to distinguish `managed_only` from `mixed` or to prove `legacy_only`.

### Completion task failure posture

`case_indexing_complete_task` no longer assigns `legacy_only` on classification failure.

On unknown composition it:

- logs a safe error
- does not enter the exclusive fence, Buffer OPTIMIZE, case-wide dedup, or legacy derivation tail
- does not clear Redis progress or the completion trigger
- defers with bounded retry: `_classification_retry_count` starts at 0, max 10 retries, countdown `min(30, 2 ** retry_count)` seconds (1, 2, 4, 8, 16, then 30)
- after 10 retries, raises `CompletionCompositionUnknown`

Redis reporting `complete` cannot authorize the destructive tail while PostgreSQL composition is unknown.

### Dedup authority guard

`case_has_managed_source_generations()` now returns a boolean only when the PostgreSQL probe succeeds:

- query succeeds + managed generation exists => `True` / block destructive dedup
- query succeeds + no managed generation exists => `False` / legacy dedup may proceed
- query fails => raise `ManagedEvidenceAuthorityUnavailable`

`deduplicate_case_events(..., allow_managed_evidence=False)` independently rechecks that authority before any ClickHouse client is created. Defense in depth is required: the completion route must be proven `legacy_only` before the old tail, and the dedup helper still fail-closes on its own probe.

### Missing-schema behavior

At 4.21 the Phase 1B control-plane tables are part of the deployed schema contract. A missing `evidence_source_generations` table is a schema/migration defect. It is not interpreted as a legacy installation. `ProgrammingError` / relation-absent fails closed.

### Direct dedup defense-in-depth

Production callers of case-wide destructive dedup:

- `case_indexing_complete_task` legacy tail, only after proven `legacy_only`
- `deduplicate_case_events_task` / manual `remove_duplicate_events` route

Both go through `deduplicate_case_events`. Probe failure cannot execute `ALTER TABLE events DELETE`. `deduplicate_artifact_type` is only reached after the case-wide guard.

### Real PostgreSQL / ClickHouse proof

Disposable PG/CH tests prove:

- proven `legacy_only` may run allowed legacy dedup
- managed and mixed cases cannot run legacy dedup
- PostgreSQL authority failure before composition cannot enter the old tail
- PostgreSQL authority failure inside the direct dedup guard cannot execute a ClickHouse mutation
- renaming the generation table (missing schema) cannot classify the install as legacy
- Redis loss still does not become completion authority; Redis `complete` plus PG failure still cannot authorize destructive work

### Legacy behavior retained

This closure is fail-closed hardening, not removal of legacy dedup. Proven `legacy_only` still uses Redis progress, last-file completion, exclusive fence, optional Buffer OPTIMIZE, and case-wide dedup.
