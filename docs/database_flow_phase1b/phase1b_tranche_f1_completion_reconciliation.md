# Phase 1B Tranche F1 — Completion Becomes Durable Reconciliation

Status: implemented, uncommitted for review. Does not implement Tranche F2 or G.

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
