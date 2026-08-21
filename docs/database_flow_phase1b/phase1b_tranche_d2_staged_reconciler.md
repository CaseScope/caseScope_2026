# Phase 1B Tranche D2 Stale STAGED Batch Reconciler

## Scope

Tranche D2 implements deterministic recovery for PostgreSQL `ingest_batches` left `STAGED` after interruption. PostgreSQL remains manifest authority; ClickHouse is inspected only as physical evidence for the exact `ingest_batch_id`.

D2 does not implement capability watermarks, derivation migration, AI freeze/verify, reader cutover, `events_current`, LEK migration, graph/Qdrant lifecycle migration, memory/PCAP protocols, historical backfill, or Tranche E.

## Stale Eligibility

`STAGED` alone is not stale.

A batch may be reconciled only when PostgreSQL proves the producing attempt is no longer entitled to write:

- the producing attempt is terminal (`SUCCEEDED`, `FAILED`, `CANCELLED`, `REVOKED`);
- the producing attempt is `STARTED` and its durable lease has expired;
- no producing attempt is attached to the batch.

New manifest attempts now carry `heartbeat_at`, `lease_expires_at`, and `updated_at`. Managed writers refresh the lease around batch reservation, insertion, verification, and durable transition. If a `STARTED` attempt has a future lease, the reconciler returns `skipped_not_stale` and performs no ClickHouse mutation, no retry scheduling, and no durable promotion.

## Reconcile Ownership And Concurrency

The reconciler claims a batch by setting `ingest_batches.reconcile_owner` and `reconcile_lease_expires_at` under `FOR UPDATE OF ingest_batches`, then commits before ClickHouse inspection or mutation. This avoids holding a PostgreSQL row lock across a ClickHouse mutation while preserving a bounded crash-recoverable claim.

Before promotion, purge, or retry creation, the reconciler re-locks the PostgreSQL batch and revalidates:

- claim owner and lease;
- batch still `STAGED`;
- frozen manifest fields unchanged;
- generation state still allows the action.

Concurrent reconcilers serialize on the PostgreSQL batch row. The real PG concurrency test proves one owner performs `STAGED -> DURABLE`; the second returns a deterministic skip after the first transition.

## ClickHouse Inspection

D2 queries ClickHouse only by deterministic `ingest_batch_id`:

```sql
SELECT
    ingest_row_ordinal,
    ingest_row_hash,
    count() AS physical_copies
FROM events
WHERE ingest_batch_id = {id:String}
GROUP BY ingest_row_ordinal, ingest_row_hash
```

The observation reconstructs physical row count, ordinal set, physical copies per ordinal/hash, collapsed logical rows, and the aggregate content hash using the locked `ingest-batch:v1` binary framing helper.

No case-wide counts, timestamps, attempt IDs, task states, filenames, case IDs, source generations, or batch ordinals are used as content-equivalence evidence.

## Classifier Precedence

D2 classification is deterministic:

1. malformed manifest;
2. duplicate ordinal with different hash;
3. hash mismatch;
4. extra ordinal;
5. aggregate hash mismatch;
6. partial/missing ordinal;
7. absent;
8. duplicate ordinal with identical hash;
9. exact.

Conflict states take precedence over retryable partial states. A batch with both a missing ordinal and a conflicting duplicate is fail-closed as `duplicate_different`.

## Outcome Table

| CH state | D2 action |
|---|---|
| absent | Keep `STAGED`, create a new recovery `ingest_attempt_id`, preserve source generation and batch ID, schedule same-batch retry. |
| exact | Mark PostgreSQL batch `DURABLE`; no reinsertion and no purge. |
| partial / missing ordinal | Fail closed for publication, targeted purge by `ingest_batch_id`, wait for mutation completion, prove zero rows, create a new recovery attempt, schedule same-batch retry. |
| duplicate ordinal / identical hash | Accept retry-equivalent collapsed proof and mark `DURABLE` without rewriting physical duplicates. |
| duplicate ordinal / different hash | Fail closed, no durable promotion, no purge/retry loop. |
| hash mismatch | Fail closed, no durable promotion, no purge/retry loop. |
| extra ordinal | Fail closed, no automatic retry. D2 leaves physical rows in place for explicit operator recovery rather than silently rewriting evidence conflict. |
| aggregate hash mismatch | Fail closed as a contract violation. |

## Targeted Purge Mechanics

The only destructive recovery mutation uses:

```text
ALTER TABLE events DELETE WHERE ingest_batch_id = '<target batch>'
```

The existing mutation wait helper blocks until the ClickHouse mutation is complete. D2 then performs an explicit `SELECT count() FROM events WHERE ingest_batch_id = ...` and creates the retry attempt only after the count is zero.

Tripwire tests patch case-wide and CaseFile-wide delete helpers to raise; D2 partial and replacement recovery still pass.

## Retry Semantics

Recovery creates a new `ingest_attempt_id` for execution identity only. It preserves:

- source generation;
- `ingest_batch_id`;
- batch ordinal;
- expected row count;
- expected row hashes;
- `batch_content_hash`;
- frozen generation contract.

The operational recovery task deterministically re-enumerates the same managed CASE_FILE source until the target batch ordinal is reproduced, then inserts only that target batch. It does not pretend random seeking exists, does not touch prior durable batches, does not create later manifests, and does not declare EOF or activate the generation.

Automatic recovery attempts are bounded by `reconcile_attempt_count`; conflict outcomes are recorded as fail-closed and are not retried automatically.

## Generation-State Behavior

- `BUILDING_INITIAL`: stale STAGED recovery and exact promotion are allowed.
- `BUILDING_REPLACEMENT`: stale STAGED recovery and exact promotion are allowed while the prior `ACTIVE` generation remains unchanged and hiddenness is preserved.
- `ACTIVE`: a STAGED batch is treated as an invariant violation and is not repaired or published.
- `SUPERSEDED`: no recovery or publication.
- `FAILED`: no automatic retry or publication.
- `INVALIDATED`: no automatic retry or publication.

D2 never declares EOF, computes a new final batch ordinal, increases expected rows, or activates a generation because known STAGED batches became `DURABLE`. Activation remains D1 authority.

## Auditability

Each reconciliation decision writes `ingest_batch_reconciliation_audit` with batch/source identity, prior batch state, classification, physical and collapsed counts, missing/extra/conflicting/hash-mismatch ordinals, expected and actual aggregate hashes, action taken, recovery attempt ID when created, owner, reason, and timestamp.

The batch row also records the latest reconcile outcome/error and bounded attempt count for operational visibility and loop control.

## Execution Entry

D2 adds:

- `tasks.reconcile_stale_staged_ingest_batches`: bounded scan and reconcile task;
- `tasks.recover_staged_ingest_batch`: batch-local deterministic replay task.

No periodic scheduler is enabled in D2. Scheduling can be added in a later operational tranche without changing reconciliation semantics.

## Discovery And Index

Discovery is bounded with a caller-provided limit and stable ordering over `STAGED` batches. The additive indexes are:

- `idx_ingest_batch_staged_updated(state, updated_at, id)`;
- `idx_ingest_batch_reconcile_claim(state, reconcile_lease_expires_at, id)`;
- `idx_ingest_attempt_lease_expires(lease_expires_at)`.

The query loads a bounded candidate set, applies stale eligibility, and uses `FOR UPDATE SKIP LOCKED` semantics where supported.

## Real PG/CH Evidence

Focused D2 real PostgreSQL/ClickHouse suite:

- `tests/test_phase1b_tranche_d2_staged_reconciler.py`: 14 passed.

Covered cases:

- active writer skipped until lease expiry;
- absent CH rows create same-batch recovery attempt;
- exact CH rows mark `DURABLE` without reinsertion;
- partial rows target-purge by `ingest_batch_id`, wait, prove zero, then retry;
- duplicate-identical collapsed proof marks `DURABLE` while preserving physical copies;
- duplicate-different, hash mismatch, extra ordinal, and aggregate mismatch fail closed;
- purge crash requires the next pass to reinspect and prove zero before retry;
- two-batch same-generation isolation;
- prior `ACTIVE` generation isolation during N+1 replacement recovery;
- `ACTIVE` generation STAGED invariant violation;
- real PG concurrent reconciler serialization;
- bounded stale discovery.

## Performance And Operability

The focused real suite ran 14 tests in 8.39 seconds including setup, ClickHouse mutations, proof queries, and teardown. D2 result objects expose timings for PostgreSQL claim, ClickHouse inspection, targeted purge, and PostgreSQL transition. Memory use is bounded by scan limit and by one batch observation grouped by ordinal/hash.

## No-Cutover Audit

- Capability watermarks: no.
- Derivation migration: no.
- AI freeze/verify: no.
- Reader migration: no.
- `events_current`: no.
- LEK cutover: no.
- Graph lifecycle migration: no.
- Qdrant lifecycle migration: no.
- Memory/PCAP protocol: no.

## Verdict

D2 implements stale-STAGED batch reconciliation without starting Tranche E.
