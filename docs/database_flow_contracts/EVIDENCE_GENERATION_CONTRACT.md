# Evidence Generation Contract

Status: LOCKED for Phase 0B. This is a lifecycle contract, not an implementation.

## Generic Source Identity

Every evidence source is identified by:

- `source_ref_type`
- `source_ref_id`
- `source_generation`

Initial source types:

- `CASE_FILE`
- `MEMORY_JOB`
- `PCAP_FILE`

`CASE_FILE` is implemented first later. The lifecycle is generic now so memory and PCAP migrations cannot invent incompatible semantics.

## Per-Generation States Versus Source-Level Operations

Generation state is a property of one `(source_ref_type, source_ref_id, source_generation)` row.

The source-level operation "replacement in progress" is derived, never a generation state:

```text
replacement_in_progress(source) :=
    EXISTS generation N with state = ACTIVE
    AND EXISTS generation N+k with state = BUILDING_REPLACEMENT
```

An existing `ACTIVE` generation does not change into the replacement generation. A replacement is always a newly allocated generation.

## State Machine

Allowed per-generation states:

- `BUILDING_INITIAL`
- `BUILDING_REPLACEMENT`
- `ACTIVE`
- `SUPERSEDED`
- `INVALIDATED`
- `FAILED`

Allowed transitions. The `From` column is the state of the same generation identified in `Actor generation`.

| Actor generation | From | To | Rule |
|---|---|---|---|
| N (first generation) | none | BUILDING_INITIAL | First generation allocation for a source. |
| N | BUILDING_INITIAL | ACTIVE | Initial generation completes all required batches/derivations for activation. |
| N | BUILDING_INITIAL | FAILED | Initial build cannot complete. Durable rows may exist but are not ACTIVE. |
| N+1 (new allocation) | none | BUILDING_REPLACEMENT | Explicit reprocess or semantic producer/version change allocates a NEW generation. Prior ACTIVE generation N is unchanged. |
| N+1 | BUILDING_REPLACEMENT | ACTIVE | Atomic authority switch succeeds. In the same PostgreSQL transaction, prior ACTIVE generation N becomes SUPERSEDED. |
| N+1 | BUILDING_REPLACEMENT | FAILED | Replacement build fails. Generation N remains ACTIVE and visible. Generation N+1 is never mixed into default surfaces. |
| N | ACTIVE | SUPERSEDED | Only inside the atomic activation transaction that sets generation N+1 ACTIVE. |
| any ACTIVE, BUILDING_*, or SUPERSEDED | current | INVALIDATED | Source deleted or interpretation revoked. |
| FAILED | FAILED | INVALIDATED | Failed generation cleaned up. |

Prohibited transitions (non-exhaustive; anything not listed above is prohibited):

- `ACTIVE -> BUILDING_REPLACEMENT` on the same generation.
- `ACTIVE -> BUILDING_INITIAL` on the same generation.
- `SUPERSEDED -> ACTIVE` without a new contract version.
- `FAILED -> ACTIVE` without a new contract version.
- Any in-place conversion of generation N into generation N+1.

No other transitions are allowed without a new contract version.

## First Ingest

Generation N = 1 for a source with no prior authoritative generation:

```text
allocation -> BUILDING_INITIAL
BUILDING_INITIAL -> ACTIVE on successful activation
BUILDING_INITIAL -> FAILED on failure
```

- Durable batches are progressively published as they become `DURABLE`.
- Product surfaces may show partial source coverage with coverage notes.
- If failure occurs before any durable batch, state becomes `FAILED` and nothing is published.
- If failure occurs after durable initial batches, published batches remain visible as an incomplete initial generation until retry/reconciliation either completes the same generation or marks it `FAILED` by explicit failure policy.

## Reprocess

Generation N is `ACTIVE`. Replacement allocates generation N+1:

```text
generation N:
    remains ACTIVE while replacement builds
    becomes SUPERSEDED only during successful atomic activation

generation N+1:
    allocation -> BUILDING_REPLACEMENT
    BUILDING_REPLACEMENT -> ACTIVE on successful atomic activation
    BUILDING_REPLACEMENT -> FAILED on failure
```

- Existing `ACTIVE` generation N remains published.
- Replacement rows and derivations of N+1 remain hidden from default surfaces.
- Failure of N+1 leaves N `ACTIVE` and visible.
- N never enters `BUILDING_REPLACEMENT`.

## Atomic Activation Transaction

Activation is one PostgreSQL-authoritative transaction. ClickHouse projections may lag; default readers must use PostgreSQL generation authority (projected into CH) and must never observe a mixture of old and replacement generations for the same source after commit.

Required preconditions, all checked under row locks:

- Generation N exists and `state = ACTIVE`.
- Generation N+1 exists and `state = BUILDING_REPLACEMENT`.
- No other `BUILDING_REPLACEMENT` generation exists for the source.
- N+1 has met activation completeness rules (required batches durable; required derivations verified per derivation contract).

Authoritative SQL shape (normative semantics, not a shipped migration):

```sql
BEGIN;

SELECT source_generation, state, state_version
FROM evidence_source_generation
WHERE case_id = :case_id
  AND source_ref_type = :source_ref_type
  AND source_ref_id = :source_ref_id
  AND source_generation IN (:n, :n_plus_1)
FOR UPDATE;

-- Must observe exactly:
--   :n        ACTIVE
--   :n_plus_1 BUILDING_REPLACEMENT
-- else ROLLBACK.

UPDATE evidence_source_generation
SET state = 'SUPERSEDED',
    state_version = state_version + 1,
    superseded_at = now(),
    superseded_by_generation = :n_plus_1
WHERE case_id = :case_id
  AND source_ref_type = :source_ref_type
  AND source_ref_id = :source_ref_id
  AND source_generation = :n
  AND state = 'ACTIVE';
-- Must update exactly 1 row else ROLLBACK.

UPDATE evidence_source_generation
SET state = 'ACTIVE',
    state_version = state_version + 1,
    activated_at = now()
WHERE case_id = :case_id
  AND source_ref_type = :source_ref_type
  AND source_ref_id = :source_ref_id
  AND source_generation = :n_plus_1
  AND state = 'BUILDING_REPLACEMENT';
-- Must update exactly 1 row else ROLLBACK.

INSERT INTO evidence_generation_audit (
  case_id, source_ref_type, source_ref_id,
  prior_active_generation, new_active_generation,
  actor, reason, occurred_at
) VALUES (
  :case_id, :source_ref_type, :source_ref_id,
  :n, :n_plus_1, :actor, :reason, now()
);

COMMIT;
```

The two state updates plus audit insert are one transaction. Partial visibility after commit is a defect.

CH `visible_evidence_generations` projection must reflect PostgreSQL after the transaction: N hidden as `SUPERSEDED`, N+1 visible as `ACTIVE`. Projection lag must not publish N+1 before N is unpublished.

## Failure, Retry, and Attempts

- `source_generation != ingest_attempt_id`.
- A task retry is not automatically a new generation.
- Retrying the same generation creates a new `ingest_attempt_id` and reuses deterministic batch IDs/content contracts.
- A parser or normalization semantic change requires a new generation only when the source is intentionally reinterpreted under that new version.

## Generation Allocation

- Per `(case_id, source_ref_type, source_ref_id)`, generation numbers are monotonically increasing positive integers.
- Allocation is PostgreSQL-authoritative.
- One open building generation per source is allowed at a time (`BUILDING_INITIAL` or `BUILDING_REPLACEMENT`).
- A new replacement cannot start while another replacement for the same source is building unless the earlier one is `FAILED` or `INVALIDATED`.
- Allocation of N+1 as `BUILDING_REPLACEMENT` does not mutate generation N.

## Version Triggers

New generation required:

- explicit analyst reprocess;
- parser version change that changes emitted event semantics;
- normalization version change that changes canonical row values, timestamps, ERK inputs, or LEK inputs;
- source repair that changes the authoritative interpretation of the source.

New generation not required:

- Celery retry;
- worker crash/restart;
- attempt timeout followed by retry with same frozen manifest;
- idempotent derivation rerun.

## Source Deletion and Invalidation

- Source deletion transitions all active/building/superseded generations for the source to `INVALIDATED` or schedules equivalent deletion-aware retraction.
- Invalidated generations are not visible on default surfaces.
- Audit must record actor, reason, prior state, replacement state when applicable, and timestamps.

## Rollback and Recovery

- Replacement rollback is state-based: failed replacement N+1 remains `FAILED` and hidden; previous generation N remains `ACTIVE` and visible.
- Initial-build recovery retries the same generation and attempts until the operator marks it `FAILED` or it completes.
- Reconciler may clean physical rows for failed/staged batches but must not delete published previous generation rows.

## Tests

Required before Phase 1B implementation. These are contract tests, not production DB writes in Phase 0B.

- CT-001: same source + retry keeps generation N.
- CT-002: explicit reprocess allocates N+1; N remains `ACTIVE` during build.
- CT-004: N+1 remains invisible until activation.
- CT-005: failed N+1 leaves N `ACTIVE`.
- CT-027: generation N never enters `BUILDING_REPLACEMENT` (allocation, reprocess, crash, and activation fixtures).
- CT-028: atomic activation updates N `ACTIVE -> SUPERSEDED` and N+1 `BUILDING_REPLACEMENT -> ACTIVE` in one PostgreSQL transaction; a mid-transaction failure rolls both back.

## Explicit Open Items

- NOT APPLICABLE: Phase 0B does not create generation tables or projections.
- OPEN — ADDITIONAL MEASUREMENT REQUIRED: source-generation duplicate metrics after the schema exists.
