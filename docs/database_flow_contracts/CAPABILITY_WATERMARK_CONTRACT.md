# Capability Watermark Contract

Status: LOCKED for Phase 0B. No watermark tables or gates are implemented here.

## Authoritative State

Authoritative row shape:

- `case_id`
- `capability`
- `source_ref_type`
- `source_ref_id`
- `source_generation`
- `contiguous_batch_ordinal`
- `derivation_version`
- `status`
- `updated_at`

`case_capability_source_state` is authoritative. `case_capability_state` is UI/aggregate only and must not gate correctness-sensitive work.

## Contiguous Semantics

Only the contiguous prefix of completed durable batches counts.

Example:

```text
1 ✓
2 ✓
3 ✗
4 ✓
5 ✓
```

The contiguous watermark is `2`. Batches `4` and `5` are complete but not part of the safe prefix.

When batch `3` later completes, the contiguous watermark advances to `5` if batches `4` and `5` are still complete for the same `capability`, `source_ref`, `source_generation`, and `derivation_version`.

## Status Values

- `NOT_STARTED`
- `IN_PROGRESS`
- `CONTIGUOUS_READY`
- `COMPLETE`
- `FAILED`
- `INVALIDATED`

`FAILED` and `INVALIDATED` do not satisfy gates.

## Generation Behavior

- `BUILDING_INITIAL`: durable batches may advance source watermarks progressively.
- `ACTIVE`: source watermarks gate default readers and derivations.
- `BUILDING_REPLACEMENT`: hidden from default surfaces; watermarks may advance for replacement but do not replace active generation gates until activation.
- `SUPERSEDED`: no longer gates default surfaces.
- `INVALIDATED`: coverage is invalidated and must not gate reads.
- Source deletion invalidates source capability rows.
- Derivation version upgrade creates separate source rows for the new `derivation_version`; old rows do not satisfy new-version gates.
- Reprocessing allocates new generation rows; previous ACTIVE rows remain valid until atomic supersession.

## AI Privacy Gating

Required ordering:

```text
retrieve/select candidate evidence
↓
freeze exact ERKs and/or ingest_batch_ids
↓
verify alias coverage for the frozen set
↓
alias payload
↓
send
```

Prohibited ordering:

```text
check case readiness
↓
retrieve later
```

Coverage verification must answer whether the frozen ERKs/batches are covered by the required privacy derivation version. New ingest after freeze cannot expand or alter the outbound request.

## Capabilities

Initial capability names:

- `privacy_aliases`
- `ioc_matches`
- `mitre_matches`
- `graph_extraction`
- `known_principal_discovery`
- `behavioral_profile_contribution`
- `pattern_detection`
- `event_embeddings`

Additional capabilities require a decision-log entry and test mapping.

## Race Tests

- Out-of-order completion does not advance through holes.
- Late hole completion advances the contiguous prefix.
- Replacement generation coverage does not satisfy active-generation default gates before activation.
- AI frozen set rejects any uncovered ERK/batch.
- New rows arriving after freeze do not alter the frozen request.
- Source invalidation withdraws coverage.

## Explicit Open Items

- OPEN — ADDITIONAL MEASUREMENT REQUIRED: per-capability timing baselines after batch manifests exist.
- NOT APPLICABLE: Phase 0B does not create `case_capability_source_state` or API gates.
