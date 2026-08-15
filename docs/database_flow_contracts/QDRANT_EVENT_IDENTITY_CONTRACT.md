# Qdrant Event Identity Contract

Status: LOCKED for Phase 0B. No Qdrant production changes are made here.

## Current Baseline

- Case event collection name: `case_<case_id>_events`.
- Current point ID: numeric hash of `(case_id, embedding_scope, selector_key)`.
- Current payload includes selector-era event fields, duplicate text count, `embedding_scope`, `embedded_at`, `case_id`, and `case_uuid`.
- Current refresh removes stale points for a scope by `embedded_at`, not by source generation.
- `source_generation`, LEK, `derivation_version`, and `embedding_version` are not implemented in event vectors.

## Publication-Safe Design Choice

Locked choice: **A — revisioned points**.

Justification versus B (isolated staging collection):

- Default retrieval is one vector per LEK, but a LEK may be supported by many `(source_ref_type, source_ref_id, source_generation)` observations.
- Replacing one source must not rebuild or swap an entire case collection.
- Point identity that includes a PostgreSQL-authoritative `publication_epoch` lets replacement vectors write to **different point IDs** while the currently published point remains untouched.
- Atomic activation updates the published epoch pointer; unpublished epochs are not default-retrievable.
- Isolated staging collections are too coarse for mixed-source LEKs and would still need per-LEK publication pointers.

Rule: **no replacement write may overwrite the currently published vector before atomic activation.**

## Retrieval Basis

Default event retrieval uses one **published** vector per LEK.

Reason: default analyst/RAG retrieval is logical-event oriented per the counting-basis contract. Physical provenance remains available through observation ERK backreferences.

Exception: ERK-level retrieval is allowed only for explicit provenance, custody, or "show all observations" workflows.

Default retrieval MUST surface a LEK iff:

1. the point's `publication_epoch` equals the currently published epoch for that `(case_id, lek, embedding_scope, derivation_version, embedding_version)`;
2. `active_support_count >= 1`;
3. `invalidated = false`;
4. `superseded = false` for the **vector revision** (unpublished/replaced revisions are not default).

## Point ID Construction

Future point ID canonical input:

```text
{"basis":"LEK","case_id":<int>,"derivation_version":<version>,"embedding_scope":<scope>,"embedding_version":<version>,"lek":<lek>,"publication_epoch":<int>}
```

Hash with SHA-256. Use a stable Qdrant-supported point representation chosen during implementation; if numeric IDs are required, use a documented deterministic truncation and collision check.

`publication_epoch` is PostgreSQL-authoritative, monotonically increasing per `(case_id, lek, embedding_scope)`. It is allocated when a new vector revision is **built**, including hidden `BUILDING_REPLACEMENT` revisions. Staging epochs are unpublished. Activation promotes a staging epoch to published. Unpublished epochs remain distinct point IDs and cannot collide with the published point.

Selector-key point IDs are compatibility-only and must not be used for new event-vector authority.

## Multi-Source Support Representation

Singular `source_generation` payload authority is insufficient. A LEK may be supported by observations from multiple sources.

Required payload support fields:

- `support_generation_keys[]`: ordered unique list of `source_ref_type + ":" + source_ref_id + ":" + source_generation`. Sort lexicographically for determinism.
- `representative_generation_key`: the support key of the canonical representative observation selected by the LEK representative contract.
- `active_support_count`: count of support keys whose generation is currently `ACTIVE` (or `BUILDING_INITIAL` when that generation is published). `SUPERSEDED`, `INVALIDATED`, and `FAILED` supports are not active.
- `observation_erks`: ERKs of currently active supporting observations, or a bounded list plus provenance lookup token.
- `representative_erk`
- `observation_count`
- `source_count`: distinct active `(source_ref_type, source_ref_id)` values, not a substitute for `active_support_count`.
- `field_conflict`

`source_ref_type`, `source_ref_id`, and `source_generation` MAY remain as denormalized copies of `representative_generation_key`. They are not the support set.

## Future Payload Fields

Every event vector payload must include:

- `erk` (representative ERK; compatibility alias of `representative_erk`)
- `lek`
- `support_generation_keys`
- `representative_generation_key`
- `active_support_count`
- `publication_epoch`
- `derivation_version`
- `embedding_version`
- `embedding_scope`
- `case_id`
- `case_uuid`
- `representative_erk`
- `observation_erks`
- `observation_count`
- `source_count`
- `field_conflict`
- `superseded` (true when this vector revision is not the published epoch)
- `invalidated` (true when no valid support remains and the point is retained only for audit/pending delete)

## Lifecycle Rules

Replacement write isolation:

- While generation N is `ACTIVE` and N+1 is `BUILDING_REPLACEMENT`, embed N+1 into points whose `publication_epoch` is a new unpublished staging epoch.
- Those writes MUST NOT use the published point ID (published epoch is absent from the staging point ID).
- Default retrieval continues to return N's published epoch.

Atomic publication:

- PostgreSQL records `published_publication_epoch` per `(case_id, lek, embedding_scope)` or an equivalent publication index.
- Activation of source generation N+1, or any support-set change that requires a new vector, commits the new published epoch in the same authority transaction that makes the new support set current.
- After commit, default retrieval selects the new epoch. The previous epoch is `superseded=true` and is not default.

One support superseded while another remains `ACTIVE`:

- Remove the superseded generation key from active support.
- If `active_support_count >= 1`, rebuild a new revision (new epoch) with remaining support and updated representative if needed. Do not delete the LEK.
- If the superseded key was `representative_generation_key`, recompute representative from remaining ACTIVE observations using the LEK representative contract.

One support invalidated while another remains `ACTIVE`:

- Same as supersession: drop the invalidated key; keep the LEK if active support remains; new epoch; prune stale payload arrays.

Replacement of representative source:

- Representative may change when a higher-scoring ACTIVE observation appears or the previous representative's generation leaves ACTIVE.
- New epoch; previous published point is not overwritten in place.

Delete-file:

- Invalidate/supersede that source's generation.
- For each LEK: drop that support key; rebuild remaining LEKs; delete points whose `active_support_count` becomes 0.

Delete-case:

- Delete the case event collection or all case-scoped points as part of coordinated deletion.

Re-embedding:

- New `embedding_version` creates distinct point IDs (version is already in the point ID).
- Retrieval filters to the current embedding version. Old-version points remain until pruned and are not default.

Stale support pruning:

- Background job may delete points whose epoch is not published and whose generation is `FAILED`, `SUPERSEDED`, or `INVALIDATED`, after the published successor exists or `active_support_count = 0`.
- Pruning must not delete the currently published epoch.

## Physical Provenance Backreferences

LEK points must carry enough references to recover physical observations:

- representative ERK;
- all active observation ERKs or a bounded list plus a provenance lookup token when too large;
- `support_generation_keys`;
- observation and source counts;
- field conflict flag.

## Migration Compatibility

- Existing selector-key points may be searched only during compatibility.
- Migration builds generation-aware revisioned LEK points alongside selector-era points.
- Retrieval switches to LEK/epoch filters before selector-era points are deleted.
- Selector-key result payloads must be resolvable to ERK or rejected as ambiguous in the API layer.

## Tests

- CT-022: superseded / unpublished epoch cannot surface in default retrieval.
- CT-036: `BUILDING_REPLACEMENT` vector writes do not overwrite the published point ID.
- CT-037: one support superseded while another remains ACTIVE still surfaces the LEK under a new published epoch.
- CT-038: one support invalidated while another remains ACTIVE still surfaces the LEK.
- CT-039: representative source replacement updates payload and epoch without dropping remaining support.
- CT-040: delete-file prunes only that source's support.
- CT-041: delete-case removes all case event vectors.
- CT-042: re-embedding changes point identity by `embedding_version`; old version is not default.
- Selector-era point migration preserves ERK provenance or reports an explicit blocker.

## Explicit Open Items

- OPEN — ADDITIONAL MEASUREMENT REQUIRED: retrieval recall parity for one-vector-per-LEK after LEK exists.
- NOT APPLICABLE: Phase 0B does not modify Qdrant collections or tasks.
