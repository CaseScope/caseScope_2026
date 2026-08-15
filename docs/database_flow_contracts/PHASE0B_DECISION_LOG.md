# Phase 0B Decision Log

Date: 2026-08-14

Correction pass (same date): PHASE0B-DEC-017 through PHASE0B-DEC-022 close external-review blockers. DEC-001 through DEC-016 remain historical; DEC-017 supersedes the `ACTIVE -> BUILDING_REPLACEMENT` interpretation of DEC-007.

## Decisions

### PHASE0B-DEC-001

- Contract: LEK
- Question: Should legacy `ARTIFACT_DEDUP_CONFIGS` become LEK recipes?
- Evidence: Current recipes include `source_file`; Phase 0A duplicate sample shows many cross-file/different-ERK duplicates.
- Alternatives: copy legacy recipes; derive entirely new recipes; lock only safe recipes and use ERK fallback elsewhere.
- Chosen rule: Lock only safe source-independent recipes; unsupported families use one LEK per ERK.
- Rationale: Maximizing dedup would overmerge evidence without sufficient collision proof.
- Risk: Some logical duplicates remain uncollapsed until later measurement.
- Future change/versioning: New recipe requires `logical_identity_version` bump and measurement entry.

### PHASE0B-DEC-002

- Contract: LEK
- Question: How should canonical representatives be selected?
- Evidence: Locked v4 prohibits `any()` and merge-order-dependent selection.
- Alternatives: first row; latest row; deterministic score.
- Chosen rule: Deterministic score with lexicographically smallest ERK final tie-break.
- Rationale: Stable across merge order, retries, and ClickHouse execution plans.
- Risk: Representative may not be the analyst-preferred source.
- Future change/versioning: Change scoring under new representative contract version.

### PHASE0B-DEC-003

- Contract: LEK
- Question: What happens on field disagreement under one LEK?
- Evidence: Locked v4 requires conflict surfacing, not hiding.
- Alternatives: choose representative value only; concatenate values; explicit conflicts.
- Chosen rule: Keep all observations, set `field_conflict`, and expose values by provenance lookup.
- Rationale: Deduplication becomes reconciliation, not deletion.
- Risk: UI must handle conflict indicators.
- Future change/versioning: Add conflict fields by LEK contract version.

### PHASE0B-DEC-004

- Contract: Principal Identity
- Question: Should SID always merge user identities?
- Evidence: Current KnownUser prefers SID when present; graph identity requires SID/authority/host scope.
- Alternatives: SID always; username always; SID only when observed as actual identity evidence.
- Chosen rule: SID preferred only when observed as actual identity evidence.
- Rationale: Avoids inventing equality for strings that look like SIDs but are not authority evidence.
- Risk: Some aliases remain separate until curated.
- Future change/versioning: Directory-backed identity can add a new key version.

### PHASE0B-DEC-005

- Contract: Principal Identity
- Question: Should hostname and IP be equivalent system identity?
- Evidence: KnownSystem comments warn `src_ip` may be remote attacker/workstation evidence, not host ownership.
- Alternatives: merge hostname and IP; treat IP as attribute; require authority evidence.
- Chosen rule: IP is not equal to hostname identity without authoritative machine evidence.
- Rationale: Prevents overmerging NAT, DHCP, and remote-source observations.
- Risk: More weak IP-only principals.
- Future change/versioning: Machine-ID evidence can promote identity in a new key version.

### PHASE0B-DEC-006

- Contract: Evidence Generation
- Question: Does retry allocate a new generation?
- Evidence: Locked v4 says crash/timeout/retry is same generation, new attempt.
- Alternatives: new generation per attempt; same generation with attempt ID.
- Chosen rule: Retry uses same generation and new `ingest_attempt_id`.
- Rationale: Prevents retry noise from becoming semantic source history.
- Risk: Reconciler must handle partial attempts correctly.
- Future change/versioning: None without generation contract revision.

### PHASE0B-DEC-007

- Contract: Evidence Generation
- Question: How are replacements published?
- Evidence: Locked v4 distinguishes first ingest progressive publication from hidden replacement builds.
- Alternatives: publish replacement progressively; block all search; atomic replacement activation.
- Chosen rule: Existing ACTIVE remains visible; BUILDING_REPLACEMENT hidden until atomic switch.
- Rationale: Prevents half-generation mixtures.
- Risk: Replacement results are not searchable until activation.
- Future change/versioning: Requires generation-state contract change.

### PHASE0B-DEC-008

- Contract: Ingest Batch
- Question: What proves retry equivalence?
- Evidence: Locked v4 requires deterministic batch ID plus content hash; current Buffer insert does not prove durability.
- Alternatives: Celery success; row count only; content hash.
- Chosen rule: Stable batch ID plus canonical batch content hash.
- Rationale: Detects changed ordering, batch size, or row content under same ordinal.
- Risk: Requires strict canonical serialization.
- Future change/versioning: Batching contract version bump.

### PHASE0B-DEC-009

- Contract: Ingest Batch
- Question: What happens on content hash mismatch?
- Evidence: Locked v4 says mismatch fails closed.
- Alternatives: treat as retry; overwrite; fail closed.
- Chosen rule: Fail closed, do not publish, require human/reconciler decision.
- Rationale: Mismatch means deterministic identity was violated.
- Risk: Operational intervention may be needed.
- Future change/versioning: None without contract revision.

### PHASE0B-DEC-010

- Contract: Capability Watermark
- Question: Is latest completed batch a safe watermark?
- Evidence: Locked v4 hole example shows scalar latest is unsafe.
- Alternatives: latest completed; contiguous prefix.
- Chosen rule: Per-source contiguous watermark.
- Rationale: Prevents capability gates from skipping failed/missing batches.
- Risk: Later completed batches wait behind holes.
- Future change/versioning: Requires watermark contract revision.

### PHASE0B-DEC-011

- Contract: Capability Watermark
- Question: How should AI privacy gating avoid races?
- Evidence: Locked v4 requires freeze-then-verify.
- Alternatives: check case readiness then retrieve; freeze exact evidence then verify.
- Chosen rule: Freeze ERKs/batches, verify coverage for that frozen set, then send.
- Rationale: Prevents newly arriving evidence from bypassing alias coverage.
- Risk: More request bookkeeping.
- Future change/versioning: Gate API version bump.

### PHASE0B-DEC-012

- Contract: Derivation
- Question: Are task IDs semantic versions?
- Evidence: Current UUID run IDs exist; locked v4 says UUID scan versions are run IDs, not semantic versions.
- Alternatives: reuse task IDs; add `derivation_version`; combine with state version.
- Chosen rule: Separate `derivation_version`, `derivation_run_id`, and `state_version`.
- Rationale: Supports deterministic reprocessing and audit.
- Risk: Requires broad derived-state schema updates later.
- Future change/versioning: Per-derivation semantic version strings.

### PHASE0B-DEC-013

- Contract: Counting Basis
- Question: What is the default analyst count?
- Evidence: Locked v4 matrix and duplicate sample show physical duplicates can be numerous.
- Alternatives: ERK count; LEK count.
- Chosen rule: Analyst default count uses LEK; provenance uses ERK.
- Rationale: Analyst workflows count logical events without losing physical evidence.
- Risk: Users need visible observation counts for source support.
- Future change/versioning: Counting-basis consumer map update.

### PHASE0B-DEC-014

- Contract: ERK API
- Question: How should selector ambiguity behave?
- Evidence: Selectors are source/file/timestamp derived and can map to multiple physical rows.
- Alternatives: pick first; return all; fail typed ambiguity.
- Chosen rule: Multiple ERKs returns typed ambiguity and no mutation.
- Rationale: Prevents silent mutation of the wrong evidence row.
- Risk: Compatibility clients may need updates.
- Future change/versioning: API deprecation stages.

### PHASE0B-DEC-015

- Contract: Qdrant Event Identity
- Question: What is default event vector basis?
- Evidence: Counting contract makes default AI event retrieval logical; current Qdrant selector identity is temporary.
- Alternatives: one vector per ERK; one vector per selector; one vector per LEK.
- Chosen rule: Default retrieval uses one vector per LEK with ERK provenance.
- Rationale: Matches analyst/RAG logical event semantics while preserving physical backreferences.
- Risk: Recall parity must be measured after LEK exists.
- Future change/versioning: Embedding version and retrieval basis version.

### PHASE0B-DEC-016

- Contract: Ingest Fence
- Question: What happens when Redis is unavailable?
- Evidence: Current guard can fail open, but locked v4 requires fail-closed for correctness-sensitive operations.
- Alternatives: bypass; best effort; fail closed.
- Chosen rule: Redis unavailable plus correctness-sensitive fence dependency refuses/retries.
- Rationale: Destructive operations and Buffer removal cannot race active writers.
- Risk: Redis outage can pause ingest/admin work.
- Future change/versioning: Fence contract version.

### PHASE0B-DEC-017

- Contract: Evidence Generation
- Question: Does an ACTIVE generation transition to BUILDING_REPLACEMENT?
- Evidence: External architecture review; locked v4 says a replacement builds invisibly while the old generation remains published. Prior contract table listed `ACTIVE -> BUILDING_REPLACEMENT` as if the same generation changed state.
- Alternatives: mutate N to BUILDING_REPLACEMENT; allocate N+1 as BUILDING_REPLACEMENT while N stays ACTIVE.
- Chosen rule: Replacement is a NEW generation. N remains ACTIVE until the atomic activation transaction sets N SUPERSEDED and N+1 ACTIVE together. `replacement_in_progress` is a derived source-level operation, not a generation state. `ACTIVE -> BUILDING_REPLACEMENT` is prohibited.
- Rationale: Prevents confusing source-level reprocess with per-generation state and prevents half-generation publication.
- Risk: Implementation must lock both generation rows in one PostgreSQL transaction.
- Future change/versioning: Generation-state contract revision. Supersedes the transition table interpretation in the pre-correction contract.

### PHASE0B-DEC-018

- Contract: Ingest Batch
- Question: How is batch_content_hash reconstructed after CH insert?
- Evidence: External review: ordered batch hash was defined without persisted CH row identity sufficient to prove it.
- Alternatives: hash opaque extra_fields; hash insertion bytes; persist ingest_batch_id + ingest_row_ordinal + ingest_row_hash.
- Chosen rule: Every CH batch row stores `ingest_batch_id`, zero-based `ingest_row_ordinal`, and `ingest_row_hash` over an explicit canonical allowlist plus a five-field `parser_provenance` object. Aggregate hash is SHA-256 over framed ordered row hashes. Duplicate ordinal identical hash is the only retry-equivalent duplicate path; missing/extra/different-hash ordinals fail closed.
- Rationale: Reconciler must prove count, ordinal set, uniqueness, per-row hashes, and aggregate hash from CH.
- Risk: Parser changes that alter allowlisted fields require a new generation.
- Future change/versioning: `batching_contract_version` bump.

### PHASE0B-DEC-019

- Contract: LEK
- Question: May firewall/IIS/SonicWall/Huntress collapse across sources using timestamp plus endpoint or event_id?
- Evidence: `IISLogParser` has no unique event/record id and can repeat requests in the same second. `FirewallLogParser` emits no native unique id. SonicWall CSV `ID` is a message type code. `HuntressParser` maps `event_id` from ECS `event.code`/`action`/category, explicitly not a unique UUID (`entity_id` was rejected as a grouping key).
- Alternatives: keep medium-confidence collapse recipes; invent synthetic ids; ERK-backed non-collapse until a verified native id exists.
- Chosen rule: Uncertainty => no cross-source collapse. Quality `medium` is not permission to collapse. Families without a verified native identifier are `NO_SAFE_CROSS_SOURCE_RECIPE_YET`. EVTX remains separately locked.
- Rationale: Collapsing independent legitimate events destroys forensic identity.
- Risk: More logical duplicates remain until native-ID recipes are measured.
- Future change/versioning: New `logical_identity_version` after proven native-ID measurement.

### PHASE0B-DEC-020

- Contract: Qdrant Event Identity
- Question: How can replacement vectors be built without overwriting the published LEK point, and how is multi-source support represented?
- Evidence: Default one-vector-per-LEK plus point IDs that omitted lifecycle revision would let BUILDING_REPLACEMENT writes collide with published points. Singular `source_generation` cannot represent multiple supporting sources.
- Alternatives: A revisioned points with `publication_epoch` in point ID; B isolated staging collection.
- Chosen rule: Option A. Point ID includes PostgreSQL-authoritative `publication_epoch`. Staging writes use a new unpublished epoch. Payload carries `support_generation_keys[]`, `representative_generation_key`, and `active_support_count`. Default retrieval requires published epoch and `active_support_count >= 1`.
- Rationale: Mixed-source LEKs must not swap an entire case collection; unpublished epochs must not share the published point ID.
- Risk: More points per LEK over time until stale epochs are pruned.
- Future change/versioning: Embedding/publication contract version.

### PHASE0B-DEC-021

- Contract: Event Surface / Counting Basis
- Question: Is summing grouped consumer counts to 167 sufficient migration accounting?
- Evidence: External review: 23 grouped records summing to 167 do not make each Phase 0A location addressable.
- Alternatives: keep groups; groups with members[]; one record per Phase 0A reader ID.
- Chosen rule: One machine-readable record per `phase0a_reader_id` P0A-R001..P0A-R167. Validation is set equality of IDs across Phase 0A reconstruction, event-surface consumers, and counting-basis consumers. Duplicates, missing IDs, and extra IDs fail. Graph topology (`CANONICAL_EDGE`) is not an `events` reader.
- Rationale: Implementation-ready migration accounting needs location-level addressability.
- Risk: Surface/basis totals differ from the earlier grouped 23-record summary because that summary was not location-true.
- Future change/versioning: Add a new ID when a newly discovered `events` reader appears.

### PHASE0B-DEC-022

- Contract: Principal Identity
- Question: May KnownSystem.id participate in principal_key?
- Evidence: External review: `principal:system:v1:...:known-system:<known_system_id>` makes curation mint the identity that curation is supposed to reference.
- Alternatives: keep surrogate-id keys; use hostname/machine-id evidence only.
- Chosen rule: Remove PostgreSQL KnownSystem surrogate IDs from principal_key. Authority direction is evidence -> principal_key; KnownSystem references/merges/aliases principal_keys. System priority is authoritative machine-id, then hostname/FQDN, then weak IP-only.
- Rationale: Avoid circular identity authority.
- Risk: Hostname collisions remain until machine-id evidence exists; measured later.
- Future change/versioning: New principal key version if directory/machine-id authority is added.
