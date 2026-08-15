# Phase 0B Contract Status Matrix

Phase 0A is accepted. The locked v4 plan remains frozen and is not edited by Phase 0B.

This file reflects the Phase 0B contract correction pass that closed six external-review blockers. No production code, schema, or migrations were changed.

## Summary

| Metric | Count |
|---|---:|
| Required contracts | 10 |
| LOCKED contracts | 10 |
| OPEN contracts | 0 |
| BLOCKED contracts | 0 |

Open measurement items remain inside some contracts. They are non-blocking because unsafe artifact families stay one observation per ERK until a verified native-ID recipe is versioned later.

## Matrix

| Contract | Status | Implementation phase | Current-state mismatch | Key locked decisions |
|---|---|---|---|---|
| LEK_CONTRACT | LOCKED | Phase 4 | LEK is absent; legacy dedup includes `source_file` and deletes physical observations. Huntress `event_id` is a grouping code, not a UUID. | Uncertainty means no cross-source collapse. Only EVTX is locked. IIS/firewall/SonicWall/Huntress are ERK-backed non-collapsing LEKs. |
| PRINCIPAL_IDENTITY_CONTRACT | LOCKED | Phase 6 | No unified `principal_key`; KnownUser/KnownSystem/graph use related but different normalization. | SID preferred only as evidence; KnownSystem.id is not a `principal_key` input; system keys use machine-id then host then IP. |
| EVIDENCE_GENERATION_CONTRACT | LOCKED | Phase 1B / Phase 4 | No `source_generation`; retry/reprocess currently deletes by `case_file_id`. | Per-generation state; `ACTIVE` never becomes `BUILDING_REPLACEMENT`; replacement is a new generation; atomic PG activation. |
| INGEST_BATCH_CONTRACT | LOCKED | Phase 1B | No deterministic `ingest_batch_id`; Buffer success is not a durable protocol. | CH rows persist `ingest_batch_id`, zero-based `ingest_row_ordinal`, `ingest_row_hash`; framed aggregate hash; ordinal anomalies fail closed except proven identical-hash retry copies. |
| CAPABILITY_WATERMARK_CONTRACT | LOCKED | Phase 1B | Current readiness is case/file-level and direct reads can race derivation coverage. | Per-source contiguous watermarks; case aggregate is UI-only; AI freeze-then-verify required. |
| DERIVATION_CONTRACT | LOCKED | Phase 1B / Phase 6 | Task/run IDs are not semantic versions; many derivations run whole-case after completion. | Version/run/state identities are distinct; derivations classified by idempotency and late-batch behavior. |
| COUNTING_BASIS_CONTRACT | LOCKED | Phase 4-6 | Raw `events` readers do not declare ERK/LEK/graph basis. | ERK for provenance; LEK for analyst defaults; 167 location-level IDs with set equality; graph topology is not an `events` reader. |
| ERK_API_CONTRACT | LOCKED | Phase 3.0 | Selector remains API/mutation identity. | New responses expose ERK; mutations accept ERK; selector resolves server-side; ambiguity fails. |
| QDRANT_EVENT_IDENTITY_CONTRACT | LOCKED | Phase 3.0 / Phase 4 | Event vector points are selector-key based and payloads lack lifecycle fields. | Revisioned points (option A); `publication_epoch` in point ID; multi-source `support_generation_keys[]`; replacement cannot overwrite published points. |
| INGEST_FENCE_CONTRACT | LOCKED | Phase 1.4a | Current destructive guard can fail open and writers have no shared lease. | Fail-closed shared/exclusive fence; Redis unavailable refuses correctness-sensitive operations. |

Machine-readable detail is in `CONTRACT_STATUS.json`.
