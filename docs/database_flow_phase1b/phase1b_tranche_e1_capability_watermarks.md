# Phase 1B Tranche E1 Capability Watermarks

## Scope

E1 installs one generic, durable, concurrency-safe capability watermark engine and migrates only `privacy_aliases` as a truthful ROW_LOCAL incremental derivation.

E1 does not implement E2 AI freeze/verify/alias/send, Tranche F completion conversion, `events_current`, LEK cutover, graph/Qdrant lifecycle, or MEMORY_JOB/PCAP managed protocol.

## Capability Inventory / Classes

| Capability | Locked class | Current implementation | E1 migrated |
|---|---|---|---|
| `privacy_aliases` | ROW_LOCAL | File-scoped DISTINCT ClickHouse scan plus incremental `ingest_batch_id` scan | Yes (`privacy-aliases:v1`) |
| `ioc_matches` | ROW_LOCAL | Case-wide `tag_all_iocs_globally` overlay tagging | No |
| `mitre_matches` | ROW_LOCAL | Hayabusa file-level EVTX insert plus case-wide procedure mapping | No |
| `graph_extraction` | ROW_LOCAL plus ADDITIVE_AGGREGATE | File/case graph materializer | No |
| `known_principal_discovery` | ADDITIVE_AGGREGATE | Completion-tail known user/system discovery | No |
| `behavioral_profile_contribution` | ADDITIVE_AGGREGATE | Case-wide profiler | No |
| `pattern_detection` | WINDOWED_STATEFUL | Pattern/window detectors | No |
| `event_embeddings` | ROW_LOCAL / LEK_CURRENT | Qdrant embedding path | No |

No capability is currently activation-blocking. `_declared_activation_requirements()` remains empty. `missing_activation_capability_requirements()` can test declared requirements later without faking readiness now.

## Schema / Completion Evidence

Authoritative current watermark row remains `case_capability_source_state`.

The inherited `completed_batch_ordinals` JSON column is retained for additive compatibility and is not completion authority. Production-scale batch counts would rewrite a growing JSON array on every completion, creating row contention, lost-update risk, and unbounded row growth.

E1 adds `case_capability_batch_completions`:

- unique `(case_id, capability, source_ref_type, source_ref_id, source_generation, derivation_version, ingest_batch_id)`
- unique ordinal for the same identity
- prefix index on identity plus `batch_ordinal`

`highest_completed_batch_ordinal` remains informational. Gates use `contiguous_batch_ordinal` plus completion rows.

## Authoritative Watermark Identity

`(case_id, capability, source_ref_type, source_ref_id, source_generation, derivation_version)`

## Contiguous Prefix Algorithm

Only a hole-free completed prefix counts.

After an idempotent completion insert, the engine locks the watermark row and walks completed ordinals starting at the next expected ordinal (`0` if none, else `contiguous + 1`) until a hole. Later completed batches are absorbed without rerunning those derivations.

Example: completed `{0,1,3,4}` => contiguous `1`. Completing `2` advances directly to `4`.

Zero-based: only batch `0` complete => contiguous `0`. None complete => `NULL`.

## Status Semantics

- `NOT_STARTED`: no completion evidence
- `IN_PROGRESS`: some completions exist but no contiguous prefix
- `CONTIGUOUS_READY`: a safe prefix exists, generation not fully covered
- `COMPLETE`: D1 durable EOF exists, expected range is known, every required batch is DURABLE, capability completions cover `0..final` with no hole, or a legitimate zero-event EOF is covered
- `FAILED`: explicit correctness-terminal capability failure
- `INVALIDATED`: coverage withdrawn; does not satisfy gates

COMPLETE is never derived from highest ordinal alone.

## Zero-Event Semantics

A generation with `expected_rows = 0`, `final_batch_ordinal IS NULL`, `completed_at` set, and no ingest batches may become capability `COMPLETE` with `contiguous_batch_ordinal IS NULL`. No fake ingest batch is created.

## Ingest DURABLE Gate

STAGED evidence cannot advance a capability watermark. Completion recording fails closed.

## Derivation Version Isolation

`privacy-aliases:v1` COMPLETE does not satisfy `privacy-aliases:v2`. Version upgrades create separate authoritative rows.

## Generation / Replacement Authority

- BUILDING_INITIAL may incrementally advance watermarks.
- Default/current gates use ACTIVE if present, otherwise BUILDING_INITIAL.
- BUILDING_REPLACEMENT may derive and advance its own rows but never satisfies the current/default gate before activation.
- After atomic activation, default gates use N+1 only. SUPERSEDED N is not a fallback.
- FAILED and INVALIDATED generations do not satisfy default gates.

## Invalidation

`invalidate_source_generation()` transitions the generation to INVALIDATED and marks that generation's capability rows INVALIDATED. Completion rows are retained. No graph/Qdrant retraction is performed.

## Concurrency / Idempotency

Independent PostgreSQL sessions insert completion rows under unique constraints and lock the watermark row to recompute the prefix. Duplicate completion of the same identity is idempotent and does not inflate `state_version` unless the watermark actually changes.

## Exact-Set Coverage Primitive

`verify_capability_batch_coverage(capability, derivation_version, batch_ids)` fails if any frozen batch is missing, not DURABLE, uncovered, or belongs to a SUPERSEDED/FAILED/INVALIDATED generation.

This is not a case-ready boolean.

## ERK Coverage Model

Privacy aliases are value-level vault rows, not per-ERK alias rows.

E1 maps `ERK -> ingest_batch_id` from ClickHouse `events` and verifies those batches. Batch completion means every event in that DURABLE batch was scanned for alias candidates under `privacy-aliases:v1`. It does not claim a dedicated alias row exists for that ERK.

## Migrated Incremental Capability

`privacy_aliases` / `privacy-aliases:v1` / ROW_LOCAL

- Trigger: after PG DURABLE when `PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED` is on, plus explicit runner for tests
- Idempotency key: `(capability, derivation_version, source_generation, ingest_batch_id)`
- Output: existing `privacy_aliases` upsert on `(case_id, entity_type, normalized_value)`
- Watermark: completion row plus contiguous prefix refresh

The legacy file-scoped populate and whole-case completion tail remain.

## Deferred Capability Migrations

IOC, MITRE, graph, known principals, behavioral profiles, pattern detection, and embeddings remain `NOT_STARTED` in E1. No false COMPLETE is recorded.

## D2 Interaction

D2 may mark a STAGED batch DURABLE. D2 does not record capability completion. After later derivation of the repaired hole, the watermark advances through already-recorded later completions.

## Feature Flags

- `PHASE1B_MANIFEST_PROTOCOL_ENABLED` remains off by default
- `PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED` is off by default

Schema existence does not cut production derivations over.

EOF refresh and generation invalidation query watermark tables only after a same-connection catalog check. Fixtures that never created `case_capability_source_state` (C2 SQLite memory) skip refresh without rolling back ingest EOF or activation.

## No-E2 / No-Cutover Audit

- AI freeze/send wiring: no
- Readiness UI: no
- Completion-tail replacement: no
- `events_current`: no
- LEK cutover: no
- Graph/Qdrant lifecycle: no
- MEMORY_JOB/PCAP protocol: no
