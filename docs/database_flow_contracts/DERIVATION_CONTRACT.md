# Derivation Contract

Status: LOCKED for Phase 0B. This classifies derivations and idempotency boundaries only.

## Identity Distinctions

- `derivation_version`: deterministic semantic interpretation version, for example `privacy-aliases:v1` or `graph-events:v3`.
- `derivation_run_id`: execution/audit identity for one run. It is not semantic authority.
- `state_version`: monotonic current-state ordering value for replacement/update facts.

These three values must not be conflated.

## Classes

| Class | Definition | Idempotency boundary |
|---|---|---|
| ROW_LOCAL | Output depends only on one row/ERK and stable reference data. | `(ingest_batch_id, derivation_version)` or `(ERK, derivation_version)` for repair. |
| ADDITIVE_AGGREGATE | Batch contributes additive facts to a source/generation aggregate. | `(ingest_batch_id, derivation_version)` contribution. |
| WINDOWED_STATEFUL | Output depends on ordered windows/checkpoints across rows. | `(window/checkpoint_id, derivation_version)`. |
| WHOLE_SOURCE | Output depends on a complete source generation. | `(source_ref_type, source_ref_id, source_generation, derivation_version)`. |
| WHOLE_CASE | Output depends on a case snapshot across sources. | `(case_snapshot_id, derivation_version)`. |

Windowed/stateful work must not be forced into batch-local idempotency.

## Current Derivation Inventory

| Derivation | Class | Input surface | Counting basis | Late-batch behavior | Generation invalidation behavior | Semantic version behavior |
|---|---|---|---|---|---|---|
| Privacy aliases | ROW_LOCAL | Published physical observations | ERK coverage | Process late durable batch independently; advance source watermark by batch. | Invalidate/retract alias coverage for invalidated generation. | New alias extraction semantics require new `privacy-aliases:vN`. |
| IOC matches | ROW_LOCAL | Published physical observations | ERK facts, LEK UI counts | Process late batch independently; IOC UI summaries recompute logical counts. | Hide/retract matches for invalidated generation. | Rule/catalog/matcher change requires `ioc-engine:vN`. |
| MITRE row mappings | ROW_LOCAL | Published physical observations | ERK facts, LEK UI counts | Process late batch independently. | Hide/retract row facts for invalidated generation. | Rule mapping change requires `mitre-rules:vN`. |
| Graph extraction | ROW_LOCAL plus ADDITIVE_AGGREGATE support | Published physical observations | CANONICAL_EDGE topology; ERK/source support | Process late batch and merge support facts; topology remains canonical. | Mark support rows unavailable/invalidated by generation; topology recomputed from active support. | Extractor semantic change requires `graph-events:vN`. |
| KnownUser discovery | ADDITIVE_AGGREGATE | Published logical events for counts plus physical aliases for evidence | LEK for counts; ERK for support | Late batch adds contributions and may create alias observations. | Remove/hide source-generation contributions. | Principal-key or discovery rule change requires `known-users:vN`. |
| KnownSystem discovery | ADDITIVE_AGGREGATE | Published logical events plus CaseFile metadata | LEK for event counts; ERK/source for support | Late batch adds host/IP/alias contributions. | Remove/hide source-generation contributions. | Principal-key or discovery rule change requires `known-systems:vN`. |
| Behavioral profiles | ADDITIVE_AGGREGATE | Published logical events | LEK | Late batch contributes to principal profile for generation. | Retract source-generation contribution from profile read model. | Profiler semantic change requires `behavioral-profile:vN`. |
| Password spray/brute force/anomaly detectors | WINDOWED_STATEFUL | Published logical events ordered by case timezone/UTC | LEK | Late hole can reopen affected windows/checkpoints. | Invalidate findings whose windows include invalidated generation observations. | Detector/rule/window change requires detector-specific `:vN`. |
| Pattern detection | WINDOWED_STATEFUL | Published logical events with overlay filters | LEK | Late hole reopens candidate windows; no batch boundary as detection boundary. | Findings tied to invalidated input become unavailable/pending revalidation. | Pattern/rule change requires `pattern-detection:vN`. |
| Storyline / incident storyline | WINDOWED_STATEFUL or WHOLE_CASE | Published logical events | LEK | Late batch reopens affected timeline windows or case snapshot. | Snapshot rebuilt from active generations. | Storyline logic change requires `storyline:vN`. |
| Temporal baseline | WHOLE_CASE | Published logical events | LEK | Late batch invalidates/recomputes baseline snapshot or incremental checkpoint. | Snapshot excludes invalidated generations. | Baseline model change requires `temporal-baseline:vN`. |
| Qdrant event embeddings | ROW_LOCAL/LEK_CURRENT | Published logical events | LEK default, ERK provenance | Late batch embeds new LEK or updates representative/provenance. | Superseded/invalidated points cannot surface. | Embedding model/prompt/text schema change requires `embedding:vN`. |
| RAG pattern vectors | WHOLE_CASE for sync catalog, not event-source gated | Attack pattern catalog | OTHER | Not source batch driven. | NOT APPLICABLE to source generation. | Model/catalog change requires `pattern-vector:vN`. |
| AI report/timeline summaries | WHOLE_CASE | Frozen published logical/physical evidence set | LEK display, ERK provenance | Late batch does not alter frozen report input; new report uses new snapshot. | Snapshot excludes invalidated generations. | Prompt/model/schema change requires `ai-report:vN`. |

## Rules

- Derivations read published surfaces only in the target architecture.
- Row-local derivations may run per durable batch.
- Additive aggregates store per-source-generation contributions so generation invalidation can retract without destructive raw rewrites.
- Windowed derivations checkpoint on contiguous watermarks and reopen windows when holes fill.
- Whole-source and whole-case derivations require source or case snapshot completeness according to their declared input surface.

## Explicit Open Items

- OPEN — ADDITIONAL MEASUREMENT REQUIRED: exact version labels for existing rule packs and profile models during implementation.
- NOT APPLICABLE: Phase 0B does not add derivation tables or queues.
