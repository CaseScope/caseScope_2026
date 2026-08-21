# Phase 1B Tranche F2 — PostgreSQL-Authoritative Readiness UI

Status: **IMPLEMENTED** for F2 UI completion (readiness DTO/API, Case Files strip, F1-consistent completion/repair, non-blocking Hunt coverage note). Product-search publication gate: **CLOSED** (version 4.21.2). This tranche does not claim Phase 1B EXIT ACCEPTANCE.

## Publication gate CLOSED

The accepted interim Hunt Artifacts bridge remains in place and was not redesigned in this UI completion:

- `GET /api/hunting/events/<case_id>`
- `GET /api/hunting/event/detail/<case_id>`
- `GET /api/hunting/event/raw/<case_id>`

Helper: `build_hunting_publication_bridge` in `routes/hunting_query_helpers.py`.

Regression: `tests/test_phase1b_tranche_f2_product_search_publication_gate.py`.

Visibility remains:

- STAGED hidden
- DURABLE BUILDING_INITIAL searchable before EOF
- BUILDING_REPLACEMENT hidden; current ACTIVE remains visible
- after activation, authority follows N+1
- true legacy NULL-identity rows remain visible
- malformed protocol identity fails closed

This is not `events_current`, not `event_observations_current`, and not a Phase 4 reader migration.

## Readiness DTO / API

One authenticated, case-scoped, read-only endpoint is consumed by both Case Files and Hunt Artifacts Events:

`GET /api/case/readiness/<case_uuid>` → `routes.case_files.get_case_readiness`

Engine: `utils/case_readiness.py` `build_case_readiness_dto`.

It is a **read model**. It does not create `case.ready`, `case.search_ready`, `case.ai_ready`, `case.analysis_ready`, or `case.processing_complete`.

Durable dimensions reuse F1:

- `snapshot_case_completion_authority`
- `build_case_reconciliation_readiness`
- `classify_case_ingest_composition`
- latest `case_completion_reconciliation_audit` compared to the existing F1 generation fingerprint **and** stored `batch_counts`

Normal polling issues **0 ClickHouse queries**. It does not call `count_events`, whole-case event scans, IOC/MITRE/graph scans, or Redis as durable authority.

A small F1 snapshot optimization computes default-authority generation ids from already-loaded rows (`default_generation_ids_from_rows`) and reuses the loaded generation list for composition classification. Semantics match `resolve_default_capability_generation`.

## PostgreSQL authority

Authoritative dimensions:

- **Evidence** — `evidence_source_generations` + `ingest_batches`
- **Privacy** — `case_capability_source_state` + `case_capability_batch_completions` for `privacy_aliases` / `privacy-aliases:v1` only
- **Reconciliation** — F1 inspect-only assessment plus current audit (never a permanent ready latch)

Redis cannot determine Evidence, Privacy, or Reconciliation.

## Redis decoration

**Live Activity** may display currently processing, current item, worker activity, and ephemeral file/phase progress.

If Redis disappears, only Live Activity degrades to unavailable/idle/unknown. Durable dimensions stay identical. Redis file completion is not durable reconciliation completion.

## Four dimensions

Compact UI exposes at most:

1. Evidence
2. Privacy
3. Reconciliation
4. Live Activity

No IOC, MITRE, graph, embeddings, profiles, patterns, KnownUser, KnownSystem, or generalized analysis-readiness indicators.

Status always includes text; color is optional enhancement.

## BUILDING_INITIAL

If DURABLE batches exist before EOF:

- search is available
- copy: `Published evidence is searchable; ingest is still expanding.`
- a factual count such as `3 published batches` is allowed

The final denominator is unknown. The DTO sets `final_percent` to `null` and does not infer a percentage from highest ordinal, known batches, Redis totals, file counts, or row counts.

## Unknown denominator

A final completion percentage cannot be shown before durable EOF declaration.

## ACTIVE

ACTIVE proves source-generation lifecycle completion. It does not mean IOC, MITRE, graph, embeddings, profiles, or patterns are complete. UI copy states ingest publication, not analysis completion.

## BUILDING_REPLACEMENT

With N ACTIVE and N+1 BUILDING_REPLACEMENT:

- current Evidence stays based on N
- current search is not presented as partial
- quiet secondary copy: `Replacement processing`
- Hunt optional quiet note: `Replacement processing in background.`

After activation, the next PostgreSQL read follows N+1 without Redis.

## Privacy

The only Phase 1B authoritative capability presented is `privacy_aliases` / `privacy-aliases:v1`.

Presentation is **informational only**. `authorizes_ai_egress` is always false. The DTO is not imported by `utils/ai/router.py` or `utils/ai_privacy_freeze.py` and is not an AI authorization gate.

E2 remains: retrieve/select → freeze exact evidence → verify exact privacy coverage → alias exact payload → send.

### Contiguous-prefix / hole-aware

Completed `{0, 2}` with batch 1 missing reports safe coverage through batch 0, never through batch 2. Highest-completed semantics are not used.

### Replacement

Current N privacy is not marked incomplete merely because N+1 replacement privacy is unfinished. Replacement privacy may appear as secondary/background state.

## Reconciliation

F1 assessments are presented when the latest audit still matches current generation fingerprint and batch counts:

`reconciled`, `work_queued`, `in_progress`, `incomplete_ingest`, `blocked`, `deferred`, `failed`

A prior `reconciled` audit becomes stale when current PG generation/batch authority changes (new BUILDING_INITIAL source, new DURABLE batch, replacement generation, activation, invalidation). The UI does not keep claiming reconciliation is current.

## Legacy

Legacy evidence has no Phase 1B manifest proof. The DTO says untracked. No fabricated managed percentages. Case Files may retain the accepted Redis/latest-ingest repair banner for proven `legacy_only`. The repair route keeps the accepted legacy worker after positive legacy classification.

## Mixed

Managed published readiness plus untracked legacy presence. No combined denominator. Hunt uses qualitative wording only. Completion/repair uses F1 reconciliation. The destructive legacy completion tail is not used.

## Zero-event

D1/E1 semantics preserved: `expected_rows = 0`, `completed_at IS NOT NULL`, `final_batch_ordinal IS NULL`, no fake batch. UI does not show missing batch or `0/1`.

## Case Files readiness strip

One compact strip in `static/templates/case_files.html` using existing CaseScope tiles/CSS (`static/css/main.css` `.readiness-strip`). Four labeled dimensions with text values and details. Usable when Redis is unavailable. PostgreSQL failure shows Unavailable rather than a false ready state.

## Case Files completion / repair

Managed-only and mixed no longer treat Redis file completion as stalled durable completion.

`POST /api/files/repair-completion/<case_uuid>` classifies composition **before** clearing Redis:

- `managed_only` → F1 via existing `case_indexing_complete_task` (no completion-trigger clear)
- `mixed` → same F1 path
- `legacy_only` → accepted legacy repair (clear trigger, waiting_for_completion, same task)
- unknown / PG composition failure → fail closed, no trigger clear, no queue

No competing repair worker was added. No UI path can clear state and then bypass the F1 composition guard.

## Hunt Artifacts coverage note

One informational note on the Events search surface (`static/templates/hunting/tab_events.html`), filled from the same readiness API.

Search remains fully enabled. Query, filters, pagination, detail, and raw detail are not disabled by readiness.

- BUILDING_INITIAL with published evidence: `Results cover currently published evidence. Ingest is still adding evidence.`
- ACTIVE with no expanding BUILDING_INITIAL: note hidden/quiet
- N ACTIVE + N+1 BUILDING_REPLACEMENT: not “partial search”; optional `Replacement processing in background.`
- mixed: qualitative managed + untracked wording
- authority unavailable: status unavailable; Hunt search stays enabled

## Redis failure

Read with Redis, then without. Evidence, Privacy, and Reconciliation are identical. Only Live Activity changes.

## PostgreSQL failure

If PostgreSQL readiness authority cannot be read:

- composition `unknown`
- durable dimensions `unavailable`
- no ready / complete / legacy / 100%
- no Redis fallback
- no ClickHouse readiness fallback

UNKNOWN != LEGACY. Missing control-plane schema is not treated as a legacy install.

## Real PostgreSQL tests

`tests/test_phase1b_tranche_f2_readiness_ui.py` exercises the actual DTO/API for:

BUILDING_INITIAL before DURABLE; BUILDING_INITIAL with DURABLE before EOF; ACTIVE; N ACTIVE + N+1 BUILDING_REPLACEMENT; replacement activation; privacy hole; zero-event; failed/incomplete; legacy-only; managed-only; mixed; new source after reconciled audit; new DURABLE batch; invalidation; PG authority failure; Redis unavailable.

Search-during-ingest E2E uses the actual Hunt Events route plus the readiness API and template wiring.

## Product-search regression

`tests/test_phase1b_tranche_f2_product_search_publication_gate.py` remains the publication-gate proof. The bridge was not modified to make UI implementation easier.

## Performance

Normal readiness request, measured on a representative 4-source / 12-DURABLE-batch fixture (`test_representative_polling_is_bounded_and_clickhouse_free`):

- ClickHouse calls: **0**
- PostgreSQL statements: **8**
- PostgreSQL rows loaded (generations + batches + privacy completions/watermarks + latest F1 audit): **16**
- Redis calls: **2** (live-activity ping + progress hash; a failed ping is 1 and cannot change durable dimensions)
- Response latency: **166 ms**
- Payload: **1779 bytes**
- `final_percent`: always `null`

Accepted Hunt publication-bridge latency from `test_publication_bridge_query_shape_and_latency` (unchanged bridge): product request **110 ms**; 2 hunt SELECT round-trips; 0 extra round-trips. This tranche does not start a new ClickHouse optimization effort.

## Security / accessibility

The readiness endpoint requires login and uses `Case.get_by_uuid` case access. Cross-case reads abort 403. Repair remains write-gated; viewers cannot repair. Repair control is a labeled `button type="button"`. Strip/note use `role="status"` and text, not color alone. No new frontend framework.

## No-later-phase audit

- Phase 2 ClickHouse modernization: **NO**
- Phase 3 ERK API migration: **NO**
- `event_observations_current`: **NO**
- `events_current`: **NO**
- LEK calculation or reader cutover: **NO**
- broad product-reader migration: **NO**
- Phase 4 evidence identity/dedup: **NO**
- Phase 5 overlay migration: **NO**
- Phase 6 derived-evidence migration: **NO**
- Qdrant lifecycle migration: **NO**
- MEMORY_JOB / PCAP managed generations: **NO**
- `docs/database_flow_contracts/event_surface_consumers.json`: **unchanged**
- Hunt publication bridge: **not generalized** to unrelated readers

Parser certification unchanged: 84 registered / 12 CERTIFIED_MANAGED / 72 DEFERRED_LEGACY_ONLY / 0 unclassified.

## Final F2 assessment

| Requirement | Status |
|---|---|
| 1B.1 manifest + watermarks + control projections | Present from A–E1 |
| 1B.2 progressive BUILDING_INITIAL publication + hidden replacement | Protocol from D1; Hunt Artifacts uses the accepted F2 publication bridge |
| 1B.3 AI freeze-then-verify | Present from E2 + E2 closure |
| 1B.4 PostgreSQL-authoritative completion reconciliation | Present from F1 + F1 closure |
| 1B.5 PG readiness UI + Redis decoration + non-blocking Hunt coverage note | **Implemented in this tranche** |

Remaining work after this implementation is only independent **Phase 1B EXIT ACCEPTANCE REVIEW**. Do not start Phase 2.
