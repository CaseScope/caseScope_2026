# Phase 0A Direct Events Reader Inventory

Source of truth: `casescope_database_flow_plan_v4_locked.md`.

Scope: production code paths that directly query ClickHouse `events`. Tests are excluded except where they encode migration/diagnostic behavior. Repeated queries are grouped by module/function family when they share purpose, dependencies, and target surface.

## Summary

- Full-scan production file/function readers: 167
- Production files touched: 52
- Embedded query strings: 227+ (`models/pattern_rules.py` 75, `utils/pattern_check_definitions.py` about 136, `models/rag.py` 16)
- Read vs in-query write: 159 read, 8 read+write
- Approximate full-scan target split: `events_current` 69, `event_observations_current` 8, administrative/raw 33, unresolved 57
- Grouped inventory records below: 23

Highest-risk migrations:

- `routes/hunting.py`: primary analyst UI, broad filters, overlays, selectors, raw payload fields.
- AI/RAG/report paths: mixed use of `raw_json`, `extra_fields`, `search_blob`, MITRE/IOC/noise/analyst overlays; counting basis must be ratified.
- Pattern/detector paths: should likely move to LEK basis, but current code reads raw `events` directly.
- `utils/event_deduplication.py`: current destructive physical rewrite path remains administrative/raw-only until Phase 4.
- Analyst-state/noise bootstrap helpers: authority is not yet PostgreSQL, matching the locked plan baseline.

Highest fan-out hubs:

- `utils/clickhouse.py`
- `utils/chat_tools.py`
- `routes/hunting.py`
- `tasks/rag_tasks.py`
- `utils/pattern_check_definitions.py`
- `models/pattern_rules.py`
- `models/rag.py`

Embedded runtime query libraries:

| File | Container | Count | Basis | Future surface |
|---|---|---:|---|---|
| `models/pattern_rules.py` | `*_ATTACK_PATTERNS` `detection_query` | 75 | Logical | `events_current` |
| `utils/pattern_check_definitions.py` | `PATTERN_CHECKS` `query_template` | ~136 | Logical | `events_current` |
| `models/rag.py` | `CAMPAIGN_TEMPLATES` `detection_query` | 16 | Logical | `events_current` |

## Reader Records

| File / function family | Purpose | Basis | Dependencies | Category | Future surface |
|---|---|---|---|---|---|
| `utils/clickhouse.py` generic helpers | Generic events queries, ERK lookup, counts, stats | Unknown | ERK for lookup | maintenance/other | unresolved |
| `tasks/celery_tasks.py` `_insert_hayabusa_mitre_matches_for_case_file` | Fresh EVTX Hayabusa MITRE backfill | Physical | MITRE, selector_key, extra_fields | MITRE, finalization | event_observations_current |
| `tasks/celery_tasks.py` delete/rebuild/IOC flows | Counts before delete/rebuild; IOC candidate reads | Unknown | IOC, raw_json | deletion, IOC | unresolved |
| `routes/case_files.py` stats routes | UI counts and overlay counters | Logical | IOC, MITRE, noise, analyst state, selector_key | hunting/UI | events_current |
| `routes/hunting.py` hunting routes | Main event list/detail/search/process pivots | Logical | IOC, MITRE, noise, analyst state, selector_key, ERK, raw_json, extra_fields, search_blob | hunting/UI | events_current |
| `utils/investigation_context.py` | AI/investigation context retrieval | Unknown | ERK, selector_key, raw_json, extra_fields, search_blob, MITRE | AI/RAG | unresolved |
| `utils/graph_query.py` | Event evidence lookup for graph display | Physical | ERK, selector_key | graph | event_observations_current |
| `utils/graph_materializer.py` | Streams event rows to graph facts | Physical | ERK, extra_fields | graph | event_observations_current |
| `utils/graph_projection.py` | Graph eligibility probe and EXPLAIN | Physical | ERK | graph/diagnostic | event_observations_current |
| `utils/graph_support_lifecycle.py` | ERK lookup by case_file_id | Physical | ERK | graph/deletion | event_observations_current |
| `utils/ioc_artifact_tagger.py` | IOC scans and artifact/host summaries | Physical | IOC, ERK, raw_json, extra_fields, search_blob | IOC | event_observations_current |
| `utils/ioc_match_provenance.py` | IOC match provenance lookup | Physical | IOC, ERK, search_blob | IOC | event_observations_current |
| `utils/event_analyst_state.py` | Legacy analyst state bootstrap/projection | Unknown | analyst state, selector_key, ERK | analyst-state/migration | unresolved |
| `utils/event_noise_state.py` | Legacy/effective noise state | Unknown | noise, selector_key, ERK | noise/migration | unresolved |
| `utils/event_mitre_state.py` | MITRE state and summary helpers | Physical | MITRE, selector_key, ERK, extra_fields | MITRE | event_observations_current |
| `utils/behavioral_profiler.py`, `utils/temporal_baseline.py`, `utils/stateful_detectors/*` | Behavioral and auth detectors | Logical | event_id, time, user, host | profile/detector | events_current |
| `pipeline/pattern_analysis.py`, `utils/deterministic_evidence_engine.py`, `utils/candidate_extractor.py` | Pattern/candidate detection | Logical | IOC, MITRE, noise, analyst state, selector_key, ERK, raw_json, extra_fields, search_blob | detector | events_current |
| AI/RAG/chat modules | Embeddings, retrieval, source snippets | Unknown | IOC, MITRE, noise, analyst state, selector_key, ERK, raw_json, extra_fields, search_blob | AI/RAG | unresolved |
| `utils/known_users_discovery.py`, `utils/known_systems_discovery.py` | User/system discovery | Logical | user/system columns | discovery | events_current |
| `utils/event_deduplication.py` | Legacy duplicate counting/deletion | Physical | ERK, raw_json/search_blob for some recipes | maintenance/deletion | administrative/raw-events-only |
| IOC/report/timeline generators | IOC views, reports, timelines, summaries | Unknown | IOC, MITRE, noise, analyst state, selector_key, ERK, raw_json, extra_fields, search_blob | IOC/export/AI | unresolved |
| migration/backfill modules | Administrative backfills and shadow copies | Physical | selector_key, ERK, raw_json, extra_fields, search_blob | migration | administrative/raw-events-only |

Full machine-readable details are in `docs/database_flow_phase0/events_reader_inventory.json`.
