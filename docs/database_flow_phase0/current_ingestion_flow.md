# Phase 0A Current Ingestion Flow

Source of truth: `casescope_database_flow_plan_v4_locked.md`. This document describes current code, not the target architecture.

## Flow Diagram

```text
Case upload / staging / reprocess
  -> CaseFile rows in PostgreSQL
  -> queue_case_files_for_parsing(case_id, case_uuid, case_files)
       - auto-completes retained sidecars/support files
       - marks parseable files QUEUED
       - commits PostgreSQL before Celery dispatch
       - dispatches parse_file_task per CaseFile

Additional current queue/recovery paths:
  -> routes/case_files.py::import_staging_orphans -> parse_file_task.delay(...)
  -> routes/case_files.py::recover_stuck_files -> parse_file_task.delay(...)
  -> These bypass the shared queue step's sidecar handling, cancellation clearing,
     and progress initialization behavior.

parse_file_task(file_path, case_id, case_file_id, ...)
  -> cancellation check
  -> case timezone lookup in PostgreSQL
  -> mark CaseFile ingesting
  -> parser registry resolves parser
  -> get_fresh_client() ClickHouse client
  -> delete_hayabusa_matches_for_case_file(case_file_id)
  -> _cleanup_case_file_events(case_file_id)
       - delete_file_events(wait=True)
       - ALTER TABLE events DELETE WHERE case_file_id = ...
       - ALTER TABLE events_buffer DELETE WHERE case_file_id = ...
       - wait for events mutation completion
  -> process_file(...)
       - ParserRegistry singleton
       - resolve_parser_for_file(...)
       - parser.parse(file_path)
       - BatchProcessor(use_buffer=True)
       - per-event alias candidate extraction
       - client.insert("events_buffer", batch)
       - upsert_alias_candidates(...) per batch
  -> EVTX path when artifact_type == evtx
       - EvtxECmd and Hayabusa run in parallel when Hayabusa is available
       - EvtxECmd JSONL is consumed and normalized into ParsedEvent rows
       - nested Payload JSON is decoded where present
       - search_blob, raw_json, extra_fields, ERK metadata are built per event
       - Hayabusa detections are merged by record id
       - current key is record_id only, not (source_file, record_id)
  -> post-parse Hayabusa MITRE match insert for EVTX
  -> CaseFile status/events_indexed/parser_type/error_message update
  -> progress update
  -> when all files complete, case_indexing_complete_task.delay(...)

case_indexing_complete_task(case_id, case_uuid, case_file_ids)
  -> verify no files still pending/queued/ingesting; defer if needed
  -> OPTIMIZE TABLE events_buffer
  -> deduplicate_case_events(... rewrite_guard_behavior="skip")
  -> discover_known_systems(...)
  -> discover_known_users(...)
  -> stale ingesting cleanup
  -> duplicate CaseFile path cleanup
  -> staging folder junk/orphan cleanup
  -> ingest summary and audit/work activity
  -> queue deterministic MITRE mapping
  -> queue high-priority event embeddings
  -> queue materialize_case_graph_task(...)
  -> clear progress

materialize_case_graph_task(...)
  -> ensure graph projection state
  -> materialize_events_for_case(...) from events
  -> materialize memory graph facts
  -> materialize network graph facts
  -> audit graph projection result
```

## Current Baseline Discrepancies / Confirmations

- Confirmed: `events_buffer` remains the default ingest destination through `BatchProcessor`.
- Confirmed: final completion still runs `OPTIMIZE TABLE events_buffer`.
- Confirmed: pre-parse cleanup uses synchronous `delete_file_events(wait=True)`.
- Confirmed: whole-case delete guard currently fails open when Redis is unavailable unless `require_lock=True`.
- Confirmed: analyst-state PostgreSQL authority is not yet complete; product code still joins transitional projections and legacy `events` columns.
- Confirmed: destructive post-ingest dedup still exists and uses legacy artifact recipes that include `source_file` for several artifacts.
- Confirmed: Phase 1+ concepts such as LEK, source_generation, ingest_attempt_id, deterministic ingest batches, durable batch projections, and current surfaces are not currently implemented.
- Confirmed: some recovery/import routes dispatch `parse_file_task` directly instead of using `queue_case_files_for_parsing`.
- Confirmed: Hayabusa enrichment currently correlates by `record_id` only; the v4 Phase 1.7 target `(source_file, record_id)` key is not implemented.
- Confirmed: behavioral profiling is not part of automatic ingest completion; it is invoked elsewhere.
