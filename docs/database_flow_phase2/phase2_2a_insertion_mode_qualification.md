# Phase 2.2A Insertion-Mode Qualification Result

## 1. Starting State

{
  "repository": "/opt/casescope",
  "python": "/opt/casescope/venv/bin/python",
  "head": "3ad458b9db38945787392a504786a73d578cf771",
  "origin_main": "3ad458b9db38945787392a504786a73d578cf771",
  "head_equals_origin_main": true,
  "working_tree_clean_at_start": false,
  "allowed_dirty_paths": [
    "docs/database_flow_phase2/phase2_2a_insertion_mode_qualification.json",
    "docs/database_flow_phase2/phase2_2a_insertion_mode_qualification.md",
    "scripts/phase2_2a_insertion_mode_qualification.py",
    "tests/test_phase2_2a_insertion_mode_qualification.py"
  ],
  "dirty_paths": [
    "docs/database_flow_phase2/phase2_2a_insertion_mode_qualification.json",
    "docs/database_flow_phase2/phase2_2a_insertion_mode_qualification.md",
    "scripts/phase2_2a_insertion_mode_qualification.py",
    "tests/test_phase2_2a_insertion_mode_qualification.py"
  ],
  "unexpected_dirty_paths": [],
  "expected_head": "3ad458b9db38945787392a504786a73d578cf771",
  "expected_version": "4.26.0",
  "version": "4.26.0",
  "ok": true
}

## 2. Phase 2.1 Closed Preconditions

{
  "version": "4.26.0",
  "commit": "3ad458b9db38945787392a504786a73d578cf771",
  "clickhouse": "26.7.3.19",
  "idx_search_blob_text": true,
  "idx_search_ngram": true,
  "idx_search_token_absent": true,
  "materialize_skip_indexes_on_insert": "1",
  "command_line": "COMMAND_LINE_INDEX_DEFER",
  "keep_materialize": "KEEP_PRODUCTION_MATERIALIZE_SKIP_INDEXES_ON_INSERT_1",
  "phase2_1_closed": true
}

## 3. Production Server Insert Settings

[
  {
    "name": "async_insert",
    "value": "1",
    "default": "1",
    "changed": 0,
    "type": "Bool"
  },
  {
    "name": "async_insert_busy_timeout_decrease_rate",
    "value": "0.2",
    "default": "0.2",
    "changed": 0,
    "type": "Double"
  },
  {
    "name": "async_insert_busy_timeout_increase_rate",
    "value": "0.2",
    "default": "0.2",
    "changed": 0,
    "type": "Double"
  },
  {
    "name": "async_insert_busy_timeout_max_ms",
    "value": "200",
    "default": "200",
    "changed": 0,
    "type": "Milliseconds"
  },
  {
    "name": "async_insert_busy_timeout_min_ms",
    "value": "50",
    "default": "50",
    "changed": 0,
    "type": "Milliseconds"
  },
  {
    "name": "async_insert_busy_timeout_ms",
    "value": "200",
    "default": "200",
    "changed": 0,
    "type": "Milliseconds"
  },
  {
    "name": "async_insert_cleanup_timeout_ms",
    "value": "1000",
    "default": "1000",
    "changed": 0,
    "type": "Milliseconds"
  },
  {
    "name": "async_insert_deduplicate",
    "value": "0",
    "default": "0",
    "changed": 0,
    "type": "Bool"
  },
  {
    "name": "async_insert_max_data_size",
    "value": "10485760",
    "default": "10485760",
    "changed": 0,
    "type": "UInt64"
  },
  {
    "name": "async_insert_max_query_number",
    "value": "450",
    "default": "450",
    "changed": 0,
    "type": "UInt64"
  },
  {
    "name": "async_insert_poll_timeout_ms",
    "value": "10",
    "default": "10",
    "changed": 0,
    "type": "Milliseconds"
  },
  {
    "name": "async_insert_stale_timeout_ms",
    "value": "0",
    "default": "0",
    "changed": 0,
    "type": "Milliseconds"
  },
  {
    "name": "async_insert_threads",
    "value": "16",
    "default": "16",
    "changed": 0,
    "type": "UInt64"
  },
  {
    "name": "async_insert_use_adaptive_busy_timeout",
    "value": "1",
    "default": "1",
    "changed": 0,
    "type": "Bool"
  },
  {
    "name": "materialize_skip_indexes_on_insert",
    "value": "1",
    "default": "1",
    "changed": 0,
    "type": "Bool"
  },
  {
    "name": "throw_if_deduplication_in_dependent_materialized_views_enabled_with_async_insert",
    "value": "0",
    "default": "0",
    "changed": 0,
    "type": "Bool"
  },
  {
    "name": "wait_for_async_insert",
    "value": "1",
    "default": "1",
    "changed": 0,
    "type": "Bool"
  },
  {
    "name": "wait_for_async_insert_timeout",
    "value": "120",
    "default": "120",
    "changed": 0,
    "type": "Seconds"
  }
]

## 4. Current Application Client Settings

{
  "get_client_pins_async_insert": false,
  "get_fresh_client_pins_async_insert": false,
  "get_client_pins_wait_for_async_insert": false,
  "explicit_async_insert": false,
  "explicit_wait_for_async_insert": false,
  "inherits_server_user_defaults": true,
  "settings_present": [
    "max_threads",
    "max_execution_time"
  ],
  "source_mentions_async_insert": false,
  "acceptable_final_architecture": false,
  "reason": "Phase 2.2 must end with an explicit CaseScope insertion-mode decision on the parser/event-ingest boundary."
}

## 5. Event INSERT Inventory

[
  {
    "file": "parsers/registry.py",
    "function": "BatchProcessor.flush",
    "destination_table": "events (events_buffer only if use_buffer=True)",
    "client_source": "constructor clickhouse_client; process_file/process_evtx_group pass get_fresh_client()",
    "batch_size_source": "BatchProcessor.DEFAULT_BATCH_SIZE=10000 / process_file(batch_size=10000) / Config.PARSER_BATCH_SIZE unused by this call",
    "managed_or_legacy": "legacy",
    "shared_ingest_fence_coverage": true,
    "current_explicit_async_setting": false,
    "current_explicit_wait_setting": false,
    "must_be_covered_by_phase_2_2": true,
    "notes": "Production callers do not pass use_buffer=True. No repo insert() into events_buffer."
  },
  {
    "file": "utils/manifest_protocol.py",
    "function": "insert_managed_batch",
    "destination_table": "events",
    "client_source": "caller-supplied clickhouse_client (Celery get_fresh_client())",
    "batch_size_source": "generation.configured_batch_size (frozen); new gens use Config.PHASE1B_MANIFEST_BATCH_SIZE or 10000",
    "managed_or_legacy": "managed",
    "shared_ingest_fence_coverage": true,
    "current_explicit_async_setting": false,
    "current_explicit_wait_setting": false,
    "must_be_covered_by_phase_2_2": true
  },
  {
    "file": "tasks/celery_tasks.py",
    "function": "_process_managed_initial_case_file / parse_file_task managed branch",
    "destination_table": "events via insert_managed_batch",
    "client_source": "get_fresh_client() then reused for verify + control projection",
    "batch_size_source": "generation.configured_batch_size",
    "managed_or_legacy": "managed",
    "shared_ingest_fence_coverage": true,
    "current_explicit_async_setting": false,
    "current_explicit_wait_setting": false,
    "must_be_covered_by_phase_2_2": true
  },
  {
    "file": "tasks/celery_tasks.py",
    "function": "recover_staged_ingest_batch_task",
    "destination_table": "events via insert_managed_batch",
    "client_source": "get_fresh_client()",
    "batch_size_source": "generation.configured_batch_size",
    "managed_or_legacy": "repair/retry",
    "shared_ingest_fence_coverage": true,
    "current_explicit_async_setting": false,
    "current_explicit_wait_setting": false,
    "must_be_covered_by_phase_2_2": true
  },
  {
    "file": "tasks/celery_tasks.py",
    "function": "parse_file_task legacy branch / process_file",
    "destination_table": "events via BatchProcessor.flush",
    "client_source": "get_fresh_client()",
    "batch_size_source": "process_file default 10000",
    "managed_or_legacy": "legacy",
    "shared_ingest_fence_coverage": true,
    "current_explicit_async_setting": false,
    "current_explicit_wait_setting": false,
    "must_be_covered_by_phase_2_2": true
  },
  {
    "file": "tasks/celery_tasks.py",
    "function": "parse_evtx_group_task / process_evtx_group",
    "destination_table": "events via BatchProcessor.flush or managed insert_managed_batch",
    "client_source": "get_fresh_client()",
    "batch_size_source": "10000 or generation.configured_batch_size",
    "managed_or_legacy": "legacy or managed",
    "shared_ingest_fence_coverage": true,
    "current_explicit_async_setting": false,
    "current_explicit_wait_setting": false,
    "must_be_covered_by_phase_2_2": true
  },
  {
    "file": "utils/manifest_protocol.py",
    "function": "project_generation_control_state",
    "destination_table": "visible_evidence_generations / durable_ingest_batches",
    "client_source": "same Celery get_fresh_client() as events INSERT",
    "batch_size_source": "n/a (control rows)",
    "managed_or_legacy": "control projection",
    "shared_ingest_fence_coverage": false,
    "current_explicit_async_setting": false,
    "current_explicit_wait_setting": false,
    "must_be_covered_by_phase_2_2": false,
    "notes": "Must not inherit events insertion-mode pin. Covered as a 2.2B non-goal."
  },
  {
    "file": "utils/staged_batch_reconciler.py",
    "function": "reconcile_staged_batch -> recover_staged_ingest_batch_task",
    "destination_table": "events via recovery insert_managed_batch",
    "client_source": "get_fresh_client() in celery reconciler/recovery tasks",
    "batch_size_source": "generation.configured_batch_size",
    "managed_or_legacy": "repair/retry",
    "shared_ingest_fence_coverage": true,
    "current_explicit_async_setting": false,
    "current_explicit_wait_setting": false,
    "must_be_covered_by_phase_2_2": true
  },
  {
    "file": "migrations/*.py / scripts/* / tests/* / bin/*",
    "function": "various",
    "destination_table": "events or scratch tables",
    "client_source": "get_fresh_client or dedicated connect",
    "batch_size_source": "n/a",
    "managed_or_legacy": "migration / test / offline utility",
    "shared_ingest_fence_coverage": "varies",
    "current_explicit_async_setting": false,
    "current_explicit_wait_setting": false,
    "must_be_covered_by_phase_2_2": false
  }
]

## 6. Client-Scope Inventory

{
  "get_client": {
    "settings": [
      "max_threads",
      "max_execution_time"
    ],
    "async_insert_explicit": false,
    "wait_for_async_insert_explicit": false,
    "cached": true,
    "primary_uses": "reader (Hunt, reports, graph queries, privacy alias scan, case files)",
    "must_not_pin_insert_mode": true
  },
  "get_fresh_client": {
    "settings": [
      "max_threads",
      "max_execution_time"
    ],
    "async_insert_explicit": false,
    "wait_for_async_insert_explicit": false,
    "cached": false,
    "primary_uses": [
      "event writer (parse_file_task, recover_staged_ingest_batch_task, process_file)",
      "control-projection writer (same client after managed INSERT)",
      "derivation (IOC tagger, candidate extractor, behavioral profiler, graph materializer)",
      "migration/admin",
      "repair/reconciler"
    ],
    "must_not_pin_insert_mode_globally": true
  },
  "narrowest_safe_future_boundary": {
    "shape": "per-call INSERT settings on events inserts",
    "option": "A",
    "apply_to": [
      "utils.manifest_protocol.insert_managed_batch client.insert('events', ...)",
      "parsers.registry.BatchProcessor.flush client.insert(self.table, ...) when table=='events'"
    ],
    "do_not_apply_to": [
      "utils.clickhouse.get_client",
      "utils.clickhouse.get_fresh_client",
      "Hunt / graph / IOC / derivation readers",
      "verify_ingest_batch SELECT",
      "visible_evidence_generations INSERT",
      "durable_ingest_batches INSERT",
      "migration clients"
    ],
    "reason": "tasks.celery_tasks.parse_file_task / recover_staged_ingest_batch_task obtain one get_fresh_client() and reuse it for events INSERT, verification SELECT, and control projection INSERT. Pinning async_insert on the generic client would change acknowledgement semantics of control projections and Hunt/read sessions. Per-call settings on the events insert only is the narrowest explicit parser/event-ingest boundary required by Phase 2.2.",
    "control_projections": "unchanged; keep current client/session defaults",
    "fallback_if_per_call_unreliable": "dedicated get_event_ingest_client() used only for events INSERT"
  },
  "why_not_global": "Hunt, graph, IOC, and derivation sessions share get_client/get_fresh_client. Celery parser tasks reuse one fresh client for INSERT + SELECT verify + control projection. A global async_insert pin would leak into those paths."
}

## 7. clickhouse_connect Async-Mode Proof

Client.insert entered async buffering: True

{
  "client_insert_sql_prefix": "INSERT INTO {table} (...) FORMAT Native",
  "settings_passed_as_http_params": true,
  "qid_async": "97bba3b4-9606-4681-a148-e7153eec4362",
  "qid_sync": "f3555363-c882-4036-bc4d-920f7ae7f55f",
  "async_wait_client_ms": 220.75427882373333,
  "sync_client_ms": 6.194841116666794,
  "async_query_log": {
    "query_id": "97bba3b4-9606-4681-a148-e7153eec4362",
    "type": "QueryFinish",
    "query_kind": "Insert",
    "query": "INSERT INTO `async_probe` (`k`, `v`) FORMAT Native\n",
    "async_insert": "",
    "wait_for_async_insert": "",
    "async_insert_query": 1,
    "async_insert_bytes": 250,
    "query_duration_ms": 3
  },
  "sync_query_log": {
    "query_id": "f3555363-c882-4036-bc4d-920f7ae7f55f",
    "type": "QueryFinish",
    "query_kind": "Insert",
    "query": "INSERT INTO `async_probe` (`k`, `v`) FORMAT Native\n",
    "async_insert": "0",
    "wait_for_async_insert": "",
    "async_insert_query": 0,
    "async_insert_bytes": 0,
    "query_duration_ms": 2
  },
  "async_asynchronous_insert_log": [
    {
      "query_id": "97bba3b4-9606-4681-a148-e7153eec4362",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 20,
      "bytes": 250,
      "flush_time": "2026-08-22 16:38:41",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "e9c57e88-3306-4357-9a7f-892ac1e8749e",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 1,
      "bytes": 36,
      "flush_time": "2026-08-22 16:36:05",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "f5d064db-1208-451a-ac24-683e84c66bfe",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 20,
      "bytes": 250,
      "flush_time": "2026-08-22 16:36:04",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "94b911f2-b553-4336-bec9-3b5024decbd8",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 1,
      "bytes": 36,
      "flush_time": "2026-08-22 15:31:56",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "6257fe1a-0129-4596-9024-6ea4fdca5483",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 20,
      "bytes": 250,
      "flush_time": "2026-08-22 15:31:55",
      "timeout_milliseconds": 50,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "c937d0cc-9b1b-421c-8c30-2112789eccb6",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 1,
      "bytes": 36,
      "flush_time": "2026-08-22 15:29:12",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "ac216009-9400-4f17-ae04-be797b6eb2ad",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 20,
      "bytes": 250,
      "flush_time": "2026-08-22 15:29:11",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "fedaa7d2-fe92-42f9-8469-18c83146288c",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 1,
      "bytes": 26,
      "flush_time": "2026-08-22 15:27:25",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "32b506fd-8ddb-47a0-b392-33c6636ee7a3",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 20,
      "bytes": 250,
      "flush_time": "2026-08-22 15:26:55",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "9dd2e15b-0307-4cdf-a7e6-6b2c7864a3e4",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 1,
      "bytes": 36,
      "flush_time": "2026-08-22 15:26:55",
      "timeout_milliseconds": 50,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    }
  ],
  "sync_asynchronous_insert_log": [
    {
      "query_id": "97bba3b4-9606-4681-a148-e7153eec4362",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 20,
      "bytes": 250,
      "flush_time": "2026-08-22 16:38:41",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "e9c57e88-3306-4357-9a7f-892ac1e8749e",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 1,
      "bytes": 36,
      "flush_time": "2026-08-22 16:36:05",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "f5d064db-1208-451a-ac24-683e84c66bfe",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 20,
      "bytes": 250,
      "flush_time": "2026-08-22 16:36:04",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "94b911f2-b553-4336-bec9-3b5024decbd8",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 1,
      "bytes": 36,
      "flush_time": "2026-08-22 15:31:56",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "6257fe1a-0129-4596-9024-6ea4fdca5483",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 20,
      "bytes": 250,
      "flush_time": "2026-08-22 15:31:55",
      "timeout_milliseconds": 50,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "c937d0cc-9b1b-421c-8c30-2112789eccb6",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 1,
      "bytes": 36,
      "flush_time": "2026-08-22 15:29:12",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "ac216009-9400-4f17-ae04-be797b6eb2ad",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 20,
      "bytes": 250,
      "flush_time": "2026-08-22 15:29:11",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "fedaa7d2-fe92-42f9-8469-18c83146288c",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 1,
      "bytes": 26,
      "flush_time": "2026-08-22 15:27:25",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "32b506fd-8ddb-47a0-b392-33c6636ee7a3",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 20,
      "bytes": 250,
      "flush_time": "2026-08-22 15:26:55",
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "9dd2e15b-0307-4cdf-a7e6-6b2c7864a3e4",
      "status": "Ok",
      "data_kind": "Parsed",
      "rows": 1,
      "bytes": 36,
      "flush_time": "2026-08-22 15:26:55",
      "timeout_milliseconds": 50,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    }
  ],
  "table_asynchronous_insert_log": [
    {
      "query_id": "97bba3b4-9606-4681-a148-e7153eec4362",
      "status": "Ok",
      "rows": 20,
      "bytes": 250,
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "e9c57e88-3306-4357-9a7f-892ac1e8749e",
      "status": "Ok",
      "rows": 1,
      "bytes": 36,
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "f5d064db-1208-451a-ac24-683e84c66bfe",
      "status": "Ok",
      "rows": 20,
      "bytes": 250,
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "94b911f2-b553-4336-bec9-3b5024decbd8",
      "status": "Ok",
      "rows": 1,
      "bytes": 36,
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "6257fe1a-0129-4596-9024-6ea4fdca5483",
      "status": "Ok",
      "rows": 20,
      "bytes": 250,
      "timeout_milliseconds": 50,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "c937d0cc-9b1b-421c-8c30-2112789eccb6",
      "status": "Ok",
      "rows": 1,
      "bytes": 36,
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "ac216009-9400-4f17-ae04-be797b6eb2ad",
      "status": "Ok",
      "rows": 20,
      "bytes": 250,
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "fedaa7d2-fe92-42f9-8469-18c83146288c",
      "status": "Ok",
      "rows": 1,
      "bytes": 26,
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "32b506fd-8ddb-47a0-b392-33c6636ee7a3",
      "status": "Ok",
      "rows": 20,
      "bytes": 250,
      "timeout_milliseconds": 0,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    },
    {
      "query_id": "9dd2e15b-0307-4cdf-a7e6-6b2c7864a3e4",
      "status": "Ok",
      "rows": 1,
      "bytes": 36,
      "timeout_milliseconds": 50,
      "query": "INSERT INTO casescope_phase2_2a_scratch.async_probe (k, v) FORMAT Native"
    }
  ],
  "async_query_id_in_async_insert_log": true,
  "sync_query_id_in_async_insert_log": false,
  "timing_distinct": true,
  "async_insert_participated": true,
  "sync_is_genuinely_synchronous": true,
  "client_insert_honors_async_distinctly": true,
  "proof_note": "clickhouse_connect Client.insert() sends INSERT ... FORMAT Native over HTTP. async+wait client 220.8 ms vs sync 6.2 ms; async query_id in asynchronous_insert_log=True; sync query_id in asynchronous_insert_log=False.",
  "nowait_demo": {
    "classified": "ASYNC_NO_WAIT_FORBIDDEN",
    "eligible_for_production": false,
    "query_id": "0220b235-d9bb-4577-9b60-e1ed24998bc5",
    "error": null
  },
  "hard_gate": "PASS"
}

## 8. Benchmark Corpus

{
  "rows": 1000000,
  "fingerprint": {
    "n": 1000000,
    "min_ts": "1601-01-01 00:27:09.167000",
    "max_ts": "2026-07-23 09:06:00.002000",
    "blob_bytes": 151801893,
    "raw_bytes": 452537190,
    "extra_bytes": 750811244,
    "fp": "C337E274E231CBC4D0626690F442EB49",
    "source_case_id": 32,
    "reused_existing_corpus": true,
    "copy_seconds": 0
  },
  "target_rows": 1000000,
  "reused": true,
  "disk_before": {
    "path": "/var/lib/clickhouse",
    "free_bytes": 75671228416,
    "total_bytes": 524068962304
  },
  "disk_after_copy": {
    "path": "/var/lib/clickhouse",
    "free_bytes": 75671162880,
    "total_bytes": 524068962304
  }
}

## 9. Raw Insert Matrix

- SYNC 10000: 8549.165972484852 rows/s, p50 275.4960369784385 ms, p95 358.24862788431346 ms, RSS 281.890625 MiB
- ASYNC_WAIT 10000: 8350.461088909324 rows/s, p50 283.323856536299 ms, p95 360.78496023546904 ms, RSS 993.2421875 MiB
- SYNC 25000: 8749.772984968575 rows/s, p50 670.807289192453 ms, p95 756.391784735024 ms, RSS 418.46875 MiB
- ASYNC_WAIT 25000: 8699.257421752507 rows/s, p50 687.1544562745839 ms, p95 752.5055964011699 ms, RSS 993.2421875 MiB
- SYNC 50000: 8959.118814212656 rows/s, p50 1314.438204281032 ms, p95 1422.1747010014951 ms, RSS 648.20703125 MiB
- ASYNC_WAIT 50000: 9023.72109962807 rows/s, p50 1315.7383527141064 ms, p95 1414.226719783619 ms, RSS 993.2421875 MiB
- SYNC 100000: 9106.727375897139 rows/s, p50 2619.7289370466024 ms, p95 2767.6025251159444 ms, RSS 989.970703125 MiB
- ASYNC_WAIT 100000: 9087.155507791538 rows/s, p50 2608.317797537893 ms, p95 2770.322672976181 ms, RSS 995.994140625 MiB

## 10. Concurrency Matrix

[
  {
    "mode": "PHASE2_2_MODE_SYNC",
    "batch_size": 10000,
    "writers": 1,
    "per_writer_rows": 250000,
    "aggregate_rows": 250000,
    "aggregate_wall_seconds": 31.547388079576194,
    "aggregate_rows_per_sec": 7924.586319773655,
    "per_writer_p50_ms": [
      276.3535240665078
    ],
    "per_writer_p95_ms": [
      371.24162614345545
    ],
    "peak_rss_mb": 996.703125,
    "parts": {
      "by_part_type": [
        {
          "part_type": "Wide",
          "parts": 5,
          "rows": 250000,
          "bytes": 61470310
        }
      ],
      "active_parts": 5,
      "active_rows": 250000,
      "merges_in_flight": 0
    },
    "async_logs": [
      {}
    ],
    "errors": []
  },
  {
    "mode": "PHASE2_2_MODE_SYNC",
    "batch_size": 10000,
    "writers": 2,
    "per_writer_rows": 250000,
    "aggregate_rows": 500000,
    "aggregate_wall_seconds": 49.18988074734807,
    "aggregate_rows_per_sec": 10164.69225790827,
    "per_writer_p50_ms": [
      515.2681125327945,
      615.7664302736521
    ],
    "per_writer_p95_ms": [
      761.8156015872955,
      793.2672742754221
    ],
    "peak_rss_mb": 1057.9140625,
    "parts": {
      "by_part_type": [
        {
          "part_type": "Wide",
          "parts": 10,
          "rows": 500000,
          "bytes": 122940646
        }
      ],
      "active_parts": 10,
      "active_rows": 500000,
      "merges_in_flight": 0
    },
    "async_logs": [
      {},
      {}
    ],
    "errors": []
  },
  {
    "mode": "PHASE2_2_MODE_SYNC",
    "batch_size": 10000,
    "writers": 4,
    "per_writer_rows": 250000,
    "aggregate_rows": 1000000,
    "aggregate_wall_seconds": 96.9006272079423,
    "aggregate_rows_per_sec": 10319.850643010457,
    "per_writer_p50_ms": [
      722.6831531152129,
      1009.1446526348591,
      920.1701954007149,
      836.2266570329666
    ],
    "per_writer_p95_ms": [
      1154.3365359306333,
      1494.62543670088,
      1232.5769359245896,
      1177.50842589885
    ],
    "peak_rss_mb": 1181.69921875,
    "parts": {
      "by_part_type": [
        {
          "part_type": "Wide",
          "parts": 20,
          "rows": 1000000,
          "bytes": 245881292
        }
      ],
      "active_parts": 20,
      "active_rows": 1000000,
      "merges_in_flight": 0
    },
    "async_logs": [
      {},
      {},
      {},
      {}
    ],
    "errors": []
  },
  {
    "mode": "PHASE2_2_MODE_SYNC",
    "batch_size": 25000,
    "writers": 1,
    "per_writer_rows": 250000,
    "aggregate_rows": 250000,
    "aggregate_wall_seconds": 30.639063122682273,
    "aggregate_rows_per_sec": 8159.518422576165,
    "per_writer_p50_ms": [
      689.0353444032371
    ],
    "per_writer_p95_ms": [
      748.7094190903007
    ],
    "peak_rss_mb": 1181.69921875,
    "parts": {
      "by_part_type": [
        {
          "part_type": "Wide",
          "parts": 5,
          "rows": 250000,
          "bytes": 61052127
        }
      ],
      "active_parts": 5,
      "active_rows": 250000,
      "merges_in_flight": 0
    },
    "async_logs": [
      {}
    ],
    "errors": []
  },
  {
    "mode": "PHASE2_2_MODE_SYNC",
    "batch_size": 25000,
    "writers": 2,
    "per_writer_rows": 250000,
    "aggregate_rows": 500000,
    "aggregate_wall_seconds": 49.455001048743725,
    "aggregate_rows_per_sec": 10110.200978606616,
    "per_writer_p50_ms": [
      1299.8612951487303,
      1007.1446215733886
    ],
    "per_writer_p95_ms": [
      1649.2882745806128,
      1592.2585499472916
    ],
    "peak_rss_mb": 1194.97265625,
    "parts": {
      "by_part_type": [
        {
          "part_type": "Wide",
          "parts": 10,
          "rows": 500000,
          "bytes": 122104267
        }
      ],
      "active_parts": 10,
      "active_rows": 500000,
      "merges_in_flight": 0
    },
    "async_logs": [
      {},
      {}
    ],
    "errors": []
  },
  {
    "mode": "PHASE2_2_MODE_SYNC",
    "batch_size": 25000,
    "writers": 4,
    "per_writer_rows": 250000,
    "aggregate_rows": 1000000,
    "aggregate_wall_seconds": 94.46186131890863,
    "aggregate_rows_per_sec": 10586.283035689325,
    "per_writer_p50_ms": [
      1567.944545764476,
      1898.1887819245458,
      1636.2998294644058,
      2548.5112271271646
    ],
    "per_writer_p95_ms": [
      2178.399182390421,
      2608.564768824726,
      2090.056193945929,
      3554.546325886621
    ],
    "peak_rss_mb": 1504.7265625,
    "parts": {
      "by_part_type": [
        {
          "part_type": "Wide",
          "parts": 20,
          "rows": 1000000,
          "bytes": 244208575
        }
      ],
      "active_parts": 20,
      "active_rows": 1000000,
      "merges_in_flight": 0
    },
    "async_logs": [
      {},
      {},
      {},
      {}
    ],
    "errors": []
  },
  {
    "mode": "PHASE2_2_MODE_ASYNC_WAIT",
    "batch_size": 10000,
    "writers": 1,
    "per_writer_rows": 250000,
    "aggregate_rows": 250000,
    "aggregate_wall_seconds": 31.69212659727782,
    "aggregate_rows_per_sec": 7888.394590140052,
    "per_writer_p50_ms": [
      286.2173402681947
    ],
    "per_writer_p95_ms": [
      371.2895013391971
    ],
    "peak_rss_mb": 1504.7265625,
    "parts": {
      "by_part_type": [
        {
          "part_type": "Wide",
          "parts": 5,
          "rows": 250000,
          "bytes": 61470310
        }
      ],
      "active_parts": 5,
      "active_rows": 250000,
      "merges_in_flight": 0
    },
    "async_logs": [
      {
        "error": "Received ClickHouse exception, code: 26, server response: Code: 26. DB::Exception: Cannot parse quoted string: expected opening quote ''', got '<': value [<bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfeb4a3f0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75ade7b7b6e0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfa246de0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adeaa77650>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfc8fbce0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfc5b8140>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfd968140>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfe08b980>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff239070>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff955790>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75ade804ccb0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf85d90d0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfe5a8a70>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfe131eb0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfefbcd10>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfa4ec200>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfd0a7e00>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf996c2f0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75ade6d2c1d0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf69369c0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adffa5ccb0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfb32c6b0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf33dd760>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfe31d550>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfca26ea0>>] cannot be parsed as Array(String) for query parameter 'ids'. (CANNOT_PARSE_QUOTED_STRING) (version 26.7.3.19 (official build)) (for url http://localhost:8123)",
        "records": 0
      }
    ],
    "errors": []
  },
  {
    "mode": "PHASE2_2_MODE_ASYNC_WAIT",
    "batch_size": 10000,
    "writers": 2,
    "per_writer_rows": 250000,
    "aggregate_rows": 500000,
    "aggregate_wall_seconds": 49.705136568285525,
    "aggregate_rows_per_sec": 10059.322527221988,
    "per_writer_p50_ms": [
      539.8621931672096,
      624.7348682954907
    ],
    "per_writer_p95_ms": [
      741.2293469533322,
      856.3472649082541
    ],
    "peak_rss_mb": 1504.7265625,
    "parts": {
      "by_part_type": [
        {
          "part_type": "Wide",
          "parts": 10,
          "rows": 500000,
          "bytes": 122940646
        }
      ],
      "active_parts": 10,
      "active_rows": 500000,
      "merges_in_flight": 0
    },
    "async_logs": [
      {
        "error": "Received ClickHouse exception, code: 26, server response: Code: 26. DB::Exception: Cannot parse quoted string: expected opening quote ''', got '<': value [<bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf41a7ec0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf87790d0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfb9f4b00>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf8ca1040>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf522db20>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf8ca0080>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf5b94d40>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfdb1dca0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff317e60>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adebc7c500>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adffbaa570>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfe556750>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfec17ef0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff12ff50>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf4d28920>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfb5fd550>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfbafc080>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf33a5640>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf998ae10>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff577140>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfc1c6e40>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfef0bce0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adffc87440>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf7a79e80>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf6c744d0>>] cannot be parsed as Array(String) for query parameter 'ids'. (CANNOT_PARSE_QUOTED_STRING) (version 26.7.3.19 (official build)) (for url http://localhost:8123)",
        "records": 0
      },
      {
        "error": "Received ClickHouse exception, code: 26, server response: Code: 26. DB::Exception: Cannot parse quoted string: expected opening quote ''', got '<': value [<bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff20a1e0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfedfcd10>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfb9f4e00>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff9fc410>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfb9f5dc0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf5b97b90>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfdb1deb0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfc7b31d0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff1de960>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adffba9fd0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfec03080>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf4058890>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfec16480>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf4d298b0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfe5b8c50>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfb9b1100>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf334ae10>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75ae000fe3c0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff574470>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf7f7cda0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfa7bdb80>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff643ad0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfef098b0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfbde6e40>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf41a5c70>>] cannot be parsed as Array(String) for query parameter 'ids'. (CANNOT_PARSE_QUOTED_STRING) (version 26.7.3.19 (official build)) (for url http://localhost:8123)",
        "records": 0
      }
    ],
    "errors": []
  },
  {
    "mode": "PHASE2_2_MODE_ASYNC_WAIT",
    "batch_size": 10000,
    "writers": 4,
    "per_writer_rows": 250000,
    "aggregate_rows": 1000000,
    "aggregate_wall_seconds": 97.54205676633865,
    "aggregate_rows_per_sec": 10251.988046504837,
    "per_writer_p50_ms": [
      801.6350585967302,
      789.0288354828954,
      1033.6026446893811,
      965.4627274721861
    ],
    "per_writer_p95_ms": [
      1148.330051638186,
      1144.930384121835,
      1443.2279465720057,
      1241.501104086637
    ],
    "peak_rss_mb": 1504.7265625,
    "parts": {
      "by_part_type": [
        {
          "part_type": "Wide",
          "parts": 20,
          "rows": 1000000,
          "bytes": 245881293
        }
      ],
      "active_parts": 20,
      "active_rows": 1000000,
      "merges_in_flight": 0
    },
    "async_logs": [
      {
        "error": "Received ClickHouse exception, code: 26, server response: Code: 26. DB::Exception: Cannot parse quoted string: expected opening quote ''', got '<': value [<bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf43cd3d0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf99dc890>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf59473e0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfccc7650>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfdf3a030>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf48890d0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfb9f58b0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfdf07f50>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfe64aff0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff78a450>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf994c710>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfcfc2930>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adea692cf0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfa6fea20>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfcce19d0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff6cfad0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf6d11ee0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adf897faa0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adffa93e00>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfde7b140>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adff65dfd0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfec2e2d0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfe1ed3d0>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfd861460>>, <bound method QuerySummary.query_id of <clickhouse_connect.driver.summary.QuerySummary object at 0x75adfe31da00>>] cannot be parsed as Array(String) for query parameter 'ids'. (CANNOT_PARSE_QUOTED_STRING) (version 26.7.3.19 (offic

## 11. Managed Protocol End-to-End

[
  {
    "mode": "PHASE2_2_MODE_SYNC",
    "batch_size": 10000,
    "rows": 50000,
    "case_id": 1,
    "batch_count": 5,
    "wall_seconds": 16.22243675775826,
    "rows_per_sec": 3082.151020011705,
    "stages": [
      {
        "ingest_batch_id": "ingest-batch:v1:19328c306ba20690a7af7e264f5d3acf1a8e65afc5311234d99ea94a306c0c43",
        "row_count": 10000,
        "batch_content_hash": "1c870b31f8e448c212522fa07bf181da1b3f63b2f7587163e1e2ebfc582e5d1d",
        "reserve_to_insert_return_ms": 343.99456810206175,
        "insert_return_to_verification_ms": 179.53452840447426,
        "verification_ms": 179.53452840447426,
        "mark_durable_ms": 167.75163542479277,
        "projection_ms": 21.851549856364727,
        "durable_to_first_searchable_ms": 64.02207165956497,
        "staged_to_searchable_ms": 755.3028035908937,
        "immediate_visible_rows": 10000,
        "verification_outcome": "exact",
        "published_after_batch": 10000,
        "construct_ms": 2550.7758874446154
      },
      {
        "ingest_batch_id": "ingest-batch:v1:1cb12da599262cb43a928163733d013a06753a35b465618db4cd3d54c19a221f",
        "row_count": 10000,
        "batch_content_hash": "407e70d5bd4fa09788b3e8e76387ba93e882c549bda59cea24538092b0bdf52c",
        "reserve_to_insert_return_ms": 335.6609707698226,
        "insert_return_to_verification_ms": 162.3356295749545,
        "verification_ms": 162.3356295749545,
        "mark_durable_ms": 13.1171103566885,
        "projection_ms": 25.88311769068241,
        "durable_to_first_searchable_ms": 58.33398923277855,
        "staged_to_searchable_ms": 569.4476999342442,
        "immediate_visible_rows": 10000,
        "verification_outcome": "exact",
        "published_after_batch": 20000,
        "construct_ms": 2562.755878083408
      },
      {
        "ingest_batch_id": "ingest-batch:v1:3a016a44d1fd827555ec5fe31194229aae66dea34e124db31d8bba3a9ee25df2",
        "row_count": 10000,
        "batch_content_hash": "0761493e74eaeb33bb3f89ae7bda45b1b06413c72d553aaf9c519eb8c3c697eb",
        "reserve_to_insert_return_ms": 310.32590568065643,
        "insert_return_to_verification_ms": 175.5065657198429,
        "verification_ms": 175.5065657198429,
        "mark_durable_ms": 10.884259827435017,
        "projection_ms": 26.979098096489906,
        "durable_to_first_searchable_ms": 61.45432498306036,
        "staged_to_searchable_ms": 558.1710562109947,
        "immediate_visible_rows": 10000,
        "verification_outcome": "exact",
        "published_after_batch": 30000,
        "construct_ms": 2321.0571836680174
      },
      {
        "ingest_batch_id": "ingest-batch:v1:0586328e7ef23bf660f5ed86173cfe4c6bd8025f07b9609a5024d47052f370fc",
        "row_count": 10000,
        "batch_content_hash": "19ece2903b85403e1ddd1b715b282ffd087b090ae2e9b6ddb51260bc5abeeadb",
        "reserve_to_insert_return_ms": 319.387873634696,
        "insert_return_to_verification_ms": 179.92114089429379,
        "verification_ms": 179.92114089429379,
        "mark_durable_ms": 12.978358194231987,
        "projection_ms": 31.535898335278034,
        "durable_to_first_searchable_ms": 63.88780754059553,
        "staged_to_searchable_ms": 576.1751802638173,
        "immediate_visible_rows": 10000,
        "verification_outcome": "exact",
        "published_after_batch": 40000,
        "construct_ms": 2612.0391990989447
      },
      {
        "ingest_batch_id": "ingest-batch:v1:8e592dda02216637761ed05021695a33d8195b832c85a45201ae53151c3e6523",
        "row_count": 10000,
        "batch_content_hash": "e36dc663ad7694409d1c2d4f71cc3c3f3365c28e7ff3b88441e35771bd0274cc",
        "reserve_to_insert_return_ms": 326.80509611964226,
        "insert_return_to_verification_ms": 475.09386390447617,
        "verification_ms": 475.09386390447617,
        "mark_durable_ms": 13.01509141921997,
        "projection_ms": 40.18630366772413,
        "durable_to_first_searchable_ms": 82.15039037168026,
        "staged_to_searchable_ms": 897.0644418150187,
        "immediate_visible_rows": 10000,
        "verification_outcome": "exact",
        "published_after_batch": 50000,
        "construct_ms": 2572.5447395816445
      }
    ],
    "median_staged_to_searchable_ms": 576.1751802638173,
    "median_reserve_to_insert_ms": 326.80509611964226,
    "median_verification_ms": 179.53452840447426,
    "median_durable_to_searchable_ms": 63.88780754059553,
    "published_rows": 50000,
    "token_rows": 50000,
    "published_token_rows": 50000,
    "immediate_verification_ok": true,
    "text_explain": {
      "raw": "Output: count()\n\nAggregating\n\u2502  Keys:\n\u2502  Aggregates: count()\n\u2502  Skip merging: 0\n\u2514\u2500\u2500Filter\n   \u2502  Filter column: __text_index_idx_search_blob_text_hasAllTokens_11774ed84af139863c3c1300caeb0caf\n   \u2514\u2500\u2500ReadFromMergeTree (phase2_2a_test.events)\n         Read type: Default\n         Parts: 5 | Granules: 10\n         Output: __text_index_idx_search_blob_text_hasAllTokens_11774ed84af139863c3c1300caeb0caf\n         Indexes:\n           Min-Max\n             Condition: true\n             Parts: 5/5\n             Granules: 10/10\n           Partition\n             Condition: true\n             Parts: 5/5\n             Granules: 10/10\n           PrimaryKey\n             Condition: true\n             Parts: 5/5\n             Granules: 10/10\n           Skip\n             Name: idx_search_blob_text\n             Description: text GRANULARITY 100000000\n             Condition: (mode: All; tokens: [\"zxqvphase22aunique\"])\n             Parts: 5/5\n             Granules: 10/10\n           Ranges: 5",
      "parsed": {
        "skip_names": [
          "idx_search_blob_text"
        ],
        "blocks": [
          {
            "name": "idx_search_blob_text",
            "description": "text GRANULARITY 100000000",
            "parts": "5/5",
            "granules": "10/10",
            "granules_before": 10,
            "granules_after": 10,
            "pruned": false
          }
        ],
        "prewhere": "Output: __text_index_idx_search_blob_text_hasAllTokens_11774ed84af139863c3c1300caeb0caf",
        "read": "Parts: 5 | Granules: 10",
        "direct_text_index": true,
        "idx_search_blob_text": true,
        "idx_search_ngram": false,
        "idx_search_token": false,
        "text_pruned": false,
        "ngram_pruned": false,
        "token_pruned": false,
        "text_granules": "10/10",
        "ngram_granules": null,
        "token_granules": null
      }
    },
    "ngram_explain": {
      "raw": "Output: count()\n\nAggregating\n\u2502  Keys:\n\u2502  Aggregates: count()\n\u2502  Skip merging: 0\n\u2514\u2500\u2500Filter ((WHERE + Change column names to column identifiers))\n   \u2502  Filter column: search_blob LIKE '%NTLM%'\n   \u2514\u2500\u2500ReadFromMergeTree (phase2_2a_test.events)\n         Read type: Default\n         Parts: 5 | Granules: 10\n         Output: search_blob\n         Indexes:\n           Min-Max\n             Condition: true\n             Parts: 5/5\n             Granules: 10/10\n           Partition\n             Condition: true\n             Parts: 5/5\n             Granules: 10/10\n           PrimaryKey\n             Condition: true\n             Parts: 5/5\n             Granules: 10/10\n           Skip\n             Name: idx_search_blob_text\n             Description: text GRANULARITY 100000000\n             Condition: (mode: All; tokens: [])\n             Parts: 5/5\n             Granules: 10/10\n           Skip\n             Name: idx_search_ngram\n             Description: ngrambf_v1 GRANULARITY 4\n             Parts: 5/5\n             Granules: 10/10\n           Ranges: 5",
      "parsed": {
        "skip_names": [
          "idx_search_blob_text",
          "idx_search_ngram"
        ],
        "blocks": [
          {
            "name": "idx_search_blob_text",
            "description": "text GRANULARITY 100000000",
            "parts": "5/5",
            "granules": "10/10",
            "granules_before": 10,
            "granules_after": 10,
            "pruned": false
          },
          {
            "name": "idx_search_ngram",
            "description": "ngrambf_v1 GRANULARITY 4",
            "parts": "5/5",
            "granules": "10/10",
            "granules_before": 10,
            "granules_after": 10,
            "pruned": false
          }
        ],
        "prewhere": null,
        "read": "Parts: 5 | Granules: 10",
        "direct_text_index": false,
        "idx_search_blob_text": true,
        "idx_search_ngram": true,
        "idx_search_token": false,
        "text_pruned": false,
        "ngram_pruned": false,
        "token_pruned": false,
        "text_granules": "10/10",
        "ngram_granules": "10/10",
        "token_granules": null
      }
    },
    "text_index_files": {
      "active_parts": 5,
      "text_index_files": 5,
      "ngram_index_files": 5,
      "missing_text_parts": [],
      "list_errors": [],
      "parts": [
        {
          "name": "1_1_1_0",
          "partition": "1",
          "rows": 10000,
          "path": "/var/lib/clickhouse/store/8fc/8fcf8221-b3b6-4412-9792-ecb35ca19e09/1_1_1_0/",
          "part_type": "Wide",
          "bytes_on_disk": 1105228,
          "secondary_indices_compressed_bytes": 97082,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "1_2_2_0",
          "partition": "1",
          "rows": 10000,
          "path": "/var/lib/clickhouse/store/8fc/8fcf8221-b3b6-4412-9792-ecb35ca19e09/1_2_2_0/",
          "part_type": "Wide",
          "bytes_on_disk": 1104734,
          "secondary_indices_compressed_bytes": 97097,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "1_3_3_0",
          "partition": "1",
          "rows": 10000,
          "path": "/var/lib/clickhouse/store/8fc/8fcf8221-b3b6-4412-9792-ecb35ca19e09/1_3_3_0/",
          "part_type": "Wide",
          "bytes_on_disk": 1104448,
          "secondary_indices_compressed_bytes": 97097,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "1_4_4_0",
          "partition": "1",
          "rows": 10000,
          "path": "/var/lib/clickhouse/store/8fc/8fcf8221-b3b6-4412-9792-ecb35ca19e09/1_4_4_0/",
          "part_type": "Wide",
          "bytes_on_disk": 1104683,
          "secondary_indices_compressed_bytes": 97097,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "1_5_5_0",
          "partition": "1",
          "rows": 10000,
          "path": "/var/lib/clickhouse/store/8fc/8fcf8221-b3b6-4412-9792-ecb35ca19e09/1_5_5_0/",
          "part_type": "Wide",
          "bytes_on_disk": 1104188,
          "secondary_indices_compressed_bytes": 97103,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        }
      ],
      "ok": true,
      "sentinel": "skp_idx_idx_search_blob_text.idx",
      "ngram_sentinel": "skp_idx_idx_search_ngram.idx"
    },
    "events_insert_calls": 5,
    "control_insert_calls": 0,
    "identity": {
      "batch_ids": [
        "ingest-batch:v1:19328c306ba20690a7af7e264f5d3acf1a8e65afc5311234d99ea94a306c0c43",
        "ingest-batch:v1:1cb12da599262cb43a928163733d013a06753a35b465618db4cd3d54c19a221f",
        "ingest-batch:v1:3a016a44d1fd827555ec5fe31194229aae66dea34e124db31d8bba3a9ee25df2",
        "ingest-batch:v1:0586328e7ef23bf660f5ed86173cfe4c6bd8025f07b9609a5024d47052f370fc",
        "ingest-batch:v1:8e592dda02216637761ed05021695a33d8195b832c85a45201ae53151c3e6523"
      ],
      "first_batch_hash": "1c870b31f8e448c212522fa07bf181da1b3f63b2f7587163e1e2ebfc582e5d1d",
      "batch_content_hashes": [
        "1c870b31f8e448c212522fa07bf181da1b3f63b2f7587163e1e2ebfc582e5d1d",
        "407e70d5bd4fa09788b3e8e76387ba93e882c549bda59cea24538092b0bdf52c",
        "0761493e74eaeb33bb3f89ae7bda45b1b06413c72d553aaf9c519eb8c3c697eb",
        "19ece2903b85403e1ddd1b715b282ffd087b090ae2e9b6ddb51260bc5abeeadb",
        "e36dc663ad7694409d1c2d4f71cc3c3f3365c28e7ff3b88441e35771bd0274cc"
      ]
    },
    "result_fingerprint": "b2cc880888a4f411b37126e0c9cc1608fb2d3f29a3e8d8cd2182cb69de17e0d9"
  },
  {
    "mode": "PHASE2_2_MODE_SYNC",
    "batch_size": 25000,
    "rows": 50000,
    "case_id": 1,
    "batch_count": 2,
    "wall_seconds": 18.121683854609728,
    "rows_per_sec": 2759.12549855466,
    "stages": [
      {
        "ingest_batch_id": "ingest-batch:v1:19328c306ba20690a7af7e264f5d3acf1a8e65afc5311234d99ea94a306c0c43",
        "row_count": 25000,
        "batch_content_hash": "414b72ef7f4c39d4dfadf2e36923777dd923ca7c08c61b8869a1deed89061cc7",
        "reserve_to_insert_return_ms": 768.5315571725368,
        "insert_return_to_verification_ms": 1187.982969917357,
        "verification_ms": 1187.982969917357,
        "mark_durable_ms": 20.769267342984676,
        "projection_ms": 83.83630774915218,
        "durable_to_first_searchable_ms": 128.51593643426895,
        "staged_to_searchable_ms": 2105.7997308671474,
        "immediate_visible_rows": 25000,
        "verification_outcome": "exact",
        "published_after_batch": 25000,
        "construct_ms": 7257.659961469471
      },
      {
        "ingest_batch_id": "ingest-batch:v1:1cb12da599262cb43a928163733d013a06753a35b465618db4cd3d54c19a221f",
        "row_count": 25000,
        "batch_content_hash": "3ff3e07ba59400fba9c6c8cfeefe553f1a252f6d25abc701120b9c1d88509705",
        "reserve_to_insert_return_ms": 778.8597363978624,
        "insert_return_to_verification_ms": 917.7654888480902,
        "verification_ms": 917.7654888480902,
        "mark_durable_ms": 20.515065640211105,
        "projection_ms": 37.935453467071056,
        "durable_to_first_searchable_ms": 75.53126197308302,
        "staged_to_searchable_ms": 1792.6715528592467,
        "immediate_visible_rows": 25000,
        "verification_outcome": "exact",
        "published_after_batch": 50000,
        "construct_ms": 6769.663393497467
      }
    ],
    "median_staged_to_searchable_ms": 1949.235641863197,
    "median_reserve_to_insert_ms": 773.6956467851996,
    "median_verification_ms": 1052.8742293827236,
    "median_durable_to_searchable_ms": 102.02359920367599,
    "published_rows": 50000,
    "token_rows": 50000,
    "published_token_rows": 50000,
    "immediate_verification_ok": true,
    "text_explain": {
      "raw": "Output: count()\n\nAggregating\n\u2502  Keys:\n\u2502  Aggregates: count()\n\u2502  Skip merging: 0\n\u2514\u2500\u2500Filter\n   \u2502  Filter column: __text_index_idx_search_blob_text_hasAllTokens_11774ed84af139863c3c1300caeb0caf\n   \u2514\u2500\u2500ReadFromMergeTree (phase2_2a_test.events)\n         Read type: Default\n         Parts: 2 | Granules: 8\n         Output: __text_index_idx_search_blob_text_hasAllTokens_11774ed84af139863c3c1300caeb0caf\n         Indexes:\n           Min-Max\n             Condition: true\n             Parts: 2/2\n             Granules: 8/8\n           Partition\n             Condition: true\n             Parts: 2/2\n             Granules: 8/8\n           PrimaryKey\n             Condition: true\n             Parts: 2/2\n             Granules: 8/8\n           Skip\n             Name: idx_search_blob_text\n             Description: text GRANULARITY 100000000\n             Condition: (mode: All; tokens: [\"zxqvphase22aunique\"])\n             Parts: 2/2\n             Granules: 8/8\n           Ranges: 2",
      "parsed": {
        "skip_names": [
          "idx_search_blob_text"
        ],
        "blocks": [
          {
            "name": "idx_search_blob_text",
            "description": "text GRANULARITY 100000000",
            "parts": "2/2",
            "granules": "8/8",
            "granules_before": 8,
            "granules_after": 8,
            "pruned": false
          }
        ],
        "prewhere": "Output: __text_index_idx_search_blob_text_hasAllTokens_11774ed84af139863c3c1300caeb0caf",
        "read": "Parts: 2 | Granules: 8",
        "direct_text_index": true,
        "idx_search_blob_text": true,
        "idx_search_ngram": false,
        "idx_search_token": false,
        "text_pruned": false,
        "ngram_pruned": false,
        "token_pruned": false,
        "text_granules": "8/8",
        "ngram_granules": null,
        "token_granules": null
      }
    },
    "ngram_explain": {
      "raw": "Output: count()\n\nAggregating\n\u2502  Keys:\n\u2502  Aggregates: count()\n\u2502  Skip merging: 0\n\u2514\u2500\u2500Filter ((WHERE + Change column names to column identifiers))\n   \u2502  Filter column: search_blob LIKE '%NTLM%'\n   \u2514\u2500\u2500ReadFromMergeTree (phase2_2a_test.events)\n         Read type: Default\n         Parts: 2 | Granules: 8\n         Output: search_blob\n         Indexes:\n           Min-Max\n             Condition: true\n             Parts: 2/2\n             Granules: 8/8\n           Partition\n             Condition: true\n             Parts: 2/2\n             Granules: 8/8\n           PrimaryKey\n             Condition: true\n             Parts: 2/2\n             Granules: 8/8\n           Skip\n             Name: idx_search_blob_text\n             Description: text GRANULARITY 100000000\n             Condition: (mode: All; tokens: [])\n             Parts: 2/2\n             Granules: 8/8\n           Skip\n             Name: idx_search_ngram\n             Description: ngrambf_v1 GRANULARITY 4\n             Parts: 2/2\n             Granules: 8/8\n           Ranges: 2",
      "parsed": {
        "skip_names": [
          "idx_search_blob_text",
          "idx_search_ngram"
        ],
        "blocks": [
          {
            "name": "idx_search_blob_text",
            "description": "text GRANULARITY 100000000",
            "parts": "2/2",
            "granules": "8/8",
            "granules_before": 8,
            "granules_after": 8,
            "pruned": false
          },
          {
            "name": "idx_search_ngram",
            "description": "ngrambf_v1 GRANULARITY 4",
            "parts": "2/2",
            "granules": "8/8",
            "granules_before": 8,
            "granules_after": 8,
            "pruned": false
          }
        ],
        "prewhere": null,
        "read": "Parts: 2 | Granules: 8",
        "direct_text_index": false,
        "idx_search_blob_text": true,
        "idx_search_ngram": true,
        "idx_search_token": false,
        "text_pruned": false,
        "ngram_pruned": false,
        "token_pruned": false,
        "text_granules": "8/8",
        "ngram_granules": "8/8",
        "token_granules": null
      }
    },
    "text_index_files": {
      "active_parts": 2,
      "text_index_files": 2,
      "ngram_index_files": 2,
      "missing_text_parts": [],
      "list_errors": [],
      "parts": [
        {
          "name": "1_1_1_0",
          "partition": "1",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/4b7/4b739ccb-21fb-43ee-831e-1bbc3d67022f/1_1_1_0/",
          "part_type": "Wide",
          "bytes_on_disk": 2731303,
          "secondary_indices_compressed_bytes": 239381,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "1_2_2_0",
          "partition": "1",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/4b7/4b739ccb-21fb-43ee-831e-1bbc3d67022f/1_2_2_0/",
          "part_type": "Wide",
          "bytes_on_disk": 2728893,
          "secondary_indices_compressed_bytes": 239259,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        }
      ],
      "ok": true,
      "sentinel": "skp_idx_idx_search_blob_te

## 12. Immediate Verification / Visibility

{
  "ok": true,
  "cells": [
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "ok": true,
      "published_rows": 50000
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "ok": true,
      "published_rows": 50000
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "ok": true,
      "published_rows": 50000
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "ok": true,
      "published_rows": 50000
    }
  ]
}

## 13. Text-Index Immediate Searchability

{
  "ok": true,
  "details": [
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "token_rows": 50000,
      "direct_text_index": true,
      "files": {
        "active_parts": 5,
        "text_index_files": 5,
        "ngram_index_files": 5,
        "missing_text_parts": [],
        "list_errors": [],
        "parts": [
          {
            "name": "1_1_1_0",
            "partition": "1",
            "rows": 10000,
            "path": "/var/lib/clickhouse/store/8fc/8fcf8221-b3b6-4412-9792-ecb35ca19e09/1_1_1_0/",
            "part_type": "Wide",
            "bytes_on_disk": 1105228,
            "secondary_indices_compressed_bytes": 97082,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          },
          {
            "name": "1_2_2_0",
            "partition": "1",
            "rows": 10000,
            "path": "/var/lib/clickhouse/store/8fc/8fcf8221-b3b6-4412-9792-ecb35ca19e09/1_2_2_0/",
            "part_type": "Wide",
            "bytes_on_disk": 1104734,
            "secondary_indices_compressed_bytes": 97097,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          },
          {
            "name": "1_3_3_0",
            "partition": "1",
            "rows": 10000,
            "path": "/var/lib/clickhouse/store/8fc/8fcf8221-b3b6-4412-9792-ecb35ca19e09/1_3_3_0/",
            "part_type": "Wide",
            "bytes_on_disk": 1104448,
            "secondary_indices_compressed_bytes": 97097,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          },
          {
            "name": "1_4_4_0",
            "partition": "1",
            "rows": 10000,
            "path": "/var/lib/clickhouse/store/8fc/8fcf8221-b3b6-4412-9792-ecb35ca19e09/1_4_4_0/",
            "part_type": "Wide",
            "bytes_on_disk": 1104683,
            "secondary_indices_compressed_bytes": 97097,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          },
          {
            "name": "1_5_5_0",
            "partition": "1",
            "rows": 10000,
            "path": "/var/lib/clickhouse/store/8fc/8fcf8221-b3b6-4412-9792-ecb35ca19e09/1_5_5_0/",
            "part_type": "Wide",
            "bytes_on_disk": 1104188,
            "secondary_indices_compressed_bytes": 97103,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          }
        ],
        "ok": true,
        "sentinel": "skp_idx_idx_search_blob_text.idx",
        "ngram_sentinel": "skp_idx_idx_search_ngram.idx"
      }
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "token_rows": 50000,
      "direct_text_index": true,
      "files": {
        "active_parts": 2,
        "text_index_files": 2,
        "ngram_index_files": 2,
        "missing_text_parts": [],
        "list_errors": [],
        "parts": [
          {
            "name": "1_1_1_0",
            "partition": "1",
            "rows": 25000,
            "path": "/var/lib/clickhouse/store/4b7/4b739ccb-21fb-43ee-831e-1bbc3d67022f/1_1_1_0/",
            "part_type": "Wide",
            "bytes_on_disk": 2731303,
            "secondary_indices_compressed_bytes": 239381,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          },
          {
            "name": "1_2_2_0",
            "partition": "1",
            "rows": 25000,
            "path": "/var/lib/clickhouse/store/4b7/4b739ccb-21fb-43ee-831e-1bbc3d67022f/1_2_2_0/",
            "part_type": "Wide",
            "bytes_on_disk": 2728893,
            "secondary_indices_compressed_bytes": 239259,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          }
        ],
        "ok": true,
        "sentinel": "skp_idx_idx_search_blob_text.idx",
        "ngram_sentinel": "skp_idx_idx_search_ngram.idx"
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "token_rows": 50000,
      "direct_text_index": true,
      "files": {
        "active_parts": 5,
        "text_index_files": 5,
        "ngram_index_files": 5,
        "missing_text_parts": [],
        "list_errors": [],
        "parts": [
          {
            "name": "1_1_1_0",
            "partition": "1",
            "rows": 10000,
            "path": "/var/lib/clickhouse/store/7f1/7f1b5b46-8431-4ce9-8ecd-badd81fd07b0/1_1_1_0/",
            "part_type": "Wide",
            "bytes_on_disk": 1105228,
            "secondary_indices_compressed_bytes": 97082,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          },
          {
            "name": "1_2_2_0",
            "partition": "1",
            "rows": 10000,
            "path": "/var/lib/clickhouse/store/7f1/7f1b5b46-8431-4ce9-8ecd-badd81fd07b0/1_2_2_0/",
            "part_type": "Wide",
            "bytes_on_disk": 1104734,
            "secondary_indices_compressed_bytes": 97097,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          },
          {
            "name": "1_3_3_0",
            "partition": "1",
            "rows": 10000,
            "path": "/var/lib/clickhouse/store/7f1/7f1b5b46-8431-4ce9-8ecd-badd81fd07b0/1_3_3_0/",
            "part_type": "Wide",
            "bytes_on_disk": 1104448,
            "secondary_indices_compressed_bytes": 97097,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          },
          {
            "name": "1_4_4_0",
            "partition": "1",
            "rows": 10000,
            "path": "/var/lib/clickhouse/store/7f1/7f1b5b46-8431-4ce9-8ecd-badd81fd07b0/1_4_4_0/",
            "part_type": "Wide",
            "bytes_on_disk": 1104683,
            "secondary_indices_compressed_bytes": 97097,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          },
          {
            "name": "1_5_5_0",
            "partition": "1",
            "rows": 10000,
            "path": "/var/lib/clickhouse/store/7f1/7f1b5b46-8431-4ce9-8ecd-badd81fd07b0/1_5_5_0/",
            "part_type": "Wide",
            "bytes_on_disk": 1104188,
            "secondary_indices_compressed_bytes": 97103,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          }
        ],
        "ok": true,
        "sentinel": "skp_idx_idx_search_blob_text.idx",
        "ngram_sentinel": "skp_idx_idx_search_ngram.idx"
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "token_rows": 50000,
      "direct_text_index": true,
      "files": {
        "active_parts": 2,
        "text_index_files": 2,
        "ngram_index_files": 2,
        "missing_text_parts": [],
        "list_errors": [],
        "parts": [
          {
            "name": "1_1_1_0",
            "partition": "1",
            "rows": 25000,
            "path": "/var/lib/clickhouse/store/9ac/9acff952-258b-48ee-9ae8-f6229036115d/1_1_1_0/",
            "part_type": "Wide",
            "bytes_on_disk": 2731303,
            "secondary_indices_compressed_bytes": 239381,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          },
          {
            "name": "1_2_2_0",
            "partition": "1",
            "rows": 25000,
            "path": "/var/lib/clickhouse/store/9ac/9acff952-258b-48ee-9ae8-f6229036115d/1_2_2_0/",
            "part_type": "Wide",
            "bytes_on_disk": 2728893,
            "secondary_indices_compressed_bytes": 239259,
            "text_index_file": true,
            "ngram_index_file": true,
            "listed_file_count": 416
          }
        ],
        "ok": true,
        "sentinel": "skp_idx_idx_search_blob_text.idx",
        "ngram_sentinel": "skp_idx_idx_search_ngram.idx"
      }
    }
  ]
}

## 14. Ngram Maintenance Proof

{
  "ok": true,
  "large_table": {
    "ngram_count": 304,
    "ngram_explain": {
      "skip_names": [
        "idx_search_blob_text",
        "idx_search_ngram"
      ],
      "blocks": [
        {
          "name": "idx_search_blob_text",
          "description": "text GRANULARITY 100000000",
          "parts": "20/20",
          "granules": "212/212",
          "granules_before": 212,
          "granules_after": 212,
          "pruned": false
        },
        {
          "name": "idx_search_ngram",
          "description": "ngrambf_v1 GRANULARITY 4",
          "parts": "20/20",
          "granules": "196/212",
          "granules_before": 212,
          "granules_after": 196,
          "pruned": true
        }
      ],
      "prewhere": null,
      "read": "Parts: 20 | Granules: 196",
      "direct_text_index": false,
      "idx_search_blob_text": true,
      "idx_search_ngram": true,
      "idx_search_token": false,
      "text_pruned": false,
      "ngram_pruned": true,
      "token_pruned": false,
      "text_granules": "212/212",
      "ngram_granules": "196/212",
      "token_granules": null
    },
    "text_count": 3220,
    "text_explain": {
      "skip_names": [
        "idx_search_blob_text"
      ],
      "blocks": [
        {
          "name": "idx_search_blob_text",
          "description": "text GRANULARITY 100000000",
          "parts": "20/20",
          "granules": "108/212",
          "granules_before": 212,
          "granules_after": 108,
          "pruned": true
        }
      ],
      "prewhere": "Output: __text_index_idx_search_blob_text_hasAllTokens_e54b45757fcbe742caf8a80a5063acc3",
      "read": "Parts: 20 | Granules: 108",
      "direct_text_index": true,
      "idx_search_blob_text": true,
      "idx_search_ngram": false,
      "idx_search_token": false,
      "text_pruned": true,
      "ngram_pruned": false,
      "token_pruned": false,
      "text_granules": "108/212",
      "ngram_granules": null,
      "token_granules": null
    },
    "files": {
      "active_parts": 20,
      "text_index_files": 20,
      "ngram_index_files": 20,
      "missing_text_parts": [],
      "list_errors": [],
      "parts": [
        {
          "name": "900001_28_28_0",
          "partition": "900001",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900001_28_28_0/",
          "part_type": "Wide",
          "bytes_on_disk": 6613484,
          "secondary_indices_compressed_bytes": 816022,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 412
        },
        {
          "name": "900001_32_32_0",
          "partition": "900001",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900001_32_32_0/",
          "part_type": "Wide",
          "bytes_on_disk": 5771704,
          "secondary_indices_compressed_bytes": 648601,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "900001_36_36_0",
          "partition": "900001",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900001_36_36_0/",
          "part_type": "Wide",
          "bytes_on_disk": 6864248,
          "secondary_indices_compressed_bytes": 760785,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 398
        },
        {
          "name": "900001_3_23_1",
          "partition": "900001",
          "rows": 150000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900001_3_23_1/",
          "part_type": "Wide",
          "bytes_on_disk": 36027560,
          "secondary_indices_compressed_bytes": 3700027,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 419
        },
        {
          "name": "900001_40_40_0",
          "partition": "900001",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900001_40_40_0/",
          "part_type": "Wide",
          "bytes_on_disk": 5775147,
          "secondary_indices_compressed_bytes": 619193,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "900002_26_26_0",
          "partition": "900002",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900002_26_26_0/",
          "part_type": "Wide",
          "bytes_on_disk": 6613484,
          "secondary_indices_compressed_bytes": 816022,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 412
        },
        {
          "name": "900002_2_24_1",
          "partition": "900002",
          "rows": 150000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900002_2_24_1/",
          "part_type": "Wide",
          "bytes_on_disk": 36027567,
          "secondary_indices_compressed_bytes": 3700027,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 419
        },
        {
          "name": "900002_31_31_0",
          "partition": "900002",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900002_31_31_0/",
          "part_type": "Wide",
          "bytes_on_disk": 5771703,
          "secondary_indices_compressed_bytes": 648601,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "900002_34_34_0",
          "partition": "900002",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900002_34_34_0/",
          "part_type": "Wide",
          "bytes_on_disk": 6864250,
          "secondary_indices_compressed_bytes": 760785,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 398
        },
        {
          "name": "900002_39_39_0",
          "partition": "900002",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900002_39_39_0/",
          "part_type": "Wide",
          "bytes_on_disk": 5775147,
          "secondary_indices_compressed_bytes": 619193,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "900003_1_21_1",
          "partition": "900003",
          "rows": 150000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900003_1_21_1/",
          "part_type": "Wide",
          "bytes_on_disk": 36027560,
          "secondary_indices_compressed_bytes": 3700027,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 419
        },
        {
          "name": "900003_25_25_0",
          "partition": "900003",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900003_25_25_0/",
          "part_type": "Wide",
          "bytes_on_disk": 6613484,
          "secondary_indices_compressed_bytes": 816022,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 412
        },
        {
          "name": "900003_29_29_0",
          "partition": "900003",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900003_29_29_0/",
          "part_type": "Wide",
          "bytes_on_disk": 5771703,
          "secondary_indices_compressed_bytes": 648601,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "900003_33_33_0",
          "partition": "900003",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900003_33_33_0/",
          "part_type": "Wide",
          "bytes_on_disk": 6864249,
          "secondary_indices_compressed_bytes": 760785,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 398
        },
        {
          "name": "900003_37_37_0",
          "partition": "900003",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900003_37_37_0/",
          "part_type": "Wide",
          "bytes_on_disk": 5775147,
          "secondary_indices_compressed_bytes": 619193,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "900004_27_27_0",
          "partition": "900004",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900004_27_27_0/",
          "part_type": "Wide",
          "bytes_on_disk": 6613484,
          "secondary_indices_compressed_bytes": 816022,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 412
        },
        {
          "name": "900004_30_30_0",
          "partition": "900004",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900004_30_30_0/",
          "part_type": "Wide",
          "bytes_on_disk": 5771703,
          "secondary_indices_compressed_bytes": 648601,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "900004_35_35_0",
          "partition": "900004",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900004_35_35_0/",
          "part_type": "Wide",
          "bytes_on_disk": 6864248,
          "secondary_indices_compressed_bytes": 760785,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 398
        },
        {
          "name": "900004_38_38_0",
          "partition": "900004",
          "rows": 25000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900004_38_38_0/",
          "part_type": "Wide",
          "bytes_on_disk": 5775147,
          "secondary_indices_compressed_bytes": 619193,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 416
        },
        {
          "name": "900004_4_22_1",
          "partition": "900004",
          "rows": 150000,
          "path": "/var/lib/clickhouse/store/5ca/5caede70-f5a7-4816-9bb2-bd6770d2db35/900004_4_22_1/",
          "part_type": "Wide",
          "bytes_on_disk": 36027977,
          "secondary_indices_compressed_bytes": 3700027,
          "text_index_file": true,
          "ngram_index_file": true,
          "listed_file_count": 419
        }
      ],
      "ok": true,
      "sentinel": "skp_idx_idx_search_blob_text.idx",
      "ngram_sentinel": "skp_idx_idx_search_ngram.idx"
    },
    "refreshed_on_reuse": true,
    "leftover_rows": 1000000
  },
  "details": [
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "idx_search_ngram": true,
      "ngram_pruned": false
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "idx_search_ngram": true,
      "ngram_pruned": false
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "idx_search_ngram": true,
      "ngram_pruned": false
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "idx_search_ngram": true,
      "ngram_pruned": false
    }
  ]
}

## 15. Failure Matrix

{
  "A_invalid_insert": {
    "insert_raised": true,
    "error": "RuntimeError: invalid row / server INSERT error",
    "pg_state": "STAGED",
    "not_durable": true,
    "ch_rows": 0,
    "ok": true
  },
  "B_fence_denied": {
    "error": "IngestAdmissionDenied: Shared ingest admission denied (exclusive_held); fail/retry, do not bypass fence",
    "inserts_sent": 0,
    "pg_state": "STAGED",
    "unavailable_error": "IngestFenceUnavailable: Ingest fence Redis unavailable; refusing uncoordinated access",
    "unavailable_inserts_sent": 0,
    "ok": true
  },
  "C_verification_fail": {
    "verification_success": false,
    "verification_outcome": "aggregate_mismatch",
    "durable_error": "ManifestProtocolError: verification did not authorize DURABLE: aggregate_mismatch",
    "pg_state": "STAGED",
    "ok": true
  },
  "D_retry_same_batch": {
    "same_ingest_batch_id": true,
    "same_hashes": true,
    "same_batch_content_hash": true,
    "verification_outcome": "duplicate_identical",
    "physical_rows": 4,
    "ok": true
  }
}

## 16. Lost-Acknowledgement / Retry Proof

{
  "proof_kind": "SIMULATED_CLIENT_TIMEOUT_AFTER_STORE",
  "lost_ack_error": "simulated lost acknowledgement after ClickHouse accepted INSERT",
  "stored_before_raise": true,
  "not_durable_after_loss": true,
  "verify_after_loss": {
    "success": true,
    "outcome": "exact"
  },
  "retry_error": null,
  "verify_after_retry": {
    "success": true,
    "outcome": "duplicate_identical"
  },
  "final_state": "DURABLE",
  "ok": true
}

## 17. Identity Invariance

{
  "construct_equal": {
    "ingest_batch_id": true,
    "row_ordinals": true,
    "ingest_row_hashes": true,
    "batch_content_hash": true,
    "erk_set": true
  },
  "live_ch_equal": true,
  "ok": true,
  "ingest_batch_id": "ingest-batch:v1:19328c306ba20690a7af7e264f5d3acf1a8e65afc5311234d99ea94a306c0c43",
  "batch_content_hash": "4407e63c338f6ffb1f9e1f949538e7ae9ca78cc3db16a529fc905e6f666039c8",
  "row_count": 50
}

## 18. Parts / Merge Pressure

{
  "raw": [
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 9,
            "rows": 1000000,
            "bytes": 244928214
          }
        ],
        "active_parts": 9,
        "active_rows": 1000000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 8,
            "rows": 1000000,
            "bytes": 243452291
          }
        ],
        "active_parts": 8,
        "active_rows": 1000000,
        "merges_in_flight": 1
      }
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 50000,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 5,
            "rows": 1000000,
            "bytes": 244262216
          }
        ],
        "active_parts": 5,
        "active_rows": 1000000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 100000,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 5,
            "rows": 1000000,
            "bytes": 243757417
          }
        ],
        "active_parts": 5,
        "active_rows": 1000000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 9,
            "rows": 1000000,
            "bytes": 244928214
          }
        ],
        "active_parts": 9,
        "active_rows": 1000000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 8,
            "rows": 1000000,
            "bytes": 243452291
          }
        ],
        "active_parts": 8,
        "active_rows": 1000000,
        "merges_in_flight": 1
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 50000,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 5,
            "rows": 1000000,
            "bytes": 244262216
          }
        ],
        "active_parts": 5,
        "active_rows": 1000000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 100000,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 5,
            "rows": 1000000,
            "bytes": 243757417
          }
        ],
        "active_parts": 5,
        "active_rows": 1000000,
        "merges_in_flight": 0
      }
    }
  ],
  "concurrency": [
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "writers": 1,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 5,
            "rows": 250000,
            "bytes": 61470310
          }
        ],
        "active_parts": 5,
        "active_rows": 250000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "writers": 2,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 10,
            "rows": 500000,
            "bytes": 122940646
          }
        ],
        "active_parts": 10,
        "active_rows": 500000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "writers": 4,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 20,
            "rows": 1000000,
            "bytes": 245881292
          }
        ],
        "active_parts": 20,
        "active_rows": 1000000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "writers": 1,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 5,
            "rows": 250000,
            "bytes": 61052127
          }
        ],
        "active_parts": 5,
        "active_rows": 250000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "writers": 2,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 10,
            "rows": 500000,
            "bytes": 122104267
          }
        ],
        "active_parts": 10,
        "active_rows": 500000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "writers": 4,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 20,
            "rows": 1000000,
            "bytes": 244208575
          }
        ],
        "active_parts": 20,
        "active_rows": 1000000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "writers": 1,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 5,
            "rows": 250000,
            "bytes": 61470310
          }
        ],
        "active_parts": 5,
        "active_rows": 250000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "writers": 2,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 10,
            "rows": 500000,
            "bytes": 122940646
          }
        ],
        "active_parts": 10,
        "active_rows": 500000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "writers": 4,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 20,
            "rows": 1000000,
            "bytes": 245881293
          }
        ],
        "active_parts": 20,
        "active_rows": 1000000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "writers": 1,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 5,
            "rows": 250000,
            "bytes": 61052127
          }
        ],
        "active_parts": 5,
        "active_rows": 250000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "writers": 2,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 10,
            "rows": 500000,
            "bytes": 122104275
          }
        ],
        "active_parts": 10,
        "active_rows": 500000,
        "merges_in_flight": 0
      }
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "writers": 4,
      "parts": {
        "by_part_type": [
          {
            "part_type": "Wide",
            "parts": 20,
            "rows": 1000000,
            "bytes": 244208996
          }
        ],
        "active_parts": 20,
        "active_rows": 1000000,
        "merges_in_flight": 0
      }
    }
  ]
}

## 19. Memory / Resource Result

{
  "raw_peak_rss_by_cell": [
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "median_peak_rss_mb": 281.890625
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "median_peak_rss_mb": 418.46875
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 50000,
      "median_peak_rss_mb": 648.20703125
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 100000,
      "median_peak_rss_mb": 989.970703125
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "median_peak_rss_mb": 993.2421875
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "median_peak_rss_mb": 993.2421875
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 50000,
      "median_peak_rss_mb": 993.2421875
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 100000,
      "median_peak_rss_mb": 995.994140625
    }
  ],
  "concurrency_peak_rss_mb": [
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "writers": 1,
      "peak_rss_mb": 996.703125
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "writers": 2,
      "peak_rss_mb": 1057.9140625
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 10000,
      "writers": 4,
      "peak_rss_mb": 1181.69921875
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "writers": 1,
      "peak_rss_mb": 1181.69921875
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "writers": 2,
      "peak_rss_mb": 1194.97265625
    },
    {
      "mode": "PHASE2_2_MODE_SYNC",
      "batch_size": 25000,
      "writers": 4,
      "peak_rss_mb": 1504.7265625
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "writers": 1,
      "peak_rss_mb": 1504.7265625
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "writers": 2,
      "peak_rss_mb": 1504.7265625
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 10000,
      "writers": 4,
      "peak_rss_mb": 1504.7265625
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "writers": 1,
      "peak_rss_mb": 1504.7265625
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "writers": 2,
      "peak_rss_mb": 1504.7265625
    },
    {
      "mode": "PHASE2_2_MODE_ASYNC_WAIT",
      "batch_size": 25000,
      "writers": 4,
      "peak_rss_mb": 1504.7265625
    }
  ],
  "disk_after": {
    "path": "/var/lib/clickhouse",
    "free_bytes": 75605569536,
    "total_bytes": 524068962304
  }
}

## 20. Insert-Mode Decision

PHASE2_2_MODE_SYNC

## 21. Async No-Wait Decision

ASYNC_NO_WAIT_FORBIDDEN

## 22. Batch-Size Decision

KEEP_PRODUCTION_BATCH_SIZE_10000

## 23. Recommended 2.2B Configuration Boundary

{
  "shape": "per-call INSERT settings on events inserts",
  "option": "A",
  "apply_to": [
    "utils.manifest_protocol.insert_managed_batch client.insert('events', ...)",
    "parsers.registry.BatchProcessor.flush client.insert(self.table, ...) when table=='events'"
  ],
  "do_not_apply_to": [
    "utils.clickhouse.get_client",
    "utils.clickhouse.get_fresh_client",
    "Hunt / graph / IOC / derivation readers",
    "verify_ingest_batch SELECT",
    "visible_evidence_generations INSERT",
    "durable_ingest_batches INSERT",
    "migration clients"
  ],
  "reason": "tasks.celery_tasks.parse_file_task / recover_staged_ingest_batch_task obtain one get_fresh_client() and reuse it for events INSERT, verification SELECT, and control projection INSERT. Pinning async_insert on the generic client would change acknowledgement semantics of control projections and Hunt/read sessions. Per-call settings on the events insert only is the narrowest explicit parser/event-ingest boundary required by Phase 2.2.",
  "control_projections": "unchanged; keep current client/session defaults",
  "fallback_if_per_call_unreliable": "dedicated get_event_ingest_client() used only for events INSERT"
}

## 24. Existing Generation Compatibility

{
  "current_flush_uses": "generation.configured_batch_size",
  "recovery_uses": "generation.configured_batch_size",
  "new_generation_uses": "contract_from_parser(configured_batch_size=Config.PHASE1B_MANIFEST_BATCH_SIZE or 10000)",
  "resume_hazard": "allocate_case_file_initial_generation/_assert_frozen_contract_matches compares the incoming contract (built from the current Config default) against the frozen BUILDING generation. A global default change would fail an already-BUILDING generation.",
  "if_new_default_chosen_2_2b_must": [
    "When a BUILDING_INITIAL or BUILDING_REPLACEMENT generation already exists, pass that generation's configured_batch_size into contract_from_parser",
    "Apply any new default only when allocating a new generation",
    "Leave PARSER_BATCH_SIZE/legacy BatchProcessor default independent unless separately justified",
    "Do not mutate frozen generation rows"
  ]
}

## 25. Control Projection Ordering

{
  "events_mode_must_not_apply_to_control_projections": true,
  "required_order": [
    "events batch fully verified",
    "PG DURABLE",
    "project visible_evidence_generations / durable_ingest_batches"
  ],
  "observed_control_inserts_unpinned": true,
  "design": "2.2B pins settings only on events INSERT; control projection insert() is unscoped"
}

## 26. Regression Tests

220 passed, 0 failed, 0 skipped. Protocol/F2 tests were not skipped.
py_compile, pyflakes, and git diff --check passed.

## 27. Files Changed

[
  "scripts/phase2_2a_insertion_mode_qualification.py",
  "tests/test_phase2_2a_insertion_mode_qualification.py",
  "docs/database_flow_phase2/phase2_2a_insertion_mode_qualification.md",
  "docs/database_flow_phase2/phase2_2a_insertion_mode_qualification.json"
]

## 28. Version

4.26.0

## 29. Production Mutation Audit

"NONE"

## 30. No-Later-Phase Audit

{
  "production_async_insert_change": false,
  "production_wait_for_async_insert_change": false,
  "production_batch_size_change": false,
  "materialize_skip_indexes_on_insert_change": false,
  "search_index_changes": false,
  "idx_search_ngram_changes": false,
  "pattern_rules_changes": false,
  "phase_2_3": false,
  "phase_2_4": false,
  "phase_3_plus": false,
  "lek": false,
  "events_current": false,
  "event_observations_current": false,
  "pagination": false
}

## 31. Git State

{
  "expected_at_end_of_measurement": "uncommitted until operator commit",
  "not_pushed_by_measurement": true
}

## 32. Phase 2.2 State

PHASE2_2_DECISION_READY

## 33. Remaining Work

[
  "Independent D2A review",
  "Phase 2.2B \u2014 explicit parser/event-ingest mode implementation + live activation proof",
  "Do not start Phase 2.3"
]

## 34. Verdict

PHASE2_2A_PASS

