# Phase 2.4B2A Publication-Safety Census

Dated 2026-08-22. Does not close Phase 2. Does not start Phase 3 or Phase 4.
Does not restart production services. Candidate source version is 4.26.4.

## Tokens

- `DURABLE_REPLAY_NONEXACT_FAILS_CLOSED`
- `PARTIAL_PROTOCOL_IDENTITY_FAILS_CLOSED`
- `HUNT_RELATIVE_RANGE_RAW_ANCHOR_CONFIRMED`
- `PUBLICATION_PREDICATE_READY_FOR_B2B`
- `PHASE2_NORMAL_TEST_COLLECTION_ISOLATED`
- `PRODUCTION_MANAGED_PROTOCOL_STATE_STILL_EMPTY`
- `HIDDEN_REPLACEMENT_PRECOMPUTE_CURRENT_STATE_LEAK`
- `D2_EXACT_STALE_ATTEMPT_STATUS_HARMLESS`
- `STALE_CASEFILE_STATE_AMBIGUOUS`

## Production managed protocol

{
  "evidence_source_generations": 0,
  "ingest_attempts": 0,
  "ingest_batches": 0,
  "evidence_generation_audit": 0,
  "ingest_batch_reconciliation_audit": 0
}

{
  "visible_evidence_generations": 0,
  "durable_ingest_batches": 0
}

## Historical Phase 0 reconciliation

Historical `event_surface_consumers.json` was not rewritten.

{
  "historical_inventory_unchanged": true,
  "phase0_direct_readers": 167,
  "current_direct_readers_including_admin": 194,
  "removed_from_current_scan": [
    "routes/hunting.py::get_unified_process_tree::get_children_from_events",
    "routes/hunting.py::get_unified_process_tree::get_process_from_events",
    "utils/chat_tools.py::investigate_question::run_event_section",
    "utils/forensic_chat_sources.py::get_unified_process_tree::_children_from_events",
    "utils/forensic_chat_sources.py::get_unified_process_tree::_from_events"
  ],
  "added_since_phase0": [
    "bin/archive_then_reset.py::_clickhouse_table_count",
    "bin/database_flow_baseline.py::_explain_query_shapes",
    "bin/database_flow_baseline.py::collect_duplicate_baseline",
    "bin/database_flow_baseline.py::collect_explain_baseline",
    "migrations/add_events_table.py::_count_table_rows",
    "migrations/add_evidence_record_identity.py::_count_empty_identity",
    "migrations/add_evidence_record_identity.py::_count_events",
    "migrations/add_evidence_record_identity.py::_count_identity_prefix",
    "migrations/add_evidence_record_identity.py::_count_invalid_identity_metadata",
    "migrations/add_evidence_record_identity.py::_count_unknown_identity",
    "migrations/add_evidence_record_identity.py::_count_valid_v2_identity",
    "routes/hunting.py::get_unified_process_tree",
    "utils/ai_privacy_freeze.py::select_current_generation_event_rows",
    "utils/capability_watermarks.py::resolve_erk_ingest_batch_ids",
    "utils/chat_tools.py::run_event_section",
    "utils/clickhouse.py::_case_file_events_exist",
    "utils/clickhouse.py::delete_case_events",
    "utils/clickhouse.py::delete_file_events",
    "utils/forensic_chat_sources.py::_children_from_events",
    "utils/forensic_chat_sources.py::_from_events",
    "utils/manifest_protocol.py::_grouped_batch_rows",
    "utils/phase1_step3_ioc_recall.py::classify_a_minus_b",
    "utils/phase1_step3_ioc_recall.py::explain_clause",
    "utils/phase1_step3_ioc_recall.py::stream_matches",
    "utils/phase1_step3_profiler.py::fetch_system_role_stats",
    "utils/phase1_step3_profiler.py::fetch_system_rows_legacy",
    "utils/phase1_step3_profiler.py::fetch_system_rows_set_based",
    "utils/phase1_step3_profiler.py::fetch_user_rows_legacy",
    "utils/phase1_step3_profiler.py::fetch_user_rows_set_based",
    "utils/search_blob_text_index.py::explain_has_all_tokens",
    "utils/search_blob_text_index.py::partition_value_fingerprint",
    "utils/staged_batch_reconciler.py::inspect_batch"
  ],
  "moved_or_renamed_confident": []
}

## Current reader classification counts (production_runtime)

{
  "CURRENT_PUBLICATION_BYPASS": 139,
  "FAILS_CLOSED_BEFORE_SIDE_EFFECT": 1,
  "LEGACY_ONLY_MANAGED_BLOCKED": 6,
  "PUBLICATION_SAFE_CURRENT": 6,
  "RAW_ADMIN_ALLOWED": 7,
  "RAW_PROTOCOL_INTERNAL_ALLOWED": 3
}

## Current mutation classification counts (production_runtime)

{
  "ADMIN_DESTRUCTIVE_RAW_ALLOWED": 2,
  "CURRENT_MUTATION_PUBLICATION_BYPASS": 15,
  "LEGACY_ONLY_MANAGED_BLOCKED": 1,
  "PROTOCOL_INTERNAL_RAW_ALLOWED": 1
}

## B2B families

### B2B-1 — shared product counts, dashboard, and remaining time anchors

Readers: 5. Mutations: 0.

- reader `routes/case_files.py::get_case_statistics`
- reader `routes/dashboard.py::dashboard_stats`
- reader `routes/hunting.py::get_noise_stats`
- reader `utils/chat_tools.py::count_events`
- reader `utils/clickhouse.py::count_events`

### B2B-2 — analyst and manual-noise read plus UPDATE target scoping

Readers: 2. Mutations: 2.

- reader `utils/event_analyst_state.py::_count_matching`
- reader `utils/event_analyst_state.py::_fetch_prior_analyst_state`
- mutation `utils/event_analyst_state.py::upsert_event_analyst_state_rows`
- mutation `utils/event_noise_state.py::upsert_manual_noise_state_rows`

### B2B-3 — IOC / noise / MITRE current mutation and scan scoping

Readers: 17. Mutations: 9.

- reader `tasks/celery_tasks.py::_insert_hayabusa_mitre_matches_for_case_file`
- reader `tasks/mitre_mapper.py::map_case_mitre_procedures`
- reader `tasks/noise_tagger.py::tag_noise_events`
- reader `utils/event_ioc_state.py::_count_matching`
- reader `utils/event_ioc_state.py::insert_ioc_scan_matches`
- reader `utils/event_mitre_state.py::_count_matching`
- reader `utils/event_mitre_state.py::count_mitre_mapped_events`
- reader `utils/event_mitre_state.py::delete_hayabusa_matches_for_case_file`
- reader `utils/event_mitre_state.py::get_mitre_mapping_stats`
- reader `utils/event_mitre_state.py::insert_mitre_rule_matches`
- reader `utils/event_noise_state.py::_count_matching`
- reader `utils/event_noise_state.py::_fetch_prior_noise_state`
- reader `utils/event_noise_state.py::count_effective_noise_events`
- reader `utils/event_noise_state.py::insert_noise_scan_matches`
- reader `utils/hayabusa_mitre_reenrichment.py::_query_existing_events`
- reader `utils/ioc_artifact_tagger.py::get_matching_systems_for_ioc`
- reader `utils/ioc_artifact_tagger.py::search_artifacts_for_ioc`
- mutation `utils/event_ioc_state.py::insert_ioc_scan_matches`
- mutation `utils/event_ioc_state.py::start_ioc_refresh`
- mutation `utils/event_mitre_state.py::_delete_source_matches_for_selectors`
- mutation `utils/event_mitre_state.py::insert_mitre_rule_matches`
- mutation `utils/event_mitre_state.py::rebuild_mitre_summary_columns`
- mutation `utils/event_mitre_state.py::start_mitre_mapping_scan`
- mutation `utils/event_noise_state.py::insert_noise_scan_matches`
- mutation `utils/event_noise_state.py::start_noise_scan`
- mutation `utils/hayabusa_mitre_reenrichment.py::_update_legacy_event_mitre_fields`

### B2B-4 — graph, known principal, behavioral, and detector inputs

Readers: 33. Mutations: 0.

- reader `models/pattern_rules.py::<module>`
- reader `utils/behavioral_profiler.py::_calculate_system_profile`
- reader `utils/behavioral_profiler.py::_calculate_user_profile`
- reader `utils/graph_extractors.py::<module>`
- reader `utils/graph_materializer.py::_graph_events_query`
- reader `utils/graph_materializer.py::_next_eligible_timestamp_query`
- reader `utils/graph_projection.py::graph_eligible_probe`
- reader `utils/graph_projection.py::graph_stream_explain_sql`
- reader `utils/graph_query.py::exact_evidence`
- reader `utils/graph_support_lifecycle.py::stream_case_file_evidence_record_keys`
- reader `utils/incident_storyline_detector.py::_query_case_time_buckets`
- reader `utils/incident_storyline_detector.py::_query_containment_events`
- reader `utils/incident_storyline_detector.py::_query_download_execution_pairs`
- reader `utils/known_systems_discovery.py::_get_destination_hosts_and_shares`
- reader `utils/known_systems_discovery.py::_get_hostnames_from_events`
- reader `utils/known_systems_discovery.py::_get_remote_workstations_from_logon_events`
- reader `utils/known_systems_discovery.py::_get_system_details_from_events`
- reader `utils/known_systems_discovery.py::discover_known_systems`
- reader `utils/known_users_discovery.py::_get_users_from_events`
- reader `utils/known_users_discovery.py::_process_user`
- reader `utils/known_users_discovery.py::discover_known_users`
- reader `utils/phase1_step3_ioc_recall.py::classify_a_minus_b`
- reader `utils/phase1_step3_ioc_recall.py::explain_clause`
- reader `utils/phase1_step3_ioc_recall.py::stream_matches`
- reader `utils/phase1_step3_profiler.py::fetch_system_role_stats`
- reader `utils/phase1_step3_profiler.py::fetch_system_rows_legacy`
- reader `utils/phase1_step3_profiler.py::fetch_system_rows_set_based`
- reader `utils/phase1_step3_profiler.py::fetch_user_rows_legacy`
- reader `utils/phase1_step3_profiler.py::fetch_user_rows_set_based`
- reader `utils/stateful_detectors/auth_events.py::build_source_slot_query`
- reader `utils/stateful_detectors/auth_events.py::build_successful_accounts_query`
- reader `utils/stateful_detectors/auth_events.py::build_target_slot_query`
- reader `utils/temporal_baseline.py::build_activity_day_query`

### B2B-5 — RAG, embedding, AI, chat current readers

Readers: 42. Mutations: 0.

- reader `routes/rag.py::get_case_rag_stats`
- reader `tasks/rag_tasks.py::_count_scope_eligible_events`
- reader `tasks/rag_tasks.py::_get_semantic_pattern_suggestions`
- reader `tasks/rag_tasks.py::_prepare_pattern_detection_query`
- reader `tasks/rag_tasks.py::rag_discover_patterns`
- reader `tasks/rag_tasks.py::rag_embed_high_severity_events`
- reader `tasks/rag_tasks.py::rag_generate_timeline`
- reader `tasks/rag_tasks.py::rag_hunt_related`
- reader `utils/ai_event_summary.py::_build_event_context`
- reader `utils/ai_event_summary.py::_extract_key_indicators`
- reader `utils/ai_event_summary.py::_fetch_tagged_events`
- reader `utils/ai_report_generator.py::_fetch_tagged_events`
- reader `utils/ai_report_generator.py::generate_timeline`
- reader `utils/ai_timeline_generator.py::_fetch_tagged_events`
- reader `utils/chat_agent.py::get_case_context`
- reader `utils/chat_tools.py::_query_event_page`
- reader `utils/chat_tools.py::_top_values`
- reader `utils/chat_tools.py::get_authentication_summary`
- reader `utils/chat_tools.py::get_case_coverage`
- reader `utils/chat_tools.py::get_entity_profile`
- reader `utils/chat_tools.py::get_event_context`
- reader `utils/chat_tools.py::get_processes`
- reader `utils/chat_tools.py::get_raw_event`
- reader `utils/chat_tools.py::investigate_question`
- reader `utils/chat_tools.py::lookup_ioc`
- reader `utils/chat_tools.py::query_events`
- reader `utils/chat_tools.py::run_event_section`
- reader `utils/forensic_chat_sources.py::_children_from_events`
- reader `utils/forensic_chat_sources.py::_from_events`
- reader `utils/forensic_chat_sources.py::build_event_corpus_coverage`
- reader `utils/forensic_chat_sources.py::get_browser_download_rows`
- reader `utils/forensic_chat_sources.py::get_unified_process_list`
- reader `utils/forensic_chat_sources.py::search_artifacts`
- reader `utils/investigation_context.py::_fetch_logical_records`
- reader `utils/investigation_context.py::_next_process_creation`
- reader `utils/investigation_context.py::_process_termination`
- reader `utils/investigation_context.py::_resolve_anchor`
- reader `utils/privacy_aliases.py::_scan_distinct_field`
- reader `utils/privacy_aliases.py::_scan_distinct_ip_field`
- reader `utils/privacy_aliases.py::scan_clickhouse_case_alias_candidates`
- reader `utils/rag_embeddings.py::embed_event_context`
- reader `utils/rag_llm.py::analyze_pattern_match`

### B2B-6 — remaining Hunt raw surfaces (process tree, hostnames, MITRE hide-noise)

Readers: 6. Mutations: 0.

- reader `routes/hunting.py::get_process_children`
- reader `routes/hunting.py::get_process_hostnames`
- reader `routes/hunting.py::get_process_parent`
- reader `routes/hunting.py::get_unified_process_tree`
- reader `routes/hunting.py::get_unified_processes`
- reader `routes/hunting.py::list_mitre_mapping_matches`

### B2B-7 — remaining current publication bypasses not in B2B-1..6

Readers: 34. Mutations: 4.

- reader `models/rag.py::<module>`
- reader `pipeline/pattern_analysis.py::run_pattern_census`
- reader `routes/iocs.py::get_find_iocs_stats`
- reader `routes/noise.py::api_test_matching`
- reader `routes/noise.py::api_test_single_rule`
- reader `routes/rag.py::ask_ai`
- reader `routes/rag.py::review_events`
- reader `tasks/celery_tasks.py::find_iocs_in_events_task`
- reader `utils/candidate_extractor.py::_extract_events`
- reader `utils/candidate_extractor.py::_extract_mitre_support_events`
- reader `utils/candidate_extractor.py::_probe_anchor_exists`
- reader `utils/clickhouse.py::count_file_events`
- reader `utils/clickhouse.py::get_event_by_evidence_record_key`
- reader `utils/clickhouse.py::get_event_stats`
- reader `utils/clickhouse.py::query_events`
- reader `utils/deterministic_evidence_engine.py::_check_coverage`
- reader `utils/deterministic_evidence_engine.py::_check_coverage_batch`
- reader `utils/deterministic_evidence_engine.py::_detect_bursts`
- reader `utils/deterministic_evidence_engine.py::_evaluate_spread`
- reader `utils/deterministic_evidence_engine.py::_query_sequence_step`
- reader `utils/event_overlay_repair.py::get_case_event_overlay_row_counts`
- reader `utils/hayabusa_correlator.py::_query_hayabusa_detections`
- reader `utils/ioc_match_provenance.py::_stream_ioc_matching_erks`
- reader `utils/ioc_timeline_builder.py::_find_ioc_events`
- reader `utils/ioc_timeline_builder.py::_get_host_context`
- reader `utils/mitre_attack_sync.py::_generate_alternate_auth_query`
- reader `utils/mitre_attack_sync.py::_generate_brute_force_query`
- reader `utils/mitre_attack_sync.py::_generate_credential_dump_query`
- reader `utils/mitre_attack_sync.py::_generate_generic_query`
- reader `utils/mitre_attack_sync.py::_generate_kerberos_query`
- reader `utils/mitre_attack_sync.py::_generate_standard_query`
- reader `utils/pattern_check_definitions.py::<module>`
- reader `utils/sigma_converter.py::_build_aggregation_query`
- reader `utils/sigma_converter.py::_build_clickhouse_query`
- mutation `utils/clickhouse.py::run_events_lightweight_update`
- mutation `utils/clickhouse.py::run_events_update`
- mutation `utils/event_overlay_repair.py::purge_case_event_overlay_state`
- mutation `utils/event_overlay_repair.py::purge_case_legacy_overlay_rows`

## Complete current production reader matrix

See JSON `current_readers` (production_runtime plus administrative_migration).
No production_runtime reader is unclassified.

## Complete current mutation matrix

See JSON `current_mutations`. No production_runtime mutation is unclassified.

## Later-phase work explicitly deferred

- LEK / logical representative / same-ERK collapse
- events_current / event_observations_current
- IOC / MITRE / analyst PostgreSQL authority migration
- Qdrant identity migration
- graph derived-plane migration
- RMT event-engine change
- semantic duplicate detection

## Predicate qualification

`PUBLICATION_PREDICATE_READY_FOR_B2B` on ClickHouse 26.7.3.19.

SELECT LEFT JOIN, tuple IN, and EXISTS are semantically identical on the disposable fixture.
ALTER UPDATE fails with a SELECT alias (`e.column`). It succeeds with `alias="events"` or unaliased columns.
B2B mutations must use `build_event_publication_predicate(alias="events")` or `alias=""`.
B2A does not retrofit current mutations.

## Production mutation / service restart

NONE in B2A. Application processes remain the B1 19:40:58-19:41:02 UTC start, which predates 4.26.3/4.26.4 source on disk.
