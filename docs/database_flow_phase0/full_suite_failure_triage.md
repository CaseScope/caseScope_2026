# Phase 0A Full-Suite Failure Triage

## Comparison States

- A_clean_main: {'tests': 2085, 'duration_seconds': 74.809, 'failures': 6, 'errors': 7, 'skipped': 7}
- B_phase0a_only_after_fix: {'tests': 2090, 'duration_seconds': 73.075, 'failures': 6, 'errors': 7, 'skipped': 7}
- C_current_after_fix: {'tests': 2092, 'duration_seconds': 67.908, 'failures': 6, 'errors': 6, 'skipped': 7}

## Fixed Phase 0A Regression

- `tests.test_parser_hardening` EVTX transform tests returned `None` in State B/C because Phase 0A counters were initialized in `EvtxECmdParser.__init__`, while these tests construct with `object.__new__`. Fixed by lazily initializing metric counters before transform timing updates.

## Remaining Issues

| Classification | Test | State A | State B | State C | Current last line |
|---|---|---|---|---|---|
| `PRE_EXISTING_MAIN_FAILURE` | `test_a_case_with_no_aliases_reports_zero (tests.test_privacy_alias_number_allocation.HighestAliasNumberQueryTestCase.test_a_case_with_no_aliases_reports_zero)` | present | present | present | `AttributeError: 'types.SimpleNamespace' object has no attribute 'func'` |
| `PRE_EXISTING_MAIN_FAILURE` | `test_assert_active_detects_stolen_token_synchronously (tests.test_clickhouse_destructive_lock.ClickHouseDestructiveLockTestCase.test_assert_active_detects_stolen_token_synchronously)` | present | present | present | `AttributeError: module 'utils.clickhouse' has no attribute '_destructive_rewrite_lock_renew_interval'` |
| `ENVIRONMENT_DEPENDENT` | `test_delete_pcap_scope_raises_before_metadata_delete_when_clickhouse_delete_fails (tests.test_clickhouse_delete_dedup_contracts.PcapReindexContractTestCase.test_delete_pcap_scope_raises_before_metadata_delete_when_clickhouse_delete_fails)` | present | present | absent | `` |
| `PRE_EXISTING_MAIN_FAILURE` | `test_dispatcher_caches_allow_for_same_sensitive_params (tests.test_phase6_chat_runtime_contract.Phase6ChatRuntimeContractTestCase.test_dispatcher_caches_allow_for_same_sensitive_params)` | present | present | present | `+ completed` |
| `PRE_EXISTING_MAIN_FAILURE` | `test_dispatcher_interrupts_sensitive_read_without_cached_approval (tests.test_phase6_chat_runtime_contract.Phase6ChatRuntimeContractTestCase.test_dispatcher_interrupts_sensitive_read_without_cached_approval)` | present | present | present | `+ interrupt` |
| `PRE_EXISTING_MAIN_FAILURE` | `test_dispatcher_requires_new_approval_for_different_sensitive_params (tests.test_phase6_chat_runtime_contract.Phase6ChatRuntimeContractTestCase.test_dispatcher_requires_new_approval_for_different_sensitive_params)` | present | present | present | `+ completed` |
| `PRE_EXISTING_MAIN_FAILURE` | `test_dispatcher_session_allow_applies_to_new_sensitive_params (tests.test_phase6_chat_runtime_contract.Phase6ChatRuntimeContractTestCase.test_dispatcher_session_allow_applies_to_new_sensitive_params)` | present | present | present | `+ completed` |
| `PRE_EXISTING_MAIN_FAILURE` | `test_parallel_profile_task_delegates_to_pipeline_baselines_stage (tests.test_phase7_baselines_stage.Phase7BaselinesStageTestCase.test_parallel_profile_task_delegates_to_pipeline_baselines_stage)` | present | present | present | `-  'progress_callback': <function _wave_progress_reporter.<locals>.report at 0x714e44f2d760>}` |
| `PRE_EXISTING_MAIN_FAILURE` | `test_required_lock_fails_closed_when_redis_unavailable (tests.test_clickhouse_destructive_lock.ClickHouseDestructiveLockTestCase.test_required_lock_fails_closed_when_redis_unavailable)` | present | present | present | `AttributeError: module 'utils.clickhouse' has no attribute 'destructive_event_rewrite_guard'` |
| `PRE_EXISTING_MAIN_FAILURE` | `test_required_lock_uses_admin_redis_without_secret_and_renews (tests.test_clickhouse_destructive_lock.ClickHouseDestructiveLockTestCase.test_required_lock_uses_admin_redis_without_secret_and_renews)` | present | present | present | `AttributeError: module 'utils.clickhouse' has no attribute '_destructive_rewrite_lock_renew_interval'` |
| `PRE_EXISTING_MAIN_FAILURE` | `test_tag_artifacts_start_routes_to_ioc_queue_and_tracks_task_access (tests.test_route_security_regressions.RouteSecurityRegressionTestCase.test_tag_artifacts_start_routes_to_ioc_queue_and_tracks_task_access)` | present | present | present | `  Actual: apply_async(args=(11, 'tester', None), queue='ioc')` |
| `PRE_EXISTING_MAIN_FAILURE` | `test_unlicensed_deterministic_report_does_not_invoke_ai_provider (tests.test_investigation_thread_report_snapshots.DeterministicReportRouteLifecycleTestCase.test_unlicensed_deterministic_report_does_not_invoke_ai_provider)` | present | present | present | `AttributeError: 'tuple' object has no attribute 'get_json'` |
| `PRE_EXISTING_MAIN_FAILURE` | `tests.test_async_cancellation_remaining (unittest.loader._FailedTest.tests.test_async_cancellation_remaining)` | present | present | present | `AttributeError: type object '_FakeAnalysisStatus' has no attribute 'terminal_statuses'. Did you mean: 'running_statuses'?` |

## Isolation Limits

- Some tests read absolute `/opt/casescope/...` source paths, so detached worktree discovery is not perfectly isolated for source-contract tests.
- The remaining current failures/errors are present on clean main under the same runtime, except one temp-worktree upload permission error that is absent in the current worktree and classified environment-dependent.


## Production Safety Correction

Full `unittest discover` with `/etc/casescope/casescope.env` loaded is not a read-only operation on this host. Clean worktrees isolate code, but not service targets.

Production-touching tests identified:

- `tests/test_graph_bulk_writer_postgres.py`: writes graph-related rows to PostgreSQL using `CASESCOPE_POSTGRES_TEST_DATABASE_URL` or falling back to `DATABASE_URL`. With production env loaded, this can write to production PostgreSQL.
- `tests/test_deterministic_pattern_regressions.py`: inserts rows into ClickHouse `events` and issues `ALTER TABLE events DELETE` for reserved high case IDs.
- `tests/test_event_selector.py`: performs read-only ClickHouse selector parity queries when ClickHouse is reachable.

Future non-destructive comparisons should use disposable service targets or skip/exclude these production-touching modules. The A/B/C comparison already captured is still useful for causality, but it should be treated as a controlled production-env comparison rather than a safe read-only test run.
