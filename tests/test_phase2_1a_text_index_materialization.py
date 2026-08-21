"""Phase 2.1A partition-scoped text-index materialization tests.

    /opt/casescope/venv/bin/python -m pytest tests/test_phase2_1a_text_index_materialization.py -q
"""
from __future__ import annotations

import inspect
import os
import subprocess
import unittest
import uuid

os.environ.setdefault("SECRET_KEY", "phase2-1a-test-secret")

from migrations.add_events_search_blob_text_index import (
    INDEX_NAME,
    INDEX_TYPE_SQL,
    IncompatibleSearchBlobTextIndex,
    add_events_search_blob_text_index,
)
from routes import hunting_query_helpers
from utils.search_blob_text_index import (
    COVERAGE_MATERIALIZED,
    COVERAGE_PARTIAL,
    COVERAGE_UNKNOWN,
    COVERAGE_UNMATERIALIZED,
    TEXT_INDEX_SENTINEL_FILE,
    ConflictingMutationError,
    DeployedSchemaDrift,
    TextIndexOperatorError,
    active_parts,
    classify_part_files,
    classify_partition_statuses,
    explain_uses_text_index_direct_read,
    explain_uses_token_scan,
    inspect_partition_coverage,
    inspect_schema_preconditions,
    materialize_case_partition,
    part_has_text_index_files,
    partition_materialize_sql,
    require_compatible_text_index,
    require_no_conflicting_mutations,
    sql_table_name,
)


SCRIPT_PATH = "/opt/casescope/scripts/phase2_1_materialize_search_index.py"
PYTHON = "/opt/casescope/venv/bin/python"


class _QueryResult:
    def __init__(self, rows=None, column_names=None):
        self.result_rows = list(rows or [])
        self.column_names = list(column_names or [])


class _FakeClickHouse:
    def __init__(
        self,
        *,
        database="phase2_1a_test",
        engine_full="",
        indices=None,
        table_exists=True,
        columns=None,
        tables=None,
        parts=None,
        mutations=None,
        fingerprint_rows=0,
    ):
        self.database = database
        self.engine_full = engine_full or (
            "MergeTree PARTITION BY case_id SETTINGS index_granularity = 8192, "
            "enable_block_number_column = 1, enable_block_offset_column = 1, "
            "exclude_materialize_skip_indexes_on_merge = 'idx_search_blob_text'"
        )
        self.indices = list(indices or [])
        self.table_exists = table_exists
        self.columns = list(columns or [])
        self.tables = list(tables or ["visible_evidence_generations", "durable_ingest_batches"])
        self.parts = list(parts or [])
        self.mutations = list(mutations or [])
        self.fingerprint_rows = fingerprint_rows
        self.commands = []
        self.queries = []

    def query(self, sql, parameters=None):
        parameters = parameters or {}
        self.queries.append(sql)
        text = " ".join(sql.split())
        if "SELECT currentDatabase()" in text:
            return _QueryResult([(self.database,)], ["currentDatabase()"])
        if "FROM system.tables" in text and "engine_full" in text:
            if not self.table_exists:
                return _QueryResult([])
            return _QueryResult([(self.engine_full,)], ["engine_full"])
        if "FROM system.tables" in text and "name IN" in text:
            return _QueryResult([(name,) for name in self.tables], ["name"])
        if "FROM system.tables" in text:
            return _QueryResult([(1 if self.table_exists else 0,)], ["count()"])
        if "FROM system.columns" in text:
            return _QueryResult([(name,) for name in self.columns], ["name"])
        if "FROM system.data_skipping_indices" in text:
            return _QueryResult(
                [
                    (
                        item["name"],
                        item.get("type", "text"),
                        item.get("type_full", ""),
                        item.get("expr", "search_blob"),
                        item.get("granularity", 1),
                    )
                    for item in self.indices
                ],
                ["name", "type", "type_full", "expr", "granularity"],
            )
        if "FROM system.mutations" in text and "is_done = 0" in text:
            active = [item for item in self.mutations if not item.get("is_done")]
            return _QueryResult(
                [
                    (
                        item["mutation_id"],
                        item.get("command", ""),
                        item.get("create_time"),
                        item.get("is_done", 0),
                        item.get("latest_failed_part"),
                        item.get("latest_fail_reason", ""),
                        item.get("parts_to_do", 1),
                    )
                    for item in active
                ],
                [
                    "mutation_id",
                    "command",
                    "create_time",
                    "is_done",
                    "latest_failed_part",
                    "latest_fail_reason",
                    "parts_to_do",
                ],
            )
        if "FROM system.mutations" in text:
            return _QueryResult([], ["mutation_id"])
        if "FROM system.parts" in text:
            wanted = parameters.get("partition")
            rows = []
            for item in self.parts:
                if wanted is not None and str(item.get("partition")) != str(wanted):
                    continue
                if not item.get("active", 1):
                    continue
                rows.append(
                    (
                        item.get("partition"),
                        item.get("partition_id"),
                        item.get("name"),
                        item.get("min_block_number", 1),
                        item.get("max_block_number", 1),
                        item.get("rows", 0),
                        item.get("bytes_on_disk", 0),
                        item.get("data_compressed_bytes", 0),
                        item.get("data_uncompressed_bytes", 0),
                        item.get("secondary_indices_compressed_bytes", 0),
                        item.get("files", 0),
                        item.get("hash_of_all_files", ""),
                        item.get("hash_of_uncompressed_files", ""),
                        item.get("data_version", 1),
                        item.get("path"),
                        1,
                    )
                )
            return _QueryResult(
                rows,
                [
                    "partition",
                    "partition_id",
                    "name",
                    "min_block_number",
                    "max_block_number",
                    "rows",
                    "bytes_on_disk",
                    "data_compressed_bytes",
                    "data_uncompressed_bytes",
                    "secondary_indices_compressed_bytes",
                    "files",
                    "hash_of_all_files",
                    "hash_of_uncompressed_files",
                    "data_version",
                    "path",
                    "active",
                ],
            )
        if "countIf(" in text:
            return _QueryResult(
                [(self.fingerprint_rows, 1, 2, 0)],
                ["rows", "erk_hash", "search_blob_hash", "protocol_identity_nonnull"],
            )
        if "ORDER BY evidence_record_key" in text:
            return _QueryResult([], ["evidence_record_key", "search_blob_hash", "search_blob_len"])
        return _QueryResult([])

    def command(self, sql):
        self.commands.append(sql)


def _compatible_indices():
    return [
        {
            "name": "idx_search_ngram",
            "type": "ngrambf_v1",
            "type_full": "ngrambf_v1(3, 512, 2, 0)",
            "expr": "search_blob",
            "granularity": 4,
        },
        {
            "name": "idx_search_token",
            "type": "tokenbf_v1",
            "type_full": "tokenbf_v1(32768, 3, 0)",
            "expr": "search_blob",
            "granularity": 4,
        },
        {
            "name": INDEX_NAME,
            "type": "text",
            "type_full": INDEX_TYPE_SQL,
            "expr": "search_blob",
            "granularity": 100000000,
        },
    ]


def _protocol_columns():
    return [
        "source_ref_type",
        "source_ref_id",
        "source_generation",
        "ingest_batch_id",
        "ingest_row_ordinal",
        "ingest_row_hash",
        "ingest_attempt_id",
    ]


class CoverageClassifierTests(unittest.TestCase):
    def test_part_files_require_sentinel(self):
        self.assertFalse(part_has_text_index_files(["skp_idx_idx_search_ngram.idx"]))
        self.assertTrue(
            part_has_text_index_files(
                [TEXT_INDEX_SENTINEL_FILE, "skp_idx_idx_search_blob_text.dct.idx"]
            )
        )
        self.assertEqual(classify_part_files(None, listed=False), COVERAGE_UNKNOWN)
        self.assertEqual(classify_part_files(["data.bin"], listed=True), COVERAGE_UNMATERIALIZED)

    def test_partition_status_and_unknown_fail_closed(self):
        self.assertEqual(
            classify_partition_statuses([COVERAGE_MATERIALIZED, COVERAGE_MATERIALIZED]),
            COVERAGE_MATERIALIZED,
        )
        self.assertEqual(
            classify_partition_statuses([COVERAGE_UNMATERIALIZED]),
            COVERAGE_UNMATERIALIZED,
        )
        self.assertEqual(
            classify_partition_statuses([COVERAGE_MATERIALIZED, COVERAGE_UNMATERIALIZED]),
            COVERAGE_PARTIAL,
        )
        self.assertEqual(
            classify_partition_statuses([COVERAGE_MATERIALIZED, COVERAGE_UNKNOWN]),
            COVERAGE_UNKNOWN,
        )
        self.assertEqual(classify_partition_statuses([]), COVERAGE_UNKNOWN)

    def test_partition_sql_is_scoped_and_has_no_forbidden_tokens(self):
        sql = partition_materialize_sql(33)
        self.assertEqual(
            sql,
            "ALTER TABLE events MATERIALIZE INDEX idx_search_blob_text "
            "IN PARTITION 33 SETTINGS mutations_sync = 1",
        )
        self.assertNotIn("OPTIMIZE", sql)
        self.assertNotIn("DROP INDEX", sql)
        self.assertNotIn("UPDATE", sql)
        with self.assertRaises(TextIndexOperatorError):
            sql_table_name("events; DROP TABLE events")


class OperatorFailClosedTests(unittest.TestCase):
    def test_production_requires_ack(self):
        client = _FakeClickHouse(database="casescope", indices=_compatible_indices())
        with self.assertRaises(TextIndexOperatorError):
            materialize_case_partition(client, 33, allow_production=False)

    def test_wrong_expression_fails_closed(self):
        indices = _compatible_indices()
        for item in indices:
            if item["name"] == INDEX_NAME:
                item["expr"] = "command_line"
        client = _FakeClickHouse(indices=indices, columns=_protocol_columns())
        with self.assertRaises(IncompatibleSearchBlobTextIndex):
            require_compatible_text_index(client)
        with self.assertRaises(IncompatibleSearchBlobTextIndex):
            materialize_case_partition(client, 1, allow_production=True)
        self.assertEqual(client.commands, [])

    def test_wrong_type_fails_closed(self):
        indices = _compatible_indices()
        for item in indices:
            if item["name"] == INDEX_NAME:
                item["type_full"] = "text(tokenizer = ngrams(3), preprocessor = lower(search_blob))"
        client = _FakeClickHouse(indices=indices, columns=_protocol_columns())
        with self.assertRaises(IncompatibleSearchBlobTextIndex):
            materialize_case_partition(client, 1, allow_production=True)
        self.assertEqual(client.commands, [])

    def test_conflicting_mutation_fails_closed(self):
        client = _FakeClickHouse(
            indices=_compatible_indices(),
            columns=_protocol_columns(),
            mutations=[{"mutation_id": "mutation_9.txt", "command": "UPDATE", "is_done": 0}],
        )
        with self.assertRaises(ConflictingMutationError):
            require_no_conflicting_mutations(client)
        with self.assertRaises(ConflictingMutationError):
            materialize_case_partition(client, 1, allow_production=True)
        self.assertEqual(client.commands, [])

    def test_schema_drift_fails_closed(self):
        client = _FakeClickHouse(
            indices=_compatible_indices(),
            columns=["case_id"],
            tables=[],
            engine_full="MergeTree SETTINGS index_granularity = 8192",
        )
        inspection = inspect_schema_preconditions(client)
        self.assertFalse(inspection["ok"])
        with self.assertRaises(DeployedSchemaDrift):
            materialize_case_partition(client, 1, allow_production=True)

    def test_unknown_coverage_fails_closed_and_dry_run_does_not_command(self):
        parts = [
            {
                "partition": "7",
                "partition_id": "7",
                "name": "7_1_1_0",
                "rows": 10,
                "path": "/var/lib/clickhouse/store/aa/aaaa/7_1_1_0/",
            }
        ]
        client = _FakeClickHouse(
            indices=_compatible_indices(),
            columns=_protocol_columns(),
            parts=parts,
            fingerprint_rows=10,
        )

        def boom(_path):
            raise TextIndexOperatorError("cannot list")

        with self.assertRaises(TextIndexOperatorError):
            materialize_case_partition(client, 7, allow_production=True, lister=boom)
        dry = materialize_case_partition(
            client, 7, allow_production=True, dry_run=True, lister=boom
        )
        self.assertTrue(dry["dry_run"])
        self.assertEqual(client.commands, [])

    def test_already_materialized_skips_sql(self):
        parts = [
            {
                "partition": "7",
                "partition_id": "7",
                "name": "7_1_1_0",
                "rows": 10,
                "bytes_on_disk": 100,
                "hash_of_all_files": "abc",
                "path": "/var/lib/clickhouse/store/aa/aaaa/7_1_1_0/",
            }
        ]
        client = _FakeClickHouse(
            indices=_compatible_indices(),
            columns=_protocol_columns(),
            parts=parts,
            fingerprint_rows=10,
        )
        result = materialize_case_partition(
            client,
            7,
            allow_production=True,
            lister=lambda _path: [TEXT_INDEX_SENTINEL_FILE, "skp_idx_idx_search_blob_text.dct.idx"],
        )
        self.assertTrue(result["already_materialized"])
        self.assertTrue(result["skipped"])
        self.assertEqual(client.commands, [])


def _load_operator():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "phase2_1_materialize_search_index",
        SCRIPT_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _clear_fence():
    return {
        "ok": True,
        "shared_writer_count": 0,
        "exclusive": None,
        "error": None,
        "refusal_reason": None,
    }


def _stopped_systemd():
    return {
        "ok": True,
        "states": {
            "casescope-web": "inactive",
            "casescope-workers": "inactive",
            "casescope-beat": "inactive",
        },
        "refusal_reason": None,
    }


def _active_systemd():
    return {
        "ok": False,
        "states": {
            "casescope-web": "inactive",
            "casescope-workers": "active",
            "casescope-beat": "inactive",
        },
        "refusal_reason": "local service still active: casescope-workers=active",
    }


def _empty_broker():
    return {
        "ok": True,
        "queues": {"celery": 0, "ioc": 0},
        "queued_count": 0,
        "unacked_count": 0,
        "error": None,
    }


_UNSET = object()


class OperatorIdleCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.op = _load_operator()

    def _celery(self, active=_UNSET, reserved=_UNSET, scheduled=_UNSET, broker=None, error=None):
        workers = {"celery@host": []}
        return self.op.compose_celery_report(
            workers if active is _UNSET else active,
            workers if reserved is _UNSET else reserved,
            workers if scheduled is _UNSET else scheduled,
            broker if broker is not None else _empty_broker(),
            error=error,
        )

    def _inspect(self, *, require_idle, fence=None, systemd=None, celery=None):
        return self.op.inspect_writers(
            require_idle=require_idle,
            fence=fence if fence is not None else _clear_fence(),
            systemd=systemd if systemd is not None else _stopped_systemd(),
            celery=celery if celery is not None else self._celery(),
        )

    def test_fence_clear_services_stopped_celery_empty_passes(self):
        report = self._inspect(require_idle=True)
        self.assertTrue(report["ok"])
        self.assertIsNone(report["refusal_reason"])

    def test_celery_active_refuses(self):
        celery = self._celery(active={"w": [{"id": "t-active"}]})
        with self.assertRaises(SystemExit) as raised:
            self._inspect(require_idle=True, celery=celery)
        self.assertIn("celery active count=1", str(raised.exception))

    def test_celery_reserved_refuses(self):
        celery = self._celery(reserved={"w": [{"id": "t-reserved"}]})
        with self.assertRaises(SystemExit) as raised:
            self._inspect(require_idle=True, celery=celery)
        self.assertIn("celery reserved count=1", str(raised.exception))

    def test_celery_scheduled_refuses(self):
        celery = self._celery(scheduled={"w": [{"id": "t-scheduled"}]})
        with self.assertRaises(SystemExit) as raised:
            self._inspect(require_idle=True, celery=celery)
        self.assertIn("celery scheduled count=1", str(raised.exception))

    def test_celery_inspection_error_refuses(self):
        celery = self.op.inspect_celery(
            inspector_factory=lambda: (_ for _ in ()).throw(RuntimeError("broker timeout")),
            broker_factory=_empty_broker,
        )
        with self.assertRaises(SystemExit) as raised:
            self._inspect(require_idle=True, celery=celery)
        self.assertIn("celery inspection error", str(raised.exception))
        self.assertIn("broker timeout", str(raised.exception))

    def test_none_payload_is_not_zero(self):
        counted = self.op.count_celery_inspect_payload(None, "celery active")
        self.assertFalse(counted["inspected"])
        self.assertIsNone(counted["count"])
        celery = self._celery(active=None, reserved={"w": []}, scheduled={"w": []})
        self.assertIsNone(celery["active_count"])
        self.assertFalse(celery["ok"])
        with self.assertRaises(SystemExit) as raised:
            self._inspect(require_idle=True, systemd=_active_systemd(), celery=celery)
        message = str(raised.exception)
        self.assertIn("celery inspection error", message)
        self.assertNotIn("celery active count=0", message)

    def test_fence_unavailable_refuses(self):
        fence = {
            "ok": False,
            "shared_writer_count": None,
            "exclusive": None,
            "error": "redis down",
            "refusal_reason": "ingest fence unavailable: redis down",
        }
        with self.assertRaises(SystemExit) as raised:
            self._inspect(require_idle=True, fence=fence)
        self.assertIn("ingest fence unavailable", str(raised.exception))

    def test_local_service_still_active_refuses(self):
        with self.assertRaises(SystemExit) as raised:
            self._inspect(require_idle=True, systemd=_active_systemd())
        self.assertIn("local service still active", str(raised.exception))

    def test_status_mode_reports_degraded_without_raising(self):
        report = self._inspect(
            require_idle=False,
            systemd=_active_systemd(),
            celery=self._celery(active={"w": [{"id": "busy"}]}),
        )
        self.assertFalse(report["ok"])
        self.assertIn("celery active count=1", report["refusal_reason"])
        self.assertIn("local service still active", report["refusal_reason"])

    def test_workers_down_and_broker_empty_passes(self):
        celery = self._celery(active=None, reserved=None, scheduled=None)
        report = self._inspect(require_idle=True, celery=celery)
        self.assertTrue(report["ok"], report)

    def test_workers_down_and_broker_error_refuses(self):
        celery = self._celery(
            active=None,
            reserved=None,
            scheduled=None,
            broker={
                "ok": False,
                "queues": {},
                "queued_count": None,
                "unacked_count": None,
                "error": "redis connection refused",
            },
        )
        with self.assertRaises(SystemExit) as raised:
            self._inspect(require_idle=True, celery=celery)
        self.assertIn("celery inspection error", str(raised.exception))


class OperatorQueueSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.op = _load_operator()

    def test_empty_args_with_kwargs_case_id_is_not_malformed(self):
        summary = self.op.celery_task_payload_summary(
            {
                "id": "0e0fed2b-6318-48cc-af38-a20dbc66b335",
                "name": "tasks.materialize_case_graph",
                "args": [],
                "kwargs": {
                    "case_id": 3,
                    "case_uuid": "case-uuid",
                    "case_file_ids": None,
                },
            }
        )
        self.assertEqual(summary["case_id"], 3)
        self.assertEqual(summary["case_id_source"], "kwargs")
        self.assertTrue(summary["has_case_id"])
        self.assertFalse(summary["missing_case_id_proven"])
        self.assertEqual(summary["args"], [])

    def test_empty_args_and_empty_kwargs_proves_missing_case_id(self):
        summary = self.op.celery_task_payload_summary(
            {"id": "dead", "name": "tasks.materialize_case_graph", "args": [], "kwargs": {}}
        )
        self.assertIsNone(summary["case_id"])
        self.assertFalse(summary["has_case_id"])
        self.assertTrue(summary["missing_case_id_proven"])

    def test_positional_args_alone_are_not_inferred_as_kwargs_case_id(self):
        summary = self.op.celery_task_payload_summary(
            {
                "id": "mitre",
                "name": "tasks.mitre_mapper.map_case_mitre_procedures",
                "args": [3, "system"],
                "kwargs": {},
            }
        )
        self.assertIsNone(summary["case_id"])
        self.assertFalse(summary["has_case_id"])
        self.assertFalse(summary["missing_case_id_proven"])

    def test_quiesce_steps_do_not_delete_broker_messages(self):
        self.assertFalse(self.op.BROKER_MESSAGE_DELETION_ALLOWED)
        actions = [step["action"] for step in self.op.SAFE_QUIESCE_STEPS]
        self.assertEqual(
            actions,
            [
                "stop_new_producers",
                "leave_workers_alive",
                "wait_for_celery_drain",
                "stop_workers",
                "recheck_idle",
            ],
        )
        self.assertNotIn("delete_broker_messages", actions)
        self.assertNotIn("purge", " ".join(actions))

    def test_drain_complete_while_workers_still_active(self):
        celery = self.op.compose_celery_report(
            {"celery@host": []},
            {"celery@host": []},
            {"celery@host": []},
            _empty_broker(),
        )
        systemd = {
            "ok": False,
            "states": {
                "casescope-web": "inactive",
                "casescope-workers": "active",
                "casescope-beat": "inactive",
            },
            "refusal_reason": "local service still active: casescope-workers=active",
        }
        fence = _clear_fence()
        self.assertTrue(self.op.celery_work_drained(celery))
        drain = self.op.drain_status_payload(fence=fence, systemd=systemd, celery=celery)
        self.assertTrue(drain["safe_to_stop_workers"])
        self.assertTrue(drain["workers_still_active"])
        with self.assertRaises(SystemExit) as raised:
            self.op.inspect_writers(
                require_idle=True, fence=fence, systemd=systemd, celery=celery
            )
        self.assertIn("casescope-workers=active", str(raised.exception))

    def test_unacked_work_refuses_idle_without_recommending_deletion(self):
        celery = self.op.compose_celery_report(
            None,
            {"celery@host": []},
            {"celery@host": []},
            {
                "ok": True,
                "queues": {"celery": 0, "ioc": 0},
                "queued_count": 0,
                "unacked_count": 2,
                "error": None,
            },
        )
        with self.assertRaises(SystemExit) as raised:
            self.op.inspect_writers(
                require_idle=True,
                fence=_clear_fence(),
                systemd=_stopped_systemd(),
                celery=celery,
            )
        message = str(raised.exception)
        self.assertIn("celery unacked count=2", message)
        self.assertIn("do not delete broker or unacked messages", message)

    def test_compose_report_keeps_kwargs_in_task_summaries(self):
        celery = self.op.compose_celery_report(
            {
                "celery@host": [
                    {
                        "id": "0e0fed2b-6318-48cc-af38-a20dbc66b335",
                        "name": "tasks.materialize_case_graph",
                        "args": [],
                        "kwargs": {"case_id": 3, "case_uuid": "a580e5ce-4bb2-4912-b34b-8b63b4cf80cd"},
                    }
                ]
            },
            {"celery@host": []},
            {"celery@host": []},
            _empty_broker(),
        )
        self.assertEqual(len(celery["task_summaries"]), 1)
        summary = celery["task_summaries"][0]
        self.assertEqual(summary["args"], [])
        self.assertEqual(summary["kwargs"]["case_id"], 3)
        self.assertTrue(summary["has_case_id"])


class CoverageActivePartTests(unittest.TestCase):
    def test_active_parts_sql_ignores_inactive(self):
        source = inspect.getsource(active_parts)
        self.assertIn("AND active", source)

    def _client_with_parts(self, parts):
        return _FakeClickHouse(
            indices=_compatible_indices(),
            columns=_protocol_columns(),
            parts=parts,
        )

    def test_inactive_unmaterialized_source_part_does_not_influence(self):
        parts = [
            {
                "partition": "7",
                "partition_id": "7",
                "name": "7_1_1_0",
                "rows": 10,
                "bytes_on_disk": 100,
                "active": 0,
                "path": "/var/lib/clickhouse/store/aa/aaaa/7_1_1_0/",
            },
            {
                "partition": "7",
                "partition_id": "7",
                "name": "7_1_1_0_9",
                "rows": 10,
                "bytes_on_disk": 140,
                "active": 1,
                "path": "/var/lib/clickhouse/store/aa/aaaa/7_1_1_0_9/",
            },
        ]

        def lister(path):
            if path.rstrip("/").endswith("7_1_1_0"):
                return ["data.bin"]
            return [TEXT_INDEX_SENTINEL_FILE, "skp_idx_idx_search_blob_text.dct.idx"]

        result = inspect_partition_coverage(
            self._client_with_parts(parts), 7, lister=lister
        )
        self.assertEqual(result["coverage"], COVERAGE_MATERIALIZED)
        self.assertEqual(len(result["parts"]), 1)
        self.assertEqual(result["parts"][0]["name"], "7_1_1_0_9")

    def test_mixed_active_parts_are_partial(self):
        parts = [
            {
                "partition": "7",
                "name": "7_1_1_0_9",
                "rows": 10,
                "path": "/var/lib/clickhouse/store/aa/aaaa/7_1_1_0_9/",
                "active": 1,
            },
            {
                "partition": "7",
                "name": "7_2_2_0",
                "rows": 4,
                "path": "/var/lib/clickhouse/store/aa/aaaa/7_2_2_0/",
                "active": 1,
            },
        ]

        def lister(path):
            if path.rstrip("/").endswith("7_1_1_0_9"):
                return [TEXT_INDEX_SENTINEL_FILE, "skp_idx_idx_search_blob_text.dct.idx"]
            return ["data.bin"]

        result = inspect_partition_coverage(
            self._client_with_parts(parts), 7, lister=lister
        )
        self.assertEqual(result["coverage"], COVERAGE_PARTIAL)

    def test_inability_to_inspect_any_active_part_is_unknown(self):
        parts = [
            {
                "partition": "7",
                "name": "7_1_1_0_9",
                "rows": 10,
                "path": "/var/lib/clickhouse/store/aa/aaaa/7_1_1_0_9/",
                "active": 1,
            }
        ]

        def boom(_path):
            raise TextIndexOperatorError("cannot list")

        result = inspect_partition_coverage(
            self._client_with_parts(parts), 7, lister=boom
        )
        self.assertEqual(result["coverage"], COVERAGE_UNKNOWN)


class ProductBoundaryTests(unittest.TestCase):
    def test_hunt_substring_and_exclusion_paths_still_use_ilike(self):
        source = inspect.getsource(hunting_query_helpers)
        self.assertIn("search_blob ilike", source)
        self.assertIn("hasAllTokens", source)
        self.assertNotIn("hasAllTokens(lower(search_blob)", source)

    def test_script_has_no_all_partitions_default(self):
        source = open(SCRIPT_PATH, encoding="utf-8").read()
        self.assertNotRegex(source, r"add_argument\(\s*['\"]--all['\"]")
        self.assertIn("there is no all-partitions default", source)
        proc = subprocess.run(
            [PYTHON, SCRIPT_PATH],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--case-id", proc.stderr)

    def test_operator_source_never_drops_blooms_or_optimize(self):
        from utils import search_blob_text_index as module

        source = inspect.getsource(module) + open(SCRIPT_PATH, encoding="utf-8").read()
        self.assertNotIn("ALTER TABLE events DROP INDEX", source)
        self.assertNotIn("OPTIMIZE FINAL", source)
        self.assertNotIn("DROP INDEX idx_search_ngram", source)
        self.assertNotIn("DROP INDEX idx_search_token", source)


def _live_client(database):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST") or "localhost",
        port=int(os.environ.get("CLICKHOUSE_PORT") or 8123),
        database=database,
        username=os.environ.get("CLICKHOUSE_USER") or "default",
        password=os.environ.get("CLICKHOUSE_PASSWORD") or "",
        autogenerate_session_id=False,
        settings={
            "async_insert": 0,
            "wait_for_async_insert": 1,
            "materialize_skip_indexes_on_insert": 0,
        },
        send_receive_timeout=120,
    )


def _clickhouse_available():
    try:
        client = _live_client("default")
        client.query("SELECT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(_clickhouse_available(), "live ClickHouse is required")
class LivePartitionMaterializeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database = f"cs_p21a_test_{uuid.uuid4().hex[:12]}"
        admin = _live_client("default")
        admin.command(f"CREATE DATABASE {cls.database}")
        cls.client = _live_client(cls.database)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.command(f"DROP DATABASE IF EXISTS {cls.database}")
        except Exception:
            pass

    def _create_control_tables(self):
        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS visible_evidence_generations (
                case_id UInt32,
                source_ref_type String,
                source_ref_id String,
                source_generation UInt32,
                visibility_state String,
                state_version UInt64
            )
            ENGINE = ReplacingMergeTree(state_version)
            ORDER BY (case_id, source_ref_type, source_ref_id, source_generation)
            """
        )
        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS durable_ingest_batches (
                ingest_batch_id String,
                case_id UInt32,
                source_ref_type String,
                source_ref_id String,
                source_generation UInt32,
                status String,
                state_version UInt64
            )
            ENGINE = ReplacingMergeTree(state_version)
            ORDER BY ingest_batch_id
            """
        )

    def _create_events(self):
        self.client.command("DROP TABLE IF EXISTS events")
        self.client.command(
            """
            CREATE TABLE events (
                case_id UInt32,
                selector_key String,
                search_blob String,
                evidence_record_key String,
                command_line String DEFAULT '',
                source_ref_type Nullable(String) DEFAULT NULL,
                source_ref_id Nullable(String) DEFAULT NULL,
                source_generation Nullable(UInt32) DEFAULT NULL,
                ingest_batch_id Nullable(String) DEFAULT NULL,
                ingest_row_ordinal Nullable(UInt32) DEFAULT NULL,
                ingest_row_hash Nullable(String) DEFAULT NULL,
                ingest_attempt_id Nullable(UUID) DEFAULT NULL,
                INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
                INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
            )
            ENGINE = MergeTree
            PARTITION BY case_id
            ORDER BY (case_id, selector_key)
            SETTINGS
                index_granularity = 8192,
                enable_block_number_column = 1,
                enable_block_offset_column = 1
            """
        )

    def _insert_partition(self, case_id, n, prefix):
        rows = []
        for i in range(n):
            blob = (
                f"PowerShell user:{prefix} host-{case_id}.corp.local 10.20.30.{i % 50} "
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
                "event:4688 HKLM\\Software\\Run"
            )
            if i % 11 == 0:
                blob += " zxqvunique"
            if i % 17 == 0:
                blob += " substringneedle"
            rows.append((case_id, f"{prefix}-{i}", blob, f"erk-{prefix}-{i}"))
        self.client.insert(
            "events",
            rows,
            column_names=["case_id", "selector_key", "search_blob", "evidence_record_key"],
        )

    def test_three_partition_operator_proof(self):
        from utils.search_blob_text_index import (
            explain_has_all_tokens,
            inspect_partition_coverage,
            partition_value_fingerprint,
        )

        self._create_control_tables()
        self._create_events()
        self._insert_partition(1, 1500, "small")
        self._insert_partition(2, 8000, "medium")
        self._insert_partition(3, 3000, "unmat")
        add_events_search_blob_text_index(self.client, allow_production=True)
        mutations_before = self.client.query(
            "SELECT count() FROM system.mutations "
            "WHERE database = currentDatabase() AND table = 'events'"
        ).result_rows[0][0]
        dry = materialize_case_partition(self.client, 1, dry_run=True)
        self.assertTrue(dry["dry_run"])
        mutations_after_dry = self.client.query(
            "SELECT count() FROM system.mutations "
            "WHERE database = currentDatabase() AND table = 'events'"
        ).result_rows[0][0]
        self.assertEqual(mutations_before, mutations_after_dry)
        self.assertEqual(
            inspect_partition_coverage(self.client, 1)["coverage"],
            COVERAGE_UNMATERIALIZED,
        )
        explain_before = explain_has_all_tokens(self.client, 1)
        self.assertTrue(explain_uses_token_scan(explain_before))
        self.assertFalse(explain_uses_text_index_direct_read(explain_before))

        fp1 = partition_value_fingerprint(self.client, 1)
        fp2 = partition_value_fingerprint(self.client, 2)
        fp3 = partition_value_fingerprint(self.client, 3)
        ids_before = {
            case_id: [
                row[0]
                for row in self.client.query(
                    "SELECT evidence_record_key FROM events "
                    "WHERE case_id = {c:UInt32} AND hasAllTokens(search_blob, {t:String}) "
                    "ORDER BY evidence_record_key",
                    parameters={"c": case_id, "t": "powershell"},
                ).result_rows
            ]
            for case_id in (1, 2, 3)
        }

        result = materialize_case_partition(self.client, 1)
        self.assertTrue(result["executed"])
        self.assertEqual(result["coverage_after"]["coverage"], COVERAGE_MATERIALIZED)
        self.assertTrue(result["rows_unchanged"])
        self.assertTrue(result["values_unchanged"])
        self.assertTrue(result["other_partitions_unchanged"]["unchanged"])
        self.assertEqual(
            inspect_partition_coverage(self.client, 2)["coverage"],
            COVERAGE_UNMATERIALIZED,
        )
        self.assertEqual(
            inspect_partition_coverage(self.client, 3)["coverage"],
            COVERAGE_UNMATERIALIZED,
        )
        self.assertEqual(partition_value_fingerprint(self.client, 1), fp1)
        self.assertEqual(partition_value_fingerprint(self.client, 2), fp2)
        self.assertEqual(partition_value_fingerprint(self.client, 3), fp3)
        explain_after = explain_has_all_tokens(self.client, 1)
        self.assertTrue(explain_uses_text_index_direct_read(explain_after))
        for case_id in (1, 2, 3):
            ids_after = [
                row[0]
                for row in self.client.query(
                    "SELECT evidence_record_key FROM events "
                    "WHERE case_id = {c:UInt32} AND hasAllTokens(search_blob, {t:String}) "
                    "ORDER BY evidence_record_key",
                    parameters={"c": case_id, "t": "powershell"},
                ).result_rows
            ]
            self.assertEqual(ids_after, ids_before[case_id])

        rerun = materialize_case_partition(self.client, 1)
        self.assertTrue(rerun["already_materialized"])
        self.assertFalse(rerun["executed"])
        self.assertEqual(
            inspect_partition_coverage(self.client, 3)["coverage"],
            COVERAGE_UNMATERIALIZED,
        )

        self._insert_partition(2, 1200, "medium2")
        self.assertEqual(
            inspect_partition_coverage(self.client, 2)["coverage"],
            COVERAGE_UNMATERIALIZED,
        )
        second = materialize_case_partition(self.client, 2)
        self.assertEqual(second["coverage_after"]["coverage"], COVERAGE_MATERIALIZED)
        self.assertEqual(
            inspect_partition_coverage(self.client, 3)["coverage"],
            COVERAGE_UNMATERIALIZED,
        )

    def test_wrong_existing_index_fails_closed_live(self):
        self._create_control_tables()
        self._create_events()
        self._insert_partition(1, 20, "bad")
        self.client.command(
            """
            ALTER TABLE events ADD INDEX idx_search_blob_text command_line TYPE text(
                tokenizer = 'splitByNonAlpha',
                preprocessor = lower(command_line)
            ) GRANULARITY 1
            """
        )
        with self.assertRaises(IncompatibleSearchBlobTextIndex):
            materialize_case_partition(self.client, 1)
        create = self.client.query("SHOW CREATE TABLE events").result_rows[0][0]
        self.assertIn("INDEX idx_search_blob_text command_line", create)
        self.assertIn("idx_search_ngram", create)
        self.assertIn("idx_search_token", create)

    def test_missing_text_index_fails_closed(self):
        self._create_control_tables()
        self._create_events()
        self._insert_partition(1, 20, "none")
        with self.assertRaises(TextIndexOperatorError):
            materialize_case_partition(self.client, 1)

    def test_mutation_generated_active_part_coverage(self):
        self._create_control_tables()
        self._create_events()
        self._insert_partition(1, 2500, "mut")
        add_events_search_blob_text_index(self.client, allow_production=True)
        before = inspect_partition_coverage(self.client, 1)
        self.assertEqual(before["coverage"], COVERAGE_UNMATERIALIZED)
        result = materialize_case_partition(self.client, 1)
        self.assertEqual(result["coverage_after"]["coverage"], COVERAGE_MATERIALIZED)

        all_parts = self.client.query(
            """
            SELECT name, active
            FROM system.parts
            WHERE database = currentDatabase()
              AND table = 'events'
              AND partition = '1'
            ORDER BY name
            """
        ).result_rows
        inactive_names = [name for name, is_active in all_parts if not int(is_active)]
        active_names = [name for name, is_active in all_parts if int(is_active)]
        after = inspect_partition_coverage(self.client, 1)
        after_names = [item["name"] for item in after["parts"]]
        self.assertEqual(sorted(after_names), sorted(active_names))
        self.assertTrue(
            inactive_names,
            "expected MATERIALIZE INDEX to leave inactive source parts",
        )
        for name in inactive_names:
            self.assertNotIn(name, after_names)
        self.assertEqual(after["coverage"], COVERAGE_MATERIALIZED)

        self._insert_partition(1, 400, "mut2")
        mixed = inspect_partition_coverage(self.client, 1)
        self.assertEqual(mixed["coverage"], COVERAGE_PARTIAL)

        def boom(_path):
            raise TextIndexOperatorError("cannot list")

        unknown = inspect_partition_coverage(self.client, 1, lister=boom)
        self.assertEqual(unknown["coverage"], COVERAGE_UNKNOWN)
